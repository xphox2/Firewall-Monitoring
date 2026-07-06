package classify

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

// Candidate database filenames looked up in the live (downloaded) directory, in
// precedence order. The paid MaxMind updater writes these; whichever exists wins
// over the embedded DB-IP Lite bundle. City is a superset of Country for our
// purposes (we only read the country subfield), and ISP is a superset of ASN.
var (
	liveCountryCandidates = []string{"GeoIP2-City.mmdb", "GeoLite2-City.mmdb", "GeoIP2-Country.mmdb", "GeoLite2-Country.mmdb"}
	liveASNCandidates     = []string{"GeoIP2-ISP.mmdb", "GeoLite2-ASN.mmdb"}
)

// geoDB holds one memory-mapped reader together with the stat it was opened at
// (so a reload can cheaply detect a changed file) and the resolved path it came
// from (so a reload can also detect that a higher-precedence file appeared).
type geoDB struct {
	reader *geoip2.Reader
	// mmdb is the raw maxminddb reader over the SAME file, opened only for the
	// ASN slot. geoip2-golang doesn't expose the matched network, so ASNInfoNet
	// uses mmdb.LookupNetwork to also return the ASN's CIDR prefix. nil for the
	// country slot or when the raw open failed (prefix is then just omitted).
	mmdb  *maxminddb.Reader
	path  string
	mtime time.Time
	size  int64
	// isISP marks an ASN-slot database whose records are GeoIP2-ISP shaped
	// (read via reader.ISP) rather than GeoLite2-ASN shaped (reader.ASN).
	isISP bool
}

// closeAll closes the geoip2 reader and, when present, the raw mmdb reader.
func (d *geoDB) closeAll() error {
	var err error
	if d.reader != nil {
		err = d.reader.Close()
	}
	if d.mmdb != nil {
		if e := d.mmdb.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// GeoResolver enriches a flow's addresses with an ISO country code and an
// autonomous-system number/organization. Databases are memory-mapped and the
// readers are goroutine-safe, so a single resolver is shared across the ingest
// path with no per-lookup allocation.
//
// Two sources are layered: a live directory (GEOIP_DB_DIR) that the optional
// paid MaxMind updater writes into, and an embedded DB-IP Lite bundle extracted
// to a cache dir. For each slot the live file wins when present, else the bundle
// is used — so geo works out of the box (bundle) and transparently upgrades when
// a key is configured (live).
//
// Each reader is held behind an atomic pointer so Reload can swap in a freshly
// resolved database without locking the hot lookup path. A swapped-out reader is
// retired and closed on the *next* reload cycle, by which point every
// microsecond-scale lookup that could have observed it has returned (closing
// unmaps its backing memory and an in-flight lookup would SIGBUS).
//
// Every method is nil-safe: a nil *GeoResolver (geo disabled) returns empty
// results rather than panicking.
type GeoResolver struct {
	liveDir   string
	bundleDir string
	country   atomic.Pointer[geoDB]
	asn       atomic.Pointer[geoDB]

	retireMu sync.Mutex
	retired  []io.Closer
}

// NewGeoResolver builds a resolver. When enabled is false it returns (nil, nil)
// — a disabled, nil-safe resolver. Otherwise it extracts the embedded bundle to
// cacheDir (empty = per-OS temp) and opens the highest-precedence country and
// ASN databases. If at least one slot opens, a usable resolver is returned; a
// non-fatal extraction/open error is surfaced for logging alongside it.
func NewGeoResolver(enabled bool, liveDir, cacheDir string) (*GeoResolver, error) {
	if !enabled {
		return nil, nil
	}
	g := &GeoResolver{liveDir: liveDir}
	var firstErr error
	if dir, err := ensureBundle(cacheDir); err == nil {
		g.bundleDir = dir
	} else {
		firstErr = err // no bundle; may still open live files if present
	}
	if db := g.openSlot(false); db != nil {
		g.country.Store(db)
	}
	if db := g.openSlot(true); db != nil {
		g.asn.Store(db)
	}
	if g.country.Load() == nil && g.asn.Load() == nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("no geoip databases could be opened (live=%q bundle=%q)", liveDir, g.bundleDir)
		}
		return nil, firstErr
	}
	return g, firstErr
}

// resolvePath returns the highest-precedence path for a slot plus whether it is
// an ISP-shaped ASN database. Live-dir candidates win over the bundle.
func (g *GeoResolver) resolvePath(asn bool) (path string, isISP bool) {
	candidates := liveCountryCandidates
	if asn {
		candidates = liveASNCandidates
	}
	if g.liveDir != "" {
		for _, name := range candidates {
			p := filepath.Join(g.liveDir, name)
			if _, err := os.Stat(p); err == nil {
				return p, asn && strings.Contains(name, "ISP")
			}
		}
	}
	if g.bundleDir != "" {
		name := bundledCountryDB
		if asn {
			name = bundledASNDB
		}
		return filepath.Join(g.bundleDir, name), false
	}
	return "", false
}

// openSlot resolves and opens the current best database for a slot, or nil.
func (g *GeoResolver) openSlot(asn bool) *geoDB {
	path, isISP := g.resolvePath(asn)
	if path == "" {
		return nil
	}
	db, err := openGeoDB(path, isISP, asn)
	if err != nil {
		return nil
	}
	return db
}

// openGeoDB opens a single .mmdb and records its stat + provenance. When wantNet
// is true (the ASN slot), it also opens a raw maxminddb reader over the same file
// so ASNInfoNet can return the matched network prefix; a failure there is
// non-fatal (geoip2 lookups still work, the prefix is just omitted).
func openGeoDB(path string, isISP, wantNet bool) (*geoDB, error) {
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	db := &geoDB{reader: r, path: path, isISP: isISP}
	if wantNet {
		if mr, err := maxminddb.Open(path); err == nil {
			db.mmdb = mr
		}
	}
	if fi, err := os.Stat(path); err == nil {
		db.mtime = fi.ModTime()
		db.size = fi.Size()
	}
	return db, nil
}

// Reload re-resolves both slots and, when the winning path changed or the file's
// mtime/size changed, opens the new copy and atomically swaps it in. This is how
// a freshly downloaded live database (paid tier) takes over from the bundle
// without a restart. The previous reader is retired and closed on the following
// Reload, never while a lookup could still dereference its mmap.
//
// Reload is nil-safe and intended for a periodic ticker.
func (g *GeoResolver) Reload() {
	if g == nil {
		return
	}
	g.retireMu.Lock()
	toClose := g.retired
	g.retired = nil
	g.retireMu.Unlock()
	for _, r := range toClose {
		_ = r.Close()
	}
	g.reloadSlot(&g.country, false)
	g.reloadSlot(&g.asn, true)
}

func (g *GeoResolver) reloadSlot(slot *atomic.Pointer[geoDB], asn bool) {
	path, isISP := g.resolvePath(asn)
	if path == "" {
		return
	}
	cur := slot.Load()
	if cur != nil && cur.path == path {
		fi, err := os.Stat(path)
		if err != nil {
			return // unreadable; keep serving the current mmap
		}
		if fi.ModTime().Equal(cur.mtime) && fi.Size() == cur.size {
			return // unchanged
		}
	}
	db, err := openGeoDB(path, isISP, asn)
	if err != nil {
		return // partial/corrupt new file; keep the current one
	}
	slot.Store(db)
	if cur != nil {
		g.retireMu.Lock()
		g.retired = append(g.retired, ioCloser(cur))
		g.retireMu.Unlock()
	}
}

// ioCloser adapts a *geoDB to io.Closer for the retire list (closes both the
// geoip2 and raw mmdb readers).
func ioCloser(d *geoDB) io.Closer { return closerFunc(d.closeAll) }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// Enabled reports whether any database is loaded (i.e. lookups can return data).
func (g *GeoResolver) Enabled() bool {
	return g != nil && (g.country.Load() != nil || g.asn.Load() != nil)
}

// Source returns a short human label of where the active country database comes
// from, for logging and the admin UI ("bundled (DB-IP Lite)" or "live: <file>").
func (g *GeoResolver) Source() string {
	if g == nil {
		return "disabled"
	}
	db := g.country.Load()
	if db == nil {
		db = g.asn.Load()
	}
	if db == nil {
		return "disabled"
	}
	if g.bundleDir != "" && strings.HasPrefix(db.path, g.bundleDir) {
		return "bundled (DB-IP Lite)"
	}
	return "live: " + filepath.Base(db.path)
}

// Country returns the ISO 3166-1 alpha-2 country code for ip, or "" when the
// resolver/DB is absent, the address is unparseable, or the IP isn't found
// (e.g. private/RFC1918 ranges, which the databases do not map).
func (g *GeoResolver) Country(ip string) string {
	if g == nil {
		return ""
	}
	db := g.country.Load()
	if db == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	rec, err := db.reader.Country(parsed)
	if err != nil || rec == nil {
		return ""
	}
	return rec.Country.IsoCode
}

// ASN returns the autonomous-system number for ip, or 0 when unavailable.
func (g *GeoResolver) ASN(ip string) uint32 {
	n, _ := g.ASNInfo(ip)
	return n
}

// ASNInfo returns the autonomous-system number and organization for ip, or
// (0, "") when the resolver/DB is absent, the address is unparseable, or the IP
// isn't found. Handles both GeoLite2-ASN and GeoIP2-ISP shaped databases.
func (g *GeoResolver) ASNInfo(ip string) (uint32, string) {
	if g == nil {
		return 0, ""
	}
	db := g.asn.Load()
	if db == nil {
		return 0, ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, ""
	}
	if db.isISP {
		rec, err := db.reader.ISP(parsed)
		if err != nil || rec == nil {
			return 0, ""
		}
		return uint32(rec.AutonomousSystemNumber), rec.AutonomousSystemOrganization
	}
	rec, err := db.reader.ASN(parsed)
	if err != nil || rec == nil {
		return 0, ""
	}
	return uint32(rec.AutonomousSystemNumber), rec.AutonomousSystemOrganization
}

// ASNInfoNet returns the autonomous-system number, organization, AND the network
// prefix (CIDR, e.g. "8.8.8.0/24") that the ASN database matched the IP to. The
// prefix comes from the raw maxminddb reader's LookupNetwork (geoip2-golang
// doesn't expose it); when the raw reader is unavailable it falls back to
// ASNInfo with an empty prefix. Used by the on-demand admin lookup endpoints, not
// the ingest hot path. Nil-safe.
func (g *GeoResolver) ASNInfoNet(ip string) (asn uint32, org string, prefix string) {
	if g == nil {
		return 0, "", ""
	}
	db := g.asn.Load()
	if db == nil {
		return 0, "", ""
	}
	if db.mmdb == nil {
		asn, org = g.ASNInfo(ip)
		return asn, org, ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, "", ""
	}
	var rec struct {
		Number uint   `maxminddb:"autonomous_system_number"`
		Org    string `maxminddb:"autonomous_system_organization"`
	}
	network, ok, err := db.mmdb.LookupNetwork(parsed, &rec)
	if err != nil || !ok {
		return 0, "", ""
	}
	if network != nil {
		prefix = network.String()
	}
	return uint32(rec.Number), rec.Org, prefix
}

// Close releases the memory-mapped databases, including any retired but not yet
// closed by a pending reload. Nil-safe.
func (g *GeoResolver) Close() error {
	if g == nil {
		return nil
	}
	var err error
	if db := g.country.Swap(nil); db != nil {
		if e := db.closeAll(); e != nil {
			err = e
		}
	}
	if db := g.asn.Swap(nil); db != nil {
		if e := db.closeAll(); e != nil && err == nil {
			err = e
		}
	}
	g.retireMu.Lock()
	toClose := g.retired
	g.retired = nil
	g.retireMu.Unlock()
	for _, r := range toClose {
		if e := r.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}
