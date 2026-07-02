package classify

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// Standard MaxMind GeoLite2 filenames, looked up under the configured DB dir.
const (
	geoCountryDB = "GeoLite2-Country.mmdb"
	geoASNDB     = "GeoLite2-ASN.mmdb"
)

// geoDB holds one memory-mapped GeoLite2 reader together with the mtime it was
// opened at, so a reload can cheaply detect that the file on disk changed.
type geoDB struct {
	reader *geoip2.Reader
	mtime  time.Time
	size   int64
}

// GeoResolver enriches a flow's addresses with an ISO country code and an
// autonomous-system number from MaxMind GeoLite2 databases. The .mmdb files are
// memory-mapped and the underlying reader is goroutine-safe, so a single
// resolver is shared across the ingest path with no per-lookup allocation.
//
// Each reader is held behind an atomic pointer so Reload can swap in a freshly
// opened database without locking the hot lookup path. Because closing a reader
// unmaps its backing memory — and an in-flight lookup on the old reader would
// then SIGBUS — a swapped-out reader is not closed immediately; it is retired to
// a grace list and closed on the *next* reload cycle, by which point all
// microsecond-scale lookups that could have observed it have long returned.
//
// Every method is nil-safe: a nil *GeoResolver (geo disabled, or the DB files
// were absent at startup) returns empty results rather than panicking, so
// callers never need to branch on whether geo is configured.
type GeoResolver struct {
	dir     string
	country atomic.Pointer[geoDB]
	asn     atomic.Pointer[geoDB]

	// retireMu guards readers swapped out by Reload but not yet closed. They are
	// closed at the start of the following Reload, after any in-flight lookup on
	// them has completed.
	retireMu sync.Mutex
	retired  []*geoip2.Reader
}

// NewGeoResolver opens the GeoLite2 Country and ASN databases under dir. When
// enabled is false it returns (nil, nil) — a disabled, nil-safe resolver. When
// enabled but a file can't be opened it returns a resolver holding whatever did
// open plus an error describing what didn't, so the caller can log the partial
// state and continue (the missing dimension's columns simply stay empty).
//
// Country and ASN are opened independently: a deployment may ship only one. If
// at least one opens, a usable resolver is returned; if neither opens, the error
// is returned with a nil resolver.
func NewGeoResolver(enabled bool, dir string) (*GeoResolver, error) {
	if !enabled {
		return nil, nil
	}
	if dir == "" {
		return nil, fmt.Errorf("geoip enabled but GEOIP_DB_DIR is empty")
	}
	g := &GeoResolver{dir: dir}
	var firstErr error
	if db, err := openGeoDB(filepath.Join(dir, geoCountryDB)); err == nil {
		g.country.Store(db)
	} else {
		firstErr = fmt.Errorf("open %s: %w", geoCountryDB, err)
	}
	if db, err := openGeoDB(filepath.Join(dir, geoASNDB)); err == nil {
		g.asn.Store(db)
	} else if firstErr == nil {
		firstErr = fmt.Errorf("open %s: %w", geoASNDB, err)
	}
	if g.country.Load() == nil && g.asn.Load() == nil {
		return nil, firstErr
	}
	// At least one DB opened; surface any partial-open error for logging but
	// still return the usable resolver.
	return g, firstErr
}

// openGeoDB opens a single .mmdb and records its stat so a later reload can
// detect a changed file without re-parsing it.
func openGeoDB(path string) (*geoDB, error) {
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	db := &geoDB{reader: r}
	if fi, err := os.Stat(path); err == nil {
		db.mtime = fi.ModTime()
		db.size = fi.Size()
	}
	return db, nil
}

// Reload re-stats the two database files and, for any whose mtime or size
// changed since it was opened, opens the new copy and atomically swaps it in.
// The previous reader is retired and closed on the following Reload, never
// while a lookup could still be dereferencing its mmap.
//
// MaxMind's own updater writes to a temp file and renames it into place, so the
// swap observes a complete database; operators updating by hand MUST rename, not
// overwrite in place (an in-place write mutates the live mmap and can SIGBUS a
// running lookup regardless of this reload path — see docs/ENV-VARS.md).
//
// Reload is nil-safe and is intended to be called on a periodic ticker.
func (g *GeoResolver) Reload() {
	if g == nil {
		return
	}
	// Close anything retired by the previous Reload — in-flight lookups on it
	// have finished by now (a full ticker interval ago).
	g.retireMu.Lock()
	toClose := g.retired
	g.retired = nil
	g.retireMu.Unlock()
	for _, r := range toClose {
		_ = r.Close()
	}

	g.reloadOne(&g.country, geoCountryDB)
	g.reloadOne(&g.asn, geoASNDB)
}

func (g *GeoResolver) reloadOne(slot *atomic.Pointer[geoDB], name string) {
	path := filepath.Join(g.dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return // file went away or unreadable; keep serving the current mmap
	}
	cur := slot.Load()
	if cur != nil && fi.ModTime().Equal(cur.mtime) && fi.Size() == cur.size {
		return // unchanged
	}
	db, err := openGeoDB(path)
	if err != nil {
		return // partial/corrupt new file; keep the current one
	}
	slot.Store(db)
	if cur != nil {
		g.retireMu.Lock()
		g.retired = append(g.retired, cur.reader)
		g.retireMu.Unlock()
	}
}

// Enabled reports whether any database is loaded (i.e. lookups can return data).
func (g *GeoResolver) Enabled() bool {
	return g != nil && (g.country.Load() != nil || g.asn.Load() != nil)
}

// Country returns the ISO 3166-1 alpha-2 country code for ip, or "" when the
// resolver/DB is absent, the address is unparseable, or the IP isn't found
// (e.g. private/RFC1918 ranges, which GeoLite2 does not map).
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

// ASN returns the autonomous-system number for ip, or 0 when the resolver/DB is
// absent, the address is unparseable, or the IP isn't found.
func (g *GeoResolver) ASN(ip string) uint32 {
	if g == nil {
		return 0
	}
	db := g.asn.Load()
	if db == nil {
		return 0
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	rec, err := db.reader.ASN(parsed)
	if err != nil || rec == nil {
		return 0
	}
	return uint32(rec.AutonomousSystemNumber)
}

// Close releases the memory-mapped databases, including any retired but not yet
// closed by a pending reload. Nil-safe.
func (g *GeoResolver) Close() error {
	if g == nil {
		return nil
	}
	var err error
	if db := g.country.Swap(nil); db != nil {
		if e := db.reader.Close(); e != nil {
			err = e
		}
	}
	if db := g.asn.Swap(nil); db != nil {
		if e := db.reader.Close(); e != nil && err == nil {
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
