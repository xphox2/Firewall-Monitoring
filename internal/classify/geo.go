package classify

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/oschwald/geoip2-golang"
)

// Standard MaxMind GeoLite2 filenames, looked up under the configured DB dir.
const (
	geoCountryDB = "GeoLite2-Country.mmdb"
	geoASNDB     = "GeoLite2-ASN.mmdb"
)

// GeoResolver enriches a flow's addresses with an ISO country code and an
// autonomous-system number from MaxMind GeoLite2 databases. The .mmdb files are
// memory-mapped and the underlying reader is goroutine-safe, so a single
// resolver is shared across the ingest path with no per-lookup allocation.
//
// Every method is nil-safe: a nil *GeoResolver (geo disabled, or the DB files
// were absent at startup) returns empty results rather than panicking, so
// callers never need to branch on whether geo is configured.
type GeoResolver struct {
	country *geoip2.Reader
	asn     *geoip2.Reader
}

// NewGeoResolver opens the GeoLite2 Country and ASN databases under dir. When
// enabled is false it returns (nil, nil) — a disabled, nil-safe resolver. When
// enabled but a file can't be opened it returns (nil, err) so the caller can log
// the reason and continue with geo enrichment off (the columns stay empty).
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
	g := &GeoResolver{}
	var firstErr error
	if r, err := geoip2.Open(filepath.Join(dir, geoCountryDB)); err == nil {
		g.country = r
	} else {
		firstErr = fmt.Errorf("open %s: %w", geoCountryDB, err)
	}
	if r, err := geoip2.Open(filepath.Join(dir, geoASNDB)); err == nil {
		g.asn = r
	} else if firstErr == nil {
		firstErr = fmt.Errorf("open %s: %w", geoASNDB, err)
	}
	if g.country == nil && g.asn == nil {
		return nil, firstErr
	}
	// At least one DB opened; surface any partial-open error for logging but
	// still return the usable resolver.
	return g, firstErr
}

// Enabled reports whether any database is loaded (i.e. lookups can return data).
func (g *GeoResolver) Enabled() bool {
	return g != nil && (g.country != nil || g.asn != nil)
}

// Country returns the ISO 3166-1 alpha-2 country code for ip, or "" when the
// resolver/DB is absent, the address is unparseable, or the IP isn't found
// (e.g. private/RFC1918 ranges, which GeoLite2 does not map).
func (g *GeoResolver) Country(ip string) string {
	if g == nil || g.country == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	rec, err := g.country.Country(parsed)
	if err != nil || rec == nil {
		return ""
	}
	return rec.Country.IsoCode
}

// ASN returns the autonomous-system number for ip, or 0 when the resolver/DB is
// absent, the address is unparseable, or the IP isn't found.
func (g *GeoResolver) ASN(ip string) uint32 {
	if g == nil || g.asn == nil {
		return 0
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	rec, err := g.asn.ASN(parsed)
	if err != nil || rec == nil {
		return 0
	}
	return uint32(rec.AutonomousSystemNumber)
}

// Close releases the memory-mapped databases. Nil-safe.
func (g *GeoResolver) Close() error {
	if g == nil {
		return nil
	}
	var err error
	if g.country != nil {
		if e := g.country.Close(); e != nil {
			err = e
		}
	}
	if g.asn != nil {
		if e := g.asn.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}
