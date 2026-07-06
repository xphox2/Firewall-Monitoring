package classify

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

// Bundled free geolocation databases (DB-IP Lite, licensed CC BY 4.0 — see
// NOTICE / the attribution surfaced in the admin UI). These ship inside the
// binary so geo/ASN enrichment works out of the box with no license key and no
// mounted files. The paid live-update path (MaxMind) writes newer databases into
// GEOIP_DB_DIR, which take precedence over these at resolve time (see geo.go).
//
//go:embed geoipdata/dbip-country-lite.mmdb geoipdata/dbip-asn-lite.mmdb
var bundledGeoIP embed.FS

const (
	bundledCountryDB = "dbip-country-lite.mmdb"
	bundledASNDB     = "dbip-asn-lite.mmdb"
)

// ensureBundle extracts the embedded DB-IP Lite databases to a writable cache
// directory and returns that directory. A file is (re)written only when absent
// or a different size, so repeated startups are cheap. geoip2.Open memory-maps a
// real file, so the databases must live on disk — they can't be opened straight
// from the embed.FS.
//
// cacheDir defaults to a per-OS temp subdir when empty. GEOIP_DB_DIR itself is
// deliberately NOT used as the cache: in Docker it is a read-only volume mount.
func ensureBundle(cacheDir string) (string, error) {
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "fwmon-geoip")
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("geoip bundle cache dir: %w", err)
	}
	for _, name := range []string{bundledCountryDB, bundledASNDB} {
		data, err := bundledGeoIP.ReadFile("geoipdata/" + name)
		if err != nil {
			return "", fmt.Errorf("read embedded %s: %w", name, err)
		}
		dst := filepath.Join(cacheDir, name)
		if fi, err := os.Stat(dst); err == nil && fi.Size() == int64(len(data)) {
			continue // already extracted, same size
		}
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			return "", fmt.Errorf("rename %s: %w", name, err)
		}
	}
	return cacheDir, nil
}
