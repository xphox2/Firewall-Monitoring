// Package serverhealth probes the fwmon server's OWN resources — the volumes,
// CPU and memory of the host running this software, as distinct from the
// firewalls it monitors.
//
// It exists because that distinction was invisible: on 2026-07-26 the database
// volume filled, Postgres crash-looped on "No space left on device", and nothing
// alerted, because the alert engine only ever evaluates SNMP-polled devices. The
// dashboard reported "/" — the container's overlay filesystem at 83% — while
// PGDATA sat on a bind mount at 100%.
package serverhealth

import (
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"gorm.io/gorm"
)

// Volume is one filesystem's usage. Free is carried alongside Percent because a
// percentage cannot answer "how long until full" on its own, and because the
// danger threshold for Postgres is an absolute (it needs room for a WAL segment)
// rather than a ratio.
type Volume struct {
	Path       string
	Percent    float64
	FreeBytes  uint64
	TotalBytes uint64
}

// DataDirLocator finds and remembers the database's data directory.
//
// The path is CACHED after the first success, and that is load-bearing rather
// than an optimisation: in the endgame of the outage Postgres was crash-looping,
// so `SHOW data_directory` would have failed — and the one volume that mattered
// would have gone unwatched at exactly the moment it was full. The path does not
// change for a running deployment, so remembering it keeps the check alive
// through a dead database.
type DataDirLocator struct {
	mu       sync.Mutex
	cached   string
	lastWarn time.Time
}

// WarnInterval bounds how often a failed lookup is reported. A sync.Once would
// log once per process and then go quiet forever — and a monitoring probe that
// fails silently is the very shape of the incident this package exists for.
const WarnInterval = time.Hour

// DataDirectory returns the database's data directory.
//
// The bool reports whether a path is available at all. The error is non-nil only
// when the LOOKUP ITSELF failed — which means monitoring is broken and deserves
// attention. A nil error with ok=false is the benign case: this build is not on
// Postgres, or there is simply nothing cached yet.
//
// data_directory is a superuser-only GUC, so a role lacking pg_read_all_settings
// gets 42501 here. That is a fault, not a quiet no-op.
func (l *DataDirLocator) DataDirectory(g *gorm.DB) (string, bool, error) {
	if g == nil || g.Dialector == nil || g.Dialector.Name() != "postgres" {
		return "", false, nil
	}
	return l.directory(func() (string, error) {
		var dir string
		err := g.Raw("SHOW data_directory").Scan(&dir).Error
		return dir, err
	})
}

// dataDirLookup performs the underlying data_directory read. Extracted so the
// cache/fallback logic can be exercised without a live Postgres.
type dataDirLookup func() (string, error)

// directory applies the cache/fallback policy to a lookup result. On a
// successful, non-empty read it caches and returns the fresh path; on any
// failure (or an empty scan) it falls back to the last cached path — returning
// ok=true with the original error passed through — so a crash-looping database
// does not blind the check. With nothing cached yet it reports ok=false.
func (l *DataDirLocator) directory(lookup dataDirLookup) (string, bool, error) {
	dir, err := lookup()
	if err == nil && strings.TrimSpace(dir) != "" {
		l.mu.Lock()
		l.cached = dir
		l.mu.Unlock()
		return dir, true, nil
	}

	// Fall back to the last known path so a crash-looping database does not
	// blind the check.
	l.mu.Lock()
	cached := l.cached
	l.mu.Unlock()
	if cached != "" {
		return cached, true, err
	}
	return "", false, err
}

// ShouldWarn rate-limits the "cannot read data_directory" report.
func (l *DataDirLocator) ShouldWarn(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastWarn) < WarnInterval {
		return false
	}
	l.lastWarn = now
	return true
}

// Usage reports a filesystem's usage. ok is false when the path is not visible
// to this process — an external database server, or a split-container
// deployment. That is a legitimately quiet case, distinct from a failed lookup.
func Usage(path string) (Volume, bool) {
	if strings.TrimSpace(path) == "" {
		return Volume{}, false
	}
	du, err := disk.Usage(path)
	if err != nil || du == nil {
		return Volume{}, false
	}
	return Volume{
		Path:       path,
		Percent:    du.UsedPercent,
		FreeBytes:  du.Free,
		TotalBytes: du.Total,
	}, true
}

// RootPath is the root filesystem. Watched unconditionally and independently of
// the database probe: a fault locating PGDATA must never leave the server
// entirely unwatched.
const RootPath = "/"
