package serverhealth

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// These tests guard the two load-bearing invariants derived from the
// 2026-07-26 disk-full outage: the data-directory lookup must keep the
// database volume watched through a crash-looping Postgres (cache fallback),
// and it must never claim success with an empty/unknown path.

func TestDataDirLocator_CachesOnSuccess(t *testing.T) {
	var l DataDirLocator
	const path = "/var/lib/postgresql/data"

	dir, ok, err := l.directory(func() (string, error) { return path, nil })
	if dir != path || !ok || err != nil {
		t.Fatalf("directory() = (%q, %v, %v), want (%q, true, nil)", dir, ok, err, path)
	}
	l.mu.Lock()
	cached := l.cached
	l.mu.Unlock()
	if cached != path {
		t.Fatalf("cached = %q, want %q", cached, path)
	}
}

func TestDataDirLocator_FallsBackToCachedPathOnLookupError(t *testing.T) {
	var l DataDirLocator
	const path = "/var/lib/postgresql/data"

	// Prime the cache with a success.
	if _, ok, err := l.directory(func() (string, error) { return path, nil }); !ok || err != nil {
		t.Fatalf("priming success: ok=%v err=%v", ok, err)
	}

	connErr := errors.New("dial tcp: connection refused")
	dir, ok, err := l.directory(func() (string, error) { return "", connErr })
	if dir != path {
		t.Fatalf("dir = %q, want cached %q (crash-loop must not blind the check)", dir, path)
	}
	if !ok {
		t.Fatal("ok = false, want true — the cached path IS still being watched")
	}
	if !errors.Is(err, connErr) {
		t.Fatalf("err = %v, want the original lookup error passed through (not swallowed)", err)
	}
}

func TestDataDirLocator_NoFallbackWhenNothingCachedYet(t *testing.T) {
	var l DataDirLocator
	connErr := errors.New("dial tcp: connection refused")

	dir, ok, err := l.directory(func() (string, error) { return "", connErr })
	if dir != "" {
		t.Fatalf("dir = %q, want empty", dir)
	}
	if ok {
		t.Fatal("ok = true with an empty path — must NOT claim a volume is watched when none is known")
	}
	if !errors.Is(err, connErr) {
		t.Fatalf("err = %v, want the lookup error", err)
	}
}

func TestDataDirLocator_EmptyStringScanTreatedAsFailure(t *testing.T) {
	var l DataDirLocator
	const path = "/var/lib/postgresql/data"

	// Prime a good cached value.
	if _, ok, err := l.directory(func() (string, error) { return path, nil }); !ok || err != nil {
		t.Fatalf("priming success: ok=%v err=%v", ok, err)
	}

	// A blank scan with a nil error must not overwrite the good cache and must
	// not be reported as a fresh success.
	dir, ok, err := l.directory(func() (string, error) { return "   ", nil })
	if dir != path {
		t.Fatalf("dir = %q, want cached %q — a blank scan must not overwrite a good path", dir, path)
	}
	if !ok {
		t.Fatal("ok = false, want true — falls back to the cached path")
	}
	if err != nil {
		t.Fatalf("err = %v, want nil (the lookup itself did not error)", err)
	}
	l.mu.Lock()
	cached := l.cached
	l.mu.Unlock()
	if cached != path {
		t.Fatalf("cached = %q, want %q — blank scan corrupted the cache", cached, path)
	}
}

func TestDataDirLocator_EmptyStringScanNoCacheReportsFailure(t *testing.T) {
	var l DataDirLocator
	// A blank scan with nothing cached is not a success.
	dir, ok, err := l.directory(func() (string, error) { return "", nil })
	if dir != "" || ok || err != nil {
		t.Fatalf("directory() = (%q, %v, %v), want (\"\", false, nil)", dir, ok, err)
	}
}

func TestDataDirLocator_NonPostgresDialectorShortCircuits(t *testing.T) {
	// A real non-postgres dialector (sqlite name is "sqlite") must short-circuit
	// regardless of any cached value.
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal("open sqlite:", err)
	}
	if name := g.Dialector.Name(); name == "postgres" {
		t.Fatalf("test DB dialector is %q; expected a non-postgres name to drive the short-circuit", name)
	}

	var l DataDirLocator
	l.cached = "/some/cached/path" // must be ignored on a non-postgres build

	dir, ok, errOut := l.DataDirectory(g)
	if dir != "" || ok || errOut != nil {
		t.Fatalf("DataDirectory(sqlite) = (%q, %v, %v), want (\"\", false, nil)", dir, ok, errOut)
	}

	// A nil *gorm.DB is the same benign short-circuit.
	dir, ok, errOut = l.DataDirectory(nil)
	if dir != "" || ok || errOut != nil {
		t.Fatalf("DataDirectory(nil) = (%q, %v, %v), want (\"\", false, nil)", dir, ok, errOut)
	}
}

func TestDataDirLocator_ShouldWarn_RateLimited(t *testing.T) {
	var l DataDirLocator
	t0 := time.Now()

	if !l.ShouldWarn(t0) {
		t.Fatal("first ShouldWarn(t0) = false, want true")
	}
	if l.ShouldWarn(t0.Add(30 * time.Minute)) {
		t.Fatal("ShouldWarn(t0+30m) = true, want false (inside the 1h WarnInterval)")
	}
	if !l.ShouldWarn(t0.Add(61 * time.Minute)) {
		t.Fatal("ShouldWarn(t0+61m) = false, want true (past the 1h WarnInterval)")
	}
}
