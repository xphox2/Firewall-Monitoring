package shell

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDatabaseFileSplit_AUDIT072 pins that the 4,887-line monolith
// internal/database/database.go stays split into cohesive per-domain files. It
// guards two regressions: (1) database.go regrowing into a mega-file, and (2) a
// future edit collapsing the domain files back together. The split is pure code
// organization (same package) — the real behavioural safety net is the full
// `go test ./...`; this just keeps the file structure from drifting back.
func TestDatabaseFileSplit_AUDIT072(t *testing.T) {
	const dir = "../../internal/database"

	// database.go must stay lean (core lifecycle only). It was 4,887 lines.
	const maxCoreLines = 1000
	if n := countLines(t, filepath.Join(dir, "database.go")); n > maxCoreLines {
		t.Errorf("internal/database/database.go is %d lines (> %d) (AUDIT-072): it should hold only the core (Database struct, NewDatabase, locks, Close) — move domain methods into a per-domain sibling file.", n, maxCoreLines)
	}

	// The core file must still own the connection lifecycle.
	core := readFile(t, filepath.Join(dir, "database.go"))
	for _, kw := range []string{"type Database struct", "func NewDatabase(", "func (d *Database) Close("} {
		if !strings.Contains(core, kw) {
			t.Errorf("internal/database/database.go no longer contains %q (AUDIT-072): the core lifecycle must stay in database.go.", kw)
		}
	}

	// The per-domain files the split created must exist.
	for _, f := range []string{
		"migrate.go", "telemetry.go", "events.go", "devices.go", "sites_probes.go",
		"ping.go", "charts.go", "flows.go", "stats.go", "alerts.go", "connection_detail.go",
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("internal/database/%s is missing (AUDIT-072): the domain split must keep this file.", f)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		n++
	}
	return n
}
