package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDBPoolPerProcess_AUDIT036 pins the per-process DB pool sizing. The
// container runs api/poller/trap-receiver, each with its own pool; a single
// hardcoded SetMaxOpenConns(25) meant a 75-conn/host ceiling. Each daemon now
// sets a per-process default (15/10/5), overridable via DB_MAX_OPEN_CONNS, and
// NewDatabase reads cfg.Database.MaxOpenConns instead of a literal.
func TestDBPoolPerProcess_AUDIT036(t *testing.T) {
	wants := []struct{ file, substr string }{
		{"../../cmd/api/main.go", "cfg.Database.MaxOpenConns = 15"},
		{"../../cmd/poller/main.go", "cfg.Database.MaxOpenConns = 10"},
		{"../../cmd/trap-receiver/main.go", "cfg.Database.MaxOpenConns = 5"},
		{"../../internal/database/database.go", "cfg.Database.MaxOpenConns"},
		{"../../internal/config/config.go", `getIntEnv("DB_MAX_OPEN_CONNS"`},
	}
	for _, w := range wants {
		data, err := os.ReadFile(w.file)
		if err != nil {
			t.Fatalf("read %s: %v", w.file, err)
		}
		if !strings.Contains(string(data), w.substr) {
			t.Errorf("%s is missing %q (AUDIT-036: per-process DB pool sizing)", w.file, w.substr)
		}
	}

	db, err := os.ReadFile("../../internal/database/database.go")
	if err != nil {
		t.Fatalf("read database.go: %v", err)
	}
	if strings.Contains(string(db), "SetMaxOpenConns(25)") {
		t.Error("database.go still hardcodes SetMaxOpenConns(25) — AUDIT-036 wants the value from cfg.Database.MaxOpenConns")
	}
}
