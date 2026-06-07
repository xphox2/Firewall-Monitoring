package shell

import (
	"os"
	"strings"
	"testing"
)

// TestMigrationRunnerWired_AUDIT044 pins the versioned-migration adoption:
// a schema_migrations runner exists, the api binary exposes the migrate /
// migrate-status subcommands, and the dead, destructive IRC drop-and-recreate
// heuristic stays removed.
func TestMigrationRunnerWired_AUDIT044(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	// The runner + bookkeeping table + registry exist.
	mig := read("../../internal/database/migrations.go")
	for _, kw := range []string{"schema_migrations", "registeredMigrations", "func (d *Database) RunMigrations()", `name: "baseline"`} {
		if !strings.Contains(mig, kw) {
			t.Errorf("internal/database/migrations.go missing %q (AUDIT-044).", kw)
		}
	}

	// NewDatabase applies migrations through the runner, not the old migrate().
	db := read("../../internal/database/database.go")
	if !strings.Contains(db, "d.RunMigrations()") {
		t.Error("database.go NewDatabase must call d.RunMigrations() (AUDIT-044).")
	}

	// The api binary wires the explicit subcommands.
	main := read("../../cmd/api/main.go")
	for _, kw := range []string{`case "migrate":`, `case "migrate-status":`, "db.RunMigrations()"} {
		if !strings.Contains(main, kw) {
			t.Errorf("cmd/api/main.go missing %q (AUDIT-044): the migrate subcommands must be wired.", kw)
		}
	}

	// The destructive IRC drop-and-recreate heuristic must stay gone.
	base := read("../../internal/database/migrate.go")
	if strings.Contains(base, "recreating IRC tables") || strings.Contains(base, "DropTable") {
		t.Error("the IRC drop-and-recreate heuristic reappeared in migrate.go (AUDIT-044): it is dead + destructive and must stay removed.")
	}
}
