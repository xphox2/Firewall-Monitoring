package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdvisoryLockKeysDistinct: every Postgres advisory lock in the server is
// keyed by one of these constants, and two sharing a value would silently
// serialize unrelated work — or, for the never-released startup try-lock against
// a blocking acquire, deadlock. Earlier prose lists of "distinct from" keys went
// stale as keys were added; this is the list now, and the parse below fails the
// test if a *LockKey constant exists that the list does not cover.
func TestAdvisoryLockKeysDistinct(t *testing.T) {
	keys := map[string]int64{
		"startupMigrationLockKey": startupMigrationLockKey,
		"pollerWorkLockKey":       pollerWorkLockKey,
		"flowSummaryLockKey":      flowSummaryLockKey,
		"maintenanceLockKey":      maintenanceLockKey,
		"apiSingletonLockKey":     apiSingletonLockKey,
		"devicePurgeLockKey":      devicePurgeLockKey,
		"migrationLockKey":        migrationLockKey,
	}
	seen := make(map[int64]string, len(keys))
	for name, k := range keys {
		if k == 0 {
			t.Errorf("%s is zero", name)
		}
		if other, dup := seen[k]; dup {
			t.Errorf("%s and %s share advisory key %#x", name, other, k)
		}
		seen[k] = name
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for _, id := range vs.Names {
				if strings.HasSuffix(id.Name, "LockKey") {
					if _, listed := keys[id.Name]; !listed {
						t.Errorf("%s (%s) is not in this test's key list", id.Name, f)
					}
				}
			}
			return true
		})
	}
}
