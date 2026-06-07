package shell

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readDatabasePackage concatenates every non-test .go file in
// internal/database. AUDIT-072 split the old monolithic database.go into
// per-domain files, so these static checks scan the whole package rather than a
// single file — they keep working as code moves between files.
func readDatabasePackage(t *testing.T) string {
	t.Helper()
	const dir = "../../internal/database"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("internal/database not found at %s; err: %v", dir, err)
	}
	var sb strings.Builder
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// TestErrorsIsForGormSentinels_AUDIT080 pins that the database package compares
// the gorm.ErrRecordNotFound sentinel via errors.Is, not a direct == / !=.
// Direct comparison works today but breaks silently the moment any caller
// wraps the error with %w — errors.Is unwraps, the operators don't.
func TestErrorsIsForGormSentinels_AUDIT080(t *testing.T) {
	body := readDatabasePackage(t)

	// No direct == / != comparison against the sentinel (either order).
	direct := regexp.MustCompile(`(==|!=)\s*gorm\.ErrRecordNotFound|gorm\.ErrRecordNotFound\s*(==|!=)`)
	if locs := direct.FindAllString(body, -1); len(locs) > 0 {
		t.Errorf("the database package still has %d direct == / != comparisons against gorm.ErrRecordNotFound (AUDIT-080): use errors.Is so wrapped errors still match. Examples: %v", len(locs), locs[:min(len(locs), 3)])
	}

	// And it must actually use errors.Is for the sentinel.
	if !regexp.MustCompile(`errors\.Is\(err, gorm\.ErrRecordNotFound\)`).MatchString(body) {
		t.Error("the database package no longer uses errors.Is(err, gorm.ErrRecordNotFound) (AUDIT-080): the sentinel check must go through errors.Is.")
	}
}
