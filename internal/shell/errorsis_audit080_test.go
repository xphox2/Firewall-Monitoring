package shell

import (
	"os"
	"regexp"
	"testing"
)

// TestErrorsIsForGormSentinels_AUDIT080 pins that database.go compares the
// gorm.ErrRecordNotFound sentinel via errors.Is, not a direct == / !=.
// Direct comparison works today but breaks silently the moment any caller
// wraps the error with %w — errors.Is unwraps, the operators don't.
func TestErrorsIsForGormSentinels_AUDIT080(t *testing.T) {
	const path = "../../internal/database/database.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("database.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	// No direct == / != comparison against the sentinel (either order).
	direct := regexp.MustCompile(`(==|!=)\s*gorm\.ErrRecordNotFound|gorm\.ErrRecordNotFound\s*(==|!=)`)
	if locs := direct.FindAllString(body, -1); len(locs) > 0 {
		t.Errorf("database.go still has %d direct == / != comparisons against gorm.ErrRecordNotFound (AUDIT-080): use errors.Is so wrapped errors still match. Examples: %v", len(locs), locs[:min(len(locs), 3)])
	}

	// And it must actually use errors.Is for the sentinel.
	if !regexp.MustCompile(`errors\.Is\(err, gorm\.ErrRecordNotFound\)`).MatchString(body) {
		t.Error("database.go no longer uses errors.Is(err, gorm.ErrRecordNotFound) (AUDIT-080): the sentinel check must go through errors.Is.")
	}
}
