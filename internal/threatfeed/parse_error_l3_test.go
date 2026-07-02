package threatfeed

import (
	"strings"
	"testing"
)

// TestParse_SurfacesScannerError_L3 pins the 2026-07-01 audit L3 fix: a line
// longer than the scanner buffer (bufio.ErrTooLong — e.g. a giant single-line
// HTML error page served with 200) must be returned as an error, not silently
// swallowed as a successful truncated parse.
func TestParse_SurfacesScannerError_L3(t *testing.T) {
	// One line far exceeding the 1 MiB scanner buffer, no newline.
	huge := strings.Repeat("A", 2<<20)
	_, err := Parse(strings.NewReader(huge), Feed{Name: "bad"})
	if err == nil {
		t.Fatal("Parse must return the scanner error for an over-long line, not nil")
	}

	// A normal feed still parses cleanly with no error.
	if _, err := Parse(strings.NewReader("203.0.113.0/24\n198.51.100.5\n"), Feed{Name: "ok"}); err != nil {
		t.Errorf("clean feed returned error: %v", err)
	}
}
