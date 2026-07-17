package shell

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestTrafficRangeSelectOptionsAreValidHours guards the connection-detail
// traffic chart's range dropdown against regressing into a decorative control:
// the pre-fix server whitelist ({"1h","24h","7d","30d"}) recognized NONE of
// the hour-numeric values the dropdown sends, so every selection silently
// served the 24h window. The endpoint now parses numeric hours; every option
// value must stay a positive number of hours within the 400-day chart cap so
// no option can silently coerce to the default again.
func TestTrafficRangeSelectOptionsAreValidHours(t *testing.T) {
	const path = "../../web/admin/connection-detail.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("connection-detail.html not found at %s (tests must run from the package root); err: %v", path, err)
	}

	selectRe := regexp.MustCompile(`(?s)<select[^>]*id="traffic-range-select"[^>]*>(.*?)</select>`)
	m := selectRe.FindSubmatch(data)
	if m == nil {
		t.Fatalf("traffic-range-select not found in %s", path)
	}
	optionRe := regexp.MustCompile(`<option\s+value="([^"]*)"`)
	opts := optionRe.FindAllSubmatch(m[1], -1)
	if len(opts) == 0 {
		t.Fatalf("traffic-range-select has no <option value=...> entries")
	}
	const maxHours = 400 * 24 // charts.go maxChartWindow
	for _, o := range opts {
		val := string(o[1])
		h, err := strconv.ParseFloat(val, 64)
		if err != nil || h <= 0 || h > maxHours {
			t.Errorf("traffic-range-select option value %q is not a positive hour count within the %dh chart cap — the server would silently fall back to 24h", val, maxHours)
		}
	}
}
