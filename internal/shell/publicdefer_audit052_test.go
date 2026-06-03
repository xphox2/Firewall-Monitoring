package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPublicDashboard_LibsDeferred_AUDIT052 is a static regression for the
// audit: the public wallboard (`web/public/index.html`) loaded
// chart.umd.min.js, chartjs-plugin-zoom.min.js and gridstack-all.min.js
// (~290 KB) WITHOUT `defer`, blocking parsing/first paint on exactly the page
// where time-to-render matters most. The fix adds `defer` to all three;
// `defer` scripts run in document order so public-dashboard.js (also defer,
// after them) still initializes only once the libs are present.
func TestPublicDashboard_LibsDeferred_AUDIT052(t *testing.T) {
	const path = "../../web/public/index.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("public index.html not found at %s; err: %v", path, err)
	}
	body := string(data)

	libs := []string{
		"chart.umd.min.js",
		"chartjs-plugin-zoom.min.js",
		"gridstack-all.min.js",
	}
	for _, lib := range libs {
		want := `<script defer src="/static/js/` + lib + `">`
		if !strings.Contains(body, want) {
			t.Errorf("public index.html: %s is not loaded with defer (AUDIT-052): expected %q. Blocking libs delay first paint on the wallboard.", lib, want)
		}
	}
	if !strings.Contains(body, "AUDIT-052") {
		t.Errorf("public index.html missing the AUDIT-052 marker comment (traceability).")
	}
}
