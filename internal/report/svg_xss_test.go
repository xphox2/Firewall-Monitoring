package report

import (
	"strings"
	"testing"
)

// TestAlertTimelineSVGEscapesTooltip pins H-12: the alert bucket Tooltip and
// Label are DB-sourced and interpolated into <title>/<text> in the SVG; they
// must be HTML-escaped so a crafted alert name/type cannot inject markup.
func TestAlertTimelineSVGEscapesTooltip(t *testing.T) {
	buckets := []AlertBucket{
		{Label: `<img src=x onerror=alert(1)>`, Count: 1, Crit: true, Tooltip: `<script>alert(1)</script>`},
	}
	svg := string(RenderAlertTimelineSVG(buckets, ThemeByName("")))

	for _, raw := range []string{"<script>", "<img src=x"} {
		if strings.Contains(svg, raw) {
			t.Errorf("SVG contains unescaped %q — tooltip/label not HTML-escaped", raw)
		}
	}
	if !strings.Contains(svg, "&lt;script&gt;") {
		t.Error("expected the escaped tooltip (&lt;script&gt;) in the output")
	}
}
