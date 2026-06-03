package shell

import (
	"os"
	"strings"
	"testing"
)

// servedStyleFiles are the CSS/HTML/JS files that contribute foreground text
// colors to the admin + public UI.
var servedStyleFiles = []string{
	"../../cmd/api/static/css/admin-shared.css",
	"../../cmd/api/static/css/admin-design-system.css",
	"../../cmd/api/static/css/styles.css",
	"../../cmd/api/static/css/tailwind.css",
	"../../cmd/api/static/css/admin-device-detail.css",
	"../../web/admin/admin.html",
	"../../web/admin/device-detail.html",
	"../../web/admin/connection-detail.html",
	"../../web/admin/irc.html",
	"../../web/admin/sites.html",
	"../../web/admin/probes.html",
	"../../web/admin/probe-pending.html",
	"../../web/public/index.html",
	"../../cmd/api/static/js/admin-common.js",
	"../../cmd/api/static/js/admin-main.js",
	"../../cmd/api/static/js/admin-device-detail.js",
	"../../cmd/api/static/js/admin-connection-detail.js",
	"../../cmd/api/static/js/public-dashboard.js",
	"../../cmd/api/static/js/diagram-panels.js",
	"../../cmd/api/static/js/diagram-cytoscape.js",
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// textContextHits returns line-ish offsets where `hex` is used as a foreground
// TEXT color: either a Tailwind `text-[hex]` utility, or the `color:` property
// (NOT `*-color:` like border-color/background-color, and NOT a quoted chart
// value `color: 'hex'`).
func textContextHits(body, hex string) int {
	n := 0
	if strings.Contains(body, "text-["+hex+"]") {
		n++
	}
	for _, pat := range []string{"color:" + hex, "color: " + hex} {
		i := 0
		for {
			j := strings.Index(body[i:], pat)
			if j < 0 {
				break
			}
			pos := i + j
			i = pos + 1
			if pos == 0 {
				n++
				continue
			}
			c := body[pos-1]
			if c == '-' || isASCIILetter(c) {
				continue // border-color / background-color / bgcolor etc.
			}
			n++
		}
	}
	return n
}

// TestColorContrast_NoDarkText484_AUDIT066 pins that #484f58 — which fails WCAG
// AA as readable text on the dark UI backgrounds — is no longer used in any
// foreground-text context. Decorative uses (borders, chart axis ticks which are
// the quoted '#484f58' form) are intentionally left untouched. The sweep is in
// scripts/audit_brighten_color.py.
func TestColorContrast_NoDarkText484_AUDIT066(t *testing.T) {
	for _, path := range servedStyleFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found; err: %v", path, err)
			continue
		}
		if hits := textContextHits(string(data), "#484f58"); hits > 0 {
			t.Errorf("%s still uses #484f58 as foreground text in %d place(s) (AUDIT-066): WCAG AA fail; use #8b949e. Decorative borders/chart ticks are fine.", path, hits)
		}
	}
}
