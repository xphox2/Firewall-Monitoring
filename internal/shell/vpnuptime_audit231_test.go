package shell

import (
	"regexp"
	"strings"
	"testing"
)

// TestDeviceDetailVpnUptime_UsesSharedHelper_AUDIT231 pins that the device-detail
// VPN table renders tunnel_uptime through the shared AC.formatTunnelUptime
// (which treats the value as SECONDS, its actual unit) rather than a local
// helper that divides by 100. The pre-fix local formatVpnUptime did
// `Math.floor(hundredths / 100)`, rendering a 53-minute OPNsense tunnel as
// "0m" — the one renderer missed when the shared helper was introduced.
func TestDeviceDetailVpnUptime_UsesSharedHelper_AUDIT231(t *testing.T) {
	js := readJS(t, "admin-device-detail.js")

	// The tunnel-uptime cell must call the shared helper.
	if !strings.Contains(js, "AC.formatTunnelUptime(v.tunnel_uptime)") {
		t.Error("admin-device-detail.js renderVPN no longer calls AC.formatTunnelUptime(v.tunnel_uptime) — a local uptime formatter reintroduces the /100 bug (AUDIT-231).")
	}

	// No renderer in this file may divide tunnel_uptime (a seconds field) by 100.
	// Catch a `<hundredths-ish var> / 100` inside a function whose body mentions
	// tunnel_uptime — approximated by banning the exact pre-fix expression.
	if regexp.MustCompile(`Math\.floor\(\s*hundredths\s*/\s*100\s*\)`).MatchString(js) {
		t.Error("admin-device-detail.js still divides a tunnel-uptime value by 100 — tunnel_uptime is SECONDS, not hundredths (AUDIT-231).")
	}

	// The shared helper must define tunnel uptime as seconds (no /100 inside it).
	common := readJS(t, "admin-common.js")
	i := strings.Index(common, "function formatTunnelUptime(")
	if i < 0 {
		t.Fatal("admin-common.js no longer defines formatTunnelUptime — the shared seconds-based helper AUDIT-231 depends on is gone.")
	}
	body := common[i:]
	if end := strings.Index(body, "\n    }"); end >= 0 {
		body = body[:end]
	}
	if strings.Contains(body, "/ 100") {
		t.Error("formatTunnelUptime divides by 100 — it must treat tunnel_uptime as SECONDS (AUDIT-231).")
	}
}
