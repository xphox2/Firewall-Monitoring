package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDashboardHealthPolledOnce guards against the duplicate-poller regression.
//
// The dashboard used to be refreshed by TWO independent 30s timers: one inside
// FwmonDashboard (admin-dashboard-modules.js) and a second in admin-main.js that
// called loadDashboard() -> FwmonDashboard.load() -> fetchData(). They started at
// different moments, so an open dashboard issued roughly two /dashboard/health
// requests per 30s instead of one, and the admin-main.js copy also skipped the
// `!customizing` guard the module's own timer applies.
//
// FwmonDashboard owns this poll. Nav-time loading (the `case 'dashboard'` branch
// in loadPageData) is a different thing and stays.
func TestDashboardHealthPolledOnce(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(b)
	}

	main := read("../../cmd/api/static/js/admin-main.js")
	// pollWhenVisible on a dashboard-active check is exactly the shape that was
	// removed. Matching the guard rather than the call keeps this from tripping
	// on the unrelated connection/syslog timers in the same file.
	if strings.Contains(main, "activePage.id === 'page-dashboard') loadDashboard()") {
		t.Error("admin-main.js polls the dashboard again — FwmonDashboard (admin-dashboard-modules.js) owns that timer; two of them double every /dashboard/health request.")
	}

	mods := read("../../cmd/api/static/js/admin-dashboard-modules.js")
	// Note the trailing paren: the file also feature-detects the helper
	// (`if (!pollStarted && AC.pollWhenVisible)`), which is not a registration.
	if n := strings.Count(mods, "AC.pollWhenVisible("); n != 1 {
		t.Errorf("admin-dashboard-modules.js registers %d visibility polls, want exactly 1 (the /dashboard/health refresh).", n)
	}

	// The composite is served from a background snapshot, so the client must be
	// able to tell "no snapshot yet" from real data. Rendering the sentinel as
	// data paints a false "Database — Reachable: No" on every restart.
	if !strings.Contains(mods, "'computing'") {
		t.Error("admin-dashboard-modules.js must handle the {\"status\":\"computing\"} sentinel from /dashboard/health; feeding it to the module bodies reports a healthy system as down.")
	}
	// A failed load must be recoverable rather than a permanent spinner.
	if !strings.Contains(mods, "data-dash-retry") {
		t.Error("admin-dashboard-modules.js must offer a retry when /dashboard/health fails; the silent catch is what left 'Loading system health…' on screen forever.")
	}
}
