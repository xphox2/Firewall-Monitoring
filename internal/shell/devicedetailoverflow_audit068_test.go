package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDeviceDetailOverflow_AUDIT068 is a static regression for the audit: on a
// narrow (mobile) viewport the device-detail stat grids (#systemStats /
// #extendedStats, auto-fit minmax(180–200px,1fr)) could burst the layout
// horizontally with no scroll affordance. The fix makes them overflow-x-auto
// scroll containers. (The data tables on this page are already wrapped in
// overflow-x-auto.)
func TestDeviceDetailOverflow_AUDIT068(t *testing.T) {
	const path = "../../web/admin/device-detail.html"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("device-detail.html not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, "AUDIT-068") {
		t.Errorf("device-detail.html missing the AUDIT-068 marker.")
	}
	// Each stat grid's element must carry overflow-x-auto on its own tag.
	for _, id := range []string{"systemStats", "extendedStats"} {
		re := regexp.MustCompile(`<div[^>]*\bid="` + id + `"[^>]*>`)
		m := re.FindString(body)
		if m == "" {
			// id may appear before the class on the same tag; fall back to a
			// line-scan match where the id and overflow-x-auto co-occur.
			m = findTagWithID(body, id)
		}
		if m == "" || !strings.Contains(m, "overflow-x-auto") {
			t.Errorf("device-detail.html #%s must be an overflow-x-auto scroll container (AUDIT-068). Got tag: %q", id, m)
		}
	}
}

// findTagWithID returns the <div ...> opening tag (across attribute order) that
// contains id="<id>", or "" if not found.
func findTagWithID(body, id string) string {
	needle := `id="` + id + `"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	start := strings.LastIndex(body[:idx], "<div")
	if start < 0 {
		return ""
	}
	end := strings.Index(body[idx:], ">")
	if end < 0 {
		return ""
	}
	return body[start : idx+end+1]
}
