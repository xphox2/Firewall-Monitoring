package guardrails

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The NOC live feed (v0.11.269). These pin the behaviours that would silently
// regress: the feed arrives as its own named SSE event while the snapshot stays
// the default event; stored preferences go through whitelists; the list is
// diffed (sorted insertion) rather than rebuilt; only genuinely new items slide
// in; long-running episodes keep a stable key; hover-pause is limited to
// devices that can hover; screen readers get a throttled status line instead of
// a live region; and every row is a link.
func TestNOCFeed_Guards(t *testing.T) {
	js := readJS(t, "admin-noc.js")
	must := func(sub, why string) {
		t.Helper()
		if !strings.Contains(js, sub) {
			t.Errorf("admin-noc.js is missing %q — %s", sub, why)
		}
	}
	must("es.addEventListener('feed',", "the feed is a named SSE event")
	must("es.onmessage = function", "the snapshot stays the default SSE event")
	must("FEED_COUNTS.indexOf(c) !== -1 ? c : 20", "a stored count must be whitelisted")
	must("FEED_KINDS.indexOf(k) !== -1 ? k : 'all'", "a stored kind must be whitelisted")
	must("try { return window.localStorage.getItem(key); } catch (e)", "localStorage can throw (private mode)")
	must(".slice(0, feedState.count)", "the merged list is sliced to the chosen count")
	must("list.insertBefore(li, list.children[i] || null)", "items are inserted at their sorted position, never blindly prepended")
	must("(it.truncated ? 'old' : it.at)", "a truncated episode keys on its dedup key alone")
	must("'alert|' + it.id + '|' + it.at", "an alert re-fired in place (new timestamp) re-keys and animates")
	must("prev && !prev[e.key] && genMs - tms(e.it.at) <= NEW_WINDOW_MS", "only items absent from the last rendered frame AND recent animate")
	must("tms(feed.generated_at)", "the 20-minute horizon is measured on the server's clock")
	must("feedState.prevKeys = null;", "a fresh visit animates nothing on its first frame")
	must("window.matchMedia('(hover: hover)').matches", "hover-pause only where hovering exists, or a tap freezes the feed on touch")
	must("'focusin'", "keyboard focus inside the list pauses it")
	must("'#alert/' + encodeURIComponent(", "an alert row links to the alert detail route")
	must("'&src=' + encodeURIComponent(", "flow links encode their values")
	must("history.replaceState(null, '', location.pathname + location.search)", "a repeat click on the same alert reopens it")
	must("prefers-reduced-motion: reduce", "animations respect reduced motion")
	must("li.addEventListener('animationend', function () { li.className = ''; }, { once: true });", "a slide-in plays once; a later move must not replay it")
	must("feedState.hoverPaused = false;\n        feedState.focusPaused = false;", "no hover/focus hold survives leaving the page")
	must(`<span class="fwmon-sr-only">still firing</span>`, "the still-firing dot has screen-reader text")
	if prune, place := strings.Index(js, "else list.removeChild(li);"), strings.Index(js, "if (list.children[i] !== li) list.insertBefore("); prune < 0 || place < 0 || prune > place {
		t.Error("departed feed rows must be removed BEFORE the placement loop, or every row below a departure is moved and re-animated")
	}
	if regexp.MustCompile(`\bd\.detections\b`).MatchString(js) {
		t.Error("admin-noc.js still reads the removed snapshot.detections")
	}
	if strings.Contains(js, "console.") {
		t.Error("admin-noc.js logs through fwmonLog, not console (AUDIT-151)")
	}

	b, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	start, end := strings.Index(html, `id="page-noc"`), strings.Index(html, `id="page-alerts"`)
	if start < 0 || end < start {
		t.Fatal("NOC page markup not found")
	}
	noc := html[start:end]
	for _, want := range []string{`id="noc-feed-list"`, `id="noc-feed-status" role="status"`, `id="noc-feed-count"`,
		`id="noc-feed-kind"`, `id="noc-feed-silenced"`, `id="noc-feed-pause"`, `id="noc-threat-out"`, `id="noc-threat-in"`} {
		if !strings.Contains(noc, want) {
			t.Errorf("NOC page is missing %s", want)
		}
	}
	if strings.Contains(noc, `aria-live="`) {
		t.Error("NOC lists are rebuilt or diffed every few seconds; aria-live on them reads everything out repeatedly")
	}
	if strings.Index(noc, `id="noc-threat-out"`) > strings.Index(noc, `id="noc-threat-in"`) {
		t.Error("the outbound (talking back) list comes first")
	}
}
