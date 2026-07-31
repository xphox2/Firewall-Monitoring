package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The connection-detail view renders a device pair's tunnels twice: once in the
// map side-panel (diagram-panels.js, grouped parent/child) and once on the
// standalone page (admin-connection-detail.js, flat). They are separate
// renderers over the SAME payload, and every bug fixed in v0.11.193 existed in
// both — a fix applied to one is a half fix.
//
// These pins do not prove the renderers are correct; a regex cannot. They exist
// so that the shared decisions cannot be silently DELETED, which is how the
// tri-state status ended up living in one renderer out of four. Functional
// correctness is the Playwright harness's job.

// A row's status is a claim or the absence of one. Neither page may decide that
// on its own, because two independent opinions is exactly how "unknown" came to
// render as DOWN on the flat table while the panel had already been fixed.
func TestConnDetail_BothRenderersUseTheSharedStateHelper(t *testing.T) {
	for _, f := range []struct {
		name string
		js   string
		fn   string
	}{
		{"diagram-panels.js", readPanelJS(t), `renderPanelTunnelTable\(tableId, tunnels, deviceId, family, agreed\) \{`},
		{"admin-connection-detail.js", readConnDetailJS(t), `renderTunnelTable\(tableId, tunnels, deviceId, agreed\) \{`},
	} {
		body := funcBody(t, f.js, f.fn)
		if !strings.Contains(body, "AC.tunnelStateBadge(") {
			t.Errorf("%s: the tunnel table renders a status badge without the shared "+
				"helper — this renderer can collapse 'unknown' into DOWN again", f.name)
		}
		if regexp.MustCompile(`\?\s*'?<?span class="badge up"`).MatchString(body) {
			t.Errorf("%s: a two-way up/down badge ternary is back in the tunnel table", f.name)
		}
		if !strings.Contains(body, "AC.tunnelCountersObserved(") {
			t.Errorf("%s: byte cells no longer distinguish an observed zero from a writer "+
				"that counts nothing, so a config row reads as '0 B' again", f.name)
		}
	}
}

// The counters predicate must not be reduced to "bytes are zero". Two OPNsense
// children of connection 23984 legitimately report 0/0 while up — that IS an
// observation, and blanking it would hide a live selector carrying no traffic.
func TestConnDetail_ObservedZeroIsNotBlanked(t *testing.T) {
	body := funcBody(t, readCommonJS(t), `tunnelCountersObserved\(row\) \{`)
	if !strings.Contains(body, "tunnelClaim(row) !== ''") {
		t.Error("tunnelCountersObserved no longer consults the state claim, so an 'up' row " +
			"reporting a genuine 0/0 renders as '—' — hiding a live selector that has " +
			"simply carried no traffic yet")
	}
}

// Remote IP must never be read positionally. Nothing between the query and the
// renderer applies an ORDER BY, and on a FortiGate the config rows carry no
// remote_ip at all — so `[0]` rendered "-" while the SNMP row beside it knew
// the peer address, nondeterministically.
func TestConnDetail_RemoteIPIsNotPositional(t *testing.T) {
	js := readPanelJS(t)
	if regexp.MustCompile(`g\.phase2\[0\]\s*[.\[]\s*'?remote_ip`).MatchString(js) {
		t.Error("remote IP is read from group member 0 again; the row order is whatever " +
			"the query plan returned, and member 0 may carry no remote_ip")
	}
	if !strings.Contains(js, "g.phase2.find(t => t.remote_ip)") {
		t.Error("remote IP no longer resolves to the first member that actually reports one")
	}
}

// One tunnel is one tunnel from either end. Summing the two sides reported 2 on
// the panel and 9 on the standalone page for the single tunnel of conn 23984.
func TestConnDetail_TunnelCountIsNotSummedAcrossEnds(t *testing.T) {
	for _, f := range []struct{ name, js string }{
		{"diagram-panels.js", readPanelJS(t)},
		{"admin-connection-detail.js", readConnDetailJS(t)},
	} {
		if !strings.Contains(f.js, "countLogicalTunnels(") {
			t.Errorf("%s: tunnel count no longer goes through countLogicalTunnels", f.name)
		}
		if regexp.MustCompile(`countPhase1\([^)]*\)\s*\+\s*countPhase1\(`).MatchString(f.js) ||
			regexp.MustCompile(`source_tunnels\.length\s*:\s*0\)\s*\+`).MatchString(f.js) {
			t.Errorf("%s: the two ends' tunnel counts are added again — a device pair with "+
				"one tunnel reports more than one", f.name)
		}
	}
}

// The Phase 2 tab is gone from both pages. Its markup lived in two places and
// one reference to it was UNGUARDED on the direct-family branch, so a partial
// removal throws on every ethernet/LAG/l2vlan/bridge connection and takes the
// Interfaces and Evidence views down with it.
func TestConnDetail_Phase2TabFullyRemoved(t *testing.T) {
	for _, f := range []struct{ name, js string }{
		{"diagram-panels.js", readPanelJS(t)},
		{"admin-connection-detail.js", readConnDetailJS(t)},
	} {
		for _, dead := range []string{"renderPanelPhase2", "renderPhase2Matches",
			"panel-phase2-container", "phase2-matches-container", "ptab-phase2", "'tab-phase2'"} {
			if strings.Contains(f.js, dead) {
				t.Errorf("%s: %q survives the Phase 2 removal", f.name, dead)
			}
		}
	}
	html, err := os.ReadFile("../../web/admin/connection-detail.html")
	if err != nil {
		t.Fatalf("read connection-detail.html: %v", err)
	}
	for _, dead := range []string{`id="tab-phase2"`, `id="phase2-matches-container"`, `id="tab-content-phase2"`} {
		if strings.Contains(string(html), dead) {
			t.Errorf("connection-detail.html: %q survives — the JS no longer drives it", dead)
		}
	}
}

// tunnel_uptime is SECONDS where it is an uptime at all. The standalone page
// divided by 100 and rendered a 53-minute tunnel as "0m"; two other renderers
// did not. One formatter, one answer.
func TestConnDetail_UptimeIsSecondsInOnePlace(t *testing.T) {
	if strings.Contains(readConnDetailJS(t), "hundredths / 100") {
		t.Error("the standalone page divides tunnel_uptime by 100 again — every uptime " +
			"on that table reads a hundred times too small")
	}
	body := funcBody(t, readCommonJS(t), `formatTunnelUptime\(seconds\) \{`)
	if strings.Contains(body, "/ 100") {
		t.Error("the shared uptime formatter treats tunnel_uptime as hundredths")
	}
	// A local formatter is how the three-way disagreement happened. There must
	// not be a second one anywhere in either connection view.
	for _, f := range []struct{ name, js string }{
		{"diagram-panels.js", readPanelJS(t)},
		{"admin-connection-detail.js", readConnDetailJS(t)},
	} {
		if regexp.MustCompile(`function\s+format\w*[Uu]ptime\s*\(`).MatchString(f.js) {
			t.Errorf("%s: defines its own uptime formatter again — that is exactly how one "+
				"page came to divide by 100 while the others did not", f.name)
		}
	}
}

// A FortiGate's tunnel_uptime is not an age: its dialup rows carry
// fgVpnDialupLifetime (constant 43200/7200 across thousands of polls) and its
// static tunnels report only 0 or 1. Rendering it as "up Xh" on the grouped
// table produced a permanent, never-changing age on a tunnel that had just
// bounced — and "up 0m" beside a DOWN badge. The grouped table must derive its
// age chip from last_up_at, which the SERVER computes from rows that actually
// reported 'up'.
func TestConnDetail_GroupedTableDoesNotRenderVendorUptimeAsAnAge(t *testing.T) {
	body := funcBody(t, readPanelJS(t), `renderPanelTunnelTable\(tableId, tunnels, deviceId, family, agreed\) \{`)
	// Match a property READ (`.tunnel_uptime`), not the bare word — the code
	// deliberately names the field in a comment explaining why it is not used.
	if regexp.MustCompile(`\.tunnel_uptime`).MatchString(body) {
		t.Error("the grouped tunnel table reads tunnel_uptime again — on a FortiGate that " +
			"is a configured SA lifetime, so the row would claim a fixed age forever")
	}
	if !strings.Contains(body, "last_up_at") {
		t.Error("the grouped tunnel table no longer derives its age chip from last_up_at, " +
			"the only observation this system makes itself")
	}
}

// funcBody extracts a function's body by brace matching. Block scoping matters:
// a file-wide search for a two-way up/down ternary false-positives on the
// interface renderer, where two states are all there are.
func funcBody(t *testing.T, js, sigPattern string) string {
	t.Helper()
	loc := regexp.MustCompile(sigPattern).FindStringIndex(js)
	if loc == nil {
		t.Fatalf("function matching %q not found", sigPattern)
	}
	depth, start := 0, -1
	for i := loc[1] - 1; i < len(js); i++ {
		switch js[i] {
		case '{':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				return js[start:i]
			}
		}
	}
	t.Fatalf("unbalanced braces after %q", sigPattern)
	return ""
}
