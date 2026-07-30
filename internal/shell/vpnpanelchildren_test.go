package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The VPN panel lists a tunnel's phase2 children. Two writers feed it, and
// conflating them produces a tunnel that reads wrong in two different ways.
//
// A FortiGate dialup tunnel arrives as: one SNMP row named dialup-<peer>, which
// is the ONLY member carrying liveness and counters, plus one SSH row per real
// phase2, which carry the provisioned name and selectors but read CONFIG and so
// report status "unknown" with zero bytes.

func readPanelJS(t *testing.T) string  { return readJS(t, "diagram-panels.js") }
func readCommonJS(t *testing.T) string { return readJS(t, "admin-common.js") }
func readConnDetailJS(t *testing.T) string {
	return readJS(t, "admin-connection-detail.js")
}

func readJS(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../cmd/api/static/js/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// The dialup row is a TUNNEL-level observation — FortiOS reports one entry per
// dialup PEER, not per selector — so listing it beside the real children invents
// a path. On a 2x2 tunnel that shows five selectors for four paths, one of them
// duplicating whichever real path it narrows to.
func TestVPNPanel_DialupIsNotListedAsASelectorChild(t *testing.T) {
	js := readPanelJS(t)

	if !strings.Contains(js, `t.tunnel_type !== 'ipsec-dialup'`) {
		t.Error("the child list does not exclude dialup rows; a dialup tunnel renders one " +
			"phantom child that duplicates a real path")
	}
	// It must still count toward the group's status and totals — it is the only
	// member that knows either. The status reduction moved to the shared helper
	// (AC.tunnelGroupClaim) in v0.11.193, but it must still be fed the WHOLE
	// group rather than the rendered children.
	for _, agg := range []string{
		"AC.tunnelGroupClaim(g.phase2)",
		"const sumIn = g.phase2.reduce(",
		"const sumOut = g.phase2.reduce(",
	} {
		if !strings.Contains(js, agg) {
			t.Errorf("%q changed — the dialup row must stay in the group's aggregates, "+
				"or the tunnel loses the only liveness and counters it has", agg)
		}
	}
	// Demotion must be conditional: a dialup tunnel this system did not provision
	// has no other selector source, and hiding it would leave no children at all.
	if !strings.Contains(js, "named.length ? named : withSel") {
		t.Error("dialup rows are excluded unconditionally — an unprovisioned dialup tunnel " +
			"would then show no selectors whatsoever")
	}
	// The count must follow the same set, or the label overstates.
	if !strings.Contains(js, "const selCount = children.length") {
		t.Error("selCount still counts every group member, so the label says one more " +
			"selector than the panel lists")
	}
}

// Only up/down are state claims. "unknown" means the writer could not observe
// liveness, and painting it DOWN shows dead children under a parent badged UP.
//
// v0.11.193 moved the three-way decision into admin-common.js so that all four
// renderers share one answer. That makes the CONSUMER-side pins nearly worthless
// on their own — a helper that is internally two-way satisfies every one of them
// — so the helper's own body is pinned too, in the file it actually lives in.
func TestVPNPanel_UnknownChildStateIsNotRenderedAsDown(t *testing.T) {
	block := regexp.MustCompile(`(?s)children\.forEach\(t => \{(.*?)\n            \}\);`).
		FindStringSubmatch(readPanelJS(t))
	if block == nil {
		t.Fatal("child render loop not found")
	}
	if !strings.Contains(block[1], "AC.tunnelStateBadge(AC.tunnelClaim(t)") {
		t.Error("the child row no longer renders its status through the shared tri-state " +
			"helper, so this renderer is free to collapse 'unknown' into DOWN again")
	}

	// The helper itself must actually HAVE a third state. Pinned by body, not by
	// name: `function tunnelClaim(r){ return r.status==='up'?'up':'down' }` would
	// satisfy every call-site assertion above while rendering DOWN for unknown.
	common := readCommonJS(t)
	claim := regexp.MustCompile(`(?s)function tunnelClaim\(row\) \{(.*?)\n    \}`).
		FindStringSubmatch(common)
	if claim == nil {
		t.Fatal("AC.tunnelClaim not found in admin-common.js")
	}
	if !strings.Contains(claim[1], `: '';`) {
		t.Error("tunnelClaim has no third arm — a row that reported no state resolves " +
			"to a state anyway, which is the bug this helper exists to prevent")
	}
	if !strings.Contains(claim[1], `'down'`) || !strings.Contains(claim[1], `'up'`) {
		t.Error("tunnelClaim no longer distinguishes up from down")
	}

	// And the badge must render the no-claim case as a dash rather than falling
	// through to a badge class.
	badge := regexp.MustCompile(`(?s)function tunnelStateBadge\(claim, opts\) \{(.*?)\n    \}`).
		FindStringSubmatch(common)
	if badge == nil {
		t.Fatal("AC.tunnelStateBadge not found in admin-common.js")
	}
	if !strings.Contains(badge[1], "&mdash;") {
		t.Error("tunnelStateBadge no longer renders a dash for a row that makes no claim")
	}
	if !strings.Contains(badge[1], `claim === 'up' || claim === 'down'`) {
		t.Error("tunnelStateBadge no longer gates the badge on an actual claim, so an " +
			"unknown state can reach `class=\"badge <claim>\"`")
	}
}
