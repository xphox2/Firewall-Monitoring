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

func readPanelJS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../cmd/api/static/js/diagram-panels.js")
	if err != nil {
		t.Fatalf("read diagram-panels.js: %v", err)
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
	// member that knows either.
	for _, agg := range []string{
		"const anyUp = g.phase2.some(",
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
func TestVPNPanel_UnknownChildStateIsNotRenderedAsDown(t *testing.T) {
	js := readPanelJS(t)

	block := regexp.MustCompile(`(?s)children\.forEach\(t => \{(.*?)\n            \}\);`).FindStringSubmatch(js)
	if block == nil {
		t.Fatal("child render loop not found")
	}
	body := block[1]

	// The old shape: a bare boolean that collapses everything not-up into down.
	if regexp.MustCompile(`\$\{sUp \? 'UP' : 'DOWN'\}`).MatchString(body) {
		t.Error("child status is a two-way boolean, so a config-derived 'unknown' renders " +
			"as DOWN — a claim the device never made, under a parent badged UP")
	}
	if !strings.Contains(body, `'down' : ''`) {
		t.Error("no third state for a row that makes no claim")
	}
}
