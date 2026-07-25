package ipsec_test

import (
	"encoding/json"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// Findings now carry the endpoint they belong to so the UI can put each one next
// to the control that caused it instead of in a flat list at the bottom. These
// pin the scoping rules that are easy to get subtly wrong.

func findByCode(fs []ipsec.Finding, code string) *ipsec.Finding {
	for i := range fs {
		if fs[i].Code == code {
			return &fs[i]
		}
	}
	return nil
}

// End A is index 0. A plain int would make "end A" and "not set" identical, and
// in JS `if (f.end)` on a 0 silently drops every end-A finding — half of them,
// on the end that is usually the FortiGate. So End is a POINTER, and end A must
// marshal as an explicit 0 rather than vanishing under omitempty.
func TestFinding_EndAIsExplicitZeroOnTheWire(t *testing.T) {
	zero := 0
	raw, err := json.Marshal(ipsec.Finding{Severity: ipsec.SeverityBlock, Code: "x", Message: "m", End: &zero})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"end":0`) {
		t.Errorf("end A must serialize as an explicit 0, got %s", raw)
	}
	// A tunnel-level finding carries no end at all.
	raw, _ = json.Marshal(ipsec.Finding{Severity: ipsec.SeverityBlock, Code: "x", Message: "m"})
	if strings.Contains(string(raw), `"end"`) {
		t.Errorf("a tunnel-level finding must omit end entirely, got %s", raw)
	}
}

// A malformed CIDR is only actionable if the operator knows which side's box to
// fix. The two ends' parse errors used to be merged into one list with no end.
func TestValidate_SubnetInvalidIsScopedToItsEnd(t *testing.T) {
	in := canonicalIntent()
	in.Ends[1].ProtectedSubnets = []string{"not-a-cidr"}

	f := findByCode(ipsec.Validate(in, bothCaps(t)), "subnet_invalid")
	if f == nil {
		t.Fatal("a malformed CIDR must be reported")
	}
	if f.End == nil || *f.End != 1 {
		t.Errorf("subnet_invalid must be scoped to the end whose box holds the bad value; got %v", f.End)
	}
}

// THE WRONG-SIDE ANCHOR. default_route_over_vti and self_lockout are raised
// while validating end i, but the offending subnet lives in the PEER's protected
// list — that is the field the operator has to edit. Anchoring them to end i
// would decorate a box whose contents are fine while the one needing the change
// sits unflagged on the other panel.
func TestValidate_DefaultRouteAnchorsToThePeerWhoseSubnetItIs(t *testing.T) {
	in := canonicalIntent()
	// End 1 protects 0/0; the finding is raised for end 0 (which would route it).
	in.Ends[1].ProtectedSubnets = []string{"0.0.0.0/0"}

	f := findByCode(ipsec.Validate(in, bothCaps(t)), "default_route_over_vti")
	if f == nil {
		t.Fatal("routing 0.0.0.0/0 over the tunnel must block")
	}
	if f.End == nil {
		t.Fatal("the finding must carry an end so the UI can anchor it")
	}
	if *f.End != 1 {
		t.Errorf("End = %d, want 1 — the 0/0 lives in end 1's protected list, so end 1's field is "+
			"the one to edit even though the finding is raised for end 0", *f.End)
	}
	if f.Subject != "0.0.0.0/0" {
		t.Errorf("Subject = %q, want the offending subnet so the UI can highlight that row", f.Subject)
	}
}

// Genuinely tunnel-level findings must NOT claim an end, or the UI would anchor
// them arbitrarily to one side of a problem that belongs to both.
func TestValidate_OverlapIsTunnelLevel(t *testing.T) {
	in := canonicalIntent()
	in.Ends[0].ProtectedSubnets = []string{"192.168.70.0/24"}
	in.Ends[1].ProtectedSubnets = []string{"192.168.70.0/24"}

	f := findByCode(ipsec.Validate(in, bothCaps(t)), "subnet_overlap")
	if f == nil {
		t.Fatal("overlapping protected networks must block")
	}
	if f.End != nil {
		t.Errorf("overlap belongs to the tunnel, not one end; got end %d", *f.End)
	}
}

// Per-end findings must carry the end they were raised for. This also catches a
// loop-variable aliasing mistake: if the pointer captured the loop variable
// rather than a per-iteration copy, both ends would report the same index.
func TestValidate_PerEndFindingsCarryDistinctEnds(t *testing.T) {
	in := canonicalIntent()
	in.Ends[0].EgressIface = ""
	in.Ends[1].EgressIface = ""

	var ends []int
	for _, f := range ipsec.Validate(in, bothCaps(t)) {
		if f.Code == "egress_missing" {
			if f.End == nil {
				t.Fatal("egress_missing must carry its end")
			}
			ends = append(ends, *f.End)
		}
	}
	if len(ends) != 2 {
		t.Fatalf("both ends are missing an egress; got %d findings", len(ends))
	}
	if ends[0] == ends[1] {
		t.Errorf("both findings report end %d — the End pointers alias one loop variable", ends[0])
	}
}
