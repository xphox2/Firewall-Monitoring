package ipsec_test

import (
	"encoding/json"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// Selectively disabling subnet paths.
//
// The tunnel's selectors are otherwise the full cross product of the two ends'
// protected subnets, which hands every network on one side a path to every
// network on the other. These pin the rules that make switching one off safe.

func pathIntent(aNets, bNets []string, disabled ...string) *ipsec.TunnelIntent {
	in := &ipsec.TunnelIntent{
		ID: 7, Name: "fwm-t7", Mode: ipsec.ModePolicyBased,
		DisabledPaths: disabled,
	}
	in.Ends[0].ProtectedSubnets = aNets
	in.Ends[1].ProtectedSubnets = bNets
	return in
}

// THE load-bearing invariant. Device object keys are minted from the pair's
// index, so the index must count over the FULL cross product and never compact.
// Compacting would slide fwm-t7-3 down to -2 and silently re-point a live
// phase2 at a different selector pair — worse than renumbering.
func TestPaths_DisablingOnePathDoesNotMoveTheOthers(t *testing.T) {
	a := []string{"192.168.13.0/24", "192.168.25.0/24"}
	b := []string{"192.168.50.0/24", "192.168.5.0/24"}

	full := pathIntent(a, b)
	// Disable the MIDDLE path (index 1: 13.0/24 ↔ 5.0/24).
	partial := pathIntent(a, b, ipsec.PathKey("192.168.13.0/24", "192.168.5.0/24"))

	fullPaths, partialPaths := full.PathsFor(0), partial.PathsFor(0)
	if len(fullPaths) != 4 || len(partialPaths) != 4 {
		t.Fatalf("both must enumerate all 4 slots: full=%d partial=%d", len(fullPaths), len(partialPaths))
	}

	for i := range fullPaths {
		if fullPaths[i].Index != partialPaths[i].Index ||
			fullPaths[i].Local != partialPaths[i].Local ||
			fullPaths[i].Remote != partialPaths[i].Remote {
			t.Errorf("slot %d moved: full=%+v partial=%+v — the device key derived from "+
				"Index would now name a different selector pair", i, fullPaths[i], partialPaths[i])
		}
	}
	if partialPaths[1].Enabled {
		t.Error("the disabled path is still enabled")
	}
	for _, i := range []int{0, 2, 3} {
		if !partialPaths[i].Enabled {
			t.Errorf("slot %d was disabled but only slot 1 was asked for", i)
		}
	}
}

// Keys are stored in tunnel A|B orientation while paths are yielded
// local×remote, so end B must swap back before looking up. Get this wrong and
// end A renders 3 selectors while end B renders 4 children: the disabled path's
// child goes live on one side with its pass rules. A count-only check on one
// end sails straight past it, so assert both ends agree on the same LOGICAL
// pair — using an ASYMMETRIC selection, which is the only kind that can fail.
func TestPaths_BothEndsDisableTheSameLogicalPair(t *testing.T) {
	a := []string{"192.168.13.0/24", "192.168.25.0/24"}
	b := []string{"192.168.50.0/24", "192.168.5.0/24"}
	in := pathIntent(a, b, ipsec.PathKey("192.168.25.0/24", "192.168.50.0/24"))

	enabledSet := func(self int) map[string]bool {
		out := map[string]bool{}
		for _, p := range in.PathsFor(self) {
			if !p.Enabled {
				continue
			}
			// Normalise to tunnel orientation so the two ends are comparable.
			l, r := p.Local, p.Remote
			if self == 1 {
				l, r = r, l
			}
			out[l+"|"+r] = true
		}
		return out
	}

	aSide, bSide := enabledSet(0), enabledSet(1)
	if len(aSide) != 3 || len(bSide) != 3 {
		t.Fatalf("expected 3 enabled paths per end, got A=%d B=%d", len(aSide), len(bSide))
	}
	for k := range aSide {
		if !bSide[k] {
			t.Errorf("end A carries %s but end B does not — the ends disagree about which "+
				"pair is disabled, so one side provisions a selector the other refuses", k)
		}
	}
	if aSide["192.168.25.0/24|192.168.50.0/24"] {
		t.Error("the disabled pair is still enabled on end A")
	}
	if bSide["192.168.25.0/24|192.168.50.0/24"] {
		t.Error("the disabled pair is still enabled on end B — the A|B key was almost " +
			"certainly built without swapping local/remote back for self=1")
	}
}

// A tunnel stored before this feature has no disabled_paths key at all. Going
// raw JSON → unmarshal → PathsFor deliberately, with no normalizer in between:
// every read path (deploy included) unmarshals straight from intent_json.
func TestPaths_LegacyIntentJSONKeepsTheFullMesh(t *testing.T) {
	raw := `{"id":7,"name":"fwm-t7","mode":"policy-based","ends":[
		{"protected_subnets":["192.168.13.0/24","192.168.25.0/24"]},
		{"protected_subnets":["192.168.50.0/24","192.168.5.0/24"]}]}`
	if strings.Contains(raw, "disabled_paths") {
		t.Fatal("fixture must not mention disabled_paths")
	}
	var in ipsec.TunnelIntent
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(in.DisabledPaths) != 0 {
		t.Fatalf("DisabledPaths should be empty, got %v", in.DisabledPaths)
	}
	paths := in.PathsFor(0)
	if len(paths) != 4 {
		t.Fatalf("expected 4 paths, got %d", len(paths))
	}
	for _, p := range paths {
		if !p.Enabled {
			t.Errorf("path %d (%s ↔ %s) is disabled on an intent that predates the feature — "+
				"an existing tunnel would silently lose selectors on its next deploy",
				p.Index, p.Local, p.Remote)
		}
	}
}

// Reformatting a subnet must not quietly re-enable a path. Keys are canonical
// precisely so this fails closed.
func TestPaths_KeyIsCanonicalNotRaw(t *testing.T) {
	in := pathIntent([]string{"10.0.0.1/8"}, []string{"192.168.50.0/24"},
		ipsec.PathKey("10.0.0.0/8", "192.168.50.0/24"))
	paths := in.PathsFor(0)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].Enabled {
		t.Error("a path disabled as 10.0.0.0/8 came back enabled when the operator typed " +
			"10.0.0.1/8 — the key must be canonical so a reformat fails CLOSED")
	}
}

// Route-based negotiates one 0.0.0.0/0 child and steers by route, so there is
// no per-path selector to switch off.
func TestPaths_RouteBasedIsASingleEnabledPath(t *testing.T) {
	in := pathIntent([]string{"192.168.13.0/24"}, []string{"192.168.50.0/24"},
		ipsec.PathKey("192.168.13.0/24", "192.168.50.0/24"))
	in.Mode = ipsec.ModeRouteBased

	paths := in.PathsFor(0)
	if len(paths) != 1 || !paths[0].Enabled {
		t.Fatalf("route-based must yield exactly one enabled path, got %+v", paths)
	}
	if paths[0].Local != "0.0.0.0/0" {
		t.Errorf("route-based path should be 0.0.0.0/0, got %q", paths[0].Local)
	}
}

// Emptying the lists must yield NOTHING, not a 0/0 path. The drivers fall back
// to a 0.0.0.0/0 selector when a list is empty, so returning one enabled path
// here would show an operator who just switched off their last path something
// WIDER than everything they had.
func TestPaths_EmptyListsYieldNoPathsNotWideOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []string
	}{
		{"both empty", nil, nil},
		{"A empty", nil, []string{"192.168.50.0/24"}},
		{"B empty", []string{"192.168.13.0/24"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := pathIntent(tc.a, tc.b).PathsFor(0)
			if len(paths) != 0 {
				t.Errorf("expected zero paths, got %+v — a 0/0 fallback here reads as "+
					"'carries everything' at the exact moment the operator carries nothing", paths)
			}
		})
	}
}
