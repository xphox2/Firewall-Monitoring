package ipsec_test

import (
	"regexp"
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// TestOPNsense_CaptureRemoveTokenParity pins that every object Render CAPTURES a
// UUID for is deleted by RenderRemove via that token, and every remove token was
// captured — so a rollback can never orphan a created object or reference a token
// that was never bound. (Mirrors the FortiGate PreflightProbe/Render key parity.)
func TestOPNsense_CaptureRemoveTokenParity(t *testing.T) {
	in := canonicalIntent() // end 1 is OPNsense
	d, ok := ipsec.Driver("opnsense")
	if !ok {
		t.Fatal("opnsense driver not registered")
	}
	view := ipsec.ViewFor(in, 1)
	art, err := d.Render(view)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	rem, err := d.RenderRemove(view)
	if err != nil {
		t.Fatalf("render remove: %v", err)
	}

	captured := map[string]bool{}
	for _, s := range art.Steps {
		if s.CaptureAs != "" {
			captured[s.CaptureAs] = true
		}
	}
	if len(captured) == 0 {
		t.Fatal("OPNsense Render captured no UUIDs — the chaining is not wired")
	}

	re := regexp.MustCompile(`<uuid:([a-zA-Z0-9_]+)>`)
	removeToks := map[string]bool{}
	for _, s := range rem.Steps {
		for _, m := range re.FindAllStringSubmatch(s.Path, -1) {
			removeToks[m[1]] = true
		}
	}
	for tok := range removeToks {
		if !captured[tok] {
			t.Errorf("RenderRemove references token %q that Render never captures", tok)
		}
	}
	for tok := range captured {
		if !removeToks[tok] {
			t.Errorf("Render captures token %q that RenderRemove never deletes (orphan risk)", tok)
		}
	}

	// The child/auth bodies must reference the connection token, not a literal.
	// HasPrefix covers the fanned-out child_<i> captures (one child per subnet pair).
	var sawChildRef bool
	for _, s := range art.Steps {
		if strings.HasPrefix(s.CaptureAs, "child") || s.CaptureAs == "local" || s.CaptureAs == "remote" {
			if re.MatchString(s.Body) {
				sawChildRef = true
			}
		}
	}
	if !sawChildRef {
		t.Error("child/local/remote bodies must reference the <uuid:conn> token")
	}
}

// TestValidate_RejectsReservedToken pins F7: operator free-text that would reach a
// checksummed apply body must not contain the reserved <uuid: substitution token.
func TestValidate_RejectsReservedToken(t *testing.T) {
	base := canonicalIntent()
	cA, cB := caps(t, "fortigate"), caps(t, "opnsense")

	idBad := *base
	idBad.Ends[0].LocalID.Value = "peer<uuid:conn>id"
	if !ipsec.HasBlock(ipsec.Validate(&idBad, [2]ipsec.CapabilityDescriptor{cA, cB})) {
		t.Error("an identity containing \"<uuid:\" must produce a blocking finding")
	}

	pskBad := *base
	pskBad.PSK = "abc<uuid:conn>def012345678901234567890"
	if !ipsec.HasBlock(ipsec.Validate(&pskBad, [2]ipsec.CapabilityDescriptor{cA, cB})) {
		t.Error("a PSK containing \"<uuid:\" must produce a blocking finding")
	}

	// The clean canonical intent must NOT trip the reserved-token block.
	clean := ipsec.Validate(base, [2]ipsec.CapabilityDescriptor{cA, cB})
	for _, f := range clean {
		if f.Code == "reserved_token" {
			t.Errorf("clean intent wrongly flagged reserved_token: %+v", f)
		}
	}
}
