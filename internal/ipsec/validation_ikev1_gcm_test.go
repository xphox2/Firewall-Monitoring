package ipsec_test

import (
	"testing"

	"firewall-mon/internal/ipsec"
)

// AUDIT-313: FortiGate rejects a GCM (AEAD) IKE cipher under IKEv1 (FortiOS pairs
// the phase1 AEAD proposal with a PRF only its IKEv2 stack negotiates). Neither
// the warn-only ikev1_deprecated finding nor the version-agnostic conformance
// proposal grammar caught IKEv1+GCM, so a Custom profile previewed/validated
// clean and then failed the phase1 POST mid-apply → live deploy failure and
// auto-rollback. Validate must BLOCK it, anchored to the FortiGate end.
func TestValidate_IKEv1GCM_BlockedOnFortiGate(t *testing.T) {
	c := [2]ipsec.CapabilityDescriptor{caps(t, "fortigate"), caps(t, "opnsense")}

	// IKEv1 + GCM (the Modern preset is GCM) → block on the FortiGate end (index 0).
	in := canonicalIntent()
	in.IKEVersion = ipsec.IKEv1
	fs := ipsec.Validate(in, c)
	f := findByCode(fs, "ikev1_gcm_unsupported")
	if f == nil {
		t.Fatalf("IKEv1 + GCM must be blocked on FortiGate; got %+v", fs)
	}
	if f.Severity != ipsec.SeverityBlock {
		t.Errorf("ikev1_gcm_unsupported severity = %q, want block", f.Severity)
	}
	if f.End == nil || *f.End != 0 {
		t.Errorf("finding must anchor to the FortiGate end (index 0); got End=%v", f.End)
	}

	// IKEv2 + GCM (canonical) is fine — the constraint is IKEv1-specific.
	if findByCode(ipsec.Validate(canonicalIntent(), c), "ikev1_gcm_unsupported") != nil {
		t.Error("IKEv2 + GCM must not be flagged")
	}

	// IKEv1 + CBC (with a separate integrity algorithm) is fine — the constraint is
	// about a GCM/AEAD IKE cipher, not IKEv1 itself.
	cbc := canonicalIntent()
	cbc.IKEVersion = ipsec.IKEv1
	cbc.IKE.Enc, cbc.IKE.Integ = ipsec.EncAES256CBC, ipsec.IntegritySHA256
	cbc.ESP.Enc, cbc.ESP.Integ = ipsec.EncAES256CBC, ipsec.IntegritySHA256
	if findByCode(ipsec.Validate(cbc, c), "ikev1_gcm_unsupported") != nil {
		t.Error("IKEv1 + CBC must not be flagged (only GCM/AEAD is IKEv2-only on FortiGate)")
	}
}
