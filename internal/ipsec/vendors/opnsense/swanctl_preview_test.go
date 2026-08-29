package opnsense

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
)

// swanctlPreviewFor builds a minimal intent of the given IKE version and returns
// the operator-facing swanctl preview text.
func swanctlPreviewFor(v ipsec.IKEVersion) string {
	in := &ipsec.TunnelIntent{IKEVersion: v, Mode: ipsec.ModePolicyBased}
	in.Ends[0] = ipsec.EndpointSpec{Vendor: "opnsense", LocalID: ipsec.IKEIdentity{Value: "site-a"}, ProtectedSubnets: []string{"192.168.50.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{Vendor: "fortigate", LocalID: ipsec.IKEIdentity{Value: "site-b"}, ProtectedSubnets: []string{"10.10.10.0/24"}}
	return swanctlPreview("fwm-t7", "aes256-sha256-modp2048", "aes256gcm16", "1.1.1.1", "2.2.2.2", &in.Ends[0], &in.Ends[1], in, 0)
}

// AUDIT-277: swanctlPreview hardcoded "version = 2", so an IKEv1 tunnel's
// operator-reviewed preview always misreported version 2 while the apply path
// correctly emitted version 1. The preview must mirror the apply path.
func TestSwanctlPreview_VersionMirrorsIKEVersion(t *testing.T) {
	if out := swanctlPreviewFor(ipsec.IKEv1); !strings.Contains(out, "version = 1") {
		t.Errorf("IKEv1 preview must show \"version = 1\"; got:\n%s", out)
	}
	if out := swanctlPreviewFor(ipsec.IKEv2); !strings.Contains(out, "version = 2") {
		t.Errorf("IKEv2 preview must show \"version = 2\"; got:\n%s", out)
	}
}
