package conformance_test

import (
	"fmt"
	"testing"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/ipsec/conformance"
	_ "firewall-mon/internal/ipsec/vendors" // register fortigate + opnsense drivers
)

// buildIntent renders a two-same-vendor route-based intent with the given crypto
// so we can exercise a vendor's render across its FULL capability matrix. end0 is
// static, end1 is dynamic — rendering both selves exercises both the static and
// the dynamic (empty-address) code paths.
func buildIntent(vendor string, ike ipsec.IKEProposal, esp ipsec.ESPProposal, ver ipsec.IKEVersion) *ipsec.TunnelIntent {
	_, innerA, innerB := ipsec.AllocateVTI(7)
	return &ipsec.TunnelIntent{
		ID: 7, Name: "fwm-t7", Enabled: true,
		IKEVersion: ver, Mode: ipsec.ModeRouteBased,
		IKE: ike, ESP: esp,
		IKELifetimeSecs: 86400, DPD: ipsec.DPD{DelaySecs: 30},
		PSK: "abcDEF012345678901234567890XYZ", VTISubnet: "169.254.1.28/30",
		Ends: [2]ipsec.EndpointSpec{
			{
				DeviceID: 1, Vendor: vendor, PeerIP: "66.179.9.155",
				EgressIface: "port1", LANIface: "port3",
				LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "fwm-t7-a"},
				ProtectedSubnets: []string{"10.10.10.0/24"},
				InnerIP:          innerA, Reqid: 7, MSSClamp: 1350, ChildLifetimeSecs: 7200,
			},
			{
				DeviceID: 2, Vendor: vendor, PeerIP: "198.51.100.9", Dynamic: true,
				EgressIface: "port1", LANIface: "port3",
				LocalID:          ipsec.IKEIdentity{Type: ipsec.IDTypeKeyID, Value: "fwm-t7-b"},
				ProtectedSubnets: []string{"192.168.50.0/24"},
				InnerIP:          innerB, Reqid: 7, MSSClamp: 1350, ChildLifetimeSecs: 3600,
			},
		},
	}
}

func isGCM(e ipsec.Encryption) bool {
	return e == ipsec.EncAES256GCM16 || e == ipsec.EncAES128GCM16
}

// TestConformance_FullCapabilityMatrix renders every crypto combination each
// vendor advertises in Capabilities() — not just the two presets — and asserts
// the rendered VALUES all pass that vendor's conformance spec. This is the CI net
// that would have caught the fwm-t3 bugs (prfsha384/%any/dpd_action) before merge.
func TestConformance_FullCapabilityMatrix(t *testing.T) {
	for _, vendor := range conformance.Vendors() {
		drv, ok := ipsec.Driver(vendor)
		if !ok {
			t.Fatalf("no driver for conformance vendor %q", vendor)
		}
		caps := drv.Capabilities()
		combos := 0
		for _, enc := range caps.Encryption {
			for _, dh := range caps.DHGroups {
				for _, ver := range caps.IKEVersions {
					// AEAD ciphers vary the PRF (integrity is None); CBC ciphers vary
					// the integrity hash (PRF is present but a fixed valid value).
					type crypto struct {
						integ ipsec.Integrity
						prf   ipsec.PRF
					}
					var variants []crypto
					if isGCM(enc) {
						for _, prf := range caps.PRF {
							variants = append(variants, crypto{ipsec.IntegrityNone, prf})
						}
					} else {
						for _, integ := range caps.Integrity {
							variants = append(variants, crypto{integ, ipsec.PRFSHA256})
						}
					}
					for _, cr := range variants {
						ike := ipsec.IKEProposal{Enc: enc, Integ: cr.integ, PRF: cr.prf, DH: dh}
						esp := ipsec.ESPProposal{Enc: enc, Integ: cr.integ, PFS: dh}
						intent := buildIntent(vendor, ike, esp, ver)
						for self := 0; self < 2; self++ {
							art, err := drv.Render(ipsec.ViewFor(intent, self))
							if err != nil {
								t.Fatalf("%s render(self=%d) %v/%v/%v/%v ver=%v: %v",
									vendor, self, enc, cr.integ, cr.prf, dh, ver, err)
							}
							if f := conformance.Validate(vendor, art.Steps); len(f) > 0 {
								t.Errorf("%s NON-CONFORMANT enc=%v integ=%v prf=%v dh=%v ver=%v self=%d:\n  %v",
									vendor, enc, cr.integ, cr.prf, dh, ver, self, findingsStr(f))
							}
							combos++
						}
					}
				}
			}
		}
		t.Logf("%s: %d render/validate combinations, all conformant", vendor, combos)
	}
}

// TestConformance_CatchesKnownBugs proves the harness flags the exact fwm-t3
// value bugs — a guard against the harness silently passing everything.
func TestConformance_CatchesKnownBugs(t *testing.T) {
	steps := []ipsec.ApplyStep{
		{Kind: ipsec.StepHTTPAPI, Method: "POST", Path: "/api/ipsec/connections/addConnection",
			Body: `{"connection":{"proposals":"aes256gcm16-prfsha384-ecp384","local_addrs":"%any","version":"2","unique":"replace"}}`},
		// dpd_action=restart (strongSwan spelling) and a bare no-PFS esp_proposals
		// `aes128gcm16` — both device-rejected; the latter is the PFS-off false-pass
		// the adversarial review caught.
		{Kind: ipsec.StepHTTPAPI, Method: "POST", Path: "/api/ipsec/connections/addChild",
			Body: `{"child":{"dpd_action":"restart","esp_proposals":"aes128gcm16","policies":"0"}}`},
	}
	f := conformance.Validate("opnsense", steps)
	want := map[string]bool{"proposals": false, "local_addrs": false, "dpd_action": false, "esp_proposals": false}
	for _, finding := range f {
		if _, ok := want[finding.Field]; ok {
			want[finding.Field] = true
		}
	}
	for field, found := range want {
		if !found {
			t.Errorf("conformance harness FAILED to catch bad %q; findings: %v", field, findingsStr(f))
		}
	}
}

func findingsStr(f []conformance.Finding) string {
	s := ""
	for _, x := range f {
		s += "\n  " + x.String()
	}
	if s == "" {
		return "(none)"
	}
	return fmt.Sprintf("%d finding(s):%s", len(f), s)
}
