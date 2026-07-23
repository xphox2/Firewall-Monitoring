package conformance_test

import (
	"encoding/json"
	"testing"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/ipsec/conformance"
	_ "firewall-mon/internal/ipsec/vendors"
)

// ParityCase is a proposal-grammar ground-truth case. The SAME list is pinned
// collector-side (Firewall-Collector internal/fwapi conformance_parity_test.go):
// the server (func-based) evaluator and the collector (shipped-data) evaluator
// must BOTH agree with `valid` here, or one repo's test fails. This is the
// cross-repo pin for the proposal grammar (the only reimplemented logic).
type ParityCase struct {
	Vendor string
	Path   string
	Field  string // "proposals" | "esp_proposals" | "proposal"
	Value  string
	Valid  bool
}

// ParityCases — keep byte-identical with the collector copy.
var ParityCases = []ParityCase{
	// OPNsense IKE (bare-hash 3-part enc-hash-dh)
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256gcm16-sha384-ecp384", true},
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256gcm16-prfsha384-ecp384", false}, // strongSwan prf prefix
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256-sha256-modp2048", true},
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256gcm16-sha384", false}, // missing dh
	// OPNsense ESP (enc[-dh] / enc-hash[-dh]; bare only the 4 curated)
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256gcm16-ecp384", true},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256gcm16", true},    // bare curated
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes128gcm16", false},   // bare non-curated
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256-sha256", true},  // bare curated CBC
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256-sha384", false}, // bare non-curated CBC
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256-sha256-ecp384", true},
	// FortiGate IKE (2-part enc-<prf|hash>)
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256gcm-prfsha384", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256gcm16-sha384", false}, // OPNsense-style tokens
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256-sha256", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256gcm-sha384", false}, // AEAD needs prf
	// FortiGate ESP (enc for AEAD / enc-hash for CBC)
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase2-interface", "proposal", "aes256gcm", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase2-interface", "proposal", "aes256-sha256", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase2-interface", "proposal", "aes256gcm-sha384", false}, // AEAD is single token
	// FortiGate system/interface IP MASK pairs (the fwm-t4 value class)
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "169.254.1.1 255.255.255.255", true},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", " 255.255.255.255", false},          // fwm-t4 bug value
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "169.254.1.1", false},               // missing mask
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "169.254.1.1 255.255.0.0.0", false}, // non-contiguous mask
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "", false},                          // empty
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "remote-ip", "169.254.1.2 255.255.255.252", true},
}

// parityBody wraps a proposal value in the vendor's body shape.
func parityBody(vendor, field, value string) string {
	inner := `{"` + field + `":"` + value + `"}`
	if vendor == "opnsense" {
		// OPNsense wraps under the model key; addConnection→connection, addChild→child.
		key := "connection"
		if field == "esp_proposals" {
			key = "child"
		}
		return `{"` + key + `":` + inner + `}`
	}
	return inner
}

func hasFindingFor(f []conformance.Finding, field string) bool {
	for _, x := range f {
		if x.Field == field {
			return true
		}
	}
	return false
}

// TestConformance_ParityCases pins the server (func) evaluator to the shared
// ground truth. The collector asserts the SAME cases against its data evaluator.
func TestConformance_ParityCases(t *testing.T) {
	for _, c := range ParityCases {
		steps := []ipsec.ApplyStep{{Kind: ipsec.StepHTTPAPI, Method: "POST", Path: c.Path, Body: parityBody(c.Vendor, c.Field, c.Value)}}
		f := conformance.Validate(c.Vendor, steps)
		gotValid := !hasFindingFor(f, c.Field)
		if gotValid != c.Valid {
			t.Errorf("%s %s=%q: server evaluator valid=%v, want %v (findings: %v)", c.Vendor, c.Field, c.Value, gotValid, c.Valid, f)
		}
	}
}

func TestMarshalSpec_Structure(t *testing.T) {
	for _, vendor := range conformance.Vendors() {
		raw, ok := conformance.MarshalSpec(vendor)
		if !ok {
			t.Fatalf("MarshalSpec(%q) not ok", vendor)
		}
		var sp conformance.Spec
		if err := json.Unmarshal(raw, &sp); err != nil {
			t.Fatalf("%s: unmarshal: %v", vendor, err)
		}
		if sp.Vendor != vendor || sp.Grammar != vendor {
			t.Errorf("%s: vendor/grammar = %q/%q", vendor, sp.Vendor, sp.Grammar)
		}
		if len(sp.Objects) == 0 {
			t.Errorf("%s: no objects serialized", vendor)
		}
		if len(sp.TokenSets["enc"]) == 0 || len(sp.TokenSets["dh"]) == 0 {
			t.Errorf("%s: token sets missing enc/dh", vendor)
		}
	}
}
