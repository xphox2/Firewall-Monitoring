package conformance

import "strings"

// FortiGate (FortiOS 7.x) conformance spec. Note the dialect differs from
// OPNsense: FortiOS IKE proposals are 2-part enc-<prf|hash> (the DH group is a
// SEPARATE `dhgrp` field, not part of the proposal string), and AEAD proposals
// KEEP the "prfsha384" prefix. Booleans are "enable"/"disable" strings. The
// static FortiGate spec is cross-checked against the live device schema by the
// Phase-3 `?action=schema` preflight so it can't silently rot.

var (
	fgEnc     = set("des", "3des", "aes128", "aes192", "aes256", "aes128gcm", "aes192gcm", "aes256gcm", "aria128", "aria192", "aria256", "seed", "chacha20poly1305")
	fgHash    = set("md5", "sha1", "sha256", "sha384", "sha512")
	fgPRF     = set("prfsha1", "prfsha256", "prfsha384", "prfsha512")
	fgDHGroup = set("1", "2", "5", "14", "15", "16", "17", "18", "19", "20", "21", "27", "28", "29", "30", "31", "32")
)

func fgIsAEAD(enc string) bool {
	return strings.Contains(enc, "gcm") || enc == "chacha20poly1305"
}

// fgIKEProposal validates a phase-1 proposal token: enc-<prf> for AEAD, enc-<hash>
// for CBC. (FortiOS also accepts space-separated multi-proposals; the render emits
// exactly one, which is what we validate.)
func fgIKEProposal(s string) (bool, string) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false, "expected 2-part enc-<prf|hash> (DH is a separate dhgrp field)"
	}
	if !fgEnc[parts[0]] {
		return false, "unknown cipher " + parts[0]
	}
	if fgIsAEAD(parts[0]) {
		if !fgPRF[parts[1]] {
			return false, "AEAD IKE proposal needs a prfsha* term, got " + parts[1]
		}
		return true, ""
	}
	if !fgHash[parts[1]] {
		return false, "CBC IKE proposal needs a hash term, got " + parts[1]
	}
	return true, ""
}

// fgESPProposal validates a phase-2 proposal: AEAD → enc (1 part); CBC → enc-hash.
func fgESPProposal(s string) (bool, string) {
	parts := strings.Split(s, "-")
	if len(parts) == 0 || !fgEnc[parts[0]] {
		return false, "unknown cipher"
	}
	if fgIsAEAD(parts[0]) {
		if len(parts) != 1 {
			return false, "AEAD ESP proposal is a single cipher token"
		}
		return true, ""
	}
	if len(parts) != 2 || !fgHash[parts[1]] {
		return false, "CBC ESP proposal is enc-hash"
	}
	return true, ""
}

func init() {
	register(&vendorSpec{
		vendor:  "fortigate",
		ikeProp: fgIKEProposal,
		espProp: fgESPProposal,
		objects: map[string]objectSpec{
			"vpn.ipsec/phase1-interface": {
				"ike-version":       {kind: enumRule, enum: []string{"1", "2"}},
				"net-device":        {kind: enableDisable},
				"add-route":         {kind: enableDisable},
				"type":              {kind: enumRule, enum: []string{"static", "dynamic", "ddns"}},
				"peertype":          {kind: enumRule, enum: []string{"any", "one", "dialup", "peer", "peergrp"}},
				"localid-type":      {kind: enumRule, enum: []string{"auto", "fqdn", "user-fqdn", "keyid", "address", "asn1dn"}},
				"proposal":          {kind: proposalIKE},
				"dhgrp":             {kind: enumRule, enum: keys(fgDHGroup)},
				"dpd":               {kind: enumRule, enum: []string{"disable", "on-idle", "on-demand"}},
				"keylife":           {kind: intRange, min: 120, max: 172800},
				"dpd-retryinterval": {kind: intRange, min: 1, max: 60},
			},
			"vpn.ipsec/phase2-interface": {
				"proposal":       {kind: proposalESP},
				"pfs":            {kind: enableDisable},
				"dhgrp":          {kind: enumRule, enum: keys(fgDHGroup)},
				"keylifeseconds": {kind: intRange, min: 120, max: 172800},
			},
			"router/static": {
				"blackhole": {kind: enableDisable},
				"distance":  {kind: intRange, min: 1, max: 255},
			},
			"firewall/policy": {
				"action": {kind: enumRule, enum: []string{"accept", "deny", "ipsec"}},
			},
		},
	})
}

// keys returns a set's members (order-independent; used only to seed an Enum rule
// whose check is membership, so order does not matter).
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
