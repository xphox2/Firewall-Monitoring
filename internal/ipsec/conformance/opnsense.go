package conformance

import "strings"

// OPNsense (26.1) conformance spec. Token sets mirror the box's own
// `IPsecProposalField` and model OptionField validators (verified live during the
// fwm-t3 investigation): IKE proposals are a 3-part enc-<hash>-dh with a BARE
// sha256/384/512 (never strongSwan's "prfsha384"); ESP GCM proposals are enc[-dh];
// enums (dpd_action, unique, version, keyType, ipprotocol) are the model's exact
// OptionValues; address fields reject "%any".

// opnEnc / opnHash / opnDH are the token vocabularies OPNsense's IPsecProposalField
// composes its allow-list from (the cross-product of these three IS the accepted
// proposal set). Encoding the sets — rather than the expanded cross-product —
// keeps this faithful to the box's generator and compact.
var (
	opnEnc  = set("aes128", "aes192", "aes256", "aes128gcm16", "aes192gcm16", "aes256gcm16", "chacha20poly1305")
	opnHash = set("sha256", "sha384", "sha512", "aesxcbc")
	opnDH   = set("modp2048", "modp3072", "modp4096", "modp6144", "modp8192",
		"ecp224", "ecp256", "ecp384", "ecp521", "ecp224bp", "ecp256bp", "ecp384bp", "ecp512bp",
		"x25519", "x448")
)

// opnAuth is the local/remote auth OptionValues set (Swanctl.xml).
var opnAuth = []string{"psk", "pubkey", "eap-tls", "eap-mschapv2", "xauth-pam", "eap-radius"}

func opnIsAEAD(enc string) bool {
	return strings.Contains(enc, "gcm") || enc == "chacha20poly1305"
}

// opnIKEProposal validates a phase-1 proposal: enc-<hash>-dh, all bare tokens.
func opnIKEProposal(s string) (bool, string) {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false, "expected 3-part enc-<hash>-dh (bare sha, no prf prefix)"
	}
	if !opnEnc[parts[0]] {
		return false, "unknown cipher " + parts[0]
	}
	if !opnHash[parts[1]] {
		return false, "middle term must be a bare hash (sha256/384/512/aesxcbc), got " + parts[1]
	}
	if !opnDH[parts[2]] {
		return false, "unknown DH group " + parts[2]
	}
	return true, ""
}

// opnESPProposal validates a phase-2 proposal. The PFS-ON forms are the cross
// product (AEAD → enc-dh; CBC → enc-hash-dh). The PFS-OFF (no-DH) forms are NOT
// the full cross product: OPNsense's IPsecProposalField phase-2 loop always
// appends a DH group, so the ONLY device-accepted bare proposals are the four
// curated no-PFS entries — bare `aes256gcm16`, `chacha20poly1305`, `aes256-sha1`,
// `aes256-sha256`. A render that emits any other bare token (e.g. `aes128gcm16`
// or `aes256-sha384` when PFS is disabled) is rejected by the device, so the spec
// must reject it too or the harness would false-pass the fwm-t3 bug class.
var opnBareESP = set("aes256gcm16", "chacha20poly1305", "aes256-sha1", "aes256-sha256")

func opnESPProposal(s string) (bool, string) {
	parts := strings.Split(s, "-")
	if len(parts) == 0 || !opnEnc[parts[0]] {
		return false, "unknown cipher"
	}
	noPFS := "no-PFS proposal " + s + " is not device-accepted — only aes256gcm16/chacha20poly1305/aes256-sha1/aes256-sha256 are valid without a DH group"
	if opnIsAEAD(parts[0]) {
		switch len(parts) {
		case 1: // PFS off
			if opnBareESP[s] {
				return true, ""
			}
			return false, noPFS
		case 2: // PFS on: enc-dh
			if !opnDH[parts[1]] {
				return false, "unknown DH group " + parts[1]
			}
			return true, ""
		default:
			return false, "AEAD ESP proposal is enc[-dh]"
		}
	}
	switch len(parts) {
	case 2: // CBC, PFS off: enc-hash
		if opnBareESP[s] {
			return true, ""
		}
		return false, noPFS
	case 3: // CBC, PFS on: enc-hash-dh
		if !opnHash[parts[1]] {
			return false, "unknown hash " + parts[1]
		}
		if !opnDH[parts[2]] {
			return false, "unknown DH group " + parts[2]
		}
		return true, ""
	default:
		return false, "CBC ESP proposal is enc-hash[-dh]"
	}
}

func init() {
	register(&vendorSpec{
		vendor:  "opnsense",
		ikeProp: opnIKEProposal,
		espProp: opnESPProposal,
		objects: map[string]objectSpec{
			"connections/addConnection": {
				"enabled":      {kind: bool01},
				"version":      {kind: enumRule, enum: []string{"0", "1", "2"}},
				"unique":       {kind: enumRule, enum: []string{"no", "never", "keep", "replace"}},
				"proposals":    {kind: proposalIKE},
				"local_addrs":  {kind: addressList, allowEmpty: true},
				"remote_addrs": {kind: addressList, allowEmpty: true},
				"dpd_delay":    {kind: intRange, min: 0, max: 500000},
				"rekey_time":   {kind: intRange, min: 0, max: 500000},
			},
			"connections/addChild": {
				"enabled":       {kind: bool01},
				"policies":      {kind: bool01},
				"mode":          {kind: enumRule, enum: []string{"tunnel", "transport", "pass", "drop"}},
				"dpd_action":    {kind: enumRule, enum: []string{"clear", "trap", "start"}},
				"start_action":  {kind: enumRule, enum: []string{"none", "start", "trap", "route", "trap|start"}},
				"close_action":  {kind: enumRule, enum: []string{"none", "trap", "start"}},
				"esp_proposals": {kind: proposalESP},
				"reqid":         {kind: intRange, min: 1, max: 65535},
				"rekey_time":    {kind: intRange, min: 0, max: 500000},
				"local_ts":      {kind: addressList},
				"remote_ts":     {kind: addressList},
			},
			// local/remote auth OptionValues from the Swanctl.xml model.
			"connections/addLocal":  {"enabled": {kind: bool01}, "round": {kind: intRange, min: 0, max: 10}, "auth": {kind: enumRule, enum: opnAuth}},
			"connections/addRemote": {"enabled": {kind: bool01}, "round": {kind: intRange, min: 0, max: 10}, "auth": {kind: enumRule, enum: opnAuth}},
			"pre_shared_keys/addItem": {
				"keyType": {kind: enumRule, enum: []string{"PSK", "EAP"}},
			},
			"ipsec/vti/add": {
				"enabled":       {kind: bool01},
				"reqid":         {kind: intRange, min: 1, max: 65535},
				"skip_fw":       {kind: bool01},
				"tunnel_local":  {kind: addressList},
				"tunnel_remote": {kind: addressList},
				"local":         {kind: addressList, allowEmpty: true},
				"remote":        {kind: addressList, allowEmpty: true},
			},
			"routing/settings/addGateway": {
				"ipprotocol": {kind: enumRule, enum: []string{"inet", "inet6"}},
				"gateway":    {kind: addressList},
			},
			"routes/routes/addroute": {
				"network": {kind: addressList},
			},
			// Data-plane firewall pass rule (Firewall/Filter automation model). Only
			// the controlled-vocab fields are pinned; interface is intentionally
			// unvalidated (empty/floating is valid and the assignable set is
			// box-dependent), and source_net/destination_net are freeform CIDR/alias
			// lists the box validates.
			"firewall/filter/addRule": {
				"enabled":    {kind: bool01},
				"quick":      {kind: bool01},
				"action":     {kind: enumRule, enum: []string{"pass", "block", "reject"}},
				"direction":  {kind: enumRule, enum: []string{"in", "out"}},
				"ipprotocol": {kind: enumRule, enum: []string{"inet", "inet6"}},
				"protocol":   {kind: enumRule, enum: []string{"any", "TCP", "UDP", "TCP/UDP", "ICMP", "ESP", "AH", "GRE", "IPV6-ICMP", "tcp", "udp", "icmp", "esp", "gre"}},
			},
		},
	})
}

func set(vs ...string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}
