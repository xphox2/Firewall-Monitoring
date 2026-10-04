// S-2b: hunks to re-add to internal/normalize/normalize.go when the netfilter
// and Meraki tokenizers land with their mappers.

// --- Tokens struct: add the two members ---
//	NF     *family.Netfilter
//	MK     *family.Meraki

// --- tokenize(): restore the msg parameter name and add the cases ---
//	case FamilyNetfilter:
//		if !family.HasNetfilter(raw) {
//			return tok, false
//		}
//		nf, ok := family.ParseNetfilter(raw)
//		if !ok {
//			return tok, false
//		}
//		tok.NF = &nf
//	case FamilyMeraki:
//		cat := ""
//		if family.IsMerakiCategory(msg.AppName) {
//			cat = msg.AppName
//		}
//		mk, ok := family.ParseMeraki(cat, raw)
//		if !ok {
//			return tok, false
//		}
//		tok.MK = &mk

// --- (t *Tokens) native(): add the cases ---
//	case FamilyNetfilter:
//		m := t.NF.Fields
//		m["chain"], m["verdict"] = t.NF.Ruleset, t.NF.Verdict
//		if t.NF.Index != "" {
//			m["rule_index"] = t.NF.Index
//		}
//		return m
//	case FamilyMeraki:
//		m := t.MK.Fields
//		m["category"] = t.MK.Category
//		if t.MK.Subtype != "" {
//			m["subtype"] = t.MK.Subtype
//		}
//		if t.MK.TailKind != "" {
//			m[t.MK.TailKind] = t.MK.Tail
//		}
//		return m

// --- still to write for S-2b ---
// testdata/unifi/cases.jsonl + unparsed.txt (netfilter D/A/RET, CEF 100/112/113/201/400/401/402/512/544/578/1005, dnsmasq query + DHCPACK)
// testdata/meraki/cases.jsonl + unparsed.txt (flows allow/deny/"1 all", firewall, vpn_firewall, urls, ids-alerts, security_event ids_alerted + file_scanned, events vpn_connectivity_change / client_vpn_connect / 8021x_auth / association / failover / dhcp lease, airmarshal)
// TestCapabilityProfile_NoDrift in internal/normalize (import capability; every SourceSyslog field of a profile non-NULL in >= 1 golden of that vendor)
// capability_test.go: Feature() states, Lookup fallback
// CHANGELOG 0.11.294, FEATURES row, README badge, main.go, custom-vendor.md families list ("netfilter and Meraki follow" → present)
// Label every UniFi / Meraki fixture and doc line "untested on real hardware — built from vendor docs".
