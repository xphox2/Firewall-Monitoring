package ipsec

import "net"

// NormalizeIdentities coerces each end's IKE identity TYPE to one that BOTH
// vendors can faithfully represent, so a type one end silently drops (e.g.
// OPNsense, whose config generator cannot encode a keyid identity) can never
// mismatch a peer that honors it (e.g. FortiGate, which emits ID_KEY_ID and then
// fails the peer-id constraint against the FQDN the other end assumed).
//
// For each end, if LocalID.Type is not in the intersection of both ends'
// supported IDTypes, it is coerced from the identity VALUE: an IP literal →
// IDTypeIP, otherwise → IDTypeFQDN (preferring whichever the mutual set allows).
// Both ends are normalized against the same mutual set, so they converge on a
// type each renderer produces identically — the constraint then matches.
//
// It is a no-op when the chosen type is already mutually supported (e.g. a
// FortiGate⇄FortiGate keyid tunnel keeps keyid). Pure — safe to call on every
// preview/validate/deploy path.
func NormalizeIdentities(intent *TunnelIntent, caps [2]CapabilityDescriptor) {
	if intent == nil || len(intent.Ends) != 2 {
		return
	}
	mutual := intersectIDTypes(caps[0].IDTypes, caps[1].IDTypes)
	for i := range intent.Ends {
		t := intent.Ends[i].LocalID.Type
		if containsIDType(mutual, t) {
			continue // already representable by both ends
		}
		intent.Ends[i].LocalID.Type = coerceIDType(intent.Ends[i].LocalID.Value, mutual)
	}
}

// coerceIDType picks the best mutually-supported identity type for a value: an IP
// literal maps to IDTypeIP when allowed, otherwise IDTypeFQDN when allowed. Falls
// back to IDTypeFQDN so the value never renders type-less (a non-IP string is a
// valid FQDN identity for both strongSwan and FortiOS).
func coerceIDType(value string, mutual []IDType) IDType {
	if net.ParseIP(value) != nil && containsIDType(mutual, IDTypeIP) {
		return IDTypeIP
	}
	if containsIDType(mutual, IDTypeFQDN) {
		return IDTypeFQDN
	}
	return IDTypeFQDN
}

// intersectIDTypes returns the id types present in BOTH sets, preserving a's order.
func intersectIDTypes(a, b []IDType) []IDType {
	var out []IDType
	for _, t := range a {
		if containsIDType(b, t) {
			out = append(out, t)
		}
	}
	return out
}
