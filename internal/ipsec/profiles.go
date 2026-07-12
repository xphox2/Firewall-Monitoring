package ipsec

import "fmt"

// ProfileName is a named best-practice crypto preset. v1 hardcodes these; a
// user-defined crypto_profile table is post-v1.
type ProfileName string

const (
	ProfileModern     ProfileName = "modern"
	ProfileCompatible ProfileName = "compatible"
	ProfileCustom     ProfileName = "custom"
)

// Profile is a full crypto preset (IKE + ESP proposals + lifetimes). Research
// sources: RFC 8221/8247, NSA CNSA/RFC 9206, NIST SP 800-57, BSI TR-02102-3.
type Profile struct {
	Name              ProfileName
	Label             string
	IKEVersion        IKEVersion
	IKE               IKEProposal
	ESP               ESPProposal
	IKELifetimeSecs   int
	ChildLifetimeSecs int
}

// Modern is the default: AES-256-GCM / SHA-384 PRF / DH-20 (ECP-384), PFS on.
// AEAD ⇒ no separate integrity. IKE 24h / child 1h.
var modernProfile = Profile{
	Name:              ProfileModern,
	Label:             "Modern",
	IKEVersion:        IKEv2,
	IKE:               IKEProposal{Enc: EncAES256GCM16, Integ: IntegrityNone, PRF: PRFSHA384, DH: DHGroup20},
	ESP:               ESPProposal{Enc: EncAES256GCM16, Integ: IntegrityNone, PFS: DHGroup20},
	IKELifetimeSecs:   86400,
	ChildLifetimeSecs: 3600,
}

// Compatible is the interop floor: AES-256-CBC / SHA-256 / DH-14 (MODP-2048).
var compatibleProfile = Profile{
	Name:              ProfileCompatible,
	Label:             "Compatible",
	IKEVersion:        IKEv2,
	IKE:               IKEProposal{Enc: EncAES256CBC, Integ: IntegritySHA256, PRF: PRFSHA256, DH: DHGroup14},
	ESP:               ESPProposal{Enc: EncAES256CBC, Integ: IntegritySHA256, PFS: DHGroup14},
	IKELifetimeSecs:   86400,
	ChildLifetimeSecs: 3600,
}

// Presets returns the built-in profiles (Custom is caller-supplied).
func Presets() []Profile { return []Profile{modernProfile, compatibleProfile} }

// PresetByName returns a built-in preset by name.
func PresetByName(n ProfileName) (Profile, bool) {
	switch n {
	case ProfileModern:
		return modernProfile, true
	case ProfileCompatible:
		return compatibleProfile, true
	}
	return Profile{}, false
}

// ResolveProfile picks the strongest built-in profile BOTH vendors support,
// starting from the requested preference. If the preferred profile isn't
// supported by both ends it demotes (Modern→Compatible) and reports demoted=true
// with a human reason. Custom is returned as-is (validated separately).
func ResolveProfile(pref ProfileName, a, b CapabilityDescriptor) (p Profile, demoted bool, reason string, err error) {
	order := []Profile{modernProfile, compatibleProfile}
	// Start at the requested preference (or Modern by default).
	start := 0
	for i, pr := range order {
		if pr.Name == pref {
			start = i
			break
		}
	}
	for i := start; i < len(order); i++ {
		pr := order[i]
		if profileSupported(pr, a) && profileSupported(pr, b) {
			return pr, i > start, demoteReason(order[start], pr, a, b), nil
		}
	}
	return Profile{}, false, "", fmt.Errorf("no built-in crypto profile is supported by both %s and %s", a.Vendor, b.Vendor)
}

func profileSupported(p Profile, d CapabilityDescriptor) bool {
	return d.supportsIKE(p.IKEVersion) &&
		d.supportsEnc(p.IKE.Enc) && d.supportsEnc(p.ESP.Enc) &&
		d.supportsDH(p.IKE.DH) &&
		(p.ESP.PFS == DHGroupNone || d.supportsDH(p.ESP.PFS))
}

func demoteReason(from, to Profile, a, b CapabilityDescriptor) string {
	if from.Name == to.Name {
		return ""
	}
	var who string
	if !profileSupported(from, a) {
		who = a.Vendor
	} else {
		who = b.Vendor
	}
	return fmt.Sprintf("%s does not support the %s profile; using %s", who, from.Label, to.Label)
}
