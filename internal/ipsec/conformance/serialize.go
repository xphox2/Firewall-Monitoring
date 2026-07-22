package conformance

import (
	"encoding/json"
	"sort"
)

// This file makes the conformance spec SHIPPABLE as data so the collector can
// enforce the exact same vocabulary the server rendered against — one source of
// truth (the vendor specs in opnsense.go/fortigate.go), not a second copy.
//
// The rule DATA (enums, ranges, address flags, and the proposal token sets) is
// serialized; the evaluator LOGIC (this package's Validate + the proposal
// grammar) is small, stable, and duplicated collector-side, pinned by a
// cross-repo parity test (mirroring ChecksumSteps). Adding a DH group or enum
// value is a data change here that ships automatically; only a brand-new grammar
// SHAPE would touch both evaluators.

// SerRule is the JSON form of a fieldRule. Proposal rules carry no per-field data
// — the vendor Grammar + TokenSets drive them.
type SerRule struct {
	Kind       string   `json:"kind"`
	Enum       []string `json:"enum,omitempty"`
	Min        int      `json:"min,omitempty"`
	Max        int      `json:"max,omitempty"`
	AllowEmpty bool     `json:"allow_empty,omitempty"`
	Required   bool     `json:"required,omitempty"`
}

// Spec is the shippable per-vendor conformance spec. Grammar names the proposal
// dialect ("opnsense" | "fortigate"); TokenSets holds the cipher/hash/dh/prf
// vocabularies those grammars validate against.
type Spec struct {
	Vendor    string                        `json:"vendor"`
	Grammar   string                        `json:"grammar"`
	Objects   map[string]map[string]SerRule `json:"objects"`
	TokenSets map[string][]string           `json:"token_sets"`
}

var ruleKindNames = map[ruleKind]string{
	enumRule:      "enum",
	spaceEnum:     "space_enum",
	enableDisable: "enable_disable",
	bool01:        "bool01",
	intRange:      "int_range",
	addressList:   "address",
	proposalIKE:   "proposal_ike",
	proposalESP:   "proposal_esp",
}

// SpecFor builds the serializable spec for a vendor (ok=false if none).
func SpecFor(vendor string) (Spec, bool) {
	vs := specs[vendor]
	if vs == nil {
		return Spec{}, false
	}
	sp := Spec{Vendor: vendor, Grammar: vendor, Objects: map[string]map[string]SerRule{}, TokenSets: tokenSetsFor(vendor)}
	for key, obj := range vs.objects {
		m := make(map[string]SerRule, len(obj))
		for f, r := range obj {
			m[f] = SerRule{Kind: ruleKindNames[r.kind], Enum: r.enum, Min: r.min, Max: r.max, AllowEmpty: r.allowEmpty, Required: r.required}
		}
		sp.Objects[key] = m
	}
	return sp, true
}

// MarshalSpec returns the vendor's spec as JSON for shipping in the apply payload.
func MarshalSpec(vendor string) (json.RawMessage, bool) {
	sp, ok := SpecFor(vendor)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(sp)
	if err != nil {
		return nil, false
	}
	return b, true
}

func tokenSetsFor(vendor string) map[string][]string {
	switch vendor {
	case "opnsense":
		return map[string][]string{
			"enc":      setKeys(opnEnc),
			"hash":     setKeys(opnHash),
			"dh":       setKeys(opnDH),
			"bare_esp": setKeys(opnBareESP),
		}
	case "fortigate":
		return map[string][]string{
			"enc":  setKeys(fgEnc),
			"hash": setKeys(fgHash),
			"prf":  setKeys(fgPRF),
			"dh":   setKeys(fgDHGroup),
		}
	}
	return nil
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out) // deterministic serialization
	return out
}
