// Package conformance validates a rendered IPSec Artifact's field VALUES against
// each vendor's accepted vocabulary, offline (no device I/O).
//
// It exists because the fwm-t3 outage was a value-level render bug: the OPNsense
// render emitted strongSwan-style tokens the device rejects (prfsha384 vs sha384,
// %any vs empty, dpd_action=restart vs start). Field NAMES were reviewed; field
// VALUES were only ever checked by a live write — which failed at step 1 and
// masked the rest. This package turns that class of bug into a unit-test failure
// (and a server-side pre-dispatch refusal) instead of a live rollback.
//
// The server is the single place that knows each vendor's vocabulary (it renders
// the payloads), so the spec lives here once and is reused by the offline matrix
// test, the pre-dispatch guard, and (via a shipped copy) the collector's
// pre-write check.
//
// Scope is deliberately narrow: only fields carrying a CONTROLLED vocabulary
// (enums, enable/disable, 0/1 booleans, integer ranges, addresses, and the
// per-vendor proposal grammar) are specified. Free-text fields (names, comments,
// identity values, the PSK) are intentionally omitted — validating them would
// add false positives and, for the PSK, risk echoing a secret in a Finding.
package conformance

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"firewall-mon/internal/ipsec"
)

// ruleKind enumerates the value constraints a field can carry.
type ruleKind int

const (
	free          ruleKind = iota // unchecked (not used directly; omit the field instead)
	enumRule                      // value ∈ Enum
	spaceEnum                     // whitespace-separated list; every token ∈ Enum (FortiOS multi-value)
	enableDisable                 // "enable" | "disable" (FortiOS booleans)
	bool01                        // "0" | "1" (OPNsense stringified booleans)
	intRange                      // integer in [Min, Max]
	addressList                   // IP | CIDR | hostname (never "%any"); empty allowed iff AllowEmpty
	ipMask                        // FortiOS "<ipv4> <dotted-netmask>" pair (contiguous mask)
	proposalIKE                   // phase-1 proposal, validated by VendorSpec.ikeProp
	proposalESP                   // phase-2 proposal, validated by VendorSpec.espProp
)

// fieldRule is one field's value constraint.
type fieldRule struct {
	kind       ruleKind
	enum       []string
	min, max   int
	allowEmpty bool
	required   bool
}

// objectSpec maps a field name to its rule. Only controlled-vocabulary fields
// appear; any field absent from the map is unchecked.
type objectSpec map[string]fieldRule

// vendorSpec is one vendor's conformance spec. Objects are keyed by a substring
// of the step Path that uniquely identifies the target object (a cmdb table for
// FortiGate, an endpoint path for OPNsense). ikeProp/espProp validate that
// vendor's proposal-string grammar.
type vendorSpec struct {
	vendor  string
	objects map[string]objectSpec
	ikeProp func(string) (bool, string)
	espProp func(string) (bool, string)
}

// Finding is one rendered value that the vendor would reject.
type Finding struct {
	Path   string `json:"path"`
	Field  string `json:"field"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: field %q=%q — %s", f.Path, f.Field, f.Value, f.Reason)
}

var specs = map[string]*vendorSpec{}

func register(s *vendorSpec) { specs[s.vendor] = s }

// Vendors returns the vendors that have a conformance spec.
func Vendors() []string {
	out := make([]string, 0, len(specs))
	for v := range specs {
		out = append(out, v)
	}
	return out
}

// Validate checks every HTTP write step's body against the vendor's spec and
// returns all violations (empty = conformant). Unknown vendors return nil — the
// harness only asserts on vendors it knows, never manufacturing a failure.
func Validate(vendor string, steps []ipsec.ApplyStep) []Finding {
	spec := specs[vendor]
	if spec == nil {
		return nil
	}
	var out []Finding
	for _, s := range steps {
		if s.Kind != ipsec.StepHTTPAPI || s.Body == "" {
			continue
		}
		obj := spec.match(s.Path)
		if obj == nil {
			continue
		}
		fields, ok := unwrapBody(s.Body)
		if !ok {
			out = append(out, Finding{Path: s.Path, Reason: "body is not a JSON object"})
			continue
		}
		out = append(out, spec.checkObject(s.Path, obj, fields)...)
	}
	return out
}

// match finds the objectSpec whose key is contained in the step path. Keys are
// specific enough to be unambiguous across the current object set.
func (s *vendorSpec) match(path string) objectSpec {
	// Longest key wins so a specific path (…/phase1-interface) never collides with
	// a shorter one that happens to be a prefix.
	var best string
	var bestObj objectSpec
	for key, obj := range s.objects {
		if strings.Contains(path, key) && len(key) > len(best) {
			best, bestObj = key, obj
		}
	}
	return bestObj
}

func (s *vendorSpec) checkObject(path string, obj objectSpec, fields map[string]any) []Finding {
	var out []Finding
	for name, rule := range obj {
		raw, present := fields[name]
		if !present {
			if rule.required {
				out = append(out, Finding{Path: path, Field: name, Reason: "required field missing"})
			}
			continue
		}
		val := asString(raw)
		if f, bad := s.checkValue(path, name, val, rule); bad {
			out = append(out, f)
		}
	}
	return out
}

func (s *vendorSpec) checkValue(path, name, val string, rule fieldRule) (Finding, bool) {
	mk := func(reason string) (Finding, bool) {
		return Finding{Path: path, Field: name, Value: val, Reason: reason}, true
	}
	switch rule.kind {
	case enumRule:
		if !contains(rule.enum, val) {
			return mk("not in allowed set " + strings.Join(rule.enum, "|"))
		}
	case spaceEnum:
		for _, tok := range strings.Fields(val) {
			if !contains(rule.enum, tok) {
				return mk("token " + tok + " not in allowed set " + strings.Join(rule.enum, "|"))
			}
		}
	case enableDisable:
		if val != "enable" && val != "disable" {
			return mk(`must be "enable" or "disable"`)
		}
	case bool01:
		if val != "0" && val != "1" {
			return mk(`must be "0" or "1"`)
		}
	case intRange:
		n, err := strconv.Atoi(val)
		if err != nil {
			return mk("not an integer")
		}
		if n < rule.min || n > rule.max {
			return mk(fmt.Sprintf("outside [%d,%d]", rule.min, rule.max))
		}
	case addressList:
		if val == "" {
			if !rule.allowEmpty {
				return mk("empty not allowed")
			}
			return Finding{}, false
		}
		for _, part := range strings.Split(val, ",") {
			if !validAddress(strings.TrimSpace(part)) {
				return mk(`not a valid IP/CIDR/hostname (e.g. "%any" is rejected — use empty)`)
			}
		}
	case ipMask:
		// FortiGate "IP MASK" pair: exactly two space-separated dotted-quad
		// tokens (address + contiguous netmask), e.g. "169.254.1.1
		// 255.255.255.255". Empty / single-token / malformed values are device
		// rejections (the fwm-t4 HTTP 500 class).
		if !validIPMaskPair(val) {
			return mk(`must be "<ipv4> <dotted-netmask>" (two tokens, contiguous mask)`)
		}
	case proposalIKE:
		if s.ikeProp != nil {
			if ok, why := s.ikeProp(val); !ok {
				return mk("invalid IKE proposal: " + why)
			}
		}
	case proposalESP:
		if s.espProp != nil {
			if ok, why := s.espProp(val); !ok {
				return mk("invalid ESP proposal: " + why)
			}
		}
	}
	return Finding{}, false
}

// unwrapBody parses a step body into a flat field map. OPNsense bodies wrap their
// fields under a single model key (e.g. {"connection":{…}}); FortiGate bodies are
// flat cmdb objects. A single top-level key whose value is a JSON object is
// treated as an OPNsense wrapper and unwrapped.
func unwrapBody(body string) (map[string]any, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &top); err != nil {
		return nil, false
	}
	if len(top) == 1 {
		for _, raw := range top {
			var inner map[string]any
			if json.Unmarshal(raw, &inner) == nil {
				return inner, true
			}
		}
	}
	var flat map[string]any
	if err := json.Unmarshal([]byte(body), &flat); err != nil {
		return nil, false
	}
	return flat, true
}

// asString renders a JSON scalar as the string the device would receive. Renders
// stringify numbers/bools already, but FortiGate emits some numerics (keylife,
// distance) as JSON numbers — normalize them.
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func validAddress(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return isHostname(s)
}

// validIPMaskPair validates FortiOS's "<ipv4> <dotted-netmask>" two-token form
// (system/interface ip / remote-ip): both tokens dotted-quad IPv4, the mask
// contiguous (net.IPMask.Size reports bits=32 only for contiguous masks).
// Mirrors the collector's fwapi evaluator (pinned by the cross-repo ParityCases).
func validIPMaskPair(val string) bool {
	parts := strings.Fields(val)
	if len(parts) != 2 {
		return false
	}
	if net.ParseIP(parts[0]).To4() == nil {
		return false
	}
	m := net.ParseIP(parts[1]).To4()
	if m == nil {
		return false
	}
	_, bits := net.IPMask(m).Size()
	return bits == 32
}

// isHostname is a permissive RFC-1123-ish check — enough to distinguish a real
// FQDN from a strongSwan sentinel like "%any".
func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "%*/ ") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
	}
	return true
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
