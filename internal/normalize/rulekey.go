package normalize

import (
	"strconv"
	"strings"
)

// RuleKey is the single group-by key for policy analytics (roadmap §1.3),
// derived from the first available identity tier and prefixed with that tier
// so the UI can show how stable the grouping is:
//
//	u:<uid>              vendor UUID (FortiGate poluuid, pf tracker) — survives rename and reorder
//	i:[<ruleset>/]<id>   numeric id (FortiGate policyid, pf rule number) — survives rename
//	n:[<ruleset>/]<name> rule name / text (Meraki `pattern:`) — breaks on rename
//	x:[<ruleset>/]<n>    position (UniFi chain index) — breaks on reorder
//	""                   no rule reported (NULL)
//
// The ruleset (FortiGate VDOM `vd=`, UniFi chain or policy type, Meraki
// firewall ruleset) qualifies every tier but the UUID one because ids, names
// and positions are only unique within it: policy 12 in VDOM root and policy
// 12 in VDOM dmz are different policies (operator decision: VDOM support
// required, ruleset in the rollup key). `/` separates the ruleset from the
// value, so a `/` inside the ruleset itself (UniFi policy type `IDS/IPS`)
// becomes `_` — `n:ids_ips/<name>` is unambiguous, `n:ids/ips/<name>` is not.
// Names are lower-cased and whitespace-collapsed so the Meraki
// `pattern: allow  All` spellings group together.
func RuleKey(uid string, id *int64, name, ruleset string, index *int32) string {
	switch {
	case uid != "":
		return "u:" + uid
	case id != nil:
		return "i:" + qualify(ruleset, strconv.FormatInt(*id, 10))
	case name != "":
		return "n:" + qualify(ruleset, normalizeName(name))
	case index != nil:
		return "x:" + qualify(ruleset, strconv.FormatInt(int64(*index), 10))
	}
	return ""
}

func qualify(ruleset, v string) string {
	if ruleset == "" {
		return v
	}
	return strings.ReplaceAll(ruleset, "/", "_") + "/" + v
}

// normalizeName lower-cases and collapses runs of whitespace to one space.
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.ContainsAny(s, "\t  ") && !strings.Contains(s, "  ") {
		return s
	}
	return strings.Join(strings.Fields(s), " ")
}
