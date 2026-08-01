package configdiff

import (
	"fmt"
	"sort"
	"strings"
)

// Severity levels for a classified config change, ordered low -> high.
const (
	SeverityInfo     = "info"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severityRank = map[string]int{
	SeverityInfo:     0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// SeverityAtLeast reports whether severity a ranks >= severity b.
func SeverityAtLeast(a, b string) bool { return severityRank[a] >= severityRank[b] }

// Risk is the security classification of a single ObjectChange (or of an overall
// change set). Summary is an operator-facing one-line "security impact"; Category
// groups the kind of risk; ComplianceTags is reserved for a future framework-
// mapping pass (PCI/NIST/CIS) and is empty today.
type Risk struct {
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Summary        string   `json:"summary"`
	ComplianceTags []string `json:"compliance_tags,omitempty"`
}

func risk(sev, cat, summary string) Risk {
	return Risk{Severity: sev, Category: cat, Summary: summary}
}

// ClassifyChange assigns a security severity, category, and human-readable
// impact summary to a single object change. The rule set is intentionally data-
// driven (not wired into the alert path) so compliance packs can be layered on
// later via Risk.ComplianceTags without touching callers.
//
// Rules live in per-vendor files and are selected by ObjectChange.Vendor, which
// DiffObjects stamps. When Vendor is empty — a direct caller, or a test — every
// rule set is tried in turn; Kind namespaces are vendor-disjoint, so that
// reproduces the pre-split behavior exactly.
//
// The info catch-all below must stay HERE and not migrate into a vendor rule
// set: a vendor function that always reports a match would shadow every rule set
// after it in the chain.
func ClassifyChange(c ObjectChange) Risk {
	switch c.Vendor {
	case "fortigate":
		if r, ok := classifyFortiGate(c); ok {
			return r
		}
	case "opnsense", "pfsense":
		if r, ok := classifyOPNsense(c); ok {
			return r
		}
	default:
		if r, ok := classifyFortiGate(c); ok {
			return r
		}
		if r, ok := classifyOPNsense(c); ok {
			return r
		}
	}

	verb := map[string]string{"added": "added", "removed": "removed", "modified": "modified"}[c.Op]
	return risk(SeverityInfo, "config", fmt.Sprintf("%s %s", c.Path, verb))
}

// attrBecame reports whether key changed to want. Absence of the key from the
// deltas yields false: ObjectChange.Attrs carries CHANGES only, so an unchanged
// attribute is invisible here.
func attrBecame(c ObjectChange, key, want string) bool {
	for _, d := range c.Attrs {
		if d.Key == key {
			return strings.EqualFold(strings.Trim(d.New, `"`), want)
		}
	}
	return false
}

// attrGained reports whether key was ADDED or set to the presence sentinel.
//
// Vendors that encode "on" by the mere presence of an empty element (OPNsense
// writes <log/>, not <log>1</log>) need this: the parser emits attrPresentValue
// for such elements precisely so that gaining one is distinguishable from losing
// one. With a plain empty string the two produce byte-identical deltas.
func attrGained(c ObjectChange, key string) bool {
	for _, d := range c.Attrs {
		if d.Key == key {
			return d.New != ""
		}
	}
	return false
}

// attrCleared reports whether key was REMOVED — the inverse of attrGained, and
// how OPNsense encodes turning a flag off.
func attrCleared(c ObjectChange, key string) bool {
	for _, d := range c.Attrs {
		if d.Key == key {
			return d.Old != "" && d.New == ""
		}
	}
	return false
}

// ClassifyChanges classifies every change and derives an overall verdict: the
// highest severity present, and a summary that concatenates the security-relevant
// (>= medium) impacts.
func ClassifyChanges(cs []ObjectChange) (overall Risk, per []Risk) {
	per = make([]Risk, len(cs))
	overall = risk(SeverityInfo, "config", "no security-relevant changes")
	var impacts []string
	for i := range cs {
		r := ClassifyChange(cs[i])
		per[i] = r
		if severityRank[r.Severity] > severityRank[overall.Severity] {
			overall.Severity = r.Severity
			overall.Category = r.Category
		}
		if severityRank[r.Severity] >= severityRank[SeverityMedium] {
			impacts = append(impacts, r.Summary)
		}
	}
	if len(impacts) > 0 {
		sort.Strings(impacts)
		overall.Summary = strings.Join(impacts, "; ")
	} else if len(cs) > 0 {
		overall.Summary = fmt.Sprintf("%d configuration change(s), none security-relevant", len(cs))
	}
	return overall, per
}

// isAnyValue reports whether a config value denotes "any"/"all" — i.e. an
// unrestricted source, destination, or service.
func isAnyValue(v string) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`)) {
	case "all", "any", "0.0.0.0/0", "0.0.0.0 0.0.0.0", "::/0":
		return true
	}
	return false
}

// hasWeakCrypto reports whether an IPsec proposal string contains a deprecated
// cipher or hash (DES/3DES, MD5, SHA1, NULL).
func hasWeakCrypto(v string) bool {
	s := strings.ToLower(v)
	for _, weak := range []string{"des-", "3des", "-md5", "-sha1", "null"} {
		if strings.Contains(s, weak) {
			return true
		}
	}
	return false
}

// hasWeakDHGroup reports whether a dhgrp list includes a weak modular group (1, 2, 5).
func hasWeakDHGroup(v string) bool {
	for _, f := range strings.Fields(v) {
		switch strings.Trim(f, `"`) {
		case "1", "2", "5":
			return true
		}
	}
	return false
}
