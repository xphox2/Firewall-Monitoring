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
func ClassifyChange(c ObjectChange) Risk {
	label := c.Path

	became := func(key, want string) bool {
		for _, d := range c.Attrs {
			if d.Key == key {
				return strings.EqualFold(strings.Trim(d.New, `"`), want)
			}
		}
		return false
	}

	switch {
	case c.Kind == "firewall.policy":
		if c.Op != "removed" && !became("action", "deny") {
			for _, d := range c.Attrs {
				switch d.Key {
				case "srcaddr", "dstaddr", "srcaddr6", "dstaddr6":
					if isAnyValue(d.New) {
						return risk(SeverityHigh, "exposure",
							fmt.Sprintf("%s now permits %s = %s (ANY)", label, d.Key, strings.TrimSpace(d.New)))
					}
				case "service":
					if isAnyValue(d.New) {
						return risk(SeverityHigh, "exposure",
							fmt.Sprintf("%s now permits service = %s (ANY)", label, strings.TrimSpace(d.New)))
					}
				}
			}
		}
		if became("status", "disable") {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was disabled", label))
		}
		if became("logtraffic", "disable") {
			return risk(SeverityMedium, "logging", fmt.Sprintf("%s traffic logging disabled", label))
		}
		if c.Op == "removed" {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was removed", label))
		}
		if c.Op == "added" {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was added", label))
		}

	case c.Kind == "system.admin":
		if c.Op == "added" {
			return risk(SeverityHigh, "admin", fmt.Sprintf("new administrator %q was added", c.Name))
		}
		for _, d := range c.Attrs {
			if strings.HasPrefix(d.Key, "trusthost") && (isAnyValue(d.New) || strings.TrimSpace(d.New) == "") {
				return risk(SeverityHigh, "admin",
					fmt.Sprintf("admin %q trusted-host restriction widened/removed (%s)", c.Name, d.Key))
			}
		}
		if c.Op == "removed" {
			return risk(SeverityMedium, "admin", fmt.Sprintf("administrator %q was removed", c.Name))
		}

	case strings.Contains(c.Kind, "vpn.ipsec"):
		for _, d := range c.Attrs {
			if d.Key == "proposal" && hasWeakCrypto(d.New) {
				return risk(SeverityHigh, "crypto",
					fmt.Sprintf("%s IPsec proposal weakened -> %s", label, strings.TrimSpace(d.New)))
			}
			if d.Key == "dhgrp" && hasWeakDHGroup(d.New) {
				return risk(SeverityHigh, "crypto",
					fmt.Sprintf("%s Diffie-Hellman group weakened -> %s", label, strings.TrimSpace(d.New)))
			}
		}

	case c.Kind == "system.interface":
		for _, d := range c.Attrs {
			if d.Key != "allowaccess" {
				continue
			}
			prots := strings.Fields(strings.ToLower(strings.Trim(d.New, `"`)))
			has := func(p string) bool {
				for _, x := range prots {
					if x == p {
						return true
					}
				}
				return false
			}
			if has("telnet") || has("http") {
				return risk(SeverityHigh, "mgmt-access",
					fmt.Sprintf("%s cleartext management access enabled: allowaccess = %s", label, strings.TrimSpace(d.New)))
			}
			if has("ssh") || has("https") {
				return risk(SeverityMedium, "mgmt-access",
					fmt.Sprintf("%s management access changed: allowaccess = %s", label, strings.TrimSpace(d.New)))
			}
		}
	}

	verb := map[string]string{"added": "added", "removed": "removed", "modified": "modified"}[c.Op]
	return risk(SeverityInfo, "config", fmt.Sprintf("%s %s", label, verb))
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
