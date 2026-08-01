package configdiff

import (
	"fmt"
	"strings"
)

// classifyOPNsense holds the OPNsense/pfSense risk rules. ok is false when no
// rule matched; the shared info catch-all lives in ClassifyChange.
//
// Note the inverted encoding throughout: OPNsense represents "off" by the
// ABSENCE of an element rather than by an explicit value — <disabled>1</disabled>
// present means disabled, <log> absent means logging off. FortiGate's
// became(key, "disable") idiom therefore does not apply, and attrGained /
// attrCleared carry the weight instead. Both rely on the parser emitting
// attrPresentValue for empty elements; with a plain "" the gained and cleared
// deltas are byte-identical.
func classifyOPNsense(c ObjectChange) (Risk, bool) {
	label := c.Path

	switch {
	// Legacy <filter><rule> on OPNsense, and pfSense's rules at the same Kind.
	case c.Kind == "filter.rule":
		if c.Op != "removed" && !isBlockingRuleType(attrNew(c, "type")) {
			if widened, side := widenedToAny(c); widened {
				return risk(SeverityHigh, "exposure",
					fmt.Sprintf("%s now permits %s = any", label, side)), true
			}
		}
		if attrBecame(c, "disabled", "1") {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was disabled", label)), true
		}
		if attrCleared(c, "log") {
			return risk(SeverityMedium, "logging", fmt.Sprintf("%s traffic logging disabled", label)), true
		}
		if c.Op == "removed" {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was removed", label)), true
		}
		if c.Op == "added" {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was added", label)), true
		}

	case c.Kind == "nat.rule":
		if c.Op == "added" && strings.Contains(strings.ToLower(attrNew(c, "interface")), "wan") {
			return risk(SeverityMedium, "exposure",
				fmt.Sprintf("%s inbound port-forward added on a WAN interface", label)), true
		}

	case c.Kind == "system.user":
		if c.Op == "added" {
			return risk(SeverityHigh, "admin", fmt.Sprintf("new system user %q was added", c.Name)), true
		}
		if grantsFullPrivilege(c) {
			return risk(SeverityHigh, "admin",
				fmt.Sprintf("user %q was granted full GUI privileges", c.Name)), true
		}
		if sh := attrNew(c, "shell"); sh != "" && sh != attrPresentValue && !strings.Contains(sh, "nologin") {
			return risk(SeverityHigh, "admin",
				fmt.Sprintf("user %q was granted shell access (%s)", c.Name, strings.TrimSpace(sh))), true
		}
		if c.Op == "removed" {
			return risk(SeverityMedium, "admin", fmt.Sprintf("system user %q was removed", c.Name)), true
		}

	case c.Kind == "system.group":
		if grantsFullPrivilege(c) {
			return risk(SeverityHigh, "admin",
				fmt.Sprintf("group %q was granted full GUI privileges", c.Name)), true
		}
		if strings.EqualFold(c.Name, "admins") && attrGained(c, "member") {
			return risk(SeverityHigh, "admin",
				fmt.Sprintf("a member was added to the %q group", c.Name)), true
		}

	case c.Kind == "system":
		if attrBecame(c, "webgui.protocol", "http") {
			return risk(SeverityHigh, "mgmt-access",
				fmt.Sprintf("%s web management switched to cleartext HTTP", label)), true
		}
		if attrGained(c, "ssh.enabled") {
			return risk(SeverityMedium, "mgmt-access",
				fmt.Sprintf("%s SSH management access enabled", label)), true
		}
		if attrGained(c, "webgui.nohttpreferercheck") {
			return risk(SeverityMedium, "mgmt-access",
				fmt.Sprintf("%s HTTP referer check disabled (CSRF protection weakened)", label)), true
		}

	case c.Kind == "interfaces":
		for _, key := range []string{"blockpriv", "blockbogons"} {
			if attrCleared(c, key) {
				return risk(SeverityMedium, "exposure",
					fmt.Sprintf("%s %s filtering disabled", label, key)), true
			}
		}

	case strings.HasPrefix(c.Kind, "OPNsense.Swanctl."):
		for _, d := range c.Attrs {
			switch d.Key {
			case "proposals", "esp_proposals":
				if hasWeakCrypto(d.New) || hasWeakDHGroup(d.New) {
					return risk(SeverityHigh, "crypto",
						fmt.Sprintf("%s IPsec proposal weakened -> %s", label, strings.TrimSpace(d.New))), true
				}
			}
		}
		if attrBecame(c, "aggressive", "1") {
			return risk(SeverityHigh, "crypto",
				fmt.Sprintf("%s switched to IKEv1 aggressive mode", label)), true
		}
	}

	return Risk{}, false
}

// widenedToAny reports whether this change WIDENS a rule toward any→any, and
// which side moved. Direction matters: narrowing away from any is a security
// improvement and must never raise an exposure finding.
//
// For an added object every attribute arrives as New (see attrsAsSide), so the
// same attrGained test covers both ops — but an add is only interesting when
// BOTH sides are any, whereas a modify is interesting as soon as EITHER side is
// gained. That mirrors the FortiGate precedent, which likewise fires on a single
// widened field rather than requiring a conjunction.
func widenedToAny(c ObjectChange) (bool, string) {
	src, dst := attrGained(c, "source.any"), attrGained(c, "destination.any")
	if c.Op == "added" {
		if src && dst {
			return true, "source and destination"
		}
		return false, ""
	}
	switch {
	case src && dst:
		return true, "source and destination"
	case src:
		return true, "source"
	case dst:
		return true, "destination"
	}
	return false, ""
}

// grantsFullPrivilege reports whether a user or group gained the OPNsense
// all-pages privilege.
func grantsFullPrivilege(c ObjectChange) bool {
	for _, d := range c.Attrs {
		if d.Key != "priv" {
			continue
		}
		if strings.Contains(strings.ToLower(d.New), "page-all") &&
			!strings.Contains(strings.ToLower(d.Old), "page-all") {
			return true
		}
	}
	return false
}

// isBlockingRuleType reports whether a pf rule type denies traffic. An empty
// value counts as permitting: OPNsense omits <type> only on pass rules, and for
// a modified rule whose type did not change the attribute is absent from the
// deltas entirely. That blindness is inherited from the FortiGate precedent
// (see classifyFortiGate's !attrBecame(c, "action", "deny")); fixing it properly
// means giving the classifier the full post-image, which is a larger change.
func isBlockingRuleType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "block", "reject":
		return true
	}
	return false
}

// attrNew returns the post-change value of key, or "" when the attribute did not
// change (and is therefore absent from the deltas).
func attrNew(c ObjectChange, key string) string {
	for _, d := range c.Attrs {
		if d.Key == key {
			return d.New
		}
	}
	return ""
}
