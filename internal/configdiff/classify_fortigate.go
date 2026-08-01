package configdiff

import (
	"fmt"
	"strings"
)

// classifyFortiGate holds the FortiOS risk rules, moved verbatim out of
// ClassifyChange when classification became vendor-dispatched. ok is false when
// no rule matched, so the dispatcher can fall through to the shared info
// catch-all — the catch-all deliberately does NOT live here, or this function
// would always match and no other vendor's rules would ever be reached.
func classifyFortiGate(c ObjectChange) (Risk, bool) {
	label := c.Path

	switch {
	case c.Kind == "firewall.policy":
		if c.Op != "removed" && !attrBecame(c, "action", "deny") {
			for _, d := range c.Attrs {
				switch d.Key {
				case "srcaddr", "dstaddr", "srcaddr6", "dstaddr6":
					if isAnyValue(d.New) {
						return risk(SeverityHigh, "exposure",
							fmt.Sprintf("%s now permits %s = %s (ANY)", label, d.Key, strings.TrimSpace(d.New))), true
					}
				case "service":
					if isAnyValue(d.New) {
						return risk(SeverityHigh, "exposure",
							fmt.Sprintf("%s now permits service = %s (ANY)", label, strings.TrimSpace(d.New))), true
					}
				}
			}
		}
		if attrBecame(c, "status", "disable") {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was disabled", label)), true
		}
		if attrBecame(c, "logtraffic", "disable") {
			return risk(SeverityMedium, "logging", fmt.Sprintf("%s traffic logging disabled", label)), true
		}
		if c.Op == "removed" {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was removed", label)), true
		}
		if c.Op == "added" {
			return risk(SeverityMedium, "policy", fmt.Sprintf("%s was added", label)), true
		}

	case c.Kind == "system.admin":
		if c.Op == "added" {
			return risk(SeverityHigh, "admin", fmt.Sprintf("new administrator %q was added", c.Name)), true
		}
		for _, d := range c.Attrs {
			if strings.HasPrefix(d.Key, "trusthost") && (isAnyValue(d.New) || strings.TrimSpace(d.New) == "") {
				return risk(SeverityHigh, "admin",
					fmt.Sprintf("admin %q trusted-host restriction widened/removed (%s)", c.Name, d.Key)), true
			}
		}
		if c.Op == "removed" {
			return risk(SeverityMedium, "admin", fmt.Sprintf("administrator %q was removed", c.Name)), true
		}

	case strings.Contains(c.Kind, "vpn.ipsec"):
		for _, d := range c.Attrs {
			if d.Key == "proposal" && hasWeakCrypto(d.New) {
				return risk(SeverityHigh, "crypto",
					fmt.Sprintf("%s IPsec proposal weakened -> %s", label, strings.TrimSpace(d.New))), true
			}
			if d.Key == "dhgrp" && hasWeakDHGroup(d.New) {
				return risk(SeverityHigh, "crypto",
					fmt.Sprintf("%s Diffie-Hellman group weakened -> %s", label, strings.TrimSpace(d.New))), true
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
					fmt.Sprintf("%s cleartext management access enabled: allowaccess = %s", label, strings.TrimSpace(d.New))), true
			}
			if has("ssh") || has("https") {
				return risk(SeverityMedium, "mgmt-access",
					fmt.Sprintf("%s management access changed: allowaccess = %s", label, strings.TrimSpace(d.New))), true
			}
		}
	}

	return Risk{}, false
}
