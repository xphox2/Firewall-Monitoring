// Package logfields builds the matchable field map the event-rule engine
// evaluates a syslog message against: the base syslog columns, the vendor's
// own tokens (every FortiOS key=value pair, the pf filterlog columns, CEF
// extension keys …) under their native names, and the canonical `event.*`
// view of the normalized Event (internal/normalize) beside them.
//
// Since 0.11.293 the tokenizing lives in internal/normalize/family and the
// per-vendor meaning in internal/normalize; this package is the rule engine's
// view over one Normalize call. Native keys are unchanged from the earlier
// per-vendor extractors (FortiGate: lowercased kv pairs; OPNsense / pfSense:
// interface, reason, action, dir, ipversion, proto, protoname, srcip, dstip,
// srcport, dstport), so every operator rule keeps matching; the canonical
// keys are namespaced because `action` is already taken by FortiOS
// `action="deny"` and filterlog `action=block` (plan §7.1).
package logfields

import (
	"regexp"
	"strings"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
)

// Fields builds the full matchable field map for a syslog message under the
// given device vendor. Base fields are always present; the vendor's native
// tokens are added when a normalizer family recognised the line (also when
// the mapper reported the line Unparsed — a FortiOS line of an unmapped type
// still exposes its kv pairs); the `event.*` keys only when the line mapped
// to an Event. Base severity/facility stay authoritative over a native key of
// the same name.
//
// C2 (review): a pre-1.3.48 collector's RFC 5424 space-split consumed the
// first tokens of a FortiGate key=value line into Hostname/AppName/ProcessID/
// MessageID/StructuredData, so date/devname/devid — and sometimes logid/type
// — land OUTSIDE msg.Message. normalize.Reframe re-joins them before
// tokenizing, so a rule on logid/type/devname is reliable regardless of where
// the split fell (and across mixed collector versions).
func Fields(vendor string, msg *models.SyslogMessage) map[string]string {
	ev, out := normalize.Normalize(vendor, msg)
	// Size once: base 5 + native (a FortiOS traffic line has ~40 pairs) + up
	// to ~45 event.* keys. Growing a map through rehashes costs more than the
	// slack here.
	dst := make(map[string]string, 5+len(ev.Native)+48)
	dst["severity"] = itoa(msg.Severity)
	dst["facility"] = itoa(msg.Facility)
	dst["app_name"] = msg.AppName
	dst["hostname"] = msg.Hostname
	dst["message"] = msg.Message
	for k, v := range ev.Native {
		if k == "severity" || k == "facility" {
			continue
		}
		dst[k] = v
	}
	if out.Kind == normalize.OutcomeOK {
		ev.Fields(dst)
	}
	return dst
}

var (
	reDigits = regexp.MustCompile(`\d+`)
	reSpace  = regexp.MustCompile(`\s+`)
)

// Normalize collapses variable tokens (numbers, IP octets) in a message into a
// stable template, so distinct-but-equivalent messages group together. Powers
// the rule-tester "top patterns" view and the syslog_summaries.message_pattern
// fix. Deliberately cheap and approximate. (Unrelated to internal/normalize,
// which maps a line to a typed Event.)
func Normalize(message string) string {
	s := reDigits.ReplaceAllString(message, "#")
	s = reSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func itoa(n int) string {
	// small, allocation-light itoa for the common non-negative syslog range
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
