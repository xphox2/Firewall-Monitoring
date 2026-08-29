// Package logfields extracts vendor-specific, matchable fields from a syslog
// message so the event-rule engine can match on structured content (FortiGate
// subtype/level/logid/action/…) rather than only facility/severity.
//
// Extraction is vendor-aware via the same registry idiom used by
// internal/configdiff and internal/snmp: each vendor registers an Extractor in
// init(); Lookup(vendor) returns it (or a generic fallback). FortiGate parses
// its key=value stream; OPNsense and pfSense parse the shared pf `filterlog` CSV.
package logfields

import (
	"regexp"
	"strings"

	"firewall-mon/internal/models"
)

// Extractor adds vendor-specific fields into dst. The base fields (severity,
// facility, app_name, hostname, message) are already populated by Fields; an
// Extractor reads the reconstructed raw line and adds whatever its vendor log
// format exposes (for FortiGate, every key=value pair).
type Extractor interface {
	Vendor() string
	Extract(raw string, dst map[string]string)
}

var registry = map[string]Extractor{}

// Register records an Extractor under its (lowercased) vendor name. Called from
// each vendor file's init(); a later registration for the same vendor wins.
func Register(e Extractor) {
	registry[strings.ToLower(strings.TrimSpace(e.Vendor()))] = e
}

// Lookup returns the Extractor for vendor, or the generic fallback when the
// vendor is unknown/未-profiled. Never returns nil.
func Lookup(vendor string) Extractor {
	if e, ok := registry[strings.ToLower(strings.TrimSpace(vendor))]; ok {
		return e
	}
	return genericExtractor{}
}

// Has reports whether vendor has a registered (non-generic) rich extractor.
func Has(vendor string) bool {
	_, ok := registry[strings.ToLower(strings.TrimSpace(vendor))]
	return ok
}

// Fields builds the full matchable field map for a syslog message under the
// given device vendor. Base fields are always present; the vendor extractor
// adds structured fields.
//
// C2 (review): the collector's RFC5424 space-split consumes the first tokens of
// a FortiGate key=value line into Hostname/AppName/ProcessID/MessageID/
// StructuredData, so date/devname/devid — and sometimes logid/type — land
// OUTSIDE msg.Message. We reconstruct the original stream by re-joining those
// base parts with Message before extracting, so a rule on logid/type/devname is
// reliable regardless of where the split fell (and across mixed collector
// versions).
func Fields(vendor string, msg *models.SyslogMessage) map[string]string {
	dst := make(map[string]string, 24)
	dst["severity"] = itoa(msg.Severity)
	dst["facility"] = itoa(msg.Facility)
	dst["app_name"] = msg.AppName
	dst["hostname"] = msg.Hostname
	dst["message"] = msg.Message
	Lookup(vendor).Extract(reconstruct(msg), dst)
	return dst
}

// reconstruct rebuilds the raw log line from the collector's split fields so KV
// extraction sees the whole key=value stream. Empty/placeholder ("-") parts are
// dropped so they don't inject spurious tokens.
func reconstruct(msg *models.SyslogMessage) string {
	parts := make([]string, 0, 6)
	for _, p := range []string{msg.Hostname, msg.AppName, msg.ProcessID, msg.MessageID, msg.StructuredData, msg.Message} {
		if p != "" && p != "-" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " ")
}

var (
	reDigits = regexp.MustCompile(`\d+`)
	reSpace  = regexp.MustCompile(`\s+`)
)

// Normalize collapses variable tokens (numbers, IP octets) in a message into a
// stable template, so distinct-but-equivalent messages group together. Powers
// the rule-tester "top patterns" view and the syslog_summaries.message_pattern
// fix. Deliberately cheap and approximate.
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
