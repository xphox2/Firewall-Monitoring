// Package normalize turns one vendor's syslog line into the vendor-neutral
// Event (roadmap §1) that later PRs store in net_events / sec_events and that
// the rule engine already sees as `event.*` fields through logfields.Fields.
//
// Dispatch is per vendor, not fleet-wide sniffing: a Mapper registered for
// the device's vendor names an ORDERED list of tokenizer families
// (internal/normalize/family) and the first family whose cheap gate accepts
// the line tokenizes it; the mapper then gives the tokens meaning. One device
// legitimately emits several formats (UniFi: netfilter + CEF + dnsmasq;
// FortiGate: key=value, or CEF when switched to it), which is why the list is
// per vendor. The collector's `format` hint (models.SyslogMessage.Format,
// 1.3.48+) only reorders the list — a row from an older collector or one
// re-read from the database has no hint and goes through the same list.
//
// The registry idiom (Register in init(), Lookup with a generic fallback) is
// the one internal/logfields, internal/configdiff and internal/snmp use.
// Unknown vendors get the generic mapper (CEF → filterlog → key=value), which
// maps only what those shapes state outright.
package normalize

import (
	"strings"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize/family"
)

// Family identifies a tokenizer (roadmap §2.1).
type Family uint8

const (
	FamilyFortiOSKV Family = iota + 1 // FortiOS `key="value"` stream
	FamilyKV                          // generic space-separated k=v
	FamilyCEF                         // ArcSight CEF record
	FamilyNetfilter                   // Linux netfilter LOG prefix
	FamilyMeraki                      // Meraki `<category> k=v … tail: text`
	FamilyFilterlog                   // pf filterlog CSV
	FamilyText                        // free-text daemon regex catalogue
)

var familyNames = map[Family]string{
	FamilyFortiOSKV: "fortios_kv", FamilyKV: "kv", FamilyCEF: "cef", FamilyNetfilter: "netfilter",
	FamilyMeraki: "meraki", FamilyFilterlog: "filterlog", FamilyText: "text",
}

func (f Family) String() string { return familyNames[f] }

// Tokens is the output of one family's tokenizer; exactly one of the typed
// members is set, named by Family.
type Tokens struct {
	Family Family
	KV     map[string]string
	CEF    *family.CEF
	NF     *family.Netfilter
	MK     *family.Meraki
	FL     *family.Filterlog
	TX     *family.Text
}

// Mapper gives a vendor's tokens their meaning. Map fills ev (whose Ts,
// DeviceID, ProbeID and Native are already set) and reports the outcome; it
// must not retain tok or msg.
type Mapper interface {
	Vendor() string
	Families() []Family
	Map(tok Tokens, msg *models.SyslogMessage, ev *Event) Outcome
}

var registry = map[string]Mapper{}

// Register records a Mapper under its (lowercased) vendor name. Called from
// each vendor file's init(); a later registration for the same vendor wins.
func Register(m Mapper) {
	registry[strings.ToLower(strings.TrimSpace(m.Vendor()))] = m
}

// Lookup returns the Mapper for vendor, or the generic mapper when the vendor
// has none. Never returns nil.
func Lookup(vendor string) Mapper {
	if m, ok := registry[strings.ToLower(strings.TrimSpace(vendor))]; ok {
		return m
	}
	return genericMapper{}
}

// Has reports whether vendor has its own (non-generic) mapper.
func Has(vendor string) bool {
	_, ok := registry[strings.ToLower(strings.TrimSpace(vendor))]
	return ok
}

// Normalize maps msg under the device's vendor. The Event's Native tokens are
// populated whenever a family recognised the line, even when the mapper
// reports Unparsed, so a caller that only wants the vendor's own fields
// (logfields.Fields) never tokenizes twice.
func Normalize(vendor string, msg *models.SyslogMessage) (Event, Outcome) {
	return normalize(vendor, msg, Reframe(msg))
}

// NormalizeFramed is Normalize for a row whose collector guarantees the
// framing contract (relay schema v6, collector 1.3.50+): the header columns
// are right and Message is the whole body, so the re-framing join is skipped
// and the families tokenize Message alone. Every family locates its payload
// by its own vocabulary, so this and Normalize agree on a correctly framed
// row; only a pre-1.3.48 positional split needs the join.
func NormalizeFramed(vendor string, msg *models.SyslogMessage) (Event, Outcome) {
	return normalize(vendor, msg, msg.Message)
}

func normalize(vendor string, msg *models.SyslogMessage, raw string) (Event, Outcome) {
	ev := Event{Ts: msg.Timestamp, DeviceID: msg.DeviceID, ProbeID: msg.ProbeID}
	m := Lookup(vendor)
	fams := m.Families()
	// The collector's format hint moves its family to the front; the rest
	// keep their order. Unknown hints change nothing.
	first := hintFamily(msg.Format)
	for pass := 0; pass < 2; pass++ {
		for _, f := range fams {
			if (pass == 0) != (f == first) {
				continue
			}
			tok, ok := tokenize(f, raw, msg)
			if !ok {
				continue
			}
			ev.Native = tok.native()
			out := m.Map(tok, msg, &ev)
			out.Family = f
			if out.Kind == OutcomeOK {
				finalize(&ev)
			}
			return ev, out
		}
	}
	return ev, Outcome{Kind: OutcomeNoFamily, Reason: m.Vendor() + ": no family recognised the line"}
}

// hintFamily maps the collector's format hint (models.SyslogMessage.Format)
// to the family to try first; 0 for no or an unknown hint.
func hintFamily(hint string) Family {
	switch hint {
	case "fortios_kv":
		return FamilyFortiOSKV
	case "cef":
		return FamilyCEF
	case "meraki":
		return FamilyMeraki
	}
	return 0
}

// Reframe rebuilds the raw log line from the collector's header columns so a
// tokenizer sees the whole body wherever the split fell: a pre-1.3.48
// collector's positional RFC 5424 parse put the first tokens of a FortiOS
// key=value line (and the Meraki category, the BSD tag …) into
// Hostname/AppName/ProcessID/MessageID/StructuredData. Every family locates
// its payload inside the joined string, so joining is harmless when the
// columns were right. A `fortios_kv` row needs no join: the collector keeps
// the whole body in Message and derives the columns from it.
func Reframe(msg *models.SyslogMessage) string {
	if msg.Format == "fortios_kv" {
		return msg.Message
	}
	parts := make([]string, 0, 6)
	for _, p := range []string{msg.Hostname, msg.AppName, msg.ProcessID, msg.MessageID, msg.StructuredData, msg.Message} {
		if p != "" && p != "-" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " ")
}

// tokenize runs family f's gate and tokenizer over raw.
func tokenize(f Family, raw string, msg *models.SyslogMessage) (Tokens, bool) {
	tok := Tokens{Family: f}
	switch f {
	case FamilyFortiOSKV, FamilyKV:
		if !family.HasKV(raw) {
			return tok, false
		}
		tok.KV = family.ParseKV(raw)
	case FamilyCEF:
		c, ok := family.ParseCEF(raw)
		if !ok {
			return tok, false
		}
		tok.CEF = &c
	case FamilyNetfilter:
		if !family.HasNetfilter(raw) {
			return tok, false
		}
		nf, ok := family.ParseNetfilter(raw)
		if !ok {
			return tok, false
		}
		tok.NF = &nf
	case FamilyMeraki:
		// With the category in app_name the body is tokenized alone: the
		// 1.3.48+ collector's Message IS the body, and a pre-1.3.48 re-joined
		// line is `<host> <category> <body>` — strip exactly that header rather
		// than searching for the category word, which a rule comment or a host
		// named `firewall` would also contain.
		cat, body := "", raw
		if family.IsMerakiCategory(msg.AppName) {
			cat = msg.AppName
			if msg.Format == "meraki" {
				body = msg.Message
			} else if prefix := merakiHeader(msg); strings.HasPrefix(raw, prefix) {
				body = raw[len(prefix):]
			}
		}
		mk, ok := family.ParseMeraki(cat, body)
		if !ok {
			return tok, false
		}
		tok.MK = &mk
	case FamilyFilterlog:
		fl, ok := family.ParseFilterlog(raw)
		if !ok {
			return tok, false
		}
		tok.FL = &fl
	case FamilyText:
		if !family.HasText(raw) {
			return tok, false
		}
		tx, ok := family.ParseText(raw)
		if !ok {
			return tok, false
		}
		tok.TX = &tx
	default:
		return tok, false
	}
	return tok, true
}

// merakiHeader is the `<host> <category> ` prefix Reframe puts in front of a
// Meraki body whose category sits in app_name.
func merakiHeader(msg *models.SyslogMessage) string {
	if msg.Hostname != "" && msg.Hostname != "-" {
		return msg.Hostname + " " + msg.AppName + " "
	}
	return msg.AppName + " "
}

// native returns the vendor's own key→value view of the tokens: the map
// internal/logfields has always exposed to event rules for KV and filterlog
// lines, and the equivalent flat, lowercased map for the new families.
func (t *Tokens) native() map[string]string {
	switch t.Family {
	case FamilyFortiOSKV, FamilyKV:
		return t.KV
	case FamilyCEF:
		m := t.CEF.Ext
		m["cef_vendor"], m["cef_product"], m["cef_version"] = t.CEF.Vendor, t.CEF.Product, t.CEF.DeviceVersion
		m["cef_id"], m["cef_name"], m["cef_severity"] = t.CEF.SignatureID, t.CEF.Name, t.CEF.Severity
		return m
	case FamilyNetfilter:
		m := t.NF.Fields
		m["chain"], m["verdict"] = t.NF.Ruleset, t.NF.Verdict
		if t.NF.Index != "" {
			m["rule_index"] = t.NF.Index
		}
		return m
	case FamilyMeraki:
		m := t.MK.Fields
		m["category"] = t.MK.Category
		if t.MK.Subtype != "" {
			m["subtype"] = t.MK.Subtype
		}
		if t.MK.TailKind != "" {
			m[t.MK.TailKind] = t.MK.Tail
		}
		return m
	case FamilyFilterlog:
		m := make(map[string]string, 12)
		t.FL.Fields(m)
		return m
	case FamilyText:
		m := t.TX.Fields
		m["text_kind"] = t.TX.Kind
		return m
	}
	return nil
}

// finalize derives the fields that depend on several others once the mapper
// is done: the rule identity key (roadmap §1.3).
func finalize(ev *Event) {
	if ev.RuleKey == "" {
		ev.RuleKey = RuleKey(ev.RuleUID, ev.RuleID, ev.RuleName, ev.Ruleset, ev.RuleIndex)
	}
}
