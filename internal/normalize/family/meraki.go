package family

import "strings"

// Meraki is one Cisco Meraki syslog body after the `<epoch> <host>` header:
//
//	flows src=192.0.2.10 dst=203.0.113.20 mac=00:00:5E:00:53:0A protocol=tcp sport=51514 dport=443 pattern: allow all
//	urls src=192.0.2.10:51514 dst=203.0.113.20:80 mac=... request: GET http://www.example.com/index.html
//	security_event ids_alerted signature=1:2100498:7 priority=2 timestamp=... direction=egress protocol=tcp/ip src=192.0.2.10:51514 dst=203.0.113.20:80 message: GPL ATTACK_RESPONSE id check returned root
//	events type=vpn_connectivity_change vpn_type='site-to-site' peer_contact='203.0.113.5:51856' connectivity='false'
//
// The first token is the dashboard role (Category); bare words before the
// first `k=v` are the Subtype (`ids_alerted`, `allow`, …); `k=v` tokens are
// unquoted or single-quoted (`key='value with spaces'`); a `word:` token
// (pattern:, message:, request:) ends the pairs and everything after it is
// the Tail. Free-text bodies (`failover to wan1`, `dhcp lease of ip …`) have
// no pairs: Subtype holds the whole body's words. Built from the documented
// samples; untested on real hardware.
type Meraki struct {
	Category string
	Subtype  string // bare words before the first k=v, space-joined
	Fields   map[string]string
	TailKind string // "pattern" | "message" | "request" | ""
	Tail     string
}

// merakiCategories are the dashboard roles a body may start with. Used by the
// gate when the collector's AppName is unavailable (a v5 collector split the
// Meraki header positionally, so the category may sit inside the re-joined
// line rather than in app_name).
var merakiCategories = map[string]bool{
	"flows": true, "firewall": true, "vpn_firewall": true, "cellular_firewall": true,
	"urls": true, "ids-alerts": true, "security_event": true, "events": true,
	"airmarshal_events": true, "ip_flow_start": true, "ip_flow_end": true,
	"bridge_anyconnect_client_vpn_firewall": true,
}

// IsMerakiCategory reports whether tok is a known Meraki role token.
func IsMerakiCategory(tok string) bool { return merakiCategories[tok] }

// ParseMeraki tokenizes a Meraki body. category may be supplied by the caller
// (the collector's app_name) — s is then the body alone, the caller having
// removed any re-joined header (a body may legitimately contain a category
// word, e.g. a rule comment "firewall rule for printers", so the tokenizer
// never searches for it when told the category); when empty, the first known
// category token in s is used and the body starts after it. ok=false when no
// category is found.
func ParseMeraki(category, s string) (Meraki, bool) {
	m := Meraki{Fields: make(map[string]string, 12)}
	if category != "" && merakiCategories[category] {
		m.Category = category
	} else {
		found := false
		rest := s
		for !found && rest != "" {
			tok, after := nextToken(rest)
			if merakiCategories[tok] {
				m.Category, s, found = tok, after, true
				break
			}
			if strings.ContainsRune(tok, '=') {
				break // pairs started; no category precedes them
			}
			rest = after
		}
		if !found {
			return Meraki{}, false
		}
	}

	var subtype []string
	for s != "" {
		tok, after := nextToken(s)
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			key := strings.ToLower(tok[:eq])
			val := tok[eq+1:]
			if strings.HasPrefix(val, "'") {
				// A single-quoted value may span spaces; it ends at a quote
				// followed by a space or the end of the line, so an apostrophe
				// inside the value (`peer_ident='o'brien branch'`) stays in it.
				if q := closingQuote(s[eq+2:]); q >= 0 {
					val = s[eq+2 : eq+2+q]
					after = strings.TrimLeft(s[eq+2+q+1:], " ")
				} else {
					val = strings.TrimPrefix(val, "'")
				}
			}
			m.Fields[key] = val
			s = after
			continue
		}
		if strings.HasSuffix(tok, ":") && len(tok) > 1 {
			m.TailKind = strings.ToLower(tok[:len(tok)-1])
			m.Tail = after
			m.Subtype = strings.Join(subtype, " ")
			return m, true
		}
		subtype = append(subtype, tok)
		s = after
	}
	m.Subtype = strings.Join(subtype, " ")
	return m, true
}

// closingQuote returns the index of the first `'` in s that is followed by a
// space or ends the string, or -1.
func closingQuote(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' && (i+1 == len(s) || s[i+1] == ' ') {
			return i
		}
	}
	return -1
}

func nextToken(s string) (string, string) {
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i+1:], " ")
}
