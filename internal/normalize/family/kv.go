// Package family holds the syslog tokenizers the normalizer dispatches to
// (roadmap §2.1): FortiOS / generic key=value, ArcSight CEF, the pf filterlog
// CSV and a small free-text regex catalogue (the Linux netfilter LOG prefix
// and the Cisco Meraki positional body arrive with their mappers in S-2b). A
// tokenizer knows the SHAPE of a line and nothing about what the keys mean —
// that is the vendor mapper's job in internal/normalize. Everything here is non-regex and allocation-light where
// it sits on the syslog hot path (KV, filterlog); the regex catalogue only
// runs for lines nothing cheaper claimed.
package family

import "strings"

// ParseKV parses a `key=value` / `key="quoted value"` stream into a
// lowercased-key map. Moved from internal/logfields (which keeps a thin
// wrapper) and ported originally from the collector's parseKVPairs
// (Firewall-Collector/internal/syslog/fortigate.go) so extraction behaves the
// same in both repos. Runs that are not key=value are skipped, so a syslog
// header re-joined in front of the body is harmless.
func ParseKV(s string) map[string]string {
	out := make(map[string]string, kvSizeHint(s))
	ParseKVInto(s, out)
	return out
}

// ParseKVInto is ParseKV writing into a caller-owned map.
func ParseKVInto(s string, out map[string]string) {
	i, n := 0, len(s)
	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		keyStart := i
		for i < n && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= n || s[i] != '=' {
			continue // not a key=value token
		}
		key := s[keyStart:i]
		i++ // consume '='
		if i >= n {
			out[strings.ToLower(key)] = ""
			break
		}
		var val string
		if s[i] == '"' {
			i++
			valStart := i
			for i < n && s[i] != '"' {
				i++
			}
			val = s[valStart:i]
			if i < n {
				i++ // consume closing quote
			}
		} else {
			valStart := i
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			val = s[valStart:i]
		}
		out[strings.ToLower(key)] = val
	}
}

// kvSizeHint counts '=' so the map is sized once instead of growing through
// several rehashes on a 40-pair FortiOS traffic line.
func kvSizeHint(s string) int {
	n := strings.Count(s, "=")
	if n < 8 {
		return 8
	}
	return n + 1
}

// HasKV is the cheap gate for the KV families: at least one `k=v` token with
// a non-empty key, i.e. an '=' preceded by a non-space byte.
func HasKV(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] == '=' && s[i-1] != ' ' && s[i-1] != '\t' {
			return true
		}
	}
	return false
}
