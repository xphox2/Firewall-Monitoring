package logfields

import "strings"

// parseKV parses a FortiGate-style `key=value` / `key="quoted value"` stream
// into a lowercased-key map. Ported from the collector's parseKVPairs
// (Firewall-Collector/internal/syslog/fortigate.go) to keep extraction behavior
// identical across the two repos (a cross-repo consistency point — see
// project memory on cross-repo duplication). Non key=value runs are skipped.
func parseKV(s string) map[string]string {
	out := map[string]string{}
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
	return out
}
