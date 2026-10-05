package family

import "strings"

// Netfilter is one Linux kernel LOG-target line as UniFi gateways (and any
// iptables host) write it:
//
//	[WAN_LOCAL-D-2000] DESCR="Drop All Other Traffic" IN=eth4 OUT= MAC=... SRC=203.0.113.9 DST=198.51.100.1 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=TCP SPT=51514 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
//
// The prefix grammar is `[<ruleset>-<verdict>-<index>]` where the ruleset is
// the legacy chain (WAN_IN, LAN_LOCAL …) or a zone-pair name (Network 9.0+),
// the verdict letter is A (accept), D (drop), R (reject) or RET (return) and
// the index is the rule number (2147483647 for the chain's default rule).
// Everything after the prefix is `KEY=VALUE` with uppercase keys, lowercased
// in Fields by the shared KV walker; bare flags (DF, SYN, ACK) are skipped by
// it. Built from the vendor docs and community samples; untested on real
// hardware.
type Netfilter struct {
	Ruleset string
	Verdict string // A | D | R | RET
	Index   string // decimal rule index, "" when the prefix had none
	Fields  map[string]string
}

// HasNetfilter is the cheap gate: a `[…-X-n]` prefix followed by the IN= /
// SRC= keys somewhere after it.
func HasNetfilter(s string) bool {
	open, _, _ := netfilterPrefix(s)
	return open >= 0 && (strings.Contains(s, " IN=") || strings.Contains(s, " SRC="))
}

// netfilterPrefix locates `[ruleset-verdict-index]` and returns the index of
// '[' (or -1), the prefix body and the end offset just past ']'.
func netfilterPrefix(s string) (int, string, int) {
	lim := len(s)
	if lim > 200 {
		lim = 200
	}
	open := strings.IndexByte(s[:lim], '[')
	for open >= 0 {
		close := strings.IndexByte(s[open:], ']')
		if close < 0 {
			return -1, "", 0
		}
		body := s[open+1 : open+close]
		if looksLikeNetfilterPrefix(body) {
			return open, body, open + close + 1
		}
		next := strings.IndexByte(s[open+1:lim], '[')
		if next < 0 {
			return -1, "", 0
		}
		open = open + 1 + next
	}
	return -1, "", 0
}

// looksLikeNetfilterPrefix accepts `NAME-A-123`, `NAME-D-2147483647`,
// `ZONE_PAIR-RET-5` and `NAME-D` (no index): the last dash-separated token
// is digits (or absent) and the one before is a verdict letter.
func looksLikeNetfilterPrefix(body string) bool {
	_, verdict, _, ok := splitNetfilterPrefix(body)
	return ok && verdict != ""
}

func splitNetfilterPrefix(body string) (ruleset, verdict, index string, ok bool) {
	if body == "" || strings.ContainsAny(body, " =") {
		return "", "", "", false
	}
	parts := strings.Split(body, "-")
	if len(parts) < 2 {
		return "", "", "", false
	}
	last := parts[len(parts)-1]
	if isDigits(last) {
		index = last
		parts = parts[:len(parts)-1]
		if len(parts) < 2 {
			return "", "", "", false
		}
	}
	switch parts[len(parts)-1] {
	case "A", "D", "R", "RET":
		verdict = parts[len(parts)-1]
	default:
		return "", "", "", false
	}
	ruleset = strings.Join(parts[:len(parts)-1], "-")
	return ruleset, verdict, index, ruleset != ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ParseNetfilter tokenizes a netfilter LOG line. ok=false when the prefix is
// absent.
func ParseNetfilter(s string) (Netfilter, bool) {
	open, body, end := netfilterPrefix(s)
	if open < 0 {
		return Netfilter{}, false
	}
	ruleset, verdict, index, _ := splitNetfilterPrefix(body)
	nf := Netfilter{Ruleset: ruleset, Verdict: verdict, Index: index}
	nf.Fields = ParseKV(s[end:])
	return nf, true
}
