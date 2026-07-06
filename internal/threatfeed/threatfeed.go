// Package threatfeed fetches and parses free, public open-source bad-IP lists
// into threat-intel entries the server loads into its in-memory matcher. It is
// opt-in (THREAT_FEEDS_ENABLED) and runs in the poller under the leader lock.
//
// The parser is deliberately tolerant: each feed is a plain-text list of one
// IP or CIDR per line, often with trailing comments or extra columns. We take
// the first whitespace/semicolon-delimited token per line, skip comments and
// anything that isn't a valid IP/CIDR, and cap the entry count so a malformed
// or hostile feed can't exhaust memory.
package threatfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Feed kinds. IP feeds are plain-text IP/CIDR lists; ASN feeds are ASN-reputation
// lists (currently Spamhaus ASN-DROP JSON) whose indicators are stored as
// "AS<number>" so the matcher can flag flows by autonomous system.
const (
	FeedKindIP  = "ip"
	FeedKindASN = "asn"
)

// Feed is one source list: a name (used as the threat_intel `source`), a URL,
// the category/severity to tag its entries with, and a kind (IP vs ASN).
type Feed struct {
	Name     string
	URL      string
	Category string
	Severity string
	Kind     string // FeedKindIP (default) or FeedKindASN
}

// Entry is one parsed indicator: a CIDR or bare IP plus its feed's metadata.
type Entry struct {
	CIDR     string
	Category string
	Severity string
	Source   string
}

const (
	// maxFeedBytes caps a single feed download (defense against a feed that
	// suddenly balloons). 32 MiB comfortably holds the largest free lists.
	maxFeedBytes = 32 << 20
	// maxEntriesPerFeed caps parsed indicators per feed.
	maxEntriesPerFeed = 500_000
)

// DefaultFeeds is the built-in set of reputable, free, pollable bad-IP lists.
// These are attacker/scanner-focused (so they correlate well with the port-scan
// detector) plus a couple of netblock/compromise lists. Tor exits are info-only
// (presence on Tor is not inherently malicious). All are fetched over HTTPS.
func DefaultFeeds() []Feed {
	return []Feed{
		{Name: "blocklist.de", URL: "https://lists.blocklist.de/lists/all.txt", Category: "attacker", Severity: "warning", Kind: FeedKindIP},
		{Name: "cins-army", URL: "https://cinsscore.com/list/ci-badguys.txt", Category: "attacker", Severity: "warning", Kind: FeedKindIP},
		{Name: "spamhaus-drop", URL: "https://www.spamhaus.org/drop/drop.txt", Category: "hijacked", Severity: "warning", Kind: FeedKindIP},
		{Name: "et-compromised", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", Category: "compromised", Severity: "warning", Kind: FeedKindIP},
		{Name: "tor-exits", URL: "https://check.torproject.org/torbulkexitlist", Category: "tor", Severity: "info", Kind: FeedKindIP},
		// abuse.ch Feodo Tracker — active botnet C2 IPs (Dridex/Emotet/TrickBot/
		// QakBot). CC0, no license friction. Recommended (active-only) list.
		{Name: "feodo-c2", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", Category: "c2", Severity: "critical", Kind: FeedKindIP},
		// Spamhaus ASN-DROP — worst-reputation autonomous systems (JSON). Flags
		// flows whose src/dst ASN is on the list. Do not fetch more than 1×/hr
		// (our default interval is 12h). Attribution: The Spamhaus Project.
		{Name: "spamhaus-asndrop", URL: "https://www.spamhaus.org/drop/asndrop.json", Category: "asn-reputation", Severity: "warning", Kind: FeedKindASN},
	}
}

// ParseExtraFeeds parses a CSV-of-pipe-records spec ("name|url|category|severity,
// name2|url2|...") into Feeds. Whitespace around fields is trimmed; records with
// fewer than 2 fields (name,url) are skipped. category defaults to "custom",
// severity to "warning". Returns nil for an empty spec.
func ParseExtraFeeds(spec string) []Feed {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	var feeds []Feed
	for _, rec := range strings.Split(spec, ",") {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		parts := strings.Split(rec, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		f := Feed{Name: parts[0], URL: parts[1], Category: "custom", Severity: "warning", Kind: FeedKindIP}
		if len(parts) >= 3 && parts[2] != "" {
			f.Category = parts[2]
		}
		if len(parts) >= 4 && parts[3] != "" {
			f.Severity = parts[3]
		}
		// An "asn"/"asn-reputation" category signals an ASN-reputation list.
		if strings.HasPrefix(f.Category, "asn") {
			f.Kind = FeedKindASN
		}
		feeds = append(feeds, f)
	}
	return feeds
}

// Fetch downloads and parses one feed. The body is bounded by maxFeedBytes and
// the request honors the context deadline. A non-2xx status is an error.
// authHeader, when non-empty, is applied as an extra request header formatted
// "Name: value" (e.g. "Authorization: Bearer <token>") so authenticated
// commercial feeds work.
func Fetch(ctx context.Context, client *http.Client, feed Feed, authHeader string) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "firewall-mon-threatfeed/1")
	if authHeader != "" {
		if name, value, ok := strings.Cut(authHeader, ":"); ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("feed %s: HTTP %d", feed.Name, resp.StatusCode)
	}
	body := io.LimitReader(resp.Body, maxFeedBytes)
	if feed.Kind == FeedKindASN {
		entries, err := ParseASN(body, feed)
		if err != nil {
			return nil, fmt.Errorf("feed %s: parse asn: %w", feed.Name, err)
		}
		return entries, nil
	}
	entries, err := Parse(body, feed)
	if err != nil {
		return nil, fmt.Errorf("feed %s: parse: %w", feed.Name, err)
	}
	return entries, nil
}

// ParseASN reads an ASN-reputation feed and returns one Entry per autonomous
// system, with CIDR set to "AS<number>" (the form the matcher's ASN bucket
// expects). It accepts two shapes: Spamhaus ASN-DROP JSON (one JSON object per
// line, e.g. {"asn":64496,...}, with a leading {"type":"metadata"} line) and a
// plain-text list of "AS64496" / "64496" tokens. Comment lines (#, ;) are
// skipped; the result is capped at maxEntriesPerFeed.
func ParseASN(r io.Reader, feed Feed) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := make([]Entry, 0, 1024)
	seen := make(map[uint32]struct{})
	for sc.Scan() && len(out) < maxEntriesPerFeed {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		var asn uint32
		if line[0] == '{' {
			var rec struct {
				ASN  uint32 `json:"asn"`
				Type string `json:"type"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.Type == "metadata" || rec.ASN == 0 {
				continue
			}
			asn = rec.ASN
		} else {
			tok := line
			if i := strings.IndexAny(tok, " \t;,"); i >= 0 {
				tok = tok[:i]
			}
			tok = strings.TrimPrefix(strings.TrimPrefix(tok, "AS"), "as")
			n, err := strconv.ParseUint(tok, 10, 32)
			if err != nil || n == 0 {
				continue
			}
			asn = uint32(n)
		}
		if _, dup := seen[asn]; dup {
			continue
		}
		seen[asn] = struct{}{}
		out = append(out, Entry{CIDR: "AS" + strconv.FormatUint(uint64(asn), 10), Category: feed.Category, Severity: feed.Severity, Source: feed.Name})
	}
	return out, sc.Err()
}

// Parse reads a plain-text feed body and returns the valid IP/CIDR indicators.
// Comment lines (#, ;) and unparseable tokens are skipped; the result is capped
// at maxEntriesPerFeed.
// Parse reads feed entries from r. It returns the scanner error (L3 of the
// 2026-07-01 audit): a line longer than the 1 MiB buffer (bufio.ErrTooLong —
// e.g. an HTML error page served with HTTP 200 as one giant line) or a mid-body
// read error stops the scan silently; without surfacing sc.Err(), the caller
// treats the truncated result as a successful (smaller) sync and the missing
// indicators quietly TTL-expire out of the matcher.
func Parse(r io.Reader, feed Feed) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // allow long lines
	out := make([]Entry, 0, 1024)
	for sc.Scan() && len(out) < maxEntriesPerFeed {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Take the first token (lists often append "; comment" or columns).
		tok := line
		if i := strings.IndexAny(tok, " \t;"); i >= 0 {
			tok = tok[:i]
		}
		cidr, ok := normalize(tok)
		if !ok {
			continue
		}
		out = append(out, Entry{CIDR: cidr, Category: feed.Category, Severity: feed.Severity, Source: feed.Name})
	}
	return out, sc.Err()
}

// normalize validates a token as a CIDR or bare IP and returns the canonical
// string the matcher expects (CIDR kept as-is/masked; bare IP returned as-is).
func normalize(tok string) (string, bool) {
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return a.String(), true
	}
	return "", false
}
