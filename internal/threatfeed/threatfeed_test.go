package threatfeed

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	feed := Feed{Name: "test", Category: "attacker", Severity: "warning"}
	body := strings.Join([]string{
		"# a comment line",
		"; another comment",
		"",
		"203.0.113.9",                 // bare IP
		"198.51.100.0/24 ; SBL123",    // CIDR + trailing comment (Spamhaus style)
		"192.0.2.5\t# inline tab",     // IP + tab + comment
		"2001:db8::/32",               // IPv6 CIDR
		"not-an-ip",                   // skipped
		"10.0.0.0/8 extra columns ok", // CIDR + extra columns
	}, "\n")

	got, err := Parse(strings.NewReader(body), feed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"203.0.113.9", "198.51.100.0/24", "192.0.2.5", "2001:db8::/32", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("parsed %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].CIDR != w {
			t.Errorf("entry[%d].CIDR = %q, want %q", i, got[i].CIDR, w)
		}
		if got[i].Category != "attacker" || got[i].Severity != "warning" || got[i].Source != "test" {
			t.Errorf("entry[%d] metadata = %+v, want attacker/warning/test", i, got[i])
		}
	}
}

func TestParseExtraFeeds(t *testing.T) {
	feeds := ParseExtraFeeds(" my-list|https://example.com/bad.txt|malware|critical , minimal|https://e.com/m.txt , |skip-no-name , skip-no-url| ")
	if len(feeds) != 2 {
		t.Fatalf("got %d feeds, want 2: %+v", len(feeds), feeds)
	}
	if feeds[0] != (Feed{Name: "my-list", URL: "https://example.com/bad.txt", Category: "malware", Severity: "critical", Kind: FeedKindIP}) {
		t.Errorf("feed[0] = %+v", feeds[0])
	}
	// Minimal record defaults category=custom, severity=warning, kind=ip.
	if feeds[1] != (Feed{Name: "minimal", URL: "https://e.com/m.txt", Category: "custom", Severity: "warning", Kind: FeedKindIP}) {
		t.Errorf("feed[1] = %+v", feeds[1])
	}
	if ParseExtraFeeds("") != nil {
		t.Error("empty spec should return nil")
	}
}

func TestParseExtraFeedsASNKind(t *testing.T) {
	feeds := ParseExtraFeeds("mybad|https://x/asn.json|asn|warning")
	if len(feeds) != 1 || feeds[0].Kind != FeedKindASN {
		t.Fatalf("asn-category feed should be Kind=asn: %+v", feeds)
	}
}

func TestParseASN(t *testing.T) {
	feed := Feed{Name: "asndrop", Category: "asn-reputation", Severity: "warning", Kind: FeedKindASN}
	body := strings.Join([]string{
		`{"type":"metadata","timestamp":"2026-01-01"}`,
		`{"asn":64496,"rir":"ripencc","cc":"US"}`,
		`{"asn":64497,"domain":"bad.example"}`,
		`{"asn":64496,"note":"dup ignored"}`,
		`# comment`,
		`AS64498`,
		`64499`,
		`not-an-asn`,
	}, "\n")
	got, err := ParseASN(strings.NewReader(body), feed)
	if err != nil {
		t.Fatalf("ParseASN: %v", err)
	}
	want := []string{"AS64496", "AS64497", "AS64498", "AS64499"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].CIDR != w {
			t.Errorf("entry[%d].CIDR = %q, want %q", i, got[i].CIDR, w)
		}
		if got[i].Category != "asn-reputation" || got[i].Source != "asndrop" {
			t.Errorf("entry[%d] metadata = %+v", i, got[i])
		}
	}
}

func TestDefaultFeedsAreHTTPS(t *testing.T) {
	feeds := DefaultFeeds()
	if len(feeds) == 0 {
		t.Fatal("no default feeds")
	}
	for _, f := range feeds {
		if !strings.HasPrefix(f.URL, "https://") {
			t.Errorf("feed %s URL not HTTPS: %s", f.Name, f.URL)
		}
		if f.Name == "" || f.Category == "" || f.Severity == "" {
			t.Errorf("feed %+v missing metadata", f)
		}
	}
}
