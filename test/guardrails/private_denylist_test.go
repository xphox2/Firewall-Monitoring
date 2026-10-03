package guardrails

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPrivateDenylist checks tracked files against a denylist of sensitive
// tokens (host names, domains, serials, addresses) that is kept OUTSIDE this
// repository — publishing the list, or even hashes of short tokens, would leak
// what it protects. The test runs only when FWMON_DENYLIST points at the list
// (one token per line, # comments allowed); it skips otherwise, so it never runs
// in CI. An optional FWMON_DENYLIST_KEEP file lists allowed substrings (for
// example a public contact address that contains a denylisted word).
//
// Matching is case-insensitive over the raw text. Tokens that contain letters
// are also matched with '-', '_' and '.' removed from both sides, so a compound
// token is caught whichever separator it is written with. A short all-letter
// token (3-5 letters, typically a site or owner name) is also caught when it
// is glued to other letters or digits in that separator-stripped form, such
// as "<name>fw", "fw<name>" or "<name>01".
func TestPrivateDenylist(t *testing.T) {
	listPath := os.Getenv("FWMON_DENYLIST")
	if listPath == "" {
		t.Skip("FWMON_DENYLIST not set (local-only check)")
	}
	tokens := readTokenFile(t, listPath)
	if len(tokens) == 0 {
		t.Fatalf("%s holds no tokens", listPath)
	}
	var keep []string
	if kp := os.Getenv("FWMON_DENYLIST_KEEP"); kp != "" {
		keep = readTokenFile(t, kp)
	}
	root, files := hygieneRepoFiles(t)
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil || bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		for _, hit := range denylistHits(strings.ToLower(string(data)), tokens, keep) {
			// Report the line number only, never the token itself.
			t.Errorf("%s:%d: contains a denylisted token (see the private list)", f, hit)
		}
	}
}

var denySeparators = regexp.MustCompile(`[-_.]`)

// denylistHits returns 1-based line numbers of denylisted tokens in lowered
// text, ignoring occurrences inside a keep-list substring.
func denylistHits(text string, tokens, keep []string) []int {
	var lines []int
	kept := keptSpans(text, keep)
	for _, tok := range tokens {
		rawLines := map[int]bool{}
		for from := 0; ; {
			i := strings.Index(text[from:], tok)
			if i < 0 {
				break
			}
			at := from + i
			if onBoundary(text, tok, at) && !insideSpan(kept, at, at+len(tok)) {
				n := strings.Count(text[:at], "\n") + 1
				lines = append(lines, n)
				rawLines[n] = true
			}
			from = at + 1
		}
		if shortAlphaToken(tok) {
			// Glued compound pass, per separator-stripped line.
			for n, line := range strings.Split(text, "\n") {
				if rawLines[n+1] || !strings.Contains(denySeparators.ReplaceAllString(line, ""), tok) {
					continue
				}
				if gluedMatch(denySeparators.ReplaceAllString(line, ""), tok) && !lineFullyKept(line, keep) {
					lines = append(lines, n+1)
				}
			}
			continue
		}
		if !strings.ContainsAny(tok, "abcdefghijklmnopqrstuvwxyz") || len(tok) < 6 {
			continue
		}
		// Separator-insensitive pass, per line so the line number survives.
		norm := denySeparators.ReplaceAllString(tok, "")
		for n, line := range strings.Split(text, "\n") {
			if strings.Contains(line, tok) {
				continue // already reported by the raw pass
			}
			if strings.Contains(denySeparators.ReplaceAllString(line, ""), norm) && !lineFullyKept(line, keep) {
				lines = append(lines, n+1)
			}
		}
	}
	return lines
}

// shortAlphaToken reports whether tok is 3-5 letters and nothing else.
func shortAlphaToken(tok string) bool {
	if len(tok) < 3 || len(tok) > 5 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < 'a' || tok[i] > 'z' {
			return false
		}
	}
	return true
}

// gluedMatch reports whether tok occurs in s touching a letter or digit on
// at least one side.
func gluedMatch(s, tok string) bool {
	alnum := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
	for from := 0; ; {
		i := strings.Index(s[from:], tok)
		if i < 0 {
			return false
		}
		at, end := from+i, from+i+len(tok)
		if at > 0 && alnum(s[at-1]) || end < len(s) && alnum(s[end]) {
			return true
		}
		from = at + 1
	}
}

// onBoundary reports whether the token at text[at:] stands on its own: an
// alphanumeric token edge must not touch another alphanumeric character, so
// the prefix "10.0.1." does not match inside a longer first octet and a
// long name does not match inside a longer word. (Short all-letter names get
// the extra glued pass in denylistHits.)
func onBoundary(text, tok string, at int) bool {
	alnum := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
	if at > 0 && alnum(tok[0]) && alnum(text[at-1]) {
		return false
	}
	end := at + len(tok)
	if end < len(text) && alnum(tok[len(tok)-1]) && alnum(text[end]) {
		return false
	}
	return true
}

type span struct{ start, end int }

func keptSpans(text string, keep []string) []span {
	var out []span
	for _, k := range keep {
		for from := 0; ; {
			i := strings.Index(text[from:], k)
			if i < 0 {
				break
			}
			out = append(out, span{from + i, from + i + len(k)})
			from += i + 1
		}
	}
	return out
}

func insideSpan(spans []span, start, end int) bool {
	for _, s := range spans {
		if start >= s.start && end <= s.end {
			return true
		}
	}
	return false
}

func lineFullyKept(line string, keep []string) bool {
	for _, k := range keep {
		if strings.Contains(line, k) {
			return true
		}
	}
	return false
}

func readTokenFile(t *testing.T, path string) []string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func TestPrivateDenylist_Matching(t *testing.T) {
	tokens := []string{"examplecorp-fw-01", "secret.example", "203.0.113.77", "10.0.1.", "kiwi"}
	keep := []string{"security@secret.example"}
	for _, tc := range []struct {
		text string
		want int
	}{
		{"device examplecorp-fw-01 online", 1},
		{"device EXAMPLECORP_FW_01 online", 1},
		{"device examplecorpfw01 online", 1},
		{"mail security@secret.example please", 0},
		{"host api.secret.example", 1},
		{"peer 203.0.113.77", 1},
		{"peer 203.0.113.7", 0},
		{"peer 203.0.113.771", 0},
		{"lan 10.0.1.5", 1},
		{"lan " + sampleIP(110, 0, 1, 5) + " and 10.0.15.1", 0},
		// A short name, alone, with separators, or glued to letters/digits.
		{"site kiwi", 1},
		{"device KIWI-FW and FW_KIWI", 2},
		{"device kiwifw online", 1},
		{"device fwkiwi online", 1},
		{"device kiwi01 online", 1},
		{"device fw-kiwi-lan online", 1},
		{"device fw.kiwi.example and kiwilan", 1},
		{"a kiw i split", 0},
		{"nothing here", 0},
	} {
		if got := len(denylistHits(strings.ToLower(tc.text), tokens, keep)); got != tc.want {
			t.Errorf("denylistHits(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}
