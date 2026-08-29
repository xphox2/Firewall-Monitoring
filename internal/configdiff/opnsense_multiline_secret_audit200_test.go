package configdiff

import (
	"strings"
	"testing"
)

// AUDIT-200: OPNsense secret digesting used to drop the newlines inside a
// multi-line secret body ([^<] matches \n in RE2), which broke
// prepareDiffInput's masked-vs-raw line-count invariant — and the invariant
// failure then silently discarded the WHOLE revision's masking, rendering every
// PSK/hash/private key verbatim in the line diff. These tests pin both halves
// of the fix: newline-preserving per-line digest tokens, and the fail-closed
// path for any future invariant violation.

const opnMultilineSecretA = `<opnsense>
  <system>
    <hostname>fw-edge</hostname>
  </system>
  <cert>
    <prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Fo
a2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFZoMDNqCkFCQ0RFRkdI
LS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ==</prv>
  </cert>
  <interfaces>
    <wan><if>igb0</if></wan>
  </interfaces>
</opnsense>
`

// Same config with one unrelated real change, so the diff has genuine work to
// do around the (stable) secret.
var opnMultilineSecretB = strings.Replace(opnMultilineSecretA, "igb0", "igb1", 1)

// TestOPNsenseMultilineSecretMaskPreservesLineCount: the digest of a secret
// body spanning newlines must keep masked line i aligned with raw line i, and
// EVERY consumed line must carry the secret token prefix so lineHasSecret
// display-masks each of them (bare re-appended newlines would leave lines 2..n
// tokenless and still leaking).
func TestOPNsenseMultilineSecretMaskPreservesLineCount(t *testing.T) {
	t.Parallel()
	n := opnsenseNormalizer{vendor: "opnsense"}
	masked := string(n.MaskVolatileLines([]byte(opnMultilineSecretA)))

	if got, want := strings.Count(masked, "\n"), strings.Count(opnMultilineSecretA, "\n"); got != want {
		t.Fatalf("mask changed line count: %d != %d", got, want)
	}

	rawLines := strings.Split(opnMultilineSecretA, "\n")
	maskLines := strings.Split(masked, "\n")
	secretLines := 0
	inSecret := false
	for i, rl := range rawLines {
		if strings.Contains(rl, "<prv>") {
			inSecret = true
		}
		if inSecret {
			secretLines++
			if !strings.Contains(maskLines[i], opnSecretTokenPrefix) {
				t.Errorf("masked line %d of the multi-line secret lacks the %q token: %q (raw %q)",
					i+1, opnSecretTokenPrefix, maskLines[i], rl)
			}
		}
		if strings.Contains(rl, "</prv>") {
			inSecret = false
		}
	}
	if secretLines != 3 {
		t.Fatalf("fixture drift: expected the <prv> body to span 3 lines, got %d", secretLines)
	}
}

// TestDiffLinesOPNsenseMultilineSecretNeverRendered: end-to-end through
// DiffLines — the raw secret text must appear on NO row (before the fix, the
// count mismatch disabled masking and every stable secret rendered verbatim on
// its `equal` rows), and every row covering the secret's lines must show the
// digest token instead.
func TestDiffLinesOPNsenseMultilineSecretNeverRendered(t *testing.T) {
	t.Parallel()
	d := DiffLines("opnsense", []byte(opnMultilineSecretA), []byte(opnMultilineSecretB))

	if d.Rows == nil {
		t.Fatalf("diff withheld (Note=%q) — masking should hold the invariant for a multi-line secret", d.Note)
	}
	secretFragments := []string{
		"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t",
		"a2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFZoMDNqCkFCQ0RFRkdI",
		"LS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ==",
	}
	tokenRows := 0
	for _, r := range d.Rows {
		for _, frag := range secretFragments {
			if strings.Contains(r.Text, frag) {
				t.Errorf("diff row %+v renders raw secret text", r)
			}
		}
		if strings.Contains(r.Text, opnSecretTokenPrefix) {
			tokenRows++
		}
	}
	if tokenRows < 3 {
		t.Errorf("secret token rows = %d, want >= 3 (one per line of the multi-line secret)", tokenRows)
	}
	// The unrelated real change must still diff normally.
	if d.Added != 1 || d.Removed != 1 {
		t.Errorf("added/removed = %d/%d, want 1/1 for the igb0→igb1 change", d.Added, d.Removed)
	}
}

// brokenLineMasker violates the LineMasker line-count contract on purpose, to
// pin the fail-closed path: DiffLines must withhold the raw diff (Rows nil,
// Note set) rather than fall back to rendering unmasked lines.
type brokenLineMasker struct{}

func (brokenLineMasker) Vendor() string                        { return "test-broken-masker-audit200" }
func (brokenLineMasker) Normalize(raw []byte) ([]byte, string) { return raw, QualityUnknown }
func (brokenLineMasker) VolatilePatterns() []VolatilePattern   { return nil }
func (brokenLineMasker) MaskVolatileLines(raw []byte) []byte {
	// Drop everything after the first line — a gross line-count violation.
	if i := strings.IndexByte(string(raw), '\n'); i >= 0 {
		return raw[:i]
	}
	return raw
}

// Registered from init, not the test body: the registry map is read
// concurrently by t.Parallel tests via Lookup, so a mid-test Register would be
// a data race under -race.
func init() { Register(brokenLineMasker{}) }

func TestDiffLinesFailsClosedOnMaskCountViolation(t *testing.T) {
	t.Parallel()
	a := []byte("line one\nline two\nline three\n")
	b := []byte("line one\nline TWO\nline three\n")

	d := DiffLines("test-broken-masker-audit200", a, b)
	if d.Rows != nil {
		t.Fatalf("Rows = %d rows, want nil — a mask-count violation must withhold the raw diff (fail closed)", len(d.Rows))
	}
	if !d.Truncated {
		t.Errorf("Truncated = false, want true (renderRawDiff keys the note banner off it — its rows-empty handling is pinned by internal/shell's rawdiff_withheld_note_audit200_test.go)")
	}
	if !strings.Contains(d.Note, "withheld") {
		t.Errorf("Note = %q, want the operator-facing withheld-diff explanation", d.Note)
	}
}
