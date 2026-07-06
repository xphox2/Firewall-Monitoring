package configdiff

import (
	"strings"
	"testing"
)

// countOps tallies rows by op for concise assertions.
func countOps(d LineDiff) (equal, del, ins, vol int) {
	for _, r := range d.Rows {
		switch r.Op {
		case "equal":
			equal++
		case "delete":
			del++
		case "insert":
			ins++
		case "volatile":
			vol++
		}
	}
	return
}

// TestDiffLines_InsertInMiddle_NoDrift is the core regression: inserting one line
// must flag ONLY that line; every line below it must stay aligned as "equal".
// The old positional diff flagged the entire remainder as changed.
func TestDiffLines_InsertInMiddle_NoDrift(t *testing.T) {
	a := "line1\nline2\nline3\nline4\nline5"
	b := "line1\nline2\nNEW-LINE\nline3\nline4\nline5"

	d := DiffLines("", []byte(a), []byte(b))
	equal, del, ins, vol := countOps(d)

	if ins != 1 || del != 0 || vol != 0 {
		t.Fatalf("expected exactly 1 insert and 0 delete/volatile, got ins=%d del=%d vol=%d\nrows=%+v", ins, del, vol, d.Rows)
	}
	if equal != 5 {
		t.Fatalf("expected 5 equal lines (all originals preserved), got %d\nrows=%+v", equal, d.Rows)
	}
	if d.Added != 1 || d.Removed != 0 {
		t.Fatalf("expected Added=1 Removed=0, got Added=%d Removed=%d", d.Added, d.Removed)
	}
	// The inserted row must carry the new text and only a B line number.
	for _, r := range d.Rows {
		if r.Op == "insert" {
			if r.Text != "NEW-LINE" || r.A != 0 || r.B != 3 {
				t.Fatalf("insert row wrong: %+v", r)
			}
		}
	}
}

func TestDiffLines_DeleteInMiddle_NoDrift(t *testing.T) {
	a := "a\nb\nc\nd\ne"
	b := "a\nb\nd\ne"

	d := DiffLines("", []byte(a), []byte(b))
	equal, del, ins, vol := countOps(d)
	if del != 1 || ins != 0 || vol != 0 {
		t.Fatalf("expected exactly 1 delete, got del=%d ins=%d vol=%d\nrows=%+v", del, ins, vol, d.Rows)
	}
	if equal != 4 {
		t.Fatalf("expected 4 equal, got %d", equal)
	}
}

func TestDiffLines_Identical(t *testing.T) {
	cfg := "one\ntwo\nthree"
	d := DiffLines("", []byte(cfg), []byte(cfg))
	equal, del, ins, vol := countOps(d)
	if del != 0 || ins != 0 || vol != 0 || equal != 3 {
		t.Fatalf("identical inputs should be all-equal, got equal=%d del=%d ins=%d vol=%d", equal, del, ins, vol)
	}
}

func TestDiffLines_Empty(t *testing.T) {
	d := DiffLines("", []byte(""), []byte(""))
	if len(d.Rows) != 0 {
		t.Fatalf("empty inputs should yield no rows, got %+v", d.Rows)
	}
}

// TestDiffLines_CRLF ensures a CRLF-vs-LF capture difference does not turn the
// whole diff red/green — the drift bug in a new costume.
func TestDiffLines_CRLF(t *testing.T) {
	a := "alpha\r\nbravo\r\ncharlie\r\n"
	b := "alpha\nbravo\ncharlie\n"

	d := DiffLines("", []byte(a), []byte(b))
	equal, del, ins, vol := countOps(d)
	if del != 0 || ins != 0 || vol != 0 {
		t.Fatalf("CRLF vs LF should be all-equal, got equal=%d del=%d ins=%d vol=%d\nrows=%+v", equal, del, ins, vol, d.Rows)
	}
	if equal != 3 {
		t.Fatalf("expected 3 equal, got %d", equal)
	}
}

// TestDiffLines_TrailingNewline ensures a trailing newline on one side only does
// not create a spurious blank-line insert.
func TestDiffLines_TrailingNewline(t *testing.T) {
	d := DiffLines("", []byte("x\ny\n"), []byte("x\ny"))
	_, del, ins, vol := countOps(d)
	if del != 0 || ins != 0 || vol != 0 {
		t.Fatalf("trailing-newline-only difference should not diff, got del=%d ins=%d vol=%d\nrows=%+v", del, ins, vol, d.Rows)
	}
}

// TestDiffLines_VolatileENC verifies that IV churn on ENC lines is reported as
// volatile (aligned), not as delete/insert, when the FortiGate masker is active.
func TestDiffLines_VolatileENC(t *testing.T) {
	a := "config system admin\n    edit \"admin\"\n        set password ENC AAAA1111iv==\n    next\nend"
	b := "config system admin\n    edit \"admin\"\n        set password ENC BBBB2222iv==\n    next\nend"

	d := DiffLines("fortigate", []byte(a), []byte(b))
	_, del, ins, vol := countOps(d)
	if del != 0 || ins != 0 {
		t.Fatalf("ENC IV churn must not produce delete/insert, got del=%d ins=%d\nrows=%+v", del, ins, d.Rows)
	}
	if vol != 1 {
		t.Fatalf("expected exactly 1 volatile row, got %d\nrows=%+v", vol, d.Rows)
	}
	for _, r := range d.Rows {
		if r.Op == "volatile" && r.VName != "enc" {
			t.Fatalf("volatile row should be named 'enc', got %q", r.VName)
		}
	}
}

// TestDiffLines_RealFieldChangeUnderVolatile ensures a real field change on a
// volatile line is NOT swallowed as volatile (the ${1} capture-group templates
// keep the field name distinct).
func TestDiffLines_RealFieldChangeUnderVolatile(t *testing.T) {
	a := "config x\n    edit 1\n        set adminpass ENC AAAA1111==\n    next\nend"
	b := "config x\n    edit 1\n        set wifipass ENC BBBB2222==\n    next\nend"

	d := DiffLines("fortigate", []byte(a), []byte(b))
	_, del, ins, vol := countOps(d)
	if vol != 0 {
		t.Fatalf("a real field-name change must not be treated as volatile, got vol=%d\nrows=%+v", vol, d.Rows)
	}
	if del != 1 || ins != 1 {
		t.Fatalf("expected the changed line as delete+insert, got del=%d ins=%d\nrows=%+v", del, ins, d.Rows)
	}
}

// TestDiffLines_VolatileInCommonPrefix ensures a volatile line inside the trimmed
// common prefix is still classified volatile, not equal.
func TestDiffLines_VolatileInCommonPrefix(t *testing.T) {
	// The ENC line is the very first line so it lands in the common prefix.
	a := "        set password ENC AAAA1111==\ncommon2\ncommon3"
	b := "        set password ENC BBBB2222==\ncommon2\ncommon3"

	d := DiffLines("fortigate", []byte(a), []byte(b))
	equal, del, ins, vol := countOps(d)
	if del != 0 || ins != 0 {
		t.Fatalf("no delete/insert expected, got del=%d ins=%d", del, ins)
	}
	if vol != 1 || equal != 2 {
		t.Fatalf("expected 1 volatile + 2 equal, got vol=%d equal=%d\nrows=%+v", vol, equal, d.Rows)
	}
}

// TestMaskVolatileLines_PreservesLineCount asserts the load-bearing invariant for
// the multi-line PEM and gui-dashboard patterns: masking must never change the
// number of lines, or every line below the block would misalign.
func TestMaskVolatileLines_PreservesLineCount(t *testing.T) {
	pem := "config vpn certificate local\n" +
		"    edit \"cert\"\n" +
		"        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
		"body-line-1\n" +
		"body-line-2\n" +
		"-----END ENCRYPTED PRIVATE KEY-----\"\n" +
		"    next\n" +
		"end\n" +
		"config gui-dashboard\n" +
		"    edit 1\n" +
		"        set widget foo\n" +
		"        set last-updated 1700000000\n" +
		"    next\n" +
		"end\n"

	lm, ok := Lookup("fortigate").(LineMasker)
	if !ok {
		t.Fatal("fortigate normalizer should implement LineMasker")
	}
	masked := lm.MaskVolatileLines([]byte(pem))
	rawN := strings.Count(pem, "\n")
	maskN := strings.Count(string(masked), "\n")
	if rawN != maskN {
		t.Fatalf("masking changed line count: raw newlines=%d masked=%d\nmasked:\n%s", rawN, maskN, masked)
	}
}

// TestDiffLines_VolatilePEMReencrypt verifies a re-encrypted PEM body (same line
// count) shows as volatile, not a wall of red/green.
func TestDiffLines_VolatilePEMReencrypt(t *testing.T) {
	mk := func(body string) string {
		return "        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
			body + "\n" +
			"-----END ENCRYPTED PRIVATE KEY-----\"\ntrailing-common"
	}
	a := mk("AAAAAAAAAAAAAAAA")
	b := mk("BBBBBBBBBBBBBBBB")

	d := DiffLines("fortigate", []byte(a), []byte(b))
	_, del, ins, _ := countOps(d)
	if del != 0 || ins != 0 {
		t.Fatalf("re-encrypted PEM with same line count should not delete/insert, got del=%d ins=%d\nrows=%+v", del, ins, d.Rows)
	}
}

// TestDiffLines_DCapDegraded verifies that a wildly different pair (simulating a
// capture-mode mismatch) degrades to a block replace with a Note instead of
// hanging on an O(N*D) search.
func TestDiffLines_DCapDegraded(t *testing.T) {
	var aLines, bLines []string
	for i := 0; i < maxEditDistance+500; i++ {
		aLines = append(aLines, "a-unique-line-"+itoa(i))
		bLines = append(bLines, "b-unique-line-"+itoa(i))
	}
	d := DiffLines("", []byte(strings.Join(aLines, "\n")), []byte(strings.Join(bLines, "\n")))
	if !d.Truncated || d.Note == "" {
		t.Fatalf("expected degraded (Truncated + Note), got Truncated=%v Note=%q", d.Truncated, d.Note)
	}
	_, del, ins, _ := countOps(d)
	if del == 0 || ins == 0 {
		t.Fatalf("degraded mode should render deletes and inserts, got del=%d ins=%d", del, ins)
	}
}

// itoa avoids importing strconv just for the loop above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
