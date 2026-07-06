package configdiff

import (
	"bytes"
	"regexp"
	"strings"
)

// LineRow is one row of the rendered line diff.
type LineRow struct {
	Op    string `json:"op"`              // "equal" | "delete" | "insert" | "volatile"
	Text  string `json:"text"`            // display text: b-side for equal/volatile/insert, a-side for delete
	A     int    `json:"a"`               // 1-based line number in the "from" config; 0 = absent (insert)
	B     int    `json:"b"`               // 1-based line number in the "to" config; 0 = absent (delete)
	VName string `json:"vname,omitempty"` // volatile pattern name when Op=="volatile"
}

// LineDiff is the aligned line-level diff of two config revisions.
type LineDiff struct {
	Rows      []LineRow `json:"rows"`
	Added     int       `json:"added"`
	Removed   int       `json:"removed"`
	Truncated bool      `json:"truncated"`      // hit the row cap or the D-budget degraded path
	Note      string    `json:"note,omitempty"` // operator-facing banner when degraded/truncated
}

const (
	// maxDiffRows bounds the emitted rows so a pathological input can't produce
	// unbounded JSON. Ample for any real firewall config.
	maxDiffRows = 20000
	// maxEditDistance bounds the Myers search. A capture-mode mismatch
	// (`show` vs `show full-configuration`) makes nearly every line differ, and
	// an unbounded N·D search would burn CPU/memory to render a diff no operator
	// wants line-by-line anyway. Past this we bail to a whole-block replace.
	maxEditDistance = 2000
)

// volatileTokenRe extracts the pattern name from a masked line, e.g.
// `set password ENC <volatile-enc>` → "enc".
var volatileTokenRe = regexp.MustCompile(`<volatile-([a-z0-9-]+)>`)

// DiffLines computes an aligned, volatile-aware line diff between two config
// revisions. Alignment is done with a proper Myers O(ND) diff over volatile-
// masked lines (not a positional line[i] vs line[i] comparison, which drifts the
// moment a line is inserted or removed), while the ORIGINAL text is shown. A line
// whose only difference is volatile (masked-equal, raw-different) is reported as
// Op "volatile" rather than a delete/insert pair.
func DiffLines(vendor string, a, b []byte) LineDiff {
	aRaw, aMask := prepareDiffInput(vendor, a)
	bRaw, bMask := prepareDiffInput(vendor, b)

	var d LineDiff
	emit := func(r LineRow) bool {
		if len(d.Rows) >= maxDiffRows {
			d.Truncated = true
			return false
		}
		switch r.Op {
		case "insert":
			d.Added++
		case "delete":
			d.Removed++
		}
		d.Rows = append(d.Rows, r)
		return true
	}

	// aligned emits an equal-or-volatile row for a 1:1-aligned pair (common
	// prefix/suffix, or a Myers diagonal).
	aligned := func(ai, bi int) bool {
		if aMask[ai] == bMask[bi] && aRaw[ai] != bRaw[bi] {
			return emit(LineRow{Op: "volatile", Text: bRaw[bi], A: ai + 1, B: bi + 1, VName: volatileName(aMask[ai], bMask[bi])})
		}
		return emit(LineRow{Op: "equal", Text: bRaw[bi], A: ai + 1, B: bi + 1})
	}

	// Trim the common prefix and suffix on masked lines — the fast path that
	// keeps the classic "one line inserted near the top" case near-linear and
	// bounds the Myers search to the genuinely-differing middle.
	n, m := len(aMask), len(bMask)
	p := 0
	for p < n && p < m && aMask[p] == bMask[p] {
		p++
	}
	s := 0
	for s < n-p && s < m-p && aMask[n-1-s] == bMask[m-1-s] {
		s++
	}

	for i := 0; i < p; i++ {
		if !aligned(i, i) {
			return finalizeTruncated(d)
		}
	}

	// Middle: a[p : n-s] vs b[p : m-s]. Intern both sides against ONE shared
	// table (collision-free equality) and run Myers on the masked middle.
	ids := map[string]int{}
	xs := internRange(aMask, p, n-s, ids)
	ys := internRange(bMask, p, m-s, ids)
	ops, degraded := myersOps(xs, ys, maxEditDistance)

	ai, bi := p, p
	if degraded {
		// Too many edits (e.g. capture-mode mismatch) — show the middle as a
		// whole-block replace rather than an unreadable interleaving.
		d.Truncated = true
		d.Note = "Configs differ substantially (possible capture-mode mismatch); showing the changed region as a block replace."
		for ; ai < n-s; ai++ {
			if !emit(LineRow{Op: "delete", Text: aRaw[ai], A: ai + 1}) {
				return finalizeTruncated(d)
			}
		}
		for ; bi < m-s; bi++ {
			if !emit(LineRow{Op: "insert", Text: bRaw[bi], B: bi + 1}) {
				return finalizeTruncated(d)
			}
		}
	} else {
		for _, op := range ops {
			var ok bool
			switch op {
			case opEqual:
				ok = aligned(ai, bi)
				ai++
				bi++
			case opDelete:
				ok = emit(LineRow{Op: "delete", Text: aRaw[ai], A: ai + 1})
				ai++
			case opInsert:
				ok = emit(LineRow{Op: "insert", Text: bRaw[bi], B: bi + 1})
				bi++
			}
			if !ok {
				return finalizeTruncated(d)
			}
		}
	}

	// Common suffix (1:1 aligned again). ai/bi now point at n-s / m-s.
	for ; ai < n && bi < m; ai, bi = ai+1, bi+1 {
		if !aligned(ai, bi) {
			return finalizeTruncated(d)
		}
	}
	return d
}

func finalizeTruncated(d LineDiff) LineDiff {
	d.Truncated = true
	if d.Note == "" {
		d.Note = "Diff truncated for size; download both revisions to compare offline."
	}
	return d
}

// volatileName returns the pattern name for a volatile row, or "" if none is
// embedded (e.g. a masked-away console prompt prefix).
func volatileName(maskA, maskB string) string {
	if mm := volatileTokenRe.FindStringSubmatch(maskA); mm != nil {
		return mm[1]
	}
	if mm := volatileTokenRe.FindStringSubmatch(maskB); mm != nil {
		return mm[1]
	}
	return ""
}

// prepareDiffInput returns the display lines and the masked (alignment) lines for
// one config, guaranteed to be the same length. Newlines are normalized (CRLF→LF)
// and a single trailing empty line (from a trailing newline) is dropped.
func prepareDiffInput(vendor string, raw []byte) (rawLines, maskLines []string) {
	clean := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))

	var masked []byte
	if lm, ok := Lookup(vendor).(LineMasker); ok {
		masked = lm.MaskVolatileLines(clean)
	} else {
		masked = clean
	}

	rawLines = splitTrimCR(clean)
	maskLines = splitTrimCR(masked)

	// Invariant: masking must preserve line count. If a masker ever violates it,
	// degrade safely to no masking rather than misalign the whole diff.
	if len(rawLines) != len(maskLines) {
		maskLines = rawLines
	}

	// Drop a single trailing empty element so "config\n" and "config" don't diff
	// as a spurious blank-line insert.
	if k := len(rawLines); k > 0 && rawLines[k-1] == "" {
		rawLines = rawLines[:k-1]
		maskLines = maskLines[:len(maskLines)-1]
	}
	return rawLines, maskLines
}

func splitTrimCR(b []byte) []string {
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// internRange maps the lines in src[lo:hi] to dense ints via the shared ids
// table so equality is a cheap int compare with no hash-collision risk. Both
// sides must be interned against the SAME table for the ints to be comparable.
func internRange(src []string, lo, hi int, ids map[string]int) []int {
	out := make([]int, 0, hi-lo)
	for i := lo; i < hi; i++ {
		id, ok := ids[src[i]]
		if !ok {
			id = len(ids)
			ids[src[i]] = id
		}
		out = append(out, id)
	}
	return out
}

// edit op codes for the Myers script.
const (
	opEqual = iota
	opDelete
	opInsert
)

// myersOps runs the greedy Myers O(ND) diff and returns the edit script in
// forward order. If the shortest edit distance exceeds maxD, it returns
// degraded=true and a nil script (the caller renders a block replace).
func myersOps(xs, ys []int, maxD int) (ops []int, degraded bool) {
	n, mm := len(xs), len(ys)
	if n == 0 && mm == 0 {
		return nil, false
	}
	total := n + mm
	if maxD <= 0 || maxD > total {
		maxD = total
	}
	// The search only ever touches diagonals in [-maxD, maxD], so size the V
	// arrays (and each saved trace copy) by maxD, not total — this bounds memory
	// when the edit distance is capped for a wildly-different pair.
	offset := maxD
	v := make([]int, 2*maxD+1)
	trace := make([][]int, 0, maxD+1)

	reached := -1
	for dd := 0; dd <= maxD; dd++ {
		vc := make([]int, len(v))
		copy(vc, v)
		trace = append(trace, vc)
		for k := -dd; k <= dd; k += 2 {
			var x int
			if k == -dd || (k != dd && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1] // down (insert)
			} else {
				x = v[offset+k-1] + 1 // right (delete)
			}
			y := x - k
			for x < n && y < mm && xs[x] == ys[y] {
				x++
				y++
			}
			v[offset+k] = x
			if x >= n && y >= mm {
				reached = dd
				break
			}
		}
		if reached >= 0 {
			break
		}
	}
	if reached < 0 {
		return nil, true
	}

	// Backtrack through the saved V arrays to reconstruct the script.
	x, y := n, mm
	for dd := reached; dd > 0; dd-- {
		vv := trace[dd]
		k := x - y
		var prevK int
		if k == -dd || (k != dd && vv[offset+k-1] < vv[offset+k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := vv[offset+prevK]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			ops = append(ops, opEqual)
			x--
			y--
		}
		if x == prevX {
			ops = append(ops, opInsert)
		} else {
			ops = append(ops, opDelete)
		}
		x, y = prevX, prevY
	}
	for x > 0 && y > 0 {
		ops = append(ops, opEqual)
		x--
		y--
	}
	// ops were built from the end; reverse to forward order.
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	return ops, false
}
