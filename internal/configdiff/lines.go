package configdiff

import (
	"bufio"
	"io"
)

// maxLineBytes caps the scanner buffer so a pathological single line cannot
// allocate without bound. Config lines are short (the longest realistic case is
// a pre-normalization ENC blob, and those are collapsed before the object
// parser runs); the cap exists only to bound memory, not to reject valid input.
const maxLineBytes = 8 * 1024 * 1024

// forEachLine streams the lines of r via a bufio.Scanner, calling fn for each
// line with the trailing \n (and a preceding \r for CRLF input) stripped. This
// replaces strings.Split(string(b), "\n") in the forward-only scan sites, which
// materialises a []string (one 16-byte header per line) plus a full string(b)
// copy and amplifies a large config's memory footprint. fn returning false
// stops the scan early. A line longer than maxLineBytes ends the scan (and is
// dropped); that is a deliberate memory bound.
func forEachLine(r io.Reader, fn func(line string) bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	for sc.Scan() {
		if !fn(sc.Text()) {
			return
		}
	}
}
