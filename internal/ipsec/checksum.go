package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ChecksumSteps returns a stable SHA-256 over an Artifact's apply steps. The
// collector recomputes this over the steps it receives and refuses to apply if
// it differs from Artifact.Checksum — so the bytes the operator previewed are
// provably the bytes that run. The PSK IS included (it's part of what applies),
// which is exactly why the checksum is computed over the real steps, not the
// redacted preview.
//
// The hash covers exactly Kind/CLI/Method/Path/Body. Description AND CaptureAs
// are deliberately EXCLUDED — CaptureAs is a collector-side capture hint, and
// for UUID-chained vendors the collector substitutes device UUIDs into <uuid:NAME>
// slots in Path/Body AFTER this verify passes, so the checksum pins the operator-
// approved placeholder template while opaque device IDs fill the documented slots.
// (Adding CaptureAs must not change the formula string, so existing hashes are
// stable — a parity test pins this.)
func ChecksumSteps(steps []ApplyStep) string {
	h := sha256.New()
	for _, s := range steps {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x1e", s.Kind, s.CLI, s.Method, s.Path, s.Body)
	}
	return hex.EncodeToString(h.Sum(nil))
}
