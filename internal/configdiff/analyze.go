package configdiff

import (
	"fmt"
	"strings"
)

// CaptureModeDetector is an optional capability a vendor Normalizer may
// implement to classify how a backup was produced (e.g. FortiOS
// `show full-configuration` vs a plain `show`). Two backups taken in different
// modes can never hash-match even though the device is unchanged, so Analyze
// flags the mismatch loudly rather than reporting a phantom config change.
type CaptureModeDetector interface {
	// CaptureMode returns a short mode label, or "" if undeterminable.
	CaptureMode(raw []byte) string
}

// Report is the result of comparing two firewall configs through the change-
// detection normalizer. It is what the `configcheck` tool prints and what tests
// assert against: it answers "would these two backups raise a config-change
// alert, and if so, exactly which lines survived normalization?"
type Report struct {
	Vendor   string `json:"vendor"`
	HashA    string `json:"hash_a"`
	HashB    string `json:"hash_b"`
	Match    bool   `json:"match"` // normalized hashes equal -> no alert
	QualityA string `json:"quality_a"`
	QualityB string `json:"quality_b"`

	NormLinesA int `json:"norm_lines_a"`
	NormLinesB int `json:"norm_lines_b"`

	// Residual deltas after normalization, compared indentation-insensitively so
	// pure re-indentation (e.g. console capture vs file backup) is ignored. These
	// are the lines a change-detection alert would actually be raised on.
	OnlyInA []string `json:"only_in_a"`
	OnlyInB []string `json:"only_in_b"`

	// CaptureModeMismatch is set when one config is a near-superset of the other
	// (e.g. `show full-configuration` vs a plain `show` backup). The two then can
	// never hash-match no matter how good the normalizer is, because one carries
	// thousands of default lines the other omits. The fix is collector-side
	// (capture consistently), not normalizer-side — so the tool flags it loudly
	// instead of letting it look like a real config change.
	CaptureModeMismatch bool   `json:"capture_mode_mismatch"`
	CaptureModeReason   string `json:"capture_mode_reason,omitempty"`
}

// Analyze normalizes both configs with the vendor normalizer and reports whether
// they would be treated as the same config, plus the residual line-level diff and
// a capture-mode-mismatch verdict.
func Analyze(vendor string, a, b []byte) Report {
	na, qa := Normalize(vendor, a)
	nb, qb := Normalize(vendor, b)

	setA := lineSet(na)
	setB := lineSet(nb)

	rep := Report{
		Vendor:     vendor,
		HashA:      HashNormalized(vendor, a),
		HashB:      HashNormalized(vendor, b),
		QualityA:   qa,
		QualityB:   qb,
		NormLinesA: len(setA),
		NormLinesB: len(setB),
		OnlyInA:    diffKeys(setA, setB),
		OnlyInB:    diffKeys(setB, setA),
	}
	rep.Match = rep.HashA == rep.HashB

	if d, ok := Lookup(vendor).(CaptureModeDetector); ok {
		if ma, mb := d.CaptureMode(a), d.CaptureMode(b); ma != "" && mb != "" && ma != mb {
			rep.CaptureModeMismatch = true
			rep.CaptureModeReason = fmt.Sprintf(
				"A was captured as `%s`, B as `%s`. These can never hash-match — one "+
					"emits device defaults the other omits. Fix the collector to capture "+
					"both backups the same way; this is not a real config change.", ma, mb)
		}
	}
	return rep
}

// lineSet returns the set of non-empty, whitespace-trimmed lines in a normalized
// config. Trimming makes the comparison indentation-insensitive; using a set
// makes it order-insensitive (FortiOS does not guarantee block order across
// capture modes). Counts of duplicate lines are intentionally ignored — config
// semantics are key/value, not positional.
func lineSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, ln := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			out[t] = struct{}{}
		}
	}
	return out
}

// diffKeys returns the keys present in have but not in other, in no particular
// order (callers sort for display).
func diffKeys(have, other map[string]struct{}) []string {
	var out []string
	for k := range have {
		if _, ok := other[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}
