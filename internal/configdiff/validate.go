package configdiff

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// FortiOSMinBackupSize is the smallest plausible real FortiGate backup. Real
// configs run 50 KB → 500 KB+; anything well under 1 KB is almost certainly
// truncation, not a tiny-but-valid config.
const FortiOSMinBackupSize = 1024

// FortiOSMinConfigBlocks is the minimum number of `config X` blocks expected
// in a real FortiOS backup. Even a stripped-down baseline config has dozens
// of sections (system global / interface / admin / dns / firewall policy /
// vpn ipsec / etc.). Used as a truncation tripwire.
const FortiOSMinConfigBlocks = 5

// FortiOSMaxNonPrintableRatio is the largest fraction of non-printable bytes
// (excluding tab/newline/CR) we'll tolerate before treating the payload as
// corrupt. Real configs are nearly all printable text.
const FortiOSMaxNonPrintableRatio = 0.01

// Errors are exported so callers (tests, handlers, audit log) can match on
// them rather than parsing message strings.
var (
	ErrEmptyBackup            = errors.New("backup is empty")
	ErrBackupTooSmall         = errors.New("backup smaller than minimum plausible size")
	ErrMissingVersionHeader   = errors.New("backup missing #config-version= header")
	ErrMissingSystemGlobal    = errors.New("backup missing config system global section")
	ErrTooFewConfigBlocks     = errors.New("backup has too few config blocks (likely truncated)")
	ErrUnbalancedConfigBlocks = errors.New("backup has unbalanced config/end blocks (likely truncated)")
	ErrBinaryCorruption       = errors.New("backup contains an unexpected fraction of non-printable bytes")
)

// ValidateFortiGateBackup performs a cheap structural sanity check on bytes
// that claim to be a `execute backup config tftp` upload from a FortiGate.
// Returns nil if the bytes look plausibly real; an error otherwise.
//
// The check is intentionally conservative — it is consulted by
// ReceiveConfigRevision before *overwriting* a previously-good revision in
// place. A false positive (good bytes rejected) means the row is preserved
// and the new bytes are stored as a separate "suspect" revision; a false
// negative (corrupt bytes accepted) means we lose the prior good copy.
// Bias toward false positives.
func ValidateFortiGateBackup(b []byte) error {
	if len(b) == 0 {
		return ErrEmptyBackup
	}
	if len(b) < FortiOSMinBackupSize {
		return fmt.Errorf("%w: got %d bytes, want >= %d", ErrBackupTooSmall, len(b), FortiOSMinBackupSize)
	}

	// Byte-level corruption check first — if these bytes aren't even
	// printable text, structural checks below would all be unreliable.
	nonPrintable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			continue // printable ASCII
		}
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		// Allow UTF-8 high bytes — admins occasionally drop UTF-8 into
		// descriptions / comments.
		if c >= 0x80 {
			continue
		}
		nonPrintable++
	}
	if float64(nonPrintable)/float64(len(b)) > FortiOSMaxNonPrintableRatio {
		return fmt.Errorf("%w: %d non-printable bytes in %d total (%.2f%%)",
			ErrBinaryCorruption, nonPrintable, len(b),
			100*float64(nonPrintable)/float64(len(b)))
	}
	if !utf8.Valid(b) {
		return fmt.Errorf("%w: invalid UTF-8 sequence", ErrBinaryCorruption)
	}

	s := string(b)

	if !strings.Contains(s, "#config-version=") {
		return ErrMissingVersionHeader
	}
	if !strings.Contains(s, "config system global") {
		return ErrMissingSystemGlobal
	}

	// Count `config X` and `end` lines using a line scan. We only count lines
	// that START with the keyword (after optional indentation) so embedded
	// keywords inside string values don't get counted.
	configCount, endCount := 0, 0
	for _, line := range strings.Split(s, "\n") {
		trim := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trim, "config ") {
			configCount++
		} else if trim == "end" {
			endCount++
		}
	}
	if configCount < FortiOSMinConfigBlocks {
		return fmt.Errorf("%w: %d config blocks (want >= %d)", ErrTooFewConfigBlocks, configCount, FortiOSMinConfigBlocks)
	}
	// Allow some tolerance — `config` blocks can nest, and trailing `end`s
	// occasionally drift due to FortiOS formatting quirks. A 50% mismatch is a
	// clear corruption indicator though.
	if endCount*2 < configCount {
		return fmt.Errorf("%w: %d config / %d end", ErrUnbalancedConfigBlocks, configCount, endCount)
	}

	return nil
}
