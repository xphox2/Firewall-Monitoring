// Package configdiff normalizes vendor-specific firewall config text so that
// hashes used for change detection are stable across re-emissions of the same
// logical config — even when the device wraps secrets in random-IV ciphertext
// that drifts on every backup.
//
// Each vendor has its own Normalizer. Devices with an unknown or empty vendor
// fall back to the identity normalizer (raw == normalized), preserving today's
// behavior for any vendor we haven't audited.
package configdiff

import (
	// MD5 here is a NON-CRYPTOGRAPHIC content fingerprint for config-change
	// detection, not a security primitive. It is never used for authentication,
	// integrity, or signatures. Kept as MD5 (not SHA-256) deliberately: the
	// stored NormalizedChecksum is compared against the prior revision's, so
	// changing the algorithm would flag every device's config as "changed" once
	// on upgrade (a false CONFIG_CHANGE alert per device).
	"crypto/md5" // (gosec G501 excluded in CI: non-crypto fingerprint, see note above)
	"encoding/hex"
	"strings"
)

// BackupQuality classifies how much of the original config the backup
// actually carries. The change-detection hash is meaningful for any quality;
// the flag is for operator-facing UI ("this backup is not restorable").
const (
	QualityFull    = "full"    // full backup, all secrets present (may be random-IV)
	QualityMasked  = "masked"  // FortiOS 7.2.1+ password-masking — restore requires re-entering passwords
	QualityUnknown = "unknown" // we couldn't determine
)

// VolatilePattern identifies a single class of line-level volatility (e.g. ENC
// blobs, timestamps) so the diff UI can mask matching lines instead of styling
// them as red/green deltas. Each Normalizer publishes the patterns it strips
// so the UI can stay consistent with the hash.
type VolatilePattern struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Regex       string `json:"regex"` // RE2 pattern, line-anchored where appropriate
}

// Normalizer collapses volatile-but-meaningless content in vendor config text.
// Implementations must be deterministic: same input → same output.
type Normalizer interface {
	// Vendor returns the Device.Vendor value this normalizer matches.
	Vendor() string
	// Normalize returns a byte-stable representation suitable for hashing,
	// plus a best-effort BackupQuality.
	Normalize(raw []byte) (normalized []byte, quality string)
	// VolatilePatterns returns the line patterns the diff UI should mask.
	VolatilePatterns() []VolatilePattern
}

// LineMasker is an optional capability a Normalizer may implement to support the
// line diff. MaskVolatileLines returns a masked copy of the config whose volatile
// content is neutralized (mirroring Normalize's replacements) but whose LINE COUNT
// is identical to the raw input — masked line i corresponds to raw line i. That
// 1:1 correspondence is what lets the line diff align on masked lines while
// displaying the original text, so volatile churn (random IVs, re-encrypted PEM
// bodies, GUI-dashboard timestamps) never surfaces as a red/green delta.
//
// Unlike Normalize (which may collapse multi-line blocks to a single marker for
// hashing), MaskVolatileLines must never add or remove newlines.
type LineMasker interface {
	MaskVolatileLines(raw []byte) []byte
}

// lineHasSecret reports whether a MASKED line carries a secret-class marker, so
// DiffLines can display the masked form instead of the raw one.
//
// It matches the masked LINE rather than a pattern name extracted by
// volatileTokenRe, because secret markers are deliberately bracket-free (a
// rotation must read as a real change, not as folded noise) and the token regex
// therefore never sees them. Defining this by intent instead of by match target
// once produced a predicate that could never fire.
//
// Scoped to the bracket-free digest tokens only. FortiGate's markers are
// bracketed and never match, so its rendering is unchanged — and it has no
// equivalent leak to fix: FortiOS re-encrypts ENC and PEM bodies with a fresh IV
// on every emission, so raw never equals raw and the equal-row leak cannot arise
// there. Certificate digests are excluded too: a cert is public, and hiding its
// body would defeat the point of fingerprinting the rotation.
func lineHasSecret(masked string) bool {
	return strings.Contains(masked, opnSecretTokenPrefix)
}

// attrPresentValue is the sentinel a parser emits for an element that exists but
// has no text (<descr/>, <any/>, <log/>).
//
// An empty string cannot be used. diffAttrs emits AttrDelta{Key, Old: v} when a
// key is removed and AttrDelta{Key, New: v} when one is added; with v == "" both
// serialize identically, so "this rule gained <any/>" and "this rule lost
// <any/>" become indistinguishable — which makes any widening-vs-narrowing rule
// unimplementable. FortiOS avoids the same trap with its <unset> sentinel.
//
// The value is not perfectly uncollidable — a leaf containing the literal
// &lt;present&gt; decodes to exactly this string — but that is contrived, and the
// alternative (dropping empty attributes) would erase <any/>, which the
// exposure classifier depends on.
const attrPresentValue = "<present>"

var registry = map[string]Normalizer{}

// Register installs a Normalizer for a given vendor key. Called from
// vendor-specific files' init().
func Register(n Normalizer) {
	registry[strings.ToLower(n.Vendor())] = n
}

// Lookup returns the registered normalizer for a vendor, or the identity
// normalizer if vendor is empty/unknown.
func Lookup(vendor string) Normalizer {
	if n, ok := registry[strings.ToLower(strings.TrimSpace(vendor))]; ok {
		return n
	}
	return identityNormalizer{}
}

// Normalize is the convenience entry point used by handlers.
func Normalize(vendor string, raw []byte) (normalized []byte, quality string) {
	return Lookup(vendor).Normalize(raw)
}

// HashNormalized returns the lowercase-hex MD5 of the normalized form. Used
// as DeviceConfigRevision.NormalizedChecksum.
func HashNormalized(vendor string, raw []byte) string {
	normalized, _ := Normalize(vendor, raw)
	sum := md5.Sum(normalized) // (gosec G401 excluded in CI: non-crypto fingerprint, see import note)
	return hex.EncodeToString(sum[:])
}

// VolatilePatternsFor returns the volatile patterns the diff UI should mask
// for a given vendor.
func VolatilePatternsFor(vendor string) []VolatilePattern {
	return Lookup(vendor).VolatilePatterns()
}

// HasRichNormalizer reports whether the vendor has a non-identity normalizer
// registered. Used by startup audit to flag devices whose configs will not be
// stripped of volatile content before hashing — which makes them prone to
// false CONFIG_CHANGE alerts on every backup.
func HasRichNormalizer(vendor string) bool {
	n, ok := registry[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok {
		return false
	}
	return len(n.VolatilePatterns()) > 0
}

// RegisteredVendors returns the set of vendor keys for which a normalizer is
// registered (rich or identity). Order is not stable.
func RegisteredVendors() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}

// identityNormalizer is the fallback for unknown/unsupported vendors. The
// normalized form is byte-identical to the input — equivalent to the
// pre-configdiff hashing behavior. No volatile patterns.
type identityNormalizer struct{}

func (identityNormalizer) Vendor() string                        { return "" }
func (identityNormalizer) Normalize(raw []byte) ([]byte, string) { return raw, QualityUnknown }
func (identityNormalizer) VolatilePatterns() []VolatilePattern   { return nil }
