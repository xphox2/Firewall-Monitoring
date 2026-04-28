package configdiff

import (
	"bytes"
	"regexp"
)

// FortiOS emits config text where credential-bearing fields are wrapped in
// AES-128-CBC ciphertext using a 4-byte random IV salt prepended to each blob.
// The IV is regenerated on every emission, so the same plaintext password
// produces a different ENC blob every backup. Same for `BEGIN ENCRYPTED PRIVATE
// KEY` blocks. Several header lines also drift per emission.
//
// To detect actual configuration changes we strip these patterns before
// hashing. The normalizer is deliberately conservative — only well-known
// volatile patterns are touched. Real changes to surrounding lines remain
// detectable.
//
// Pattern set is informed by the Oxidized FortiOS model
// (lib/oxidized/model/fortios.rb) and RANCID's fnrancid filter — both have
// shipped this pattern set for years across the FortiOS fleet.

func init() {
	Register(&fortigateNormalizer{})
}

type fortigateNormalizer struct{}

func (fortigateNormalizer) Vendor() string { return "fortigate" }

var (
	// `set <field> ENC <base64-blob>` — credential ciphertext. Random IV per emission.
	fortiEncLineRegex = regexp.MustCompile(`(?m)^(\s*set\s+\S+\s+ENC\s+)\S+\s*$`)

	// `#config-version=...` and `#conf_file_ver=...` — header lines that include
	// monotonically-changing version numbers and timestamps unrelated to config content.
	fortiConfigVersionRegex = regexp.MustCompile(`(?m)^(#config-version=).*$`)
	fortiConfFileVerRegex   = regexp.MustCompile(`(?m)^(#conf_file_ver=).*$`)

	// `#private-encryption-key=...` — only present when private-data-encryption is enabled.
	// The key itself is admin-supplied and we shouldn't hash it.
	fortiPrivateEncKeyRegex = regexp.MustCompile(`(?m)^(#private-encryption-key=).*$`)

	// `set last-login ...` — drifts on every login event.
	fortiLastLoginRegex = regexp.MustCompile(`(?m)^(\s*set\s+last-login\s+).*$`)

	// `!System time:` — ad-hoc timestamp banners some FortiOS builds inject.
	fortiSystemTimeRegex = regexp.MustCompile(`(?m)^(\s*!System time:\s*).*$`)

	// Multi-line PEM-style private key blocks. Body is re-encrypted with random
	// IV on every backup. Match from the BEGIN line through the matching END line.
	// Use (?s) for dotall so `.` spans newlines.
	fortiPrivateKeyBlockRegex = regexp.MustCompile(
		`(?s)(\s*set\s+private-key\s+"-----BEGIN[^"]+-----).*?(-----END[^"]+-----")`,
	)

	// Password-masking marker (FortiOS 7.2.1+ optional feature). Presence in the
	// backup means the backup is NOT restorable — restore requires re-entering
	// secrets. We surface this as BackupQuality="masked".
	fortiMaskingMarker = []byte(`config_masked_password`)
	fortiMaskingMarker2 = []byte(`ENC <removed>`)
)

func (fortigateNormalizer) Normalize(raw []byte) ([]byte, string) {
	out := make([]byte, len(raw))
	copy(out, raw)

	out = fortiEncLineRegex.ReplaceAll(out, []byte(`${1}<volatile-enc>`))
	out = fortiConfigVersionRegex.ReplaceAll(out, []byte(`${1}<volatile-version>`))
	out = fortiConfFileVerRegex.ReplaceAll(out, []byte(`${1}<volatile-conf-file-ver>`))
	out = fortiPrivateEncKeyRegex.ReplaceAll(out, []byte(`${1}<volatile-private-encryption-key>`))
	out = fortiLastLoginRegex.ReplaceAll(out, []byte(`${1}<volatile-last-login>`))
	out = fortiSystemTimeRegex.ReplaceAll(out, []byte(`${1}<volatile-system-time>`))
	out = fortiPrivateKeyBlockRegex.ReplaceAll(out, []byte(`${1}<volatile-private-key>${2}`))

	quality := QualityFull
	if bytes.Contains(raw, fortiMaskingMarker) || bytes.Contains(raw, fortiMaskingMarker2) {
		quality = QualityMasked
	}

	return out, quality
}

func (fortigateNormalizer) VolatilePatterns() []VolatilePattern {
	return []VolatilePattern{
		{Name: "enc", Description: "AES-encrypted secret with random IV", Regex: `^(\s*set\s+\S+\s+ENC\s+)\S+\s*$`},
		{Name: "config-version", Description: "FortiOS config-version header", Regex: `^(#config-version=).*$`},
		{Name: "conf-file-ver", Description: "FortiOS conf_file_ver header", Regex: `^(#conf_file_ver=).*$`},
		{Name: "private-encryption-key", Description: "Admin-supplied private-data-encryption key", Regex: `^(#private-encryption-key=).*$`},
		{Name: "last-login", Description: "Per-admin last-login timestamp", Regex: `^(\s*set\s+last-login\s+).*$`},
		{Name: "system-time", Description: "FortiOS system-time banner", Regex: `^(\s*!System time:\s*).*$`},
		{Name: "private-key", Description: "PEM-encoded private key block (random IV body)", Regex: `(?s)(\s*set\s+private-key\s+"-----BEGIN[^"]+-----).*?(-----END[^"]+-----")`},
	}
}
