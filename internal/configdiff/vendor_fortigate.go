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

	// Multi-line PEM-bearing fields. Covers `set private-key` (body re-encrypted
	// with random IV every backup), `set ca`, `set csr`, `set certificate`, and
	// any future `set <field> "-----BEGIN..."` line FortiOS adds. Even
	// deterministic certs/CSRs can drift on re-emission due to whitespace
	// normalization — masking the body keeps the diff stable. The captured
	// BEGIN/END markers are preserved so the diff UI still shows WHICH field
	// was masked.
	//
	// (?s) makes `[^"]*?` span newlines for the body, but the BEGIN/END line
	// inner-text uses [^"\r\n]+ so each match stays anchored to ONE BEGIN
	// line and ONE END line — otherwise greedy matching collapses two
	// adjacent PEM blocks (e.g. `set ca` immediately followed by `set csr`)
	// into a single capture, masking the second field name and losing the
	// boundary between them.
	fortiPemBlockRegex = regexp.MustCompile(
		`(?s)(\s*set\s+\S+\s+"-----BEGIN[^"\r\n]+-----)[^"]*?(-----END[^"\r\n]+-----")`,
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
	out = fortiPemBlockRegex.ReplaceAll(out, []byte(`${1}<volatile-pem>${2}`))

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
		{Name: "pem-block", Description: "PEM-bearing field (private-key, ca, csr, certificate) — body masked, BEGIN/END preserved", Regex: `(?s)(\s*set\s+\S+\s+"-----BEGIN[^"\r\n]+-----)[^"]*?(-----END[^"\r\n]+-----")`},
	}
}
