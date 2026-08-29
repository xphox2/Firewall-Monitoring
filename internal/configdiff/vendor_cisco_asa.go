package configdiff

import "regexp"

// Cisco ASA / IOS configs are mostly stable across `show running-config` —
// Type 5 (MD5-crypt), Type 7 (Vigenere — broken but deterministic), Type 8
// (PBKDF2-SHA256), and Type 9 (scrypt) all produce identical ciphertext on
// re-emission. The only volatile-by-design secret is Type 6 (AES-256-CBC with
// the master passphrase — `key config-key password-encryption` / `password
// encryption aes`), which uses a random nonce per emission.
//
// Strategy: mask Type 6 secrets (truly volatile) and the `: Saved` timestamp
// header. Leave Types 5/7/8/9 visible so a real password rotation produces a
// detectable hash change.

func init() {
	Register(ciscoASANormalizer{})
}

type ciscoASANormalizer struct{}

func (ciscoASANormalizer) Vendor() string { return "cisco_asa" }

var (
	// `: Saved` and `: Written by ... at ...` — timestamp banners at the top
	// of `show tech` style dumps. Plain `show running-config` skips these,
	// but some backup mechanisms include them.
	asaSavedHeaderRegex = regexp.MustCompile(`(?m)^(\s*:\s*Saved)[^\r\n]*$`)
	asaWrittenByRegex   = regexp.MustCompile(`(?m)^(\s*:\s*Written by\s+)[^\r\n]*$`)

	// Type 6 secrets (master-passphrase AES, random nonce per emission). Match
	// any password-bearing config line where the type indicator is `6`.
	// Captures: `enable secret 6 <blob>`, `username X password 6 <blob>`,
	// `<protocol> key 6 <blob>`, `key-string 6 <blob>`.
	asaType6EnableSecretRegex = regexp.MustCompile(`(?m)^(\s*enable\s+secret\s+6\s+)\S+\s*$`)
	asaType6UserPasswordRegex = regexp.MustCompile(`(?m)^(\s*username\s+\S+\s+password\s+6\s+)\S+(\s.*)?$`)
	asaType6KeyRegex          = regexp.MustCompile(`(?m)^(\s*(?:key|key-string)\s+6\s+)\S+\s*$`)

	// Master passphrase declaration itself — `key config-key password-encryption
	// <passphrase>`. Operator-supplied; not random, but logging/redacting it is
	// the right call regardless. If present, treat as masked-bytes for quality.
	asaMasterPassphraseRegex = regexp.MustCompile(`(?m)^(\s*key\s+config-key\s+password-encryption\s+)\S+\s*$`)
)

// maskVolatile replaces each volatile secret/header VALUE with a fixed
// `<volatile-*>` token while keeping the config keyword, so a real change stays
// visible. Shared by Normalize (hashing) and MaskVolatileLines (line diff) so
// the two can never drift and VolatilePatterns stays truthful.
//
// A FLAT token, not a content digest: Type 6 (AES master-passphrase) re-nonces
// on every emission for the SAME secret, so a digest would still churn — only a
// fixed token kills the false delta. Every regex is `(?m)^…$` line-anchored, so
// the line count is preserved exactly. Types 5/7/8/9 are deliberately left
// untouched (deterministic ciphertext) so a real rotation still diffs.
func (ciscoASANormalizer) maskVolatile(raw []byte) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)

	out = asaSavedHeaderRegex.ReplaceAll(out, []byte(`${1} <volatile-timestamp>`))
	out = asaWrittenByRegex.ReplaceAll(out, []byte(`${1}<volatile-timestamp>`))

	out = asaType6EnableSecretRegex.ReplaceAll(out, []byte(`${1}<volatile-type6>`))
	out = asaType6UserPasswordRegex.ReplaceAll(out, []byte(`${1}<volatile-type6>${2}`))
	out = asaType6KeyRegex.ReplaceAll(out, []byte(`${1}<volatile-type6>`))
	out = asaMasterPassphraseRegex.ReplaceAll(out, []byte(`${1}<volatile-master-passphrase>`))

	return out
}

func (n ciscoASANormalizer) Normalize(raw []byte) ([]byte, string) {
	return n.maskVolatile(raw), QualityFull
}

// MaskVolatileLines implements LineMasker (AUDIT-265): without it prepareDiffInput
// fell back to unmasked lines, so Type 6 (random-nonce) secrets and the `: Saved`
// timestamp header churned as false red/green deltas on every diff even though
// VolatilePatterns advertised them as masked. The line-anchored regexes keep the
// line count 1:1.
func (n ciscoASANormalizer) MaskVolatileLines(raw []byte) []byte {
	return n.maskVolatile(raw)
}

func (ciscoASANormalizer) VolatilePatterns() []VolatilePattern {
	return []VolatilePattern{
		{Name: "saved-header", Description: "ASA `: Saved` timestamp header", Regex: `^(\s*:\s*Saved)[^\r\n]*$`},
		{Name: "written-by-header", Description: "ASA `: Written by` timestamp header", Regex: `^(\s*:\s*Written by\s+)[^\r\n]*$`},
		{Name: "type6-enable-secret", Description: "Type 6 (AES master-passphrase) enable secret — random nonce per emission", Regex: `^(\s*enable\s+secret\s+6\s+)\S+\s*$`},
		{Name: "type6-user-password", Description: "Type 6 username password — random nonce per emission", Regex: `^(\s*username\s+\S+\s+password\s+6\s+)\S+(\s.*)?$`},
		{Name: "type6-key", Description: "Type 6 keychain/key-string — random nonce per emission", Regex: `^(\s*(?:key|key-string)\s+6\s+)\S+\s*$`},
		{Name: "master-passphrase", Description: "ASA master passphrase declaration", Regex: `^(\s*key\s+config-key\s+password-encryption\s+)\S+\s*$`},
	}
}
