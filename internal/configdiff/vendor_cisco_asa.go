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
	asaSavedHeaderRegex   = regexp.MustCompile(`(?m)^(\s*:\s*Saved)[^\r\n]*$`)
	asaWrittenByRegex     = regexp.MustCompile(`(?m)^(\s*:\s*Written by\s+)[^\r\n]*$`)

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

func (ciscoASANormalizer) Normalize(raw []byte) ([]byte, string) {
	out := make([]byte, len(raw))
	copy(out, raw)

	out = asaSavedHeaderRegex.ReplaceAll(out, []byte(`${1} <volatile-timestamp>`))
	out = asaWrittenByRegex.ReplaceAll(out, []byte(`${1}<volatile-timestamp>`))

	out = asaType6EnableSecretRegex.ReplaceAll(out, []byte(`${1}<volatile-type6>`))
	out = asaType6UserPasswordRegex.ReplaceAll(out, []byte(`${1}<volatile-type6>${2}`))
	out = asaType6KeyRegex.ReplaceAll(out, []byte(`${1}<volatile-type6>`))
	out = asaMasterPassphraseRegex.ReplaceAll(out, []byte(`${1}<volatile-master-passphrase>`))

	return out, QualityFull
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
