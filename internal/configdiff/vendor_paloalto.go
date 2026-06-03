package configdiff

import (
	"bytes"
	"regexp"
)

// PAN-OS exports its running config as XML. Several elements re-salt or
// re-encrypt on every commit/export, so byte-level diffs are noisy even when
// no operator change occurred. Pattern set is informed by:
//   - PAN community KB on per-generation salted password hashes (phash)
//   - PAN-OS encrypted-field marker `-AQ==` (AES-256-CBC ciphertext)
//   - Sanitized exports (non-superuser) replace secrets with `*****` literal,
//     which we surface as QualityMasked.
//
// The normalizer is line/element-targeted, not a full XML parser — keep it
// cheap and tolerant of formatting drift. Tests assert structural changes are
// still detected; refer to the configdiff tests for the contract.

func init() {
	Register(paloaltoNormalizer{})
}

type paloaltoNormalizer struct{}

func (paloaltoNormalizer) Vendor() string { return "paloalto" }

var (
	// <phash>$1$...salted-hash...</phash> — admin password hash, re-salted every
	// emission. Anchored to the closing tag so we don't gobble across siblings.
	panPhashRegex = regexp.MustCompile(`(?s)(<phash>)[^<]*(</phash>)`)

	// <secret>...</secret> — LDAP bind, RADIUS, IKE PSK, SNMPv3 auth/priv.
	panSecretRegex = regexp.MustCompile(`(?s)(<secret>)[^<]*(</secret>)`)

	// <key>...</key> — generic encrypted key. Most PAN-OS encrypted values are
	// prefixed with `-AQ==` but the tag itself is what we match.
	panKeyRegex = regexp.MustCompile(`(?s)(<key>)[^<]*(</key>)`)

	// <password>...</password> and <passphrase>...</passphrase> — plaintext on
	// commit, encrypted on save. Either way, masked to remove drift.
	panPasswordRegex   = regexp.MustCompile(`(?s)(<password>)[^<]*(</password>)`)
	panPassphraseRegex = regexp.MustCompile(`(?s)(<passphrase>)[^<]*(</passphrase>)`)

	// <config version="..." detail-version="..." ... > — root-element attributes
	// drift with PAN-OS build/version metadata on every save.
	panConfigVersionAttrRegex = regexp.MustCompile(`(<config\s+)[^>]*(>)`)

	// Sanitized-export marker. Non-superuser exports replace secrets with this
	// literal — the backup is NOT restorable. Surface as QualityMasked.
	panSanitizedMarker = []byte(`*****`)
)

func (paloaltoNormalizer) Normalize(raw []byte) ([]byte, string) {
	out := make([]byte, len(raw))
	copy(out, raw)

	out = panPhashRegex.ReplaceAll(out, []byte(`${1}<volatile-phash>${2}`))
	out = panSecretRegex.ReplaceAll(out, []byte(`${1}<volatile-secret>${2}`))
	out = panKeyRegex.ReplaceAll(out, []byte(`${1}<volatile-key>${2}`))
	out = panPasswordRegex.ReplaceAll(out, []byte(`${1}<volatile-password>${2}`))
	out = panPassphraseRegex.ReplaceAll(out, []byte(`${1}<volatile-passphrase>${2}`))
	out = panConfigVersionAttrRegex.ReplaceAll(out, []byte(`${1}<volatile-config-attrs>${2}`))

	quality := QualityFull
	// Heuristic: sanitized exports replace every secret with the literal `*****`.
	// We only flag masked if the marker appears multiple times — a single
	// `*****` could legitimately appear in a description/comment.
	if bytes.Count(raw, panSanitizedMarker) >= 3 {
		quality = QualityMasked
	}

	return out, quality
}

func (paloaltoNormalizer) VolatilePatterns() []VolatilePattern {
	return []VolatilePattern{
		{Name: "phash", Description: "PAN-OS admin password hash (re-salted per emission)", Regex: `(?s)(<phash>)[^<]*(</phash>)`},
		{Name: "secret", Description: "PAN-OS LDAP/RADIUS/IKE/SNMPv3 secret", Regex: `(?s)(<secret>)[^<]*(</secret>)`},
		{Name: "key", Description: "PAN-OS encrypted key (AES-256-CBC, random IV)", Regex: `(?s)(<key>)[^<]*(</key>)`},
		{Name: "password", Description: "PAN-OS password element", Regex: `(?s)(<password>)[^<]*(</password>)`},
		{Name: "passphrase", Description: "PAN-OS passphrase element", Regex: `(?s)(<passphrase>)[^<]*(</passphrase>)`},
		{Name: "config-attrs", Description: "PAN-OS <config> root attributes (version/detail-version drift)", Regex: `(<config\s+)[^>]*(>)`},
	}
}
