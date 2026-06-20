package configdiff

import (
	"bytes"
	"regexp"
	"strings"
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

	// `set last-updated <epoch>` — Unix timestamp inside GUI dashboard widgets
	// (and a few other tables). Bumped on any dashboard interaction, unrelated to
	// firewall/security configuration. Left visible it false-alerts on every save.
	fortiLastUpdatedRegex = regexp.MustCompile(`(?m)^(\s*set\s+last-updated\s+).*$`)

	// A FortiOS CLI prompt echoed into a console-captured backup, e.g.
	// `FW-HOME # #config-version=...` or `FW-HOME (global) # config system ...`.
	// The prompt is a capture artifact, not config content; stripping it lets the
	// rest of the line (notably the #config-version header) normalize correctly.
	fortiPromptPrefixRegex = regexp.MustCompile(`(?m)^[A-Za-z0-9._-]+(?: \([A-Za-z0-9._:/-]+\))? # `)

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
	fortiMaskingMarker  = []byte(`config_masked_password`)
	fortiMaskingMarker2 = []byte(`ENC <removed>`)
)

func (fortigateNormalizer) Normalize(raw []byte) ([]byte, string) {
	out := make([]byte, len(raw))
	copy(out, raw)

	// Strip console prompt echoes first so header lines (e.g. #config-version)
	// are left-anchored for the line-anchored regexes below.
	out = fortiPromptPrefixRegex.ReplaceAll(out, nil)

	// Collapse the per-admin `config gui-dashboard ... end` block. It is pure GUI
	// layout state (widget positions/sizes) plus volatile `set last-updated`
	// timestamps, and FortiOS omits it entirely from `show full-configuration`
	// while including it in a plain `show` backup — the single largest source of
	// false config-change alerts between capture modes. We replace the whole
	// block with one stable marker.
	out = stripFortiConfigBlock(out, "gui-dashboard")

	out = fortiEncLineRegex.ReplaceAll(out, []byte(`${1}<volatile-enc>`))
	out = fortiConfigVersionRegex.ReplaceAll(out, []byte(`${1}<volatile-version>`))
	out = fortiConfFileVerRegex.ReplaceAll(out, []byte(`${1}<volatile-conf-file-ver>`))
	out = fortiPrivateEncKeyRegex.ReplaceAll(out, []byte(`${1}<volatile-private-encryption-key>`))
	out = fortiLastLoginRegex.ReplaceAll(out, []byte(`${1}<volatile-last-login>`))
	out = fortiLastUpdatedRegex.ReplaceAll(out, []byte(`${1}<volatile-last-updated>`))
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
		{Name: "last-updated", Description: "GUI widget last-updated Unix timestamp", Regex: `^(\s*set\s+last-updated\s+).*$`},
		{Name: "system-time", Description: "FortiOS system-time banner", Regex: `^(\s*!System time:\s*).*$`},
		{Name: "prompt-prefix", Description: "Console CLI prompt echoed into a captured backup", Regex: `^[A-Za-z0-9._-]+(?: \([A-Za-z0-9._:/-]+\))? # `},
		{Name: "gui-dashboard", Description: "Per-admin GUI dashboard layout block (omitted by `show full-configuration`)", Regex: `(?s)^(\s*)config gui-dashboard\b.*?^\1end$`},
		{Name: "pem-block", Description: "PEM-bearing field (private-key, ca, csr, certificate) — body masked, BEGIN/END preserved", Regex: `(?s)(\s*set\s+\S+\s+"-----BEGIN[^"\r\n]+-----)[^"]*?(-----END[^"\r\n]+-----")`},
	}
}

// CaptureMode classifies how a FortiGate backup was produced by counting the
// `set` lines inside the top-level `config system global` block. A
// `show full-configuration` dump emits every default (~150-220 lines); a plain
// `show` backup emits only non-defaults (a few dozen at most). Backups taken in
// different modes can never hash-match — one carries thousands of default lines
// the other omits — so the analyzer surfaces a mode mismatch instead of letting
// it read as a real config change. Returns "full-configuration", "show", or ""
// (no global block found / undeterminable).
func (fortigateNormalizer) CaptureMode(raw []byte) string {
	// A console capture may echo the CLI prompt onto config lines; strip it so
	// the block header matches.
	clean := fortiPromptPrefixRegex.ReplaceAll(raw, nil)
	n := fortiGlobalSetCount(clean)
	switch {
	case n < 0:
		return ""
	case n >= fortiFullConfigGlobalThreshold:
		return "full-configuration"
	default:
		return "show"
	}
}

// fortiFullConfigGlobalThreshold separates a full-configuration dump from a plain
// show by `config system global` set-line count. Real samples: 207 (full) vs 18
// (show); the default global block carries 150+ settings, a non-default show a
// few dozen at most, so 80 cleanly splits them with wide margin on both sides.
const fortiFullConfigGlobalThreshold = 80

// fortiGlobalSetCount returns the number of `set` lines directly inside the
// top-level `config system global` block, or -1 if no such block exists. Depth
// counting (config/end) keeps nested sub-blocks from inflating the count.
func fortiGlobalSetCount(raw []byte) int {
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "config system global" {
			continue
		}
		count, depth := 0, 1
		for i++; i < len(lines) && depth > 0; i++ {
			switch t := strings.TrimSpace(lines[i]); {
			case strings.HasPrefix(t, "config "):
				depth++
			case t == "end":
				depth--
			case depth == 1 && strings.HasPrefix(t, "set "):
				count++
			}
		}
		return count
	}
	return -1
}

// stripFortiConfigBlock removes every top-of-stack `config <name> ... end` block
// from FortiOS config text, replacing each with a single stable marker line that
// preserves the original indentation. The matching `end` is found with a depth
// counter (`config` opens, `end` closes; `edit`/`next` balance within and are
// ignored) so it is correct regardless of indentation or nesting — a plain regex
// would mis-match the first inner `end` (e.g. a nested `config widget`).
func stripFortiConfigBlock(in []byte, name string) []byte {
	open := "config " + name
	lines := strings.Split(string(in), "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != open {
			out = append(out, lines[i])
			continue
		}
		indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
		out = append(out, indent+"<volatile-"+name+">")
		depth := 1
		for i++; i < len(lines) && depth > 0; i++ {
			switch t := strings.TrimSpace(lines[i]); {
			case strings.HasPrefix(t, "config "):
				depth++
			case t == "end":
				depth--
			}
		}
		i-- // for-loop's i++ re-advances past the consumed `end`
	}
	return []byte(strings.Join(out, "\n"))
}
