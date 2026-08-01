package configdiff

import (
	// SHA-256 here is a NON-CRYPTOGRAPHIC content fingerprint used to make a
	// secret's ROTATION visible without exposing the secret. It is never used for
	// authentication, integrity, or signatures.
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// OPNsense (and pfSense, which it forked from) store the entire device
// configuration as one XML document at /conf/config.xml, captured verbatim by
// the collector. Three classes of content in it churn without any configuration
// having changed, and all three must be neutralized before hashing:
//
//   - Save bookkeeping: the whole <revision> block, plugin persisted_at
//     attributes, and every <time>/<pwd_changed_at> epoch. Rewritten on EVERY
//     save, including a no-op save.
//   - Surrogate keys: OPNsense reassigns uuids wholesale when an object is
//     deleted and recreated — a tunnel recreate churns ~50 lines with
//     byte-identical semantics. See canonicalizeUUIDs.
//   - Secrets: private keys, pre-shared keys and password hashes, which are
//     stable plaintext here (unlike FortiOS ciphertext) and would otherwise be
//     rendered verbatim in the diff UI.
//
// Unlike the FortiOS normalizer, this one's output is RE-PARSED as XML (the
// object diff runs on prepared config text), so every replacement must leave the
// document well-formed. That constrains marker syntax in two different ways —
// see the marker constants below.

func init() {
	Register(opnsenseNormalizer{vendor: "opnsense"})
	// pfSense shares the config.xml lineage: the same save bookkeeping, the same
	// <revision> attribution block, and the same secret-bearing elements. Its
	// object identity differs (no uuid attributes; <tracker> instead), which the
	// parser's per-vendor key table handles.
	Register(opnsenseNormalizer{vendor: "pfsense"})
}

type opnsenseNormalizer struct{ vendor string }

func (n opnsenseNormalizer) Vendor() string { return n.vendor }

// Marker syntax comes in two forms because XML attribute values cannot contain
// '<'. Using the element form inside an attribute yields "unescaped < inside
// quoted string" from encoding/xml — even with Strict disabled — which would
// abort the parse at the first plugin element and make the object diff report
// the entire configuration as removed.
const (
	// Element bodies: self-closing so the document stays well-formed, and
	// matchable by linediff's volatileTokenRe so the UI can name the pattern.
	opnTimeToken     = "<volatile-time/>"
	opnRevisionToken = "<volatile-revision/>"
	// #nosec G101 -- not a credential: this is the literal placeholder written
	// INTO the config text to replace a uuid. G101 matches the "Token" in the
	// identifier name; the value is a fixed XML marker.
	opnUUIDToken = "<volatile-uuid/>"

	// Attribute values: bracket-free. Invisible to volatileTokenRe, so those raw
	// rows render as volatile without a pattern name — an accepted trade.
	opnPersistedAtToken = "volatile-persisted-at"

	// Secret and certificate digests are bracket-free by DESIGN, so volatileTokenRe
	// does NOT match them: a rotation is a real change and must read as one, not
	// be folded away as suppressed noise.
	opnSecretTokenPrefix = "volatile-secret:"
	opnCertTokenPrefix   = "volatile-cert:"
)

// Volatile pattern bodies are declared once and shared by Normalize,
// MaskVolatileLines and VolatilePatterns, so the hash and the UI can never drift
// apart — the same discipline vendor_fortigate.go documents.
const (
	opnRevisionBody    = `(?s)<revision>.*?</revision>`
	opnPersistedAtBody = `(persisted_at=")[^"]*(")`
	opnTimeBody        = `<time>[^<]*</time>`
	// #nosec G101 -- not a credential: a regex matching the ELEMENT that holds a
	// password-change timestamp, so the timestamp can be masked. G101 matches the
	// "Pwd" in the identifier name.
	opnPwdChangedAtBody = `<pwd_changed_at>[^<]*</pwd_changed_at>`
)

// opnSecretElements are elements whose text is credential material. <crt> is
// deliberately absent: a certificate is public, and its rotation is
// operationally meaningful, so it gets its own digest token rather than being
// lumped in with secrets (it must not be display-masked).
var opnSecretElements = []string{
	"password", "bcrypt-hash", "prv", "Key", "secret",
	"passphrase", "pre-shared-key", "radius_secret",
}

var (
	opnRevisionRegex     = regexp.MustCompile(opnRevisionBody)
	opnPersistedAtRegex  = regexp.MustCompile(opnPersistedAtBody)
	opnTimeRegex         = regexp.MustCompile(opnTimeBody)
	opnPwdChangedAtRegex = regexp.MustCompile(opnPwdChangedAtBody)
	opnCertRegex         = regexp.MustCompile(`<crt>[^<]*</crt>`)

	// opnSecretRegexes is one compiled regex per secret element, built from
	// opnSecretElements so adding an element cannot forget a call site.
	opnSecretRegexes = buildSecretRegexes()

	// opnUUIDAnchoredRegex matches a uuid ONLY in the two positions OPNsense
	// actually uses one: the uuid="..." attribute and a bare cross-reference leaf
	// (<connection>UUID</connection>). Anchoring matters — a document-wide
	// substitution would also rewrite a uuid an operator typed into a
	// <description>, silently corrupting operator-authored text.
	opnUUIDAnchoredRegex = regexp.MustCompile(
		`uuid="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"` +
			`|>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}<`)

	opnUUIDValueRegex = regexp.MustCompile(
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

func buildSecretRegexes() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(opnSecretElements))
	for _, el := range opnSecretElements {
		out = append(out, regexp.MustCompile(`<`+regexp.QuoteMeta(el)+`>[^<]*</`+regexp.QuoteMeta(el)+`>`))
	}
	return out
}

// Normalize produces the byte-stable form used for the change-detection hash.
//
// Pipeline order is load-bearing: secrets are digested BEFORE uuids are
// canonicalized, because a secret body containing a uuid-shaped substring would
// otherwise have its digest destabilized by an unrelated ordinal shift.
func (n opnsenseNormalizer) Normalize(raw []byte) ([]byte, string) {
	if len(raw) == 0 {
		return raw, QualityUnknown
	}

	out := maskXMLElementLines(raw, opnRevisionRegex, opnRevisionToken)
	out = opnPersistedAtRegex.ReplaceAll(out, []byte(`${1}`+opnPersistedAtToken+`${2}`))
	out = maskXMLElementLines(out, opnTimeRegex, "<time>"+opnTimeToken+"</time>")
	out = maskXMLElementLines(out, opnPwdChangedAtRegex,
		"<pwd_changed_at>"+opnTimeToken+"</pwd_changed_at>")
	out = digestSecrets(out)
	out = canonicalizeUUIDs(out)

	// OPNsense has no password-masking export mode: a config.xml read is always
	// the full configuration.
	return out, QualityFull
}

// MaskVolatileLines implements LineMasker for the line diff. It mirrors
// Normalize's replacements with one deliberate divergence: uuids collapse to a
// single fixed token rather than to Normalize's positional uuid-N.
//
// Positional tokens must NOT leak into the mask. Alignment runs on masked lines,
// so one early insertion would shift every later ordinal and cascade dozens of
// phantom delete/insert rows for a single added rule. A fixed token instead makes
// uuid churn classify as `volatile` (folded noise) and makes ordinal shift
// structurally incapable of amplifying.
//
// The accepted cost: a genuine cross-reference retarget also reads as volatile in
// the RAW view. The object view still shows it via resolved Paths, which is where
// an operator looks for it. A second, smaller cost is that collapsing uuids
// removes alignment anchors, so several sibling <child uuid="…"> open tags mask
// identically; their differing bodies still anchor the alignment in order, and
// linediff only ever emits `equal` when the RAW lines match, so this can never
// render one object's text under another's heading.
func (n opnsenseNormalizer) MaskVolatileLines(raw []byte) []byte {
	out := maskXMLElementLines(raw, opnRevisionRegex, opnRevisionToken)
	out = opnPersistedAtRegex.ReplaceAll(out, []byte(`${1}`+opnPersistedAtToken+`${2}`))
	out = maskXMLElementLines(out, opnTimeRegex, "<time>"+opnTimeToken+"</time>")
	out = maskXMLElementLines(out, opnPwdChangedAtRegex,
		"<pwd_changed_at>"+opnTimeToken+"</pwd_changed_at>")
	out = digestSecrets(out)
	out = opnUUIDAnchoredRegex.ReplaceAllFunc(out, func(m []byte) []byte {
		if m[0] == '>' {
			return []byte(">" + opnUUIDToken + "<")
		}
		return []byte(`uuid="` + opnUUIDToken + `"`)
	})
	return out
}

// ParseInput implements the ParseInput capability: the object parser is fed
// everything Normalize masks EXCEPT the uuid canonicalization, because uuids are
// its fallback object identity and the key of its cross-reference map. Feeding it
// positional tokens would both collapse distinct objects into one Path and shift
// every identity when an unrelated object is inserted earlier.
func (n opnsenseNormalizer) ParseInput(raw []byte) []byte {
	out := maskXMLElementLines(raw, opnRevisionRegex, opnRevisionToken)
	out = opnPersistedAtRegex.ReplaceAll(out, []byte(`${1}`+opnPersistedAtToken+`${2}`))
	out = maskXMLElementLines(out, opnTimeRegex, "<time>"+opnTimeToken+"</time>")
	out = maskXMLElementLines(out, opnPwdChangedAtRegex,
		"<pwd_changed_at>"+opnTimeToken+"</pwd_changed_at>")
	return digestSecrets(out)
}

func (n opnsenseNormalizer) VolatilePatterns() []VolatilePattern {
	return []VolatilePattern{
		{Name: "revision", Description: "Config save bookkeeping (user, description, timestamp) rewritten on every save", Regex: opnRevisionBody},
		{Name: "persisted-at", Description: "Plugin model save timestamp", Regex: opnPersistedAtBody},
		{Name: "time", Description: "Per-object save timestamps", Regex: opnTimeBody},
		{Name: "pwd-changed-at", Description: "Password change timestamp", Regex: opnPwdChangedAtBody},
		{Name: "uuid", Description: "Surrogate object keys, reassigned when an object is recreated", Regex: opnUUIDValueRegex.String()},
	}
}

// digestSecrets replaces secret and certificate bodies with a short
// content-derived digest.
//
// A digest rather than a flat mask, because a flat mask makes a ROTATION
// invisible: a PSK change or an admin password change on its own would produce
// no delta, no hash change, no alert and no history row — silently swallowing a
// security-relevant event. The digest is equally churn-free and keeps the
// rotation visible. It is truncated to 8 hex chars, and is only ever readable by
// an authenticated admin who could already read the configuration; that is
// strictly better than today, where the cleartext itself is rendered.
func digestSecrets(in []byte) []byte {
	out := in
	for _, re := range opnSecretRegexes {
		out = fingerprintXMLElement(out, re, opnSecretTokenPrefix)
	}
	return fingerprintXMLElement(out, opnCertRegex, opnCertTokenPrefix)
}

// fingerprintXMLElement rewrites each match's element body to
// "<tag>prefix:<8 hex>". Deterministic, so an unchanged value never churns the
// hash, yet visibly different after a rotation.
func fingerprintXMLElement(in []byte, re *regexp.Regexp, prefix string) []byte {
	return re.ReplaceAllFunc(in, func(m []byte) []byte {
		s := string(m)
		open := strings.Index(s, ">")
		close := strings.LastIndex(s, "<")
		if open < 0 || close <= open {
			return m
		}
		body := s[open+1 : close]
		if body == "" {
			return m // nothing to hide; keep empty elements distinguishable
		}
		sum := sha256.Sum256([]byte(body))
		return []byte(s[:open+1] + prefix + hex.EncodeToString(sum[:])[:8] + s[close:])
	})
}

// canonicalizeUUIDs rewrites each DISTINCT uuid to a positional token in
// first-appearance order, so a device-side uuid reshuffle with identical content
// hashes identically.
//
// Two limits, both acceptable and neither silent:
//   - Inserting an object early renumbers every later uuid and changes the hash.
//     That co-occurs with a genuine configuration change, so it is not a false
//     positive.
//   - Reordering the same set of uuids also changes the hash. Order-independence
//     is unachievable without parsing, and the parse happens downstream of the
//     hash. OPNsense appends rather than reorders, so this is theoretical.
//
// Neither limit can reach object identity: ParseInput keeps the ORIGINAL uuids,
// so the parser never sees a positional token.
func canonicalizeUUIDs(in []byte) []byte {
	seen := make(map[string]string)
	return opnUUIDAnchoredRegex.ReplaceAllFunc(in, func(m []byte) []byte {
		s := string(m)
		u := opnUUIDValueRegex.FindString(s)
		if u == "" {
			return m
		}
		tok, ok := seen[u]
		if !ok {
			tok = "uuid-" + strconv.Itoa(len(seen)+1)
			seen[u] = tok
		}
		return []byte(strings.Replace(s, u, tok, 1))
	})
}

// maskXMLElementLines is the line-count-preserving sibling of a plain
// ReplaceAll: it emits the replacement, then one extra newline per newline the
// match consumed, so masked line i still corresponds to raw line i and the Myers
// alignment in DiffLines never drifts. (Mirrors maskFortiPemLines; the same 1:1
// invariant is asserted in prepareDiffInput, which degrades to NO masking at all
// if it is violated — so a violation would silently disable volatile folding.)
//
// Applied to every element pattern, not only the multi-line <revision> block:
// the single-line ones cost nothing extra, and a multi-line body on some other
// device would otherwise break alignment invisibly.
func maskXMLElementLines(in []byte, re *regexp.Regexp, replacement string) []byte {
	return re.ReplaceAllFunc(in, func(m []byte) []byte {
		out := []byte(replacement)
		for _, c := range m {
			if c == '\n' {
				out = append(out, '\n')
			}
		}
		return out
	})
}
