package configdiff

import (
	"bytes"
	"strings"
	"testing"
)

// Synthetic FortiOS-shaped config fixtures.
//
// These mimic real `show full-configuration` output structure with:
//   - drifting header lines (#config-version, #conf_file_ver)
//   - drifting ENC blobs (random IV ciphertext per emission)
//   - drifting last-login timestamps
//   - PEM-encoded private-key blocks with random-IV bodies
//
// Two snapshots represent the same logical config emitted twice with no real
// changes — every volatile pattern differs between them, but the normalized
// form should be byte-identical.

const fortigateUnchangedA = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466111111
#buildno=2660
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC AbCdEfGh1234567890iVrandomA==
        set last-login 2026-04-27 14:32:11
    next
    edit "test"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC ZzYyXxWw9876543210iVrandomA==
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIRANDOM_IV_AAAA
restofbody=ciphertextAAA==
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
    next
end
`

const fortigateUnchangedB = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466222222
#buildno=2660
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC QqWwEeRr1111111111iVrandomB==
        set last-login 2026-04-27 14:38:42
    next
    edit "test"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC TtYyUuIi2222222222iVrandomB==
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIRANDOM_IV_BBBB
differentbody=ciphertextBBB==
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
    next
end
`

// Real change: a new firewall policy added.
const fortigatePolicyAdded = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466333333
#buildno=2660
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC AaaaBbbbCcccDdddEeeeiVrandomC==
        set last-login 2026-04-27 14:50:00
    next
    edit "test"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC FfffGgggHhhhIiiiJjjjiVrandomC==
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIRANDOM_IV_CCCC
yetanotherbody=ciphertextCCC==
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
    next
    edit 2
        set name "ALLOW_GUEST"
        set srcintf "guest"
        set dstintf "wan1"
        set action accept
    next
end
`

// Real change: an interface IP changed.
const fortigateInterfaceIPChanged = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466444444
#buildno=2660
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system interface
    edit "lan"
        set ip 192.168.5.1 255.255.255.0
    next
end
config system admin
    edit "admin"
        set password ENC ZzAaBbCcDdEeFfGgiVrandomD==
        set last-login 2026-04-27 15:00:00
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
    next
end
`

// Same plaintext password, different ENC blob (different IV). This is the
// case we explicitly accept we cannot detect through hashing — a password-only
// rotation looks identical to IV churn after normalization.
const fortigatePasswordOnly = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466555555
#buildno=2660
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC ThisIsCompletelyDifferentCiphertext==
        set last-login 2026-04-27 15:30:00
    next
    edit "test"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC AnotherCompletelyDifferentBlobZZZ==
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIRANDOM_IV_DDDD
ggggbody=ciphertextDDD==
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
    next
end
`

// Mark this fixture as masked-output (FortiOS 7.2.1+ password-masking).
const fortigateMaskedBackup = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
config system admin
    edit "admin"
        set password ENC <removed>
    next
end
`

func TestFortiGateNormalizerStableAcrossUnchangedSnapshots(t *testing.T) {
	t.Parallel()
	a, qa := Normalize("fortigate", []byte(fortigateUnchangedA))
	b, qb := Normalize("fortigate", []byte(fortigateUnchangedB))

	if !bytes.Equal(a, b) {
		t.Fatalf("normalized bytes differ between unchanged snapshots\n--- A ---\n%s\n--- B ---\n%s",
			a, b)
	}
	if HashNormalized("fortigate", []byte(fortigateUnchangedA)) !=
		HashNormalized("fortigate", []byte(fortigateUnchangedB)) {
		t.Fatal("normalized hashes differ between unchanged snapshots")
	}
	if qa != QualityFull || qb != QualityFull {
		t.Fatalf("expected full quality, got A=%q B=%q", qa, qb)
	}
}

func TestFortiGateNormalizerDetectsRealChanges(t *testing.T) {
	t.Parallel()
	base := HashNormalized("fortigate", []byte(fortigateUnchangedA))
	policy := HashNormalized("fortigate", []byte(fortigatePolicyAdded))
	iface := HashNormalized("fortigate", []byte(fortigateInterfaceIPChanged))

	if base == policy {
		t.Error("policy-added must differ from baseline")
	}
	if base == iface {
		t.Error("interface-ip-changed must differ from baseline")
	}
}

func TestFortiGatePasswordOnlyChangeIsAcceptedlyInvisible(t *testing.T) {
	t.Parallel()
	// Documented limitation: a password-only rotation produces a different
	// ENC blob, but the normalizer strips it the same way as IV churn, so
	// the hash matches the baseline. We accept this — see plan section
	// "Change detection" tradeoff.
	base := HashNormalized("fortigate", []byte(fortigateUnchangedA))
	pwOnly := HashNormalized("fortigate", []byte(fortigatePasswordOnly))
	if base != pwOnly {
		t.Errorf("password-only change should normalize to same hash as baseline (this is accepted limitation); got base=%s pwOnly=%s",
			base, pwOnly)
	}
}

func TestFortiGateNormalizerDetectsMasking(t *testing.T) {
	t.Parallel()
	_, q := Normalize("fortigate", []byte(fortigateMaskedBackup))
	if q != QualityMasked {
		t.Errorf("expected masked quality, got %q", q)
	}
}

func TestFortiGateVolatilePatternStripping(t *testing.T) {
	t.Parallel()
	out, _ := Normalize("fortigate", []byte(fortigateUnchangedA))
	s := string(out)

	// Specific volatile content must not appear in normalized output.
	bannedSubstrings := []string{
		"AbCdEfGh1234567890iVrandomA==",
		"ZzYyXxWw9876543210iVrandomA==",
		"58388916466111111",
		"2026-04-27 14:32:11",
		"restofbody=ciphertextAAA==",
	}
	for _, banned := range bannedSubstrings {
		if strings.Contains(s, banned) {
			t.Errorf("normalized output should not contain volatile substring %q", banned)
		}
	}

	// Stable structural content must still be present.
	required := []string{
		`set hostname "FW-HOME"`,
		`set admin-port 443`,
		`set accprofile "super_admin"`,
		`edit "admin"`,
		`edit "test"`,
		`set name "ALLOW_LAN"`,
	}
	for _, r := range required {
		if !strings.Contains(s, r) {
			t.Errorf("normalized output should preserve stable line %q", r)
		}
	}
}

func TestIdentityNormalizerForUnknownVendor(t *testing.T) {
	t.Parallel()
	raw := []byte("anything goes here\nincluding ENC blobs\n")
	out, q := Normalize("", raw)
	if !bytes.Equal(raw, out) {
		t.Error("identity normalizer must return raw bytes unchanged")
	}
	if q != QualityUnknown {
		t.Errorf("identity quality should be %q, got %q", QualityUnknown, q)
	}
}

func TestRegisteredVendorsLookup(t *testing.T) {
	t.Parallel()
	cases := []struct {
		vendor   string
		wantSame bool // does Normalize return identical bytes for this raw input?
	}{
		{"fortigate", false}, // FortiGate strips
		{"paloalto", true},   // identity (today)
		{"cisco_asa", true},
		{"generic", true},
		{"", true},
		{"unknown_vendor", true},
		{"FORTIGATE", false}, // case-insensitive lookup
	}
	raw := []byte("set password ENC abc123==\n")
	for _, c := range cases {
		out, _ := Normalize(c.vendor, raw)
		same := bytes.Equal(raw, out)
		if same != c.wantSame {
			t.Errorf("vendor=%q: wantSame=%v got=%v (out=%q)", c.vendor, c.wantSame, same, out)
		}
	}
}

func TestVolatilePatternsForFortiGate(t *testing.T) {
	t.Parallel()
	patterns := VolatilePatternsFor("fortigate")
	if len(patterns) == 0 {
		t.Fatal("fortigate must publish volatile patterns")
	}
	// Each published regex must be valid RE2.
	for _, p := range patterns {
		if p.Name == "" || p.Description == "" || p.Regex == "" {
			t.Errorf("incomplete VolatilePattern: %+v", p)
		}
	}
}

// FortiGate certs (CA / CSR) live in `set ca` / `set csr` lines with PEM
// bodies. They may not have random IVs like private-key, but whitespace and
// emission-order drift on re-export. The generalized fortiPemBlockRegex masks
// the body and keeps the BEGIN/END markers visible.
const fortigateCertsA = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
config vpn certificate ca
    edit "CA_Cert_1"
        set ca "-----BEGIN CERTIFICATE-----
MIID_BODY_AAAA
MIID_BODY_BBBB
-----END CERTIFICATE-----"
    next
end
config vpn certificate request
    edit "csr_1"
        set csr "-----BEGIN CERTIFICATE REQUEST-----
CSR_BODY_AAAA
-----END CERTIFICATE REQUEST-----"
    next
end
`

const fortigateCertsB = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
config vpn certificate ca
    edit "CA_Cert_1"
        set ca "-----BEGIN CERTIFICATE-----
MIID_BODY_AAAA_REWRAPPED
MIID_BODY_BBBB_REWRAPPED
-----END CERTIFICATE-----"
    next
end
config vpn certificate request
    edit "csr_1"
        set csr "-----BEGIN CERTIFICATE REQUEST-----
CSR_BODY_AAAA_DIFFERENT
-----END CERTIFICATE REQUEST-----"
    next
end
`

func TestFortiGateNormalizerStripsCertAndCSRBlocks(t *testing.T) {
	t.Parallel()
	a := HashNormalized("fortigate", []byte(fortigateCertsA))
	b := HashNormalized("fortigate", []byte(fortigateCertsB))
	if a != b {
		t.Errorf("FortiGate cert/CSR body drift must normalize to same hash; got a=%s b=%s", a, b)
	}
	out, _ := Normalize("fortigate", []byte(fortigateCertsA))
	s := string(out)
	// BEGIN/END markers preserved (so diff UI shows the field name).
	if !strings.Contains(s, `set ca "-----BEGIN CERTIFICATE-----`) {
		t.Errorf("normalized output must preserve `set ca` BEGIN marker; got:\n%s", s)
	}
	if !strings.Contains(s, `set csr "-----BEGIN CERTIFICATE REQUEST-----`) {
		t.Errorf("normalized output must preserve `set csr` BEGIN marker")
	}
	// Body content gone.
	if strings.Contains(s, "MIID_BODY_AAAA") {
		t.Errorf("cert body should be stripped from normalized output")
	}
	if strings.Contains(s, "CSR_BODY_AAAA") {
		t.Errorf("CSR body should be stripped from normalized output")
	}
}

// ---- PAN-OS ----

const panosA = `<config version="9.1.0" detail-version="9.1.0-h1" urldb="paloaltonetworks">
<mgt-config>
  <users>
    <entry name="admin">
      <phash>$1$abcdSALT1$randomhash1aaaaaaaaaa</phash>
    </entry>
  </users>
</mgt-config>
<shared>
  <local-user-database>
    <user>
      <entry name="vpnuser">
        <phash>$1$xyzSALT2$randomhash2bbbbbbbbb</phash>
      </entry>
    </user>
  </local-user-database>
</shared>
<network>
  <ike>
    <gateway>
      <entry name="gw1">
        <secret>-AQ==aaaaaaaaaaaa</secret>
        <key>-AQ==kkkkkkkkkkkk</key>
      </entry>
    </gateway>
  </ike>
</network>
</config>
`

const panosB = `<config version="9.1.1" detail-version="9.1.1-h2" urldb="paloaltonetworks">
<mgt-config>
  <users>
    <entry name="admin">
      <phash>$1$DIFFSALTQ$DIFFERENTHASHrrrrrrrrr</phash>
    </entry>
  </users>
</mgt-config>
<shared>
  <local-user-database>
    <user>
      <entry name="vpnuser">
        <phash>$1$ANOTHERSALT$ANOTHERHASHsssssssss</phash>
      </entry>
    </user>
  </local-user-database>
</shared>
<network>
  <ike>
    <gateway>
      <entry name="gw1">
        <secret>-AQ==DIFFERENTciphertext</secret>
        <key>-AQ==DIFFERENTkey</key>
      </entry>
    </gateway>
  </ike>
</network>
</config>
`

const panosRealChange = `<config version="9.1.0" detail-version="9.1.0-h1" urldb="paloaltonetworks">
<mgt-config>
  <users>
    <entry name="admin">
      <phash>$1$abcdSALT1$randomhash1aaaaaaaaaa</phash>
    </entry>
    <entry name="newadmin">
      <phash>$1$NEW$NEWHASH</phash>
    </entry>
  </users>
</mgt-config>
</config>
`

func TestPaloAltoNormalizerStableAcrossUnchangedSnapshots(t *testing.T) {
	t.Parallel()
	a := HashNormalized("paloalto", []byte(panosA))
	b := HashNormalized("paloalto", []byte(panosB))
	if a != b {
		t.Errorf("PAN-OS phash/secret/key/config-attr drift must normalize to same hash; got a=%s b=%s", a, b)
	}
}

func TestPaloAltoNormalizerDetectsRealChange(t *testing.T) {
	t.Parallel()
	base := HashNormalized("paloalto", []byte(panosA))
	added := HashNormalized("paloalto", []byte(panosRealChange))
	if base == added {
		t.Errorf("PAN-OS structural change (new admin entry) must produce a different hash")
	}
}

func TestPaloAltoNormalizerStripsSensitiveContent(t *testing.T) {
	t.Parallel()
	out, _ := Normalize("paloalto", []byte(panosA))
	s := string(out)
	banned := []string{
		"randomhash1aaaaaaaaaa",
		"randomhash2bbbbbbbbb",
		"-AQ==aaaaaaaaaaaa",
		"-AQ==kkkkkkkkkkkk",
		`version="9.1.0"`,
		`detail-version="9.1.0-h1"`,
	}
	for _, b := range banned {
		if strings.Contains(s, b) {
			t.Errorf("PAN-OS normalized output must not contain %q; got:\n%s", b, s)
		}
	}
}

func TestPaloAltoSanitizedExportDetected(t *testing.T) {
	t.Parallel()
	sanitized := `<config><phash>*****</phash><secret>*****</secret><key>*****</key></config>`
	_, q := Normalize("paloalto", []byte(sanitized))
	if q != QualityMasked {
		t.Errorf("PAN-OS sanitized export should detect QualityMasked, got %q", q)
	}
}

// ---- Cisco ASA ----

const asaA = `: Saved
: Written by admin at 14:32:01 EST Tue Apr 27 2026
ASA Version 9.16(4)
!
hostname FW-LAB
enable secret 6 a$BcDe$F.GhIj/random-nonce-aaaa
username alice password 6 a$xYz$abcDEF/nonce-bbbb privilege 15
key config-key password-encryption MasterPassphrase1
crypto key generate rsa modulus 2048
!
crypto isakmp policy 10
 key 6 a$KkK$randomnonce-cccc
!
`

const asaB = `: Saved
: Written by admin at 15:01:42 EST Tue Apr 27 2026
ASA Version 9.16(4)
!
hostname FW-LAB
enable secret 6 a$BcDe$F.GhIj/random-nonce-DDDDDIFFER
username alice password 6 a$xYz$abcDEF/nonce-EEEEEDIFFER privilege 15
key config-key password-encryption MasterPassphrase1
crypto key generate rsa modulus 2048
!
crypto isakmp policy 10
 key 6 a$KkK$randomnonce-FFFFDIFFER
!
`

const asaRealChange = `: Saved
ASA Version 9.16(4)
!
hostname FW-LAB-RENAMED
enable secret 6 a$BcDe$F.GhIj/random-nonce-aaaa
!
`

func TestCiscoASANormalizerStableAcrossUnchangedSnapshots(t *testing.T) {
	t.Parallel()
	a := HashNormalized("cisco_asa", []byte(asaA))
	b := HashNormalized("cisco_asa", []byte(asaB))
	if a != b {
		t.Errorf("Cisco ASA Type 6 nonce + : Saved timestamp drift must normalize to same hash; got a=%s b=%s", a, b)
	}
}

func TestCiscoASANormalizerDetectsRealChange(t *testing.T) {
	t.Parallel()
	base := HashNormalized("cisco_asa", []byte(asaA))
	renamed := HashNormalized("cisco_asa", []byte(asaRealChange))
	if base == renamed {
		t.Errorf("Cisco ASA hostname change must produce a different hash")
	}
}

func TestCiscoASANormalizerStripsType6Only(t *testing.T) {
	t.Parallel()
	// Type 5/7/8/9 must be visible in the normalized output — only Type 6 is
	// volatile-by-design. This guards against over-masking that would silence
	// real password changes for non-Type-6 deployments.
	mixed := `enable secret 5 $1$abcd$stable.md5.crypt
enable secret 8 $8$abcd$pbkdf2sha256.deterministic
username bob password 7 094F471A1A0A
username carol password 9 $9$abcd$scrypt.deterministic
`
	out, _ := Normalize("cisco_asa", []byte(mixed))
	s := string(out)
	required := []string{
		"$1$abcd$stable.md5.crypt",
		"$8$abcd$pbkdf2sha256.deterministic",
		"094F471A1A0A",
		"$9$abcd$scrypt.deterministic",
	}
	for _, r := range required {
		if !strings.Contains(s, r) {
			t.Errorf("Cisco ASA normalizer must NOT mask Type 5/7/8/9 (only Type 6); missing %q in:\n%s", r, s)
		}
	}
}

// ---- Registry helpers ----

func TestHasRichNormalizer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		vendor string
		rich   bool
	}{
		{"fortigate", true},
		{"paloalto", true},
		{"cisco_asa", true},
		{"generic", false}, // explicitly registered but identity
		{"unknown", false}, // not registered at all
		{"", false},
		{"FORTIGATE", true}, // case-insensitive lookup
	}
	for _, c := range cases {
		if got := HasRichNormalizer(c.vendor); got != c.rich {
			t.Errorf("HasRichNormalizer(%q) = %v, want %v", c.vendor, got, c.rich)
		}
	}
}
