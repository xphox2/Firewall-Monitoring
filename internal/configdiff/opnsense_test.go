package configdiff

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// Fixtures are hand-reduced from a real production config.xml, preserving the
// exact shapes that matter: uuid-keyed lists, a named map, a singleton with a
// nested value group, self-closing empty elements, and one truncated base64
// blob per secret class. The full 63 KB document is deliberately NOT committed —
// a reviewer cannot tell which line a test is about.

const opnsenseA = `<?xml version="1.0"?>
<opnsense>
  <revision>
    <username>root@192.168.5.15</username>
    <description>/firewall_rules_edit.php made changes</description>
    <time>1785449422.77</time>
  </revision>
  <system>
    <hostname>fw1</hostname>
    <webgui>
      <protocol>https</protocol>
    </webgui>
    <ssh/>
    <user uuid="2977294e-c9e4-494e-bc08-a70f4e64b6d2">
      <name>root</name>
      <uid>0</uid>
      <shell/>
      <password>$2y$10$abcdefghijklmnopqrstuv</password>
      <pwd_changed_at>1783897126.3262</pwd_changed_at>
    </user>
  </system>
  <interfaces>
    <wan>
      <if>dtsec1</if>
      <descr/>
      <ipaddr>dhcp</ipaddr>
      <blockpriv>1</blockpriv>
    </wan>
    <lan>
      <if>dtsec0</if>
      <ipaddr>192.168.5.1</ipaddr>
    </lan>
  </interfaces>
  <filter>
    <rule uuid="a58d71aa-ff3a-4846-85b6-ec6ba0116a2a">
      <type>pass</type>
      <interface>wan</interface>
      <source>
        <any/>
      </source>
      <destination>
        <port>443</port>
      </destination>
      <log/>
      <updated>
        <username>root@192.168.5.15</username>
        <time>1783781766.84</time>
      </updated>
    </rule>
  </filter>
  <OPNsense>
    <Swanctl version="1.0.0" persisted_at="1785449420.74">
      <Connections>
        <Connection uuid="ea805861-84eb-4769-a3c1-0331b4d9ea61">
          <proposals>aes256-sha256-modp2048</proposals>
          <aggressive>0</aggressive>
          <description>fwm-t12</description>
        </Connection>
      </Connections>
      <children>
        <child uuid="a1ddd125-1836-4139-9a8e-28c25e13f648">
          <connection>ea805861-84eb-4769-a3c1-0331b4d9ea61</connection>
          <local_ts>192.168.50.0/24</local_ts>
          <remote_ts>192.168.25.0/24</remote_ts>
          <description>fwm-t12</description>
        </child>
        <child uuid="dfe6c8af-f31e-475c-abe8-31d3b1e4efcd">
          <connection>ea805861-84eb-4769-a3c1-0331b4d9ea61</connection>
          <local_ts>192.168.50.0/24</local_ts>
          <remote_ts>192.168.13.0/24</remote_ts>
          <description>fwm-t12</description>
        </child>
      </children>
    </Swanctl>
    <IPsec>
      <preSharedKeys>
        <preSharedKey uuid="a252b745-4f1a-487c-93f5-aa9c07c696b3">
          <ident>opnsense</ident>
          <remote_ident>techlabs-fw-01</remote_ident>
          <Key>EucWSuperSecretPreSharedKeyMaterial</Key>
        </preSharedKey>
      </preSharedKeys>
    </IPsec>
  </OPNsense>
</opnsense>`

// opnsenseBSameContent is opnsenseA with EVERY Swanctl/IPsec uuid reassigned,
// persisted_at and the revision block rewritten, and the per-rule updated/time
// bumped — exactly what a production tunnel recreate produced, where 52 raw
// lines differed and nothing semantic changed.
var opnsenseBSameContent = strings.NewReplacer(
	"ea805861-84eb-4769-a3c1-0331b4d9ea61", "ad130d82-cae7-4534-8ca5-b132247146be",
	"a1ddd125-1836-4139-9a8e-28c25e13f648", "cfa1b8a3-4988-42a6-bbff-a67570405792",
	"dfe6c8af-f31e-475c-abe8-31d3b1e4efcd", "c845f2bb-b792-497c-afd3-d65ed5006bfd",
	"a252b745-4f1a-487c-93f5-aa9c07c696b3", "ef9f2c77-df87-453f-b5d9-62cbd7ddb30e",
	"1785449420.74", "1785447271.15",
	"1785449422.77", "1785447273.17",
	"1783781766.84", "1783781999.11",
).Replace(opnsenseA)

// Note what is deliberately NOT varied here: <updated><username>. Only the
// per-object <time> is volatile; the username and description are real
// attribution and must diff, which is what gives OPNsense per-object "who
// changed this" for free.

// TestOPNsenseNormalizerStableAcrossUUIDChurn is the headline regression: a
// device-side uuid reshuffle with identical semantics must not change the hash,
// or every provisioner apply writes a revision row and fires an alert.
func TestOPNsenseNormalizerStableAcrossUUIDChurn(t *testing.T) {
	t.Parallel()
	if a, b := HashNormalized("opnsense", []byte(opnsenseA)), HashNormalized("opnsense", []byte(opnsenseBSameContent)); a != b {
		t.Errorf("uuid churn changed the hash: %s vs %s", a, b)
	}
}

// TestOPNsenseObjectDiffIgnoresUUIDChurn pins the object layer for the same pair.
func TestOPNsenseObjectDiffIgnoresUUIDChurn(t *testing.T) {
	t.Parallel()
	changes, ok := DiffObjects("opnsense", []byte(opnsenseA), []byte(opnsenseBSameContent))
	if !ok {
		t.Fatal("DiffObjects reported no object parser for opnsense")
	}
	if len(changes) != 0 {
		for _, c := range changes {
			t.Logf("unexpected: %s %s %v", c.Op, c.Path, c.Attrs)
		}
		t.Errorf("expected 0 object changes across pure uuid churn, got %d", len(changes))
	}
}

// TestOPNsenseParseInputKeepsOriginalUUIDs pins the split that keeps positional
// hash tokens away from object identity.
func TestOPNsenseParseInputKeepsOriginalUUIDs(t *testing.T) {
	t.Parallel()
	in := parseInputFor("opnsense", []byte(opnsenseA))
	if !strings.Contains(string(in), "ea805861-84eb-4769-a3c1-0331b4d9ea61") {
		t.Error("ParseInput stripped the original uuids the parser needs for identity")
	}
	norm, _ := Normalize("opnsense", []byte(opnsenseA))
	if strings.Contains(string(norm), "ea805861-84eb-4769-a3c1-0331b4d9ea61") {
		t.Error("Normalize left a raw uuid in the hash input")
	}
}

// TestOPNsenseNormalizedOutputIsWellFormedXML guards the marker decision. The
// ATTRIBUTE case is the one that matters: an element-style token inside
// persisted_at="" is a fatal parse error at document line 4, which would make the
// object diff report the whole configuration as removed.
func TestOPNsenseNormalizedOutputIsWellFormedXML(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"A": opnsenseA, "B": opnsenseBSameContent} {
		norm, _ := Normalize("opnsense", []byte(body))
		dec := xml.NewDecoder(strings.NewReader(string(norm)))
		for {
			_, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("fixture %s: normalized output is not well-formed XML: %v", name, err)
			}
		}
		if strings.Contains(string(norm), `persisted_at="<`) {
			t.Errorf("fixture %s: bracketed token inside an attribute value", name)
		}
	}
}

// TestOPNsenseMaskPreservesLineCount pins the LineMasker contract.
// prepareDiffInput silently degrades to NO masking when it is violated, so only
// a test catches it.
func TestOPNsenseMaskPreservesLineCount(t *testing.T) {
	t.Parallel()
	n := opnsenseNormalizer{vendor: "opnsense"}
	for name, body := range map[string]string{"A": opnsenseA, "B": opnsenseBSameContent} {
		masked := n.MaskVolatileLines([]byte(body))
		if got, want := strings.Count(string(masked), "\n"), strings.Count(body, "\n"); got != want {
			t.Errorf("fixture %s: mask changed line count: %d != %d", name, got, want)
		}
	}
}

// TestOPNsenseSecretsNeverSurvive covers both the hash input and, critically, what
// the diff DISPLAYS. Secrets here are stable plaintext, so they land on `equal`
// rows — which carry raw text — and would otherwise be rendered on every open.
func TestOPNsenseSecretsNeverSurvive(t *testing.T) {
	t.Parallel()
	const psk = "EucWSuperSecretPreSharedKeyMaterial"
	const pw = "$2y$10$abcdefghijklmnopqrstuv"

	norm, _ := Normalize("opnsense", []byte(opnsenseA))
	for _, s := range []string{psk, pw} {
		if strings.Contains(string(norm), s) {
			t.Errorf("secret %q survived Normalize", s)
		}
	}

	// Unchanged secrets: every row is `equal`, the case a normalizer alone cannot fix.
	ld := DiffLines("opnsense", []byte(opnsenseA), []byte(opnsenseBSameContent))
	for _, r := range ld.Rows {
		for _, s := range []string{psk, pw} {
			if strings.Contains(r.Text, s) {
				t.Errorf("secret %q rendered in the line diff (op=%s): %s", s, r.Op, r.Text)
			}
		}
	}
}

// TestOPNsenseSecretRotationIsVisible pins the digest-not-flat-mask decision: a
// rotation must still produce a change, and must still not render the cleartext.
func TestOPNsenseSecretRotationIsVisible(t *testing.T) {
	t.Parallel()
	rotated := strings.Replace(opnsenseA, "EucWSuperSecretPreSharedKeyMaterial", "RotatedBrandNewPreSharedKeyValue", 1)
	if HashNormalized("opnsense", []byte(opnsenseA)) == HashNormalized("opnsense", []byte(rotated)) {
		t.Error("a PSK rotation left the hash unchanged — no alert, no history row")
	}
	ld := DiffLines("opnsense", []byte(opnsenseA), []byte(rotated))
	for _, r := range ld.Rows {
		if strings.Contains(r.Text, "RotatedBrandNewPreSharedKeyValue") {
			t.Errorf("rotated secret rendered in the line diff: %s", r.Text)
		}
	}
}

// TestOPNsenseParsesShapes covers the keyed list, the named map, the singleton
// with a nested value group, and dotted flattening.
func TestOPNsenseParsesShapes(t *testing.T) {
	t.Parallel()
	objs, ok := ParseObjects("opnsense", parseInputFor("opnsense", []byte(opnsenseA)))
	if !ok {
		t.Fatal("no object parser registered for opnsense")
	}
	byPath := map[string]ConfigObject{}
	for _, o := range objs {
		byPath[o.Path] = o
	}

	for _, want := range []string{
		"filter.rule/a58d71aa-ff3a-4846-85b6-ec6ba0116a2a", // keyed list
		"interfaces/wan", // named map
		"interfaces/lan",
		"system",           // top-level singleton
		"system.user/root", // key table by <name>, not uuid
		"OPNsense.Swanctl.children.child/fwm-t12|192.168.50.0/24|192.168.25.0/24", // composite key
	} {
		if _, ok := byPath[want]; !ok {
			t.Errorf("missing object %q", want)
		}
	}

	if got := byPath["system"].Attrs["webgui.protocol"]; got != "https" {
		t.Errorf("nested value group not flattened: webgui.protocol = %q", got)
	}
	if got := byPath["filter.rule/a58d71aa-ff3a-4846-85b6-ec6ba0116a2a"].Attrs["destination.port"]; got != "443" {
		t.Errorf("dotted flattening failed: destination.port = %q", got)
	}
	if got := byPath["filter.rule/a58d71aa-ff3a-4846-85b6-ec6ba0116a2a"].Attrs["source.any"]; got != attrPresentValue {
		t.Errorf("empty element lost its presence sentinel: source.any = %q", got)
	}
	for _, o := range objs {
		if _, bad := o.Attrs["uuid"]; bad {
			t.Errorf("%s exposes its surrogate uuid as an attribute", o.Path)
		}
	}
}

// TestOPNsenseNestedKeyedListNotSwallowed pins that a singleton or named-map
// object never flattens a nested keyed list into itself — which would collapse N
// rules into one object with colliding keys and hide real changes behind
// last-wins.
func TestOPNsenseNestedKeyedListNotSwallowed(t *testing.T) {
	t.Parallel()
	objs, _ := ParseObjects("opnsense", parseInputFor("opnsense", []byte(opnsenseA)))
	children := 0
	for _, o := range objs {
		if o.Kind == "OPNsense.Swanctl.children.child" {
			children++
		}
		for k := range o.Attrs {
			if strings.Contains(k, "children.child.") {
				t.Errorf("%s swallowed a nested keyed list: attr %q", o.Path, k)
			}
		}
	}
	if children != 2 {
		t.Errorf("expected 2 child objects, got %d", children)
	}
}

// TestOPNsenseCrossRefsResolveToPaths pins that a uuid cross-reference becomes a
// stable Path, so a recreate does not churn every referencing object.
func TestOPNsenseCrossRefsResolveToPaths(t *testing.T) {
	t.Parallel()
	objs, _ := ParseObjects("opnsense", parseInputFor("opnsense", []byte(opnsenseA)))
	found := false
	for _, o := range objs {
		if v, ok := o.Attrs["connection"]; ok {
			found = true
			if !strings.HasPrefix(v, "ref:") {
				t.Errorf("cross-reference left unresolved: connection = %q", v)
			}
		}
	}
	if !found {
		t.Error("no cross-reference attribute found — fixture or parser regressed")
	}
}

// TestClassifyOPNsenseWideningVsNarrowing is the direction test the presence
// sentinel exists to make possible: gaining <any/> is an exposure finding,
// losing it is a security improvement and must not be.
func TestClassifyOPNsenseWideningVsNarrowing(t *testing.T) {
	t.Parallel()
	widened := ObjectChange{
		Vendor: "opnsense", Kind: "filter.rule", Path: "filter.rule/x", Op: "modified",
		Attrs: []AttrDelta{{Key: "destination.any", New: attrPresentValue}},
	}
	if got := ClassifyChange(widened); got.Severity != SeverityHigh {
		t.Errorf("single-sided widening to any should be high, got %q", got.Severity)
	}

	narrowed := ObjectChange{
		Vendor: "opnsense", Kind: "filter.rule", Path: "filter.rule/x", Op: "modified",
		Attrs: []AttrDelta{{Key: "destination.any", Old: attrPresentValue}},
	}
	if got := ClassifyChange(narrowed); got.Severity == SeverityHigh {
		t.Error("narrowing away from any must not raise an exposure finding")
	}
}

// TestClassifyOPNsenseRoutineChangeIsInfo is the alert-storm regression: before
// this work every OPNsense config change escalated to critical.
func TestClassifyOPNsenseRoutineChangeIsInfo(t *testing.T) {
	t.Parallel()
	c := ObjectChange{
		Vendor: "opnsense", Kind: "system", Path: "system", Op: "modified",
		Attrs: []AttrDelta{{Key: "hostname", Old: "fw1", New: "fw2"}},
	}
	if got := ClassifyChange(c); got.Severity != SeverityInfo {
		t.Errorf("a routine hostname change should be info, got %q", got.Severity)
	}
}

// TestClassifyOPNsenseSecurityRules covers the high-severity rules an operator
// actually needs paged for.
func TestClassifyOPNsenseSecurityRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		c    ObjectChange
		want string
	}{
		{"new user", ObjectChange{Vendor: "opnsense", Kind: "system.user", Name: "eve", Path: "system.user/eve", Op: "added"}, SeverityHigh},
		{"cleartext gui", ObjectChange{Vendor: "opnsense", Kind: "system", Path: "system", Op: "modified",
			Attrs: []AttrDelta{{Key: "webgui.protocol", Old: "https", New: "http"}}}, SeverityHigh},
		{"weak proposal", ObjectChange{Vendor: "opnsense", Kind: "OPNsense.Swanctl.Connections.Connection", Path: "c", Op: "modified",
			Attrs: []AttrDelta{{Key: "proposals", Old: "aes256-sha256-modp2048", New: "3des-md5-modp1024"}}}, SeverityHigh},
		{"aggressive mode", ObjectChange{Vendor: "opnsense", Kind: "OPNsense.Swanctl.Connections.Connection", Path: "c", Op: "modified",
			Attrs: []AttrDelta{{Key: "aggressive", Old: "0", New: "1"}}}, SeverityHigh},
		{"logging off", ObjectChange{Vendor: "opnsense", Kind: "filter.rule", Path: "r", Op: "modified",
			Attrs: []AttrDelta{{Key: "log", Old: attrPresentValue}}}, SeverityMedium},
		{"blockpriv cleared", ObjectChange{Vendor: "opnsense", Kind: "interfaces", Name: "wan", Path: "interfaces/wan", Op: "modified",
			Attrs: []AttrDelta{{Key: "blockpriv", Old: "1"}}}, SeverityMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyChange(tc.c); got.Severity != tc.want {
				t.Errorf("severity = %q, want %q (%s)", got.Severity, tc.want, got.Summary)
			}
		})
	}
}

// TestClassifyChangeVendorDispatchPreservesFortiGate pins that splitting
// ClassifyChange into per-vendor rule sets was behaviour-neutral, including for
// callers that leave Vendor unset.
func TestClassifyChangeVendorDispatchPreservesFortiGate(t *testing.T) {
	t.Parallel()
	c := ObjectChange{
		Kind: "firewall.policy", Path: "firewall.policy/5", Op: "modified",
		Attrs: []AttrDelta{{Key: "srcaddr", Old: `"LAN"`, New: `"all"`}},
	}
	unset := ClassifyChange(c)
	c.Vendor = "fortigate"
	stamped := ClassifyChange(c)
	if unset.Severity != SeverityHigh || stamped.Severity != SeverityHigh {
		t.Errorf("FortiGate exposure rule regressed: unset=%q stamped=%q", unset.Severity, stamped.Severity)
	}
	if unset.Summary != stamped.Summary {
		t.Errorf("dispatch changed the summary: %q vs %q", unset.Summary, stamped.Summary)
	}
}

// TestOPNsenseParserIsTolerant pins that a truncated capture never makes
// ParseObjects error: returning one would drop the vendor back to a line-only
// diff with no severity, which is the failure this parser removes.
func TestOPNsenseParserIsTolerant(t *testing.T) {
	t.Parallel()
	truncated := opnsenseA[:len(opnsenseA)/2]
	if _, err := (opnsenseNormalizer{vendor: "opnsense"}).ParseObjects([]byte(truncated)); err != nil {
		t.Errorf("ParseObjects errored on a truncated document: %v", err)
	}
	for _, body := range []string{"", "not xml at all", "<opnsense>"} {
		if _, err := (opnsenseNormalizer{vendor: "opnsense"}).ParseObjects([]byte(body)); err != nil {
			t.Errorf("ParseObjects errored on %q: %v", body, err)
		}
	}
}
