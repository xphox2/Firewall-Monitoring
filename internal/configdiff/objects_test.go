package configdiff

import (
	"testing"
)

// findChange returns the ObjectChange with the given path, or nil.
func findChange(changes []ObjectChange, path string) *ObjectChange {
	for i := range changes {
		if changes[i].Path == path {
			return &changes[i]
		}
	}
	return nil
}

// findObject returns the ConfigObject with the given path, or nil.
func findObject(objs []ConfigObject, path string) *ConfigObject {
	for i := range objs {
		if objs[i].Path == path {
			return &objs[i]
		}
	}
	return nil
}

func TestParseObjectsFortiGateBasic(t *testing.T) {
	t.Parallel()
	objs, ok := ParseObjects("fortigate", []byte(fortigateUnchangedA))
	if !ok {
		t.Fatal("fortigate must expose an ObjectParser")
	}

	// Singleton section -> Name empty, attrs from direct sets.
	if g := findObject(objs, "system.global"); g == nil {
		t.Fatal("expected system.global singleton object")
	} else {
		if g.Name != "" {
			t.Errorf("singleton Name should be empty, got %q", g.Name)
		}
		if g.Attrs["hostname"] != `"FW-HOME"` {
			t.Errorf("system.global hostname = %q, want \"FW-HOME\"", g.Attrs["hostname"])
		}
	}

	// Table entries -> one object per edit, keyed by edit key.
	admin := findObject(objs, "system.admin/admin")
	if admin == nil {
		t.Fatal("expected system.admin/admin object")
	}
	if admin.Kind != "system.admin" || admin.Name != "admin" {
		t.Errorf("admin object Kind/Name = %q/%q", admin.Kind, admin.Name)
	}
	if admin.Attrs["accprofile"] != `"super_admin"` {
		t.Errorf("admin accprofile = %q", admin.Attrs["accprofile"])
	}

	if findObject(objs, "firewall.policy/1") == nil {
		t.Error("expected firewall.policy/1 object")
	}

	// When parsing the NORMALIZED form (as DiffObjects does), ENC values are
	// already collapsed to a stable placeholder so secret rotation / IV drift
	// never diffs as a change.
	norm, _ := Normalize("fortigate", []byte(fortigateUnchangedA))
	normObjs, _ := ParseObjects("fortigate", norm)
	if a := findObject(normObjs, "system.admin/admin"); a == nil {
		t.Fatal("expected system.admin/admin in normalized parse")
	} else if got := a.Attrs["password"]; got != "ENC <volatile-enc>" {
		t.Errorf("normalized admin password should be ENC placeholder, got %q", got)
	}
}

func TestParseObjectsNestedConfigFlattens(t *testing.T) {
	t.Parallel()
	cfg := `config system interface
    edit "wan1"
        set ip 1.2.3.4 255.255.255.0
        config ipv6
            set ip6-address 2001:db8::1/64
        end
    next
end
config router bgp
    set as 65000
    config neighbor
        edit "10.0.0.1"
            set remote-as 65001
        next
    end
end
`
	objs, ok := ParseObjects("fortigate", []byte(cfg))
	if !ok {
		t.Fatal("parser unavailable")
	}

	// Nested config inside an edit flattens with a dotted prefix.
	wan := findObject(objs, "system.interface/wan1")
	if wan == nil {
		t.Fatal("expected system.interface/wan1")
	}
	if wan.Attrs["ip"] != "1.2.3.4 255.255.255.0" {
		t.Errorf("wan1 ip = %q", wan.Attrs["ip"])
	}
	if wan.Attrs["ipv6.ip6-address"] != "2001:db8::1/64" {
		t.Errorf("wan1 nested ipv6.ip6-address = %q (want flattened key)", wan.Attrs["ipv6.ip6-address"])
	}

	// BGP: direct set on singleton + nested table entry as its own object.
	if bgp := findObject(objs, "router.bgp"); bgp == nil || bgp.Attrs["as"] != "65000" {
		t.Errorf("expected router.bgp singleton with as=65000, got %+v", bgp)
	}
	nb := findObject(objs, "router.bgp.neighbor/10.0.0.1")
	if nb == nil {
		t.Fatal("expected router.bgp.neighbor/10.0.0.1 object")
	}
	if nb.Attrs["remote-as"] != "65001" {
		t.Errorf("bgp neighbor remote-as = %q", nb.Attrs["remote-as"])
	}
}

func TestParseObjectsUnknownVendorNoParser(t *testing.T) {
	t.Parallel()
	if _, ok := ParseObjects("generic", []byte("anything")); ok {
		t.Error("generic vendor must not expose an ObjectParser")
	}
	if HasObjectParser("paloalto") {
		t.Error("paloalto has no ObjectParser yet (FortiGate-only in v1)")
	}
	if !HasObjectParser("fortigate") {
		t.Error("fortigate must expose an ObjectParser")
	}
}

func TestDiffObjectsPolicyAdded(t *testing.T) {
	t.Parallel()
	changes, ok := DiffObjects("fortigate", []byte(fortigateUnchangedA), []byte(fortigatePolicyAdded))
	if !ok {
		t.Fatal("DiffObjects unavailable for fortigate")
	}
	c := findChange(changes, "firewall.policy/2")
	if c == nil {
		t.Fatalf("expected firewall.policy/2 to be added; got changes: %+v", changes)
	}
	if c.Op != "added" {
		t.Errorf("policy/2 Op = %q, want added", c.Op)
	}
	// No phantom changes from drifting ENC/last-login between the two snapshots.
	if other := findChange(changes, "system.admin/admin"); other != nil {
		t.Errorf("admin should not show as changed (only ENC/last-login drift): %+v", other)
	}
}

func TestDiffObjectsModifiedAttr(t *testing.T) {
	t.Parallel()
	base := `config firewall policy
    edit 1
        set name "P1"
        set dstaddr "LAN"
        set action accept
    next
end
`
	changed := `config firewall policy
    edit 1
        set name "P1"
        set dstaddr "all"
        set action accept
    next
end
`
	changes, ok := DiffObjects("fortigate", []byte(base), []byte(changed))
	if !ok {
		t.Fatal("unavailable")
	}
	c := findChange(changes, "firewall.policy/1")
	if c == nil || c.Op != "modified" {
		t.Fatalf("expected firewall.policy/1 modified, got %+v", c)
	}
	if len(c.Attrs) != 1 || c.Attrs[0].Key != "dstaddr" {
		t.Fatalf("expected single dstaddr delta, got %+v", c.Attrs)
	}
	if c.Attrs[0].Old != `"LAN"` || c.Attrs[0].New != `"all"` {
		t.Errorf("dstaddr delta = %q -> %q", c.Attrs[0].Old, c.Attrs[0].New)
	}
	// Opening dst to all must classify as high-severity exposure.
	if c.Risk.Severity != SeverityHigh || c.Risk.Category != "exposure" {
		t.Errorf("expected high/exposure risk, got %q/%q (%s)", c.Risk.Severity, c.Risk.Category, c.Risk.Summary)
	}
}

func TestClassifyChangeRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		change  ObjectChange
		wantSev string
		wantCat string
	}{
		{
			name:    "policy opened to ANY service",
			change:  ObjectChange{Path: "firewall.policy/5", Kind: "firewall.policy", Op: "modified", Attrs: []AttrDelta{{Key: "service", Old: `"HTTPS"`, New: `"ALL"`}}},
			wantSev: SeverityHigh, wantCat: "exposure",
		},
		{
			name:    "policy disabled",
			change:  ObjectChange{Path: "firewall.policy/5", Kind: "firewall.policy", Op: "modified", Attrs: []AttrDelta{{Key: "status", Old: "enable", New: "disable"}}},
			wantSev: SeverityMedium, wantCat: "policy",
		},
		{
			name:    "logging disabled",
			change:  ObjectChange{Path: "firewall.policy/5", Kind: "firewall.policy", Op: "modified", Attrs: []AttrDelta{{Key: "logtraffic", Old: "all", New: "disable"}}},
			wantSev: SeverityMedium, wantCat: "logging",
		},
		{
			name:    "new admin",
			change:  ObjectChange{Path: "system.admin/eve", Kind: "system.admin", Name: "eve", Op: "added", Attrs: []AttrDelta{{Key: "accprofile", New: `"super_admin"`}}},
			wantSev: SeverityHigh, wantCat: "admin",
		},
		{
			name:    "trusthost widened",
			change:  ObjectChange{Path: "system.admin/admin", Kind: "system.admin", Name: "admin", Op: "modified", Attrs: []AttrDelta{{Key: "trusthost1", Old: "10.0.0.0 255.0.0.0", New: "0.0.0.0 0.0.0.0"}}},
			wantSev: SeverityHigh, wantCat: "admin",
		},
		{
			name:    "weak ipsec proposal",
			change:  ObjectChange{Path: "vpn.ipsec.phase1-interface/t1", Kind: "vpn.ipsec.phase1-interface", Op: "modified", Attrs: []AttrDelta{{Key: "proposal", Old: "aes256-sha256", New: "3des-md5"}}},
			wantSev: SeverityHigh, wantCat: "crypto",
		},
		{
			name:    "weak dh group",
			change:  ObjectChange{Path: "vpn.ipsec.phase1-interface/t1", Kind: "vpn.ipsec.phase1-interface", Op: "modified", Attrs: []AttrDelta{{Key: "dhgrp", Old: "14", New: "14 5"}}},
			wantSev: SeverityHigh, wantCat: "crypto",
		},
		{
			name:    "cleartext mgmt access",
			change:  ObjectChange{Path: "system.interface/wan1", Kind: "system.interface", Op: "modified", Attrs: []AttrDelta{{Key: "allowaccess", Old: "ping", New: "ping https telnet"}}},
			wantSev: SeverityHigh, wantCat: "mgmt-access",
		},
		{
			name:    "encrypted mgmt access",
			change:  ObjectChange{Path: "system.interface/wan1", Kind: "system.interface", Op: "modified", Attrs: []AttrDelta{{Key: "allowaccess", Old: "ping", New: "ping https ssh"}}},
			wantSev: SeverityMedium, wantCat: "mgmt-access",
		},
		{
			name:    "benign change",
			change:  ObjectChange{Path: "system.global", Kind: "system.global", Op: "modified", Attrs: []AttrDelta{{Key: "hostname", Old: `"A"`, New: `"B"`}}},
			wantSev: SeverityInfo, wantCat: "config",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ClassifyChange(c.change)
			if r.Severity != c.wantSev || r.Category != c.wantCat {
				t.Errorf("got %q/%q, want %q/%q (summary: %s)", r.Severity, r.Category, c.wantSev, c.wantCat, r.Summary)
			}
			if r.Summary == "" {
				t.Error("summary must not be empty")
			}
		})
	}
}

func TestClassifyChangesOverall(t *testing.T) {
	t.Parallel()
	changes := []ObjectChange{
		classified(ObjectChange{Path: "system.global", Kind: "system.global", Op: "modified", Attrs: []AttrDelta{{Key: "hostname", Old: `"A"`, New: `"B"`}}}),
		classified(ObjectChange{Path: "firewall.policy/5", Kind: "firewall.policy", Op: "modified", Attrs: []AttrDelta{{Key: "srcaddr", Old: `"LAN"`, New: `"all"`}}}),
	}
	overall, per := ClassifyChanges(changes)
	if len(per) != 2 {
		t.Fatalf("expected 2 per-change risks, got %d", len(per))
	}
	if overall.Severity != SeverityHigh {
		t.Errorf("overall severity = %q, want high", overall.Severity)
	}
	if overall.Summary == "" || overall.Summary == "no security-relevant changes" {
		t.Errorf("overall summary should describe the high-severity change, got %q", overall.Summary)
	}
}

func TestParseFortiAuditEvent(t *testing.T) {
	t.Parallel()
	// Realistic FortiOS config-change event log line.
	msg := `date=2026-06-20 time=10:11:12 logid="0100044546" type="event" subtype="system" ` +
		`level="information" user="netadmin" ui="GUI(10.20.30.40)" action="Edit" ` +
		`cfgtid=123 cfgpath="firewall.policy" cfgobj="12" cfgattr="dstaddr[LAN->all]" ` +
		`msg="Edit firewall.policy 12"`
	ev := ParseFortiAuditEvent(msg)
	if !ev.IsConfigChange {
		t.Fatal("expected IsConfigChange=true")
	}
	if ev.User != "netadmin" {
		t.Errorf("user = %q, want netadmin", ev.User)
	}
	if ev.Method != "GUI" {
		t.Errorf("method = %q, want GUI", ev.Method)
	}
	if ev.Source != "10.20.30.40" {
		t.Errorf("source = %q, want 10.20.30.40", ev.Source)
	}
	if ev.CfgPath != "firewall.policy" {
		t.Errorf("cfgpath = %q", ev.CfgPath)
	}
}

func TestParseFortiAuditEventSSHAndSrcip(t *testing.T) {
	t.Parallel()
	msg := `logid="0100044547" type="event" subtype="system" user="root" ui="ssh(192.168.1.9)" ` +
		`srcip=192.168.1.9 cfgpath="system.interface" cfgobj="wan1"`
	ev := ParseFortiAuditEvent(msg)
	if ev.Method != "CLI(ssh)" {
		t.Errorf("method = %q, want CLI(ssh)", ev.Method)
	}
	if ev.Source != "192.168.1.9" {
		t.Errorf("source = %q", ev.Source)
	}
}

func TestParseFortiAuditEventNonConfig(t *testing.T) {
	t.Parallel()
	// A traffic log is not a config-change event.
	msg := `type="traffic" subtype="forward" srcip=10.0.0.5 dstip=8.8.8.8 action="accept"`
	ev := ParseFortiAuditEvent(msg)
	if ev.IsConfigChange {
		t.Errorf("traffic log must not be classified as a config change: %+v", ev)
	}
}
