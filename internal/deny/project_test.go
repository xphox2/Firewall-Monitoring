package deny

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/threatintel"
)

func denyMsg(body string) *models.SyslogMessage {
	return &models.SyslogMessage{DeviceID: 1, ProbeID: 2, Timestamp: time.Unix(1_700_000_000, 0), Message: body}
}

const sampleDeny = `subtype="forward" srcip=203.0.113.9 srcport=44000 srcintf="wan1" srcintfrole="wan" ` +
	`dstip=66.179.9.150 dstport=3389 dstintf="root" srccountry="Mauritania" proto=6 action="deny" ` +
	`policyid=20 policytype="policy" service="RDP" policyname="IP_BLOCK-2"`

func TestProject_ActionDeny(t *testing.T) {
	ev, ok := Project(denyMsg(sampleDeny), nil, PatternConfig{})
	if !ok {
		t.Fatal("expected a projected deny event")
	}
	if ev.SrcAddr != "203.0.113.9" || ev.DstAddr != "66.179.9.150" || ev.DstPort != 3389 {
		t.Errorf("addr/port = %s->%s:%d", ev.SrcAddr, ev.DstAddr, ev.DstPort)
	}
	if ev.SrcIntfRole != models.IntfRoleWAN || ev.Subtype != models.DenySubtypeForward {
		t.Errorf("role/subtype = %d/%d", ev.SrcIntfRole, ev.Subtype)
	}
	if ev.Signal != models.DenySignalAction || ev.Protocol != 6 || ev.PolicyID != 20 {
		t.Errorf("signal/proto/policy = %d/%d/%d", ev.Signal, ev.Protocol, ev.PolicyID)
	}
}

func TestProject_NonDenySkipped(t *testing.T) {
	if _, ok := Project(denyMsg(`action="accept" srcip=1.2.3.4 dstip=5.6.7.8`), nil, PatternConfig{}); ok {
		t.Error("accept must not project")
	}
	// action="start" without a matching block-policy pattern must not project.
	start := `action="start" srcip=203.0.113.9 dstip=66.179.9.150 policyname="IP_BLOCK-2"`
	if _, ok := Project(denyMsg(start), nil, PatternConfig{}); ok {
		t.Error("action=start must not project when pattern is empty")
	}
}

func TestProject_BlockPolicyPattern(t *testing.T) {
	start := `subtype="forward" srcip=203.0.113.9 srcintfrole="wan" dstip=66.179.9.150 dstport=3389 ` +
		`proto=6 action="start" policyname="IP_BLOCK-2"`
	ev, ok := Project(denyMsg(start), nil, PatternConfig{Pattern: "IP_BLOCK*"})
	if !ok {
		t.Fatal("action=start on a matching block policy must project")
	}
	if ev.Signal != models.DenySignalPattern {
		t.Errorf("signal = %d, want pattern(%d)", ev.Signal, models.DenySignalPattern)
	}
	// A non-matching policy name must not project.
	other := `action="start" srcip=203.0.113.9 dstip=66.179.9.150 policyname="ALLOW-WEB"`
	if _, ok := Project(denyMsg(other), nil, PatternConfig{Pattern: "IP_BLOCK*"}); ok {
		t.Error("non-matching policy must not project")
	}
}

func TestProject_ScopeLocalDropped(t *testing.T) {
	// Multicast dst — pure noise, must be dropped at projection.
	mc := `srcip=192.168.25.50 dstip=224.0.0.251 dstport=5353 proto=17 action="deny"`
	if _, ok := Project(denyMsg(mc), nil, PatternConfig{}); ok {
		t.Error("multicast dst deny must be dropped")
	}
}

func TestProject_ThreatFlagBitsSrcDst(t *testing.T) {
	rows := []models.ThreatIntel{{CIDR: "203.0.113.9/32", Category: "scanner", Severity: "warning", Source: "test"}}
	var h threatintel.Holder
	h.Store(threatintel.New(rows, time.Now()))
	ev, ok := Project(denyMsg(sampleDeny), &h, PatternConfig{})
	if !ok {
		t.Fatal("expected projection")
	}
	if ev.ThreatFlag&1 == 0 {
		t.Errorf("src threat bit not set: flag=%d", ev.ThreatFlag)
	}
	// dst not on the feed → bit 1 clear; ASN bits never set for denies.
	if ev.ThreatFlag&2 != 0 || ev.ThreatFlag&(4|8) != 0 {
		t.Errorf("unexpected dst/ASN bits: flag=%d", ev.ThreatFlag)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"IP_BLOCK*", "IP_BLOCK-2", true},
		{"ip_block*", "IP_BLOCK-1", true}, // case-insensitive via caller
		{"*BLOCK*", "IP_BLOCK-2", true},
		{"IP_BLOCK-2", "IP_BLOCK-2", true},
		{"IP_BLOCK*", "ALLOW-WEB", false},
		{"", "anything", false},
	}
	for _, c := range cases {
		got := PatternConfig{Pattern: c.pat}.matches(c.s)
		if got != c.want {
			t.Errorf("matches(%q,%q)=%v want %v", c.pat, c.s, got, c.want)
		}
	}
}
