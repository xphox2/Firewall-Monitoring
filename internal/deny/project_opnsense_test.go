package deny

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func filterlogMsg(body string) *models.SyslogMessage {
	return &models.SyslogMessage{DeviceID: 7, ProbeID: 3, Timestamp: time.Unix(1_700_000_000, 0), AppName: "filterlog", Message: body}
}

// AUDIT-280: OPNsense/pfSense filterlog block/reject verdicts must project into
// denied_events via the vendor-aware entry, mirroring the FortiGate path.
func TestProjectVendor_OPNsenseFilterlog(t *testing.T) {
	block := `filterlog[42]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.9,198.51.100.10,54321,443,0,S`

	ev, ok := ProjectVendor("opnsense", filterlogMsg(block), nil, PatternConfig{})
	if !ok {
		t.Fatal("opnsense filterlog block must project")
	}
	if ev.SrcAddr != "203.0.113.9" || ev.DstAddr != "198.51.100.10" {
		t.Errorf("addr = %s->%s", ev.SrcAddr, ev.DstAddr)
	}
	if ev.DstPort != 443 || ev.SrcPort != 54321 || ev.Protocol != 6 {
		t.Errorf("port/proto = %d<-%d /%d", ev.DstPort, ev.SrcPort, ev.Protocol)
	}
	if ev.Signal != models.DenySignalAction {
		t.Errorf("signal = %d, want action(%d)", ev.Signal, models.DenySignalAction)
	}
	if ev.DeviceID != 7 || ev.ProbeID != 3 {
		t.Errorf("attribution = dev %d probe %d", ev.DeviceID, ev.ProbeID)
	}

	// reject is also a denial.
	reject := `filterlog[42]: 5,,,1,igb0,match,reject,in,4,0x0,,64,1,0,none,6,tcp,60,203.0.113.9,198.51.100.10,3000,22`
	if _, ok := ProjectVendor("opnsense", filterlogMsg(reject), nil, PatternConfig{}); !ok {
		t.Error("reject verdict must project")
	}

	// pass must NOT project.
	pass := `filterlog[42]: 5,,,1,igb0,match,pass,in,4,0x0,,64,1,0,none,6,tcp,60,203.0.113.9,198.51.100.10,3000,80`
	if _, ok := ProjectVendor("opnsense", filterlogMsg(pass), nil, PatternConfig{}); ok {
		t.Error("pass verdict must not project")
	}

	// Scope-local (multicast dst) block must be dropped like the FortiGate path.
	mc := `filterlog[42]: 5,,,1,igb0,match,block,in,4,0x0,,64,1,0,none,17,udp,60,192.168.1.50,224.0.0.251,5353,5353`
	if _, ok := ProjectVendor("opnsense", filterlogMsg(mc), nil, PatternConfig{}); ok {
		t.Error("multicast dst block must be dropped")
	}

	// pfSense shares the filterlog projection.
	if _, ok := ProjectVendor("pfsense", filterlogMsg(block), nil, PatternConfig{}); !ok {
		t.Error("pfsense filterlog block must project too")
	}

	// FortiGate path is unaffected by the vendor dispatch.
	if _, ok := ProjectVendor("fortigate", denyMsg(sampleDeny), nil, PatternConfig{}); !ok {
		t.Error("fortigate deny must still project through ProjectVendor")
	}
	// A FortiGate-style deny line under an opnsense device must NOT project
	// (no filterlog CSV) — vendors don't cross-parse.
	if _, ok := ProjectVendor("opnsense", denyMsg(sampleDeny), nil, PatternConfig{}); ok {
		t.Error("fortigate deny line under opnsense vendor must not project")
	}
}
