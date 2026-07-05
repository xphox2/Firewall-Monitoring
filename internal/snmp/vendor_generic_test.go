package snmp

import (
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// The generic profile is standards-only: every OID it asks a device for must
// live under the standard mgmt.mib-2 subtree (1.3.6.1.2.1) — no enterprise
// OIDs (1.3.6.1.4.1.*), which is the whole point of the profile.
func TestGeneric_StandardsOnlyOIDs(t *testing.T) {
	p := GetVendorProfile("generic")
	if p == nil {
		t.Fatal("generic profile not registered")
	}

	var oids []string
	oids = append(oids, p.SystemOIDs()...)
	for _, b := range []string{p.VPNBaseOID(), p.HWSensorBaseOID(), p.ProcessorBaseOID(), p.HABaseOID()} {
		if b != "" {
			oids = append(oids, b)
		}
	}
	for _, oid := range oids {
		if !strings.HasPrefix(oid, ".1.3.6.1.2.1.") {
			t.Errorf("generic profile OID %s is not under mib-2 (.1.3.6.1.2.1) — enterprise OIDs are forbidden in the generic profile", oid)
		}
	}
}

func TestGeneric_ParseSystemStatus(t *testing.T) {
	p := GetVendorProfile("generic")
	if p == nil {
		t.Fatal("generic profile not registered")
	}

	pdus := []gosnmp.SnmpPDU{
		{Name: genOIDSysName, Type: gosnmp.OctetString, Value: "edge-fw-01"},
		{Name: genOIDSysDescr, Type: gosnmp.OctetString, Value: "Acme Router OS 4.2 build 1234"},
		{Name: genOIDSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(8640000)}, // 86400 s
		{Name: genOIDHrMemorySize, Type: gosnmp.Integer, Value: 4194304},        // KB → 4096 MB
	}

	status := p.ParseSystemStatus(pdus)
	if status.Hostname != "edge-fw-01" {
		t.Errorf("Hostname = %q, want edge-fw-01", status.Hostname)
	}
	if status.Version != "Acme Router OS 4.2 build 1234" {
		t.Errorf("Version = %q", status.Version)
	}
	if status.Uptime != 86400 {
		t.Errorf("Uptime = %d, want 86400", status.Uptime)
	}
	if status.MemoryTotal != 4096 {
		t.Errorf("MemoryTotal = %d MB, want 4096", status.MemoryTotal)
	}
	// No standard scalar exists for these — must stay zero, not garbage.
	if status.CPUUsage != 0 || status.MemoryUsage != 0 || status.SessionCount != 0 {
		t.Errorf("CPUUsage/MemoryUsage/SessionCount = %v/%v/%v, want all zero (unsupported)",
			status.CPUUsage, status.MemoryUsage, status.SessionCount)
	}
}

func TestGeneric_ParseSystemStatus_SkipsSNMPExceptions(t *testing.T) {
	p := GetVendorProfile("generic")
	pdus := []gosnmp.SnmpPDU{
		{Name: genOIDSysName, Type: gosnmp.OctetString, Value: "host"},
		{Name: genOIDHrMemorySize, Type: gosnmp.NoSuchObject, Value: nil}, // agent without HOST-RESOURCES
	}
	status := p.ParseSystemStatus(pdus)
	if status.MemoryTotal != 0 {
		t.Errorf("MemoryTotal = %d, want 0 when hrMemorySize is NoSuchObject", status.MemoryTotal)
	}
	if status.Hostname != "host" {
		t.Errorf("Hostname = %q, want host", status.Hostname)
	}
}

func TestGeneric_ParseProcessors_HrProcessorLoad(t *testing.T) {
	p := GetVendorProfile("generic")
	pdus := []gosnmp.SnmpPDU{
		{Name: genOIDProcessorLoad + ".196608", Type: gosnmp.Integer, Value: 12},
		{Name: genOIDProcessorLoad + ".196609", Type: gosnmp.Integer, Value: 34},
		{Name: genBaseOIDProcessor + ".1.196608", Type: gosnmp.Integer, Value: 196608}, // hrProcessorFrwID col — ignored
	}
	procs := p.ParseProcessors(pdus)
	if len(procs) != 2 {
		t.Fatalf("got %d processors, want 2", len(procs))
	}
	byIdx := map[int]float64{}
	for _, pr := range procs {
		byIdx[pr.Index] = pr.Usage
	}
	if byIdx[196608] != 12 || byIdx[196609] != 34 {
		t.Errorf("processor loads = %v, want {196608:12, 196609:34}", byIdx)
	}
}

// Vendor-specific metric families siblings populate must be cleanly absent:
// empty base OIDs (callers skip the walk) and nil parse results.
func TestGeneric_UnsupportedMetricFamilies(t *testing.T) {
	p := GetVendorProfile("generic")
	if p == nil {
		t.Fatal("generic profile not registered")
	}
	if oid := p.VPNBaseOID(); oid != "" {
		t.Errorf("VPNBaseOID = %q, want empty (unsupported)", oid)
	}
	if oid := p.HWSensorBaseOID(); oid != "" {
		t.Errorf("HWSensorBaseOID = %q, want empty (unsupported)", oid)
	}
	if oid := p.HABaseOID(); oid != "" {
		t.Errorf("HABaseOID = %q, want empty (unsupported)", oid)
	}
	if defs := p.TrapOIDs(); len(defs) != 0 {
		t.Errorf("TrapOIDs = %v, want none", defs)
	}
	if got := p.ParseVPNStatus(nil); len(got) != 0 {
		t.Errorf("ParseVPNStatus = %v, want empty", got)
	}
	if got := p.ParseHardwareSensors(nil); len(got) != 0 {
		t.Errorf("ParseHardwareSensors = %v, want empty", got)
	}
	if got := p.ParseHAStatus(nil); len(got) != 0 {
		t.Errorf("ParseHAStatus = %v, want empty", got)
	}
	tunnels, err := p.GetAllVPNTunnels(nil)
	if err != nil || len(tunnels) != 0 {
		t.Errorf("GetAllVPNTunnels = (%v, %v), want (empty, nil)", tunnels, err)
	}
}
