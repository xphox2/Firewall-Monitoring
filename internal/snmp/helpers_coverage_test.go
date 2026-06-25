package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestSafeString(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{"bytes", []byte("hello"), "hello"},
		{"string", "world", "world"},
		{"int falls through to empty", 42, ""},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeString(tc.in); got != tc.want {
				t.Errorf("safeString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSafeFloat(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want float64
	}{
		{"DisplayString decimal (FortiGate temp)", []byte("52.500000"), 52.5},
		{"string decimal", "13.25", 13.25},
		{"whitespace trimmed", []byte("  7.0 "), 7.0},
		{"float32", float32(1.5), 1.5},
		{"float64", float64(2.5), 2.5},
		{"integer PDU", 100, 100},
		{"unparseable bytes → 0", []byte("n/a"), 0},
		{"uint", uint(9), 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeFloat(tc.in); got != tc.want {
				t.Errorf("safeFloat(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestFormatMAC(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{"6 bytes", []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}, "00:1A:2B:3C:4D:5E"},
		{"6-byte string", string([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}), "AA:BB:CC:DD:EE:FF"},
		{"too short", []byte{0x01, 0x02}, ""},
		{"too long", make([]byte, 8), ""},
		{"wrong type", 1234, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatMAC(tc.in); got != tc.want {
				t.Errorf("formatMAC(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGetIndexFromOID(t *testing.T) {
	base := ".1.3.6.1.2.1.2.2.1.2"
	cases := []struct {
		name string
		oid  string
		want int
	}{
		{"single-element index", base + ".7", 7},
		{"multi-element uses last", base + ".1.3.1.1", 1},
		{"non-numeric → -1", base + ".x", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getIndexFromOID(tc.oid, base); got != tc.want {
				t.Errorf("getIndexFromOID(%q) = %d, want %d", tc.oid, got, tc.want)
			}
		})
	}
}

func TestIsValidPDU(t *testing.T) {
	valid := gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("x")}
	if !isValidPDU(valid) {
		t.Error("OctetString PDU should be valid")
	}
	for _, badType := range []gosnmp.Asn1BER{gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView} {
		if isValidPDU(gosnmp.SnmpPDU{Type: badType}) {
			t.Errorf("PDU type %v should be invalid", badType)
		}
	}
}

func TestBuildCIDR(t *testing.T) {
	cases := []struct {
		name       string
		addr, mask string
		want       string
	}{
		{"any selector", "0.0.0.0", "0.0.0.0", "0.0.0.0/0"},
		{"any selector blank mask", "0.0.0.0", "", "0.0.0.0/0"},
		{"24-bit mask", "192.168.1.0", "255.255.255.0", "192.168.1.0/24"},
		{"host /32", "10.0.0.5", "255.255.255.255", "10.0.0.5/32"},
		{"no mask returns addr", "10.0.0.5", "", "10.0.0.5"},
		{"empty addr", "", "255.255.255.0", ""},
		{"invalid addr returned as-is", "not-an-ip", "255.255.255.0", "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildCIDR(tc.addr, tc.mask); got != tc.want {
				t.Errorf("buildCIDR(%q,%q) = %q, want %q", tc.addr, tc.mask, got, tc.want)
			}
		})
	}
}

func TestSwFormatIPAddress(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{"dotted string", "10.1.2.3", "10.1.2.3"},
		{"4-byte slice", []byte{192, 168, 0, 1}, "192.168.0.1"},
		{"non-IP string returned as-is", "hostname", "hostname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := swFormatIPAddress(tc.in); got != tc.want {
				t.Errorf("swFormatIPAddress(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSwFormatSubnetRange(t *testing.T) {
	cases := []struct {
		name, begin, end, want string
	}{
		{"single host", "10.0.0.1", "10.0.0.1", "10.0.0.1/32"},
		{"blank end → /32", "10.0.0.1", "", "10.0.0.1/32"},
		{"range", "10.0.0.1", "10.0.0.9", "10.0.0.1-10.0.0.9"},
		{"empty begin", "", "10.0.0.9", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := swFormatSubnetRange(tc.begin, tc.end); got != tc.want {
				t.Errorf("swFormatSubnetRange(%q,%q) = %q, want %q", tc.begin, tc.end, got, tc.want)
			}
		})
	}
}

func TestSwClassifySensorType(t *testing.T) {
	cases := []struct{ name, unit, want string }{
		{"CPU Temp", "C", "temperature"},
		{"Chassis Fan 1", "RPM", "fan"},
		{"VCC 3.3", "V", "voltage"},
		{"PSU Power", "Watt", "power"},
		{"Unknown", "", "other"},
	}
	for _, tc := range cases {
		if got := swClassifySensorType(tc.name, tc.unit); got != tc.want {
			t.Errorf("swClassifySensorType(%q,%q) = %q, want %q", tc.name, tc.unit, got, tc.want)
		}
	}
}

func TestPaSensorMeta(t *testing.T) {
	cases := []struct {
		sensorType         int
		wantName, wantType string
	}{
		{8, "Temperature Sensor 1", "temperature"},
		{10, "Fan 1", "fan"},
		{4, "Voltage Sensor 1", "voltage"},
		{5, "Current Sensor 1", "current"},
		{6, "Power Sensor 1", "power"},
		{99, "", ""},
	}
	for _, tc := range cases {
		name, typ, _ := paSensorMeta(tc.sensorType, 1)
		if name != tc.wantName || typ != tc.wantType {
			t.Errorf("paSensorMeta(%d,1) = (%q,%q), want (%q,%q)", tc.sensorType, name, typ, tc.wantName, tc.wantType)
		}
	}
}

func TestPaSensorScaleFactor(t *testing.T) {
	cases := map[int]float64{
		9:  1,    // base unit
		8:  1e-3, // milli
		6:  1e-9, // nano
		10: 1e3,  // kilo
		0:  1,    // unknown → 1
	}
	for scale, want := range cases {
		if got := paSensorScaleFactor(scale); got != want {
			t.Errorf("paSensorScaleFactor(%d) = %v, want %v", scale, got, want)
		}
	}
}

func TestClassifyBSDVPNInterface(t *testing.T) {
	cases := []struct {
		ifName   string
		wantType string
	}{
		{"ovpns1", "openvpn-server"},
		{"ovpnc2", "openvpn-client"},
		{"wg0", "wireguard"},
		{"tun_wg0", "wireguard"},
		{"ipsec1000", "ipsec"},
		{"em0", ""}, // physical NIC, not a VPN
	}
	for _, tc := range cases {
		got, name := classifyBSDVPNInterface(tc.ifName)
		if got != tc.wantType {
			t.Errorf("classifyBSDVPNInterface(%q) type = %q, want %q", tc.ifName, got, tc.wantType)
		}
		if tc.wantType != "" && name != tc.ifName {
			t.Errorf("classifyBSDVPNInterface(%q) name = %q, want %q", tc.ifName, name, tc.ifName)
		}
	}
}

func TestClassifyLinuxVPNInterface(t *testing.T) {
	cases := []struct {
		ifName   string
		ifType   int
		wantType string
	}{
		{"wg0", 0, "wireguard"},
		{"tun0", 53, "openvpn"},
		{"tun0", 6, ""}, // ethernet ifType → not a tunnel
		{"tap0", 0, "openvpn"},
		{"vti0", 131, "ipsec"},
		{"eth0", 6, ""},
	}
	for _, tc := range cases {
		got, _ := classifyLinuxVPNInterface(tc.ifName, tc.ifType)
		if got != tc.wantType {
			t.Errorf("classifyLinuxVPNInterface(%q,%d) = %q, want %q", tc.ifName, tc.ifType, got, tc.wantType)
		}
	}
}

func TestExtractVersions(t *testing.T) {
	t.Run("firewalla", func(t *testing.T) {
		if got := extractFirewallaVersion("Linux firewalla 5.15.0 #1 SMP"); got != "Linux 5.15.0" {
			t.Errorf("got %q", got)
		}
		if got := extractFirewallaVersion(""); got != "" {
			t.Errorf("empty → %q", got)
		}
	})
	t.Run("pfsense", func(t *testing.T) {
		got := extractPfSenseVersion("pfSense 2.7.2-RELEASE (amd64)")
		if got != "pfSense 2.7.2-RELEASE" {
			t.Errorf("got %q", got)
		}
		if extractPfSenseVersion("") != "" {
			t.Error("empty sysDescr should yield empty")
		}
	})
	t.Run("opnsense", func(t *testing.T) {
		got := extractOPNsenseVersion("OPNsense 24.1.5 (amd64/OpenSSL)")
		if got != "OPNsense 24.1.5" {
			t.Errorf("got %q", got)
		}
	})
}

// TestFortiGateParseSystemStatus exercises the default vendor's core
// system-status parser: scalar OIDs fold into a SystemStatus, disk usage is
// computed as a percentage of capacity, and SNMP error PDUs are skipped.
func TestFortiGateParseSystemStatus(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDSystemHostname, Type: gosnmp.OctetString, Value: []byte("fw-edge-1")},
		{Name: fgOIDSystemVersion, Type: gosnmp.OctetString, Value: []byte("v7.4.1")},
		{Name: fgOIDSystemCPU, Type: gosnmp.Gauge32, Value: uint(37)},
		{Name: fgOIDSystemMemory, Type: gosnmp.Gauge32, Value: uint(52)},
		{Name: fgOIDSystemSessions, Type: gosnmp.Gauge32, Value: uint(1200)},
		{Name: fgOIDSystemUptime, Type: gosnmp.TimeTicks, Value: uint(99999)},
		{Name: fgOIDSystemDisk, Type: gosnmp.Gauge32, Value: uint(250)},     // MB used
		{Name: fgOIDSystemDiskCap, Type: gosnmp.Gauge32, Value: uint(1000)}, // MB total
		// An unsupported-OID error PDU must be ignored, not crash the parse.
		{Name: fgOIDSystemCPU, Type: gosnmp.NoSuchInstance},
	}
	s := f.ParseSystemStatus(pdus)
	if s.Hostname != "fw-edge-1" || s.Version != "v7.4.1" {
		t.Errorf("identity: %q %q", s.Hostname, s.Version)
	}
	if s.CPUUsage != 37 || s.MemoryUsage != 52 || s.SessionCount != 1200 {
		t.Errorf("gauges: cpu=%v mem=%v sess=%d", s.CPUUsage, s.MemoryUsage, s.SessionCount)
	}
	if s.Uptime != 99999 {
		t.Errorf("uptime = %d", s.Uptime)
	}
	// 250/1000 MB = 25%.
	if s.DiskUsage != 25 || s.DiskTotal != 1000 {
		t.Errorf("disk: usage=%v total=%d", s.DiskUsage, s.DiskTotal)
	}
}

// TestFortiGateParseSystemStatusNoDiskCap confirms the divide-by-zero guard:
// with no capacity OID, DiskUsage stays 0 rather than NaN/Inf.
func TestFortiGateParseSystemStatusNoDiskCap(t *testing.T) {
	f := &FortiGateProfile{}
	s := f.ParseSystemStatus([]gosnmp.SnmpPDU{
		{Name: fgOIDSystemDisk, Type: gosnmp.Gauge32, Value: uint(250)},
	})
	if s.DiskUsage != 0 {
		t.Errorf("DiskUsage with no capacity = %v, want 0", s.DiskUsage)
	}
}

// TestSonicWallParseHardwareSensors exercises the PDU-driven sensor parser end
// to end: name/value/unit PDUs across two sensor indices fold into typed
// HardwareSensor rows, and a sensor missing its name is dropped.
func TestSonicWallParseHardwareSensors(t *testing.T) {
	sw := &SonicWallProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: swOIDSensorDevice + ".1", Type: gosnmp.OctetString, Value: []byte("CPU Temp")},
		{Name: swOIDSensorValue + ".1", Type: gosnmp.Integer, Value: 45},
		{Name: swOIDSensorUnit + ".1", Type: gosnmp.OctetString, Value: []byte("C")},
		// index 2 has a value but no name → must be dropped
		{Name: swOIDSensorValue + ".2", Type: gosnmp.Integer, Value: 99},
	}
	got := sw.ParseHardwareSensors(pdus)
	if len(got) != 1 {
		t.Fatalf("expected 1 named sensor, got %d (%+v)", len(got), got)
	}
	s := got[0]
	if s.Name != "CPU Temp" || s.Type != "temperature" || s.Value != 45 || s.Unit != "C" {
		t.Errorf("unexpected sensor: %+v", s)
	}
}
