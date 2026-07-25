package main

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"
)

// The connection map drew an IPSec edge that did not exist and omitted the one
// that did. A FortiGate's dialup instance is named after the peer's OBSERVED
// SOURCE address; for a peer behind NAT that is the gateway's public IP, which
// legitimately belongs to a different monitored device. Attribution by remote IP
// therefore lands on the NAT gateway — in production, two distinct peers behind
// one NAT both collapsed onto it.
//
// These tests are built from the real production shape: TECHLABS-FW-01 (a
// FortiGate) ↔ OPNsense behind DC2-FW1's NAT, provisioned as fwm-t11.

type mapFixture struct {
	p       *Poller
	db      *database.Database
	fgt     models.Device // provisioned endpoint A
	opn     models.Device // provisioned endpoint B, behind NAT
	natGw   models.Device // owns the public IP the dialup row reports
	devices []models.Device
}

func newMapFixture(t *testing.T) *mapFixture {
	t.Helper()
	p, db := newTestPoller(t)

	siteA := &models.Site{Name: "Lab"}
	siteB := &models.Site{Name: "DC"}
	for _, s := range []*models.Site{siteA, siteB} {
		if err := db.CreateSite(s); err != nil {
			t.Fatalf("create site: %v", err)
		}
	}
	mk := func(name, ip string, site *models.Site) models.Device {
		d := models.Device{Name: name, IPAddress: ip, Vendor: "fortigate", Enabled: true, SiteID: &site.ID}
		if err := db.CreateDevice(&d); err != nil {
			t.Fatalf("create device %s: %v", name, err)
		}
		return d
	}
	f := &mapFixture{p: p, db: db}
	f.natGw = mk("DC2-FW1", "10.0.0.1", siteB)
	f.fgt = mk("TECHLABS-FW-01", "10.0.0.2", siteA)
	f.opn = mk("OPNsense", "192.168.5.107", siteB)
	f.devices = []models.Device{f.natGw, f.fgt, f.opn}

	// The NAT gateway owns the public address the dialup rows report arriving
	// from. This is what makes IP matching land on the wrong device.
	if err := db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: f.natGw.ID, Index: 19, Name: "wan", TypeName: "ethernet", Status: "up", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save iface: %v", err)
	}
	if err := db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: f.natGw.ID, IfIndex: 19, IPAddress: "76.66.145.98", NetMask: "255.255.255.248", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save addr: %v", err)
	}
	return f
}

// sampleIntentFor builds the minimum intent the store needs to record a tunnel's
// endpoints and selectors.
func sampleIntentFor(name string, aID, bID uint, aNets, bNets []string) *ipsec.TunnelIntent {
	in := &ipsec.TunnelIntent{
		Name: name, Enabled: true, IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
	}
	in.Ends[0] = ipsec.EndpointSpec{
		DeviceID: aID, Vendor: "fortigate", EgressIface: "port1",
		ProtectedSubnets: aNets,
	}
	in.Ends[1] = ipsec.EndpointSpec{
		DeviceID: bID, Vendor: "opnsense", EgressIface: "wan",
		ProtectedSubnets: bNets,
	}
	return in
}

// provision records a deployed tunnel between two devices with the given
// selectors, exactly as the wizard would.
func (f *mapFixture) provision(t *testing.T, name string, a, b models.Device, aNets, bNets []string) {
	t.Helper()
	in := sampleIntentFor(name, a.ID, b.ID, aNets, bNets)
	m, err := database.IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	m.Status = "up"
	if err := f.db.CreateIPSecTunnel(m); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
}

func (f *mapFixture) connFor(t *testing.T, a, b uint) *models.DeviceConnection {
	t.Helper()
	conns, err := f.db.GetAllConnections()
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	for i := range conns {
		c := conns[i]
		if (c.SourceDeviceID == a && c.DestDeviceID == b) || (c.SourceDeviceID == b && c.DestDeviceID == a) {
			return &c
		}
	}
	return nil
}

// dialupRow is the SNMP-sourced child: liveness and selectors, but its name is
// synthesized from the peer's observed source address.
func dialupRow(deviceID uint, localSub, remoteSub string) models.VPNStatus {
	return models.VPNStatus{
		DeviceID: deviceID, TunnelName: "dialup-76.66.145.98", TunnelType: "ipsec-dialup",
		RemoteIP: "76.66.145.98", Status: "up", LocalSubnet: localSub, RemoteSubnet: remoteSub,
		Timestamp: time.Now(),
	}
}

// parentRow is the SSH-sourced parent: carries the provisioned name, but because
// `show ... phase1-interface` is CONFIG rather than live state it has no
// liveness and no counters.
func parentRow(deviceID uint, name string) models.VPNStatus {
	return models.VPNStatus{
		DeviceID: deviceID, TunnelName: name, Phase1Name: name, TunnelType: "ipsec",
		Status: "unknown", Timestamp: time.Now(),
	}
}

// THE REPORTED BUG. The tunnel must be attributed to its recorded endpoints, and
// no edge may be drawn to the NAT gateway.
func TestDetectVPN_ProvisionedTunnelBeatsNATGatewayIPMatch(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t11", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		parentRow(f.fgt.ID, "fwm-t11"),
		dialupRow(f.fgt.ID, "192.168.13.0/24", "192.168.50.0/32"),
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}

	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}

	if c := f.connFor(t, f.natGw.ID, f.fgt.ID); c != nil {
		t.Errorf("an edge to the NAT gateway must not exist — the tunnel terminates on the "+
			"peer behind it, not on the gateway; got %s (%s)", c.Name, c.MatchMethod)
	}
	c := f.connFor(t, f.fgt.ID, f.opn.ID)
	if c == nil {
		t.Fatal("the provisioned tunnel must be drawn between its recorded endpoints")
	}
	if c.MatchMethod != "provisioned" {
		t.Errorf("match_method = %q, want provisioned", c.MatchMethod)
	}
	// The dialup child supplies the liveness the config-derived parent lacks.
	if c.Status != "up" {
		t.Errorf("status = %q, want up — the SSH parent reports 'unknown', so the edge is "+
			"only green if the dialup child's liveness reaches it", c.Status)
	}
}

// THE CONTAMINATION. Two distinct peers behind ONE NAT gateway. Neither may
// attribute an edge to the gateway, and — critically — the dialup row must not
// inject its name or its hardcoded "up" into a legitimate pre-existing edge with
// that gateway.
func TestDetectVPN_DialupRowsNeverContaminateALegitimatePair(t *testing.T) {
	f := newMapFixture(t)

	// A genuine, IP-corroborated tunnel between the NAT gateway and the FortiGate.
	if err := f.db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: f.fgt.ID, Index: 3, Name: "wan", TypeName: "ethernet", Status: "up", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save iface: %v", err)
	}
	if err := f.db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: f.fgt.ID, IfIndex: 3, IPAddress: "203.0.113.7", NetMask: "255.255.255.0", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save addr: %v", err)
	}

	rows := []models.VPNStatus{
		// Legitimate named tunnel, both directions — this pair SHOULD exist.
		{DeviceID: f.natGw.ID, TunnelName: "REAL-LINK", TunnelType: "ipsec", RemoteIP: "203.0.113.7", Status: "up", Timestamp: time.Now()},
		{DeviceID: f.fgt.ID, TunnelName: "REAL-LINK", TunnelType: "ipsec", RemoteIP: "76.66.145.98", Status: "up", Timestamp: time.Now()},
		// A dialup row on the FortiGate whose peer is actually behind the NAT.
		dialupRow(f.fgt.ID, "192.168.13.0/24", "192.168.50.0/32"),
	}
	if err := f.db.SaveVPNStatuses(rows); err != nil {
		t.Fatalf("save vpn: %v", err)
	}

	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}

	c := f.connFor(t, f.natGw.ID, f.fgt.ID)
	if c == nil {
		t.Fatal("the legitimate corroborated tunnel must survive")
	}
	if got := c.TunnelNames; got != "REAL-LINK" {
		t.Errorf("tunnel_names = %q, want exactly \"REAL-LINK\" — a dialup row whose remote IP "+
			"merely happens to belong to this device must contribute nothing to it", got)
	}
}

// The order rows come out of the database must not change the outcome. Under a
// creation-only rule the dialup row's contribution depended on whether the pair
// already existed when it was reached, so tunnel_names churned every cycle.
func TestDetectVPN_OutcomeIsIndependentOfRowOrder(t *testing.T) {
	names := make([]string, 0, 2)
	for _, reversed := range []bool{false, true} {
		f := newMapFixture(t)
		if err := f.db.SaveInterfaceStats([]models.InterfaceStats{
			{DeviceID: f.fgt.ID, Index: 3, Name: "wan", TypeName: "ethernet", Status: "up", Timestamp: time.Now()},
		}); err != nil {
			t.Fatalf("save iface: %v", err)
		}
		if err := f.db.SaveInterfaceAddresses([]models.InterfaceAddress{
			{DeviceID: f.fgt.ID, IfIndex: 3, IPAddress: "203.0.113.7", NetMask: "255.255.255.0", Timestamp: time.Now()},
		}); err != nil {
			t.Fatalf("save addr: %v", err)
		}
		rows := []models.VPNStatus{
			{DeviceID: f.natGw.ID, TunnelName: "REAL-LINK", TunnelType: "ipsec", RemoteIP: "203.0.113.7", Status: "up", Timestamp: time.Now()},
			{DeviceID: f.fgt.ID, TunnelName: "REAL-LINK", TunnelType: "ipsec", RemoteIP: "76.66.145.98", Status: "up", Timestamp: time.Now()},
			dialupRow(f.fgt.ID, "192.168.13.0/24", "192.168.50.0/32"),
		}
		if reversed {
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
		if err := f.db.SaveVPNStatuses(rows); err != nil {
			t.Fatalf("save vpn: %v", err)
		}
		if _, ok := f.p.detectVPNConnections(f.devices); !ok {
			t.Fatal("detectVPNConnections reported a failed read")
		}
		c := f.connFor(t, f.natGw.ID, f.fgt.ID)
		if c == nil {
			t.Fatal("legitimate pair missing")
		}
		names = append(names, c.TunnelNames)
	}
	if names[0] != names[1] {
		t.Errorf("tunnel_names depends on row order: %q vs %q", names[0], names[1])
	}
}

// A tunnel name is free text read off a device; only ipsec_tunnels.name is
// unique. A device that is NOT an endpoint must never be able to attribute the
// provisioned pair — that failure would wear the highest-confidence label.
func TestDetectVPN_ProvisionedNameFromAnUnrelatedDeviceIsIgnored(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t11", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	// The NAT gateway is not an endpoint of fwm-t11, but reports that name.
	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		parentRow(f.natGw.ID, "fwm-t11"),
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}

	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	if c := f.connFor(t, f.fgt.ID, f.opn.ID); c != nil {
		t.Errorf("a device outside the recorded pair must not attribute it; got %s", c.MatchMethod)
	}
}

// Phase 0 is row-driven. With no telemetry naming the tunnel there must be no
// edge at all — a table-driven pair would carry no fresh evidence, render
// permanently stale, and keep advancing last_check so the sweep could never
// reap it.
func TestDetectVPN_ProvisionedTunnelWithNoTelemetryDrawsNothing(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t11", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	if c := f.connFor(t, f.fgt.ID, f.opn.ID); c != nil {
		t.Errorf("provisioning alone is not evidence a tunnel exists on the devices; got %s/%s",
			c.MatchMethod, c.Status)
	}
}

// If the SSH writer goes quiet the subnet-bearing child alone must still carry
// the tunnel — otherwise it would vanish from the map entirely, which is worse
// than the wrong-but-visible edge this change replaces.
func TestDetectVPN_DialupChildAloneStillAttributesItsTunnel(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t11", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		dialupRow(f.fgt.ID, "192.168.13.0/24", "192.168.50.0/32"),
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}
	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	c := f.connFor(t, f.fgt.ID, f.opn.ID)
	if c == nil {
		t.Fatal("a subnet-bearing dialup child must attribute its provisioned tunnel on its own")
	}
	if c.MatchMethod != "provisioned" || c.Status != "up" {
		t.Errorf("got %s/%s, want provisioned/up", c.MatchMethod, c.Status)
	}
	if f.connFor(t, f.natGw.ID, f.fgt.ID) != nil {
		t.Error("still no edge to the NAT gateway")
	}
}

// FortiOS reports selectors in two formats depending on which MIB path supplied
// them. A CIDR-only parse silently fails on the range form, leaving a healthy
// tunnel unattributed.
func TestDetectVPN_RangeFormatSelectorsAreUnderstood(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t11", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		dialupRow(f.fgt.ID, "192.168.13.0 - 192.168.13.255", "192.168.50.0 - 192.168.50.255"),
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}
	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	if c := f.connFor(t, f.fgt.ID, f.opn.ID); c == nil {
		t.Error("range-format selectors must attribute the same as CIDR — the SNMP profile " +
			"emits both, and only one path produces CIDR")
	}
}

// Ambiguity must not be resolved by guessing: a wrong parent wears the
// "provisioned" label and looks authoritative.
func TestDetectVPN_AmbiguousSubnetMatchAttributesNothing(t *testing.T) {
	f := newMapFixture(t)
	// Two tunnels from the same device with selectors that both cover the row.
	f.provision(t, "fwm-t20", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})
	f.provision(t, "fwm-t21", f.fgt, f.natGw, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		dialupRow(f.fgt.ID, "192.168.13.0/24", "192.168.50.0/32"),
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}
	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	// Assert BOTH candidates are absent. Checking only one lets a broken
	// implementation pass whenever map iteration happens to pick the other —
	// a test that fails only sometimes is worse than none.
	if c := f.connFor(t, f.fgt.ID, f.opn.ID); c != nil {
		t.Errorf("an ambiguous match must attribute nothing; got an edge to opn (%s)", c.MatchMethod)
	}
	if c := f.connFor(t, f.fgt.ID, f.natGw.ID); c != nil {
		t.Errorf("an ambiguous match must attribute nothing; got an edge to natGw (%s)", c.MatchMethod)
	}
}

// "provisioned" rests on a recorded deployment, which is better evidence than
// two inferences agreeing. Corroboration must not downgrade the label.
func TestDetectVPN_ProvisionedIsTerminalAgainstBidirectional(t *testing.T) {
	f := newMapFixture(t)
	f.provision(t, "fwm-t11", f.fgt, f.opn, []string{"192.168.13.0/24"}, []string{"192.168.50.0/24"})

	// Give both ends addresses that resolve to each other, so the bidirectional
	// check would otherwise fire on this pair.
	if err := f.db.SaveInterfaceStats([]models.InterfaceStats{
		{DeviceID: f.fgt.ID, Index: 3, Name: "wan", TypeName: "ethernet", Status: "up", Timestamp: time.Now()},
		{DeviceID: f.opn.ID, Index: 4, Name: "wan", TypeName: "ethernet", Status: "up", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save iface: %v", err)
	}
	if err := f.db.SaveInterfaceAddresses([]models.InterfaceAddress{
		{DeviceID: f.fgt.ID, IfIndex: 3, IPAddress: "203.0.113.7", NetMask: "255.255.255.0", Timestamp: time.Now()},
		{DeviceID: f.opn.ID, IfIndex: 4, IPAddress: "203.0.113.8", NetMask: "255.255.255.0", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save addr: %v", err)
	}
	if err := f.db.SaveVPNStatuses([]models.VPNStatus{
		parentRow(f.fgt.ID, "fwm-t11"),
		{DeviceID: f.fgt.ID, TunnelName: "x", TunnelType: "ipsec", RemoteIP: "203.0.113.8", Status: "up", Timestamp: time.Now()},
		{DeviceID: f.opn.ID, TunnelName: "y", TunnelType: "ipsec", RemoteIP: "203.0.113.7", Status: "up", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("save vpn: %v", err)
	}
	if _, ok := f.p.detectVPNConnections(f.devices); !ok {
		t.Fatal("detectVPNConnections reported a failed read")
	}
	c := f.connFor(t, f.fgt.ID, f.opn.ID)
	if c == nil {
		t.Fatal("pair missing")
	}
	if c.MatchMethod != "provisioned" {
		t.Errorf("match_method = %q — corroboration must not downgrade a recorded deployment", c.MatchMethod)
	}
}
