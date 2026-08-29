package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetConnectionFlowStats_MetadataTimeBounded pins AUDIT-269: the DISTINCT
// subnet-pair scan over vpn_status that seeds the flow filter is bounded to the
// query window (timestamp > cutoff). A stale config row — a subnet the tunnel
// used a month ago — must no longer leak into the filter and resurrect recent
// flows that fall in the OLD subnet into the current totals.
func TestGetConnectionFlowStats_MetadataTimeBounded(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()

	src := models.Device{Name: "fw-a", IPAddress: "192.0.2.1", Vendor: "fortigate", Enabled: true}
	dst := models.Device{Name: "fw-b", IPAddress: "192.0.2.2", Vendor: "fortigate", Enabled: true}
	if err := d.CreateDevice(&src); err != nil {
		t.Fatalf("create src: %v", err)
	}
	if err := d.CreateDevice(&dst); err != nil {
		t.Fatalf("create dst: %v", err)
	}

	conn := models.DeviceConnection{
		Name: "a-b", SourceDeviceID: src.ID, DestDeviceID: dst.ID,
		ConnectionType: "ipsec", TunnelNames: "vpn1", MatchMethod: "ip_match",
	}
	if err := d.Gorm().Create(&conn).Error; err != nil {
		t.Fatalf("create conn: %v", err)
	}

	// Current config: the subnets the tunnel carries now.
	if err := d.Gorm().Create(&models.VPNStatus{
		DeviceID: src.ID, TunnelName: "vpn1", Status: "up", Timestamp: now,
		LocalSubnet: "10.1.0.0/24", RemoteSubnet: "10.2.0.0/24",
	}).Error; err != nil {
		t.Fatalf("seed recent vpn_status: %v", err)
	}
	// Stale config: a subnet pair from a month ago, outside the 24h window used
	// below. The fix must exclude it from the DISTINCT scan.
	if err := d.Gorm().Create(&models.VPNStatus{
		DeviceID: src.ID, TunnelName: "vpn1", Status: "up", Timestamp: now.AddDate(0, 0, -30),
		LocalSubnet: "10.9.0.0/24", RemoteSubnet: "10.8.0.0/24",
	}).Error; err != nil {
		t.Fatalf("seed stale vpn_status: %v", err)
	}

	// Recent flows. F1 falls in the CURRENT subnet pair (must be counted). F2
	// falls in the STALE pair only — counted iff the stale metadata leaks in.
	mkFlow := func(s, dd string, b uint64) *models.FlowSample {
		return &models.FlowSample{DeviceID: src.ID, Timestamp: now, SrcAddr: s, DstAddr: dd, Bytes: b, Packets: 1, Protocol: 6}
	}
	if err := d.Gorm().Create(mkFlow("10.1.0.5", "10.2.0.5", 1000)).Error; err != nil {
		t.Fatalf("seed flow f1: %v", err)
	}
	if err := d.Gorm().Create(mkFlow("10.9.0.5", "10.8.0.5", 5000)).Error; err != nil {
		t.Fatalf("seed flow f2: %v", err)
	}

	res, err := d.GetConnectionFlowStats(conn.ID, 24)
	if err != nil {
		t.Fatalf("GetConnectionFlowStats: %v", err)
	}

	if res.TotalBytes != 1000 {
		t.Errorf("TotalBytes = %d, want 1000 (a total of 6000 means the stale subnet metadata leaked into the filter)", res.TotalBytes)
	}
	if res.TotalFlows != 1 {
		t.Errorf("TotalFlows = %d, want 1 (stale-subnet flow must be excluded)", res.TotalFlows)
	}
}
