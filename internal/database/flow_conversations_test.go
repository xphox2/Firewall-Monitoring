package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestGetInterfaceFlowConversations verifies the report's spike-context query:
// top conversations on a specific interface (input OR output ifIndex) within a
// time window, ranked by bytes, excluding port-0/0, other interfaces, other
// devices, and out-of-window samples.
func TestGetInterfaceFlowConversations(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().Add(-10 * time.Minute)

	rows := []models.FlowSample{
		// device 1, ifIndex 2 (input): one TCP/443 conversation, two samples -> summed.
		{Timestamp: now, DeviceID: 1, InputIfIndex: 2, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", DstPort: 443, Protocol: 6, Bytes: 9000},
		{Timestamp: now, DeviceID: 1, InputIfIndex: 2, SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", DstPort: 443, Protocol: 6, Bytes: 3000},
		// device 1, ifIndex 2 (output): smaller UDP/53.
		{Timestamp: now, DeviceID: 1, OutputIfIndex: 2, SrcAddr: "10.0.0.6", DstAddr: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 1000},
		// port-0/0 portless noise on the same interface -> excluded.
		{Timestamp: now, DeviceID: 1, InputIfIndex: 2, SrcAddr: "10.0.0.7", DstAddr: "fe80::1", SrcPort: 0, DstPort: 0, Protocol: 58, Bytes: 500000},
		// different interface -> excluded.
		{Timestamp: now, DeviceID: 1, InputIfIndex: 9, SrcAddr: "10.0.0.8", DstAddr: "1.1.1.1", DstPort: 443, Protocol: 6, Bytes: 999999},
		// out of window -> excluded.
		{Timestamp: now.Add(-2 * time.Hour), DeviceID: 1, InputIfIndex: 2, SrcAddr: "10.0.0.9", DstAddr: "2.2.2.2", DstPort: 80, Protocol: 6, Bytes: 999999},
		// different device -> excluded.
		{Timestamp: now, DeviceID: 2, InputIfIndex: 2, SrcAddr: "10.0.0.10", DstAddr: "3.3.3.3", DstPort: 443, Protocol: 6, Bytes: 999999},
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed flow samples: %v", err)
	}

	convos, err := db.GetInterfaceFlowConversations(1, 2, now.Add(-time.Hour), now.Add(time.Hour), 5)
	if err != nil {
		t.Fatalf("GetInterfaceFlowConversations: %v", err)
	}
	if len(convos) != 2 {
		t.Fatalf("expected 2 conversations (port-0/other-iface/other-device/out-of-window excluded), got %d: %+v", len(convos), convos)
	}
	if convos[0].DstAddr != "203.0.113.9" || convos[0].DstPort != 443 || convos[0].Protocol != "TCP" || convos[0].Bytes != 12000 {
		t.Errorf("top conversation wrong (want TCP 203.0.113.9:443 = 12000 bytes): %+v", convos[0])
	}
	if convos[1].DstAddr != "8.8.8.8" || convos[1].Protocol != "UDP" {
		t.Errorf("second conversation wrong (want UDP 8.8.8.8): %+v", convos[1])
	}
}
