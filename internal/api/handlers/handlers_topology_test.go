package handlers

import (
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestReceiveTopologyEntries_SavesAndNormalizes: valid rows save, MACs are
// lowercased at the boundary (the inference joins case-sensitively), and the
// device's last_polled/status is bumped (batched WHERE id IN form).
func TestReceiveTopologyEntries_SavesAndNormalizes(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	entries := []map[string]interface{}{{
		"device_id":   device.ID,
		"timestamp":   time.Now(),
		"entry_type":  "fdb",
		"if_index":    3,
		"mac_address": "AA:BB:CC:00:00:01", // uppercase on the wire → normalized
		"vlan_id":     10,
		"source":      "snmp",
	}, {
		"device_id":   device.ID,
		"timestamp":   time.Now(),
		"entry_type":  "arp",
		"if_index":    4,
		"mac_address": "aa:bb:cc:00:00:02",
		"ip_address":  "10.0.0.7",
		"source":      "snmp",
	}}

	before := time.Now().Add(-time.Second)
	w := doTestRequest(t, h.ReceiveTopologyEntries, "POST", "/topology-entries", probe.ID, probe.RegistrationKey, entries)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var rows []models.TopologyEntry
	db.Gorm().Where("device_id = ?", device.ID).Order("entry_type").Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("saved %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.MACAddress != "aa:bb:cc:00:00:01" && r.MACAddress != "aa:bb:cc:00:00:02" {
			t.Errorf("MAC not normalized to lowercase: %q", r.MACAddress)
		}
	}

	var dev models.Device
	db.Gorm().First(&dev, device.ID)
	if dev.Status != "online" || dev.LastPolled.Before(before) {
		t.Errorf("device not bumped online: status=%q last_polled=%v", dev.Status, dev.LastPolled)
	}
}

// TestReceiveTopologyEntries_ForeignDeviceFiltered: rows for a device not
// assigned to the probe are dropped, not saved.
func TestReceiveTopologyEntries_ForeignDeviceFiltered(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	foreign := &models.Device{Name: "other-fw", IPAddress: "192.168.9.9"}
	if err := db.Gorm().Create(foreign).Error; err != nil {
		t.Fatalf("create foreign device: %v", err)
	}

	entries := []map[string]interface{}{{
		"device_id":   foreign.ID,
		"entry_type":  "arp",
		"mac_address": "aa:bb:cc:00:00:03",
		"ip_address":  "10.0.0.8",
	}}
	w := doTestRequest(t, h.ReceiveTopologyEntries, "POST", "/topology-entries", probe.ID, probe.RegistrationKey, entries)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var n int64
	db.Gorm().Model(&models.TopologyEntry{}).Count(&n)
	if n != 0 {
		t.Errorf("foreign-device rows saved: %d, want 0", n)
	}
}

// TestReceiveTopologyEntries_InvalidTypeDropped: entry types outside arp|fdb
// never reach the table (they would corrupt the replace-scope semantics).
func TestReceiveTopologyEntries_InvalidTypeDropped(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	entries := []map[string]interface{}{{
		"device_id":   device.ID,
		"entry_type":  "bogus",
		"mac_address": "aa:bb:cc:00:00:04",
	}}
	w := doTestRequest(t, h.ReceiveTopologyEntries, "POST", "/topology-entries", probe.ID, probe.RegistrationKey, entries)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var n int64
	db.Gorm().Model(&models.TopologyEntry{}).Count(&n)
	if n != 0 {
		t.Errorf("invalid entry_type saved: %d rows, want 0", n)
	}
}

// TestReceiveTopologyNeighbors_Saves: the neighbor endpoint saves LLDP rows
// and normalizes the chassis id.
func TestReceiveTopologyNeighbors_Saves(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	neighbors := []map[string]interface{}{{
		"device_id":         device.ID,
		"protocol":          "lldp",
		"local_if_index":    3,
		"local_port_name":   "internal3",
		"remote_chassis_id": "AA:BB:CC:00:44:01",
		"remote_port_id":    "port7",
		"remote_sys_name":   "fw-branch",
	}}
	w := doTestRequest(t, h.ReceiveTopologyNeighbors, "POST", "/topology-neighbors", probe.ID, probe.RegistrationKey, neighbors)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var row models.TopologyNeighbor
	if err := db.Gorm().Where("device_id = ?", device.ID).First(&row).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if row.RemoteChassisID != "aa:bb:cc:00:44:01" {
		t.Errorf("chassis id not normalized: %q", row.RemoteChassisID)
	}
	if row.RemoteSysName != "fw-branch" || row.LocalPortName != "internal3" {
		t.Errorf("row wrong: %+v", row)
	}
}
