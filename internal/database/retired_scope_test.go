package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// TestRetiredDevice_ExcludedFromActivePaths pins the ActiveDevices contract
// (v0.11.239): a retired device drops out of every "live fleet" reader —
// collector device lists, the ingest allow-list, GetActiveDevices, the
// lightweight status list and the stale-device sweep — while GetDevice and
// GetAllDevices still return it so alerts and the detail page can name it.
func TestRetiredDevice_ExcludedFromActivePaths(t *testing.T) {
	d := NewDatabaseForTesting(t)

	probe := &models.Probe{Name: "p1"}
	if err := d.CreateProbe(probe); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	keep := &models.Device{Name: "keep", IPAddress: "10.0.0.1", ProbeID: &probe.ID, Enabled: true, Status: "online", LastPolled: time.Now().Add(-time.Hour)}
	gone := &models.Device{Name: "gone", IPAddress: "10.0.0.2", ProbeID: &probe.ID, Enabled: true, Status: "online", LastPolled: time.Now().Add(-time.Hour)}
	for _, dev := range []*models.Device{keep, gone} {
		if err := d.db.Create(dev).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}

	if err := d.RetireDevice(gone.ID); err != nil {
		t.Fatalf("RetireDevice: %v", err)
	}
	// Re-enable + online via raw SQL so the assertions below prove the
	// retired_at clause itself, not the enabled=false RetireDevice also sets.
	if err := d.db.Model(&models.Device{}).Where("id = ?", gone.ID).
		Updates(map[string]interface{}{"enabled": true, "status": "online"}).Error; err != nil {
		t.Fatalf("re-enable retired: %v", err)
	}

	onlyKeep := func(label string, ids []uint) {
		t.Helper()
		if len(ids) != 1 || ids[0] != keep.ID {
			t.Errorf("%s = %v, want only the active device %d", label, ids, keep.ID)
		}
	}
	devs, err := d.GetDevicesByProbe(probe.ID)
	if err != nil {
		t.Fatalf("GetDevicesByProbe: %v", err)
	}
	onlyKeep("GetDevicesByProbe", deviceIDs(devs))
	ids, err := d.GetDeviceIDsByProbe(probe.ID)
	if err != nil {
		t.Fatalf("GetDeviceIDsByProbe: %v", err)
	}
	onlyKeep("GetDeviceIDsByProbe", ids)
	active, err := d.GetActiveDevices()
	if err != nil {
		t.Fatalf("GetActiveDevices: %v", err)
	}
	onlyKeep("GetActiveDevices", deviceIDs(active))
	statuses, err := d.GetDeviceStatuses()
	if err != nil {
		t.Fatalf("GetDeviceStatuses: %v", err)
	}
	if len(statuses) != 1 {
		t.Errorf("GetDeviceStatuses returned %d rows, want 1 (retired excluded)", len(statuses))
	}
	rows, err := d.GetDeviceStatusRows()
	if err != nil {
		t.Fatalf("GetDeviceStatusRows: %v", err)
	}
	onlyKeep("GetDeviceStatusRows", deviceIDs(rows))

	// Unfiltered readers still see it.
	if _, err := d.GetDevice(gone.ID); err != nil {
		t.Errorf("GetDevice must still return a retired device: %v", err)
	}
	all, err := d.GetAllDevices()
	if err != nil {
		t.Fatalf("GetAllDevices: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("GetAllDevices returned %d, want 2 (unfiltered)", len(all))
	}

	// The stale sweep flips the active device only.
	flipped, err := d.MarkStaleProbeDevicesOffline(time.Now())
	if err != nil {
		t.Fatalf("MarkStaleProbeDevicesOffline: %v", err)
	}
	onlyKeep("MarkStaleProbeDevicesOffline", deviceIDs(flipped))
	got, _ := d.GetDevice(gone.ID)
	if got.Status != "online" {
		t.Errorf("retired device status = %q, want untouched 'online'", got.Status)
	}
}

func deviceIDs(devs []models.Device) []uint {
	out := make([]uint, 0, len(devs))
	for _, dv := range devs {
		out = append(out, dv.ID)
	}
	return out
}

// TestRetireDevice_ClosesAlertsIncidentsAndConnections covers the retire
// transaction: retired_at + enabled=false, open incidents resolved with the
// "(device retired)" reason, every unacked alert acknowledged (so the
// escalation engine stops re-notifying), open acked alerts resolved with the
// ack preserved, map connections removed — and the other device untouched.
func TestRetireDevice_ClosesAlertsIncidentsAndConnections(t *testing.T) {
	d := NewDatabaseForTesting(t)

	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", Enabled: true}
	other := &models.Device{Name: "other", IPAddress: "10.0.0.2", Enabled: true}
	for _, dv := range []*models.Device{dev, other} {
		if err := d.db.Create(dv).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}
	now := time.Now()
	ackedAt := now.Add(-time.Hour)
	seed := []*models.Alert{
		{DeviceID: dev.ID, Timestamp: now, AlertType: "DEVICE_OFFLINE", MetricName: "device_status", Message: "open unacked"},
		{DeviceID: dev.ID, Timestamp: now, AlertType: "CPU_HIGH", MetricName: "cpu", Message: "open acked", Acknowledged: true, AcknowledgedAt: &ackedAt, Notes: "operator note"},
		{DeviceID: dev.ID, Timestamp: now, AlertType: "MEM_HIGH", MetricName: "mem", Message: "resolved unacked", ResolvedAt: &ackedAt},
		{DeviceID: other.ID, Timestamp: now, AlertType: "DEVICE_OFFLINE", MetricName: "device_status", Message: "other device"},
	}
	for _, a := range seed {
		if err := d.db.Create(a).Error; err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}
	if err := d.db.Create(&models.Incident{DeviceID: dev.ID, StartedAt: now, Title: "fw offline"}).Error; err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if err := d.db.Create(&models.Incident{DeviceID: other.ID, StartedAt: now, Title: "other offline"}).Error; err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if err := d.db.Create(&models.DeviceConnection{Name: "c", SourceDeviceID: other.ID, DestDeviceID: dev.ID}).Error; err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	if err := d.RetireDevice(dev.ID); err != nil {
		t.Fatalf("RetireDevice: %v", err)
	}

	got, err := d.GetDevice(dev.ID)
	if err != nil {
		t.Fatalf("GetDevice after retire: %v", err)
	}
	if got.RetiredAt == nil || got.Enabled {
		t.Errorf("retired device: retired_at=%v enabled=%v, want set/false", got.RetiredAt, got.Enabled)
	}

	var alerts []models.Alert
	d.db.Where("device_id = ?", dev.ID).Order("id").Find(&alerts)
	for _, a := range alerts {
		if !a.Acknowledged || a.ResolvedAt == nil {
			t.Errorf("alert %q: acknowledged=%v resolved_at=%v, want true/set", a.Message, a.Acknowledged, a.ResolvedAt)
		}
		if !strings.Contains(a.Notes, "device retired") {
			t.Errorf("alert %q notes = %q, want the retire note", a.Message, a.Notes)
		}
	}
	// The operator's ack timestamp and note survive on the acked row.
	if alerts[1].AcknowledgedAt == nil || !alerts[1].AcknowledgedAt.Equal(ackedAt) || !strings.HasPrefix(alerts[1].Notes, "operator note") {
		t.Errorf("acked alert lost its ack: at=%v notes=%q", alerts[1].AcknowledgedAt, alerts[1].Notes)
	}
	// The already-resolved row keeps its original resolved_at.
	if !alerts[2].ResolvedAt.Equal(ackedAt) {
		t.Errorf("pre-resolved alert resolved_at rewritten to %v", alerts[2].ResolvedAt)
	}
	var otherAlert models.Alert
	d.db.Where("device_id = ?", other.ID).First(&otherAlert)
	if otherAlert.Acknowledged || otherAlert.ResolvedAt != nil {
		t.Error("another device's alert was touched by the retire")
	}

	var inc models.Incident
	d.db.Where("device_id = ?", dev.ID).First(&inc)
	if inc.ResolvedAt == nil || !strings.Contains(inc.Title, "(device retired)") {
		t.Errorf("incident not resolved with reason: resolved_at=%v title=%q", inc.ResolvedAt, inc.Title)
	}
	var otherInc models.Incident
	d.db.Where("device_id = ?", other.ID).First(&otherInc)
	if otherInc.ResolvedAt != nil {
		t.Error("another device's incident was resolved by the retire")
	}
	var conns int64
	d.db.Model(&models.DeviceConnection{}).Count(&conns)
	if conns != 0 {
		t.Errorf("device_connections = %d, want 0", conns)
	}

	// Idempotency + sentinels.
	if err := d.RetireDevice(dev.ID); !errors.Is(err, ErrDeviceRetired) {
		t.Errorf("second retire err = %v, want ErrDeviceRetired", err)
	}
	if err := d.RetireDevice(99999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("retire unknown err = %v, want ErrRecordNotFound", err)
	}
	if err := d.RestoreDevice(other.ID); !errors.Is(err, ErrDeviceNotRetired) {
		t.Errorf("restore active err = %v, want ErrDeviceNotRetired", err)
	}
	if err := d.RestoreDevice(99999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("restore unknown err = %v, want ErrRecordNotFound", err)
	}

	// Restore clears the marker, re-enables and resets status; history stays.
	if err := d.RestoreDevice(dev.ID); err != nil {
		t.Fatalf("RestoreDevice: %v", err)
	}
	got, _ = d.GetDevice(dev.ID)
	if got.RetiredAt != nil || !got.Enabled || got.Status != "unknown" {
		t.Errorf("restored device: retired_at=%v enabled=%v status=%q", got.RetiredAt, got.Enabled, got.Status)
	}
	var n int64
	d.db.Model(&models.Alert{}).Where("device_id = ?", dev.ID).Count(&n)
	if n != 3 {
		t.Errorf("alert history = %d rows after retire+restore, want 3", n)
	}
}
