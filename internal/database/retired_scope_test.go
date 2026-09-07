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
	if err := d.RestoreDevice(other.ID, nil); !errors.Is(err, ErrDeviceNotRetired) {
		t.Errorf("restore active err = %v, want ErrDeviceNotRetired", err)
	}
	if err := d.RestoreDevice(99999, nil); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("restore unknown err = %v, want ErrRecordNotFound", err)
	}

	// Restore clears the marker, re-enables and resets status; history stays.
	if err := d.RestoreDevice(dev.ID, nil); err != nil {
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

// TestResolveDeviceByIP_FollowsActiveDevice pins the ingest-attribution
// contract of the IP resolvers: "retire FW-01 (ip X), add FW-02 (ip X)" must
// resolve X to FW-02 for both the batched and the per-IP resolver, on the
// management-IP path AND the interface_addresses fallback — otherwise syslog/
// flow rows resolve to the retired id and the probe allow-list drops them, and
// traps attach to the retired device. An IP held only by a retired device
// resolves to nothing.
func TestResolveDeviceByIP_FollowsActiveDevice(t *testing.T) {
	d := NewDatabaseForTesting(t)

	const mgmtIP = "10.0.0.1"
	const ifaceIP = "10.0.0.99"
	old := &models.Device{Name: "FW-01", IPAddress: mgmtIP}
	if err := d.db.Create(old).Error; err != nil {
		t.Fatalf("create FW-01: %v", err)
	}
	if err := d.db.Create(&models.InterfaceAddress{DeviceID: old.ID, IPAddress: ifaceIP, Timestamp: time.Now()}).Error; err != nil {
		t.Fatalf("create FW-01 interface address: %v", err)
	}

	// Sanity: while active, FW-01 owns both IPs.
	if got := d.ResolveDeviceByIP(mgmtIP); got != old.ID {
		t.Fatalf("pre-retire ResolveDeviceByIP(mgmt) = %d, want %d", got, old.ID)
	}
	if got := d.ResolveDevicesByIPs([]string{ifaceIP})[ifaceIP]; got != old.ID {
		t.Fatalf("pre-retire ResolveDevicesByIPs(iface) = %d, want %d", got, old.ID)
	}
	if got := d.ResolveDeviceByIP(ifaceIP); got != old.ID {
		t.Fatalf("pre-retire ResolveDeviceByIP(iface) = %d, want %d", got, old.ID)
	}

	if err := d.RetireDevice(old.ID); err != nil {
		t.Fatalf("RetireDevice: %v", err)
	}

	// Only a retired device holds the IPs → no match on either path.
	if got := d.ResolveDeviceByIP(mgmtIP); got != 0 {
		t.Errorf("retired-only ResolveDeviceByIP(mgmt) = %d, want 0", got)
	}
	if got := d.ResolveDeviceByIP(ifaceIP); got != 0 {
		t.Errorf("retired-only ResolveDeviceByIP(iface) = %d, want 0", got)
	}
	if got := d.ResolveDevicesByIPs([]string{mgmtIP, ifaceIP}); len(got) != 0 {
		t.Errorf("retired-only ResolveDevicesByIPs = %v, want empty", got)
	}

	// FW-02 re-added on the same management IP, with a HIGHER id than the
	// retired FW-01 (the AUDIT-270 lowest-id ordering must not resurrect it).
	repl := &models.Device{Name: "FW-02", IPAddress: mgmtIP}
	if err := d.db.Create(repl).Error; err != nil {
		t.Fatalf("create FW-02: %v", err)
	}
	if repl.ID <= old.ID {
		t.Fatalf("test setup: FW-02 id %d must be above FW-01 id %d", repl.ID, old.ID)
	}
	if err := d.db.Create(&models.InterfaceAddress{DeviceID: repl.ID, IPAddress: ifaceIP, Timestamp: time.Now()}).Error; err != nil {
		t.Fatalf("create FW-02 interface address: %v", err)
	}

	if got := d.ResolveDeviceByIP(mgmtIP); got != repl.ID {
		t.Errorf("ResolveDeviceByIP(mgmt) = %d, want active FW-02 %d", got, repl.ID)
	}
	if got := d.ResolveDeviceByIP(ifaceIP); got != repl.ID {
		t.Errorf("ResolveDeviceByIP(iface) = %d, want active FW-02 %d", got, repl.ID)
	}
	batch := d.ResolveDevicesByIPs([]string{mgmtIP, ifaceIP})
	if batch[mgmtIP] != repl.ID {
		t.Errorf("ResolveDevicesByIPs[mgmt] = %d, want active FW-02 %d", batch[mgmtIP], repl.ID)
	}
	if batch[ifaceIP] != repl.ID {
		t.Errorf("ResolveDevicesByIPs[iface] = %d, want active FW-02 %d", batch[ifaceIP], repl.ID)
	}
}

// TestRestoreDevice_SettingsAtomic pins RestoreDevice(id, updates): the
// settings map is applied in the restore transaction (a restored row carries
// the new values), the restore columns cannot be overridden through it, and a
// settings write the database rejects (name collision) rolls the restore back
// so the device stays retired.
func TestRestoreDevice_SettingsAtomic(t *testing.T) {
	d := NewDatabaseForTesting(t)

	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", Enabled: true, Status: "online"}
	taken := &models.Device{Name: "taken", IPAddress: "10.0.0.2", Enabled: true}
	for _, dv := range []*models.Device{dev, taken} {
		if err := d.db.Create(dv).Error; err != nil {
			t.Fatalf("create device: %v", err)
		}
	}
	if err := d.RetireDevice(dev.ID); err != nil {
		t.Fatalf("RetireDevice: %v", err)
	}

	// Colliding name: the whole transaction rolls back — still retired,
	// nothing else applied, error is a unique violation.
	err := d.RestoreDevice(dev.ID, map[string]interface{}{"name": "taken", "description": "must not land"})
	if !IsUniqueViolation(err) {
		t.Fatalf("restore with colliding name err = %v, want a unique violation", err)
	}
	got, _ := d.GetDevice(dev.ID)
	if got.RetiredAt == nil || got.Enabled || got.Description != "" || got.Name != "fw" {
		t.Errorf("after rejected restore: retired_at=%v enabled=%v name=%q description=%q (restore must have rolled back)",
			got.RetiredAt, got.Enabled, got.Name, got.Description)
	}

	// Valid settings land with the restore; restore columns in the map are
	// ignored so a caller can never restore a device as disabled.
	err = d.RestoreDevice(dev.ID, map[string]interface{}{
		"description": "re-added", "ip_address": "10.0.0.9",
		"enabled": false, "status": "online", "retired_at": time.Now(),
	})
	if err != nil {
		t.Fatalf("RestoreDevice with settings: %v", err)
	}
	got, _ = d.GetDevice(dev.ID)
	if got.RetiredAt != nil || !got.Enabled || got.Status != "unknown" {
		t.Errorf("restored: retired_at=%v enabled=%v status=%q (restore columns must win)", got.RetiredAt, got.Enabled, got.Status)
	}
	if got.Description != "re-added" || got.IPAddress != "10.0.0.9" {
		t.Errorf("settings not applied: description=%q ip=%q", got.Description, got.IPAddress)
	}
}

// TestDeviceName_UniqueAmongActive pins the v0.11.241 name rule at the
// database layer (partial unique index idx_devices_name_active): a retired
// device's name is free for a new active device; a second ACTIVE device with
// the name is a unique violation; N retired rows may share the name with one
// active row; and RestoreDevice renames onto a free name in one statement
// while an active device holds the old name.
func TestDeviceName_UniqueAmongActive(t *testing.T) {
	d := NewDatabaseForTesting(t)

	a := &models.Device{Name: "FW", IPAddress: "10.0.0.1", Enabled: true}
	if err := d.CreateDevice(a); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := d.RetireDevice(a.ID); err != nil {
		t.Fatalf("retire A: %v", err)
	}
	a2 := &models.Device{Name: "FW", IPAddress: "10.0.0.2", Enabled: true}
	if err := d.CreateDevice(a2); err != nil {
		t.Fatalf("create A' with a retired device's name: %v", err)
	}
	a3 := &models.Device{Name: "FW", IPAddress: "10.0.0.3", Enabled: true}
	if err := d.CreateDevice(a3); !IsUniqueViolation(err) {
		t.Fatalf("second active A'' err = %v, want a unique violation", err)
	}
	if err := d.RetireDevice(a2.ID); err != nil {
		t.Fatalf("retire A': %v", err)
	}
	a4 := &models.Device{Name: "FW", IPAddress: "10.0.0.4", Enabled: true}
	if err := d.CreateDevice(a4); err != nil {
		t.Fatalf("create A''' with two retired namesakes: %v", err)
	}
	var retired, active int64
	d.db.Model(&models.Device{}).Where("name = ? AND retired_at IS NOT NULL", "FW").Count(&retired)
	d.db.Model(&models.Device{}).Where("name = ? AND retired_at IS NULL", "FW").Count(&active)
	if retired != 2 || active != 1 {
		t.Errorf("rows named FW: retired=%d active=%d, want 2/1", retired, active)
	}

	// Restore without a rename collides with the active A'''; with a rename it
	// lands — one statement, so the retired_at clear and the rename are atomic.
	if err := d.RestoreDevice(a.ID, nil); !IsUniqueViolation(err) {
		t.Fatalf("restore A while A''' is active err = %v, want a unique violation", err)
	}
	if got, _ := d.GetDevice(a.ID); got.RetiredAt == nil {
		t.Error("A restored despite the active namesake")
	}
	if err := d.RestoreDevice(a.ID, map[string]interface{}{"name": "FW-old"}); err != nil {
		t.Fatalf("restore A as FW-old: %v", err)
	}
	got, _ := d.GetDevice(a.ID)
	if got.RetiredAt != nil || !got.Enabled || got.Status != "unknown" || got.Name != "FW-old" {
		t.Errorf("restored A: retired_at=%v enabled=%v status=%q name=%q", got.RetiredAt, got.Enabled, got.Status, got.Name)
	}
}
