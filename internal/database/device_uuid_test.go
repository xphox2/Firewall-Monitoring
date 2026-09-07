package database

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"

	"github.com/google/uuid"
)

// deviceUUIDs returns id → uuid for every devices row, straight from the
// table (no model hook, no decrypt), so a test sees exactly what is stored.
func deviceUUIDs(t *testing.T, d *Database) map[uint]string {
	t.Helper()
	var rows []struct {
		ID   uint
		UUID *string
	}
	if err := d.db.Raw(`SELECT id, uuid FROM devices ORDER BY id`).Scan(&rows).Error; err != nil {
		t.Fatalf("select uuids: %v", err)
	}
	out := map[uint]string{}
	for _, r := range rows {
		if r.UUID == nil {
			out[r.ID] = ""
			continue
		}
		out[r.ID] = *r.UUID
	}
	return out
}

// assertDistinctUUIDs fails unless every value is a well-formed UUID and no
// two rows share one.
func assertDistinctUUIDs(t *testing.T, got map[uint]string) {
	t.Helper()
	seen := map[string]uint{}
	for id, u := range got {
		if _, err := uuid.Parse(u); err != nil || len(u) != 36 {
			t.Errorf("device %d uuid = %q, want a 36-char UUID (%v)", id, u, err)
		}
		if other, dup := seen[u]; dup {
			t.Errorf("devices %d and %d share uuid %q", other, id, u)
		}
		seen[u] = id
	}
}

// TestDeviceUUID_BeforeCreateMints: two raw db.Create calls without a UUID
// (the shape 28 test sites use) succeed with distinct values — the hook is
// what keeps the unique index from rejecting the second empty string — and CreateDevice
// mints through the same path. A caller-supplied UUID is kept.
func TestDeviceUUID_BeforeCreateMints(t *testing.T) {
	d := NewDatabaseForTesting(t)

	a := &models.Device{Name: "raw-a", IPAddress: "10.0.0.1"}
	b := &models.Device{Name: "raw-b", IPAddress: "10.0.0.2"}
	for _, dev := range []*models.Device{a, b} {
		if err := d.db.Create(dev).Error; err != nil {
			t.Fatalf("raw create %s: %v", dev.Name, err)
		}
	}
	if a.UUID == "" || b.UUID == "" || a.UUID == b.UUID {
		t.Fatalf("raw creates: uuids %q / %q, want two distinct non-empty values", a.UUID, b.UUID)
	}

	c := &models.Device{Name: "via-create", IPAddress: "10.0.0.3", SNMPCommunity: "s"}
	if err := d.CreateDevice(c); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if c.UUID == "" {
		t.Error("CreateDevice left the uuid empty")
	}

	pinned := uuid.NewString()
	p := &models.Device{Name: "pinned", IPAddress: "10.0.0.4", UUID: pinned}
	if err := d.db.Create(p).Error; err != nil {
		t.Fatalf("create with a supplied uuid: %v", err)
	}
	if p.UUID != pinned {
		t.Errorf("supplied uuid replaced: %q → %q", pinned, p.UUID)
	}

	got := deviceUUIDs(t, d)
	if len(got) != 4 {
		t.Fatalf("rows = %d, want 4", len(got))
	}
	assertDistinctUUIDs(t, got)
	for _, dev := range []*models.Device{a, b, c, p} {
		if got[dev.ID] != dev.UUID {
			t.Errorf("device %d stored uuid %q != struct %q", dev.ID, got[dev.ID], dev.UUID)
		}
	}
}

// TestDeviceUUID_UniqueIndex: the model tag produces a UNIQUE index on the
// column, and a second row with the same uuid is refused.
func TestDeviceUUID_UniqueIndex(t *testing.T) {
	d := NewDatabaseForTesting(t)
	idx := deviceIndexSQL(t, d)
	sql, ok := idx["idx_devices_uuid"]
	if !ok {
		t.Fatalf("idx_devices_uuid missing; devices indexes = %v", idx)
	}
	if !strings.Contains(strings.ToUpper(sql), "UNIQUE") {
		t.Errorf("idx_devices_uuid = %q, want a UNIQUE index", sql)
	}

	u := uuid.NewString()
	if err := d.db.Create(&models.Device{Name: "one", IPAddress: "10.0.0.1", UUID: u}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.db.Create(&models.Device{Name: "two", IPAddress: "10.0.0.2", UUID: u}).Error; !IsUniqueViolation(err) {
		t.Errorf("duplicate uuid err = %v, want a unique violation", err)
	}
}

// TestDeviceUUID_UpdateDeviceKeepsStored: a Save through UpdateDevice never
// blanks or replaces the stored UUID — neither from a struct built without
// one (the load-then-save shape) nor from one carrying a different value.
func TestDeviceUUID_UpdateDeviceKeepsStored(t *testing.T) {
	d := NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", Enabled: true}
	if err := d.CreateDevice(dev); err != nil {
		t.Fatalf("create: %v", err)
	}
	stored := dev.UUID

	blank := &models.Device{ID: dev.ID, Name: "fw", IPAddress: "10.0.0.9", Enabled: true}
	if err := d.UpdateDevice(blank); err != nil {
		t.Fatalf("UpdateDevice with a zero uuid: %v", err)
	}
	got, err := d.GetDevice(dev.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.UUID != stored {
		t.Errorf("uuid after zero-uuid Save = %q, want the stored %q", got.UUID, stored)
	}
	if got.IPAddress != "10.0.0.9" {
		t.Errorf("Save did not apply the other columns: ip = %q", got.IPAddress)
	}

	changed := &models.Device{ID: dev.ID, Name: "fw", IPAddress: "10.0.0.9", Enabled: true, UUID: uuid.NewString()}
	if err := d.UpdateDevice(changed); err != nil {
		t.Fatalf("UpdateDevice with a different uuid: %v", err)
	}
	if got, _ := d.GetDevice(dev.ID); got.UUID != stored {
		t.Errorf("uuid after a different-uuid Save = %q, want the stored %q", got.UUID, stored)
	}
}

// TestMigrateDeviceUUID: the v64 body backfills a NULL row (raw INSERT that
// does not name the column, as v61 does), an empty-string row and leaves a
// hook-minted row alone; every value is distinct afterwards and a rerun
// changes nothing.
func TestMigrateDeviceUUID(t *testing.T) {
	d := NewDatabaseForTesting(t)

	minted := &models.Device{Name: "minted", IPAddress: "10.0.0.1"}
	if err := d.db.Create(minted).Error; err != nil {
		t.Fatalf("create minted: %v", err)
	}
	// v61 shape: explicit column list without uuid → NULL.
	if err := d.db.Exec(`INSERT INTO devices (id, name, ip_address, snmp_port, snmp_version, enabled, public_visible, vendor,
		wan_speed_mbps, sslvpn_users, sslvpn_tunnels, ssh_port, ssh_poll_enabled, ssh_poll_interval, api_port, api_insecure_tls,
		created_at, updated_at, status, retired_at)
		VALUES (77, 'orphan', '0.0.0.0', 161, '2c', ?, ?, 'fortigate', 1000, 0, 0, 22, ?, 900, 443, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'offline', CURRENT_TIMESTAMP)`,
		false, false, false, false).Error; err != nil {
		t.Fatalf("raw insert without uuid: %v", err)
	}
	if err := d.db.Exec(`INSERT INTO devices (id, name, ip_address, uuid, created_at, updated_at) VALUES (78, 'blank', '10.0.0.3', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatalf("raw insert with empty uuid: %v", err)
	}
	before := deviceUUIDs(t, d)
	if before[77] != "" || before[78] != "" {
		t.Fatalf("test setup: raw rows should have no uuid, got %q / %q", before[77], before[78])
	}
	var updatedBefore string
	d.db.Raw(`SELECT updated_at FROM devices WHERE id = 77`).Scan(&updatedBefore)

	if err := d.migrateDeviceUUID(); err != nil {
		t.Fatalf("migrate v64: %v", err)
	}
	after := deviceUUIDs(t, d)
	if len(after) != 3 {
		t.Fatalf("rows = %d, want 3", len(after))
	}
	assertDistinctUUIDs(t, after)
	if after[minted.ID] != minted.UUID {
		t.Errorf("hook-minted uuid rewritten: %q → %q", minted.UUID, after[minted.ID])
	}
	var updatedAfter string
	d.db.Raw(`SELECT updated_at FROM devices WHERE id = 77`).Scan(&updatedAfter)
	if updatedAfter != updatedBefore {
		t.Errorf("backfill touched updated_at: %q → %q", updatedBefore, updatedAfter)
	}

	if err := d.migrateDeviceUUID(); err != nil {
		t.Fatalf("rerun v64: %v", err)
	}
	again := deviceUUIDs(t, d)
	for id, u := range after {
		if again[id] != u {
			t.Errorf("rerun changed device %d uuid %q → %q", id, u, again[id])
		}
	}
}
