package database

import (
	"time"

	"firewall-mon/internal/models"
)

// L2 topology evidence storage (relay schema v5). topology_entries and
// topology_neighbors are STATE tables: each relayed batch is the device's
// complete snapshot for the entry types / protocols it contains, so saving
// REPLACES those scopes in one transaction (delete + insert). An UPSERT would
// never remove aged-out rows — a MAC that moved ports would keep drawing a
// stale link — and time-series retention would balloon on multi-thousand-row
// FDB tables. Replay of an identical batch (probe retry) reproduces the
// identical end state; ordering protection against OLD snapshots is handled
// collector-side (topology sends are never spooled).

// SaveTopologyEntriesSnapshot replaces each device's ARP/FDB snapshot with the
// rows in this batch, scoped to the (device_id, entry_type) pairs present —
// an ARP-only batch (e.g. the FortiGate SSH supplement) never wipes FDB rows.
func (d *Database) SaveTopologyEntriesSnapshot(entries []models.TopologyEntry) error {
	if len(entries) == 0 {
		return nil
	}
	type scope struct {
		deviceID  uint
		entryType string
	}
	scopes := map[scope]bool{}
	for _, e := range entries {
		scopes[scope{e.DeviceID, e.EntryType}] = true
	}
	tx := d.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	for s := range scopes {
		if err := tx.Where("device_id = ? AND entry_type = ?", s.deviceID, s.entryType).
			Delete(&models.TopologyEntry{}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.CreateInBatches(entries, 500).Error; err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// SaveTopologyNeighborsSnapshot replaces each device's LLDP/CDP neighbor
// snapshot, scoped to the (device_id, protocol) pairs present in the batch.
func (d *Database) SaveTopologyNeighborsSnapshot(neighbors []models.TopologyNeighbor) error {
	if len(neighbors) == 0 {
		return nil
	}
	type scope struct {
		deviceID uint
		protocol string
	}
	scopes := map[scope]bool{}
	for _, n := range neighbors {
		scopes[scope{n.DeviceID, n.Protocol}] = true
	}
	tx := d.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	for s := range scopes {
		if err := tx.Where("device_id = ? AND protocol = ?", s.deviceID, s.protocol).
			Delete(&models.TopologyNeighbor{}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.CreateInBatches(neighbors, 500).Error; err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// GetTopologyEntriesSince returns topology entries fresher than the cutoff,
// optionally filtered to a MAC allow-list (pre-lowercased — topology rows are
// stored lowercase). The poller passes the monitored devices' interface MACs
// here so multi-thousand-row FDB tables are filtered in SQL, not in Go.
func (d *Database) GetTopologyEntriesSince(cutoff time.Time, ownedMACs []string) ([]models.TopologyEntry, error) {
	var entries []models.TopologyEntry
	q := d.db.Where("timestamp >= ?", cutoff)
	if ownedMACs != nil {
		q = q.Where("mac_address IN ?", ownedMACs)
	}
	err := q.Find(&entries).Error
	return entries, err
}

// GetTopologyNeighborsSince returns LLDP/CDP neighbor rows fresher than the
// cutoff (neighbor tables are small — no further filtering needed).
func (d *Database) GetTopologyNeighborsSince(cutoff time.Time) ([]models.TopologyNeighbor, error) {
	var neighbors []models.TopologyNeighbor
	err := d.db.Where("timestamp >= ?", cutoff).Find(&neighbors).Error
	return neighbors, err
}

// GetTopologyEntriesByDevice returns one device's current topology snapshot
// (connection-detail evidence view).
func (d *Database) GetTopologyEntriesByDevice(deviceID uint) ([]models.TopologyEntry, error) {
	var entries []models.TopologyEntry
	err := d.db.Where("device_id = ?", deviceID).Find(&entries).Error
	return entries, err
}
