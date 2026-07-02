package database

import (
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm/clause"
)

// UpsertThreatIntel inserts or updates a threat-intel feed entry, keyed by the
// unique (cidr, source) pair. On conflict it refreshes category/severity/
// last_seen/expires_at so a re-fed entry extends its lifetime. FirstSeen is set
// on insert and preserved on update.
func (d *Database) UpsertThreatIntel(e *models.ThreatIntel) error {
	now := time.Now().UTC()
	if e.FirstSeen.IsZero() {
		e.FirstSeen = now
	}
	if e.LastSeen.IsZero() {
		e.LastSeen = now
	}
	if e.Severity == "" {
		e.Severity = "warning"
	}
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "cidr"}, {Name: "source"}},
		DoUpdates: clause.AssignmentColumns([]string{"category", "severity", "last_seen", "expires_at"}),
	}).Create(e).Error
}

// UpsertThreatIntelBatch upserts many feed entries in batches (keyed on
// (cidr, source)), refreshing category/severity/last_seen/expires_at on conflict
// so re-fed indicators extend their lifetime. Used by the threat-feed poller,
// which can ingest tens of thousands of rows per cycle — far too many for the
// single-row UpsertThreatIntel.
func (d *Database) UpsertThreatIntelBatch(entries []models.ThreatIntel) error {
	if len(entries) == 0 {
		return nil
	}
	now := time.Now().UTC()

	// M5 of the 2026-07-01 audit: dedup by (cidr, source) BEFORE the upsert,
	// keeping the first occurrence. Feed normalization masks prefixes, so two
	// distinct feed lines (e.g. "203.0.113.4/24" and "203.0.113.200/24") — or
	// a plain repeated IP, common in aggregate lists — collapse to the same
	// conflict key. PostgreSQL rejects a statement where two inserted rows hit
	// the same ON CONFLICT target ("cannot affect row a second time") and
	// CreateInBatches wraps all chunks in ONE transaction, so a single in-batch
	// duplicate rolled back the WHOLE feed's upsert every sync; the feed's
	// indicators then TTL-expired out of the matcher with only a log line as
	// evidence. SQLite tolerates in-statement duplicates, which is why
	// dev/tests never caught it.
	seen := make(map[string]struct{}, len(entries))
	deduped := entries[:0]
	for i := range entries {
		key := entries[i].CIDR + "\x00" + entries[i].Source
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if entries[i].FirstSeen.IsZero() {
			entries[i].FirstSeen = now
		}
		if entries[i].LastSeen.IsZero() {
			entries[i].LastSeen = now
		}
		if entries[i].Severity == "" {
			entries[i].Severity = "warning"
		}
		deduped = append(deduped, entries[i])
	}

	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "cidr"}, {Name: "source"}},
		DoUpdates: clause.AssignmentColumns([]string{"category", "severity", "last_seen", "expires_at"}),
	}).CreateInBatches(deduped, 1000).Error
}

// PruneExpiredThreatIntel deletes threat-intel rows whose expiry has passed, so
// indicators that drop off their feed don't accumulate forever. Returns the
// number deleted. Rows with a NULL expires_at (e.g. permanent manual entries)
// are never touched.
func (d *Database) PruneExpiredThreatIntel() (int64, error) {
	res := d.db.Where("expires_at IS NOT NULL AND expires_at < ?", time.Now().UTC()).
		Delete(&models.ThreatIntel{})
	return res.RowsAffected, res.Error
}

// GetActiveThreatIntel returns all non-expired threat-intel rows, for building
// the in-memory matcher. "Active" means expires_at is NULL or in the future.
func (d *Database) GetActiveThreatIntel() ([]models.ThreatIntel, error) {
	var rows []models.ThreatIntel
	err := d.db.Where("expires_at IS NULL OR expires_at > ?", time.Now().UTC()).
		Find(&rows).Error
	return rows, err
}

// ListThreatIntel returns recent threat-intel rows for the admin UI/API,
// newest-first. limit <= 0 defaults to 500.
func (d *Database) ListThreatIntel(limit int) ([]models.ThreatIntel, error) {
	if limit <= 0 {
		limit = 500
	}
	var rows []models.ThreatIntel
	err := d.db.Order("created_at DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

// CountActiveThreatIntel returns the number of non-expired entries (status).
func (d *Database) CountActiveThreatIntel() (int64, error) {
	var n int64
	err := d.db.Model(&models.ThreatIntel{}).
		Where("expires_at IS NULL OR expires_at > ?", time.Now().UTC()).
		Count(&n).Error
	return n, err
}

// DeleteThreatIntel removes one entry by id. Missing id is a no-op (not an error).
func (d *Database) DeleteThreatIntel(id uint) error {
	return d.db.Where("id = ?", id).Delete(&models.ThreatIntel{}).Error
}
