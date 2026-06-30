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
