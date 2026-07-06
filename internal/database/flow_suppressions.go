package database

import (
	"net"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// normalizeSrc canonicalizes a source IP so lookups match regardless of the
// textual form the detector recorded (e.g. IPv6 case/zero-compression). Returns
// the input unchanged when it isn't a parseable IP (defensive — callers already
// validate).
func normalizeSrc(src string) string {
	if ip := net.ParseIP(src); ip != nil {
		return ip.String()
	}
	return src
}

// SuppressFlowSource silences an attacking source until `until` (v0.11.46). Upsert
// on the unique src_addr: an existing row's window EXTENDS (never shortens), so
// re-silencing a still-suppressed source with a longer window works and a shorter
// one is a no-op. by/reason are audit fields.
func (d *Database) SuppressFlowSource(src string, until time.Time, by, reason string) error {
	src = normalizeSrc(src)
	row := models.FlowSourceSuppression{
		SrcAddr:          src,
		SuppressedUntil:  until.UTC(),
		SuppressedBy:     by,
		SuppressedReason: reason,
	}
	// ON CONFLICT(src_addr): extend to the later of the two windows and refresh
	// the audit fields. The "later of two scalars" function differs by dialect —
	// PG's MAX is an aggregate, so it needs GREATEST; SQLite's MAX() is scalar.
	extend := "MAX(flow_source_suppressions.suppressed_until, excluded.suppressed_until)"
	if d.dialect.IsPostgres() {
		extend = "GREATEST(flow_source_suppressions.suppressed_until, excluded.suppressed_until)"
	}
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "src_addr"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"suppressed_until":  gorm.Expr(extend),
			"suppressed_by":     by,
			"suppressed_reason": reason,
		}),
	}).Create(&row).Error
}

// IsFlowSourceSuppressed reports whether src has an active suppression at ref.
// Single-source point check for the API path; the poller loads the whole active
// set once per cycle via ListActiveFlowSuppressions instead (a storm has hundreds
// of distinct sources — per-source queries would be a per-cycle storm of reads).
func (d *Database) IsFlowSourceSuppressed(src string, ref time.Time) (bool, error) {
	src = normalizeSrc(src)
	var cnt int64
	err := d.db.Model(&models.FlowSourceSuppression{}).
		Where("src_addr = ? AND suppressed_until > ?", src, ref.UTC()).
		Count(&cnt).Error
	return cnt > 0, err
}

// ListActiveFlowSuppressions returns every suppression whose window has not yet
// expired, newest-expiring first (for the admin "Silenced sources" panel and the
// poller's per-cycle in-memory set).
func (d *Database) ListActiveFlowSuppressions() ([]models.FlowSourceSuppression, error) {
	var rows []models.FlowSourceSuppression
	err := d.db.Where("suppressed_until > ?", time.Now().UTC()).
		Order("suppressed_until DESC").Find(&rows).Error
	return rows, err
}

// DeleteFlowSuppression removes a suppression by id (operator un-silence).
func (d *Database) DeleteFlowSuppression(id uint) error {
	return d.db.Delete(&models.FlowSourceSuppression{}, id).Error
}

// PruneExpiredFlowSuppressions deletes suppressions whose window has fully
// elapsed. Called from CleanupOldData so the table stays tiny.
func (d *Database) PruneExpiredFlowSuppressions() error {
	return d.db.Where("suppressed_until <= ?", time.Now().UTC()).
		Delete(&models.FlowSourceSuppression{}).Error
}
