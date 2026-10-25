package database

import (
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"

	"gorm.io/gorm/clause"
)

// The AuthManager prefers this durable guard whenever its database implements
// it; pin that *Database does, so a refactor cannot silently fall back to the
// per-process map.
var _ auth.TOTPReplayStore = (*Database)(nil)

// migrateUsedTOTPCodes (v83) creates used_totp_codes, the durable TOTP replay
// guard (D-14). A handful of rows per active 2FA user, each swept 90 s after
// it is written: no retention or partitioning needed.
func (d *Database) migrateUsedTOTPCodes() error {
	return d.db.AutoMigrate(&models.UsedTOTPCode{})
}

// ClaimTOTPCode records the TOTP code identified by keyHash as consumed until
// now+ttl and reports whether this call claimed it: false means the code was
// already used and is still inside its validity window (a replay). The insert
// is one statement with ON CONFLICT DO NOTHING, so of two concurrent claims —
// two requests, two processes, two API instances — exactly one wins. Expired
// rows are swept first, so a code value that comes round again after its
// window is claimable.
func (d *Database) ClaimTOTPCode(keyHash string, now time.Time, ttl time.Duration) (bool, error) {
	if err := d.db.Where("expires_at < ?", now.Unix()).Delete(&models.UsedTOTPCode{}).Error; err != nil {
		return false, err
	}
	res := d.db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&models.UsedTOTPCode{KeyHash: keyHash, ExpiresAt: now.Add(ttl).Unix()})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}
