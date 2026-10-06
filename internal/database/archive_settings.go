package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The raw archive's admin-UI settings (A-10). Each ARCHIVE_* key may be
// stored in system_settings under config.ArchiveField.Setting(); a stored row
// wins over the environment, an absent one leaves the environment's value
// (config.ArchiveConfig.WithSettings). A row exists only while the admin form
// sets the field: "revert to the environment default" deletes it, so even an
// empty string (an empty ARCHIVE_WINDOW, say) can be an admin value.
//
// The secret access key is a SecretSettingKeys member: encrypted at rest
// (EncryptField), masked by GET /admin/api/settings, upgraded by the startup
// backfill. The generic settings save does not accept any of these keys; only
// the archive settings route (password + TOTP) writes them.

// ArchiveSecretSettingKey is the system_settings key of the secret access key.
const ArchiveSecretSettingKey = "archive_s3_secret_access_key" // #nosec G101 -- a settings key name, not a credential

// archiveSettingKeys are the system_settings keys of every archive field.
func archiveSettingKeys(fields []config.ArchiveField) []string {
	keys := make([]string, 0, len(fields))
	for _, f := range fields {
		keys = append(keys, f.Setting())
	}
	return keys
}

// archiveSettingValues reads the stored admin values of fields: ARCHIVE_* key
// → value, the secret decrypted. problems names a stored secret that no
// longer decrypts (the encryption key changed): it resolves as unset, and the
// caller makes the configuration refuse it.
func (d *Database) archiveSettingValues(ctx context.Context, fields []config.ArchiveField) (vals map[string]string, problems []string, err error) {
	var rows []models.SystemSetting
	if err := d.db.WithContext(ctx).Where("\"key\" IN ?", archiveSettingKeys(fields)).Find(&rows).Error; err != nil {
		return nil, nil, fmt.Errorf("read the archive settings: %w", err)
	}
	byKey := make(map[string]string, len(rows))
	for _, r := range rows {
		byKey[r.Key] = r.Value
	}
	vals = map[string]string{}
	for _, f := range fields {
		v, ok := byKey[f.Setting()]
		if !ok {
			continue
		}
		if f.Kind == config.ArchiveKindSecret {
			if v == "" {
				continue
			}
			plain := d.DecryptField(v)
			if plain == "" {
				problems = append(problems, f.Env+" stored on the admin page cannot be decrypted with this server's encryption key; enter it again")
				continue
			}
			v = plain
		}
		vals[f.Env] = v
	}
	return vals, problems, nil
}

// ArchiveResolution is the archive configuration in effect and where each
// value came from.
type ArchiveResolution struct {
	Config config.ArchiveConfig
	// UI lists the ARCHIVE_* keys an admin setting supplies.
	UI map[string]bool
}

// ResolveArchiveConfig is env (the environment's archive configuration) with
// the admin settings applied. Every reader of the archive configuration goes
// through it: the poller's workers each tick, the retention gate (enable
// switches only, cached briefly), the status and restore routes, the CLI.
func (d *Database) ResolveArchiveConfig(ctx context.Context, env config.ArchiveConfig) (ArchiveResolution, error) {
	vals, problems, err := d.archiveSettingValues(ctx, config.ArchiveFields)
	if err != nil {
		return ArchiveResolution{Config: env}, err
	}
	res := ArchiveResolution{Config: env.WithSettings(vals), UI: map[string]bool{}}
	for k := range vals {
		res.UI[k] = true
	}
	for _, p := range problems {
		res.Config = res.Config.WithProblem(p)
	}
	return res, nil
}

// ArchiveHasChunks reports whether the archive has cut any chunk: from then
// on its objects' location (endpoint, bucket, prefix) is fixed.
func (d *Database) ArchiveHasChunks(ctx context.Context) (bool, error) {
	var ids []uint
	if err := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).Limit(1).Pluck("id", &ids).Error; err != nil {
		return false, fmt.Errorf("read the archive manifest: %w", err)
	}
	return len(ids) > 0, nil
}

// CanEncryptSettings reports whether this server has an encryption key, so a
// secret setting is stored encrypted rather than as plaintext.
func (d *Database) CanEncryptSettings() bool { return len(d.encKeys.current) > 0 }

// SaveArchiveSettings applies one admin save in a single transaction: set
// stores ARCHIVE_* key → value (the secret encrypted), revert deletes the
// keys' rows (the environment applies again), and each stream in disabled —
// switched off by this save — gets its "disabled" interval opened now, as the
// poller does at start (only once the stream has chunks), so the months it
// affects are sealed partial. The caller has validated everything.
func (d *Database) SaveArchiveSettings(ctx context.Context, set map[string]string, revert []string, disabled []string, now time.Time) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for env, v := range set {
			f, ok := config.ArchiveFieldByEnv(env)
			if !ok {
				return fmt.Errorf("unknown archive setting %q", env)
			}
			row := models.SystemSetting{Key: f.Setting()}
			if err := tx.FirstOrCreate(&row, models.SystemSetting{Key: f.Setting()}).Error; err != nil {
				return fmt.Errorf("upsert %s: %w", f.Setting(), err)
			}
			row.Value, row.Type, row.Category = v, f.Kind, "archive"
			row.Label = "Raw archive: " + f.Env + " (admin setting; the environment value is the default)"
			if f.Kind == config.ArchiveKindSecret {
				row.Value, row.IsSecret = d.EncryptField(v), true
			}
			if err := tx.Save(&row).Error; err != nil {
				return fmt.Errorf("save %s: %w", f.Setting(), err)
			}
		}
		for _, env := range revert {
			f, ok := config.ArchiveFieldByEnv(env)
			if !ok {
				return fmt.Errorf("unknown archive setting %q", env)
			}
			if err := tx.Where("\"key\" = ?", f.Setting()).Delete(&models.SystemSetting{}).Error; err != nil {
				return fmt.Errorf("revert %s: %w", f.Setting(), err)
			}
		}
		for _, stream := range disabled {
			if archiveGateTables(stream) == nil {
				return fmt.Errorf("archive: unknown stream %q", stream)
			}
			if err := recordArchiveDisabledTx(tx, stream, now.UTC()); err != nil {
				return err
			}
		}
		return nil
	})
}

// ArchiveStreamEnabled reports whether gate stream's archiving is on in a.
func ArchiveStreamEnabled(a config.ArchiveConfig, stream string) bool {
	switch strings.ToLower(stream) {
	case ArchiveGateSyslog:
		return a.SyslogEnabled
	case ArchiveGateFlows:
		return a.FlowsEnabled
	}
	return false
}

// ArchiveLocationKey is the system_settings key holding the location
// (config.ArchiveConfig.Location) the archive's chunks were written to.
const ArchiveLocationKey = "archive_location"

// CheckArchiveLocation compares loc, the location the worker is about to
// write to, with the one recorded for the archive's chunks. While there is no
// chunk the record follows loc; once chunks exist it is kept (an install from
// before 0.11.310 records loc on its first check). mismatch: chunks exist and
// were recorded at recorded, not at loc — the environment changed under them
// (the admin form refuses such a change).
func (d *Database) CheckArchiveLocation(ctx context.Context, loc string) (recorded string, mismatch bool, err error) {
	has, err := d.ArchiveHasChunks(ctx)
	if err != nil {
		return "", false, err
	}
	var rows []models.SystemSetting
	if err := d.db.WithContext(ctx).Where("\"key\" = ?", ArchiveLocationKey).Limit(1).Find(&rows).Error; err != nil {
		return "", false, fmt.Errorf("read %s: %w", ArchiveLocationKey, err)
	}
	if has && len(rows) > 0 {
		return rows[0].Value, rows[0].Value != loc, nil
	}
	if len(rows) > 0 && rows[0].Value == loc {
		return loc, false, nil
	}
	row := models.SystemSetting{Key: ArchiveLocationKey}
	if err := d.db.WithContext(ctx).FirstOrCreate(&row, models.SystemSetting{Key: ArchiveLocationKey}).Error; err != nil {
		return "", false, fmt.Errorf("record %s: %w", ArchiveLocationKey, err)
	}
	row.Value, row.Type, row.Category = loc, "string", "archive"
	row.Label = "Raw archive: where its chunks are written (endpoint/bucket/prefix)"
	return loc, false, d.db.WithContext(ctx).Save(&row).Error
}
