//go:build integration

// The raw archive's admin-UI settings (A-10) on a real PostgreSQL: the
// settings round trip (the secret encrypted at rest), and the retention gate
// following an admin's stream switch at runtime through the real delete path.
// Synthetic data only (RFC 5737, fw-example-NN).
package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestArchiveSettings_PG(t *testing.T) {
	ctx := context.Background()
	d := NewIntegrationDB(t)
	if !d.CanEncryptSettings() {
		d.SetEncryptionKeyForTesting("archive-settings-pg-key")
	}
	env := archiveEnvForTest()
	if err := d.SaveArchiveSettings(ctx, map[string]string{
		"ARCHIVE_S3_BUCKET": "example-bucket-ui", "ARCHIVE_S3_SECRET_ACCESS_KEY": "fake-ui-secret", "ARCHIVE_WINDOW": "",
	}, nil, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := d.db.Raw(`SELECT value FROM system_settings WHERE "key" = ?`, ArchiveSecretSettingKey).Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "{enc}") || strings.Contains(stored, "fake-ui-secret") {
		t.Fatalf("secret stored as %q", stored)
	}
	res, err := d.ResolveArchiveConfig(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.Bucket != "example-bucket-ui" || res.Config.SecretAccessKey.Reveal() != "fake-ui-secret" || res.Config.Prefix != env.Prefix || !res.UI["ARCHIVE_WINDOW"] {
		t.Fatalf("resolved %+v %v", res.Config, res.UI)
	}
	if err := d.SaveArchiveSettings(ctx, nil, []string{"ARCHIVE_S3_BUCKET", "ARCHIVE_S3_SECRET_ACCESS_KEY"}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if res, _ = d.ResolveArchiveConfig(ctx, env); res.Config.Bucket != env.Bucket || res.Config.SecretAccessKey.Reveal() != "fake-env-secret" {
		t.Fatalf("after revert: %q", res.Config.Bucket)
	}
}

// TestArchiveGate_AdminSwitch_PG: the environment leaves syslog off; an admin
// switches it on and the next retention pass after the cache TTL holds every
// row (no chunk verified: V = 0); switched off, the pass after the TTL deletes
// them, with the disabled interval recorded.
func TestArchiveGate_AdminSwitch_PG(t *testing.T) {
	ctx := context.Background()
	d := NewIntegrationDB(t)
	clock := time.Now()
	orig := archiveGateClock
	archiveGateClock = func() time.Time { return clock }
	t.Cleanup(func() { archiveGateClock = orig })
	ret := gateFixture(t, d)
	seedGateChunks(t, d, "syslog_messages", gateChunk{1, 0, 0, models.ArchiveChunkPending})
	if err := d.RecordArchiveGateState(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "true"}, nil, nil, clock); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(archiveGateCacheTTL + time.Second)
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatal(err)
	}
	if got := gateIDs(t, d, "syslog_messages"); len(got) != 20 {
		t.Fatalf("switched on: %d syslog rows left, want all 20 held", len(got))
	}
	if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false"}, nil, []string{ArchiveGateSyslog}, clock); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(archiveGateCacheTTL + time.Second)
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatal(err)
	}
	if got := gateIDs(t, d, "syslog_messages"); len(got) != 0 {
		t.Fatalf("switched off: %d syslog rows left, want none", len(got))
	}
	var open int64
	d.db.Model(&models.ArchiveGateEvent{}).Where("stream = ? AND kind = ? AND to_ts IS NULL", ArchiveGateSyslog, models.ArchiveGateEventDisabled).Count(&open)
	if open != 1 {
		t.Fatalf("open disabled intervals = %d, want 1", open)
	}
}
