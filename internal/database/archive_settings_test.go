package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// The raw archive's admin-UI settings (A-10) on the SQLite lane: resolution
// over the environment, the transactional save, and the retention gate picking
// a switch up while the process runs. Synthetic fixtures only.

func archiveEnvForTest() config.ArchiveConfig {
	return config.ArchiveConfig{Endpoint: "https://s3.example.com", Region: "us-east-005", Bucket: "example-bucket-env",
		Prefix: "fwmon-env", AccessKeyID: "005exampleKeyID", SecretAccessKey: config.Secret("fake-env-secret"),
		PathStyle: true, MinAgeHours: 2, SealGraceHours: 48, SealReverify: config.SealReverifyHead,
		SyslogRateRowsPerSec: 5000, FlowRateRowsPerSec: 20000, StagingDir: "/var/lib/fwmon/archive-staging"}
}

// TestResolveArchiveConfig_Precedence: no row = the environment's value; a
// stored row wins (the secret decrypted, stored encrypted); a revert brings
// the environment back; a secret that no longer decrypts is unset and makes
// an enabled configuration invalid.
func TestResolveArchiveConfig_Precedence(t *testing.T) {
	ctx := context.Background()
	d := NewDatabaseForTesting(t)
	d.SetEncryptionKeyForTesting("archive-settings-test-key")
	env := archiveEnvForTest()

	res, err := d.ResolveArchiveConfig(ctx, env)
	if err != nil || len(res.UI) != 0 || res.Config.Bucket != "example-bucket-env" || res.Config.SecretAccessKey.Reveal() != "fake-env-secret" {
		t.Fatalf("no admin settings: %+v %v", res, err)
	}
	if err := d.SaveArchiveSettings(ctx, map[string]string{
		"ARCHIVE_S3_BUCKET": "example-bucket-ui", "ARCHIVE_S3_SECRET_ACCESS_KEY": "fake-ui-secret",
		"ARCHIVE_SYSLOG_ENABLED": "true", "ARCHIVE_WINDOW": "",
	}, nil, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	var row models.SystemSetting
	if err := d.db.Where("\"key\" = ?", ArchiveSecretSettingKey).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.Value, "{enc}") || !row.IsSecret || strings.Contains(row.Value, "fake-ui-secret") {
		t.Fatalf("secret stored as %q (is_secret %v), want encrypted", row.Value, row.IsSecret)
	}
	res, err = d.ResolveArchiveConfig(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	a := res.Config
	if a.Bucket != "example-bucket-ui" || a.SecretAccessKey.Reveal() != "fake-ui-secret" || !a.SyslogEnabled ||
		a.Prefix != "fwmon-env" || !res.UI["ARCHIVE_S3_BUCKET"] || res.UI["ARCHIVE_S3_PREFIX"] || !res.UI["ARCHIVE_WINDOW"] {
		t.Fatalf("resolved %+v ui %v", a, res.UI)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if err := d.SaveArchiveSettings(ctx, nil, []string{"ARCHIVE_S3_BUCKET"}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if res, _ = d.ResolveArchiveConfig(ctx, env); res.Config.Bucket != "example-bucket-env" || res.UI["ARCHIVE_S3_BUCKET"] {
		t.Fatalf("after revert: bucket %q ui %v", res.Config.Bucket, res.UI)
	}

	d.SetEncryptionKeyForTesting("a-different-key") // the server's key changed
	res, err = d.ResolveArchiveConfig(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.SecretAccessKey.Reveal() == "fake-ui-secret" || res.UI["ARCHIVE_S3_SECRET_ACCESS_KEY"] {
		t.Fatalf("an undecryptable secret resolved: %+v", res.UI)
	}
	if err := res.Config.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Fatalf("Validate with an undecryptable secret: %v", err)
	}
}

// TestSaveArchiveSettings_DisabledInterval: switching a stream off opens its
// disabled interval in the save's transaction once the stream has chunks
// (not before: nothing was archived), and only one.
func TestSaveArchiveSettings_DisabledInterval(t *testing.T) {
	ctx := context.Background()
	d := NewDatabaseForTesting(t)
	at := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	events := func() []models.ArchiveGateEvent {
		var evs []models.ArchiveGateEvent
		d.db.Where("kind = ?", models.ArchiveGateEventDisabled).Find(&evs)
		return evs
	}
	if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false"}, nil, []string{ArchiveGateSyslog}, at); err != nil {
		t.Fatal(err)
	}
	if evs := events(); len(evs) != 0 {
		t.Fatalf("no chunks yet, but %d disabled events", len(evs))
	}
	seedGateChunks(t, d, export.TableSyslog, gateChunk{1, 0, 10, models.ArchiveChunkVerified})
	for range 2 {
		if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false"}, nil, []string{ArchiveGateSyslog}, at); err != nil {
			t.Fatal(err)
		}
	}
	if evs := events(); len(evs) != 1 || evs[0].Stream != ArchiveGateSyslog || !evs[0].From.Equal(at) || evs[0].To != nil {
		t.Fatalf("disabled events %+v, want one open from the save", evs)
	}
	if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_NOT_A_KEY": "1"}, nil, nil, at); err == nil {
		t.Fatal("an unknown key was saved")
	}
	if has, err := d.ArchiveHasChunks(ctx); err != nil || !has {
		t.Fatalf("ArchiveHasChunks = %v, %v", has, err)
	}
}

// archiveSwitchFixture is a database whose gate caches the switches (as
// Connect builds it), with the clock under the test's control.
func archiveSwitchFixture(t *testing.T) (*Database, *time.Time) {
	t.Helper()
	d := NewDatabaseForTesting(t)
	d.archiveGateCache = &archiveGateCacheState{}
	clock := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	orig := archiveGateClock
	archiveGateClock = func() time.Time { return clock }
	t.Cleanup(func() { archiveGateClock = orig })
	return d, &clock
}

// TestArchiveGate_AdminSwitchHotReload: the environment leaves syslog off; an
// admin switches it on, then off again, while the poller runs. The gate
// notices within the cache TTL (not before: one resolution per TTL), ends the
// disabled interval when the stream comes on, and opens one when it goes off.
func TestArchiveGate_AdminSwitchHotReload(t *testing.T) {
	ctx := context.Background()
	d, clock := archiveSwitchFixture(t)
	seedGateChunks(t, d, export.TableSyslog, gateChunk{1, 0, 10, models.ArchiveChunkVerified})
	if err := d.RecordArchiveGateState(ctx); err != nil { // the poller's start: disabled, with chunks
		t.Fatal(err)
	}
	open := func() []models.ArchiveGateEvent {
		var evs []models.ArchiveGateEvent
		d.db.Where("stream = ? AND kind = ? AND to_ts IS NULL", ArchiveGateSyslog, models.ArchiveGateEventDisabled).Find(&evs)
		return evs
	}
	if len(open()) != 1 || d.archiveGate(ctx, export.TableSyslog).on {
		t.Fatal("start: want syslog ungated with an open disabled interval")
	}

	if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "true"}, nil, nil, *clock); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(archiveGateCacheTTL / 2)
	if d.archiveGate(ctx, export.TableSyslog).on {
		t.Fatal("re-resolved before the cache TTL")
	}
	*clock = clock.Add(archiveGateCacheTTL)
	if g := d.archiveGate(ctx, export.TableSyslog); !g.on || g.v != 10 {
		t.Fatalf("after the TTL the admin switch must gate syslog: %+v", g)
	}
	if evs := open(); len(evs) != 0 {
		t.Fatalf("the disabled interval is still open after the stream came on: %+v", evs)
	}

	disabledAt := clock.Add(time.Minute)
	*clock = disabledAt
	if err := d.SaveArchiveSettings(ctx, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false"}, nil, nil, *clock); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(archiveGateCacheTTL + time.Second)
	if d.archiveGate(ctx, export.TableSyslog).on {
		t.Fatal("still gated after the admin switched syslog off")
	}
	if evs := open(); len(evs) != 1 || evs[0].From.Before(disabledAt) {
		t.Fatalf("switching off at runtime: open disabled intervals %+v, want one from the switch", evs)
	}
}

// TestArchiveGate_EnabledMidPass: a stream switched on while a retention pass
// runs gates that pass's next batch (the switch is resolved per batch, not
// once per pass).
func TestArchiveGate_EnabledMidPass(t *testing.T) {
	d, clock := archiveSwitchFixture(t)
	gateFixture(t, d)
	if err := d.RecordArchiveGateState(context.Background()); err != nil { // caches "off"
		t.Fatal(err)
	}
	// The admin's save lands just as the pass starts: its first batch still
	// sees the cached "off"; the cache expires during that batch (the hook
	// runs inside the batch's transaction, so it only moves the clock).
	if err := d.SaveArchiveSettings(context.Background(), map[string]string{"ARCHIVE_SYSLOG_ENABLED": "true"}, nil, nil, *clock); err != nil {
		t.Fatal(err)
	}
	origBatch, origSleep := cleanupDeleteBatchSize, batchDeleteInterSleep
	cleanupDeleteBatchSize, batchDeleteInterSleep = 4, 0
	calls := 0
	cleanupBatchHook = func(int) error {
		if calls++; calls == 1 {
			*clock = clock.Add(archiveGateCacheTTL + time.Second)
		}
		return nil
	}
	t.Cleanup(func() { cleanupDeleteBatchSize, batchDeleteInterSleep, cleanupBatchHook = origBatch, origSleep, nil })
	if err := d.batchedDeleteOlderThanGated(&models.SyslogMessage{}, "syslog_messages", time.Now(), d.archiveGateFn("syslog_messages"), ""); err != nil {
		t.Fatal(err)
	}
	if got := gateIDs(t, d, "syslog_messages"); !sameIDs(got, idRange(5, 20)) {
		t.Fatalf("syslog ids %v, want 5..20: one ungated batch of 4, then gated with V = 0", got)
	}
}

// TestArchiveGate_SwitchReadFailsClosed: when the switches cannot be read
// before any read succeeded, both streams' deletes wait (nothing ungated
// without the seal knowing).
func TestArchiveGate_SwitchReadFailsClosed(t *testing.T) {
	d, _ := archiveSwitchFixture(t)
	if err := d.db.Migrator().DropTable(&models.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	if cfg := d.archiveGateConfig(); !cfg.Syslog || !cfg.Flows {
		t.Fatalf("unreadable switches resolved to %+v, want both gated", cfg)
	}
	if err := d.RecordArchiveGateState(context.Background()); err == nil {
		t.Fatal("RecordArchiveGateState succeeded without its switches")
	}
}

// TestArchiveGate_StartupReadFailureHolds: the poller's start cannot read the
// switches (after the startup log line already cached them): both streams stay
// gated, and the first successful read records the start — the disabled
// interval of a disabled stream with chunks opens before its deletes are
// ungated.
func TestArchiveGate_StartupReadFailureHolds(t *testing.T) {
	ctx := context.Background()
	d, clock := archiveSwitchFixture(t)
	seedGateChunks(t, d, export.TableFlows, gateChunk{1, 0, 10, models.ArchiveChunkVerified})
	d.LogArchiveGateState(ctx) // caches "both off" (the environment's)
	if err := d.db.Migrator().DropTable(&models.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordArchiveGateState(ctx); err == nil {
		t.Fatal("RecordArchiveGateState succeeded without its switches")
	}
	if !d.archiveGate(ctx, export.TableFlows).on {
		t.Fatal("flows ungated although the start was not recorded")
	}
	*clock = clock.Add(archiveGateCacheTTL + time.Second)
	if !d.archiveGate(ctx, export.TableFlows).on {
		t.Fatal("flows ungated while the switches still cannot be read")
	}
	if err := d.db.AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(archiveGateRetry + time.Second)
	if d.archiveGate(ctx, export.TableFlows).on {
		t.Fatal("still gated after the switches could be read")
	}
	var evs []models.ArchiveGateEvent
	d.db.Where("stream = ? AND kind = ? AND to_ts IS NULL", ArchiveGateFlows, models.ArchiveGateEventDisabled).Find(&evs)
	if len(evs) != 1 {
		t.Fatalf("disabled intervals of flows %+v, want one open before its deletes were ungated", evs)
	}
}

// TestCheckArchiveLocation: the recorded location follows the configuration
// while the archive is empty, and is fixed once it holds a chunk: a later
// location is reported as a mismatch.
func TestCheckArchiveLocation(t *testing.T) {
	ctx := context.Background()
	d := NewDatabaseForTesting(t)
	const a, b = "https://s3.example.com/example-bucket/fwmon/", "https://s3.example.net/example-bucket/fwmon/"
	for _, loc := range []string{a, b, a} {
		if rec, mismatch, err := d.CheckArchiveLocation(ctx, loc); err != nil || mismatch || rec != loc {
			t.Fatalf("empty archive at %s: %q %v %v", loc, rec, mismatch, err)
		}
	}
	seedGateChunks(t, d, export.TableSyslog, gateChunk{1, 0, 10, models.ArchiveChunkVerified})
	if _, mismatch, err := d.CheckArchiveLocation(ctx, a); err != nil || mismatch {
		t.Fatalf("same location with chunks: %v %v", mismatch, err)
	}
	if rec, mismatch, err := d.CheckArchiveLocation(ctx, b); err != nil || !mismatch || rec != a {
		t.Fatalf("moved with chunks: %q %v %v, want a mismatch against %s", rec, mismatch, err, a)
	}
	// The bucket re-cased ("Example-Bucket", as B2's console shows it) is the
	// same location, and the record keeps the spelling it was written with.
	const recased = "https://s3.example.com/Example-Bucket/fwmon/"
	if rec, mismatch, err := d.CheckArchiveLocation(ctx, recased); err != nil || mismatch || rec != a {
		t.Fatalf("re-cased bucket with chunks: %q %v %v, want no mismatch and the record %s kept", rec, mismatch, err, a)
	}
	if rec, _, _ := d.CheckArchiveLocation(ctx, a); rec != a {
		t.Fatalf("record after the re-cased check = %q, want %s unchanged", rec, a)
	}
	// The prefix is part of every key: its case is a move.
	if _, mismatch, err := d.CheckArchiveLocation(ctx, "https://s3.example.com/example-bucket/FWMON/"); err != nil || !mismatch {
		t.Fatalf("re-cased prefix with chunks: %v %v, want a mismatch", mismatch, err)
	}
}

// TestArchiveGateReadHealth: the gate's record of its switch reads — failing
// since the first failed read in a row (later failures keep that start),
// holding both streams before any read succeeded and the last switches
// after one, and healthy again on the first read that succeeds.
func TestArchiveGateReadHealth(t *testing.T) {
	d, clock := archiveSwitchFixture(t)
	if h := d.ArchiveGateReadHealth(*clock); h.FailingSince != nil {
		t.Fatalf("a readable gate reports %+v", h)
	}
	first := *clock
	*clock = clock.Add(archiveGateCacheTTL + time.Second)
	if err := d.db.Migrator().RenameTable("system_settings", "system_settings_away"); err != nil {
		t.Fatal(err)
	}
	failedAt := *clock
	h := d.ArchiveGateReadHealth(*clock)
	if h.FailingSince == nil || !h.FailingSince.Equal(failedAt) || h.HoldingAll || !strings.Contains(h.Error, "system_settings") {
		t.Fatalf("after a successful read at %v then a failure: %+v, want failing since %v keeping the last switches", first, h, failedAt)
	}
	*clock = clock.Add(archiveGateRetry + time.Second)
	if h := d.ArchiveGateReadHealth(*clock); h.FailingSince == nil || !h.FailingSince.Equal(failedAt) {
		t.Fatalf("a second failure moved the start: %+v", h)
	}
	if err := d.db.Migrator().RenameTable("system_settings_away", "system_settings"); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(archiveGateRetry + time.Second)
	if h := d.ArchiveGateReadHealth(*clock); h.FailingSince != nil || h.Error != "" {
		t.Fatalf("readable again: %+v", h)
	}

	// No read has ever succeeded (the poller's start failed): both held.
	d2, clock2 := archiveSwitchFixture(t)
	if err := d2.db.Migrator().DropTable(&models.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	if err := d2.RecordArchiveGateState(context.Background()); err == nil {
		t.Fatal("RecordArchiveGateState succeeded without its switches")
	}
	if h := d2.ArchiveGateReadHealth(*clock2); h.FailingSince == nil || !h.HoldingAll {
		t.Fatalf("start unrecorded: %+v, want failing and holding both streams", h)
	}
}
