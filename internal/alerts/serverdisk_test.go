package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/serverhealth"
)

// SERVER_DISK_HIGH exists because DISK_HIGH is keyed on a device id and fed from
// device polling, so the fwmon server's own volumes were never evaluated by
// anything. On 2026-07-26 the database volume filled, Postgres crash-looped, and
// nothing alerted.

const gb = uint64(1) << 30

func setServerDiskPolicy(am *AlertManager, cooldownMin int) {
	cd := cooldownMin
	policy := models.AlertPolicy{
		ID: 1, Name: "test", IsDefault: true,
		CooldownMinutes: cd,
		Rules: []models.AlertRule{{
			PolicyID: 1, AlertType: models.AlertTypeServerDiskHigh, Enabled: true,
		}},
	}
	am.policyCache = PolicyCache{
		policies:      []models.AlertPolicy{policy},
		policyByID:    map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		defaultPolicy: &policy,
		loaded:        true,
	}
}

func serverDiskAlerts(t *testing.T, am *AlertManager, metric string) int64 {
	t.Helper()
	var n int64
	q := am.db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND resolved_at IS NULL", models.AlertTypeServerDiskHigh)
	if metric != "" {
		q = q.Where("metric_name = ?", metric)
	}
	if err := q.Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func vol(path string, pct float64, freeGB uint64) serverhealth.Volume {
	return serverhealth.Volume{Path: path, Percent: pct, FreeBytes: freeGB * gb, TotalBytes: 200 * gb}
}

func TestServerDisk_FiresOnPercentageBreach(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	am.CheckServerVolumes([]ServerVolume{{Label: "data", Volume: vol("/data", 91, 50)}}, 85, 5*gb)

	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 1 {
		t.Fatalf("open alerts = %d, want 1 — 91%% exceeds the 85%% threshold", n)
	}
}

// The floor is what catches the real failure mode: Postgres dies when it cannot
// write WAL, which is bytes, not a ratio. This case has percentage well under
// threshold, so it fails if only the percentage trigger is wired.
func TestServerDisk_FiresOnFreeSpaceFloorWithHealthyPercentage(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	// 60% used on a huge volume, but only 2 GB left.
	am.CheckServerVolumes([]ServerVolume{{Label: "data", Volume: vol("/data", 60, 2)}}, 85, 5*gb)

	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 1 {
		t.Fatalf("open alerts = %d, want 1 — 2 GB free is below the 5 GB floor even though "+
			"60%% is well under the 85%% threshold; a percentage-only check misses this", n)
	}
}

func TestServerDisk_SilentWhenHealthy(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	am.CheckServerVolumes([]ServerVolume{{Label: "data", Volume: vol("/data", 49, 95)}}, 85, 5*gb)

	if n := serverDiskAlerts(t, am, ""); n != 0 {
		t.Errorf("open alerts = %d, want 0 — 49%% / 95 GB free trips neither trigger", n)
	}
}

// A zero threshold disables that trigger, so an operator can run on the floor
// alone or the percentage alone.
func TestServerDisk_ZeroDisablesEachTrigger(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	// Percentage disabled: 91% must NOT fire when only the floor is armed.
	am.CheckServerVolumes([]ServerVolume{{Label: "data", Volume: vol("/data", 91, 50)}}, 0, 5*gb)
	if n := serverDiskAlerts(t, am, ""); n != 0 {
		t.Errorf("a 0 percentage threshold must disable that trigger, got %d alerts", n)
	}

	// Floor disabled: 2 GB free must NOT fire when only the percentage is armed.
	am.CheckServerVolumes([]ServerVolume{{Label: "root", Volume: vol("/", 60, 2)}}, 85, 0)
	if n := serverDiskAlerts(t, am, ""); n != 0 {
		t.Errorf("a 0 free-space floor must disable that trigger, got %d alerts", n)
	}
}

// THE RECOVERY LEG. This is the bug in the template it is modelled on:
// RecordProbeDataTruncation never calls markActiveLocked, so sendRecovery finds
// wasActive=false and skips the recovery notification entirely.
func TestServerDisk_ResolvesAndSendsRecoveryCompanion(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	am.CheckServerVolumes([]ServerVolume{{Label: "data", Volume: vol("/data", 91, 2)}}, 85, 5*gb)
	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 1 {
		t.Fatalf("setup: expected 1 open alert, got %d", n)
	}

	am.CheckServerVolumes([]ServerVolume{{Label: "data", Volume: vol("/data", 40, 120)}}, 85, 5*gb)

	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 0 {
		t.Errorf("open alerts = %d, want 0 — the volume recovered and the row must resolve", n)
	}
	var companions int64
	am.db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ? AND metric_name = ?", models.AlertTypeServerDiskHigh+"_RESOLVED", "recovery").
		Count(&companions)
	if companions == 0 {
		t.Error("no recovery companion — markActiveLocked was not called at fire time, so " +
			"sendRecovery saw wasActive=false and skipped notifying (the template's bug)")
	}
}

// Per-volume metric names are mandatory, not cosmetic: resolveOpenAlertRows
// scopes by (device, type, metric_name), and DeviceID is 0 for both volumes. A
// shared name would let the root recovering close the database volume's row.
func TestServerDisk_RootRecoveryDoesNotCloseTheDataVolumeAlert(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	am.CheckServerVolumes([]ServerVolume{
		{Label: "data", Volume: vol("/data", 95, 1)},
		{Label: "root", Volume: vol("/", 95, 1)},
	}, 85, 5*gb)
	if n := serverDiskAlerts(t, am, ""); n != 2 {
		t.Fatalf("setup: expected 2 open alerts (one per volume), got %d", n)
	}

	// Root recovers; the data volume is still critical.
	am.CheckServerVolumes([]ServerVolume{
		{Label: "data", Volume: vol("/data", 95, 1)},
		{Label: "root", Volume: vol("/", 40, 100)},
	}, 85, 5*gb)

	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 1 {
		t.Errorf("the data volume's alert was closed by the ROOT volume recovering (%d open) "+
			"— both volumes share DeviceID 0, so only a per-volume metric_name keeps "+
			"resolveOpenAlertRows from crossing them", n)
	}
	if n := serverDiskAlerts(t, am, "server_disk_root"); n != 0 {
		t.Errorf("root alert = %d, want 0 — it recovered", n)
	}
}

// The cooldown must come from the resolved policy chain, not a hardcoded
// constant — the third bug in the template. With a 30-minute policy cooldown a
// second immediate breach must be suppressed.
func TestServerDisk_CooldownComesFromTheResolvedPolicy(t *testing.T) {
	am, _ := newTestManager(t)
	setServerDiskPolicy(am, 30)

	v := []ServerVolume{{Label: "data", Volume: vol("/data", 95, 1)}}
	am.CheckServerVolumes(v, 85, 5*gb)
	am.CheckServerVolumes(v, 85, 5*gb)

	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 1 {
		t.Errorf("open alerts = %d, want 1 — the second breach is inside the 30-minute "+
			"cooldown and must be suppressed", n)
	}

	// And the recorded cooldown must actually be the policy's 30 minutes, not a
	// hardcoded 5 — otherwise a re-breach at +6 minutes would page.
	// Prove the window is the policy's 30 minutes, not a hardcoded 5: rewind the
	// recorded fire time by 6 minutes and re-check. Under a 5-minute hardcode
	// that is out of cooldown and would fire a second alert.
	am.mu.Lock()
	fired, ok := am.lastAlert[serverDiskKey("data")]
	if ok {
		am.lastAlert[serverDiskKey("data")] = fired.Add(-6 * time.Minute)
	}
	am.mu.Unlock()
	if !ok {
		t.Fatal("no cooldown recorded")
	}
	am.CheckServerVolumes(v, 85, 5*gb)
	if n := serverDiskAlerts(t, am, "server_disk_data"); n != 1 {
		t.Errorf("open alerts = %d, want 1 — a re-breach 6 minutes after firing must still "+
			"be suppressed by the policy's 30-minute cooldown; %d means the check is "+
			"ignoring resolved.CooldownMinutes and hardcoding ~5 minutes", n, n)
	}
}
