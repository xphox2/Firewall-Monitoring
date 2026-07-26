package alerts

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/serverhealth"
)

// ServerVolume is one volume to evaluate, already probed.
type ServerVolume struct {
	// Label distinguishes the volumes in the cooldown key and the MetricName.
	// It MUST be stable and per-volume: resolveOpenAlertRows scopes by
	// (device, type, metric_name), so a shared name would let the root volume
	// recovering close the database volume's open alert row, and a shared
	// cooldown key would let a root fire mask a database-volume fire.
	Label  string
	Volume serverhealth.Volume
}

// serverDiskMetric is the per-volume MetricName, shared by the fire and
// recovery legs so recovery resolves the row its own fire opened.
func serverDiskMetric(label string) string { return "server_disk_" + label }

func serverDiskKey(label string) string { return "server_disk_high_" + label }

// breached reports whether a volume trips either trigger, and why.
//
// Two triggers because neither alone is adequate: a percentage is a poor proxy
// on a large volume (90% of 196GB is 19.6GB free, comfortable) and fires too
// late on a small one, while a free-space floor alone stays silent on a large
// disk until it is nearly full. A zero threshold disables that trigger.
func breached(v serverhealth.Volume, pctThreshold float64, freeFloorBytes uint64) (bool, string) {
	if pctThreshold > 0 && v.Percent >= pctThreshold {
		return true, fmt.Sprintf("%.1f%% used (threshold %.0f%%)", v.Percent, pctThreshold)
	}
	if freeFloorBytes > 0 && v.FreeBytes < freeFloorBytes {
		return true, fmt.Sprintf("%.1f GB free (floor %.1f GB)",
			float64(v.FreeBytes)/(1<<30), float64(freeFloorBytes)/(1<<30))
	}
	return false, ""
}

// CheckServerVolumes evaluates the fwmon server's OWN volumes and fires or
// resolves SERVER_DISK_HIGH per volume.
//
// This exists because DISK_HIGH is keyed on a device id and fed from device
// polling, so the server's own disk was never evaluated by anything. On
// 2026-07-26 the database volume filled, Postgres crash-looped, and nothing
// alerted.
//
// Modelled on RecordProbeDataTruncation — the established device-less alert —
// but deliberately NOT a copy of it. That function carries three latent bugs:
// it builds its notify config from the bare SnapshotConfig (so PolicyActive is
// never set and it can never page PagerDuty/Opsgenie/Teams), it never calls
// markActiveLocked (so sendRecovery finds wasActive=false and skips the recovery
// notification), and it hardcodes a 5-minute cooldown while ignoring
// resolved.CooldownMinutes (making every policy and rule cooldown decorative).
// All three are fixed here.
func (am *AlertManager) CheckServerVolumes(vols []ServerVolume, pctThreshold float64, freeFloorBytes uint64) {
	if am.db == nil {
		return
	}
	for _, sv := range vols {
		am.checkOneServerVolume(sv, pctThreshold, freeFloorBytes)
	}
}

func (am *AlertManager) checkOneServerVolume(sv ServerVolume, pctThreshold float64, freeFloorBytes uint64) {
	key := serverDiskKey(sv.Label)
	metric := serverDiskMetric(sv.Label)
	now := time.Now()

	over, why := breached(sv.Volume, pctThreshold, freeFloorBytes)
	if !over {
		// Recovery is idempotent and restart-safe; it no-ops when nothing is open.
		am.sendRecovery(key, models.AlertTypeServerDiskHigh, metric,
			fmt.Sprintf("Server volume %s recovered: %.1f%% used, %.1f GB free",
				sv.Volume.Path, sv.Volume.Percent, float64(sv.Volume.FreeBytes)/(1<<30)),
			0, nil)
		return
	}

	am.mu.Lock()
	resolved := am.resolveAlertConfig(0, nil, models.AlertTypeServerDiskHigh)
	severity := defaultSeverityForType(models.AlertTypeServerDiskHigh)
	if resolved.Severity != "" {
		severity = resolved.Severity
	}
	// Read the RESOLVED cooldown rather than hardcoding one — the third
	// template bug. Without this the seeded 30-minute rule, the policy editor
	// and the event rule's own override are all dead code.
	cooldown := time.Duration(resolved.CooldownMinutes) * time.Minute

	devRule, devSuppressed := am.consultDeviceRuleLocked(models.AlertTypeServerDiskHigh, 0, nil,
		string(severity), map[string]string{
			"volume": sv.Label,
			"path":   sv.Volume.Path,
		}, &resolved)
	if devRule != nil && devRule.action == "alert" {
		if devRule.severity != "" {
			severity = devRule.severity
		}
		if devRule.cooldownMin != nil && *devRule.cooldownMin > 0 {
			cooldown = time.Duration(*devRule.cooldownMin) * time.Minute
		}
	}
	if devSuppressed || !resolved.AlertEnabled || !am.canAlertWithCooldown(key, now, cooldown) {
		am.mu.Unlock()
		if devRule != nil {
			am.RecordEventRuleHit(devRule.id)
		}
		return
	}
	// Cross-restart backstop. The in-memory cooldown map dies with the process,
	// so without this a poller restart into a still-full disk re-pages
	// immediately — once per restart, and a crash-loop would page continuously.
	// Every other persistent-state alert applies this via dispatchFired.
	if am.dbCooldownActive(0, models.AlertTypeServerDiskHigh, metric, now, cooldown) {
		am.mu.Unlock()
		if devRule != nil {
			am.RecordEventRuleHit(devRule.id)
		}
		return
	}
	am.recordCooldownLocked(key, now, cooldown)
	// Mark active so the recovery leg actually notifies — the second template bug.
	am.markActiveLocked(key, now)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	// Layer the resolved policy so PolicyActive is set and incident channels
	// (PagerDuty/Opsgenie/Teams) are eligible — the first template bug.
	nc := BuildNotifyConfigFromResolved(resolved, globalNC)
	am.mu.Unlock()
	if devRule != nil {
		am.RecordEventRuleHit(devRule.id)
	}

	alert := models.Alert{
		Timestamp: now,
		AlertType: models.AlertTypeServerDiskHigh,
		Severity:  severity,
		Message: fmt.Sprintf("Firewall-Mon server volume %s (%s) is %s",
			sv.Volume.Path, sv.Label, why),
		MetricName: metric,
		// Set here rather than left to enrichAlert: with no device and no probe
		// it would stay empty, and the notification would not say where it came
		// from (the email subject drops its suffix and the context block omits
		// any origin line).
		DeviceName: "Firewall-Mon server",
	}
	am.saveAlert(&alert)
	if err := am.notify(&alert, nc); err != nil {
		log.Printf("Failed to send server disk alert for %s: %v", sv.Volume.Path, err)
	}
}
