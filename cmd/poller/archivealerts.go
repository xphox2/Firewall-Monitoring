package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/archive/status"
)

// The raw archive's alerts (archive plan PR 8): ARCHIVE_LAG,
// ARCHIVE_NEEDS_ATTENTION, ARCHIVE_SEAL_OVERDUE, RETENTION_HELD and
// ARCHIVE_UNSETTLED_LONG, evaluated on the server-health tick from the same
// status the admin API shows (status.Build / Evaluator.Conditions) and fired
// or resolved through the alert engine's device-less path, like
// SERVER_DISK_HIGH: policy, event rules (seeded with a 6 h cooldown),
// maintenance windows, the cross-restart cooldown backstop and recovery
// notifications. Like the disk check it takes no advisory lock: it only reads.

// archiveAlertEval remembers since when each daily stream's lag has been
// above its threshold (status.DailySustain).
var archiveAlertEval = status.NewEvaluator()

// archiveDiskWindow: RETENTION_HELD compares the database volume's free
// space now with the newest sample at least an hour old (and at most three).
const (
	archiveDiskAgo    = time.Hour
	archiveDiskAgoMax = 3 * time.Hour
)

// archiveAlertLog rate-limits the "status unreadable" line.
var archiveAlertLog struct{ last time.Time }

// checkArchiveAlerts evaluates the archive alerts. vols / dataOK are this
// tick's probe of the server's volumes (collectServerVolumes).
func (p *Poller) checkArchiveAlerts(vols []alerts.ServerVolume, dataOK bool) {
	if p.db == nil || p.alertManager == nil || p.cfg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	now := time.Now()
	st, err := status.Build(ctx, p.db, p.cfg, now)
	if err == nil && len(st.Problems) > 0 {
		err = fmt.Errorf("%s", strings.Join(st.Problems, "; "))
	}
	if err != nil {
		// A partial read could resolve an alert that still holds: keep every
		// alert as it is until the status reads whole again.
		if now.Sub(archiveAlertLog.last) >= time.Hour {
			archiveAlertLog.last = now
			log.Printf("archive alerts: status not readable, alerts left as they are: %v", err)
		}
		return
	}
	if !st.Enabled && !archiveHasChunks(st) {
		return // never archived here: nothing can have fired
	}
	stored, err := p.db.SettingValues(ctx, status.ThresholdKeys())
	if err != nil {
		log.Printf("archive alerts: read the thresholds: %v (the defaults apply)", err)
	}
	conds := archiveAlertEval.Conditions(st, status.ReadThresholds(stored), p.archiveDiskTrend(ctx, vols, dataOK, now))
	out := make([]alerts.ServerCondition, 0, len(conds))
	for _, c := range conds {
		if !c.Known {
			continue
		}
		out = append(out, alerts.ServerCondition{Type: c.Type, Key: c.Key(), Metric: c.Metric(), Breached: c.Breached,
			Message: c.Message, Recovery: c.Recovery, Fields: c.Fields})
	}
	p.alertManager.CheckServerConditions(out)
}

func archiveHasChunks(st *status.Status) bool {
	for _, t := range st.Tables {
		if t.HasChunks {
			return true
		}
	}
	return false
}

// archiveDiskTrend reports whether the database volume's free space dropped
// since the newest server_metrics sample 1-3 h old. Unknown (no data volume
// probe now, an external database, no older sample) is reported as such;
// RETENTION_HELD counts it as growing.
func (p *Poller) archiveDiskTrend(ctx context.Context, vols []alerts.ServerVolume, dataOK bool, now time.Time) status.DiskTrend {
	var cur *uint64
	if dataOK {
		for _, v := range vols {
			if v.Label == "data" {
				f := v.Volume.FreeBytes
				cur = &f
			}
		}
	}
	if cur == nil {
		return status.DiskTrend{Detail: "database volume not measured"}
	}
	// server_metrics.timestamp is written with time.Now() (the poller's
	// zone), so the bounds are too (a SQLite comparison is textual).
	past, err := p.db.ServerDataDiskFreeAt(ctx, now.Add(-archiveDiskAgoMax), now.Add(-archiveDiskAgo))
	if err != nil || past == nil {
		return status.DiskTrend{Detail: fmt.Sprintf("%.1f GiB free, no sample from an hour ago to compare", float64(*cur)/(1<<30))}
	}
	growing := *cur < *past
	return status.DiskTrend{Known: true, Growing: growing,
		Detail: fmt.Sprintf("%.1f GiB free, %.1f GiB an hour or more ago", float64(*cur)/(1<<30), float64(*past)/(1<<30))}
}
