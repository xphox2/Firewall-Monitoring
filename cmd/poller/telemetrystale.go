package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// TELEMETRY_STALE (v0.11.101) closes the silent-failure gap opened by
// v0.11.100: a device the collector still reaches (successful pings bump
// devices.last_polled, so DEVICE_OFFLINE never fires) whose polled SNMP/SSH
// telemetry stopped arriving used to just vanish from every threshold check —
// the freshness gate skips stale rows without alerting.
//
// Two signals, either one stale fires (one alone provably misses the fleet's
// primary failure mode):
//   - system_status (vitals): produced every cycle by SNMP on every vendor
//     and by the FortiGate SSH perf writer;
//   - interface_stats: dies with SNMP on every vendor — catches the FortiGate
//     case where the SSH perf writer keeps vitals fresh through an SNMP outage.
//
// A signal is stale iff the device HAS a row inside the 24h lookback (natural
// "produced this recently" gate — ping-only devices never qualify) whose
// timestamp is older than the effective threshold.
const (
	// telemetryStaleLookback bounds how far back the signal queries and the
	// staleness evaluation look. Also keeps the widened MAX(timestamp) scan
	// partition-pruned on the partitioned tables.
	telemetryStaleLookback = 24 * time.Hour
	// telemetryStaleCycles is the consecutive-cycle debounce: the condition
	// must hold this many monitoring cycles before firing. Absorbs
	// poller-restart-after-outage storms (DB still says "online", rows
	// outage-old), collector spool replay (replayed old pings bump last_polled
	// to now while row timestamps stay old until the first live poll), and
	// re-enabled devices' first cycle.
	telemetryStaleCycles = 3
	// telemetryStaleDefaultMinutes is the telemetry_stale_minutes setting
	// default. It deliberately sits above the FortiGate SSH perf cadence
	// (SSHPollInterval default 900s), so an SNMP-dead/SSH-alive device fires
	// via the interface signal without fire/recover-cycling on vitals.
	telemetryStaleDefaultMinutes = 60
)

// telemetryStaleInputs carries the per-cycle signal state checkRelayedTelemetry
// already collected — the evaluation adds no queries beyond the settings read.
type telemetryStaleInputs struct {
	devByID       map[uint]*models.Device
	justFlipped   map[uint]struct{} // this cycle's online→offline sweep transitions
	freshStatus   map[uint]bool     // devices with a vitals row newer than cutoff
	staleVitals   map[uint]time.Time
	latestIface   map[uint]time.Time // newest interface-stats timestamp within lookback
	statusQueryOK bool
	ifaceQueryOK  bool
	staleAfter    time.Duration
	now           time.Time
}

// evaluateTelemetryStale applies the fire condition per device, maintains the
// consecutive-cycle debounce counters, and drives fire/recovery/cold-resolve
// through the AlertManager. Runs on the single leader-locked monitoring-cycle
// goroutine — telemetryStaleStreak needs no mutex.
func (p *Poller) evaluateTelemetryStale(in telemetryStaleInputs) {
	if p.alertManager == nil {
		return
	}
	if p.telemetryStaleStreak == nil { // hand-built Pollers (tests) skip NewPoller
		p.telemetryStaleStreak = make(map[uint]int)
	}

	// 0 disables the check entirely (checked BEFORE clamping — the clamp must
	// not turn "off" into "on at 2×staleAfter"). Otherwise the threshold is
	// clamped to ≥ 2×staleAfter so DEVICE_OFFLINE always wins a full outage.
	minutes := p.db.GetIntSetting("telemetry_stale_minutes", telemetryStaleDefaultMinutes)
	if minutes <= 0 {
		p.telemetryStaleStreak = make(map[uint]int)
		return
	}
	threshold := time.Duration(minutes) * time.Minute
	if threshold < 2*in.staleAfter {
		threshold = 2 * in.staleAfter
	}

	noVitalsRow := 0 // online devices with no vitals row in the whole lookback → skew log
	for id, dev := range in.devByID {
		eligible := dev.ProbeID != nil && dev.Status == "online"
		if _, flipped := in.justFlipped[id]; flipped {
			eligible = false
		}
		if !eligible {
			delete(p.telemetryStaleStreak, id)
			continue
		}

		var staleParts []string
		if in.statusQueryOK && !in.freshStatus[id] {
			if ts, ok := in.staleVitals[id]; ok && in.now.Sub(ts) >= threshold {
				staleParts = append(staleParts, fmt.Sprintf("no system vitals for %s (last at %s)",
					in.now.Sub(ts).Round(time.Minute), ts.Format("2006-01-02 15:04 MST")))
			} else if !ok {
				noVitalsRow++
			}
		}
		if in.ifaceQueryOK {
			if ts, ok := in.latestIface[id]; ok && in.now.Sub(ts) >= threshold {
				staleParts = append(staleParts, fmt.Sprintf("no interface stats for %s (last at %s)",
					in.now.Sub(ts).Round(time.Minute), ts.Format("2006-01-02 15:04 MST")))
			}
		}

		if len(staleParts) == 0 {
			delete(p.telemetryStaleStreak, id)
			// Recovery only makes sense when telemetry is actually flowing
			// again — at least one fresh signal. (A device whose rows merely
			// aged out of the lookback stays as-is; its open alert remains the
			// signal.) CheckTelemetryRecovered gates its own DB work.
			if in.freshStatus[id] || (!in.latestIface[id].IsZero() && in.now.Sub(in.latestIface[id]) < in.staleAfter) {
				p.alertManager.CheckTelemetryRecovered(dev)
			}
			continue
		}

		p.telemetryStaleStreak[id]++
		if p.telemetryStaleStreak[id] < telemetryStaleCycles {
			continue // debounce: condition must persist across cycles
		}
		if err := p.alertManager.CheckTelemetryStale(dev, strings.Join(staleParts, "; ")); err != nil {
			log.Printf("Device %s: telemetry stale check error - %v", dev.Name, err)
		}
	}

	// Preserved visibility log (pre-v0.11.101 behavior): online devices with
	// no vitals row AT ALL in the lookback can't alert (never produced the
	// signal) — but a fleet-wide count here is the tell for collector NTP
	// clock skew silently disabling every threshold check.
	if in.statusQueryOK && noVitalsRow > 0 {
		log.Printf("Telemetry check: %d online device(s) had no system_status within %v — ping-only devices, or collector NTP/clock skew", noVitalsRow, telemetryStaleLookback)
	}
}
