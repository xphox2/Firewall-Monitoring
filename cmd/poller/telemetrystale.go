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
	// outage-old) and re-enabled devices' first cycle. (Since v0.11.105 spool
	// replay bumps last_polled with row timestamps, not now, so drain windows
	// no longer feed this.)
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

// staleSignalParts records WHICH signals were stale when a TELEMETRY_STALE
// fired (AUDIT-189). Recovery must see EVERY part that fired come back fresh:
// the old gate closed on ANY fresh signal, so an iface-stale alert (SNMP dead,
// SSH perf alive) auto-resolved with a false "recovered" notification the
// moment the dead interface rows aged out of the 24h lookback while vitals
// stayed fresh — then re-fired, forever, while SNMP was still broken.
type staleSignalParts struct {
	vitals, iface bool
}

// evaluateTelemetryStale applies the fire condition per device, maintains the
// consecutive-cycle debounce counters, and drives fire/recovery/cold-resolve
// through the AlertManager. Runs on the single leader-locked monitoring-cycle
// goroutine — telemetryStaleStreak and telemetryStaleParts need no mutex.
func (p *Poller) evaluateTelemetryStale(in telemetryStaleInputs) {
	if p.alertManager == nil {
		return
	}
	if p.telemetryStaleStreak == nil { // hand-built Pollers (tests) skip NewPoller
		p.telemetryStaleStreak = make(map[uint]int)
	}
	if p.telemetryStaleParts == nil {
		p.telemetryStaleParts = make(map[uint]staleSignalParts)
	}

	// 0 disables the check entirely (checked BEFORE clamping — the clamp must
	// not turn "off" into "on at 2×staleAfter"). Otherwise the threshold is
	// clamped to ≥ 2×staleAfter so DEVICE_OFFLINE always wins a full outage.
	minutes := p.db.GetIntSetting("telemetry_stale_minutes", telemetryStaleDefaultMinutes)
	if minutes <= 0 {
		p.telemetryStaleStreak = make(map[uint]int)
		// Parts records reset with the streaks: with the check disabled no
		// recovery can run anyway, and on re-enable a still-stale device
		// re-fires (cooldown-deduped) and re-records.
		p.telemetryStaleParts = make(map[uint]staleSignalParts)
		return
	}
	threshold := time.Duration(minutes) * time.Minute
	if threshold < 2*in.staleAfter {
		threshold = 2 * in.staleAfter
	}

	// A failed signal query must freeze the evaluation, not feed it: with (say)
	// the interface query errored, an alert held open by a stale interface
	// signal would see empty staleParts + fresh vitals and send a false
	// "recovered" notification — then re-fire when the query heals. Streaks
	// keep their value (the condition didn't observably change), recovery and
	// firing both wait for a cycle where both signals answered. The query
	// error itself is already logged by checkRelayedTelemetry.
	if !in.statusQueryOK || !in.ifaceQueryOK {
		return
	}

	noVitalsRow := 0 // online devices with no vitals row in the whole lookback → skew log
	for id, dev := range in.devByID {
		eligible := dev.ProbeID != nil && dev.Status == "online"
		if _, flipped := in.justFlipped[id]; flipped {
			eligible = false
		}
		if !eligible {
			delete(p.telemetryStaleStreak, id)
			delete(p.telemetryStaleParts, id)
			continue
		}

		var staleParts []string
		var partVitals, partIface bool
		if !in.freshStatus[id] {
			if ts, ok := in.staleVitals[id]; ok && in.now.Sub(ts) >= threshold {
				partVitals = true
				staleParts = append(staleParts, fmt.Sprintf("no system vitals for %s (last at %s)",
					in.now.Sub(ts).Round(time.Minute), ts.Format("2006-01-02 15:04 MST")))
			} else if !ok {
				noVitalsRow++
			}
		}
		if ts, ok := in.latestIface[id]; ok && in.now.Sub(ts) >= threshold {
			partIface = true
			staleParts = append(staleParts, fmt.Sprintf("no interface stats for %s (last at %s)",
				in.now.Sub(ts).Round(time.Minute), ts.Format("2006-01-02 15:04 MST")))
		}

		if len(staleParts) == 0 {
			delete(p.telemetryStaleStreak, id)
			// Recovery requires EVERY signal that fired to be fresh again
			// (AUDIT-189), not just any fresh signal: with vitals fresh, an
			// iface-stale alert used to false-recover the moment the dead
			// interface rows aged out of the lookback — while SNMP was still
			// broken. An iface-stale part recovers only when latestIface has a
			// PRESENT and fresh entry; an aged-out key is NOT recovered.
			rec, tracked := p.telemetryStaleParts[id]
			if !tracked {
				// Cold start: a row left open across a poller restart has no
				// parts record — do not guess which signals fired. Be
				// conservative and do not recover via this gate: a
				// stranded-open alert (closed by AutoResolveTelemetryStale on
				// full offline, or by a re-fire→genuine-recovery cycle) is
				// smaller harm than silently suppressing the alert this
				// feature exists to keep open.
				continue
			}
			vitalsFresh := in.freshStatus[id]
			ifaceTS, ifaceSeen := in.latestIface[id]
			ifaceFresh := ifaceSeen && in.now.Sub(ifaceTS) < in.staleAfter
			if (!rec.vitals || vitalsFresh) && (!rec.iface || ifaceFresh) {
				p.alertManager.CheckTelemetryRecovered(dev)
				delete(p.telemetryStaleParts, id)
			}
			continue
		}

		p.telemetryStaleStreak[id]++
		if p.telemetryStaleStreak[id] < telemetryStaleCycles {
			continue // debounce: condition must persist across cycles
		}
		// Record the stale signal set for the recovery gate. Refreshed every
		// post-debounce cycle so a second signal dying mid-outage tightens the
		// recovery requirement to match the live condition.
		p.telemetryStaleParts[id] = staleSignalParts{vitals: partVitals, iface: partIface}
		if err := p.alertManager.CheckTelemetryStale(dev, strings.Join(staleParts, "; ")); err != nil {
			log.Printf("Device %s: telemetry stale check error - %v", dev.Name, err)
		}
	}

	// Prune streak/parts entries for devices that left devByID entirely
	// (deleted or disabled) — without this the maps leak, and a stale
	// carried-over streak would defeat the debounce when a device is
	// re-enabled.
	for id := range p.telemetryStaleStreak {
		if _, ok := in.devByID[id]; !ok {
			delete(p.telemetryStaleStreak, id)
		}
	}
	for id := range p.telemetryStaleParts {
		if _, ok := in.devByID[id]; !ok {
			delete(p.telemetryStaleParts, id)
		}
	}

	// Preserved visibility log (pre-v0.11.101 behavior): online devices with
	// no vitals row AT ALL in the lookback can't alert (never produced the
	// signal) — but a fleet-wide count here is the tell for collector NTP
	// clock skew silently disabling every threshold check.
	if noVitalsRow > 0 {
		log.Printf("Telemetry check: %d online device(s) had no system_status within %v — ping-only devices, telemetry dead >%v, or collector NTP/clock skew", noVitalsRow, telemetryStaleLookback, telemetryStaleLookback)
	}
}
