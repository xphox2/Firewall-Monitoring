package main

import (
	"log"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsectelemetry"
)

// IPSec session telemetry cadence.
//
// The freshness gate is 30 minutes and rows vanish entirely past 3 hours, so the
// interval has to leave room for a missed cycle rather than sit near the limit.
// The command rides the collector's 60s heartbeat, so 5 minutes costs almost
// nothing and gives roughly six cycles of margin before anything looks stale.
const ipsecTelemetryInterval = 5 * time.Minute

// unknownTypeBackoff is how long to wait before re-offering telemetry to a
// collector that answered "unknown command type".
//
// Time-bounded on purpose. Backing off permanently would be the obvious
// implementation and the wrong one: it never self-heals, so a collector upgraded
// an hour later would stay dark forever with nothing on screen explaining it.
// An hour keeps a stale collector to one failed command per device per hour
// (rather than twelve) while recovering on its own after an upgrade.
const unknownTypeBackoff = time.Hour

// runIPSecTelemetryCycle enqueues a session-document fetch for every device that
// has session telemetry to report.
//
// Skips quietly for vendors with no session telemetry — most report VPN state
// over SNMP and need nothing here.
func (p *Poller) runIPSecTelemetryCycle() {
	if p.db == nil {
		return
	}
	devices, err := p.db.GetAllDevices()
	if err != nil {
		log.Printf("ipsec telemetry: list devices: %v", err)
		return
	}
	now := time.Now()
	for i := range devices {
		dev := &devices[i]
		if !dev.Enabled || len(ipsectelemetry.StepsFor(dev.Vendor)) == 0 {
			continue
		}
		if skip, why := p.skipTelemetry(dev.ID, now); skip {
			if why != "" {
				log.Printf("ipsec telemetry: device %d (%s): %s", dev.ID, dev.Name, why)
			}
			continue
		}
		cmd, berr := ipsectelemetry.BuildCommand(dev)
		if berr != nil {
			log.Printf("ipsec telemetry: device %d (%s): %v", dev.ID, dev.Name, berr)
			continue
		}
		if cmd == nil {
			continue
		}
		if eerr := p.db.EnqueueProbeCommand(cmd); eerr != nil {
			log.Printf("ipsec telemetry: enqueue for device %d: %v", dev.ID, eerr)
		}
	}
}

// skipTelemetry decides whether to leave this device alone for now.
func (p *Poller) skipTelemetry(deviceID uint, now time.Time) (bool, string) {
	last, err := p.db.GetLatestCommandByDeviceType(deviceID, database.ProbeCommandTypeIPSecTelemetry)
	if err != nil || last == nil {
		return false, ""
	}
	// A command still in flight. Without this an offline collector accumulates
	// one per cycle and runs them all at once on reconnect — harmless, since the
	// snapshots are near-identical, but pointless.
	if last.Status == database.ProbeCommandStatusPending ||
		last.Status == database.ProbeCommandStatusDispatched {
		return true, ""
	}
	// A collector too old to know this command type. Back off ONLY on that exact
	// answer — never on failure in general, because a transient failure (device
	// unreachable for sixty seconds) would then latch telemetry off, which is the
	// silent-permanent failure this whole design is trying to avoid.
	if last.Status == database.ProbeCommandStatusFailed &&
		strings.Contains(strings.ToLower(last.Result), "unknown command type") {
		if now.Sub(last.CreatedAt) < unknownTypeBackoff {
			return true, ""
		}
		return false, "retrying telemetry after unknown-command-type back-off (collector may have been upgraded)"
	}
	return false, ""
}
