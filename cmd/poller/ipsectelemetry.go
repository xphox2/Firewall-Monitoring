package main

import (
	"log"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsectelemetry"
	"firewall-mon/internal/models"
)

// minTelemetryAgent is the first collector build that understands
// ipsec_telemetry. A collector older than this cannot run the command, so
// enqueueing for it only produces a failed row.
const minTelemetryAgent = "1.3.30"

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
		if skip, why := p.skipTelemetry(dev, now); skip {
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
func (p *Poller) skipTelemetry(dev *models.Device, now time.Time) (bool, string) {
	deviceID := dev.ID

	// Ask the collector's reported version first. When it is known this is an
	// exact answer, and it costs nothing: a collector too old to run the command
	// is skipped SILENTLY, with no failed row and no log line, instead of being
	// asked every five minutes and answering "unknown command type" forever.
	//
	// An empty version means a collector too old to report one at all — which is
	// itself older than the first build that understands this command. But it is
	// deliberately NOT treated as a skip: it also covers a probe that has not yet
	// re-registered since the server upgraded, and refusing telemetry on an
	// unknown is how a feature quietly never starts. Unknown falls through to the
	// error-text back-off below, which self-heals either way.
	if v := p.probeAgentVersion(dev); v != "" && versionLess(v, minTelemetryAgent) {
		return true, ""
	}

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

// probeAgentVersion returns the reported build of the collector that owns this
// device, or "" when unknown.
func (p *Poller) probeAgentVersion(dev *models.Device) string {
	if dev.ProbeID == nil || *dev.ProbeID == 0 {
		return ""
	}
	pr, err := p.db.GetProbe(*dev.ProbeID)
	if err != nil || pr == nil {
		return ""
	}
	return pr.AgentVersion
}

// versionLess compares dotted numeric versions (1.3.30 < 1.3.31 < 1.4.0).
//
// Deliberately not a string compare, which would put "1.3.9" after "1.3.30",
// and not a semver library for three integers. A segment that does not parse
// makes the comparison return false — "not older" — so an unrecognised format
// never silently disables the feature.
func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(strings.TrimSpace(as[i]))
		bi, berr := strconv.Atoi(strings.TrimSpace(bs[i]))
		if aerr != nil || berr != nil {
			return false
		}
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}
