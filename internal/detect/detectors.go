package detect

import (
	"fmt"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// minFlows is the floor on flow count before a policy detector fires, so a
// single stray sampled packet doesn't generate a finding. sFlow is sampled, so
// any persisted flow already represents ~sampling_rate real packets.
const minFlows = 3

// forwardedOnly excludes DENIED firewall-event rows (NSEL/FortiGate IE 233 = 3)
// from detectors that assert traffic actually crossed the network. Tranche 3
// deliberately stores zero-byte denied records in flow_samples; without this
// predicate, blocked internet background radiation (three denied Telnet probes
// in a window) produced perpetual false "cleartext traffic" / "leaving the
// network" / "known-bad traffic" findings for connections the firewall
// stopped. port_scan/super_spreader intentionally KEEP denied rows — a blocked
// probe is still scan evidence. Detectors FOR denied traffic (deny storms,
// denied-then-allowed) are a separate class deferred to the Tranche 4
// detection backlog (docs/flow-protocol-research-2026-07-03.md §4 item 3) —
// do not bolt them onto the forwarded-traffic detectors here.
func forwardedOnly(q *gorm.DB) *gorm.DB {
	return q.Where("firewall_event <> ?", models.FirewallEventDenied)
}

// completeFlowsExpr counts the COMPLETE (unsampled session-export) rows inside
// a GROUP BY so a mixed-corpus aggregate can gate flow-count (fps) math
// per-metric without a second query: NetFlow v5/v9/IPFIX with sampling_rate 0
// or 1. sFlow (flow_source 0) is packet-sampled even at rate 1; FortiGate 7.6+
// netflow-sample-rate>1 exports SAMPLED NetFlow, excluded by the rate test.
// The collector's sampler chain never emits a rate <1 for live rows (rateFor
// falls back to 1; v5 clamps 0→1), so <=1 is exact. Flow-count and per-flow
// timing are only valid over these rows (T4-1). Phase 2's denied-flow
// detectors add the WHERE-clause twin (`completeRows`) with their first caller.
const completeFlowsExpr = "SUM(CASE WHEN flow_source <> 0 AND sampling_rate <= 1 THEN 1 ELSE 0 END)"

// epochMinuteExpr returns a SQL expression bucketing `timestamp` into unix
// epoch minutes, per dialect. detect stays a leaf package: gorm's
// Dialector.Name() is the only dependency.
func epochMinuteExpr(db *gorm.DB) string {
	if db.Dialector.Name() == "sqlite" {
		return "CAST(strftime('%s', timestamp) AS INTEGER) / 60"
	}
	return "CAST(FLOOR(EXTRACT(EPOCH FROM timestamp) / 60) AS BIGINT)"
}

// epochSecondExpr is epochMinuteExpr's whole-second sibling. Aggregates over
// it (MAX(...)) scan portably into int64 — scanning MAX(timestamp) directly
// into time.Time breaks on the SQLite test backend, where an aggregate loses
// the column's declared type and comes back as raw TEXT.
func epochSecondExpr(db *gorm.DB) string {
	if db.Dialector.Name() == "sqlite" {
		return "CAST(strftime('%s', timestamp) AS INTEGER)"
	}
	return "CAST(FLOOR(EXTRACT(EPOCH FROM timestamp)) AS BIGINT)"
}

// portLabels names the ports the policy detectors care about, for readable
// messages without pulling in a full service registry.
var portLabels = map[uint16]string{
	20: "FTP-DATA", 21: "FTP", 23: "Telnet", 69: "TFTP", 110: "POP3", 143: "IMAP",
	139: "NetBIOS", 445: "SMB", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL",
	5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}

func portLabel(p uint16) string {
	if n, ok := portLabels[p]; ok {
		return n
	}
	return fmt.Sprintf("port %d", p)
}

// portGroupRow is the shared shape for the two port-based policy detectors.
type portGroupRow struct {
	DeviceID uint
	DstPort  uint16
	Protocol uint8
	Bytes    uint64
	Flows    int64
}

// --- cleartext (policy) -----------------------------------------------------

// cleartextDetector flags use of legacy unencrypted protocols (Telnet, FTP,
// TFTP, POP3, IMAP). These leak credentials and content in plaintext and are
// almost always a misconfiguration or shadow device worth a look.
type cleartextDetector struct{}

func (cleartextDetector) Name() string       { return "cleartext" }
func (cleartextDetector) Category() Category { return CategoryPolicy }

func (d cleartextDetector) Detect(w Window) ([]Detection, error) {
	cleartextPorts := []uint16{20, 21, 23, 69, 110, 143}
	var rows []portGroupRow
	if err := forwardedOnly(w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End)).
		Where("dst_port IN ?", cleartextPorts).
		Select("device_id, dst_port, protocol, SUM(bytes) as bytes, COUNT(*) as flows").
		Group("device_id, dst_port, protocol").
		Having("COUNT(*) >= ?", minFlows).
		Order("bytes DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			DeviceID: r.DeviceID, DstPort: r.DstPort, Protocol: r.Protocol,
			Score:    float64(r.Bytes),
			Message:  fmt.Sprintf("Cleartext %s traffic: %d flows (%d bytes sampled)", portLabel(r.DstPort), r.Flows, r.Bytes),
			DedupKey: fmt.Sprintf("cleartext_%d_%d", r.DeviceID, r.DstPort),
			Details:  map[string]any{"flows": r.Flows, "bytes": r.Bytes, "dst_port": r.DstPort},
		})
	}
	return out, nil
}

// --- unexpected egress (policy) ---------------------------------------------

// unexpectedEgressDetector flags internal hosts opening admin/database protocols
// (SMB, RDP, SQL engines, Redis, Mongo) OUTBOUND to public addresses. That
// pattern is rarely legitimate and is a classic lateral-movement / data-access
// signal — these services should not be reachable across the internet.
type unexpectedEgressDetector struct{}

func (unexpectedEgressDetector) Name() string       { return "unexpected_egress" }
func (unexpectedEgressDetector) Category() Category { return CategoryPolicy }

func (d unexpectedEgressDetector) Detect(w Window) ([]Detection, error) {
	egressPorts := []uint16{139, 445, 3389, 1433, 3306, 5432, 6379, 27017}
	var rows []portGroupRow
	if err := forwardedOnly(w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End)).
		Where("direction = ?", classify.DirOutbound).
		Where("dst_port IN ?", egressPorts).
		Select("device_id, dst_port, protocol, SUM(bytes) as bytes, COUNT(*) as flows").
		Group("device_id, dst_port, protocol").
		Having("COUNT(*) >= ?", minFlows).
		Order("bytes DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			DeviceID: r.DeviceID, DstPort: r.DstPort, Protocol: r.Protocol,
			Score:    float64(r.Bytes),
			Message:  fmt.Sprintf("%s (port %d) leaving the network outbound: %d flows (%d bytes sampled)", portLabel(r.DstPort), r.DstPort, r.Flows, r.Bytes),
			DedupKey: fmt.Sprintf("egress_%d_%d", r.DeviceID, r.DstPort),
			Details:  map[string]any{"flows": r.Flows, "bytes": r.Bytes, "dst_port": r.DstPort},
		})
	}
	return out, nil
}

// --- sampling back-off (operational) ----------------------------------------

// samplingBackoffDetector surfaces sFlow agents that dropped samples in the
// window (flow_agent_drops). Drops mean the agent couldn't keep up and the
// traffic accounting is under-reported — an operational signal that the agent is
// overloaded or the sampling rate needs tuning.
type samplingBackoffDetector struct{}

func (samplingBackoffDetector) Name() string       { return "sampling_backoff" }
func (samplingBackoffDetector) Category() Category { return CategoryOperational }

func (d samplingBackoffDetector) Detect(w Window) ([]Detection, error) {
	type agentRow struct {
		AgentAddress string
		Drops        uint64
	}
	var rows []agentRow
	if err := w.DB.Model(&models.AgentDrops{}).
		Where("window_start >= ? AND window_start < ?", w.Start, w.End).
		Where("drops_count > 0").
		Select("agent_address, SUM(drops_count) as drops").
		Group("agent_address").
		Order("drops DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			SrcAddr:  r.AgentAddress,
			Score:    float64(r.Drops),
			Message:  fmt.Sprintf("sFlow agent %s dropped %d samples — traffic under-reported, agent overloaded", r.AgentAddress, r.Drops),
			DedupKey: fmt.Sprintf("sampbackoff_%s", r.AgentAddress),
			Details:  map[string]any{"agent": r.AgentAddress, "drops": r.Drops},
		})
	}
	return out, nil
}

// --- capacity (operational) -------------------------------------------------

// snmpSpeedSaturated is the SNMP ifSpeed value (2^32-1) that signals the gauge
// saturated and the true speed is in ifHighSpeed (Mbps). See InterfaceStats.
const snmpSpeedSaturated = uint64(4294967295)

// defaultCapacityThreshold is the egress-utilisation fraction at which a finding
// fires when not overridden via detect.Config.
const defaultCapacityThreshold = 0.80

// capacityDetector estimates per-interface egress throughput from sampled bytes
// and compares it to the interface's SNMP-reported speed. >80% of link speed is
// a capacity-planning signal (warning); >=95% is congestion (critical). Uses
// SNMP ifSpeed until sFlow if_counters land (a later increment).
type capacityDetector struct{}

func (capacityDetector) Name() string       { return "capacity" }
func (capacityDetector) Category() Category { return CategoryOperational }

func (d capacityDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	type ifRow struct {
		DeviceID      uint
		OutputIfIndex uint32
		Bytes         uint64
	}
	var rows []ifRow
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("output_if_index > 0").
		Select("device_id, output_if_index, SUM(bytes) as bytes").
		Group("device_id, output_if_index").
		Order("bytes DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	secs := w.Seconds()
	out := make([]Detection, 0)
	for _, r := range rows {
		// Latest known speed for this (device, ifIndex). interface_stats.Index is
		// the SNMP ifIndex, which matches sFlow's output_if_index.
		var iface struct {
			Speed     uint64
			HighSpeed uint64
		}
		if err := w.DB.Model(&models.InterfaceStats{}).
			Where(`device_id = ? AND "index" = ?`, r.DeviceID, r.OutputIfIndex).
			Select("speed, high_speed").
			Order("timestamp DESC").Limit(1).Scan(&iface).Error; err != nil {
			continue
		}
		speedBps := iface.Speed
		if speedBps == snmpSpeedSaturated && iface.HighSpeed > 0 {
			speedBps = iface.HighSpeed * 1_000_000 // ifHighSpeed is Mbps
		}
		if speedBps == 0 {
			// SNMP speed unknown (e.g. SNMP host-restricted) — fall back to the
			// sFlow-reported ifSpeed from the latest counter sample (schema v2).
			var sf struct{ IfSpeed uint64 }
			if err := w.DB.Model(&models.FlowInterfaceCounter{}).
				Where("device_id = ? AND if_index = ?", r.DeviceID, r.OutputIfIndex).
				Select("if_speed").
				Order("timestamp DESC").Limit(1).Scan(&sf).Error; err == nil {
				speedBps = sf.IfSpeed
			}
		}
		if speedBps == 0 {
			continue // unknown link speed — can't judge utilisation
		}
		bps := float64(r.Bytes) * 8 / secs
		pct := bps / float64(speedBps)
		if pct < cfg.CapacityThreshold {
			continue
		}
		sev := "warning"
		if pct >= 0.95 {
			sev = "critical"
		}
		// T4-8 attribution: "the link is 83% full and here's who." One bounded
		// query per SATURATED interface only (rare), so the common case adds
		// zero queries to the cycle.
		talkers, talkerText, sampled := capacityTopTalkers(w, r.DeviceID, r.OutputIfIndex, r.Bytes)
		msg := fmt.Sprintf("Interface ifIndex %d at %.0f%% of link speed (%.0f Mbps of %d Mbps)", r.OutputIfIndex, pct*100, bps/1e6, speedBps/1_000_000)
		if talkerText != "" {
			msg += " — top talkers: " + talkerText
		}
		details := map[string]any{"if_index": r.OutputIfIndex, "bps": bps, "speed_bps": speedBps, "pct": pct * 100}
		if len(talkers) > 0 {
			details["top_talkers"] = talkers
			details["estimate"] = sampled // byte shares from sFlow-sampled rows are estimates
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: r.DeviceID,
			Score:    pct * 100,
			Message:  msg,
			DedupKey: fmt.Sprintf("capacity_%d_%d", r.DeviceID, r.OutputIfIndex),
			Details:  details,
		})
	}
	return out, nil
}

// capacityTopTalkers returns the top-3 (src,dst) pairs by bytes on a saturated
// egress interface, with each pair's share of the interface's window bytes.
func capacityTopTalkers(w Window, deviceID uint, ifIndex uint32, ifBytes uint64) (talkers []map[string]any, text string, sampled bool) {
	if ifBytes == 0 {
		return nil, "", false
	}
	type pairRow struct {
		SrcAddr string
		DstAddr string
		B       uint64
		Sampled int64
	}
	var rows []pairRow
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("device_id = ? AND output_if_index = ?", deviceID, ifIndex).
		Select("src_addr, dst_addr, SUM(bytes) as b, SUM(CASE WHEN flow_source = 0 THEN 1 ELSE 0 END) as sampled").
		Group("src_addr, dst_addr").
		Order("b DESC").Limit(3).Scan(&rows).Error; err != nil {
		return nil, "", false
	}
	var parts []string
	for _, r := range rows {
		share := float64(r.B) * 100 / float64(ifBytes)
		talkers = append(talkers, map[string]any{
			"src": r.SrcAddr, "dst": r.DstAddr, "bytes": r.B, "share_pct": share,
		})
		parts = append(parts, fmt.Sprintf("%s → %s (%.0f%%)", r.SrcAddr, r.DstAddr, share))
		if r.Sampled > 0 {
			sampled = true
		}
	}
	return talkers, joinComma(parts), sampled
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
