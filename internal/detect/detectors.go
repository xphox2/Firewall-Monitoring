package detect

import (
	"fmt"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// minFlows is the floor on flow count before a policy detector fires, so a
// single stray sampled packet doesn't generate a finding. sFlow is sampled, so
// any persisted flow already represents ~sampling_rate real packets.
const minFlows = 3

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
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
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
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
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
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: r.DeviceID,
			Score:    pct * 100,
			Message:  fmt.Sprintf("Interface ifIndex %d at %.0f%% of link speed (%.0f Mbps of %d Mbps)", r.OutputIfIndex, pct*100, bps/1e6, speedBps/1_000_000),
			DedupKey: fmt.Sprintf("capacity_%d_%d", r.DeviceID, r.OutputIfIndex),
			Details:  map[string]any{"if_index": r.OutputIfIndex, "bps": bps, "speed_bps": speedBps, "pct": pct * 100},
		})
	}
	return out, nil
}
