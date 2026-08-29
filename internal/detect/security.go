package detect

import (
	"fmt"
	"math"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// Default security-detector thresholds. These are the fallbacks when the
// operator doesn't override them via detect.Config (DETECT_* env). The port-scan
// floor was raised from 20→100 (v0.10.514): 20 distinct dst ports in a 15-minute
// window is easily reached by a busy legitimate host, so it produced false
// positives. A real scan sweeps far more ports — and the detector now also
// escalates to critical when the source is on the threat-intel feed.
const (
	defaultPortScanPorts      = 100            // distinct dst ports from one src
	defaultSuperSpreaderHosts = 100            // distinct dst hosts from one src
	defaultDataExfilBytes     = int64(1) << 30 // 1 GiB outbound (src,dst) in the window
	defaultBeaconMinSamples   = 8              // min flows to judge periodicity
	defaultBeaconMaxAvgBytes  = 1500           // "small" callouts only
	defaultBeaconMaxCV        = 0.35           // inter-arrival coefficient-of-variation ceiling
)

// --- port scan (security) ---------------------------------------------------

// portScanDetector flags a source touching many distinct destination ports —
// the classic horizontal/vertical scan signature. Denied firewall-event rows
// are intentionally INCLUDED (no forwardedOnly): a blocked probe is still scan
// evidence — the source really touched that port, the firewall just said no.
type portScanDetector struct{}

func (portScanDetector) Name() string       { return "port_scan" }
func (portScanDetector) Category() Category { return CategorySecurity }

func (d portScanDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	type row struct {
		SrcAddr  string
		DeviceID uint
		Ports    int64
		Hosts    int64
		Threat   int // MAX(threat_flag): bit 0 set => source matched the threat feed
	}
	var rows []row
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Select("src_addr, MAX(device_id) as device_id, COUNT(DISTINCT dst_port) as ports, COUNT(DISTINCT dst_addr) as hosts, MAX(threat_flag) as threat").
		Group("src_addr").
		Having("COUNT(DISTINCT dst_port) >= ?", cfg.PortScanPorts).
		Order("ports DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		// A scan from a known-bad source (on the threat-intel feed by IP or by
		// ASN reputation) is a high-confidence finding — escalate to critical.
		knownBad := r.Threat&1 != 0 || r.Threat&4 != 0
		sev := "warning"
		msg := fmt.Sprintf("Possible port scan from %s: %d distinct ports across %d hosts", r.SrcAddr, r.Ports, r.Hosts)
		if knownBad {
			sev = "critical"
			msg = fmt.Sprintf("Port scan from KNOWN-BAD source %s: %d distinct ports across %d hosts", r.SrcAddr, r.Ports, r.Hosts)
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: r.DeviceID,
			SrcAddr:  r.SrcAddr, Score: float64(r.Ports),
			Message:  msg,
			DedupKey: "portscan_" + r.SrcAddr,
			Details:  map[string]any{"distinct_ports": r.Ports, "distinct_hosts": r.Hosts, "known_bad": knownBad},
		})
	}
	return out, nil
}

// --- super spreader (security) ----------------------------------------------

// superSpreaderDetector flags a source talking to an unusually large number of
// distinct destinations — worm/scan propagation or misconfigured discovery.
// Like port_scan it keeps denied rows: blocked fan-out is still fan-out.
type superSpreaderDetector struct{}

func (superSpreaderDetector) Name() string       { return "super_spreader" }
func (superSpreaderDetector) Category() Category { return CategorySecurity }

func (d superSpreaderDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	type row struct {
		SrcAddr  string
		DeviceID uint
		Hosts    int64
	}
	var rows []row
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Select("src_addr, MAX(device_id) as device_id, COUNT(DISTINCT dst_addr) as hosts").
		Group("src_addr").
		Having("COUNT(DISTINCT dst_addr) >= ?", cfg.SuperSpreaderHosts).
		Order("hosts DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			DeviceID: r.DeviceID,
			SrcAddr:  r.SrcAddr, Score: float64(r.Hosts),
			Message:  fmt.Sprintf("Super-spreader %s: %d distinct destinations in the window", r.SrcAddr, r.Hosts),
			DedupKey: "spreader_" + r.SrcAddr,
			Details:  map[string]any{"distinct_hosts": r.Hosts},
		})
	}
	return out, nil
}

// --- data exfiltration (security) -------------------------------------------

// dataExfilDetector flags large outbound transfers from one internal host to a
// single external destination — a bulk data-exfil signature.
type dataExfilDetector struct{}

func (dataExfilDetector) Name() string       { return "data_exfil" }
func (dataExfilDetector) Category() Category { return CategorySecurity }

func (d dataExfilDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	type row struct {
		SrcAddr    string
		DstAddr    string
		DeviceID   uint
		DstCountry string
		Bytes      int64
	}
	var rows []row
	if err := forwardedOnly(w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End)).
		Where("direction = ?", classify.DirOutbound).
		Select("src_addr, dst_addr, MAX(device_id) as device_id, dst_country, SUM(bytes) as bytes").
		Group("src_addr, dst_addr, dst_country").
		Having("SUM(bytes) >= ?", cfg.DataExfilBytes).
		Order("bytes DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		dest := r.DstAddr
		if r.DstCountry != "" {
			dest = fmt.Sprintf("%s (%s)", r.DstAddr, r.DstCountry)
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			DeviceID: r.DeviceID,
			SrcAddr:  r.SrcAddr, DstAddr: r.DstAddr, Score: float64(r.Bytes),
			Message:  fmt.Sprintf("Large outbound transfer: %s → %s, %.2f GB (estimated)", r.SrcAddr, dest, float64(r.Bytes)/float64(int64(1)<<30)),
			DedupKey: "exfil_" + r.SrcAddr + "_" + r.DstAddr,
			Details:  map[string]any{"bytes": r.Bytes, "dst_country": r.DstCountry},
		})
	}
	return out, nil
}

// --- threat intel (security) ------------------------------------------------

// threatIntelDetector aggregates flows whose source or destination matched the
// known-bad feed at ingest (threat_flag != 0). Highest-confidence security
// signal; one finding per (src, dst) pair.
type threatIntelDetector struct{}

func (threatIntelDetector) Name() string       { return "threat_intel" }
func (threatIntelDetector) Category() Category { return CategorySecurity }

func (d threatIntelDetector) Detect(w Window) ([]Detection, error) {
	type row struct {
		SrcAddr  string
		DstAddr  string
		DeviceID uint
		Bytes    int64
		Flows    int64
		Flag     int
	}
	// forwardedOnly: a denied flow to a known-bad destination means the
	// firewall WORKED — reporting it as "Traffic with known-bad destination"
	// was indistinguishable from real compromise traffic. The Tranche 4
	// denied-flow detector class will surface blocked-threat activity properly.
	var rows []row
	if err := forwardedOnly(w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End)).
		Where("threat_flag <> 0").
		Select("src_addr, dst_addr, MAX(device_id) as device_id, SUM(bytes) as bytes, COUNT(*) as flows, MAX(threat_flag) as flag").
		Group("src_addr, dst_addr").
		Order("bytes DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		// bit 0/2 = src bad (IP/ASN), bit 1/3 = dst bad (IP/ASN).
		srcBad := r.Flag&1 != 0 || r.Flag&4 != 0
		dstBad := r.Flag&2 != 0 || r.Flag&8 != 0
		who := "destination"
		if srcBad && dstBad {
			who = "source and destination"
		} else if srcBad {
			who = "source"
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			DeviceID: r.DeviceID,
			SrcAddr:  r.SrcAddr, DstAddr: r.DstAddr, Score: float64(r.Bytes),
			Message:  fmt.Sprintf("Traffic with known-bad %s: %s → %s (%d flows, %d bytes sampled)", who, r.SrcAddr, r.DstAddr, r.Flows, r.Bytes),
			DedupKey: "threat_" + r.SrcAddr + "_" + r.DstAddr,
			Details:  map[string]any{"flows": r.Flows, "bytes": r.Bytes, "threat_flag": r.Flag},
		})
	}
	return out, nil
}

// --- C2 beacon (security, heuristic) ----------------------------------------

// c2BeaconDetector looks for periodic small callouts from an internal host to a
// single external destination — a command-and-control beacon signature. It
// computes the coefficient of variation of inter-arrival times per (src, dst,
// port); a low CV means regular intervals.
//
// CAVEAT: sFlow is sampled, so observed timestamps are a sparse subset of the
// real traffic and inter-arrival regularity is noisy. This is a best-effort,
// info-severity heuristic — treat hits as leads, not proof. Real beacon hunting
// wants unsampled flow timing.
type c2BeaconDetector struct{}

// beaconPerFrameBytesExpr is the average PER-FRAME payload size for the byte
// gate (AUDIT-273). BeaconMaxAvgBytes is an MTU-ish per-frame ceiling, but the
// stored `bytes` column is PRE-MULTIPLIED by sampling_rate at ingest
// (the sFlow parser — now collector-side; the server's own copy was removed
// in v0.11.228 — sets Bytes = frame_length * sampling_rate when rate > 1,
// else frame_length). Comparing AVG(bytes) against a per-frame ceiling made the
// gate unreachable on sampled sFlow — at rate 512 it demanded an average frame
// <= ~2.9 bytes — so no sampled c2_beacon candidate could ever pass even though
// the detector is classified ValiditySampledOK. Divide each row's bytes by its
// own effective sampling rate (max(sampling_rate,1), matching the ingest
// multiplier) BEFORE averaging, so the comparison is per-frame on both sampled
// and unsampled (rate 0/1) rows. Division is per-row (inside AVG) so a source
// whose rows carry different sampling rates is still normalized correctly. The
// *1.0 forces float division in both SQLite and PostgreSQL; the CASE avoids
// GREATEST, which SQLite lacks.
const beaconPerFrameBytesExpr = "AVG(bytes * 1.0 / CASE WHEN sampling_rate > 1 THEN sampling_rate ELSE 1 END)"

func (c2BeaconDetector) Name() string       { return "c2_beacon" }
func (c2BeaconDetector) Category() Category { return CategorySecurity }

func (d c2BeaconDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	// Candidate (src,dst,port) groups: enough small-payload outbound/external
	// flows to judge periodicity.
	type cand struct {
		SrcAddr  string
		DstAddr  string
		DeviceID uint
		DstPort  uint16
		Cnt      int64
	}
	var cands []cand
	if err := forwardedOnly(w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End)).
		Where("direction IN ?", []int{int(classify.DirOutbound), int(classify.DirExternal)}).
		Select("src_addr, dst_addr, MAX(device_id) as device_id, dst_port, COUNT(*) as cnt").
		Group("src_addr, dst_addr, dst_port").
		Having("COUNT(*) >= ? AND "+beaconPerFrameBytesExpr+" <= ?", cfg.BeaconMinSamples, cfg.BeaconMaxAvgBytes).
		Order("cnt DESC").Limit(50).Scan(&cands).Error; err != nil {
		return nil, err
	}

	out := make([]Detection, 0)
	for _, c := range cands {
		var ts []time.Time
		if err := forwardedOnly(w.DB.Model(&models.FlowSample{}).
			Where("timestamp >= ? AND timestamp < ?", w.Start, w.End)).
			Where("src_addr = ? AND dst_addr = ? AND dst_port = ?", c.SrcAddr, c.DstAddr, c.DstPort).
			Order("timestamp ASC").Limit(1000).Pluck("timestamp", &ts).Error; err != nil {
			continue
		}
		cv, ok := interArrivalCV(ts, cfg.BeaconMinSamples)
		if !ok || cv > cfg.BeaconMaxCV {
			continue
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "info",
			DeviceID: c.DeviceID,
			SrcAddr:  c.SrcAddr, DstAddr: c.DstAddr, DstPort: c.DstPort, Score: float64(c.Cnt),
			Message:  fmt.Sprintf("Possible C2 beacon: %s → %s:%d, %d regular small callouts (CV %.2f)", c.SrcAddr, c.DstAddr, c.DstPort, c.Cnt, cv),
			DedupKey: fmt.Sprintf("beacon_%s_%s_%d", c.SrcAddr, c.DstAddr, c.DstPort),
			Details:  map[string]any{"count": c.Cnt, "cv": cv, "dst_port": c.DstPort},
		})
	}
	return out, nil
}

// interArrivalCV returns the coefficient of variation (stddev/mean) of the gaps
// between consecutive sorted timestamps. ok is false when there aren't enough
// gaps or the mean is zero. A low CV indicates regular (periodic) arrivals.
func interArrivalCV(ts []time.Time, minSamples int) (float64, bool) {
	if len(ts) < minSamples {
		return 0, false
	}
	gaps := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i].Sub(ts[i-1]).Seconds())
	}
	var sum float64
	for _, g := range gaps {
		sum += g
	}
	mean := sum / float64(len(gaps))
	if mean <= 0 {
		return 0, false
	}
	var varc float64
	for _, g := range gaps {
		d := g - mean
		varc += d * d
	}
	varc /= float64(len(gaps))
	return math.Sqrt(varc) / mean, true
}
