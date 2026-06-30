package detect

import (
	"fmt"
	"math"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// Security-detector thresholds. Tuned conservative for observe-mode; operators
// adjust by acking noise. All operate on the bytes-are-sampling-scaled values.
const (
	portScanDistinctPorts      = 20             // distinct dst ports from one src
	superSpreaderDistinctHosts = 100            // distinct dst hosts from one src
	dataExfilBytes             = int64(1) << 30 // 1 GiB outbound (src,dst) in the window
	beaconMinSamples           = 8              // min flows to judge periodicity
	beaconMaxAvgBytes          = 1500           // "small" callouts only
	beaconMaxCV                = 0.35           // inter-arrival coefficient-of-variation ceiling
)

// --- port scan (security) ---------------------------------------------------

// portScanDetector flags a source touching many distinct destination ports —
// the classic horizontal/vertical scan signature.
type portScanDetector struct{}

func (portScanDetector) Name() string       { return "port_scan" }
func (portScanDetector) Category() Category { return CategorySecurity }

func (d portScanDetector) Detect(w Window) ([]Detection, error) {
	type row struct {
		SrcAddr string
		Ports   int64
		Hosts   int64
	}
	var rows []row
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Select("src_addr, COUNT(DISTINCT dst_port) as ports, COUNT(DISTINCT dst_addr) as hosts").
		Group("src_addr").
		Having("COUNT(DISTINCT dst_port) >= ?", portScanDistinctPorts).
		Order("ports DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			SrcAddr: r.SrcAddr, Score: float64(r.Ports),
			Message:  fmt.Sprintf("Possible port scan from %s: %d distinct ports across %d hosts", r.SrcAddr, r.Ports, r.Hosts),
			DedupKey: "portscan_" + r.SrcAddr,
			Details:  map[string]any{"distinct_ports": r.Ports, "distinct_hosts": r.Hosts},
		})
	}
	return out, nil
}

// --- super spreader (security) ----------------------------------------------

// superSpreaderDetector flags a source talking to an unusually large number of
// distinct destinations — worm/scan propagation or misconfigured discovery.
type superSpreaderDetector struct{}

func (superSpreaderDetector) Name() string       { return "super_spreader" }
func (superSpreaderDetector) Category() Category { return CategorySecurity }

func (d superSpreaderDetector) Detect(w Window) ([]Detection, error) {
	type row struct {
		SrcAddr string
		Hosts   int64
	}
	var rows []row
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Select("src_addr, COUNT(DISTINCT dst_addr) as hosts").
		Group("src_addr").
		Having("COUNT(DISTINCT dst_addr) >= ?", superSpreaderDistinctHosts).
		Order("hosts DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			SrcAddr: r.SrcAddr, Score: float64(r.Hosts),
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
	type row struct {
		SrcAddr    string
		DstAddr    string
		DstCountry string
		Bytes      int64
	}
	var rows []row
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("direction = ?", classify.DirOutbound).
		Select("src_addr, dst_addr, dst_country, SUM(bytes) as bytes").
		Group("src_addr, dst_addr, dst_country").
		Having("SUM(bytes) >= ?", dataExfilBytes).
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
			SrcAddr: r.SrcAddr, DstAddr: r.DstAddr, Score: float64(r.Bytes),
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
		SrcAddr string
		DstAddr string
		Bytes   int64
		Flows   int64
		Flag    int
	}
	var rows []row
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("threat_flag <> 0").
		Select("src_addr, dst_addr, SUM(bytes) as bytes, COUNT(*) as flows, MAX(threat_flag) as flag").
		Group("src_addr, dst_addr").
		Order("bytes DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		who := "destination"
		if r.Flag&1 != 0 && r.Flag&2 != 0 {
			who = "source and destination"
		} else if r.Flag&1 != 0 {
			who = "source"
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			SrcAddr: r.SrcAddr, DstAddr: r.DstAddr, Score: float64(r.Bytes),
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

func (c2BeaconDetector) Name() string       { return "c2_beacon" }
func (c2BeaconDetector) Category() Category { return CategorySecurity }

func (d c2BeaconDetector) Detect(w Window) ([]Detection, error) {
	// Candidate (src,dst,port) groups: enough small-payload outbound/external
	// flows to judge periodicity.
	type cand struct {
		SrcAddr string
		DstAddr string
		DstPort uint16
		Cnt     int64
	}
	var cands []cand
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("direction IN ?", []int{int(classify.DirOutbound), int(classify.DirExternal)}).
		Select("src_addr, dst_addr, dst_port, COUNT(*) as cnt").
		Group("src_addr, dst_addr, dst_port").
		Having("COUNT(*) >= ? AND AVG(bytes) <= ?", beaconMinSamples, beaconMaxAvgBytes).
		Order("cnt DESC").Limit(50).Scan(&cands).Error; err != nil {
		return nil, err
	}

	out := make([]Detection, 0)
	for _, c := range cands {
		var ts []time.Time
		if err := w.DB.Model(&models.FlowSample{}).
			Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
			Where("src_addr = ? AND dst_addr = ? AND dst_port = ?", c.SrcAddr, c.DstAddr, c.DstPort).
			Order("timestamp ASC").Limit(1000).Pluck("timestamp", &ts).Error; err != nil {
			continue
		}
		cv, ok := interArrivalCV(ts)
		if !ok || cv > beaconMaxCV {
			continue
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "info",
			SrcAddr: c.SrcAddr, DstAddr: c.DstAddr, DstPort: c.DstPort, Score: float64(c.Cnt),
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
func interArrivalCV(ts []time.Time) (float64, bool) {
	if len(ts) < beaconMinSamples {
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
