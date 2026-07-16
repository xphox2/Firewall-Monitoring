package detect

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// Tranche 4 Phase 1 — volumetric DDoS detection (per-victim + per-prefix).
//
// Defaults follow FastNetMon community edition (threshold_mbps 1000 /
// threshold_pps 20000 / threshold_flows 3500) — the reference OSS volumetric
// detector. Static thresholds first: a 5-firewall fleet has a handful of
// inbound-exposed hosts and a static number is explainable in the alert text;
// a per-victim z-score adaptive mode over rollup history (which retains
// dst_addr) is a clean later increment.
//
// Validity (rate_gated): bps and pps are evaluated over ALL rows — bytes and
// packets are pre-multiplied by sampling_rate at ingest (collector parser
// contract), so the sums are unbiased traffic estimates even on sampled sFlow.
// fps (flows/second) is only meaningful over complete session exports and is
// counted via completeFlowsExpr; pps is additionally skipped when the victim's
// rows carry zero packets (ASA NSEL exports no packet counters).
//
// Denied rows are deliberately INCLUDED (no forwardedOnly): a SYN flood the
// firewall drops still saturates the inbound pipe, and NSEL deny rows
// contribute flow count — their only signal (zero bytes/packets is harmless
// in the sums).
const (
	defaultDDoSBps        = int64(1_000_000_000) // 1 Gb/s (FastNetMon threshold_mbps 1000)
	defaultDDoSPps        = int64(20_000)        // FastNetMon threshold_pps
	defaultDDoSFps        = 3_500                // FastNetMon threshold_flows
	ddosCandidateLimit    = 50
	ddosPrefixCandidates  = 5000
	ddosPrefixFloorDiv    = 1024 // per-dst floor divisor for the prefix candidate pass
	ddosPrefixFireFactor  = 0.75 // see prefix undercount math in ddosPrefixDetector
	ddosSmearMinSpan      = 60 * time.Second
	ddosSmearRowLimit     = 200
	ddosCriticalMultiple  = 2.0
	ddosTopSourcesInAlert = 3
)

// ddosVictimRow is the Stage-A aggregate per candidate victim.
type ddosVictimRow struct {
	DstAddr       string
	DeviceID      uint
	Bytes         uint64
	Packets       uint64
	Flows         int64
	CompleteFlows int64
}

// ddosMinuteRow is one Stage-B per-minute bucket for a candidate.
type ddosMinuteRow struct {
	M             int64
	Bytes         uint64
	Packets       uint64
	CompleteFlows int64
}

// ddosSmearRow is one long-span record for the elephant-smear correction.
type ddosSmearRow struct {
	FlowStart *time.Time
	FlowEnd   *time.Time
	Bytes     uint64
	Packets   uint64
}

// ddosPeaks holds the peak-minute rates after smear correction.
type ddosPeaks struct {
	bps float64
	pps float64
	fps float64
}

// Victim-traffic scoping (inlined in each query): direction IN (Inbound,
// External) — a flood at the firewall's own WAN address classifies as
// DirExternal (address-scope classification; denied flows are pre-NAT, dst =
// the WAN IP) — plus scope_local = FALSE.

// stageACandidates runs the shared candidate aggregation. floorDiv=1 for the
// per-host pass; ddosPrefixFloorDiv for the prefix pass (so a subnet spread
// across many small victims still surfaces).
func stageACandidates(w Window, cfg Config, floorDiv int64, limit int) ([]ddosVictimRow, error) {
	windowSecs := int64(60) // HAVING floors are "one minute's worth at threshold"
	var rows []ddosVictimRow
	err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("direction IN ?", []int{int(classify.DirInbound), int(classify.DirExternal)}).
		Where("scope_local = ?", false).
		Select("dst_addr, MAX(device_id) as device_id, SUM(bytes) as bytes, SUM(packets) as packets, COUNT(*) as flows, "+completeFlowsExpr+" as complete_flows").
		Group("dst_addr").
		Having("SUM(bytes) >= ? OR SUM(packets) >= ? OR "+completeFlowsExpr+" >= ?",
			cfg.DDoSBps*windowSecs/8/floorDiv,
			cfg.DDoSPps*windowSecs/floorDiv,
			int64(cfg.DDoSFps)*windowSecs/floorDiv).
		Order("bytes DESC").Limit(limit).Scan(&rows).Error
	return rows, err
}

// peakMinuteRates computes per-minute peaks for a set of victim addresses
// (one for the per-host case, the prefix's member addresses for the prefix
// case), applying the elephant-smear correction: NetFlow stamps Timestamp at
// flow END, so a long active-timeout record dumps its whole interval's bytes
// into one minute — an 8-30x phantom spike for a legitimate transfer. Long
// rows are redistributed at their true average rate before peaks are taken.
// (Moot for sFlow rows, whose flow_start/flow_end are the sample instant.)
//
// Matching is by exact `dst_addr IN` — never a textual LIKE, which for
// zero-compressed IPv6 prefixes ("2001:db8::/64" → "2001:db8:%") would
// over-match every sibling /64 and pollute the aggregation.
func peakMinuteRates(w Window, dstAddrs []string) (ddosPeaks, error) {
	if len(dstAddrs) == 0 {
		return ddosPeaks{}, nil
	}
	minuteExpr := epochMinuteExpr(w.DB)
	var buckets []ddosMinuteRow
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("dst_addr IN ?", dstAddrs).
		Where("direction IN ?", []int{int(classify.DirInbound), int(classify.DirExternal)}).
		Where("scope_local = ?", false).
		Select(minuteExpr + " as m, SUM(bytes) as bytes, SUM(packets) as packets, " + completeFlowsExpr + " as complete_flows").
		Group(minuteExpr).
		Scan(&buckets).Error; err != nil {
		return ddosPeaks{}, err
	}

	byMinute := make(map[int64]*ddosMinuteRow, len(buckets))
	for i := range buckets {
		b := buckets[i]
		byMinute[b.M] = &ddosMinuteRow{M: b.M, Bytes: b.Bytes, Packets: b.Packets, CompleteFlows: b.CompleteFlows}
	}

	// Elephant-smear correction: pull long-span rows and redistribute.
	var smear []ddosSmearRow
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("dst_addr IN ?", dstAddrs).
		Where("direction IN ?", []int{int(classify.DirInbound), int(classify.DirExternal)}).
		Where("scope_local = ?", false).
		Where("flow_start IS NOT NULL AND flow_end IS NOT NULL").
		Select("flow_start, flow_end, bytes, packets").
		Order("bytes DESC").Limit(ddosSmearRowLimit).
		Scan(&smear).Error; err != nil {
		return ddosPeaks{}, err
	}
	for _, s := range smear {
		if s.FlowStart == nil || s.FlowEnd == nil {
			continue
		}
		span := s.FlowEnd.Sub(*s.FlowStart)
		if span <= ddosSmearMinSpan {
			continue
		}
		// Remove the row's whole byte count from its end-minute bucket
		// (NetFlow stamps Timestamp = flow_end, so the record landed there).
		endMin := s.FlowEnd.Unix() / 60
		if b, ok := byMinute[endMin]; ok {
			if b.Bytes >= s.Bytes {
				b.Bytes -= s.Bytes
			} else {
				b.Bytes = 0
			}
			if b.Packets >= s.Packets {
				b.Packets -= s.Packets
			} else {
				b.Packets = 0
			}
		}
		// Redistribute at the row's TRUE average rate: divide by the FULL span's
		// minute count (not the window-clipped count), then add the per-minute
		// share only to the minutes that fall inside the window. Dividing by the
		// clipped count would concentrate a flow that predates the window into
		// the in-window minutes — a steady 500 Mb/s backup spanning past the
		// window edge would read as a multi-Gb/s "peak" and false-fire critical.
		fullMinutes := s.FlowEnd.Unix()/60 - s.FlowStart.Unix()/60 + 1
		if fullMinutes < 1 {
			fullMinutes = 1
		}
		perMinB := s.Bytes / uint64(fullMinutes)
		perMinP := s.Packets / uint64(fullMinutes)
		start := *s.FlowStart
		if start.Before(w.Start) {
			start = w.Start
		}
		end := *s.FlowEnd
		if end.After(w.End) {
			end = w.End
		}
		firstMin, lastMin := start.Unix()/60, end.Unix()/60
		for m := firstMin; m <= lastMin; m++ {
			b, ok := byMinute[m]
			if !ok {
				b = &ddosMinuteRow{M: m}
				byMinute[m] = b
			}
			b.Bytes += perMinB
			b.Packets += perMinP
		}
	}

	var p ddosPeaks
	for _, b := range byMinute {
		if v := float64(b.Bytes) * 8 / 60; v > p.bps {
			p.bps = v
		}
		if v := float64(b.Packets) / 60; v > p.pps {
			p.pps = v
		}
		if v := float64(b.CompleteFlows) / 60; v > p.fps {
			p.fps = v
		}
	}
	return p, nil
}

// topSources returns the top source countries/counts for a set of victim
// addresses — message enrichment only, one bounded GROUP BY.
func topSources(w Window, dstAddrs []string) (distinct int64, top []map[string]any) {
	if len(dstAddrs) == 0 {
		return 0, nil
	}
	type srcRow struct {
		SrcCountry string
		Srcs       int64
	}
	var rows []srcRow
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("dst_addr IN ?", dstAddrs).
		Where("direction IN ?", []int{int(classify.DirInbound), int(classify.DirExternal)}).
		Where("scope_local = ?", false).
		Select("src_country, COUNT(DISTINCT src_addr) as srcs").
		Group("src_country").
		Order("srcs DESC").Limit(ddosTopSourcesInAlert).
		Scan(&rows).Error; err != nil {
		return 0, nil
	}
	for _, r := range rows {
		distinct += r.Srcs
		cc := r.SrcCountry
		if cc == "" {
			cc = "??"
		}
		top = append(top, map[string]any{"country": cc, "sources": r.Srcs})
	}
	return distinct, top
}

// ddosEvaluate applies the OR-threshold fire logic shared by the host and
// prefix variants. Returns severity ("" = no fire) and the metrics crossed.
func ddosEvaluate(p ddosPeaks, sumPackets uint64, completeFlows int64, bps, pps int64, fps int) (string, []string) {
	var crossed []string
	worst := 0.0
	if p.bps >= float64(bps) {
		crossed = append(crossed, "bps")
		if r := p.bps / float64(bps); r > worst {
			worst = r
		}
	}
	// pps is skipped entirely when the victim's rows carry zero packets (ASA
	// NSEL and any exporter omitting IE 2 — pps math impossible there).
	if sumPackets > 0 && p.pps >= float64(pps) {
		crossed = append(crossed, "pps")
		if r := p.pps / float64(pps); r > worst {
			worst = r
		}
	}
	// fps only when complete rows exist (flow counts are invalid under sampling).
	if completeFlows > 0 && p.fps >= float64(fps) {
		crossed = append(crossed, "fps")
		if r := p.fps / float64(fps); r > worst {
			worst = r
		}
	}
	if len(crossed) == 0 {
		return "", nil
	}
	if worst >= ddosCriticalMultiple {
		return "critical", crossed
	}
	return "warning", crossed
}

func ddosMessage(subject string, p ddosPeaks, crossed []string, distinctSrcs int64, top []map[string]any) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%.0f Mb/s", p.bps/1e6))
	if p.pps > 0 {
		parts = append(parts, fmt.Sprintf("%.1f kpps", p.pps/1e3))
	}
	if p.fps > 0 {
		parts = append(parts, fmt.Sprintf("%.0f flows/s", p.fps))
	}
	topCC := ""
	if len(top) > 0 {
		topCC = fmt.Sprintf(", top source country %v", top[0]["country"])
	}
	return fmt.Sprintf("DDoS: %s receiving %s inbound (peak 60s; crossed %s). %d distinct sources%s. pps/fps are omitted where the exporter cannot report them.",
		subject, strings.Join(parts, " / "), strings.Join(crossed, "+"), distinctSrcs, topCC)
}

// --- ddos_volumetric (security, victim-keyed, rate_gated) --------------------

type ddosVolumetricDetector struct{}

func (ddosVolumetricDetector) Name() string       { return "ddos_volumetric" }
func (ddosVolumetricDetector) Category() Category { return CategorySecurity }

// firesPerHost reports whether a single victim crosses the per-host thresholds
// on its peak-minute rates — the exact per-host fire condition. Shared by the
// volumetric detector and the prefix detector's suppression (a prefix finding
// is redundant only when a member host ACTUALLY fires per-host, not merely
// crosses a window-sum floor).
func firesPerHost(w Window, cfg Config, r ddosVictimRow) (bool, ddosPeaks, string, []string, error) {
	peaks, err := peakMinuteRates(w, []string{r.DstAddr})
	if err != nil {
		return false, ddosPeaks{}, "", nil, err
	}
	sev, crossed := ddosEvaluate(peaks, r.Packets, r.CompleteFlows, cfg.DDoSBps, cfg.DDoSPps, cfg.DDoSFps)
	return sev != "", peaks, sev, crossed, nil
}

func (d ddosVolumetricDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	if cfg.DDoSVolumetricDisabled {
		return nil, nil
	}
	rows, err := stageACandidates(w, cfg, 1, ddosCandidateLimit)
	if err != nil {
		return nil, err
	}
	var out []Detection
	for _, r := range rows {
		fired, peaks, sev, crossed, err := firesPerHost(w, cfg, r)
		if err != nil {
			return out, err
		}
		if !fired {
			continue
		}
		distinct, top := topSources(w, []string{r.DstAddr})
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: r.DeviceID, DstAddr: r.DstAddr,
			Score:    peaks.bps,
			Message:  ddosMessage(r.DstAddr, peaks, crossed, distinct, top),
			DedupKey: fmt.Sprintf("ddosvol_%s", r.DstAddr),
			Details: map[string]any{
				"peak_bps": peaks.bps, "peak_pps": peaks.pps, "peak_fps": peaks.fps,
				"crossed": crossed, "complete_flows": r.CompleteFlows,
				"distinct_sources": distinct, "top_sources": top,
				"thresholds": map[string]any{"bps": cfg.DDoSBps, "pps": cfg.DDoSPps, "fps": cfg.DDoSFps},
			},
		})
	}
	return out, nil
}

// --- ddos_prefix (security, victim-keyed, rate_gated) ------------------------

// prefixOf folds a victim address into its fixed aggregation prefix: /24 for
// IPv4, /64 for IPv6 (RTBH/blackhole granularity; FastNetMon hostgroup
// practice). Returns "" for unparseable addresses.
//
// IPv6 CAVEAT: the ÷1024 candidate-floor undercount bound is derived for IPv4
// (a /24 has ≤256 hosts → a prefix at threshold T is observed at ≥0.75T). A
// /64 has 2^64 hosts, so an attack that randomizes the low 64 bits gives every
// dst one sub-floor row and can hide an unbounded fraction of T; IPv6 carpet
// bombing with randomized interface IDs is therefore NOT reliably detected by
// this per-dst-floor approach. IPv6 /64 aggregation here catches only attacks
// concentrated on a handful of addresses. (Fleet is IPv4/sFlow today.)
func prefixOf(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

type ddosPrefixDetector struct{}

func (ddosPrefixDetector) Name() string       { return "ddos_prefix" }
func (ddosPrefixDetector) Category() Category { return CategorySecurity }

func (d ddosPrefixDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	if cfg.DDoSPrefixDisabled {
		return nil, nil
	}
	// Candidate pass with per-dst floors ÷1024 so a carpet-bombed subnet whose
	// individual hosts sit far below the per-host threshold still surfaces (see
	// prefixOf for the IPv4 undercount bound and the IPv6 caveat).
	rows, err := stageACandidates(w, cfg, ddosPrefixFloorDiv, ddosPrefixCandidates)
	if err != nil {
		return nil, err
	}

	type prefixAgg struct {
		bytes, packets uint64
		completeFlows  int64
		deviceID       uint
		members        []ddosVictimRow // for exact dst_addr IN matching + suppression
	}
	byPrefix := map[string]*prefixAgg{}
	for _, r := range rows {
		pfx := prefixOf(r.DstAddr)
		if pfx == "" {
			continue
		}
		a := byPrefix[pfx]
		if a == nil {
			a = &prefixAgg{}
			byPrefix[pfx] = a
		}
		a.bytes += r.Bytes
		a.packets += r.Packets
		a.completeFlows += r.CompleteFlows
		a.members = append(a.members, r)
		if r.DeviceID > a.deviceID {
			a.deviceID = r.DeviceID
		}
	}

	// Deterministic order for stable output.
	prefixes := make([]string, 0, len(byPrefix))
	for pfx := range byPrefix {
		prefixes = append(prefixes, pfx)
	}
	sort.Strings(prefixes)

	windowFloor := func(thr int64) uint64 { return uint64(float64(thr*60) * ddosPrefixFireFactor) }
	var out []Detection
	for _, pfx := range prefixes {
		a := byPrefix[pfx]
		if len(a.members) < 2 {
			continue // single-host events belong to ddos_volumetric
		}
		// Suppression: a prefix finding is redundant only when a member host
		// ACTUALLY fires the per-host detector (a peak-based condition — a
		// window-sum floor is necessary but not sufficient, so using it would
		// blind the prefix to a real carpet-bomb whenever the /24 also held one
		// merely-busy host). Only members crossing the per-host window floor
		// are fire candidates, so this runs the per-host peak check for a small
		// subset.
		hostFired := false
		for _, m := range a.members {
			if m.Bytes < uint64(cfg.DDoSBps*60/8) && m.Packets < uint64(cfg.DDoSPps*60) && m.CompleteFlows < int64(cfg.DDoSFps)*60 {
				continue // cannot fire per-host — skip the peak query
			}
			fired, _, _, _, err := firesPerHost(w, cfg, m)
			if err != nil {
				return out, err
			}
			if fired {
				hostFired = true
				break
			}
		}
		if hostFired {
			continue
		}
		// Cheap window-level pre-check before the per-minute query.
		if a.bytes < windowFloor(cfg.DDoSPrefixBps/8) && a.packets < windowFloor(cfg.DDoSPrefixPps) && a.completeFlows < int64(float64(cfg.DDoSPrefixFps)*60*ddosPrefixFireFactor) {
			continue
		}
		members := make([]string, len(a.members))
		for i, m := range a.members {
			members[i] = m.DstAddr
		}
		peaks, err := peakMinuteRates(w, members)
		if err != nil {
			return out, err
		}
		firedBps := int64(float64(cfg.DDoSPrefixBps) * ddosPrefixFireFactor)
		firedPps := int64(float64(cfg.DDoSPrefixPps) * ddosPrefixFireFactor)
		firedFps := int(float64(cfg.DDoSPrefixFps) * ddosPrefixFireFactor)
		sev, crossed := ddosEvaluate(peaks, a.packets, a.completeFlows, firedBps, firedPps, firedFps)
		if sev == "" {
			continue
		}
		distinct, top := topSources(w, members)
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: a.deviceID, DstAddr: pfx,
			Score:    peaks.bps,
			Message:  ddosMessage("prefix "+pfx+" (carpet bombing)", peaks, crossed, distinct, top),
			DedupKey: fmt.Sprintf("ddospfx_%s", pfx),
			Details: map[string]any{
				"prefix": pfx, "victim_hosts": len(a.members),
				"peak_bps": peaks.bps, "peak_pps": peaks.pps, "peak_fps": peaks.fps,
				"crossed": crossed, "fire_factor": ddosPrefixFireFactor,
				"thresholds": map[string]any{"bps": cfg.DDoSPrefixBps, "pps": cfg.DDoSPrefixPps, "fps": cfg.DDoSPrefixFps},
			},
		})
		if len(out) >= ddosCandidateLimit {
			break
		}
	}
	return out, nil
}
