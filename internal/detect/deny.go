package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// Tranche 4 Phase 2 — deny detectors over denied_events, the FortiGate syslog
// action="deny" projection (internal/deny). Phase 0 proved FortiOS never
// exports blocked sessions via NetFlow, so syslog is the only deny source.
// Counts here are EXACT (one logged line = one row) — see ValidityLoggedEvents.
//
// Thresholds are the per-15m-window floors above the deny baseline noise
// (~10k denies/window fleet-wide, ~1000 distinct WAN sources/window), each a
// Config knob. deny_storm splits internal-vs-external on the FortiGate-
// authoritative src_intf_role (better than the flow CIDR guess).

const (
	defaultDenyStormExternal    = 300  // WAN-src denies/15m from one src
	defaultDenyStormInternal    = 100  // LAN-src denies/15m from one src (higher-signal → lower floor)
	defaultDenyVictimSources    = 200  // distinct srcs onto one victim/15m
	defaultDenyVictimCount      = 2000 // raw denies onto one victim/15m (OR-threshold)
	defaultDeniedThenAllowedMin = 2    // prior denies before an allow to flag a policy gap
)

// denyThreatBad reports whether a deny threat bitfield marks the SOURCE as
// known-bad. Only bits 0/1 are ever set for denies (syslog carries no ASN), so
// bit 0 (src IP) is the source signal; there is no ASN escalation.
func denyThreatBad(flag int) bool { return flag&1 != 0 }

// --- deny_storm (security, src-keyed) ---------------------------------------

// denyStormDetector flags a single source generating a burst of denials — an
// external host hammering the edge (scan/brute) or an internal host repeatedly
// blocked (misconfig / malware into a denied policy). Two variants split on
// src_intf_role; an unknown/undefined role feeds neither src-keyed variant but
// still counts toward deny_storm_victim.
type denyStormDetector struct{}

func (denyStormDetector) Name() string       { return "deny_storm" }
func (denyStormDetector) Category() Category { return CategorySecurity }

func (d denyStormDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	if cfg.DenyStormDisabled {
		return nil, nil
	}
	out := []Detection{}
	// external (WAN-src) then internal (LAN-src)
	ext, err := d.variant(w, models.IntfRoleWAN, cfg.DenyStormExternal, "ext")
	if err != nil {
		return nil, err
	}
	out = append(out, ext...)
	intl, err := d.variant(w, models.IntfRoleLAN, cfg.DenyStormInternal, "int")
	if err != nil {
		return out, err
	}
	return append(out, intl...), nil
}

func (d denyStormDetector) variant(w Window, role uint8, threshold int, tag string) ([]Detection, error) {
	type row struct {
		SrcAddr    string
		DeviceID   uint
		Denies     int64
		Ports      int64
		Dsts       int64
		Threat     int
		SrcCountry string
		Subtype    int
	}
	var rows []row
	if err := w.DB.Model(&models.DeniedEvent{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Where("src_intf_role = ?", role).
		Select("src_addr, MAX(device_id) as device_id, COUNT(*) as denies, "+
			"COUNT(DISTINCT dst_port) as ports, COUNT(DISTINCT dst_addr) as dsts, "+
			"MAX(threat_flag) as threat, MAX(src_country) as src_country, MAX(subtype) as subtype").
		Group("src_addr").
		Having("COUNT(*) >= ?", threshold).
		Order("denies DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		knownBad := denyThreatBad(r.Threat)
		sev := "warning"
		if knownBad {
			sev = "critical"
		}
		scope := "external"
		if role == models.IntfRoleLAN {
			scope = "internal"
		}
		country := ""
		if r.SrcCountry != "" {
			country = " (" + r.SrcCountry + ")"
		}
		msg := fmt.Sprintf("Deny storm from %s %s%s: %d blocked attempts across %d ports / %d targets in the window",
			scope, r.SrcAddr, country, r.Denies, r.Ports, r.Dsts)
		if knownBad {
			msg = "KNOWN-BAD " + msg
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: r.DeviceID, SrcAddr: r.SrcAddr, Score: float64(r.Denies),
			Message:  msg,
			DedupKey: "denystorm_" + tag + "_" + r.SrcAddr,
			Details: map[string]any{
				"scope": scope, "denies": r.Denies, "distinct_ports": r.Ports,
				"distinct_dsts": r.Dsts, "src_country": r.SrcCountry,
				"subtype": denySubtypeLabel(uint8(r.Subtype)), "known_bad": knownBad,
			},
		})
	}
	return out, nil
}

// --- deny_storm_victim (security, victim-keyed) -----------------------------

// denyStormVictimDetector flags a single destination pounded from many distinct
// sources (distributed scan / would-be flood the firewall is dropping). Keyed
// by the victim (DstAddr); routes down the per-detection path, emitting
// SFLOW_DENY_STORM_VICTIM.
type denyStormVictimDetector struct{}

func (denyStormVictimDetector) Name() string       { return "deny_storm_victim" }
func (denyStormVictimDetector) Category() Category { return CategorySecurity }

func (d denyStormVictimDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	if cfg.DenyStormVictimDisabled {
		return nil, nil
	}
	type row struct {
		DstAddr  string
		DeviceID uint
		Denies   int64
		Sources  int64
		Ports    int64
		Threat   int
	}
	var rows []row
	if err := w.DB.Model(&models.DeniedEvent{}).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Select("dst_addr, MAX(device_id) as device_id, COUNT(*) as denies, "+
			"COUNT(DISTINCT src_addr) as sources, COUNT(DISTINCT dst_port) as ports, "+
			"MAX(threat_flag) as threat").
		Group("dst_addr").
		Having("COUNT(DISTINCT src_addr) >= ? OR COUNT(*) >= ?", cfg.DenyVictimSources, cfg.DenyVictimCount).
		Order("sources DESC").Limit(100).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		// bit 1 = the VICTIM (dst) itself is on the threat feed (e.g. a decoy).
		victimFlagged := r.Threat&2 != 0
		sev := "warning"
		if victimFlagged || r.Sources >= int64(cfg.DenyVictimSources)*10 {
			sev = "critical"
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: r.DeviceID, DstAddr: r.DstAddr, Score: float64(r.Sources),
			Message: fmt.Sprintf("Distributed deny storm against %s: %d distinct sources, %d blocked attempts, %d ports in the window",
				r.DstAddr, r.Sources, r.Denies, r.Ports),
			DedupKey: "denyvictim_" + r.DstAddr,
			Details: map[string]any{
				"distinct_sources": r.Sources, "denies": r.Denies,
				"distinct_ports": r.Ports, "victim_flagged": victimFlagged,
			},
		})
	}
	return out, nil
}

// --- denied_then_allowed (policy, src-keyed) --------------------------------

// deniedThenAllowedDetector flags a (src,dst,dport,proto) tuple that was DENIED
// in the last hour and is now ALLOWED — a policy change opened a hole an
// attacker was already probing. Allows come from flow_samples (forwarded, i.e.
// firewall_event <> denied); denies from denied_events. CategoryPolicy so it
// emits its own SFLOW_DENIED_THEN_ALLOWED alert (not folded into the source-
// consolidated SFLOW_SECURITY card — the subject is the exposed path).
//
// Recall caveat: if a FortiGate runs NetFlow netflow-sample-rate>1, the step-1
// allow tuples in flow_samples are sampled → some real allows are missed (false
// negatives), never wrong findings.
type deniedThenAllowedDetector struct{}

func (deniedThenAllowedDetector) Name() string       { return "denied_then_allowed" }
func (deniedThenAllowedDetector) Category() Category { return CategoryPolicy }

func (d deniedThenAllowedDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	if cfg.DeniedThenAllowedDisabled {
		return nil, nil
	}
	// Step 1: candidate ALLOW tuples seen this window (forwarded flows only).
	type allowRow struct {
		SrcAddr  string
		DstAddr  string
		DstPort  uint16
		Protocol uint8
		DeviceID uint
	}
	var allows []allowRow
	if err := forwardedOnly(w.DB.Model(&models.FlowSample{})).
		Where("timestamp >= ? AND timestamp < ?", w.Start, w.End).
		Select("src_addr, dst_addr, dst_port, protocol, MAX(device_id) as device_id").
		Group("src_addr, dst_addr, dst_port, protocol").
		// Surface sensitive-port allows first so a real policy gap to SSH/RDP/SMB/
		// DB isn't the tuple that gets dropped when a busy window has >50 distinct
		// allowed tuples (bounded scan; the cap is a cost guard, not a filter).
		Order(sensitivePortFirstExpr + ", dst_port").Limit(50).Scan(&allows).Error; err != nil {
		return nil, err
	}
	if len(allows) == 0 {
		return nil, nil
	}
	// Step 2: single query — which of those tuples were DENIED in the 60m
	// lookback, at least DeniedThenAllowedMin times? (No per-tuple N+1.)
	type key struct {
		src, dst string
		port     uint16
		proto    uint8
	}
	tuples := make([]key, 0, len(allows))
	seen := make(map[key]allowRow, len(allows))
	for _, a := range allows {
		k := key{a.SrcAddr, a.DstAddr, a.DstPort, a.Protocol}
		if _, ok := seen[k]; !ok {
			seen[k] = a
			tuples = append(tuples, k)
		}
	}
	// Build the IN-list of composite tuples. gorm supports a slice of value
	// slices for a tuple IN on Postgres AND SQLite.
	inVals := make([][]any, 0, len(tuples))
	for _, t := range tuples {
		inVals = append(inVals, []any{t.src, t.dst, t.port, t.proto})
	}
	type denyRow struct {
		SrcAddr     string
		DstAddr     string
		DstPort     uint16
		Protocol    uint8
		PriorDenies int64
		Threat      int
	}
	var denies []denyRow
	if err := w.DB.Model(&models.DeniedEvent{}).
		Where("timestamp >= ? AND timestamp < ?", w.Lookback(60*time.Minute), w.End).
		Where("(src_addr, dst_addr, dst_port, protocol) IN ?", inVals).
		Select("src_addr, dst_addr, dst_port, protocol, COUNT(*) as prior_denies, MAX(threat_flag) as threat").
		Group("src_addr, dst_addr, dst_port, protocol").
		Having("COUNT(*) >= ?", cfg.DeniedThenAllowedMin).Scan(&denies).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(denies))
	for _, r := range denies {
		a := seen[key{r.SrcAddr, r.DstAddr, r.DstPort, r.Protocol}]
		sensitive := portLabels[r.DstPort] != ""
		sev := "warning"
		if sensitive || denyThreatBad(r.Threat) {
			sev = "critical"
		}
		label := ""
		if sensitive {
			label = " " + portLabels[r.DstPort]
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: sev,
			DeviceID: a.DeviceID, SrcAddr: r.SrcAddr, DstAddr: r.DstAddr,
			DstPort: r.DstPort, Protocol: r.Protocol, Score: float64(r.PriorDenies),
			Message: fmt.Sprintf("Policy gap: %s→%s:%d%s was blocked %d× in the last hour, now ALLOWED — verify the rule change was intentional",
				r.SrcAddr, r.DstAddr, r.DstPort, label, r.PriorDenies),
			DedupKey: fmt.Sprintf("denyallow_%s_%s_%d", r.SrcAddr, r.DstAddr, r.DstPort),
			Details: map[string]any{
				"prior_denies": r.PriorDenies, "dst_port": r.DstPort,
				"protocol": r.Protocol, "sensitive_port": sensitive,
			},
		})
	}
	return out, nil
}

// sensitivePortFirstExpr orders sensitive destination ports (the portLabels set
// — SSH/Telnet/SMB/RDP/DB) ahead of everything else, so denied_then_allowed's
// bounded candidate scan keeps the highest-risk allows when it caps at 50.
var sensitivePortFirstExpr = func() string {
	// Build "CASE WHEN dst_port IN (22,23,...) THEN 0 ELSE 1 END" from portLabels
	// so it stays in sync with the sensitivity set the detector escalates on.
	ports := make([]string, 0, len(portLabels))
	for p := range portLabels {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	// Deterministic order for a stable SQL string (map iteration is random).
	sort.Strings(ports)
	return "CASE WHEN dst_port IN (" + strings.Join(ports, ",") + ") THEN 0 ELSE 1 END"
}()

func denySubtypeLabel(s uint8) string {
	switch s {
	case models.DenySubtypeLocal:
		return "local-in"
	case models.DenySubtypeForward:
		return "forward"
	default:
		return "unknown"
	}
}
