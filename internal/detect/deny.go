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
// exports blocked sessions IDENTIFIABLY via NetFlow, so syslog is the only
// deny source. Live prod sharpened that finding (2026-07-17): FortiOS DOES
// emit NetFlow v9 records for denied traffic — it just omits IE 233, so they
// arrive as firewall_event=0 and are indistinguishable from forwarded flows.
// Any detector treating verdict-less flow rows as allow-evidence will see the
// same denied traffic through both pipes (see deniedThenAllowedDetector).
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

// denyAllowQuietMargin is how long a tuple's denies must have been quiet before
// a verdict-less forwarded flow counts as allow-evidence for
// denied_then_allowed. FortiOS exports NetFlow records for DENIED traffic with
// firewall_event=0 (no IE 233), so a flow row co-occurring with active denies
// is usually the deny itself seen through the flow pipe — only traffic that
// KEEPS flowing after denials stop evidences a real policy change. This is
// evidence hygiene, not an operator threshold, hence a const and not a Config
// knob. It must comfortably exceed the deny-side ingest lag (syslog is
// near-realtime; NetFlow exports on session end) without delaying real
// findings by more than one or two detector cycles.
const denyAllowQuietMargin = 10 * time.Minute

// denyAllowIngestGrace excludes the freshest flow rows from allow-evidence.
// A denied packet reaches the DB twice — flow row (NetFlow) and deny row
// (syslog projection) — on different pipes, seconds apart. If a scanner pauses
// past the quiet margin and resumes, its first flow row can land before its
// paired deny row; a detector cycle in that gap would see a "quiet" tuple with
// fresh traffic and fire once (observed transiently on prod). Requiring flow
// evidence to be at least this old lets the paired deny (if any) arrive and
// reset the quiet clock; a real policy gap just fires up to a minute later.
const denyAllowIngestGrace = time.Minute

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
// attacker was already probing. Denies come from denied_events; allow-evidence
// comes from flow_samples, but a forwarded-looking row alone is NOT enough:
// FortiOS exports NetFlow records for denied traffic with firewall_event=0
// (no IE 233), so verdict-less rows co-occurring with active denies are the
// denies themselves seen through the flow pipe (the v0.11.107 false-positive
// flood: Telnet scanner tuples "blocked N×, now ALLOWED" while the denies were
// still arriving). A tuple therefore fires only with real evidence, either:
//   - positive verdict: ≥1 flow row with firewall_event Created/Deleted/Update
//     — the exporter explicitly reported a session lifecycle event (PAN, ASA
//     NSEL, FortiGates that send IE 233); or
//   - temporal quiet gate: the tuple's newest forwarded flow is more than
//     denyAllowQuietMargin AFTER its newest deny — denials stopped, traffic
//     still flows. When a scanner gives up, both streams stop together, so
//     verdict-less noise can never satisfy this.
//
// CategoryPolicy so it emits its own SFLOW_DENIED_THEN_ALLOWED alert (not
// folded into the source-consolidated SFLOW_SECURITY card — the subject is the
// exposed path).
//
// Recall caveat: if a FortiGate runs NetFlow netflow-sample-rate>1, the
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
	// One query: join the per-tuple flow aggregates (allow-evidence side)
	// with the per-tuple deny aggregates and apply the evidence gate in SQL,
	// so it is evaluated over ALL tuples. The LIMIT then caps EMITTED
	// findings — an alert-volume guard on already-gated true positives —
	// ordered sensitive-port-first, then most-denied-first. The pre-fix shape
	// capped CANDIDATES before deny history or the gate were known, so >50
	// gated scanner tuples (a Telnet spray; tie-break dst_port ASC even put
	// port 23 ahead of 3389) starved genuine sensitive-port gaps out of the
	// detector entirely.
	epoch := epochSecondExpr(w.DB)
	type gapRow struct {
		SrcAddr     string
		DstAddr     string
		DstPort     uint16
		Protocol    uint8
		DeviceID    uint
		Verdicted   int
		PriorDenies int64
		Threat      int
	}
	query := fmt.Sprintf(`
		SELECT a.src_addr, a.dst_addr, a.dst_port, a.protocol,
		       a.device_id, a.verdicted, d.prior_denies, d.threat
		FROM (
			SELECT src_addr, dst_addr, dst_port, protocol,
			       MAX(device_id) AS device_id,
			       MAX(%s) AS last_allow,
			       MAX(CASE WHEN firewall_event IN (%d,%d,%d) THEN 1 ELSE 0 END) AS verdicted
			FROM flow_samples
			WHERE timestamp >= ? AND timestamp < ? AND firewall_event <> %d
			GROUP BY src_addr, dst_addr, dst_port, protocol
		) a
		JOIN (
			SELECT src_addr, dst_addr, dst_port, protocol,
			       COUNT(*) AS prior_denies, MAX(threat_flag) AS threat,
			       MAX(%s) AS last_deny
			FROM denied_events
			WHERE timestamp >= ? AND timestamp < ?
			GROUP BY src_addr, dst_addr, dst_port, protocol
			HAVING COUNT(*) >= ?
		) d ON d.src_addr = a.src_addr AND d.dst_addr = a.dst_addr
		   AND d.dst_port = a.dst_port AND d.protocol = a.protocol
		WHERE a.verdicted = 1 OR a.last_allow > d.last_deny + ?
		ORDER BY %s, d.prior_denies DESC
		LIMIT 50`,
		epoch,
		models.FirewallEventCreated, models.FirewallEventDeleted, models.FirewallEventUpdate,
		models.FirewallEventDenied,
		epoch,
		sensitivePortCase("a.dst_port"))
	var rows []gapRow
	// Flow evidence stops denyAllowIngestGrace before the window edge (see the
	// const); the deny lookback runs to the true edge so a freshly projected
	// deny always outranks the flow row it was paired with.
	if err := w.DB.Raw(query,
		w.Start, w.End.Add(-denyAllowIngestGrace),
		w.Lookback(60*time.Minute), w.End, cfg.DeniedThenAllowedMin,
		int64(denyAllowQuietMargin/time.Second)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Detection, 0, len(rows))
	for _, r := range rows {
		evidence := "quiet_gap"
		if r.Verdicted == 1 {
			evidence = "verdict"
		}
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
			DeviceID: r.DeviceID, SrcAddr: r.SrcAddr, DstAddr: r.DstAddr,
			DstPort: r.DstPort, Protocol: r.Protocol, Score: float64(r.PriorDenies),
			Message: fmt.Sprintf("Policy gap: %s→%s:%d%s was blocked %d× in the last hour, now ALLOWED — verify the rule change was intentional",
				r.SrcAddr, r.DstAddr, r.DstPort, label, r.PriorDenies),
			DedupKey: fmt.Sprintf("denyallow_%s_%s_%d", r.SrcAddr, r.DstAddr, r.DstPort),
			Details: map[string]any{
				"prior_denies": r.PriorDenies, "dst_port": r.DstPort,
				"protocol": r.Protocol, "sensitive_port": sensitive,
				"evidence": evidence,
			},
		})
	}
	return out, nil
}

// sensitivePortCase builds "CASE WHEN <col> IN (22,23,...) THEN 0 ELSE 1 END"
// from portLabels, so ORDER BY puts sensitive destination ports (Telnet/SMB/
// RDP/DB — the set the detector escalates on) ahead of everything else when
// denied_then_allowed caps emitted findings at 50. Takes the column reference
// so callers can qualify it inside a join.
func sensitivePortCase(col string) string {
	ports := make([]string, 0, len(portLabels))
	for p := range portLabels {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	// Deterministic order for a stable SQL string (map iteration is random).
	sort.Strings(ports)
	return "CASE WHEN " + col + " IN (" + strings.Join(ports, ",") + ") THEN 0 ELSE 1 END"
}

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
