package database

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/classify"
)

// NOC threat lists (v0.11.269): the threat-intel-flagged flows of the last
// minute, split by WHO STARTED the conversation. A flow exporter records a
// session as a request row and a reply row, one in each direction, so the row
// direction alone would put every flagged address in both lists. The session
// initiator is decided per row, in order:
//
//  1. A TCP SYN without ACK: its source started the session — and decides
//     the direction of the whole session, reply included.
//  2. Equal ports, or no ports at all (ICMP, GRE, ESP): cannot tell.
//  3. The service port. If the flagged side owns it, the flagged address is the
//     server and one of our hosts connected to it (outbound, "talking back");
//     if our side owns it, the flagged address connected to us (inbound).
//
// When BOTH ports are well-known services the stored service port is the lower
// one, which is also the shape of a scan from a spoofed well-known source port
// (a stateless-ACL bypass), so our side's port is used and the row is marked
// inferred. A service port that is not in the known table is a guess, and is
// marked inferred too.
const (
	nocThreatWindow   = 60 * time.Second
	nocThreatTopN     = 10
	nocThreatMaxHosts = 3
	// nocThreatGroupCap bounds the grouped rows read per tick on a very busy
	// install; the summary totals are counted separately and stay exact.
	nocThreatGroupCap = 20000
)

// ThreatEntry is one flagged address in the Inbound or Outbound list.
type ThreatEntry struct {
	Addr     string `json:"addr"`
	Requests int64  `json:"requests"` // sampled request records, not sessions
	Bytes    uint64 `json:"bytes"`    // both halves of the conversation
	Service  uint16 `json:"service"`  // the port with the most requests
	Protocol uint8  `json:"protocol"`
	// InternalHosts names our side (up to three, by requests); InternalCount
	// counts all of them.
	InternalHosts []string `json:"internal_hosts"`
	InternalCount int      `json:"internal_count"`
	Devices       int      `json:"devices"`
	// Inferred: most requests were classified from a guessed service port.
	Inferred bool `json:"inferred,omitempty"`
	// IPMatch: the address itself is listed; false means only its ASN is.
	IPMatch bool  `json:"ip_match"`
	Blocked int64 `json:"blocked,omitempty"`
}

// ThreatSummary counts the window's flagged traffic. Inbound and outbound count
// request records, like the entries; the rest count flow records.
type ThreatSummary struct {
	Inbound      int64 `json:"inbound"`
	Outbound     int64 `json:"outbound"`
	Unclassified int64 `json:"unclassified"`
	Other        int64 `json:"other"`
	Blocked      int64 `json:"blocked"`
}

// NOCThreatTop is the "Threats — last 60 s" card.
type NOCThreatTop struct {
	WindowSeconds int           `json:"window_seconds"`
	Summary       ThreatSummary `json:"summary"`
	Outbound      []ThreatEntry `json:"outbound"`
	Inbound       []ThreatEntry `json:"inbound"`
}

// threatClassSQL returns the per-row derived columns over the flagged flows in
// the window, as a subquery (with its two time binds).
func threatClassSQL() string {
	ports := classify.KnownServicePorts()
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	known := strings.Join(parts, ",")
	// bad/our: the flagged external endpoint and our endpoint, by direction.
	// own: the flag is on the external side (bits 1/4 = source, 2/8 = dest).
	//
	// syn_cls resolves the SYN rule per SESSION: the request and the reply of
	// one conversation share (bad, our, bad_port, our_port, protocol), so a
	// SYN-only record anywhere in the session decides the direction of both
	// halves — otherwise the reply (SYN|ACK, no bare SYN) would fall to the
	// port rule and could land in the opposite list.
	return fmt.Sprintf(`
		SELECT s.*,
			CASE
				WHEN s.own = 0 THEN 'other'
				WHEN s.syn_cls IS NOT NULL THEN s.syn_cls
				WHEN s.protocol NOT IN (6, 17) OR s.src_port = s.dst_port OR s.eff = 0 THEN 'unclassified'
				WHEN s.bad_port = s.eff THEN 'out'
				WHEN s.our_port = s.eff THEN 'in'
				ELSE 'unclassified'
			END AS cls
		FROM (
			SELECT c.*,
				MAX(CASE WHEN c.syn = 1 THEN (CASE WHEN c.direction = 1 THEN 'in' ELSE 'out' END) END)
					OVER (PARTITION BY c.bad, c.our, c.bad_port, c.our_port, c.protocol) AS syn_cls
			FROM (
			SELECT device_id, bytes, protocol, src_port, dst_port, direction, firewall_event,
				CASE WHEN direction = 1 THEN src_addr ELSE dst_addr END AS bad,
				CASE WHEN direction = 1 THEN dst_addr ELSE src_addr END AS our,
				CASE WHEN direction = 1 THEN src_port ELSE dst_port END AS bad_port,
				CASE WHEN direction = 1 THEN dst_port ELSE src_port END AS our_port,
				CASE WHEN (direction = 1 AND (threat_flag & 5) <> 0) OR (direction = 2 AND (threat_flag & 10) <> 0) THEN 1 ELSE 0 END AS own,
				CASE WHEN (direction = 1 AND (threat_flag & 1) <> 0) OR (direction = 2 AND (threat_flag & 2) <> 0) THEN 1 ELSE 0 END AS ipm,
				CASE WHEN protocol = 6 AND (tcp_flags & 18) = 2 THEN 1 ELSE 0 END AS syn,
				CASE WHEN src_port IN (%[1]s) AND dst_port IN (%[1]s)
					THEN (CASE WHEN direction = 1 THEN dst_port ELSE src_port END)
					ELSE service_port END AS eff,
				CASE WHEN src_port IN (%[1]s) AND dst_port IN (%[1]s) THEN 1
					WHEN service_port <> 0 AND app_category = 0 THEN 1 ELSE 0 END AS guessed
			FROM flow_samples
			WHERE timestamp > ? AND timestamp <= ? AND threat_flag <> 0
			) AS c
		) AS s`, known)
}

// threatRequestSQL is the "this row is a request" predicate over threatClassSQL:
// in a session decided by a SYN, the SYN record; otherwise the record sent to
// the service port.
const threatRequestSQL = `(t.cls IN ('in', 'out') AND ((t.syn_cls IS NOT NULL AND t.syn = 1) OR (t.syn_cls IS NULL AND t.dst_port = t.eff)))`

// getNOCThreatTop builds the threat card for the minute ending at nocNow.
func (d *Database) getNOCThreatTop() (*NOCThreatTop, error) {
	now := nocNow().UTC()
	from := now.Add(-nocThreatWindow)
	top := &NOCThreatTop{WindowSeconds: int(nocThreatWindow.Seconds()), Outbound: []ThreatEntry{}, Inbound: []ThreatEntry{}}
	base := threatClassSQL()

	// Totals, exact: request records for in/out, flow records otherwise.
	var sums []struct {
		Cls      string
		Requests int64
		Records  int64
		Blocked  int64
	}
	if err := d.db.Raw(fmt.Sprintf(`
		SELECT t.cls AS cls,
			SUM(CASE WHEN %s THEN 1 ELSE 0 END) AS requests,
			COUNT(*) AS records,
			SUM(CASE WHEN t.firewall_event = 3 THEN 1 ELSE 0 END) AS blocked
		FROM (%s) AS t GROUP BY t.cls`, threatRequestSQL, base), from, now).Scan(&sums).Error; err != nil {
		return nil, fmt.Errorf("noc threats: totals: %w", err)
	}
	for _, s := range sums {
		switch s.Cls {
		case "in":
			top.Summary.Inbound = s.Requests
		case "out":
			top.Summary.Outbound = s.Requests
		case "unclassified":
			top.Summary.Unclassified = s.Records
		default:
			top.Summary.Other = s.Records
		}
		top.Summary.Blocked += s.Blocked
	}

	// Entries: grouped per (class, flagged address, our address, service), then
	// folded per flagged address here.
	var groups []struct {
		Cls      string
		Bad      string
		Our      string
		Eff      uint16
		Protocol uint8
		DeviceID uint
		Requests int64
		Guessed  int64
		IPMatch  int64 `gorm:"column:ip_match"`
		Bytes    uint64
		Blocked  int64
	}
	if err := d.db.Raw(fmt.Sprintf(`
		SELECT t.cls AS cls, t.bad AS bad, t.our AS our, t.eff AS eff, t.protocol AS protocol, t.device_id AS device_id,
			SUM(CASE WHEN %[1]s THEN 1 ELSE 0 END) AS requests,
			SUM(CASE WHEN %[1]s AND t.syn_cls IS NULL AND t.guessed = 1 THEN 1 ELSE 0 END) AS guessed,
			MAX(t.ipm) AS ip_match,
			COALESCE(SUM(t.bytes), 0) AS bytes,
			SUM(CASE WHEN t.firewall_event = 3 THEN 1 ELSE 0 END) AS blocked
		FROM (%[2]s) AS t
		WHERE t.cls IN ('in', 'out')
		GROUP BY t.cls, t.bad, t.our, t.eff, t.protocol, t.device_id
		ORDER BY requests DESC, bad ASC
		LIMIT %[3]d`, threatRequestSQL, base, nocThreatGroupCap), from, now).Scan(&groups).Error; err != nil {
		return nil, fmt.Errorf("noc threats: entries: %w", err)
	}

	in, out := map[string]*threatAcc{}, map[string]*threatAcc{}
	for _, g := range groups {
		m := in
		if g.Cls == "out" {
			m = out
		}
		a := m[g.Bad]
		if a == nil {
			a = &threatAcc{entry: ThreatEntry{Addr: g.Bad}, hosts: map[string]int64{}, devices: map[uint]struct{}{}, services: map[[2]uint16]int64{}}
			m[g.Bad] = a
		}
		a.entry.Requests += g.Requests
		a.entry.Bytes += g.Bytes
		a.entry.Blocked += g.Blocked
		a.guessed += g.Guessed
		if g.IPMatch > 0 {
			a.entry.IPMatch = true
		}
		a.hosts[g.Our] += g.Requests
		a.devices[g.DeviceID] = struct{}{}
		if g.Requests > 0 {
			a.services[[2]uint16{g.Eff, uint16(g.Protocol)}] += g.Requests
		}
	}
	top.Inbound = foldThreatEntries(in)
	top.Outbound = foldThreatEntries(out)
	return top, nil
}

// threatAcc accumulates one flagged address's grouped rows.
type threatAcc struct {
	entry    ThreatEntry
	guessed  int64
	hosts    map[string]int64 // our address -> requests
	devices  map[uint]struct{}
	services map[[2]uint16]int64 // {port, proto} -> requests
}

// foldThreatEntries finishes the per-address accumulators and returns the top
// entries: addresses with at least one request, IP matches before ASN-only
// matches, then by requests.
func foldThreatEntries(m map[string]*threatAcc) []ThreatEntry {
	out := make([]ThreatEntry, 0, len(m))
	for _, a := range m {
		e := a.entry
		if e.Requests == 0 {
			continue // only the reply half fell inside the window
		}
		e.Inferred = a.guessed*2 > e.Requests
		e.Devices = len(a.devices)
		e.InternalCount = len(a.hosts)
		hosts := make([]string, 0, len(a.hosts))
		for h := range a.hosts {
			hosts = append(hosts, h)
		}
		sort.Slice(hosts, func(i, j int) bool {
			if a.hosts[hosts[i]] != a.hosts[hosts[j]] {
				return a.hosts[hosts[i]] > a.hosts[hosts[j]]
			}
			return hosts[i] < hosts[j]
		})
		if len(hosts) > nocThreatMaxHosts {
			hosts = hosts[:nocThreatMaxHosts]
		}
		e.InternalHosts = hosts
		var best [2]uint16
		var bestN int64 = -1
		for svc, n := range a.services {
			if n > bestN || (n == bestN && svc[0] < best[0]) {
				best, bestN = svc, n
			}
		}
		e.Service, e.Protocol = best[0], uint8(best[1])
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPMatch != out[j].IPMatch {
			return out[i].IPMatch
		}
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Addr < out[j].Addr
	})
	if len(out) > nocThreatTopN {
		out = out[:nocThreatTopN]
	}
	return out
}
