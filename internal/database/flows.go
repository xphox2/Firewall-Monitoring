package database

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// protoNames maps IP protocol numbers to human-readable names.
var protoNames = map[uint8]string{
	0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 8: "EGP",
	17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE",
	50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
	88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 137: "MPLS-in-IP",
}

// protoName returns the human name for a protocol number, or "Proto N" as fallback.
func protoName(p uint8) string {
	if name, ok := protoNames[p]; ok {
		return name
	}
	return fmt.Sprintf("Proto %d", p)
}

// FlowStatsResult holds aggregated flow statistics
var wellKnownPorts = map[uint16]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 500: "IKE", 4500: "NAT-T",
	1194: "OpenVPN", 51820: "WireGuard",
}

type FlowStatsResult struct {
	TotalFlows       int64              `json:"total_flows"`
	TotalBytes       uint64             `json:"total_bytes"`
	TotalPackets     uint64             `json:"total_packets"`
	BitsPerSecond    float64            `json:"bits_per_second"`
	UniqueSources    int64              `json:"unique_sources"`
	UniqueDests      int64              `json:"unique_dests"`
	ProtocolCount    int64              `json:"protocol_count"`
	BucketSeconds    int                `json:"bucket_seconds"`
	AvgSamplingRate  float64            `json:"avg_sampling_rate"`
	EstimatedBytes   uint64             `json:"estimated_bytes"`
	ByProtocol       []KeyCount         `json:"by_protocol"`
	ByCategory       []KeyCount         `json:"by_category"`
	ByDirection      []KeyCount         `json:"by_direction"`
	TopCountries     []KeyCount         `json:"top_countries"`
	TopASNs          []KeyCount         `json:"top_asns"`
	TopSources       []KeyCount         `json:"top_sources"`
	TopDestinations  []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
	TopPorts         []KeyCount         `json:"top_ports"`
	// LocalTraffic is the scope-local noise (link-local / multicast / broadcast /
	// loopback) excluded from the top-N charts above. JSON name kept as
	// `local_traffic` for API stability; the Flows notice bar surfaces it.
	LocalTraffic struct {
		Bytes   uint64 `json:"bytes"`
		Packets uint64 `json:"packets"`
		Flows   int64  `json:"flows"`
	} `json:"local_traffic"`
	// MixedSourceDevices lists device names whose recent flows carry more
	// than one flow_source — the same traffic metered by two protocols
	// double-counts every byte, so the UI warns (Tranche 3 dual-export
	// visibility; the collector-side dedup policy normally prevents this).
	MixedSourceDevices []string `json:"mixed_source_devices,omitempty"`
	// GeoEnabled / GeoSource describe whether geo/ASN enrichment is active and
	// where the database comes from, so the UI can show the Top Countries / ASNs
	// cards with a meaningful state instead of hiding them silently. Set by the
	// handler (the DB layer doesn't know the runtime geo config).
	GeoEnabled bool   `json:"geo_enabled"`
	GeoSource  string `json:"geo_source,omitempty"`
}

// GetMixedFlowSourceDevices returns the names of devices whose last hour of
// flow_samples contains >1 distinct flow_source. Uses the (device_id,
// timestamp) index prefix; errors degrade to an empty list (the banner is
// advisory, never load-bearing).
//
// Two groupings, because device resolution can fail for one flow family while
// succeeding for the other (a `device_id > 0`-only GROUP BY then never sees
// both sources in one group and the advisory stays silent):
//  1. by device_id over attributed rows — catches a device whose two families
//     export from DIFFERENT sampler IPs (multi-VDOM / mgmt-interface exports);
//  2. by sampler_address over ALL rows (attributed or not) — catches the same
//     exporter IP sending two families regardless of whether either family
//     resolved to a device. Labeled with the device name when any row
//     resolved, else with the bare sampler address.
func (d *Database) GetMixedFlowSourceDevices() []string {
	cutoff := time.Now().Add(-time.Hour)
	var byDevice []string
	if err := d.db.Raw(`SELECT dv.name FROM devices dv WHERE dv.id IN (
			SELECT device_id FROM flow_samples
			WHERE timestamp > ? AND device_id > 0
			GROUP BY device_id
			HAVING COUNT(DISTINCT flow_source) > 1
		)`, cutoff).Scan(&byDevice).Error; err != nil {
		log.Printf("GetMixedFlowSourceDevices: %v", err)
		return nil
	}
	var bySampler []string
	if err := d.db.Raw(`SELECT COALESCE(NULLIF(dv.name, ''), m.addr) FROM (
			SELECT sampler_address AS addr, MAX(device_id) AS did
			FROM flow_samples
			WHERE timestamp > ? AND sampler_address <> ''
			GROUP BY sampler_address
			HAVING COUNT(DISTINCT flow_source) > 1
		) m LEFT JOIN devices dv ON dv.id = m.did`, cutoff).Scan(&bySampler).Error; err != nil {
		log.Printf("GetMixedFlowSourceDevices (sampler grouping): %v", err)
		bySampler = nil // keep the device-grouped result — advisory degrades, never fails
	}
	seen := make(map[string]struct{}, len(byDevice)+len(bySampler))
	names := make([]string, 0, len(byDevice)+len(bySampler))
	for _, n := range append(byDevice, bySampler...) {
		if _, dup := seen[n]; dup || n == "" {
			continue
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// topAddrsByBytes returns top N addresses grouped by addrCol, ordered by total bytes descending.
func topAddrsByBytes(base func() *gorm.DB, addrCol string, limit int) []KeyCount {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	base().Select(addrCol + " as addr, SUM(bytes) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out
}

// topAddrsByBytesRollup is like topAddrsByBytes but for rollup tables (bytes_sum column).
func topAddrsByBytesRollup(base func() *gorm.DB, addrCol string, limit int) []KeyCount {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	base().Select(addrCol + " as addr, SUM(bytes_sum) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out
}

// FlowStatsFilter narrows GetFlowStats to a subset of flows. All fields are
// optional; the zero value means "no filter" for that dimension. These mirror
// the filters the Flow Samples list honors, so the Flows page's shared filter
// row drives the aggregate views (top talkers, conversations, chart) too.
type FlowStatsFilter struct {
	DeviceID    uint    // device_id (flow_samples + flow_rollups)
	SiteID      uint    // site_id — matches every device in the site via subquery
	ProbeID     uint    // probe_id  (flow_samples only — forces raw-only when set)
	Protocol    *uint8  // IP protocol number; nil = all
	DstPort     *uint16 // destination port; nil = all
	SrcAddr     string  // source IP or CIDR (cidrToLikePattern semantics)
	DstAddr     string  // destination IP or CIDR
	AppCategory *uint8  // classify.Category id; nil = all
	Direction   *uint8  // classify.Dir* id; nil = all
	DstCountry  string  // ISO alpha-2 destination country; "" = all
	DstASN      *uint32 // destination ASN; nil = all
	FlowSource  *uint8  // models.FlowSource* (0=sFlow,1=v5,2=v9,3=IPFIX); nil = all
	// FirewallEvent filters on the IE 233 event label (models.FirewallEvent*;
	// 3 = denied). 0 (none) is a real value — nil = all. Carried onto rollups
	// by migration v30, so the filter resolves past the raw window.
	FirewallEvent *uint8
}

// flowAddrFilter applies an IP/CIDR filter on an address column. It reuses
// cidrToLikePattern (the same helper the connection-detail flow queries use) so
// the conversations/top-talker views filter addresses identically to how the
// samples list does. An unparseable value falls back to an exact match (no
// rows) rather than silently dropping the filter.
func flowAddrFilter(q *gorm.DB, column, val string) *gorm.DB {
	val = strings.TrimSpace(val)
	if val == "" {
		return q
	}
	pattern := cidrToLikePattern(val)
	if pattern == "" {
		return q.Where(column+" = ?", val)
	}
	if strings.Contains(pattern, "%") {
		return q.Where(column+" LIKE ? ESCAPE '\\'", pattern)
	}
	return q.Where(column+" = ?", pattern)
}

// rollupIntervalsForWindow returns every rollup tier whose age band intersects
// a lookback window of `hours`. The rollup ladder (RunFlowRollupCycle) keeps
// tiers DISJOINT — each promotion deletes its source rows — so raw covers the
// last ~1h, 5m covers (1h,48h], 1h covers (48h,30d], 1d covers >30d. Any
// window longer than a band's start intersects that band, so the tier list is
// cumulative, and summing across the returned tiers can neither gap nor
// double-count. Shared by GetFlowStats and GetConnectionFlowStats.
func rollupIntervalsForWindow(hours int) []string {
	intervals := []string{"5m"}
	if hours > 48 {
		intervals = append(intervals, "1h")
	}
	if hours > 720 { // 30 days
		intervals = append(intervals, "1d")
	}
	return intervals
}

// GetFlowStats returns aggregated flow statistics, optionally narrowed by filter.
// It queries both raw flow_samples (recent) and flow_rollups (older data).
func (d *Database) GetFlowStats(hours int, filter FlowStatsFilter) (*FlowStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &FlowStatsResult{}

	// Determine which data source to use:
	// - hours <= 1: raw samples only (rollups haven't consumed them yet)
	// - hours > 1: union raw samples + rollups
	// A probe_id filter forces raw-only: flow_rollups has no probe_id column, so
	// it can't honor that filter without leaking rows the operator excluded.
	useRollups := hours > 1 && filter.ProbeID == 0

	// applyCommonFilters writes the filters shared by flow_samples and
	// flow_rollups (both carry device_id / src_addr / dst_addr / dst_port /
	// protocol). probe_id is applied separately on the raw base only.
	applyCommonFilters := func(q *gorm.DB) *gorm.DB {
		if filter.DeviceID > 0 {
			q = q.Where("device_id = ?", filter.DeviceID)
		}
		// Site filter: an uncorrelated subquery against the small devices table.
		// flow_samples/flow_rollups carry device_id but no site_id, so a site maps
		// to "every device currently assigned to it". Portable on SQLite and PG.
		if filter.SiteID > 0 {
			q = q.Where("device_id IN (SELECT id FROM devices WHERE site_id = ?)", filter.SiteID)
		}
		if filter.Protocol != nil {
			q = q.Where("protocol = ?", *filter.Protocol)
		}
		if filter.DstPort != nil {
			q = q.Where("dst_port = ?", *filter.DstPort)
		}
		if filter.AppCategory != nil {
			q = q.Where("app_category = ?", *filter.AppCategory)
		}
		if filter.Direction != nil {
			q = q.Where("direction = ?", *filter.Direction)
		}
		if filter.DstCountry != "" {
			q = q.Where("dst_country = ?", filter.DstCountry)
		}
		if filter.DstASN != nil {
			q = q.Where("dst_asn = ?", *filter.DstASN)
		}
		// flow_source exists on BOTH flow_samples and flow_rollups (v29), so
		// this filter works across the raw window and rolled-up history alike.
		if filter.FlowSource != nil {
			q = q.Where("flow_source = ?", *filter.FlowSource)
		}
		// firewall_event likewise exists on both tables (v30) — the Denied
		// filter holds up after raw samples age out.
		if filter.FirewallEvent != nil {
			q = q.Where("firewall_event = ?", *filter.FirewallEvent)
		}
		q = flowAddrFilter(q, "src_addr", filter.SrcAddr)
		q = flowAddrFilter(q, "dst_addr", filter.DstAddr)
		return q
	}

	// --- Raw flow_samples base ---
	newRawBase := func() *gorm.DB {
		q := applyCommonFilters(d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff))
		if filter.ProbeID > 0 {
			q = q.Where("probe_id = ?", filter.ProbeID)
		}
		return q
	}

	// --- Rollup base ---
	// The rollup lifecycle keeps each age band in exactly ONE tier (promotion
	// deletes the source rows in the same transaction): 5m covers (1h,48h],
	// 1h covers (48h,30d], 1d covers >30d. A window therefore needs EVERY tier
	// whose band it intersects — querying a single "best" interval left the
	// younger bands out entirely (a 7d view silently dropped (1h,48h], ~28% of
	// its window and the most recent part). Because the tiers are disjoint by
	// construction, summing across them can never double-count.
	rollupIntervals := rollupIntervalsForWindow(hours)
	newRollupBase := func() *gorm.DB {
		return applyCommonFilters(d.db.Model(&models.FlowRollup{}).Where("timestamp > ? AND interval_type IN ?", cutoff, rollupIntervals))
	}

	// Combined aggregates: count, bytes, unique src/dst from raw samples
	var rawAgg struct {
		TotalFlows    int64
		TotalBytes    uint64
		UniqueSources int64
		UniqueDests   int64
	}
	// L1 of the 2026-07-01 audit: flow_samples.bytes is ALREADY sampling-scaled
	// at ingest (collector + server parser both multiply by sampling_rate;
	// migration v7 backfilled historical rows), so SUM(bytes) is real traffic —
	// do NOT multiply again below.
	if err := newRawBase().Select("COUNT(*) as total_flows, COALESCE(SUM(bytes),0) as total_bytes, " +
		"COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
		Scan(&rawAgg).Error; err != nil {
		return nil, fmt.Errorf("flow stats raw aggregates: %w", err)
	}
	result.TotalFlows = rawAgg.TotalFlows
	result.TotalBytes = rawAgg.TotalBytes
	result.UniqueSources = rawAgg.UniqueSources
	result.UniqueDests = rawAgg.UniqueDests

	// Add rollup aggregates if needed
	if useRollups {
		var rollupAgg struct {
			TotalFlows    int64
			TotalBytes    uint64
			UniqueSources int64
			UniqueDests   int64
		}
		if err := newRollupBase().Select("COALESCE(SUM(flow_count),0) as total_flows, COALESCE(SUM(bytes_sum),0) as total_bytes, " +
			"COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
			Scan(&rollupAgg).Error; err != nil {
			log.Printf("Flow stats rollup aggregates: %v", err)
		} else {
			result.TotalFlows += rollupAgg.TotalFlows
			result.TotalBytes += rollupAgg.TotalBytes
			// For unique counts, the union of distinct sets needs re-counting; this is approximate
			if rollupAgg.UniqueSources > result.UniqueSources {
				result.UniqueSources = rollupAgg.UniqueSources
			}
			if rollupAgg.UniqueDests > result.UniqueDests {
				result.UniqueDests = rollupAgg.UniqueDests
			}
		}
	}

	// Total packets from raw
	var totalPkts struct{ Sum uint64 }
	newRawBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPkts)
	result.TotalPackets = totalPkts.Sum

	// Average sampling rate (0 means no sampling or unknown)
	var avgRate struct{ Rate float64 }
	newRawBase().Select("COALESCE(AVG(CASE WHEN sampling_rate > 0 THEN sampling_rate ELSE NULL END),0) as rate").Scan(&avgRate)
	result.AvgSamplingRate = avgRate.Rate
	// L1: bytes is already sampling-scaled, so estimated == total (the field is
	// retained for API back-compat; the old `* AvgSamplingRate` over-reported by
	// ~the sampling rate).
	result.EstimatedBytes = result.TotalBytes

	// Computed throughput
	if hours > 0 {
		result.BitsPerSecond = float64(result.TotalBytes) * 8 / (float64(hours) * 3600)
	}

	// Scope-local traffic stats (link-local / multicast / broadcast / loopback
	// noise, flagged at ingest by classify.ScopeLocal). Raw and rollup bases use
	// the SAME predicate now, so the two tiers agree across the raw/rollup window
	// boundary (the old port-0 filter was asymmetric: NOT(src=0 AND dst=0) vs
	// dst_port != 0).
	var localRaw struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	newRawBase().Where("scope_local = ?", true).
		Select("COALESCE(SUM(bytes),0) as bytes, COALESCE(SUM(packets),0) as packets, COUNT(*) as flows").
		Scan(&localRaw)
	result.LocalTraffic.Bytes = localRaw.Bytes
	result.LocalTraffic.Packets = localRaw.Packets
	result.LocalTraffic.Flows = localRaw.Flows

	if useRollups {
		var localRollup struct {
			Bytes   uint64
			Packets uint64
			Flows   int64
		}
		newRollupBase().Where("scope_local = ?", true).
			Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
			Scan(&localRollup)
		result.LocalTraffic.Bytes += localRollup.Bytes
		result.LocalTraffic.Packets += localRollup.Packets
		result.LocalTraffic.Flows += localRollup.Flows
	}

	// Filtered bases that exclude scope-local noise for top-N charts. Portless
	// routed protocols (ESP/GRE/ICMP/OSPF) are NOT scope-local, so they now
	// appear in the top-talker cards (the old port-0 filter hid them).
	newFilteredRawBase := func() *gorm.DB {
		return newRawBase().Where("scope_local = ?", false)
	}
	newFilteredRollupBase := func() *gorm.DB {
		return newRollupBase().Where("scope_local = ?", false)
	}

	// Protocol distribution (from raw; supplement with rollups).
	// Exclude protocol 0 (HOPOPT): it is never a legitimate terminal protocol
	// in a flow record — it only appears when an IPv6 packet's Hop-by-Hop
	// extension header was mistaken for the upper-layer protocol (see the
	// collector's IPv6 extension-header walk fix) or a packet was unparseable.
	// Leaving it in let it dominate the breakdown. Other portless protocols
	// (ICMP/GRE/ESP/OSPF) are intentionally kept.
	var protocols []struct {
		Protocol uint8
		Count    int64
	}
	if err := newRawBase().Where("protocol <> 0").Select("protocol, COUNT(*) as count").Group("protocol").
		Order("count DESC").Limit(10).Scan(&protocols).Error; err != nil {
		log.Printf("Flow stats protocol distribution: %v", err)
	}
	if useRollups {
		var rollupProtos []struct {
			Protocol uint8
			Count    int64
		}
		newRollupBase().Where("protocol <> 0").Select("protocol, SUM(flow_count) as count").Group("protocol").
			Order("count DESC").Limit(10).Scan(&rollupProtos)
		// Merge rollup protocol counts into raw
		protoMap := make(map[uint8]int64)
		for _, p := range protocols {
			protoMap[p.Protocol] = p.Count
		}
		for _, p := range rollupProtos {
			protoMap[p.Protocol] += p.Count
		}
		protocols = protocols[:0]
		for proto, count := range protoMap {
			protocols = append(protocols, struct {
				Protocol uint8
				Count    int64
			}{proto, count})
		}
		sort.SliceStable(protocols, func(i, j int) bool { return protocols[i].Count > protocols[j].Count })
		if len(protocols) > 10 {
			protocols = protocols[:10]
		}
	}
	for _, p := range protocols {
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
	}
	result.ProtocolCount = int64(len(protocols))

	// Application-category and direction distribution (by flow count), raw
	// samples supplemented with rollups. Both are ingest-time classification
	// columns (internal/classify) carried onto rollups, so the breakdown holds
	// up after raw samples age out. Closure mirrors the protocol-distribution
	// merge above for a single smallint dimension column.
	dimDist := func(col string, nameFn func(uint8) string) []KeyCount {
		type drow struct {
			V     uint8
			Count int64
		}
		var raws []drow
		newRawBase().Select(col + " as v, COUNT(*) as count").Group(col).Scan(&raws)
		m := make(map[uint8]int64, len(raws))
		for _, r := range raws {
			m[r.V] += r.Count
		}
		if useRollups {
			var rs []drow
			newRollupBase().Select(col + " as v, SUM(flow_count) as count").Group(col).Scan(&rs)
			for _, r := range rs {
				m[r.V] += r.Count
			}
		}
		out := make([]KeyCount, 0, len(m))
		for v, c := range m {
			out = append(out, KeyCount{Key: nameFn(v), Count: c})
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		return out
	}
	result.ByCategory = dimDist("app_category", classify.CategoryName)
	result.ByDirection = dimDist("direction", classify.DirectionName)

	// Top destination countries / ASNs by bytes (GeoLite2 enrichment; empty when
	// geo is disabled). Destination-oriented — where traffic is going. The
	// `<> ''` / `<> 0` filters exclude unmapped rows (NULL too: NULL <> '' is not
	// TRUE), which covers all internal/private traffic GeoLite2 doesn't map.
	geoTopCountry := func() []KeyCount {
		type grow struct {
			K     string
			Total int64
		}
		collect := func(base func() *gorm.DB, byteCol string) []KeyCount {
			var rows []grow
			base().Where("dst_country <> ?", "").
				Select("dst_country as k, SUM(" + byteCol + ") as total").
				Group("dst_country").Order("total DESC").Limit(10).Scan(&rows)
			out := make([]KeyCount, 0, len(rows))
			for _, r := range rows {
				out = append(out, KeyCount{Key: r.K, Count: r.Total})
			}
			return out
		}
		out := collect(newFilteredRawBase, "bytes")
		if useRollups {
			out = mergeKeyCounts(out, collect(newFilteredRollupBase, "bytes_sum"), 10)
		}
		return out
	}
	geoTopASN := func() []KeyCount {
		type grow struct {
			K     int64
			Total int64
		}
		collect := func(base func() *gorm.DB, byteCol string) []KeyCount {
			var rows []grow
			base().Where("dst_asn <> 0").
				Select("dst_asn as k, SUM(" + byteCol + ") as total").
				Group("dst_asn").Order("total DESC").Limit(10).Scan(&rows)
			out := make([]KeyCount, 0, len(rows))
			for _, r := range rows {
				out = append(out, KeyCount{Key: fmt.Sprintf("AS%d", r.K), Count: r.Total})
			}
			return out
		}
		out := collect(newFilteredRawBase, "bytes")
		if useRollups {
			out = mergeKeyCounts(out, collect(newFilteredRollupBase, "bytes_sum"), 10)
		}
		return out
	}
	result.TopCountries = geoTopCountry()
	result.TopASNs = geoTopASN()

	// Top sources by bytes (filtered: excludes port-0 local traffic)
	result.TopSources = topAddrsByBytes(newFilteredRawBase, "src_addr", 10)
	if useRollups {
		rollupSrc := topAddrsByBytesRollup(newFilteredRollupBase, "src_addr", 10)
		result.TopSources = mergeKeyCounts(result.TopSources, rollupSrc, 10)
	}

	// Top destinations by bytes (filtered: excludes port-0 local traffic)
	result.TopDestinations = topAddrsByBytes(newFilteredRawBase, "dst_addr", 10)
	if useRollups {
		rollupDst := topAddrsByBytesRollup(newFilteredRollupBase, "dst_addr", 10)
		result.TopDestinations = mergeKeyCounts(result.TopDestinations, rollupDst, 10)
	}

	// Top conversations (filtered: excludes port-0 local traffic)
	var convos []struct {
		SrcAddr  string
		DstAddr  string
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	if err := newFilteredRawBase().Select("src_addr, dst_addr, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, dst_port, protocol").
		Order("bytes DESC").Limit(10).Scan(&convos).Error; err != nil {
		log.Printf("Flow stats top conversations: %v", err)
	}
	for _, c := range convos {
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr:  c.SrcAddr,
			DstAddr:  c.DstAddr,
			DstPort:  c.DstPort,
			Protocol: protoName(c.Protocol),
			Bytes:    c.Bytes,
			Packets:  c.Packets,
		})
	}

	// Top destination ports
	var topPorts []struct {
		Port  uint16
		Total int64
	}
	newFilteredRawBase().Select("dst_port as port, SUM(bytes) as total").
		Where("dst_port > 0").Group("dst_port").Order("total DESC").Limit(10).Scan(&topPorts)
	for _, p := range topPorts {
		portName := fmt.Sprintf("%d", p.Port)
		if n, ok := wellKnownPorts[p.Port]; ok {
			portName = n
		}
		result.TopPorts = append(result.TopPorts, KeyCount{Key: portName, Count: p.Total})
	}

	// Adaptive time bucketing for bytes over time
	bucketUnit := "hour"
	result.BucketSeconds = 3600
	if hours <= 6 {
		bucketUnit = "minute"
		result.BucketSeconds = 60
	} else if hours > 168 {
		bucketUnit = "day"
		result.BucketSeconds = 86400
	}
	var timeSeries []struct {
		Bucket string
		Total  int64
	}
	if err := newRawBase().Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries).Error; err != nil {
		log.Printf("Flow stats bytes over time: %v", err)
	}

	// Merge rollup time series
	if useRollups {
		var rollupTS []struct {
			Bucket string
			Total  int64
		}
		newRollupBase().Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes_sum) as total").
			Group("bucket").Order("bucket ASC").Scan(&rollupTS)
		timeSeries = mergeTimeSeries(timeSeries, rollupTS)
	}

	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

// mergeKeyCounts merges two KeyCount slices by summing counts for matching keys,
// then returns the top N sorted by count descending.
func mergeKeyCounts(a, b []KeyCount, limit int) []KeyCount {
	m := make(map[string]int64, len(a)+len(b))
	for _, kc := range a {
		m[kc.Key] += kc.Count
	}
	for _, kc := range b {
		m[kc.Key] += kc.Count
	}
	merged := make([]KeyCount, 0, len(m))
	for k, c := range m {
		merged = append(merged, KeyCount{Key: k, Count: c})
	}
	// Sort descending by count
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].Count > merged[j].Count })
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

// mergeTimeSeries merges two time-bucketed series by summing totals for matching buckets.
func mergeTimeSeries(a, b []struct {
	Bucket string
	Total  int64
}) []struct {
	Bucket string
	Total  int64
} {
	m := make(map[string]int64, len(a)+len(b))
	for _, ts := range a {
		m[ts.Bucket] += ts.Total
	}
	for _, ts := range b {
		m[ts.Bucket] += ts.Total
	}
	// Collect and sort by bucket
	result := make([]struct {
		Bucket string
		Total  int64
	}, 0, len(m))
	for k, v := range m {
		result = append(result, struct {
			Bucket string
			Total  int64
		}{k, v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Bucket < result[j].Bucket })
	return result
}

// rollupRow holds aggregated data during rollup operations.
type rollupRow struct {
	Bucket          string
	DeviceID        uint
	SrcAddr         string
	DstAddr         string
	DstPort         uint16
	Protocol        uint8
	AppCategory     uint8
	Direction       uint8
	ScopeLocal      bool
	DstCountry      string
	DstASN          uint32
	FlowSource      uint8
	FirewallEvent   uint8
	BytesSum        uint64
	PacketsSum      uint64
	FlowCount       int64
	SamplingRateAvg float64
}

// batchInsertRollups inserts rollup rows in batches within the given transaction.
func batchInsertRollups(tx *gorm.DB, rows []rollupRow, intervalType, bucketFmt string) error {
	const batchSize = 500
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]models.FlowRollup, 0, end-i)
		for _, r := range rows[i:end] {
			ts, _ := time.Parse(bucketFmt, r.Bucket)
			batch = append(batch, models.FlowRollup{
				Timestamp:       ts,
				DeviceID:        r.DeviceID,
				IntervalType:    intervalType,
				SrcAddr:         r.SrcAddr,
				DstAddr:         r.DstAddr,
				DstPort:         r.DstPort,
				Protocol:        r.Protocol,
				AppCategory:     r.AppCategory,
				Direction:       r.Direction,
				ScopeLocal:      r.ScopeLocal,
				DstCountry:      r.DstCountry,
				DstASN:          r.DstASN,
				FlowSource:      r.FlowSource,
				FirewallEvent:   r.FirewallEvent,
				BytesSum:        r.BytesSum,
				PacketsSum:      r.PacketsSum,
				FlowCount:       r.FlowCount,
				SamplingRateAvg: r.SamplingRateAvg,
			})
		}
		if err := tx.Create(&batch).Error; err != nil {
			return fmt.Errorf("batch insert rollups: %w", err)
		}
	}
	return nil
}

// RunFlowRollupCycle aggregates raw flow samples into rollup buckets for scalability.
// Called every 5 minutes by the poller:
//  1. Raw flows older than 1h → 5m rollups
//  2. 5m rollups older than 48h → 1h rollups
//  3. 1h rollups older than 30d → 1d rollups
func (d *Database) RunFlowRollupCycle() {
	work := false

	// Step 1: raw flows > 1h old → 5m rollups
	cutoff1h := time.Now().Add(-1 * time.Hour)
	if d.aggregateFlowsToRollup(cutoff1h, "5m") {
		work = true
	}

	// Step 2: 5m rollups > 48h old → 1h rollups
	cutoff48h := time.Now().Add(-48 * time.Hour)
	if d.aggregateRollupsUp("5m", "1h", cutoff48h) {
		work = true
	}

	// Step 3: 1h rollups > 30d old → 1d rollups
	cutoff30d := time.Now().Add(-30 * 24 * time.Hour)
	if d.aggregateRollupsUp("1h", "1d", cutoff30d) {
		work = true
	}

	if !work {
		log.Println("Flow rollup: cycle complete (no data to aggregate)")
	}
}

// flowRollupPageSize bounds how many distinct groups each rollup aggregation
// reads per page. A package var (not a const) so tests can shrink it to
// exercise the multi-page path. Defaults to 50000.
var flowRollupPageSize = 50000

// flowRollupGroupKey is the full grouping key of the rollup aggregations. It
// doubles as the ORDER BY so LIMIT/OFFSET partitions the group set
// deterministically — without it, PostgreSQL's hash/parallel aggregation gives
// no cross-query ordering guarantee and pages can overlap or skip groups
// (H1 of the 2026-07-01 audit).
// firewall_event joined the key in v30 (LC-03): without it a denied record —
// "the headline NetFlow win" — was collapsed into an anonymous flow_count and
// erased one hour after ingest. Like flow_source it is near-functionally
// determined per conversation (1-2 values in practice, 6 possible), so the
// cardinality cost is bounded.
const flowRollupGroupKey = "bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event"

// aggregateFlowsToRollup groups raw FlowSamples older than cutoff into 5-minute rollups.
// Returns true if work was done.
//
// Correctness shape (H1+H2 of the 2026-07-01 audit):
//   - A MAX(id) watermark is captured first and every read AND the final delete
//     are scoped to `id <= watermark`, so the source set is immutable for the
//     whole pass — rows that arrive mid-aggregation (e.g. a collector replaying
//     its store-and-forward backlog with old timestamps) are never deleted
//     un-aggregated; they simply wait for the next cycle.
//   - The paginated GROUP BY carries a deterministic ORDER BY over the full
//     group key, so OFFSET pages neither overlap nor skip groups.
//   - The page inserts and the consumed-row delete run in ONE transaction:
//     either the whole pass commits (rollups inserted + raw rows deleted) or
//     nothing changed, so a mid-pass failure can never leave rollups behind
//     for the next cycle to double-count.
func (d *Database) aggregateFlowsToRollup(cutoff time.Time, intervalType string) bool {
	bucketExpr := d.dialect.TimeBucket("5min", "timestamp")
	pageSize := flowRollupPageSize
	totalGroups := 0

	err := d.db.Transaction(func(tx *gorm.DB) error {
		// Work probe first: an unfiltered watermark is non-zero whenever the
		// table holds any row, so it can no longer signal "nothing to roll up".
		var probe []int64
		if err := tx.Model(&models.FlowSample{}).
			Where("timestamp < ?", cutoff).
			Select("1").Limit(1).
			Scan(&probe).Error; err != nil {
			return fmt.Errorf("flow rollup: work probe: %w", err)
		}
		if len(probe) == 0 {
			return nil
		}

		// UNFILTERED deliberately — see the note on the promote path below. The
		// watermark is only an upper bound excluding rows that arrive mid-pass,
		// so any bound >= every id in the target set is correct; the predicates
		// stay on the reads and the delete, which already carry them.
		var watermark int64
		if err := tx.Model(&models.FlowSample{}).
			Select("COALESCE(MAX(id), 0)").
			Scan(&watermark).Error; err != nil {
			return fmt.Errorf("flow rollup: watermark: %w", err)
		}
		if watermark == 0 {
			return nil
		}

		offset := 0
		for {
			var rows []rollupRow
			if err := tx.Model(&models.FlowSample{}).
				Where("timestamp < ? AND id <= ?", cutoff, watermark).
				Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event, " +
					"SUM(bytes) as bytes_sum, SUM(packets) as packets_sum, COUNT(*) as flow_count, " +
					"AVG(sampling_rate) as sampling_rate_avg").
				Group(flowRollupGroupKey).
				Order(flowRollupGroupKey).
				Limit(pageSize).Offset(offset).
				Scan(&rows).Error; err != nil {
				return fmt.Errorf("flow rollup: scan raw flows: %w", err)
			}
			if len(rows) == 0 {
				break
			}
			if err := batchInsertRollups(tx, rows, intervalType, "2006-01-02 15:04"); err != nil {
				return fmt.Errorf("flow rollup: insert %s rollups: %w", intervalType, err)
			}
			totalGroups += len(rows)
			if len(rows) < pageSize {
				break
			}
			offset += pageSize
		}

		if totalGroups == 0 {
			return nil
		}

		// Delete exactly the rows that were aggregated (same watermark scope),
		// inside the same transaction as the inserts.
		if err := tx.Where("timestamp < ? AND id <= ?", cutoff, watermark).
			Delete(&models.FlowSample{}).Error; err != nil {
			return fmt.Errorf("flow rollup: delete consumed raw flows: %w", err)
		}
		return nil
	})
	if err != nil {
		// Full rollback: no rollups inserted, no raw rows deleted — the next
		// cycle retries the identical work with no double-counting.
		log.Printf("Flow rollup: %v (rolled back, will retry next cycle)", err)
		return false
	}

	if totalGroups == 0 {
		return false
	}
	log.Printf("Flow rollup: aggregated %d groups from raw flows into %s rollups", totalGroups, intervalType)
	return true
}

// aggregateRollupsUp promotes rollups from srcInterval older than cutoff into dstInterval.
// Uses weighted average for sampling rate. Returns true if work was done.
//
// Same correctness shape as aggregateFlowsToRollup (H1+H2 of the 2026-07-01
// audit): MAX(id) watermark scopes both the reads and the delete to an
// immutable source set (the dstInterval rows we insert into the same table get
// ids above the watermark and a different interval_type, so they can never
// enter the source set), the paginated GROUP BY is ordered deterministically,
// and inserts + delete commit in one transaction. The pagination itself keeps
// per-page memory bounded (M1 of the 2026-06-23 audit).
func (d *Database) aggregateRollupsUp(srcInterval, dstInterval string, cutoff time.Time) bool {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if dstInterval == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")
	pageSize := flowRollupPageSize
	totalGroups := 0

	err := d.db.Transaction(func(tx *gorm.DB) error {
		var probe []int64
		if err := tx.Model(&models.FlowRollup{}).
			Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Select("1").Limit(1).
			Scan(&probe).Error; err != nil {
			return fmt.Errorf("flow rollup: %s work probe: %w", srcInterval, err)
		}
		if len(probe) == 0 {
			return nil
		}

		// The watermark is deliberately UNFILTERED, and this is the site that
		// proved why. PostgreSQL rewrites MAX(id) into a backward walk of the
		// primary key that stops at the first row passing the filter, priced by
		// expected-rows-until-first-match. Under `interval_type = ? AND
		// timestamp < ?` the newest ids all fail the timestamp test, so the walk
		// crossed most of the table while the planner still estimated 4.48
		// against a real worst case of 29,536,475 — measured on production, it
		// blew the 30s statement_timeout and every cycle rolled back and retried:
		//
		//   flows.go:950: Flow rollup: 5m watermark: ERROR: canceling statement
		//   due to statement timeout (SQLSTATE 57014) (rolled back, will retry)
		//
		// Unfiltered, the same rewrite stops on the first tuple: 1.3ms. Only the
		// upper bound matters — rows inserted below carry dstInterval and ids
		// above this bound, and the delete keeps `interval_type = srcInterval`,
		// so it can never reach them.
		var watermark int64
		if err := tx.Model(&models.FlowRollup{}).
			Select("COALESCE(MAX(id), 0)").
			Scan(&watermark).Error; err != nil {
			return fmt.Errorf("flow rollup: %s watermark: %w", srcInterval, err)
		}
		if watermark == 0 {
			return nil
		}

		offset := 0
		for {
			var rows []rollupRow
			if err := tx.Model(&models.FlowRollup{}).
				Where("interval_type = ? AND timestamp < ? AND id <= ?", srcInterval, cutoff, watermark).
				Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event, " +
					"SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count, " +
					"CASE WHEN SUM(flow_count) > 0 THEN SUM(sampling_rate_avg * flow_count) / SUM(flow_count) ELSE 0 END as sampling_rate_avg").
				Group(flowRollupGroupKey).
				Order(flowRollupGroupKey).
				Limit(pageSize).Offset(offset).
				Scan(&rows).Error; err != nil {
				return fmt.Errorf("flow rollup: scan %s rollups: %w", srcInterval, err)
			}
			if len(rows) == 0 {
				break
			}
			if err := batchInsertRollups(tx, rows, dstInterval, bucketFmt); err != nil {
				return fmt.Errorf("flow rollup: promote %s→%s: insert: %w", srcInterval, dstInterval, err)
			}
			totalGroups += len(rows)
			if len(rows) < pageSize {
				break
			}
			offset += pageSize
		}

		if totalGroups == 0 {
			return nil
		}

		if err := tx.Where("interval_type = ? AND timestamp < ? AND id <= ?", srcInterval, cutoff, watermark).
			Delete(&models.FlowRollup{}).Error; err != nil {
			return fmt.Errorf("flow rollup: delete consumed %s rollups: %w", srcInterval, err)
		}
		return nil
	})
	if err != nil {
		log.Printf("Flow rollup: %v (rolled back, will retry next cycle)", err)
		return false
	}

	if totalGroups == 0 {
		return false
	}
	log.Printf("Flow rollup: promoted %d groups from %s to %s rollups", totalGroups, srcInterval, dstInterval)
	return true
}

// FlowConversation represents a top conversation from flow data.
type FlowConversation struct {
	SrcAddr  string `json:"src_addr"`
	DstAddr  string `json:"dst_addr"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
}

// GetInterfaceFlowConversations returns the top sFlow conversations seen on a
// device's interface (matched on input OR output ifIndex) within [from, to],
// ranked by bytes. It gives the report per-spike "what was the traffic" context
// so an operator can triage without logging into the firewall. Scope-local
// noise (link-local / multicast / broadcast / loopback) is excluded; portless
// routed protocols (ESP/GRE/ICMP) are kept. Returns an empty slice when there
// is no flow data (e.g. sFlow not enabled for the device) — never an error.
func (d *Database) GetInterfaceFlowConversations(deviceID uint, ifIndex int, from, to time.Time, limit int) ([]FlowConversation, error) {
	if limit <= 0 {
		limit = 5
	}
	var rows []struct {
		SrcAddr  string
		DstAddr  string
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	if err := d.db.Model(&models.FlowSample{}).
		Where("device_id = ? AND (input_if_index = ? OR output_if_index = ?) AND timestamp BETWEEN ? AND ? AND scope_local = ?",
			deviceID, ifIndex, ifIndex, from, to, false).
		Select("src_addr, dst_addr, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, dst_port, protocol").
		Order("bytes DESC").
		Limit(limit).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]FlowConversation, 0, len(rows))
	for _, r := range rows {
		out = append(out, FlowConversation{
			SrcAddr:  r.SrcAddr,
			DstAddr:  r.DstAddr,
			DstPort:  r.DstPort,
			Protocol: protoName(r.Protocol),
			Bytes:    r.Bytes,
			Packets:  r.Packets,
		})
	}
	return out, nil
}
