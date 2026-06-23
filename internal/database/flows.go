package database

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

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
	TopSources       []KeyCount         `json:"top_sources"`
	TopDestinations  []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
	TopPorts         []KeyCount         `json:"top_ports"`
	LocalTraffic     struct {
		Bytes   uint64 `json:"bytes"`
		Packets uint64 `json:"packets"`
		Flows   int64  `json:"flows"`
	} `json:"local_traffic"`
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
	DeviceID uint    // device_id (flow_samples + flow_rollups)
	ProbeID  uint    // probe_id  (flow_samples only — forces raw-only when set)
	Protocol *uint8  // IP protocol number; nil = all
	DstPort  *uint16 // destination port; nil = all
	SrcAddr  string  // source IP or CIDR (cidrToLikePattern semantics)
	DstAddr  string  // destination IP or CIDR
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
		if filter.Protocol != nil {
			q = q.Where("protocol = ?", *filter.Protocol)
		}
		if filter.DstPort != nil {
			q = q.Where("dst_port = ?", *filter.DstPort)
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

	// --- Rollup base (best available interval for the time range) ---
	rollupInterval := "5m"
	if hours > 48 {
		rollupInterval = "1h"
	}
	if hours > 720 { // 30 days
		rollupInterval = "1d"
	}
	newRollupBase := func() *gorm.DB {
		return applyCommonFilters(d.db.Model(&models.FlowRollup{}).Where("timestamp > ? AND interval_type = ?", cutoff, rollupInterval))
	}

	// Combined aggregates: count, bytes, unique src/dst from raw samples
	var rawAgg struct {
		TotalFlows    int64
		TotalBytes    uint64
		UniqueSources int64
		UniqueDests   int64
	}
	// Multiply bytes/packets by sampling_rate to estimate actual traffic volume
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
	if result.AvgSamplingRate > 1 {
		result.EstimatedBytes = uint64(float64(result.TotalBytes) * result.AvgSamplingRate)
	} else {
		result.EstimatedBytes = result.TotalBytes
	}

	// Computed throughput
	if hours > 0 {
		result.BitsPerSecond = float64(result.TotalBytes) * 8 / (float64(hours) * 3600)
	}

	// Local traffic stats (port-0 internal traffic, e.g. IPv6 link-local)
	var localRaw struct {
		Bytes   uint64
		Packets uint64
		Flows   int64
	}
	newRawBase().Where("src_port = 0 AND dst_port = 0").
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
		newRollupBase().Where("dst_port = 0").
			Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
			Scan(&localRollup)
		result.LocalTraffic.Bytes += localRollup.Bytes
		result.LocalTraffic.Packets += localRollup.Packets
		result.LocalTraffic.Flows += localRollup.Flows
	}

	// Filtered bases that exclude port-0 local traffic for top-N charts
	newFilteredRawBase := func() *gorm.DB {
		return newRawBase().Where("NOT (src_port = 0 AND dst_port = 0)")
	}
	newFilteredRollupBase := func() *gorm.DB {
		return newRollupBase().Where("dst_port != 0")
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

// aggregateFlowsToRollup groups raw FlowSamples older than cutoff into 5-minute rollups.
// Returns true if work was done.
func (d *Database) aggregateFlowsToRollup(cutoff time.Time, intervalType string) bool {
	bucketExpr := d.dialect.TimeBucket("5min", "timestamp")

	// Paginate: process in chunks to limit memory usage
	const pageSize = 50000
	offset := 0
	totalGroups := 0

	for {
		var rows []rollupRow
		if err := d.db.Model(&models.FlowSample{}).
			Where("timestamp < ?", cutoff).
			Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, " +
				"SUM(bytes) as bytes_sum, SUM(packets) as packets_sum, COUNT(*) as flow_count, " +
				"AVG(sampling_rate) as sampling_rate_avg").
			Group("bucket, device_id, src_addr, dst_addr, dst_port, protocol").
			Limit(pageSize).Offset(offset).
			Scan(&rows).Error; err != nil {
			log.Printf("Flow rollup: error scanning raw flows: %v", err)
			return totalGroups > 0
		}

		if len(rows) == 0 {
			break
		}

		// Wrap insert+delete in a transaction for atomicity
		if err := d.db.Transaction(func(tx *gorm.DB) error {
			if err := batchInsertRollups(tx, rows, intervalType, "2006-01-02 15:04"); err != nil {
				return fmt.Errorf("flow rollup: insert %s rollups: %w", intervalType, err)
			}
			return nil
		}); err != nil {
			log.Printf("Flow rollup: transaction error: %v", err)
			return totalGroups > 0
		}

		totalGroups += len(rows)
		if len(rows) < pageSize {
			break
		}
		offset += pageSize
	}

	if totalGroups == 0 {
		return false
	}

	// Delete consumed raw rows (outside the insert tx since we've confirmed inserts succeeded)
	if err := d.db.Where("timestamp < ?", cutoff).Delete(&models.FlowSample{}).Error; err != nil {
		log.Printf("Flow rollup: error deleting consumed raw flows: %v", err)
	}
	log.Printf("Flow rollup: aggregated %d groups from raw flows into %s rollups", totalGroups, intervalType)
	return true
}

// aggregateRollupsUp promotes rollups from srcInterval older than cutoff into dstInterval.
// Uses weighted average for sampling rate. Returns true if work was done.
func (d *Database) aggregateRollupsUp(srcInterval, dstInterval string, cutoff time.Time) bool {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if dstInterval == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	var rows []rollupRow
	if err := d.db.Model(&models.FlowRollup{}).
		Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
		Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, " +
			"SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count, " +
			"CASE WHEN SUM(flow_count) > 0 THEN SUM(sampling_rate_avg * flow_count) / SUM(flow_count) ELSE 0 END as sampling_rate_avg").
		Group("bucket, device_id, src_addr, dst_addr, dst_port, protocol").
		Scan(&rows).Error; err != nil {
		log.Printf("Flow rollup: error scanning %s rollups: %v", srcInterval, err)
		return false
	}

	if len(rows) == 0 {
		return false
	}

	// Wrap insert+delete in a transaction for atomicity
	if err := d.db.Transaction(func(tx *gorm.DB) error {
		if err := batchInsertRollups(tx, rows, dstInterval, bucketFmt); err != nil {
			return fmt.Errorf("aggregate rollups %s→%s: insert: %w", srcInterval, dstInterval, err)
		}
		// Delete consumed source rollups within the same transaction
		if err := tx.Where("interval_type = ? AND timestamp < ?", srcInterval, cutoff).
			Delete(&models.FlowRollup{}).Error; err != nil {
			return fmt.Errorf("delete consumed %s rollups: %w", srcInterval, err)
		}
		return nil
	}); err != nil {
		log.Printf("Flow rollup: transaction error promoting %s to %s: %v", srcInterval, dstInterval, err)
		return false
	}

	log.Printf("Flow rollup: promoted %d groups from %s to %s rollups", len(rows), srcInterval, dstInterval)
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
// so an operator can triage without logging into the firewall. Port-0/0
// (portless/local) flows are excluded. Returns an empty slice when there is no
// flow data (e.g. sFlow not enabled for the device) — never an error for that.
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
		Where("device_id = ? AND (input_if_index = ? OR output_if_index = ?) AND timestamp BETWEEN ? AND ? AND NOT (src_port = 0 AND dst_port = 0)",
			deviceID, ifIndex, ifIndex, from, to).
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
