package database

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	// Degraded reports that at least one rolled-up aggregate did not complete
	// within its budget, so the figures below cover LESS than the requested
	// window — in the worst case only the ~1h still held in flow_samples. The
	// page MUST say so: before this existed, a 30d request that lost its rollup
	// queries returned one hour of data labelled "30 days" and looked fine.
	// DegradedBlocks names the panels that fell back. The order is goroutine
	// scheduling order, not a ranking — nothing should depend on it.
	Degraded       bool     `json:"degraded,omitempty"`
	DegradedBlocks []string `json:"degraded_blocks,omitempty"`
	// UniqueApproximate marks UniqueSources/UniqueDests as an upper bound rather
	// than a count. Raw and rollup tiers are counted separately and summed, and
	// an address present in both tiers is counted twice; the true union needs a
	// re-count the tier layout cannot provide. There was no marker at all before
	// (the old code took max() of the two tiers and said nothing), so a caller
	// could not tell an exact figure from an estimate.
	UniqueApproximate bool `json:"unique_approximate,omitempty"`
	// SamplingRateMin/Max are the range of per-flow sampling rates observed in
	// the window, replacing a single average. A bytes-weighted mean across a
	// regime change is a number that never existed: prod's rates are 1:1 for the
	// last 59 days and up to 1:1024 before that, averaging to a fictitious 1:125.
	SamplingRateMin float64 `json:"sampling_rate_min,omitempty"`
	SamplingRateMax float64 `json:"sampling_rate_max,omitempty"`
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
// topAddrsByBytesRollupQ takes an ALREADY-PREPARED query rather than a base
// factory, so the caller can bind it to a request budget first and surface the
// error instead of dropping it (the old form returned only a slice, so a
// cancelled query was indistinguishable from an empty tier).
func topAddrsByBytesRollupQ(q *gorm.DB, addrCol string, limit int) ([]KeyCount, error) {
	type row struct {
		Addr  string
		Total int64
	}
	var rows []row
	err := q.Select(addrCol + " as addr, SUM(bytes_sum) as total").Group(addrCol).
		Order("total DESC").Limit(limit).Scan(&rows).Error
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: r.Addr, Count: r.Total})
	}
	return out, err
}

// bucketLabelAt renders an arbitrary instant in the same label format
// d.dialect.TimeBucket produces for unit, so a caller can recognise the bucket
// any given moment falls inside — the still-filling one at the new end of a
// series, or the partially-covered one at the old end.
//
// UTC because that is what the buckets are: the Postgres DSN pins TimeZone=UTC
// and SQLite's strftime is UTC, so both render bucket labels in UTC.
func bucketLabelAt(at time.Time, unit string) string {
	now := at.UTC()
	switch unit {
	case "minute":
		return now.Format("2006-01-02 15:04")
	case "5min":
		return now.Truncate(5 * time.Minute).Format("2006-01-02 15:04")
	case "hour":
		return now.Format("2006-01-02 15:00")
	case "6hour":
		return now.Truncate(6 * time.Hour).Format("2006-01-02 15:00")
	case "day":
		return now.Format("2006-01-02")
	default:
		return ""
	}
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
func flowAddrFilter(q *gorm.DB, d Dialect, column, val string) *gorm.DB {
	val = strings.TrimSpace(val)
	if val == "" {
		return q
	}
	// "everything" means no filter. It used to fall through to an exact string
	// compare against the literal "0.0.0.0/0" and match nothing at all.
	if val == "0.0.0.0/0" || val == "::/0" {
		return q
	}

	// Exact containment where the dialect can express it (PostgreSQL's inet
	// operators). cidrToLikePattern rounds every mask UP to the enclosing octet
	// boundary, so on its own a /25 silently returned the whole /24, a /17 the
	// whole /16, and anything shorter than /8 returned "" and then matched
	// nothing. The LIKE prefix is kept alongside as an index-friendly superset
	// pre-filter when one exists.
	if _, _, err := net.ParseCIDR(val); err == nil {
		if expr, ok := d.AddrInCIDR(column); ok {
			pattern := cidrToLikePattern(val)
			if strings.Contains(pattern, "%") {
				q = q.Where(column+" LIKE ? ESCAPE '\\'", pattern)
			}
			return q.Where(expr, val)
		}
		// No exact form available (SQLite test lane): fall back to the prefix
		// superset rather than matching nothing.
		if pattern := cidrToLikePattern(val); pattern != "" {
			if strings.Contains(pattern, "%") {
				return q.Where(column+" LIKE ? ESCAPE '\\'", pattern)
			}
			return q.Where(column+" = ?", pattern)
		}
		return q
	}

	pattern := cidrToLikePattern(val)
	if pattern == "" {
		// Not a CIDR and not parseable as one — an exact address, or garbage.
		// Comparing literally keeps a malformed filter matching nothing, which
		// is the safe direction for a filter.
		return q.Where(column+" = ?", val)
	}
	if strings.Contains(pattern, "%") {
		return q.Where(column+" LIKE ? ESCAPE '\\'", pattern)
	}
	return q.Where(column+" = ?", pattern)
}

// rollupIntervalsForWindow returns the rollup tiers a window of `hours` can
// contain rows from.
//
// The thresholds are DERIVED from the ladder's own promotion ages rather than
// repeating them as literals. That is the entire point of this function's
// present shape. It used to compare against inline `48` and `720`, which was
// correct only by coincidence: aggregateRollupsUp takes its cutoff as a
// PARAMETER, so moving an age on the ladder side silently broke the reader here
// with nothing to catch it. Demonstrated by mutation — promote 5m->1h at 24h,
// ask for hours=48, and the literal form returns 4,000 of 7,000 seeded bytes;
// promote 1h->1d at 10 days and the 30-day window loses the same way. The test
// that existed pinned {48:[5m]} and {720:[5m,1h]}, enshrining the coupling
// rather than guarding it.
//
// Reading EVERY tier unconditionally was tried and rejected. It is correct —
// the tiers are disjoint because promotion deletes its source rows in the same
// transaction, so `timestamp > cutoff` cannot gap or double-count — but it is
// not free, because PostgreSQL's planner treats `interval_type IN (...)` and
// `timestamp > c` as independent predicates. A wider IN list inflates the row
// estimate and crosses the seq-scan threshold. Measured on production: 24h
// top-conversations 4.54s -> 6.43s with a 115MB external merge, and a 48h SUM
// 1.63s -> 10.85s on a full-table scan.
//
// With the default ages this returns exactly what the old literals did, so no
// query plan moves; what changed is that moving an age now moves the reader too.
//
// Shared by GetFlowStats and GetConnectionFlowStats.
func rollupIntervalsForWindow(hours int) []string {
	window := time.Duration(hours) * time.Hour
	intervals := []string{"5m"}
	if window > flowPromote5mTo1hAge {
		intervals = append(intervals, "1h")
	}
	if window > flowPromote1hTo1dAge {
		intervals = append(intervals, "1d")
	}
	return intervals
}

// The ages at which the ladder promotes each tier, and the only place they are
// written down. rollupIntervalsForWindow derives the read side from them;
// RunFlowRollupCycle drives the write side from them. Vars rather than consts so
// a test can move a promotion age and assert the reader followed.
var (
	flowPromote5mTo1hAge = 48 * time.Hour
	flowPromote1hTo1dAge = 30 * 24 * time.Hour
)

// GetFlowStats runs against TWO independent 30-second walls, and the second one
// is the binding constraint:
//
//   - statement_timeout = 30s, set per-connection in the DSN
//     (`options=-c statement_timeout=...`, see database.go; default
//     config.Database.StatementTimeout). It cancels ONE query.
//   - http.Server WriteTimeout = 30s (cmd/api, config.Server.WriteTimeout).
//     The ENTIRE response must be written within 30s of the request, or the
//     connection is closed before c.JSON ever runs and the browser gets a
//     transport error rather than data.
//
// GetFlowStats issues ~24 queries, so their SUM has to fit the second wall.
// Measured on production, a bare SUM over the rollup tiers costs 12.9s at 7d,
// 15.1s at 30d and 19.5s at 90d, and the top-conversations GROUP BY costs 79.6s
// at 7d — so on a wide window the old code could not possibly deliver a payload.
// It did not fail loudly either: rollup errors were logged and execution
// continued, so the response carried raw-only figures (~1 hour) under the
// requested window's label.
//
// NOTE for anyone re-measuring: the SERVER's statement_timeout is 0, so a psql
// session runs unbounded and its timings say what a query COSTS, not what the
// page survives. Measure through the endpoint.
//
// flowStatsBudget bounds the rolled-up work so the handler always returns
// something honest: every panel shares one wall-clock deadline, and whatever has
// not finished by then is reported as degraded rather than silently dropped.
//
// A caveat worth knowing when a wide window degrades: pgx cancels a query by
// deadlining the socket, so the connection is discarded and the SERVER-side
// backend keeps running until the DSN's own statement_timeout fires. A degraded
// load therefore costs a few pool reconnects and some orphaned I/O, and is not
// as cheap as its wall time suggests. Bounded, not a leak — but it is another
// reason wide windows want the summary tables rather than this path.
type flowStatsBudget struct {
	mu       sync.Mutex
	parent   context.Context
	deadline time.Time
	degraded bool
	blocks   []string
}

// flowStatsRollupBudget is the wall-clock allowance for ALL rolled-up
// aggregates in one request. It is deliberately well under WriteTimeout: the
// raw-side queries, JSON encoding and the network write all have to fit in
// what is left.
const flowStatsRollupBudget = 20 * time.Second

// flowStatsRollupConcurrency caps how many rolled-up panels query at once.
//
// This is what makes the default view work at all. Measured per-query against
// production's 24h band, the fourteen rolled-up panels cost about 25s in total
// — top_conversations alone is 6.4s — so running them one after another cannot
// fit any budget that also respects the 30s WriteTimeout. Run in parallel they
// finish in roughly the cost of the slowest one.
//
// Four, not fourteen: the API process's pool is 15 connections
// (config.Database.MaxOpenConns), and one page load must not be able to consume
// it. Four leaves eleven for everything else while still cutting the wall time
// to about a quarter.
const flowStatsRollupConcurrency = 4

func newFlowStatsBudget(parent context.Context) *flowStatsBudget {
	if parent == nil {
		parent = context.Background()
	}
	return &flowStatsBudget{
		parent:   parent,
		deadline: time.Now().Add(flowStatsRollupBudget),
	}
}

// bound returns q bound to the request deadline. ok is false when the allowance
// has already run out, in which case the caller must skip the query entirely.
// The returned cancel func must always be called.
//
// There is no separate per-query cap: the panels run concurrently, so they share
// one wall clock rather than consuming a sequence of independent timeouts.
func (b *flowStatsBudget) bound(q *gorm.DB) (bounded *gorm.DB, cancel context.CancelFunc, ok bool) {
	b.mu.Lock()
	deadline := b.deadline
	b.mu.Unlock()
	if !time.Now().Before(deadline) {
		return nil, func() {}, false
	}
	ctx, cancelFn := context.WithDeadline(b.parent, deadline)
	return q.WithContext(ctx), cancelFn, true
}

// note records the outcome of a rolled-up query. A non-nil error marks the
// result degraded and names the panel so the UI can say which figures cover
// less than the requested window.
func (b *flowStatsBudget) note(block string, err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.degraded {
		b.degraded = true
	}
	log.Printf("Flow stats: %s fell back to raw-only (%v)", block, err)
	b.blocks = append(b.blocks, block)
}

// skip records a panel that was never attempted because the budget was already
// spent, so DegradedBlocks names every affected panel and not just the first.
func (b *flowStatsBudget) skip(block string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocks = append(b.blocks, block)
}

// stamp copies the budget outcome onto the result. Called once, after every
// rolled-up query has either run or been skipped.
func (b *flowStatsBudget) stamp(result *FlowStatsResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Degraded means a panel actually lost data — a query failed, or one was
	// skipped because the allowance had run out. Do NOT key this off the
	// deadline alone: a request whose panels all completed at 17.9s against an
	// 18s allowance is fully correct, and marking it degraded would cry wolf on
	// every slow-but-successful load.
	if !b.degraded && len(b.blocks) == 0 {
		return
	}
	result.Degraded = true
	result.DegradedBlocks = append(result.DegradedBlocks, b.blocks...)
}

// GetFlowStats returns aggregated flow statistics, optionally narrowed by filter.
// It queries both raw flow_samples (recent) and flow_rollups (older data).
func (d *Database) GetFlowStats(hours int, filter FlowStatsFilter) (*FlowStatsResult, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	result := &FlowStatsResult{}
	budget := newFlowStatsBudget(d.db.Statement.Context)

	// Determine which data source to use:
	// - hours <= 1: raw samples only (rollups haven't consumed them yet)
	// - hours > 1: union raw samples + rollups
	//
	// A probe_id filter used to force raw-only here, because flow_rollups has no
	// probe_id column. That was silently catastrophic: raw holds only what the
	// rollup ladder has not yet consumed (~1 hour on production), so choosing a
	// probe collapsed EVERY tile to that hour while the range pill still said 7
	// days — measured at 1.7% of the true flow count, with no warning. Production
	// has exactly one probe, so the dropdown has a single obvious entry and
	// picking it is the natural thing to do.
	//
	// The rollup side can honor the filter after all, via the device that owns
	// the flows — same shape as the site filter below. See applyCommonFilters.
	useRollups := hours > 1

	// applyCommonFilters writes the filters shared by flow_samples and
	// flow_rollups (both carry device_id / src_addr / dst_addr / dst_port /
	// protocol). probe_id is applied separately per base: the raw table records
	// it per row, the rollup table resolves it through the owning device.
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
		q = flowAddrFilter(q, d.dialect, "src_addr", filter.SrcAddr)
		q = flowAddrFilter(q, d.dialect, "dst_addr", filter.DstAddr)
		return q
	}

	// --- Raw flow_samples base ---
	// session returns a fresh gorm session for each base builder.
	//
	// This is belt-and-braces, NOT the fix for the "no such table" failures seen
	// when the panels first ran concurrently — an earlier comment here claimed it
	// was, and that was wrong. Those came from the test harness: SQLite
	// ":memory:" gives every pooled connection its own private, empty database,
	// so the first concurrent query opened a second connection onto an unmigrated
	// schema (see NewDatabaseForTesting, which now pins the pool to one
	// connection). gorm itself is safe here: a *gorm.DB from Open or Session
	// clones its Statement before any chain method mutates it, so concurrent
	// chaining off one handle is supported. Session() is kept because it states
	// that intent locally rather than relying on the caller's clone state.
	session := func() *gorm.DB { return d.db.Session(&gorm.Session{}) }

	newRawBase := func() *gorm.DB {
		q := applyCommonFilters(session().Model(&models.FlowSample{}).Where("timestamp > ?", cutoff))
		if filter.ProbeID > 0 {
			q = q.Where("probe_id = ?", filter.ProbeID)
		}
		return q
	}

	// --- Rollup base ---
	// EVERY tier, always. The rollup lifecycle keeps each age band in exactly ONE
	// tier (promotion deletes the source rows in the same transaction), so
	// summing across all of them can neither gap nor double-count, and the
	// timestamp predicate decides what is actually in range.
	//
	// Two earlier forms of this were wrong in opposite directions. Querying a
	// single "best" interval dropped the younger bands entirely — a 7d view lost
	// ~28% of its window, the most recent part. Selecting tiers by comparing the
	// window against the ladder's promotion ages was correct, but only derivably
	// so, and it coupled this file to literals in RunFlowRollupCycle that nothing
	// kept in step. See rollupIntervalsForWindow.
	rollupIntervals := rollupIntervalsForWindow(hours)
	newRollupBase := func() *gorm.DB {
		q := applyCommonFilters(session().Model(&models.FlowRollup{}).Where("timestamp > ? AND interval_type IN ?", cutoff, rollupIntervals))
		if filter.ProbeID > 0 {
			// flow_rollups carries no probe_id, so map the probe to the devices it
			// owns — the same uncorrelated-subquery shape the site filter uses
			// above, portable on SQLite and Postgres alike.
			//
			// Deliberately an inline subquery rather than GetDeviceIDsByProbe:
			// that helper applies the ActiveDevices scope, which would drop a
			// retired device's history from probe-filtered views while the site
			// filter (unscoped) keeps it — the two filters would disagree about
			// the same rows.
			//
			// One documented semantic, same as the site filter's: this means
			// "devices CURRENTLY owned by this probe". Rolled-up rows carry no
			// probe attribution of their own, so re-homing a device rewrites its
			// history. The raw side, which stores probe_id per row, does not.
			q = q.Where("device_id IN (SELECT id FROM devices WHERE probe_id = ?)", filter.ProbeID)
		}
		return q
	}

	// --- Summary bases -------------------------------------------------------
	//
	// useSummary decides, once, whether this request reads the pre-aggregate
	// instead of flow_rollups. Three conditions, all necessary:
	//
	//   - the window is wide enough to be worth it (below that the live path is
	//     exact and quick, and exactness beats speed at the default range);
	//   - the filter touches no high-cardinality dimension, which the summary
	//     stores as per-bucket top-N rather than as a filterable column;
	//   - the summary demonstrably COVERS the window. While a backfill is still
	//     running its oldest bucket is later than the window start, and reading
	//     it anyway would silently report a fraction of the range — precisely the
	//     failure this whole change exists to remove.
	useSummary := hours > flowSummaryMinHours && flowSummaryCompatible(filter) &&
		d.summaryBackfillComplete()
	// The top-talker panels cannot honour a filter on a cube dimension: their
	// lists are computed per bucket across all protocols and categories. Showing
	// unfiltered talkers beside filtered totals would be a new way to mislead, so
	// they report degraded instead.
	summaryTopsUsable := useSummary && !flowSummaryDimensionFiltered(filter)

	// The cube carries the same column NAMES as flow_rollups for every dimension
	// it holds, so the aggregate panels below run the same SQL against either —
	// only the table changes.
	newSummaryBase := func() *gorm.DB {
		q := applyCommonFilters(session().Model(&models.FlowSummary{}).
			Where("interval_type IN ? AND timestamp > ?", flowSummaryReadIntervals, cutoff))
		if filter.ProbeID > 0 {
			// applyCommonFilters does NOT carry the probe filter — the raw base
			// applies it by column and the rollup base by device subquery, so a
			// cube base that used applyCommonFilters alone silently served EVERY
			// device's traffic under a probe filter. Measured in a harness:
			// 36,000 bytes against 6,000. The same class of defect as the
			// probe-filter bug v0.11.247 fixed, reintroduced one table over.
			q = q.Where("device_id IN (SELECT id FROM devices WHERE probe_id = ?)", filter.ProbeID)
		}
		return q
	}
	newFilteredSummaryBase := func() *gorm.DB {
		return newSummaryBase().Where("scope_local = ?", false)
	}
	newSummaryTopBase := func() *gorm.DB {
		q := session().Model(&models.FlowSummaryTop{}).
			Where("interval_type IN ? AND timestamp > ?", flowSummaryReadIntervals, cutoff)
		return applySummaryDeviceFilters(q, filter)
	}
	newSummaryBucketBase := func() *gorm.DB {
		q := session().Model(&models.FlowSummaryBucket{}).
			Where("interval_type IN ? AND timestamp > ?", flowSummaryReadIntervals, cutoff)
		return applySummaryDeviceFilters(q, filter)
	}
	// aggBase is whichever table the dimension panels read. The cube carries the
	// same column names as flow_rollups for every dimension it holds, so those
	// panels run identical SQL either way — only the table changes.
	aggBase := newRollupBase
	if useSummary {
		aggBase = newSummaryBase
	}

	// runRollup SCHEDULES one rolled-up panel; it does not run it. `query` fills
	// the panel's own local variables, and `merge` folds them into the response.
	// Queries run concurrently in flushRollups; merges run afterwards, one at a
	// time, in registration order — so a merge may touch shared state freely
	// while the expensive part still overlaps.
	//
	// Scheduling rather than executing is what allows the parallelism: measured
	// on production, the fourteen rolled-up panels cost ~25s sequentially at the
	// default 24h range, which no budget under the 30s WriteTimeout can absorb.
	//
	// A panel's merge runs ONLY if its query succeeded. Several of these queries
	// used to discard their error entirely, which is why a degraded window was
	// indistinguishable from an empty one; and gorm's Scan streams rows before
	// reporting a late cancellation, so a cancelled query can leave a partial
	// slice behind. Merging that would silently under-report as though complete.
	type rollupJob struct {
		block string
		base  func() *gorm.DB
		query func(*gorm.DB) error
		merge func()
	}
	var rollupJobs []*rollupJob
	runRollup := func(block string, base func() *gorm.DB, query func(*gorm.DB) error, merge func()) {
		rollupJobs = append(rollupJobs, &rollupJob{block: block, base: base, query: query, merge: merge})
	}

	// flushRollups runs every scheduled panel, then merges the ones that
	// succeeded. Concurrency is bounded so a single page load cannot drain the
	// connection pool.
	flushRollups := func() {
		if len(rollupJobs) == 0 {
			return
		}
		okFlags := make([]bool, len(rollupJobs))
		sem := make(chan struct{}, flowStatsRollupConcurrency)
		var wg sync.WaitGroup
		for i, job := range rollupJobs {
			wg.Add(1)
			go func(i int, job *rollupJob) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				q, cancel, ok := budget.bound(job.base())
				if !ok {
					budget.skip(job.block)
					return
				}
				defer cancel()
				err := job.query(q)
				budget.note(job.block, err)
				okFlags[i] = err == nil
			}(i, job)
		}
		wg.Wait()
		for i, job := range rollupJobs {
			if okFlags[i] && job.merge != nil {
				job.merge()
			}
		}
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
	if err := newRawBase().Select("COUNT(*) as total_flows, COALESCE(SUM(bytes),0) as total_bytes").
		Scan(&rawAgg).Error; err != nil {
		return nil, fmt.Errorf("flow stats raw aggregates: %w", err)
	}
	result.TotalFlows = rawAgg.TotalFlows
	result.TotalBytes = rawAgg.TotalBytes

	// Unique address counts are split out of the aggregate above and asked as
	// COUNT(*) FROM (SELECT DISTINCT x) rather than COUNT(DISTINCT x). Measured
	// on production's 24h band at the live work_mem of 16MB: 3.7s against 6.5s,
	// with no settings change and no loss of exactness, because the planner can
	// hash the distinct set instead of sorting it inside the aggregate. The cost
	// is that one statement becomes three, so each needs its own error handling.
	countDistinct := func(base func() *gorm.DB, col string) (int64, error) {
		var n int64
		err := session().Table("(?) as distinct_vals", base().Select("DISTINCT "+col)).
			Select("COUNT(*)").Scan(&n).Error
		return n, err
	}
	if n, err := countDistinct(newRawBase, "src_addr"); err != nil {
		return nil, fmt.Errorf("flow stats raw unique sources: %w", err)
	} else {
		result.UniqueSources = n
	}
	if n, err := countDistinct(newRawBase, "dst_addr"); err != nil {
		return nil, fmt.Errorf("flow stats raw unique dests: %w", err)
	} else {
		result.UniqueDests = n
	}

	// Raw packets and the raw sampling range. These MUST be computed before the
	// rollup block below, which accumulates onto them — reversing the order
	// silently discards the rolled-up figures, which is the bug that made a 90d
	// view report 0.05% of its real packet count.
	var totalPkts struct{ Sum uint64 }
	if err := newRawBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPkts).Error; err != nil {
		return nil, fmt.Errorf("flow stats raw packets: %w", err)
	}
	result.TotalPackets = totalPkts.Sum

	var rawRate struct {
		Min float64
		Max float64
	}
	newRawBase().Select("COALESCE(MIN(NULLIF(sampling_rate,0)),0) as min, COALESCE(MAX(sampling_rate),0) as max").Scan(&rawRate)
	result.SamplingRateMin = rawRate.Min
	result.SamplingRateMax = rawRate.Max

	// Add rollup aggregates if needed
	if useRollups {
		var rollupAgg struct {
			TotalFlows  int64
			TotalBytes  uint64
			TotalPkts   uint64
			SamplingMin float64
			SamplingMax float64
		}
		// Packets and the sampling range ride along with the totals rather than
		// running as separate scans: all four come from the same band, and on a
		// wide window each extra scan is 13-20s of a budget that has to cover
		// every panel. TotalPackets and the sampling figures were RAW-ONLY before
		// this, which is why a 90d view reported 0.05% of its real packet count
		// and the sampling chip always read 1:1.
		// The cube carries no sampling column — the page reports a RANGE and that
		// lives in flow_summary_buckets — so the summary form drops those two
		// aggregates and a separate panel supplies them below.
		totalsSelect := "COALESCE(SUM(flow_count),0) as total_flows, COALESCE(SUM(bytes_sum),0) as total_bytes, " +
			"COALESCE(SUM(packets_sum),0) as total_pkts, " +
			"COALESCE(MIN(NULLIF(sampling_rate_avg,0)),0) as sampling_min, " +
			"COALESCE(MAX(sampling_rate_avg),0) as sampling_max"
		if useSummary {
			totalsSelect = "COALESCE(SUM(flow_count),0) as total_flows, COALESCE(SUM(bytes_sum),0) as total_bytes, " +
				"COALESCE(SUM(packets_sum),0) as total_pkts"
		}
		runRollup("totals", aggBase, func(q *gorm.DB) error {
			return q.Select(totalsSelect).Scan(&rollupAgg).Error
		}, func() {
			result.TotalFlows += rollupAgg.TotalFlows
			result.TotalBytes += rollupAgg.TotalBytes
			result.TotalPackets += rollupAgg.TotalPkts
			if rollupAgg.SamplingMin > 0 && (result.SamplingRateMin == 0 || rollupAgg.SamplingMin < result.SamplingRateMin) {
				result.SamplingRateMin = rollupAgg.SamplingMin
			}
			if rollupAgg.SamplingMax > result.SamplingRateMax {
				result.SamplingRateMax = rollupAgg.SamplingMax
			}
		})

		// Unique counts across tiers are a SUM, not a max(). The old code took
		// max(raw, rollup) and called it approximate; max is not an approximation
		// of a union, it is a lower bound that ignores one tier entirely. Summing
		// is the upper bound (an address in both tiers is counted twice), and
		// UniqueApproximate now says so instead of leaving the caller to guess.
		for _, u := range []struct {
			col    string
			sumCol string
			dst    *int64
		}{{"src_addr", "distinct_src", &result.UniqueSources}, {"dst_addr", "distinct_dst", &result.UniqueDests}} {
			u := u
			var n int64
			if useSummary {
				// NOT published from the summary. Summing per-bucket distinct
				// counts is not the same approximation the live path makes when
				// it sums two tiers — a 90-day window has roughly 850
				// (bucket x device x scope) rows, so an address present
				// throughout is counted hundreds of times. Measured in a
				// harness: 12 against a true 2. That is not an over-estimate of
				// the union, it is a different quantity, and labelling it
				// "approximate" would not make it honest.
				//
				// The tile therefore shows the raw window's exact count and the
				// panel is named as degraded. Publishing a real window-level
				// unique count from the summary needs a sketch (HyperLogLog),
				// which is worth revisiting now that scanning is no longer the
				// dominant cost.
				_ = u.sumCol
				budget.skip("unique_" + u.col)
				continue
			}
			// The base here is d.db, not a rollup base: the rollup query is the
			// SUBQUERY, wrapped so the planner can hash the distinct set instead
			// of sorting it inside an aggregate.
			runRollup("unique_"+u.col, session,
				func(q *gorm.DB) error {
					return q.Table("(?) as distinct_vals", newRollupBase().Select("DISTINCT "+u.col)).
						Select("COUNT(*)").Scan(&n).Error
				}, func() {
					*u.dst += n
					result.UniqueApproximate = true
				})
		}

		// The cube has no sampling column, so when reading the summary the range
		// comes from the per-bucket table instead of riding along with the totals.
		//
		// Only when no cube dimension is filtered: flow_summary_buckets carries no
		// dimension columns, so under such a filter it would report the range for
		// ALL traffic beside filtered totals — quietly, since nothing else would
		// hint at it.
		if useSummary && !summaryTopsUsable {
			budget.skip("sampling")
		} else if useSummary {
			var sampling struct {
				Min float64
				Max float64
			}
			runRollup("sampling", newSummaryBucketBase, func(q *gorm.DB) error {
				return q.Select("COALESCE(MIN(NULLIF(sampling_rate_min,0)),0) as min, " +
					"COALESCE(MAX(sampling_rate_max),0) as max").Scan(&sampling).Error
			}, func() {
				if sampling.Min > 0 && (result.SamplingRateMin == 0 || sampling.Min < result.SamplingRateMin) {
					result.SamplingRateMin = sampling.Min
				}
				if sampling.Max > result.SamplingRateMax {
					result.SamplingRateMax = sampling.Max
				}
			})
		}
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
		runRollup("local_traffic", aggBase, func(q *gorm.DB) error {
			return q.Where("scope_local = ?", true).
				Select("COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets, COALESCE(SUM(flow_count),0) as flows").
				Scan(&localRollup).Error
		}, func() {
			result.LocalTraffic.Bytes += localRollup.Bytes
			result.LocalTraffic.Packets += localRollup.Packets
			result.LocalTraffic.Flows += localRollup.Flows
		})
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

	filteredAggBase := newFilteredRollupBase
	if useSummary {
		filteredAggBase = newFilteredSummaryBase
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
	// No Limit here, unlike the other top-N panels: protocol is a uint8 with ~7
	// live values on production, so the full group is tiny — and ProtocolCount
	// below must count them all. The display list is truncated to 10 at the end.
	if err := newRawBase().Where("protocol <> 0").Select("protocol, COUNT(*) as count").Group("protocol").
		Order("count DESC").Scan(&protocols).Error; err != nil {
		log.Printf("Flow stats protocol distribution: %v", err)
	}
	// finalizeProtocols publishes the protocol breakdown. It is a closure so it
	// can run either directly (raw-only windows) or as the rolled-up panel's
	// merge step, after the concurrent query has filled rollupProtos.
	var rollupProtos []struct {
		Protocol uint8
		Count    int64
	}
	// finalizeProtocols must be IDEMPOTENT: it is called once up front to publish
	// the raw-only view, and again as the merge step if the rolled-up query
	// succeeds. It therefore builds a fresh list and ASSIGNS — an earlier version
	// appended to result.ByProtocol and truncated the source slice in place, so a
	// second call doubled the list.
	finalizeProtocols := func() {
		merged := make(map[uint8]int64, len(protocols)+len(rollupProtos))
		for _, p := range protocols {
			merged[p.Protocol] += p.Count
		}
		for _, p := range rollupProtos {
			merged[p.Protocol] += p.Count
		}
		type protoCount struct {
			Protocol uint8
			Count    int64
		}
		all := make([]protoCount, 0, len(merged))
		for proto, count := range merged {
			all = append(all, protoCount{proto, count})
		}
		sort.SliceStable(all, func(i, j int) bool { return all[i].Count > all[j].Count })
		// ProtocolCount is taken BEFORE the display truncation. It used to be
		// len(protocols) after a Limit(10), so the tile silently stopped counting
		// at ten however many protocols the window actually carried.
		result.ProtocolCount = int64(len(all))
		if len(all) > 10 {
			all = all[:10]
		}
		out := make([]KeyCount, 0, len(all))
		for _, p := range all {
			out = append(out, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
		}
		result.ByProtocol = out
	}
	// Publish the raw-only breakdown NOW, exactly as every other panel does.
	// Leaving this to the merge alone meant that on a degraded window — which at
	// 7 days and beyond is every window — the protocols tile came back EMPTY
	// rather than falling back to recent samples, while its neighbours kept their
	// raw rows. The banner said "falls back to recent samples only", which for
	// this panel was simply untrue.
	finalizeProtocols()
	if useRollups {
		runRollup("protocols", aggBase, func(q *gorm.DB) error {
			return q.Where("protocol <> 0").Select("protocol, SUM(flow_count) as count").Group("protocol").
				Order("count DESC").Scan(&rollupProtos).Error
		}, finalizeProtocols)
	}

	// Application-category and direction distribution (by flow count), raw
	// samples supplemented with rollups. Both are ingest-time classification
	// columns (internal/classify) carried onto rollups, so the breakdown holds
	// up after raw samples age out. Closure mirrors the protocol-distribution
	// merge above for a single smallint dimension column.
	// dimDist writes into dst rather than returning, so the rolled-up half can be
	// scheduled and merged after its concurrent query completes.
	dimDist := func(col string, nameFn func(uint8) string, dst *[]KeyCount) {
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
		publish := func() {
			out := make([]KeyCount, 0, len(m))
			for v, c := range m {
				out = append(out, KeyCount{Key: nameFn(v), Count: c})
			}
			sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
			*dst = out
		}
		if !useRollups {
			publish()
			return
		}
		var rs []drow
		runRollup("by_"+col, aggBase, func(q *gorm.DB) error {
			return q.Select(col + " as v, SUM(flow_count) as count").Group(col).Scan(&rs).Error
		}, func() {
			for _, r := range rs {
				m[r.V] += r.Count
			}
			publish()
		})
		// Publish the raw-only view now so the field is populated even if the
		// rolled-up half never completes; the merge overwrites it if it does.
		publish()
	}
	dimDist("app_category", classify.CategoryName, &result.ByCategory)
	dimDist("direction", classify.DirectionName, &result.ByDirection)

	// Top destination countries / ASNs by bytes (GeoLite2 enrichment; empty when
	// geo is disabled). Destination-oriented — where traffic is going. The
	// `<> ''` / `<> 0` filters exclude unmapped rows (NULL too: NULL <> '' is not
	// TRUE), which covers all internal/private traffic GeoLite2 doesn't map.
	geoTopCountry := func() {
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
		result.TopCountries = out
		if useRollups {
			var rollup []KeyCount
			runRollup("top_countries", filteredAggBase, func(q *gorm.DB) error {
				var rows []grow
				err := q.Where("dst_country <> ?", "").
					Select("dst_country as k, SUM(bytes_sum) as total").
					Group("dst_country").Order("total DESC").Limit(10).Scan(&rows).Error
				rollup = rollup[:0]
				for _, r := range rows {
					rollup = append(rollup, KeyCount{Key: r.K, Count: r.Total})
				}
				return err
			}, func() {
				result.TopCountries = mergeKeyCounts(out, rollup, 10)
			})
		}
	}
	geoTopASN := func() {
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
		result.TopASNs = out
		if useRollups {
			var rollup []KeyCount
			mergeASNs := func() { result.TopASNs = mergeKeyCounts(out, rollup, 10) }
			switch {
			case summaryTopsUsable:
				runRollup("top_asns", newSummaryTopBase, func(q *gorm.DB) error {
					vals, err := flowSummaryTopValues(q, flowSummaryDimDstASN, 10)
					rollup = rollup[:0]
					for _, v := range vals {
						// Stored bare so one column serves every dimension.
						rollup = append(rollup, KeyCount{Key: "AS" + v.Key, Count: v.Count})
					}
					return err
				}, mergeASNs)
			case useSummary:
				budget.skip("top_asns")
			default:
				runRollup("top_asns", newFilteredRollupBase, func(q *gorm.DB) error {
					var rows []grow
					err := q.Where("dst_asn <> 0").
						Select("dst_asn as k, SUM(bytes_sum) as total").
						Group("dst_asn").Order("total DESC").Limit(10).Scan(&rows).Error
					rollup = rollup[:0]
					for _, r := range rows {
						rollup = append(rollup, KeyCount{Key: fmt.Sprintf("AS%d", r.K), Count: r.Total})
					}
					return err
				}, mergeASNs)
			}
		}
	}
	geoTopCountry()
	geoTopASN()

	// Top sources by bytes (filtered: excludes port-0 local traffic)
	result.TopSources = topAddrsByBytes(newFilteredRawBase, "src_addr", 10)
	if useRollups {
		rawSrc := result.TopSources
		var rollupSrc []KeyCount
		if summaryTopsUsable {
			runRollup("top_sources", newSummaryTopBase, func(q *gorm.DB) error {
				var err error
				rollupSrc, err = flowSummaryTopValues(q, flowSummaryDimSrcAddr, 10)
				return err
			}, func() {
				result.TopSources = mergeKeyCounts(rawSrc, rollupSrc, 10)
			})
		} else if useSummary {
			budget.skip("top_sources")
		} else {
			runRollup("top_sources", newFilteredRollupBase, func(q *gorm.DB) error {
				var err error
				rollupSrc, err = topAddrsByBytesRollupQ(q, "src_addr", 10)
				return err
			}, func() {
				result.TopSources = mergeKeyCounts(rawSrc, rollupSrc, 10)
			})
		}
	}

	// Top destinations by bytes (filtered: excludes port-0 local traffic)
	result.TopDestinations = topAddrsByBytes(newFilteredRawBase, "dst_addr", 10)
	if useRollups {
		rawDst := result.TopDestinations
		var rollupDst []KeyCount
		if summaryTopsUsable {
			runRollup("top_destinations", newSummaryTopBase, func(q *gorm.DB) error {
				var err error
				rollupDst, err = flowSummaryTopValues(q, flowSummaryDimDstAddr, 10)
				return err
			}, func() {
				result.TopDestinations = mergeKeyCounts(rawDst, rollupDst, 10)
			})
		} else if useSummary {
			budget.skip("top_destinations")
		} else {
			runRollup("top_destinations", newFilteredRollupBase, func(q *gorm.DB) error {
				var err error
				rollupDst, err = topAddrsByBytesRollupQ(q, "dst_addr", 10)
				return err
			}, func() {
				result.TopDestinations = mergeKeyCounts(rawDst, rollupDst, 10)
			})
		}
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
	// Merge the rolled-up tiers in. Without this the card showed only what raw
	// still holds — about one hour — beside tiles summing the whole window: on
	// production the displayed #1 was 427 MB at 0.56% while the real #1 (NFS,
	// 6,799 MB over 24h) was absent from the list entirely, and the percentage
	// column divided raw-only bytes by a rollup-inclusive total.
	if useRollups {
		var rollupConvos []struct {
			SrcAddr  string
			DstAddr  string
			DstPort  uint16
			Protocol uint8
			Bytes    uint64
			Packets  uint64
		}
		convoQuery := func(q *gorm.DB) error {
			return q.Select("src_addr, dst_addr, dst_port, protocol, SUM(bytes_sum) as bytes, SUM(packets_sum) as packets").
				Group("src_addr, dst_addr, dst_port, protocol").
				Order("bytes DESC").Limit(10).Scan(&rollupConvos).Error
		}
		convoBase := newFilteredRollupBase
		if summaryTopsUsable {
			convoBase = newSummaryTopBase
			// The summary packs the tuple into one text column so a single table
			// can serve every high-cardinality dimension; unpack it back into the
			// same shape the raw side produces.
			convoQuery = func(q *gorm.DB) error {
				var rows []struct {
					Value   string
					Bytes   uint64
					Packets uint64
				}
				err := q.Where("dimension = ? AND scope_local = ?", flowSummaryDimConversation, false).
					Select("value, COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as packets").
					Group("value").Order("bytes DESC").Order("value ASC").Limit(10).Scan(&rows).Error
				rollupConvos = rollupConvos[:0]
				for _, r := range rows {
					parts := strings.Split(r.Value, "|")
					if len(parts) != 4 {
						continue
					}
					port, _ := strconv.ParseUint(parts[2], 10, 16)
					proto, _ := strconv.ParseUint(parts[3], 10, 8)
					rollupConvos = append(rollupConvos, struct {
						SrcAddr  string
						DstAddr  string
						DstPort  uint16
						Protocol uint8
						Bytes    uint64
						Packets  uint64
					}{parts[0], parts[1], uint16(port), uint8(proto), r.Bytes, r.Packets})
				}
				return err
			}
		} else if useSummary {
			convoBase = nil
		}
		if convoBase == nil {
			budget.skip("top_conversations")
		} else {
			runRollup("top_conversations", convoBase, convoQuery, func() {
				if len(rollupConvos) == 0 {
					return
				}
				type convoKey struct {
					Src, Dst string
					Port     uint16
					Proto    uint8
				}
				merged := make(map[convoKey]*FlowConversation, len(convos)+len(rollupConvos))
				order := make([]convoKey, 0, len(convos)+len(rollupConvos))
				add := func(src, dst string, port uint16, proto uint8, bytes, packets uint64) {
					k := convoKey{src, dst, port, proto}
					if existing, ok := merged[k]; ok {
						existing.Bytes += bytes
						existing.Packets += packets
						return
					}
					merged[k] = &FlowConversation{
						SrcAddr: src, DstAddr: dst, DstPort: port,
						Protocol: protoName(proto), Bytes: bytes, Packets: packets,
					}
					order = append(order, k)
				}
				for _, c := range convos {
					add(c.SrcAddr, c.DstAddr, c.DstPort, c.Protocol, c.Bytes, c.Packets)
				}
				for _, c := range rollupConvos {
					add(c.SrcAddr, c.DstAddr, c.DstPort, c.Protocol, c.Bytes, c.Packets)
				}
				out := make([]FlowConversation, 0, len(order))
				for _, k := range order {
					out = append(out, *merged[k])
				}
				sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
				if len(out) > 10 {
					out = out[:10]
				}
				// REPLACES the raw-only list published below, rather than appending
				// to it — the merge already folded those rows in.
				result.TopConversations = out
			})
		}
	}

	// Top destination ports
	var topPorts []struct {
		Port  uint16
		Total int64
	}
	newFilteredRawBase().Select("dst_port as port, SUM(bytes) as total").
		Where("dst_port > 0").Group("dst_port").Order("total DESC").Limit(10).Scan(&topPorts)
	portName := func(port uint16) string {
		if n, ok := wellKnownPorts[port]; ok {
			return n
		}
		return fmt.Sprintf("%d", port)
	}
	for _, p := range topPorts {
		result.TopPorts = append(result.TopPorts, KeyCount{Key: portName(p.Port), Count: p.Total})
	}
	// Same raw-only defect as Top Conversations: magnitudes ran ~19x low and
	// port 2049 (the busiest on production) was missing entirely.
	if useRollups {
		var rollupPorts []struct {
			Port  uint16
			Total int64
		}
		rawPorts := result.TopPorts
		var summaryPorts []KeyCount
		mergePorts := func() {
			rollupKC := summaryPorts
			if rollupKC == nil {
				rollupKC = make([]KeyCount, 0, len(rollupPorts))
				for _, p := range rollupPorts {
					rollupKC = append(rollupKC, KeyCount{Key: portName(p.Port), Count: p.Total})
				}
			}
			if len(rollupKC) > 0 {
				result.TopPorts = mergeKeyCounts(rawPorts, rollupKC, 10)
			}
		}
		switch {
		case summaryTopsUsable:
			runRollup("top_ports", newSummaryTopBase, func(q *gorm.DB) error {
				vals, err := flowSummaryTopValues(q, flowSummaryDimDstPort, 10)
				summaryPorts = make([]KeyCount, 0, len(vals))
				for _, v := range vals {
					// The value is the port as text; name it the same way the raw
					// side does so the merge keys line up.
					if n, convErr := strconv.ParseUint(v.Key, 10, 16); convErr == nil {
						summaryPorts = append(summaryPorts, KeyCount{Key: portName(uint16(n)), Count: v.Count})
					}
				}
				return err
			}, mergePorts)
		case useSummary:
			budget.skip("top_ports")
		default:
			runRollup("top_ports", newFilteredRollupBase, func(q *gorm.DB) error {
				return q.Select("dst_port as port, SUM(bytes_sum) as total").
					Where("dst_port > 0").Group("dst_port").Order("total DESC").Limit(10).Scan(&rollupPorts).Error
			}, mergePorts)
		}
	}

	// Adaptive time bucketing for bytes over time.
	//
	// The bucket must NEVER be finer than the finest tier feeding the window.
	// A 6h view used minute buckets and applied them to flow_rollups too, whose
	// finest tier is 5m — so each 5-minute row's whole byte count landed in one
	// minute bucket and the next four were empty. The client divides every point
	// by a single bucket_seconds, so those points read 5x the true rate and the
	// line alternated spike-and-zero instead of being linear in time.
	bucketUnit := "hour"
	result.BucketSeconds = 3600
	if hours <= 6 {
		bucketUnit = "5min"
		result.BucketSeconds = 300
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

	// publishSeries drops the still-filling bucket and writes the chart series.
	// The newest bucket covers only the elapsed part of the current 5 minutes /
	// hour / day, so plotting it at full width ended every chart in a false
	// cliff of up to ~90%. The series is ordered ascending, so it is the last
	// element.
	publishSeries := func(series []struct {
		Bucket string
		Total  int64
	}) {
		// Trim the still-filling bucket at the NEW end.
		if n := len(series); n > 0 {
			if cutBucket := bucketLabelAt(time.Now(), bucketUnit); cutBucket != "" && series[n-1].Bucket == cutBucket {
				series = series[:n-1]
			}
		}
		// And the partial bucket at the OLD end, for the same reason at the other
		// end of the chart. The window's cutoff lands inside a bucket, and
		// `timestamp > cutoff` keeps only that bucket's post-cutoff slice — which
		// was then drawn at full bucket width, so the first point read anywhere
		// from 8% to 100% of its true rate depending on the wall-clock minute.
		// v0.11.247 fixed the false cliff at the trailing end and missed this one
		// because it only looked at the newest bucket.
		if len(series) > 0 {
			if cutBucket := bucketLabelAt(cutoff, bucketUnit); cutBucket != "" && series[0].Bucket == cutBucket {
				series = series[1:]
			}
		}
		out := make([]TimeBucket, 0, len(series))
		for _, t := range series {
			out = append(out, TimeBucket{Bucket: t.Bucket, Count: t.Total})
		}
		result.BytesOverTime = out
	}

	// Merge rollup time series
	if useRollups {
		var rollupTS []struct {
			Bucket string
			Total  int64
		}
		runRollup("bytes_over_time", aggBase, func(q *gorm.DB) error {
			return q.Select(d.dialect.TimeBucket(bucketUnit, "timestamp") + " as bucket, SUM(bytes_sum) as total").
				Group("bucket").Order("bucket ASC").Scan(&rollupTS).Error
		}, func() {
			publishSeries(mergeTimeSeries(timeSeries, rollupTS))
		})
	}
	// Publish the raw-only series now so the chart is populated even if the
	// rolled-up half never completes; the merge replaces it if it does.
	publishSeries(timeSeries)

	// Run every scheduled rolled-up panel concurrently, then merge the ones that
	// succeeded. This is the last thing before stamping, so DegradedBlocks names
	// every panel that lost data rather than only the first.
	flushRollups()

	// Derived figures come AFTER the flush, because the rolled-up totals they
	// build on are merged there. Computing them earlier would publish throughput
	// and estimated bytes for the raw window only.
	//
	// AvgSamplingRate is retained for API back-compat and now reports the HIGHEST
	// rate observed rather than an average: a bytes-weighted mean across a
	// sampling-regime change is a rate that never existed (production ran 1:1024
	// until 2026-07-16 and 1:1 since, averaging to a fictitious 1:125). Clients
	// should prefer SamplingRateMin/Max; when the two are equal this is exactly
	// the old meaning.
	result.AvgSamplingRate = result.SamplingRateMax
	// L1: bytes is already sampling-scaled, so estimated == total (the field is
	// retained for API back-compat; the old `* AvgSamplingRate` over-reported by
	// ~the sampling rate).
	result.EstimatedBytes = result.TotalBytes
	if hours > 0 {
		result.BitsPerSecond = float64(result.TotalBytes) * 8 / (float64(hours) * 3600)
	}

	budget.stamp(result)

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

// rollupKey is rollupRow's GROUP BY key — every field except the four measures.
type rollupKey struct {
	Bucket        string
	DeviceID      uint
	SrcAddr       string
	DstAddr       string
	DstPort       uint16
	Protocol      uint8
	AppCategory   uint8
	Direction     uint8
	ScopeLocal    bool
	DstCountry    string
	DstASN        uint32
	FlowSource    uint8
	FirewallEvent uint8
}

func (r rollupRow) key() rollupKey {
	return rollupKey{
		Bucket: r.Bucket, DeviceID: r.DeviceID, SrcAddr: r.SrcAddr, DstAddr: r.DstAddr,
		DstPort: r.DstPort, Protocol: r.Protocol, AppCategory: r.AppCategory,
		Direction: r.Direction, ScopeLocal: r.ScopeLocal, DstCountry: r.DstCountry,
		DstASN: r.DstASN, FlowSource: r.FlowSource, FirewallEvent: r.FirewallEvent,
	}
}

// rollupAccumulator folds the partial aggregates of a sub-ranged promotion
// window into one row per group key, so splitting a window's SELECT across
// several statements still emits each destination bucket exactly once.
//
// The first batch is adopted WHOLE, without building the index — a window that
// is scanned in one statement (every promotion but 1h→1d) then costs exactly
// what it did before, and the map is only paid for when there is something to
// merge.
type rollupAccumulator struct {
	rows []rollupRow
	idx  map[rollupKey]int // nil until a second batch arrives
}

func (a *rollupAccumulator) add(batch []rollupRow) {
	if len(batch) == 0 {
		return
	}
	if a.rows == nil {
		a.rows = batch
		return
	}
	if a.idx == nil {
		// Reserved only to skip the first few doublings; the index still grows.
		// Do not read this as "most keys recur across sub-ranges" — production
		// says the opposite. A day of the 1h tier is 2.4M rows folding to 2.1M
		// day-groups (see the scanStep comment below), so roughly 88% of keys
		// occur in exactly ONE hour and the finished index holds close to one
		// entry per group, not one per hour's worth.
		//
		// So peak memory here is the group slice — which the single-statement
		// form already materialised in full, through the same append doublings —
		// plus an index of about that many entries. The index is the real cost of
		// merging in Go, and it is what buys every statement staying under the
		// 30s cancel.
		a.idx = make(map[rollupKey]int, 2*(len(a.rows)+len(batch)))
		for i, r := range a.rows {
			a.idx[r.key()] = i
		}
	}
	for _, r := range batch {
		k := r.key()
		i, ok := a.idx[k]
		if !ok {
			a.idx[k] = len(a.rows)
			a.rows = append(a.rows, r)
			continue
		}
		dst := &a.rows[i]
		// Re-weight the sampling mean BEFORE FlowCount moves under it.
		if total := dst.FlowCount + r.FlowCount; total > 0 {
			dst.SamplingRateAvg = (dst.SamplingRateAvg*float64(dst.FlowCount) +
				r.SamplingRateAvg*float64(r.FlowCount)) / float64(total)
		}
		dst.BytesSum += r.BytesSum
		dst.PacketsSum += r.PacketsSum
		dst.FlowCount += r.FlowCount
	}
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
			// AUDIT-203: a bucket/layout mismatch must fail the transaction, not
			// silently commit a year-0001 rollup in the same tx that deletes the
			// raw rows — retention would then reap the mis-dated rollup and the
			// aggregated history would vanish with no log. The caller's tx rolls
			// back, so the raw rows are preserved for the next cycle.
			ts, err := time.Parse(bucketFmt, r.Bucket)
			if err != nil {
				return fmt.Errorf("parse bucket %q with layout %q: %w", r.Bucket, bucketFmt, err)
			}
			// The bucket label is zone-less and both engines emit it in UTC, so
			// Parse yields a UTC instant. Carry it into the local zone before
			// storing: the instant is unchanged (PostgreSQL stores timestamptz,
			// so nothing moves there), but SQLite stores the rendered text, and
			// a rollup row rendered "+00:00" beside raw rows rendered in the
			// writer's offset makes SQLite's lexical comparison mis-order the
			// tiers against a reader cutoff that can only be in one zone.
			ts = ts.In(time.Local)
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

	// Step 2: 5m rollups older than flowPromote5mTo1hAge → 1h rollups
	cutoff48h := time.Now().Add(-flowPromote5mTo1hAge)
	if d.aggregateRollupsUp("5m", "1h", cutoff48h) {
		work = true
	}

	// Step 3: 1h rollups older than flowPromote1hTo1dAge → 1d rollups
	cutoff30d := time.Now().Add(-flowPromote1hTo1dAge)
	if d.aggregateRollupsUp("1h", "1d", cutoff30d) {
		work = true
	}

	if !work {
		log.Println("Flow rollup: cycle complete (no data to aggregate)")
	}
}

// flowRollupWindow is the width of one aggregation time window — the slice of
// raw/rollup history one transaction aggregates and deletes (AUDIT-204, same
// shape as syslogAggWindow). A package var (not a const) so tests can shrink
// it to exercise the multi-window path. Defaults to one hour — a multiple of
// the 5m bucket and equal to the 1h bucket, so neither straddles a window;
// day-bucket promotions widen it to 24h (see aggregateRollupsUp).
var flowRollupWindow = time.Hour

// flowRollupGroupKey is the full grouping key of the rollup aggregations.
// (It doubled as a deterministic ORDER BY while the aggregations paged with
// LIMIT/OFFSET — H1 of the 2026-07-01 audit; the AUDIT-204 window walk
// consumes each window's whole group set in one statement, so the ordering is
// no longer needed.)
// firewall_event joined the key in v30 (LC-03): without it a denied record —
// "the headline NetFlow win" — was collapsed into an anonymous flow_count and
// erased one hour after ingest. Like flow_source it is near-functionally
// determined per conversation (1-2 values in practice, 6 possible), so the
// cardinality cost is bounded.
const flowRollupGroupKey = "bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event"

// aggregateFlowsToRollup groups raw FlowSamples older than cutoff into
// 5-minute rollups, one bounded time window at a time (AUDIT-204 — see
// window_agg.go; the same LIMIT/OFFSET-over-GROUP-BY shape that wedged the
// syslog pass lived here). Returns true if work was done.
//
// Correctness shape (H1+H2 of the 2026-07-01 audit, retained):
//   - A MAX(id) watermark is captured first and every read AND delete are
//     scoped to `id <= watermark`, so the source set is immutable for the
//     whole pass — rows that arrive mid-aggregation (e.g. a collector
//     replaying its store-and-forward backlog with old timestamps) are never
//     deleted un-aggregated; they simply wait for the next cycle.
//   - Each window's inserts and its consumed-row delete run in ONE
//     transaction; windows commit independently, so a failure mid-backlog
//     keeps earlier windows' progress and can never leave rollups behind for
//     the next cycle to double-count.

// truncateToBucket rounds an instant DOWN to the start of the bucket it falls
// in, for the destination bucket width of a promotion step.
//
// This is what makes a promotion emit each destination bucket exactly ONCE.
// walkAggregationWindows clamps its final window at the cutoff
// (`winEnd = cutoff`, window_agg.go), so an un-truncated cutoff splits the
// bucket it lands in: the slice below the cutoff is promoted now and the rest on
// a later cycle, each producing a separate destination row with an identical
// group key. With a 5-minute ticker that happens every cycle, forever. Measured
// on production for a single day of the 1h tier: 2,416,851 rows for 2,085,373
// distinct keys — a multiplicity of 1.159, so roughly 16% of the table is
// redundant rows.
//
// Truncating defers the straddled bucket to the next cycle instead of splitting
// it. The cost is that a tier holds its data up to one extra bucket-width before
// promoting, which no longer matters to readers: they take every tier and let
// the timestamp predicate decide (see rollupIntervalsForWindow).
//
// The boundary is computed in UTC, because that is the zone the DB buckets in —
// the Postgres DSN pins TimeZone=UTC and SQLite's strftime normalises to UTC —
// so a local-zone day boundary would disagree with the bucket labels for any
// offset that is not a whole multiple of the width. The result is then carried
// back into the CALLER's zone. Same instant either way, but the zone is not
// cosmetic: this value becomes a `timestamp < ?` bound, and SQLite compares
// timestamps as rendered TEXT including the offset, so a UTC-rendered bound
// sorts against locally-rendered rows by its digits and silently misses them.
// walkAggregationWindows documents the same rule for its own window bounds.
func truncateToBucket(t time.Time, unit string) time.Time {
	u := t.UTC()
	switch unit {
	case "5min":
		return u.Truncate(5 * time.Minute).In(t.Location())
	case "hour":
		return u.Truncate(time.Hour).In(t.Location())
	case "day":
		return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).In(t.Location())
	default:
		return t
	}
}

func (d *Database) aggregateFlowsToRollup(cutoff time.Time, intervalType string) bool {
	// Whole destination buckets only — see truncateToBucket.
	cutoff = truncateToBucket(cutoff, "5min")
	bucketExpr := d.dialect.TimeBucket("5min", "timestamp")

	// No work probe here. There used to be a `SELECT 1 ... WHERE timestamp < ?
	// LIMIT 1` at this point, guarding against the fact that an unfiltered
	// watermark is non-zero whenever the table holds any row and so cannot
	// itself signal "nothing to roll up". That role now belongs to the start
	// probe below (oldestEligibleTimestamp), which answers the same question
	// from the same index and returns ok=false on MIN(timestamp) IS NULL.
	//
	// The removed probe was not merely redundant, it was a trap: `LIMIT 1`
	// divides the seq-scan cost estimate by the expected number of matches, so
	// a large estimate makes a full scan look nearly free. Its sibling on
	// flow_rollups was measured on production reading 1,971,092 buffers over
	// 23 seconds to return zero rows, every five minutes. See the note in
	// aggregateRollupsUp.

	// UNFILTERED deliberately — see the note on the promote path below. The
	// watermark is only an upper bound excluding rows that arrive mid-pass,
	// so any bound >= every id in the target set is correct; the predicates
	// stay on the reads and the delete, which already carry them.
	var watermark int64
	if err := d.db.Model(&models.FlowSample{}).
		Select("COALESCE(MAX(id), 0)").
		Scan(&watermark).Error; err != nil {
		log.Printf("Flow rollup: watermark: %v (will retry next cycle)", err)
		return false
	}
	if watermark == 0 {
		return false
	}

	// Window-walk start: the oldest eligible sample — the standalone timestamp
	// index's first tuple (the oldest rows pass the residual predicates
	// immediately; see oldestEligibleTimestamp's planner note).
	start, ok, err := oldestEligibleTimestamp(d.db.Model(&models.FlowSample{}).
		Where("timestamp < ? AND id <= ?", cutoff, watermark))
	if err != nil {
		log.Printf("Flow rollup: window start: %v (will retry next cycle)", err)
		return false
	}
	if !ok {
		return false
	}

	nextEligible := func(after time.Time) (time.Time, bool, error) {
		return oldestEligibleTimestamp(d.db.Model(&models.FlowSample{}).
			Where("timestamp >= ? AND timestamp < ? AND id <= ?", after, cutoff, watermark))
	}
	totalGroups, err := walkAggregationWindows(d.db, flowRollupWindow, start, cutoff, nextEligible,
		func(tx *gorm.DB, winStart, winEnd time.Time) (int, error) {
			var rows []rollupRow
			if err := tx.Model(&models.FlowSample{}).
				Where("timestamp >= ? AND timestamp < ? AND id <= ?", winStart, winEnd, watermark).
				Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event, " +
					"SUM(bytes) as bytes_sum, SUM(packets) as packets_sum, COUNT(*) as flow_count, " +
					"AVG(sampling_rate) as sampling_rate_avg").
				Group(flowRollupGroupKey).
				Scan(&rows).Error; err != nil {
				return 0, fmt.Errorf("flow rollup: scan raw flows: %w", err)
			}
			if len(rows) == 0 {
				return 0, nil
			}
			if err := batchInsertRollups(tx, rows, intervalType, "2006-01-02 15:04"); err != nil {
				return 0, fmt.Errorf("flow rollup: insert %s rollups: %w", intervalType, err)
			}
			// Delete exactly this window's aggregated rows (same watermark
			// scope), inside the same transaction as the inserts.
			if err := tx.Where("timestamp >= ? AND timestamp < ? AND id <= ?", winStart, winEnd, watermark).
				Delete(&models.FlowSample{}).Error; err != nil {
				return 0, fmt.Errorf("flow rollup: delete consumed raw flows: %w", err)
			}
			return len(rows), nil
		})
	if err != nil {
		log.Printf("Flow rollup: %v (window rolled back; %d groups from earlier windows kept, will resume next cycle)", err, totalGroups)
		return totalGroups > 0
	}

	if totalGroups == 0 {
		return false
	}
	log.Printf("Flow rollup: aggregated %d groups from raw flows into %s rollups", totalGroups, intervalType)
	return true
}

// aggregateRollupsUp promotes rollups from srcInterval older than cutoff into
// dstInterval, one bounded time window at a time (AUDIT-204). Uses weighted
// average for sampling rate. Returns true if work was done.
//
// Same correctness shape as aggregateFlowsToRollup (H1+H2 of the 2026-07-01
// audit): the MAX(id) watermark scopes both the reads and the delete to an
// immutable source set (the dstInterval rows we insert into the same table get
// ids above the watermark and a different interval_type, so they can never
// enter the source set), and each window's inserts + delete commit in one
// transaction. The window bound keeps per-transaction memory bounded, taking
// over that duty from the old pagination (M1 of the 2026-06-23 audit).
func (d *Database) aggregateRollupsUp(srcInterval, dstInterval string, cutoff time.Time) bool {
	bucketUnit := "hour"
	bucketFmt := "2006-01-02 15:04"
	if dstInterval == "1d" {
		bucketUnit = "day"
		bucketFmt = "2006-01-02"
	}
	// Whole destination buckets only — see truncateToBucket.
	cutoff = truncateToBucket(cutoff, bucketUnit)
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")

	// No work probe here — deliberately, and this is the site that proved why.
	//
	// The probe used to be `SELECT 1 FROM flow_rollups WHERE interval_type = ?
	// AND timestamp < ? LIMIT 1`. idx_rollup_interval_ts covers that predicate
	// exactly, but `LIMIT 1` prices a seq scan as (total cost / expected
	// matches), and with ~21M rows estimated to match the planner concluded the
	// first row was immediately at hand. Zero rows actually matched, so it read
	// the entire 19GB table to find nothing — measured on production at
	// 1,971,092 buffers and 23,234ms, running every five minutes forever.
	//
	// It is not replaced by an ORDER BY, because oldestEligibleTimestamp below
	// already answers the identical question correctly: it returns ok=false
	// exactly when MIN(timestamp) IS NULL, from the same index, as a
	// first-tuple stop measured at 1.9ms on the same zero-eligible case. The
	// unfiltered watermark between here and there is unaffected (it always runs
	// when any row exists, and watermark == 0 also returns false), so the whole
	// no-work path now costs about 7.7ms instead of 23 seconds.

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
	if err := d.db.Model(&models.FlowRollup{}).
		Select("COALESCE(MAX(id), 0)").
		Scan(&watermark).Error; err != nil {
		log.Printf("Flow rollup: %s watermark: %v (will retry next cycle)", srcInterval, err)
		return false
	}
	if watermark == 0 {
		return false
	}

	// Window-walk start: idx_rollup_interval_ts (interval_type, timestamp)
	// pins the leading column, so this is a first-tuple stop (see
	// oldestEligibleTimestamp's planner note).
	start, ok, err := oldestEligibleTimestamp(d.db.Model(&models.FlowRollup{}).
		Where("interval_type = ? AND timestamp < ? AND id <= ?", srcInterval, cutoff, watermark))
	if err != nil {
		log.Printf("Flow rollup: %s window start: %v (will retry next cycle)", srcInterval, err)
		return false
	}
	if !ok {
		return false
	}

	window := flowRollupWindow
	if bucketUnit == "day" && window < 24*time.Hour {
		window = 24 * time.Hour // never split a day bucket across windows
	}

	// scanStep bounds how much time ONE aggregate/delete statement pair covers
	// INSIDE a window. Zero means the window is handled in a single pair, which
	// is what every promotion but 1h→1d does.
	//
	// A day-destination window has to be 24 hours wide — splitting a day bucket
	// across windows writes it twice, the exact duplication truncateToBucket
	// exists to stop — which makes its SELECT and DELETE the largest statements
	// the ladder issues. Measured on production, a day of the 1h tier runs 2.4M
	// to 3.8M rows (2026-09-14 and 2026-09-13 respectively); the 2.4M day folds
	// to 2.1M groups and takes 14.7s to aggregate, and the DELETE covers the same
	// rows the SELECT read. Both run against the 30s statement_timeout the DSN
	// pins, and exceeding it there is not a slow cycle but a PERMANENT stall:
	// the window rolls back and the next tick reissues the identical statement,
	// forever. That is precisely the failure window_agg.go's header records from
	// the syslog pass.
	//
	// Walking the window in sub-ranges and merging the partial aggregates in Go
	// keeps every statement to one source-bucket width while the destination
	// rows stay whole-bucket: each sub-range emits the SAME bucket label, so the
	// accumulator folds them by group key into one row per bucket.
	//
	// What this buys is precisely that every STATEMENT stays under the 30s
	// cancel. It does NOT shorten the transaction, so it does not reduce how long
	// xmin is pinned — the window holds the same snapshot either way. Raising the
	// timeout was the alternative and is still declined, on the other half of
	// window_agg.go's reasoning for rejecting `SET LOCAL statement_timeout = 0`:
	// a single unbounded aggregate can spill temp files on the data volume, and
	// it removes the only AUTOMATIC backstop against a plan going wrong on a
	// table this size — pg_cancel_backend still works, but only if someone is
	// watching.
	var scanStep time.Duration
	if bucketUnit == "day" {
		scanStep = time.Hour
	}

	nextEligible := func(after time.Time) (time.Time, bool, error) {
		return oldestEligibleTimestamp(d.db.Model(&models.FlowRollup{}).
			Where("interval_type = ? AND timestamp >= ? AND timestamp < ? AND id <= ?", srcInterval, after, cutoff, watermark))
	}
	totalGroups, err := walkAggregationWindows(d.db, window, start, cutoff, nextEligible,
		func(tx *gorm.DB, winStart, winEnd time.Time) (int, error) {
			var acc rollupAccumulator
			for subStart := winStart; subStart.Before(winEnd); {
				subEnd := winEnd
				if scanStep > 0 {
					if e := subStart.Add(scanStep); e.Before(winEnd) {
						subEnd = e
					}
				}
				var rows []rollupRow
				if err := tx.Model(&models.FlowRollup{}).
					Where("interval_type = ? AND timestamp >= ? AND timestamp < ? AND id <= ?", srcInterval, subStart, subEnd, watermark).
					Select(bucketExpr + " as bucket, device_id, src_addr, dst_addr, dst_port, protocol, app_category, direction, scope_local, dst_country, dst_asn, flow_source, firewall_event, " +
						"SUM(bytes_sum) as bytes_sum, SUM(packets_sum) as packets_sum, SUM(flow_count) as flow_count, " +
						"CASE WHEN SUM(flow_count) > 0 THEN SUM(sampling_rate_avg * flow_count) / SUM(flow_count) ELSE 0 END as sampling_rate_avg").
					Group(flowRollupGroupKey).
					Scan(&rows).Error; err != nil {
					return 0, fmt.Errorf("flow rollup: scan %s rollups: %w", srcInterval, err)
				}
				// A GROUP BY over a non-empty range yields at least one group, so
				// no rows means no source rows and nothing to delete.
				if len(rows) > 0 {
					acc.add(rows)
					if err := tx.Where("interval_type = ? AND timestamp >= ? AND timestamp < ? AND id <= ?", srcInterval, subStart, subEnd, watermark).
						Delete(&models.FlowRollup{}).Error; err != nil {
						return 0, fmt.Errorf("flow rollup: delete consumed %s rollups: %w", srcInterval, err)
					}
				}
				subStart = subEnd
			}
			if len(acc.rows) == 0 {
				return 0, nil
			}
			// The insert trails every sub-range's delete, but they share one
			// transaction so the window is still atomic, and `id <= watermark`
			// keeps a delete from ever reaching a row this insert wrote.
			if err := batchInsertRollups(tx, acc.rows, dstInterval, bucketFmt); err != nil {
				return 0, fmt.Errorf("flow rollup: promote %s→%s: insert: %w", srcInterval, dstInterval, err)
			}
			return len(acc.rows), nil
		})
	if err != nil {
		log.Printf("Flow rollup: %v (window rolled back; %d groups from earlier windows kept, will resume next cycle)", err, totalGroups)
		return totalGroups > 0
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
