package database

import (
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"

	"gorm.io/gorm"
)

// Readers for the v72 normalized network-event table (Phase 2, PR 1, extended
// by PR 2). This is the first read path over net_events: the admin Events page.
// It lists rows newest-first over a bounded time window with device/probe/site/
// activity/action and src/dst/rule-key filters and paging. The filters are the
// ones the table's indexes serve — ts for the window (which prunes the daily
// partitions on Postgres), device_id for the device/site filters, and rule_key/
// src_ip/dst_ip for the endpoint and rule filters. Those last three were
// dropped by migration v80 (their one reader had moved to net_event_rollups);
// PR 2 re-adds them (net_event_index_readd.go, migration v82) because this
// page is their reader again.

// netEventPagerCountCap bounds the Events list's "of N" count; beyond it the
// response reports total_capped and the pager reads "10,000+". Mirrors
// syslogPagerCountCap: an exact COUNT over a busy 24 h window read millions of
// index entries on production, and past ten thousand rows nobody pages to the
// end anyway. A package var (not a const) so the SQLite test can shrink it —
// seeding 10,001 rows is slow; production always runs at 10,000.
var netEventPagerCountCap = 10000

// NetEventFilter constrains a ListNetEvents query. Zero-value fields are
// "no filter" — a device/probe/site id of 0 is never a real row (PKs start at
// 1) — except Activity and Action, where 0 is a real value ("unknown"), so
// those are pointers: nil means "all", a non-nil value filters equality.
// SrcIP/DstIP are a bare IP or a CIDR (validated by the handler), and RuleKey
// is an exact string; an empty string means "no filter". Hours is the lookback
// window in hours and is always > 0 (the handler derives it from
// httputil.ParseHours, default 24); ListNetEvents coerces a non-positive Hours
// to 24 so the query is never unbounded.
type NetEventFilter struct {
	DeviceID uint
	ProbeID  uint
	SiteID   uint
	Activity *int16
	Action   *int16
	SrcIP    string
	DstIP    string
	RuleKey  string
	Hours    int
}

// NetEventRow is the wire shape of one net_events row for the Events page:
// the columns the table renderer needs, plus the device name and vendor
// resolved post-load (see enrichNetEventRows). It is NOT the full GORM model —
// a page of 100 rows has no use for the rule/NAT/web/DNS/provenance columns,
// and omitting them keeps the scan and the JSON payload small. The NULL
// discipline matches models.NetEvent: a pointer is nil exactly when the vendor
// did not supply the field.
type NetEventRow struct {
	ID         uint      `json:"id"`
	Ts         time.Time `json:"ts"`
	DeviceID   uint      `json:"device_id"`
	ProbeID    uint      `json:"probe_id"`
	Activity   int16     `json:"activity"`
	Action     int16     `json:"action"`
	Direction  *int16    `json:"direction"`
	SrcIP      *string   `json:"src_ip"`
	SrcPort    *int32    `json:"src_port"`
	DstIP      *string   `json:"dst_ip"`
	DstPort    *int32    `json:"dst_port"`
	Proto      *int16    `json:"proto"`
	App        *string   `json:"app"`
	AppCat     *string   `json:"app_cat"`
	UserName   *string   `json:"user_name"`
	SrcCountry *string   `json:"src_country"`
	DstCountry *string   `json:"dst_country"`
	BytesIn    *int64    `json:"bytes_in"`
	BytesOut   *int64    `json:"bytes_out"`
	ThreatFlag int16     `json:"threat_flag"`
	// DeviceName and Vendor are transient: enriched from the devices table, not
	// stored on net_events.
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor"`
}

// netEventSelectColumns is the explicit SELECT list behind ListNetEvents, in
// NetEventRow field order. A hand-written list (not a GORM Select of the model)
// so only the columns the page renders are read off the leaf.
const netEventSelectColumns = "id, ts, device_id, probe_id, activity, action, direction, " +
	"src_ip, src_port, dst_ip, dst_port, proto, app, app_cat, user_name, " +
	"src_country, dst_country, bytes_in, bytes_out, threat_flag"

// ListNetEvents returns a filtered, newest-first page of net_events rows plus
// the capped count of rows matching the filter. limit is clamped to [1,500];
// offset is clamped to >= 0 (the handler already enforces these via
// httputil.ParsePagination; the clamps guard a store-level caller). The query
// is always ts-bounded (partition pruning) and the count stops at
// netEventPagerCountCap+1 via the subquery idiom, so the pager total is exact
// up to 10,000 and reads "10,000+" past it.
func (d *Database) ListNetEvents(f NetEventFilter, offset, limit int) ([]NetEventRow, int64, bool, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	hours := f.Hours
	if hours <= 0 {
		hours = 24
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// apply rebuilds the filtered query fresh on every call. This is load-bearing:
	// GORM chain methods MUTATE the statement in place (the clone returned by the
	// first method carries clone=0), so reusing a single `base` after `.Scan`
	// would leak the list query's ORDER/LIMIT/OFFSET into the COUNT subquery and
	// under-count by `offset` rows. Keeping the filters in ONE place also removes
	// the drift hazard of two hand-copied filter blocks — the syslog list had
	// that bug before AUDIT-193's fix, where editing one but not the other
	// desynced the pager total from the rows returned.
	apply := func() *gorm.DB {
		q := d.db.Table("net_events").Where("ts >= ?", cutoff)
		if f.DeviceID != 0 {
			q = q.Where("device_id = ?", f.DeviceID)
		}
		if f.ProbeID != 0 {
			q = q.Where("probe_id = ?", f.ProbeID)
		}
		// net_events has no site_id column; a site filter narrows by the devices
		// assigned to that site. The IN (subquery) form is portable across the
		// SQLite test lane and Postgres, and uses the devices.site_id index.
		if f.SiteID != 0 {
			q = q.Where("device_id IN (?)", d.db.Model(&models.Device{}).Where("site_id = ?", f.SiteID).Select("id"))
		}
		if f.Activity != nil {
			q = q.Where("activity = ?", *f.Activity)
		}
		if f.Action != nil {
			q = q.Where("action = ?", *f.Action)
		}
		if f.SrcIP != "" {
			q = netEventAddrFilter(q, d.dialect, "src_ip", f.SrcIP)
		}
		if f.DstIP != "" {
			q = netEventAddrFilter(q, d.dialect, "dst_ip", f.DstIP)
		}
		if f.RuleKey != "" {
			q = q.Where("rule_key = ?", f.RuleKey)
		}
		return q
	}

	var rows []NetEventRow
	if err := apply().Select(netEventSelectColumns).Order("ts DESC").Limit(limit).Offset(offset).Scan(&rows).Error; err != nil {
		return nil, 0, false, err
	}

	// The count stops at netEventPagerCountCap+1 via a real subquery (GORM's
	// Count on a query carrying a Limit still counts every row). Deliberately no
	// ORDER BY inside the subquery — only the number of rows matters, and an
	// ordered LIMIT cannot stop at the first match the way an unordered one can
	// (see the same note in handlers_analytics.go GetSyslogMessages).
	capped := apply().Select("1").Limit(netEventPagerCountCap + 1)
	var total int64
	if err := d.db.Table("(?) AS t", capped).Count(&total).Error; err != nil {
		return nil, 0, false, err
	}
	totalCapped := total > int64(netEventPagerCountCap)
	if totalCapped {
		total = int64(netEventPagerCountCap)
	}

	d.enrichNetEventRows(rows)
	return rows, total, totalCapped, nil
}

// netEventAddrFilter applies an IP/CIDR filter on one of the net_events inet
// columns (src_ip / dst_ip). The value is a bare IP or a CIDR, already
// validated by the handler, so this only picks the right predicate:
//
//   - Postgres: the columns are real inet. A bare IP filters on equality
//     (src_ip = '10.0.0.5'::inet), so the (src_ip, ts) btree index serves it;
//     a CIDR filters on the native containment operator (src_ip <<=
//     '10.0.0.0/8'::inet), which is exact for any mask length and address
//     family.
//   - SQLite: inet is stored as text, so the filter falls back to the
//     octet-aligned LIKE prefix cidrToLikePattern produces (a superset —
//     acceptable for the dev/test lane) for a CIDR, and an exact text match for
//     a bare IP. An IPv6 CIDR (unexpressible as a v4 prefix) becomes an exact
//     text match and therefore matches nothing — the safe direction.
func netEventAddrFilter(q *gorm.DB, d Dialect, column, val string) *gorm.DB {
	val = strings.TrimSpace(val)
	if val == "" {
		return q
	}
	// "everything" means no filter, matching the flow filters' semantics.
	if val == "0.0.0.0/0" || val == "::/0" {
		return q
	}
	if d.IsPostgres() {
		if strings.Contains(val, "/") {
			return q.Where(column+" <<= ?::inet", val)
		}
		return q.Where(column+" = ?::inet", val)
	}
	// SQLite (text): prefix-match the octet-aligned superset; a bare IP or an
	// unexpressible value becomes an exact text match.
	if pattern := cidrToLikePattern(val); pattern != "" {
		if strings.Contains(pattern, "%") {
			return q.Where(column+" LIKE ? ESCAPE '\\'", pattern)
		}
		return q.Where(column+" = ?", pattern)
	}
	return q.Where(column+" = ?", val)
}

// enrichNetEventRows resolves each row's DeviceName and Vendor from the devices
// table in one batched query (no N+1), mirroring deviceSiteNames / the alert
// enrichment. Unknown device ids are simply left with an empty name/vendor —
// net_events may hold rows for a device retired (but not purged) since.
func (d *Database) enrichNetEventRows(rows []NetEventRow) {
	if len(rows) == 0 {
		return
	}
	idset := make(map[uint]struct{}, len(rows))
	for _, r := range rows {
		if r.DeviceID != 0 {
			idset[r.DeviceID] = struct{}{}
		}
	}
	ids := make([]uint, 0, len(idset))
	for id := range idset {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	var devs []struct {
		ID     uint
		Name   string
		Vendor string
	}
	if err := d.db.Model(&models.Device{}).Where("id IN ?", ids).Select("id, name, vendor").Scan(&devs).Error; err != nil {
		return // enrichment is best-effort: a device lookup failure must not drop the page
	}
	type devNameVendor struct{ Name, Vendor string }
	byID := make(map[uint]devNameVendor, len(devs))
	for _, dv := range devs {
		byID[dv.ID] = devNameVendor{dv.Name, dv.Vendor}
	}
	for i := range rows {
		if dv, ok := byID[rows[i].DeviceID]; ok {
			rows[i].DeviceName = dv.Name
			rows[i].Vendor = dv.Vendor
		}
	}
}

// ---------------------------------------------------------------------------
// sec_events — the security half of the Events page (Phase 2, PR 3)
// ---------------------------------------------------------------------------

// secEventPagerCountCap bounds the Security events list's "of N" count; beyond
// it the response reports total_capped and the pager reads "10,000+". Mirrors
// netEventPagerCountCap and is a separate package var (not shared) so the
// SQLite test can shrink each list's cap independently — seeding 10,001 rows
// twice would be pointlessly slow.
var secEventPagerCountCap = 10000

// SecEventFilter constrains a ListSecEvents query. Zero-value fields are
// "no filter" — a device/probe id of 0 is never a real row (PKs start at 1) —
// except Class, Activity, Action and Severity, where the model's default (0 /
// NULL) is a real value, so those are pointers: nil means "all", a non-nil
// value filters equality. AdminUser / SigName / TunnelName / WanName are
// substrings (see secEventTextFilter) — an exact match on a
// free-text name is rarely what the operator wants, and none of these columns
// is indexed to serve one anyway. Hours is the lookback window and is always
// > 0; ListSecEvents coerces a non-positive Hours to 24 so the query is never
// unbounded.
type SecEventFilter struct {
	DeviceID   uint
	ProbeID    uint
	Class      *int16
	Activity   *int16
	Action     *int16
	Severity   *int16
	AdminUser  string
	SigName    string
	TunnelName string
	WanName    string
	Hours      int
}

// SecEventRow is the wire shape of one sec_events row for the Security events
// page: the columns the class-conditional table renderer needs, plus the device
// name and vendor resolved post-load (see enrichSecEventRows). It is NOT the
// full GORM model — but unlike NetEventRow (one class, one column set) the
// Security page spans every class, so the row carries the UNION of the
// class-specific fields (finding/auth/config_change/vpn_session/device_health)
// and omits only the provenance columns nothing on this page renders. The NULL
// discipline matches models.SecEvent: a pointer is nil exactly when the vendor
// did not supply the field.
type SecEventRow struct {
	ID          uint      `json:"id"`
	Ts          time.Time `json:"ts"`
	DeviceID    uint      `json:"device_id"`
	ProbeID     uint      `json:"probe_id"`
	Class       int16     `json:"class"`
	Activity    int16     `json:"activity"`
	Action      int16     `json:"action"`
	Severity    *int16    `json:"severity"`
	SrcIP       *string   `json:"src_ip"`
	SrcPort     *int32    `json:"src_port"`
	DstIP       *string   `json:"dst_ip"`
	DstPort     *int32    `json:"dst_port"`
	Proto       *int16    `json:"proto"`
	UserName    *string   `json:"user_name"`
	SrcHostname *string   `json:"src_hostname"`
	AdminUser   *string   `json:"admin_user"`
	AdminSrcIP  *string   `json:"admin_src_ip"`
	AdminMethod *string   `json:"admin_method"`
	SigID       *string   `json:"sig_id"`
	SigName     *string   `json:"sig_name"`
	ThreatCat   *string   `json:"threat_cat"`
	FileHash    *string   `json:"file_hash"`
	URLHost     *string   `json:"url_host"`
	TunnelName  *string   `json:"tunnel_name"`
	TunnelType  *string   `json:"tunnel_type"`
	TunnelPeer  *string   `json:"tunnel_peer"`
	ConfigPath  *string   `json:"config_path"`
	ConfigObj   *string   `json:"config_obj"`
	ConfigOld   *string   `json:"config_old"`
	ConfigNew   *string   `json:"config_new"`
	WANName     *string   `json:"wan_name"`
	MetricName  *string   `json:"metric_name"`
	MetricValue *float64  `json:"metric_value"`
	Message     *string   `json:"message"`
	// DeviceName and Vendor are transient: enriched from the devices table, not
	// stored on sec_events.
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor"`
}

// secEventSelectColumns is the explicit SELECT list behind ListSecEvents, in
// SecEventRow field order — a hand-written list so only the columns the page
// renders are read off the leaf (the page never touches raw_id/raw_ts/extra).
const secEventSelectColumns = "id, ts, device_id, probe_id, class, activity, action, severity, " +
	"src_ip, src_port, dst_ip, dst_port, proto, user_name, src_hostname, " +
	"admin_user, admin_src_ip, admin_method, sig_id, sig_name, threat_cat, file_hash, url_host, " +
	"tunnel_name, tunnel_type, tunnel_peer, config_path, config_obj, config_old, config_new, " +
	"wan_name, metric_name, metric_value, message"

// ListSecEvents returns a filtered, newest-first page of sec_events rows plus
// the capped count of rows matching the filter. limit is clamped to [1,500];
// offset is clamped to >= 0. The query is always ts-bounded (partition pruning)
// and the count stops at secEventPagerCountCap+1 via the subquery idiom — the
// same reasons as ListNetEvents, and the same apply()-closure so the count and
// the list never leak OFFSET into each other.
func (d *Database) ListSecEvents(f SecEventFilter, offset, limit int) ([]SecEventRow, int64, bool, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	hours := f.Hours
	if hours <= 0 {
		hours = 24
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// apply rebuilds the filtered query fresh on every call, for the same
	// reason as ListNetEvents: GORM chain methods mutate the statement in place,
	// so a shared base would leak ORDER/LIMIT/OFFSET into the count subquery.
	apply := func() *gorm.DB {
		q := d.db.Table("sec_events").Where("ts >= ?", cutoff)
		if f.DeviceID != 0 {
			q = q.Where("device_id = ?", f.DeviceID)
		}
		if f.ProbeID != 0 {
			q = q.Where("probe_id = ?", f.ProbeID)
		}
		if f.Class != nil {
			q = q.Where("class = ?", *f.Class)
		}
		if f.Activity != nil {
			q = q.Where("activity = ?", *f.Activity)
		}
		if f.Action != nil {
			q = q.Where("action = ?", *f.Action)
		}
		if f.Severity != nil {
			q = q.Where("severity = ?", *f.Severity)
		}
		q = secEventTextFilter(q, "admin_user", f.AdminUser)
		q = secEventTextFilter(q, "sig_name", f.SigName)
		q = secEventTextFilter(q, "tunnel_name", f.TunnelName)
		q = secEventTextFilter(q, "wan_name", f.WanName)
		return q
	}

	var rows []SecEventRow
	if err := apply().Select(secEventSelectColumns).Order("ts DESC").Limit(limit).Offset(offset).Scan(&rows).Error; err != nil {
		return nil, 0, false, err
	}

	// The count stops at secEventPagerCountCap+1 via a real subquery (GORM's
	// Count on a query carrying a Limit still counts every row). No ORDER BY
	// inside the subquery — an unordered LIMIT can stop at the first match.
	capped := apply().Select("1").Limit(secEventPagerCountCap + 1)
	var total int64
	if err := d.db.Table("(?) AS t", capped).Count(&total).Error; err != nil {
		return nil, 0, false, err
	}
	totalCapped := total > int64(secEventPagerCountCap)
	if totalCapped {
		total = int64(secEventPagerCountCap)
	}

	d.enrichSecEventRows(rows)
	return rows, total, totalCapped, nil
}

// secEventTextFilter applies a substring filter on one of the sec_events
// free-text columns (admin_user / sig_name / tunnel_name / wan_name). The value
// is a name the operator types, so a substring with the wildcards escaped
// (mirroring the syslog search filter) is far more useful than an exact match.
// None of these columns is indexed, so there is no index to lose by matching
// with LIKE.
func secEventTextFilter(q *gorm.DB, column, val string) *gorm.DB {
	val = strings.TrimSpace(val)
	if val == "" {
		return q
	}
	escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(val)
	return q.Where(column+" LIKE ? ESCAPE '\\'", "%"+escaped+"%")
}

// enrichSecEventRows resolves each row's DeviceName and Vendor from the devices
// table in one batched query (no N+1), mirroring enrichNetEventRows. Unknown
// device ids are left with an empty name/vendor — sec_events may hold rows for
// a device retired (but not purged) since.
func (d *Database) enrichSecEventRows(rows []SecEventRow) {
	if len(rows) == 0 {
		return
	}
	idset := make(map[uint]struct{}, len(rows))
	for _, r := range rows {
		if r.DeviceID != 0 {
			idset[r.DeviceID] = struct{}{}
		}
	}
	ids := make([]uint, 0, len(idset))
	for id := range idset {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	var devs []struct {
		ID     uint
		Name   string
		Vendor string
	}
	if err := d.db.Model(&models.Device{}).Where("id IN ?", ids).Select("id, name, vendor").Scan(&devs).Error; err != nil {
		return // enrichment is best-effort: a device lookup failure must not drop the page
	}
	type devNameVendor struct{ Name, Vendor string }
	byID := make(map[uint]devNameVendor, len(devs))
	for _, dv := range devs {
		byID[dv.ID] = devNameVendor{dv.Name, dv.Vendor}
	}
	for i := range rows {
		if dv, ok := byID[rows[i].DeviceID]; ok {
			rows[i].DeviceName = dv.Name
			rows[i].Vendor = dv.Vendor
		}
	}
}

// ---------------------------------------------------------------------------
// net_event_rollups — the Events page's long-term analytics (Phase 2, PR 4)
// ---------------------------------------------------------------------------

// The rollup table exists for counts-only history: raw net_events keep a short
// TTL, so a window past that TTL can only be answered from net_event_rollups,
// whose (day, device_id, rule_key, action, direction, app_cat, ruleset) unique
// key already carries the daily hits/bytes/distinct_src. Every series below is
// therefore a GROUP BY over `day >= from` — the unique key's (day, device_id, …)
// prefix serves both the day scan and the device/site narrowing — and no new
// index or migration is added.

const (
	// netEventRollupStatsDefaultDays is the lookback NetEventRollupStats uses
	// when the filter does not name a window; netEventRollupStatsMaxDays is the
	// ceiling (one year — the rollup retention window).
	netEventRollupStatsDefaultDays = 30
	netEventRollupStatsMaxDays     = 365
	// netEventRollupTopRules bounds the "top rules" card. The chart cannot show
	// an unbounded ranking, and past a handful of rules nothing is readable.
	netEventRollupTopRules = 10
)

// NetEventRollupFilter constrains a NetEventRollupStats query. Days is the
// lookback window in UTC days (coerced to [1,365]; default 30). DeviceID and
// SiteID of 0 mean "no filter" — a device id of 0 is never a real row (PKs
// start at 1), and a site filter narrows by the devices assigned to that site
// (net_event_rollups has no site_id column).
type NetEventRollupFilter struct {
	Days     int
	DeviceID uint
	SiteID   uint
}

// NetEventRollupRule is one policy rule's aggregate over the window — the
// "top rules" card's rows. The empty rule_key (the rollup's "no rule reported"
// sentinel) is excluded by the query: "top rules" names real rules.
type NetEventRollupRule struct {
	RuleKey  string `json:"rule_key"`
	Hits     int64  `json:"hits"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// NetEventRollupDay is one UTC day's aggregate — a point on the policy-bytes
// and deny-trend charts. Day is "YYYY-MM-DD" (the rollup's day column is a UTC
// midnight, so bucketing it to a day is a no-op).
type NetEventRollupDay struct {
	Day      string `json:"day"`
	Hits     int64  `json:"hits"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// NetEventRollupDirection is one direction's SUM(hits) over the window. The
// int16 is the raw rollup direction so the UI labels it via enums.js DIRECTION.
type NetEventRollupDirection struct {
	Direction int16 `json:"direction"`
	Hits      int64 `json:"hits"`
}

// NetEventRollupStatsResult is the long-term analytics payload for the Events
// page: policy hits (top rules) and bytes, the deny trend, and the app-category
// / direction / ruleset breakdowns. The day-bucketed series (PolicyBytes and
// Deny) are ordered oldest-first; the breakdowns are ordered by count
// descending (directions by id) for direct charting.
type NetEventRollupStatsResult struct {
	PolicyHits    []NetEventRollupRule      `json:"policy_hits"`
	PolicyBytes   []NetEventRollupDay       `json:"policy_bytes"`
	Deny          []NetEventRollupDay       `json:"deny"`
	AppCategories []KeyCount                `json:"app_categories"`
	Directions    []NetEventRollupDirection `json:"directions"`
	Rulesets      []KeyCount                `json:"rulesets"`
}

// rollupByteSums is the shared SELECT tail for the rule and day-bucketed
// series: SUMs cast to BIGINT because Postgres sums bigint into numeric (the
// same cast the rollup writer uses).
const rollupByteSums = "CAST(SUM(hits) AS BIGINT) AS hits, " +
	"CAST(SUM(bytes_in) AS BIGINT) AS bytes_in, CAST(SUM(bytes_out) AS BIGINT) AS bytes_out"

// netEventRollupDayRow is the scan shape of one day-bucketed series. Day is the
// rollup's day column (a UTC midnight timestamp); the exported NetEventRollupDay
// renders it as "YYYY-MM-DD" so the wire form is dialect-independent.
type netEventRollupDayRow struct {
	Day      time.Time
	Hits     int64
	BytesIn  int64
	BytesOut int64
}

// toDays maps the day-bucketed scan rows to the wire shape, oldest-first (the
// query already orders by day).
func toDays(rows []netEventRollupDayRow) []NetEventRollupDay {
	out := make([]NetEventRollupDay, 0, len(rows))
	for _, r := range rows {
		out = append(out, NetEventRollupDay{
			Day:      r.Day.UTC().Format("2006-01-02"),
			Hits:     r.Hits,
			BytesIn:  r.BytesIn,
			BytesOut: r.BytesOut,
		})
	}
	return out
}

// NetEventRollupStats computes the six grouped series over the window. The six
// queries share one base filter (built once, so the series can never drift),
// and each rides the rollup table's unique key prefix — no new index.
func (d *Database) NetEventRollupStats(f NetEventRollupFilter) (*NetEventRollupStatsResult, error) {
	days := f.Days
	if days <= 0 {
		days = netEventRollupStatsDefaultDays
	}
	if days > netEventRollupStatsMaxDays {
		days = netEventRollupStatsMaxDays
	}
	// The window starts at the UTC midnight of (days-1) days ago, so a 30-day
	// window covers exactly 30 distinct day buckets (today plus the 29 before).
	from := utcDay(time.Now()).AddDate(0, 0, -(days - 1))

	// base rebuilds the filtered query fresh on every call for the same reason
	// ListNetEvents does: GORM chain methods mutate the statement in place, so a
	// shared base would leak one series' GROUP BY into the next. The day bound
	// is always present (partition/index pruning); the device/site filters
	// narrow through the same key prefix.
	base := func() *gorm.DB {
		q := d.db.Table("net_event_rollups").Where("day >= ?", from)
		if f.DeviceID != 0 {
			q = q.Where("device_id = ?", f.DeviceID)
		}
		// net_event_rollups has no site_id column; a site filter narrows by the
		// devices assigned to that site (the IN (subquery) form ListNetEvents
		// uses), so the (day, device_id, …) prefix still serves the day scan.
		if f.SiteID != 0 {
			q = q.Where("device_id IN (?)", d.db.Model(&models.Device{}).Where("site_id = ?", f.SiteID).Select("id"))
		}
		return q
	}

	res := &NetEventRollupStatsResult{}

	// policy_hits: the top rules by SUM(hits) with their bytes, over the whole
	// window (a ranking, not a time series). The empty rule_key sentinel is
	// excluded so "top rules" names real rules.
	if err := base().
		Select("rule_key, " + rollupByteSums).
		Where("rule_key <> ''").
		Group("rule_key").Order("hits DESC").Limit(netEventRollupTopRules).
		Scan(&res.PolicyHits).Error; err != nil {
		return nil, fmt.Errorf("policy hits: %w", err)
	}

	// policy_bytes: the bytes carried per day across every action — the whole
	// reason the rollup exists, served day-by-day for the trend chart. Grouping
	// by the day column (already a UTC midnight) gives one row per day, riding
	// the unique key's leading column.
	var policyBytes []netEventRollupDayRow
	if err := base().
		Select("day, " + rollupByteSums).
		Group("day").Order("day ASC").
		Scan(&policyBytes).Error; err != nil {
		return nil, fmt.Errorf("policy bytes: %w", err)
	}
	res.PolicyBytes = toDays(policyBytes)

	// deny: the hits/bytes denied per day, where action is one of the two deny
	// verdicts (deny and deny-with-reset). The action column is part of the
	// unique key, so `action IN (2,3)` filters on an indexed column.
	var deny []netEventRollupDayRow
	if err := base().
		Where("action IN ?", []int16{int16(normalize.ActionDeny), int16(normalize.ActionReject)}).
		Select("day, " + rollupByteSums).
		Group("day").Order("day ASC").
		Scan(&deny).Error; err != nil {
		return nil, fmt.Errorf("deny: %w", err)
	}
	res.Deny = toDays(deny)

	// app_categories: SUM(hits) by application category. app_cat is a vendor
	// string in the unique key, so this groups on an indexed column; the empty
	// string ("not reported") is kept and the UI labels it "uncategorized".
	if err := base().
		Select("app_cat AS key, CAST(SUM(hits) AS BIGINT) AS count").
		Group("app_cat").Order("count DESC").
		Scan(&res.AppCategories).Error; err != nil {
		return nil, fmt.Errorf("app categories: %w", err)
	}

	// directions: SUM(hits) by direction (an indexed key column), ordered by id
	// so the legend is stable.
	if err := base().
		Select("direction, CAST(SUM(hits) AS BIGINT) AS hits").
		Group("direction").Order("direction ASC").
		Scan(&res.Directions).Error; err != nil {
		return nil, fmt.Errorf("directions: %w", err)
	}

	// rulesets: SUM(hits) by ruleset (an indexed key column; '' is the "root"
	// / no-ruleset sentinel).
	if err := base().
		Select("ruleset AS key, CAST(SUM(hits) AS BIGINT) AS count").
		Group("ruleset").Order("count DESC").
		Scan(&res.Rulesets).Error; err != nil {
		return nil, fmt.Errorf("rulesets: %w", err)
	}

	// Normalize nil (no-rows) series to empty slices so the wire shape is []
	// rather than null — the UI maps each series without a null guard.
	if res.PolicyHits == nil {
		res.PolicyHits = []NetEventRollupRule{}
	}
	if res.PolicyBytes == nil {
		res.PolicyBytes = []NetEventRollupDay{}
	}
	if res.Deny == nil {
		res.Deny = []NetEventRollupDay{}
	}
	if res.AppCategories == nil {
		res.AppCategories = []KeyCount{}
	}
	if res.Directions == nil {
		res.Directions = []NetEventRollupDirection{}
	}
	if res.Rulesets == nil {
		res.Rulesets = []KeyCount{}
	}

	return res, nil
}
