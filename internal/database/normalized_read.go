package database

import (
	"fmt"
	"strings"
	"sync"
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
	// RawID/RawTS are the provenance back to the syslog_messages row this event
	// was normalized from (that PK is (id, timestamp) on partitioned installs,
	// hence both). nil = the vendor supplied no raw line. The list renderer
	// ignores them, but the event-detail "View raw syslog" forensic bridge
	// (Phase 2, PR 8) needs them, and they cost one nullable bigint + timestamptz
	// per row — cheaper than a second query path per clicked row.
	RawID *int64     `json:"raw_id"`
	RawTS *time.Time `json:"raw_ts"`
	// DeviceName and Vendor are transient: enriched from the devices table, not
	// stored on net_events.
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor"`
}

// netEventSelectColumns is the explicit SELECT list behind ListNetEvents and
// GetNetEvent, in NetEventRow field order. A hand-written list (not a GORM
// Select of the model) so only the columns the page and its detail view read
// are fetched off the leaf. raw_id/raw_ts are included for the detail view's
// "View raw syslog" link even though the list renderer ignores them.
const netEventSelectColumns = "id, ts, device_id, probe_id, activity, action, direction, " +
	"src_ip, src_port, dst_ip, dst_port, proto, app, app_cat, user_name, " +
	"src_country, dst_country, bytes_in, bytes_out, threat_flag, raw_id, raw_ts"

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

// GetNetEvent returns one net_events row by id (gorm.ErrRecordNotFound when
// absent), reusing the exact select list and enrichment ListNetEvents uses so
// the detail view is the list row plus the provenance columns (raw_id/raw_ts)
// the "View raw syslog" link needs. It is deliberately NOT ts-bounded: an id
// lookup is a single-PK fetch, so there is no partition bound to prune against
// and the row may legitimately be older than the list's window.
func (d *Database) GetNetEvent(id uint) (*NetEventRow, error) {
	var rows []NetEventRow
	if err := d.db.Table("net_events").Select(netEventSelectColumns).Where("id = ?", id).Limit(1).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	d.enrichNetEventRows(rows)
	return &rows[0], nil
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
	// RawID/RawTS are the provenance back to the syslog_messages row this event
	// was normalized from (that PK is (id, timestamp) on partitioned installs,
	// hence both). nil = the vendor supplied no raw line. The list renderer
	// ignores them, but the event-detail "View raw syslog" forensic bridge
	// (Phase 2, PR 8) needs them.
	RawID *int64     `json:"raw_id"`
	RawTS *time.Time `json:"raw_ts"`
	// DeviceName and Vendor are transient: enriched from the devices table, not
	// stored on sec_events.
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor"`
}

// secEventSelectColumns is the explicit SELECT list behind ListSecEvents and
// GetSecEvent, in SecEventRow field order — a hand-written list so only the
// columns the page and its detail view read are fetched off the leaf.
// raw_id/raw_ts are included for the detail view's "View raw syslog" link even
// though the list renderer ignores them.
const secEventSelectColumns = "id, ts, device_id, probe_id, class, activity, action, severity, " +
	"src_ip, src_port, dst_ip, dst_port, proto, user_name, src_hostname, " +
	"admin_user, admin_src_ip, admin_method, sig_id, sig_name, threat_cat, file_hash, url_host, " +
	"tunnel_name, tunnel_type, tunnel_peer, config_path, config_obj, config_old, config_new, " +
	"wan_name, metric_name, metric_value, message, raw_id, raw_ts"

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

// GetSecEvent returns one sec_events row by id (gorm.ErrRecordNotFound when
// absent), reusing the exact select list and enrichment ListSecEvents uses so
// the detail view is the list row plus the provenance columns (raw_id/raw_ts)
// the "View raw syslog" link needs. Not ts-bounded, for the same reason as
// GetNetEvent: an id lookup has no partition bound to prune against, and a
// config_change row is retained forever by default.
func (d *Database) GetSecEvent(id uint) (*SecEventRow, error) {
	var rows []SecEventRow
	if err := d.db.Table("sec_events").Select(secEventSelectColumns).Where("id = ?", id).Limit(1).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	d.enrichSecEventRows(rows)
	return &rows[0], nil
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
	PolicyHits  []NetEventRollupRule `json:"policy_hits"`
	PolicyBytes []NetEventRollupDay  `json:"policy_bytes"`
	// PolicyBytesFrom is the first day the byte series is trustworthy, when a
	// retrofitted install has stored netEventRollupBytesValidFromKey. It lets
	// the UI say "since <day>" instead of showing pre-fix bytes that were
	// reconciled under the old cumulative-counter bug. Empty = no clamp.
	PolicyBytesFrom string                    `json:"policy_bytes_from,omitempty"`
	Deny            []NetEventRollupDay       `json:"deny"`
	AppCategories   []KeyCount                `json:"app_categories"`
	Directions      []NetEventRollupDirection `json:"directions"`
	Rulesets        []KeyCount                `json:"rulesets"`
}

// netEventRollupBytesValidFromKey is the optional YYYY-MM-DD floor for the
// policy-bytes series. It exists for installs that collected FortiGate
// traffic rows before "accept" records stopped storing cumulative session
// counters (the fix in internal/normalize/mapper_fortigate.go): the rollup
// rows before the repaired day cannot be un-summed, so the chart starts at
// the first day that was rebuilt from corrected data. Absent = no clamp, the
// normal state on a fresh install. Set by the operator as part of the
// retrofit (see docs/DATA-RETENTION.md).
const netEventRollupBytesValidFromKey = "net_event_rollup_bytes_valid_from"

// rollupBytesFrom clamps the policy-bytes window to the retrofit marker, if
// one is stored. The other series keep the full window: their counts are not
// affected by the cumulative-counter bug.
func (d *Database) rollupBytesFrom(from time.Time) (time.Time, string) {
	v, ok := d.GetSettingValue(netEventRollupBytesValidFromKey)
	if !ok {
		return from, ""
	}
	t, err := time.Parse(time.DateOnly, strings.TrimSpace(v))
	if err != nil {
		return from, ""
	}
	if t.After(from) {
		return t, t.Format(time.DateOnly)
	}
	// The marker predates the window: the whole series is already trusted, so
	// no label is needed.
	return from, ""
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

	// The retrofit floor applies to every BYTE column the response exposes.
	// Counts (hits, distinct sources, app categories) keep the full window:
	// the cumulative-counter bug never touched them.
	policyFrom, policyFromLabel := d.rollupBytesFrom(from)
	res.PolicyBytesFrom = policyFromLabel

	// policy_hits: the top rules by SUM(hits) over the whole window (a
	// ranking, not a time series), with their bytes taken only from the
	// trusted floor. The empty rule_key sentinel is excluded so "top rules"
	// names real rules.
	hitsWithClampedBytes := "CAST(SUM(hits) AS BIGINT) AS hits, " +
		"CAST(COALESCE(SUM(CASE WHEN day >= ? THEN bytes_in END), 0) AS BIGINT) AS bytes_in, " +
		"CAST(COALESCE(SUM(CASE WHEN day >= ? THEN bytes_out END), 0) AS BIGINT) AS bytes_out"
	if err := base().
		Select("rule_key, "+hitsWithClampedBytes, policyFrom, policyFrom).
		Where("rule_key <> ''").
		Group("rule_key").Order("hits DESC").Limit(netEventRollupTopRules).
		Scan(&res.PolicyHits).Error; err != nil {
		return nil, fmt.Errorf("policy hits: %w", err)
	}

	// policy_bytes: the bytes carried per day across every action — the whole
	// reason the rollup exists, served day-by-day for the trend chart. Grouping
	// by the day column (already a UTC midnight) gives one row per day, riding
	// the unique key's leading column. The retrofit floor (if any) starts the
	// series at the first day whose bytes were rebuilt from corrected input.
	var policyBytes []netEventRollupDayRow
	if err := base().Where("day >= ?", policyFrom).
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

// ---------------------------------------------------------------------------
// net_events — short-window analytics (Phase 2, PR 5)
// ---------------------------------------------------------------------------

// The rollups (PR 4) retain counts keyed by rule/action/direction/app_cat/
// ruleset, so anything not in that key — geo (src/dst country), identity
// (IP↔MAC), the specific user/app/web-category/DNS-name, and NAT pairs — has no
// long-term home. This reader answers those dimensions directly over the raw
// net_events table, which keeps a short TTL, so the window is capped at 720
// hours (30 days) and defaults to 24. Every series is a `ts >= cutoff` GROUP BY
// (the table is RANGE-partitioned on ts by DAY, so the bound prunes daily
// partitions) with a LIMIT on each ranking, and empty/NULL groups are skipped.
// No index or migration is added: the ts bound is served by the existing
// (ts) and (device_id, ts) leaf indexes, and none of the grouped columns is
// worth an index for a 24 h dashboard read.

const (
	// netEventStatsDefaultHours is the lookback NetEventStats uses when the
	// filter does not name a window; netEventStatsMaxHours is the ceiling (30
	// days — the raw table's retention). Beyond a day the GROUP BYs grow with
	// the row count, so the default stays bounded and the handler never asks
	// for more than the ceiling.
	netEventStatsDefaultHours = 24
	netEventStatsMaxHours     = 720
	// netEventStatsTopN bounds each ranking card (users, apps, web categories,
	// DNS, NAT pairs, identity). The charts cannot show an unbounded ranking,
	// and past a handful of entries nothing is readable.
	netEventStatsTopN = 10
)

// NetEventStatsFilter constrains a NetEventStats query. Hours is the lookback
// window in hours (coerced to [1,720]; default 24). DeviceID and SiteID of 0
// mean "no filter" — a device id of 0 is never a real row (PKs start at 1), and
// a site filter narrows by the devices assigned to that site (net_events has no
// site_id column).
type NetEventStatsFilter struct {
	Hours    int
	DeviceID uint
	SiteID   uint
}

// NetEventGeoStat is one country's aggregate over the window (the "top
// countries" cards): the hit count plus the bytes it carried. Country is the
// ISO-3166 alpha-2 code stored in the char(2) column; the empty/NULL code is
// excluded by the query.
type NetEventGeoStat struct {
	Country  string `json:"country"`
	Hits     int64  `json:"hits"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// NetEventIdentityStat is one source (IP, MAC) pair's hit count — the "who is
// on the network" card. SrcMAC may be empty (the vendor did not report it) but
// SrcIP is always present: the query skips rows with no src_ip.
type NetEventIdentityStat struct {
	SrcIP  string `json:"src_ip"`
	SrcMAC string `json:"src_mac"`
	Hits   int64  `json:"hits"`
}

// NetEventNATStat is one NAT (src, dst) pair's hit count — the translated
// flows, "src before translation → dst after translation". DstIP may be empty
// when the vendor reported only the translated source.
type NetEventNATStat struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Hits  int64  `json:"hits"`
}

// NetEventStatsResult is the short-window analytics payload for the Events
// page: the grouped series the rollups do not retain. The ranking series
// (Identity, Users, Apps, AppCategories, WebCategories, DNS, NAT) are ordered
// by count descending for direct charting; the geo cards are ordered the same
// way.
type NetEventStatsResult struct {
	GeoSrc        []NetEventGeoStat      `json:"geo_src"`
	GeoDst        []NetEventGeoStat      `json:"geo_dst"`
	Identity      []NetEventIdentityStat `json:"identity"`
	Users         []KeyCount             `json:"users"`
	Apps          []KeyCount             `json:"apps"`
	AppCategories []KeyCount             `json:"app_categories"`
	WebCategories []KeyCount             `json:"web_categories"`
	DNS           []KeyCount             `json:"dns"`
	NAT           []NetEventNATStat      `json:"nat"`

	// PolicyBytesHourly / DenyHourly give the sub-day range pills a real
	// trend: the day-granular rollup has exactly one bucket for 1h..24h, which
	// renders as a single dot on a line chart. These are the same totals
	// bucketed by hour from the raw table, so the Policy Bytes and Deny cards
	// can stay hour-precise for the ranges where the rollup cannot.
	PolicyBytesHourly []NetEventHourStat `json:"policy_bytes_hourly"`
	DenyHourly        []NetEventHourStat `json:"deny_hourly"`
}

// NetEventHourStat is one hour-bucketed row of the raw analytics: hits and
// bytes for all traffic, or for the deny/reject verdicts on DenyHourly.
type NetEventHourStat struct {
	Hour     string `json:"hour"`
	Hits     int64  `json:"hits"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// netEventStatByteSums is the shared SELECT tail for the geo series: SUMs cast
// to BIGINT because Postgres sums bigint into numeric (the same cast the
// rollup reader uses).
const netEventStatByteSums = "CAST(COALESCE(SUM(bytes_in), 0) AS BIGINT) AS bytes_in, " +
	"CAST(COALESCE(SUM(bytes_out), 0) AS BIGINT) AS bytes_out"

// netEventStatKeyCount runs one key-count ranking over the shared base filter:
// COUNT(*) grouped by the named text column, empty/NULL values skipped, top-N
// kept. The five key-count series (users, apps, app_categories, web_categories,
// dns) are identical modulo the column, so one helper keeps them from drifting.
func netEventStatKeyCount(base func() *gorm.DB, column, label string) ([]KeyCount, error) {
	var out []KeyCount
	if err := base().
		Select(column + " AS key, COUNT(*) AS count").
		Where(column + " IS NOT NULL AND " + column + " <> ''").
		Group(column).Order("count DESC").Limit(netEventStatsTopN).
		Scan(&out).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return out, nil
}

// NetEventStats computes the short-window series over the raw net_events table.
// The queries share one base filter (built once, so the series can never
// drift), and each is `ts >= cutoff` bounded so the daily partitions prune. The
// top-N LIMITs keep each ranking small, and the bounded default (24 h) keeps
// the GROUP BYs cheap: the 30-day ceiling is the raw table's retention, and a
// call over it is the caller's explicit choice (the handler caps hours at 720).
func (d *Database) NetEventStats(f NetEventStatsFilter) (*NetEventStatsResult, error) {
	hours := f.Hours
	if hours <= 0 {
		hours = netEventStatsDefaultHours
	}
	if hours > netEventStatsMaxHours {
		hours = netEventStatsMaxHours
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// base rebuilds the filtered query fresh on every call for the same reason
	// ListNetEvents does: GORM chain methods mutate the statement in place, so a
	// shared base would leak one series' GROUP BY into the next. The ts bound is
	// always present (partition/index pruning); the device/site filters narrow
	// through the (device_id, ts) index.
	base := func() *gorm.DB {
		q := d.db.Table("net_events").Where("ts >= ?", cutoff)
		if f.DeviceID != 0 {
			q = q.Where("device_id = ?", f.DeviceID)
		}
		// net_events has no site_id column; a site filter narrows by the devices
		// assigned to that site (the IN (subquery) form ListNetEvents uses).
		if f.SiteID != 0 {
			q = q.Where("device_id IN (?)", d.db.Model(&models.Device{}).Where("site_id = ?", f.SiteID).Select("id"))
		}
		return q
	}

	res := &NetEventStatsResult{}

	// The eleven series run with bounded concurrency. Sequentially they cost
	// ~60 s on a 7-day production window (each is its own partition-pruned
	// scan); four at a time keeps the wait inside the response timeout without
	// letting one page load drain the connection pool — the same bound the
	// Flows page uses. Each goroutine writes only its own slice, and `res` is
	// assembled on this goroutine after the wait, so nothing is shared.
	//
	// geo_src / geo_dst: hits and bytes by country, ordered by hits. No LIMIT —
	// there are at most ~250 ISO-3166 codes, far fewer than the ranking cards'
	// budget, so capping them would only hide a long tail of small countries.
	var (
		geoSrc       []NetEventGeoStat
		geoDst       []NetEventGeoStat
		identity     []NetEventIdentityStat
		users        []KeyCount
		apps         []KeyCount
		appCats      []KeyCount
		webCats      []KeyCount
		dns          []KeyCount
		nat          []NetEventNATStat
		policyHourly []NetEventHourStat
		denyHourly   []NetEventHourStat
		firstErr     error
		errOnce      sync.Once
	)
	jobs := []func() error{
		func() error {
			if err := base().
				Select("src_country AS country, COUNT(*) AS hits, " + netEventStatByteSums).
				Where("src_country IS NOT NULL AND src_country <> ''").
				Group("src_country").Order("hits DESC").
				Scan(&geoSrc).Error; err != nil {
				return fmt.Errorf("geo_src: %w", err)
			}
			return nil
		},
		func() error {
			if err := base().
				Select("dst_country AS country, COUNT(*) AS hits, " + netEventStatByteSums).
				Where("dst_country IS NOT NULL AND dst_country <> ''").
				Group("dst_country").Order("hits DESC").
				Scan(&geoDst).Error; err != nil {
				return fmt.Errorf("geo_dst: %w", err)
			}
			return nil
		},
		func() error {
			// identity: the top (src_ip, src_mac) pairs by hits. src_ip is an
			// inet column on Postgres, so it is grouped through CastText (the
			// rollup reader's convention) and only rows with a source IP are
			// kept; a missing MAC reads as '' (an identity without a
			// vendor-supplied MAC is still an identity).
			if err := base().
				Select(d.dialect.CastText("src_ip") + " AS src_ip, COALESCE(" + d.dialect.CastText("src_mac") + ", '') AS src_mac, COUNT(*) AS hits").
				Where("src_ip IS NOT NULL").
				Group("src_ip, src_mac").Order("hits DESC").Limit(netEventStatsTopN).
				Scan(&identity).Error; err != nil {
				return fmt.Errorf("identity: %w", err)
			}
			return nil
		},
		func() error {
			var err error
			users, err = netEventStatKeyCount(base, "user_name", "users")
			return err
		},
		func() error {
			var err error
			apps, err = netEventStatKeyCount(base, "app", "apps")
			return err
		},
		func() error {
			var err error
			appCats, err = netEventStatKeyCount(base, "app_cat", "app_categories")
			return err
		},
		func() error {
			var err error
			webCats, err = netEventStatKeyCount(base, "web_cat", "web_categories")
			return err
		},
		func() error {
			var err error
			dns, err = netEventStatKeyCount(base, "dns_qname", "dns")
			return err
		},
		func() error {
			// nat: the top (nat_src_ip, nat_dst_ip) translated-flow pairs by
			// hits. The NAT columns are inet too, so the same CastText
			// grouping keeps the wire shape a plain string on both dialects;
			// only rows with a translated source are kept.
			if err := base().
				Select(d.dialect.CastText("nat_src_ip") + " AS src_ip, COALESCE(" + d.dialect.CastText("nat_dst_ip") + ", '') AS dst_ip, COUNT(*) AS hits").
				Where("nat_src_ip IS NOT NULL").
				Group("nat_src_ip, nat_dst_ip").Order("hits DESC").Limit(netEventStatsTopN).
				Scan(&nat).Error; err != nil {
				return fmt.Errorf("nat: %w", err)
			}
			return nil
		},
		func() error {
			// Only the sub-day range pills consume these hourly series; a
			// long-window caller would pay two extra raw scans for a chart it
			// never renders. The UI never asks for them above 24 h.
			if hours > 24 {
				return nil
			}
			bucket := d.dialect.TimeBucket("hour", "ts")
			if err := base().
				Select(bucket + " AS hour, CAST(COUNT(*) AS BIGINT) AS hits, " + netEventStatByteSums).
				Group(bucket).Order("hour ASC").
				Scan(&policyHourly).Error; err != nil {
				return fmt.Errorf("policy_bytes_hourly: %w", err)
			}
			return nil
		},
		func() error {
			if hours > 24 {
				return nil
			}
			bucket := d.dialect.TimeBucket("hour", "ts")
			if err := base().
				Select(bucket+" AS hour, CAST(COUNT(*) AS BIGINT) AS hits, "+netEventStatByteSums).
				Where("action IN ?", []int16{int16(normalize.ActionDeny), int16(normalize.ActionReject)}).
				Group(bucket).Order("hour ASC").
				Scan(&denyHourly).Error; err != nil {
				return fmt.Errorf("deny_hourly: %w", err)
			}
			return nil
		},
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, run := range jobs {
		wg.Add(1)
		go func(run func() error) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := run(); err != nil {
				errOnce.Do(func() { firstErr = err })
			}
		}(run)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	res.GeoSrc = geoSrc
	res.GeoDst = geoDst
	res.Identity = identity
	res.Users = users
	res.Apps = apps
	res.AppCategories = appCats
	res.WebCategories = webCats
	res.DNS = dns
	res.NAT = nat
	res.PolicyBytesHourly = policyHourly
	res.DenyHourly = denyHourly

	// Normalize nil (no-rows) series to empty slices so the wire shape is []
	// rather than null — the UI maps each series without a null guard.
	if res.GeoSrc == nil {
		res.GeoSrc = []NetEventGeoStat{}
	}
	if res.GeoDst == nil {
		res.GeoDst = []NetEventGeoStat{}
	}
	if res.Identity == nil {
		res.Identity = []NetEventIdentityStat{}
	}
	if res.Users == nil {
		res.Users = []KeyCount{}
	}
	if res.Apps == nil {
		res.Apps = []KeyCount{}
	}
	if res.AppCategories == nil {
		res.AppCategories = []KeyCount{}
	}
	if res.WebCategories == nil {
		res.WebCategories = []KeyCount{}
	}
	if res.DNS == nil {
		res.DNS = []KeyCount{}
	}
	if res.NAT == nil {
		res.NAT = []NetEventNATStat{}
	}
	if res.PolicyBytesHourly == nil {
		res.PolicyBytesHourly = []NetEventHourStat{}
	}
	if res.DenyHourly == nil {
		res.DenyHourly = []NetEventHourStat{}
	}

	return res, nil
}

// ---------------------------------------------------------------------------
// sec_events — class-scoped analytics (Phase 2, PR 6)
// ---------------------------------------------------------------------------

// The Security tab's analytics. The net_events readers (PR 4/5) group the
// network half of the Events page; this one groups the security half, one
// series per class over the raw sec_events table. Every class has a per-day
// trend (the ts column bucketed to a UTC day, the same TimeBucket("day") the
// rollup writer uses) plus top-N rankings over that class's own columns —
// findings by signature, auth by admin user/source IP, config changes by
// path/admin user, VPN sessions by tunnel/peer, and WAN health per day per WAN
// with the average and latest gauge value. Each query is `ts >= cutoff`
// bounded so the monthly RANGE partitions prune and the existing
// (class, ts) / (device_id, ts) / (ts) indexes serve the class, window and
// device/site narrowing — no index or migration is added. The window is
// expressed in days (day-folding, like the rollup reader) or hours (short
// window, like NetEventStats): Days wins when both are set.

const (
	// secEventStatsDefaultDays is the day-window SecEventStats uses when the
	// filter names neither a day nor an hour window; secEventStatsMaxDays is
	// the day ceiling (one year — matching the rollup reader's). The day
	// granularity is the natural default: the trends are day-bucketed and
	// config_change rows are retained forever.
	secEventStatsDefaultDays = 30
	secEventStatsMaxDays     = 365
	// secEventStatsDefaultHours / secEventStatsMaxHours are the hour-window
	// equivalents (default 24, ceiling 720 — the raw table's short TTL), used
	// only when the filter names Hours but not Days.
	secEventStatsDefaultHours = 24
	secEventStatsMaxHours     = 720
	// secEventStatsTopN bounds each ranking (top signatures, admin users,
	// source IPs, config paths, config admins, tunnels, tunnel peers). The
	// charts cannot show an unbounded ranking, and past a handful nothing is
	// readable.
	secEventStatsTopN = 10
)

// SecEventStatsFilter constrains a SecEventStats query. The lookback window is
// named in Days (1..365, day-folding) or Hours (1..720); Days wins when both
// are non-zero, and a filter with neither falls back to the 30-day default.
// DeviceID and SiteID of 0 mean "no filter" — a device id of 0 is never a real
// row (PKs start at 1), and a site filter narrows by the devices assigned to
// that site (sec_events has no site_id column).
type SecEventStatsFilter struct {
	Days     int
	Hours    int
	DeviceID uint
	SiteID   uint
}

// SecEventDayCount is one UTC day's count for a class — a point on that
// class's trend chart. Day is "YYYY-MM-DD" (the dialect's TimeBucket("day")
// output), so the wire form is dialect-independent and lexicographic order is
// chronological order.
type SecEventDayCount struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

// SecEventFindingStat is one signature's aggregate over the window — a row of
// the "top signatures" card. Severity is the worst (max) severity seen for the
// signature, so the card ranks by count but still surfaces how severe the
// signature is (0 = "not stated").
type SecEventFindingStat struct {
	SigName  string `json:"sig_name"`
	Severity int16  `json:"severity"`
	Count    int64  `json:"count"`
}

// SecEventWanHealth is one WAN's health reading for one UTC day: the average
// and latest metric_value (a gauge such as latency or loss) over the day. The
// latest is the value at the day's newest ts — not the peak, which MAX would
// report.
type SecEventWanHealth struct {
	Day     string  `json:"day"`
	WanName string  `json:"wan_name"`
	Avg     float64 `json:"avg"`
	Last    float64 `json:"last"`
}

// SecEventStatsResult is the class-scoped analytics payload for the Security
// tab. Each class contributes a day-bucketed trend (Findings, AdminLogins,
// ConfigChanges, VPNSessions) ordered oldest-first, plus its top-N rankings
// ordered by count descending; WanHealth is per (day, WAN) ordered by day then
// WAN. The rankings skip empty/NULL groups and every top-N carries a LIMIT.
type SecEventStatsResult struct {
	Findings        []SecEventDayCount    `json:"findings"`
	TopSignatures   []SecEventFindingStat `json:"top_signatures"`
	AdminLogins     []SecEventDayCount    `json:"admin_logins"`
	TopAdminUsers   []KeyCount            `json:"top_admin_users"`
	TopAdminSrcIPs  []KeyCount            `json:"top_admin_src_ips"`
	ConfigChanges   []SecEventDayCount    `json:"config_changes"`
	TopConfigPaths  []KeyCount            `json:"top_config_paths"`
	TopConfigAdmins []KeyCount            `json:"top_config_admins"`
	VPNSessions     []SecEventDayCount    `json:"vpn_sessions"`
	TopTunnels      []KeyCount            `json:"top_tunnels"`
	TopTunnelPeers  []KeyCount            `json:"top_tunnel_peers"`
	WanHealth       []SecEventWanHealth   `json:"wan_health"`
}

// secEventDayCounts runs one class's per-day trend: COUNT(*) grouped by the
// dialect's UTC-day bucket over the `ts >= cutoff` bound, oldest-first.
func secEventDayCounts(base func(int16) *gorm.DB, dayExpr string, class int16) ([]SecEventDayCount, error) {
	var out []SecEventDayCount
	if err := base(class).
		Select(dayExpr + " AS day, COUNT(*) AS count").
		Group("day").Order("day ASC").
		Scan(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// secEventKeyCount runs one class's key-count ranking over a free-text column
// (admin_user / sig_name / config_path / config_obj / tunnel_name): COUNT(*)
// grouped by the column, empty/NULL values skipped, top-N kept.
func secEventKeyCount(base func(int16) *gorm.DB, class int16, column string) ([]KeyCount, error) {
	var out []KeyCount
	if err := base(class).
		Select(column + " AS key, COUNT(*) AS count").
		Where(column + " IS NOT NULL AND " + column + " <> ''").
		Group(column).Order("count DESC").Limit(secEventStatsTopN).
		Scan(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// secEventInetKeyCount is secEventKeyCount for an inet column (admin_src_ip /
// tunnel_peer): it groups through CastText so the wire shape is a plain string
// on both dialects (the rollup reader's convention), and only NULLs are
// skipped — an inet column never carries the empty string the text columns do.
func (d *Database) secEventInetKeyCount(base func(int16) *gorm.DB, class int16, column string) ([]KeyCount, error) {
	var out []KeyCount
	if err := base(class).
		Select(d.dialect.CastText(column) + " AS key, COUNT(*) AS count").
		Where(column + " IS NOT NULL").
		Group(column).Order("count DESC").Limit(secEventStatsTopN).
		Scan(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// SecEventStats computes the class-scoped series over the raw sec_events table.
// The queries share one base filter per class (built fresh on every call, so
// the series can never drift), and each is `ts >= cutoff` bounded so the
// monthly partitions prune. The top-N LIMITs keep each ranking small, and the
// bounded default (30 days) keeps the GROUP BYs cheap; the hour window is the
// caller's explicit choice (the handler caps hours at 720).
func (d *Database) SecEventStats(f SecEventStatsFilter) (*SecEventStatsResult, error) {
	// Resolve the window: a day window (folds to UTC midnight, like the rollup
	// reader) wins over an hour window, and neither names a default of 30 days.
	var cutoff time.Time
	if f.Days > 0 {
		days := f.Days
		if days > secEventStatsMaxDays {
			days = secEventStatsMaxDays
		}
		cutoff = utcDay(time.Now()).AddDate(0, 0, -(days - 1))
	} else {
		hours := f.Hours
		if hours <= 0 {
			hours = secEventStatsDefaultHours
		}
		if hours > secEventStatsMaxHours {
			hours = secEventStatsMaxHours
		}
		cutoff = time.Now().Add(-time.Duration(hours) * time.Hour)
	}

	// base rebuilds the class-scoped, ts-bounded query fresh on every call for
	// the same reason ListNetEvents does: GORM chain methods mutate the
	// statement in place, so a shared base would leak one series' GROUP BY into
	// the next. The ts bound is always present (partition pruning) and the class
	// filter rides the (class, ts) index; the device/site filters narrow through
	// the (device_id, ts) index.
	base := func(class int16) *gorm.DB {
		q := d.db.Table("sec_events").Where("class = ?", class).Where("ts >= ?", cutoff)
		if f.DeviceID != 0 {
			q = q.Where("device_id = ?", f.DeviceID)
		}
		// sec_events has no site_id column; a site filter narrows by the devices
		// assigned to that site (the IN (subquery) form ListSecEvents uses).
		if f.SiteID != 0 {
			q = q.Where("device_id IN (?)", d.db.Model(&models.Device{}).Where("site_id = ?", f.SiteID).Select("id"))
		}
		return q
	}

	day := d.dialect.TimeBucket("day", "ts")

	res := &SecEventStatsResult{}
	var err error

	// findings: per-day counts and the top signatures (with their worst
	// severity). sig_name is free text; empty/NULL is skipped by both series.
	if res.Findings, err = secEventDayCounts(base, day, int16(normalize.ClassFinding)); err != nil {
		return nil, fmt.Errorf("findings trend: %w", err)
	}
	var findings []SecEventFindingStat
	if err := base(int16(normalize.ClassFinding)).
		Select("sig_name, COALESCE(MAX(severity), 0) AS severity, COUNT(*) AS count").
		Where("sig_name IS NOT NULL AND sig_name <> ''").
		Group("sig_name").Order("count DESC").Limit(secEventStatsTopN).
		Scan(&findings).Error; err != nil {
		return nil, fmt.Errorf("top signatures: %w", err)
	}
	res.TopSignatures = findings

	// admin_logins (auth): per-day counts, top admin users and top admin
	// source IPs (admin_src_ip is inet, so it groups through CastText).
	if res.AdminLogins, err = secEventDayCounts(base, day, int16(normalize.ClassAuth)); err != nil {
		return nil, fmt.Errorf("admin logins trend: %w", err)
	}
	if res.TopAdminUsers, err = secEventKeyCount(base, int16(normalize.ClassAuth), "admin_user"); err != nil {
		return nil, fmt.Errorf("top admin users: %w", err)
	}
	if res.TopAdminSrcIPs, err = d.secEventInetKeyCount(base, int16(normalize.ClassAuth), "admin_src_ip"); err != nil {
		return nil, fmt.Errorf("top admin source IPs: %w", err)
	}

	// config_changes: per-day counts, top config paths and top admin users
	// (who changed what).
	if res.ConfigChanges, err = secEventDayCounts(base, day, int16(normalize.ClassConfigChange)); err != nil {
		return nil, fmt.Errorf("config changes trend: %w", err)
	}
	if res.TopConfigPaths, err = secEventKeyCount(base, int16(normalize.ClassConfigChange), "config_path"); err != nil {
		return nil, fmt.Errorf("top config paths: %w", err)
	}
	if res.TopConfigAdmins, err = secEventKeyCount(base, int16(normalize.ClassConfigChange), "admin_user"); err != nil {
		return nil, fmt.Errorf("top config admins: %w", err)
	}

	// vpn_sessions: per-day counts, top tunnels and top tunnel peers
	// (tunnel_peer is inet, so it groups through CastText).
	if res.VPNSessions, err = secEventDayCounts(base, day, int16(normalize.ClassVPNSession)); err != nil {
		return nil, fmt.Errorf("vpn sessions trend: %w", err)
	}
	if res.TopTunnels, err = secEventKeyCount(base, int16(normalize.ClassVPNSession), "tunnel_name"); err != nil {
		return nil, fmt.Errorf("top tunnels: %w", err)
	}
	if res.TopTunnelPeers, err = d.secEventInetKeyCount(base, int16(normalize.ClassVPNSession), "tunnel_peer"); err != nil {
		return nil, fmt.Errorf("top tunnel peers: %w", err)
	}

	// wan_health: per day per WAN name, the average and latest metric_value.
	// The "latest" is the value at the day's newest ts — a window function over
	// the raw rows (before grouping) is the only portable way to get it, since
	// MAX(metric_value) would report the peak, not the latest reading.
	wanInner := base(int16(normalize.ClassDeviceHealth)).
		Select(day + " AS day, wan_name, metric_value AS v, " +
			"FIRST_VALUE(metric_value) OVER (PARTITION BY " + day + ", wan_name ORDER BY ts DESC) AS last_v").
		Where("wan_name IS NOT NULL AND wan_name <> ''").
		Where("metric_value IS NOT NULL")
	var wan []SecEventWanHealth
	if err := d.db.Table("(?) AS t", wanInner).
		Select("day, wan_name, AVG(v) AS avg, MAX(last_v) AS last").
		Group("day, wan_name").Order("day ASC, wan_name ASC").
		Scan(&wan).Error; err != nil {
		return nil, fmt.Errorf("wan health: %w", err)
	}
	res.WanHealth = wan

	// Normalize nil (no-rows) series to empty slices so the wire shape is []
	// rather than null — the UI maps each series without a null guard.
	if res.Findings == nil {
		res.Findings = []SecEventDayCount{}
	}
	if res.TopSignatures == nil {
		res.TopSignatures = []SecEventFindingStat{}
	}
	if res.AdminLogins == nil {
		res.AdminLogins = []SecEventDayCount{}
	}
	if res.TopAdminUsers == nil {
		res.TopAdminUsers = []KeyCount{}
	}
	if res.TopAdminSrcIPs == nil {
		res.TopAdminSrcIPs = []KeyCount{}
	}
	if res.ConfigChanges == nil {
		res.ConfigChanges = []SecEventDayCount{}
	}
	if res.TopConfigPaths == nil {
		res.TopConfigPaths = []KeyCount{}
	}
	if res.TopConfigAdmins == nil {
		res.TopConfigAdmins = []KeyCount{}
	}
	if res.VPNSessions == nil {
		res.VPNSessions = []SecEventDayCount{}
	}
	if res.TopTunnels == nil {
		res.TopTunnels = []KeyCount{}
	}
	if res.TopTunnelPeers == nil {
		res.TopTunnelPeers = []KeyCount{}
	}
	if res.WanHealth == nil {
		res.WanHealth = []SecEventWanHealth{}
	}

	return res, nil
}
