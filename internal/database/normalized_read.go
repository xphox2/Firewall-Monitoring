package database

import (
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Readers for the v72 normalized network-event table (Phase 2, PR 1). This is
// the first read path over net_events: the admin Events page. It lists rows
// newest-first over a bounded time window with device/probe/site/activity/
// action filters and paging. The filters are deliberately the ones the table's
// existing indexes can serve — ts for the window (which prunes the daily
// partitions on Postgres), device_id for the device/site filters — and no
// src/dst/rule-key filter, because migration v80 dropped those three indexes
// (net_event_index_trim.go) after their one reader moved to net_event_rollups.
// A later PR adds those filters back together with the indexes that justify
// them.

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
// Hours is the lookback window in hours and is always > 0 (the handler derives
// it from httputil.ParseHours, default 24); ListNetEvents coerces a non-
// positive Hours to 24 so the query is never unbounded.
type NetEventFilter struct {
	DeviceID uint
	ProbeID  uint
	SiteID   uint
	Activity *int16
	Action   *int16
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
