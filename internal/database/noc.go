package database

import (
	"fmt"
	"sort"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// NOCSnapshot is a point-in-time view of recent flow activity for the real-time
// NOC dashboard. It is computed over a short trailing window (so throughput is
// "now", not an hourly average) and is cheap enough to recompute every few
// seconds by the broadcaster. Bytes are already sampling-scaled at ingest, so
// SUM(bytes)*8/window is an estimated bits/sec.
type NOCSnapshot struct {
	GeneratedAt   time.Time `json:"generated_at"`
	WindowSeconds int       `json:"window_seconds"`

	TotalFlows    int64   `json:"total_flows"`
	TotalBytes    uint64  `json:"total_bytes"`
	BitsPerSecond float64 `json:"bits_per_second"`
	UniqueSources int64   `json:"unique_sources"`
	UniqueDests   int64   `json:"unique_dests"`
	ThreatFlows   int64   `json:"threat_flows"` // flows in window touching a known-bad endpoint

	TopSources      []KeyCount `json:"top_sources"`
	TopDestinations []KeyCount `json:"top_destinations"`
	ByCategory      []KeyCount `json:"by_category"`  // Key = classify.Category id (string)
	ByDirection     []KeyCount `json:"by_direction"` // Key = classify.Dir* id (string)
	TopCountries    []KeyCount `json:"top_countries"`

	Detections []models.FlowDetection `json:"detections"` // recent, most-severe first

	ProbesOnline      int   `json:"probes_online"`
	ProbesOffline     int   `json:"probes_offline"`
	DevicesOnline     int   `json:"devices_online"`
	DevicesOffline    int   `json:"devices_offline"`
	ActiveThreatIntel int64 `json:"active_threat_intel"`

	// Sites is the per-site → per-device health breakdown powering the NOC
	// page's site grid. Populated only on the unfiltered fleet snapshot (the
	// hub broadcast); a filtered drill-down snapshot leaves it nil.
	Sites []SiteBreakdown `json:"sites,omitempty"`
}

// NOCFilter narrows a snapshot to a single site or device for the NOC drill-down
// panel. Both fields nil = the fleet-wide snapshot (what the hub broadcasts).
type NOCFilter struct {
	SiteID   *uint
	DeviceID *uint
}

// DeviceRow is one device inside a SiteBreakdown. WorstSeverity is the composite
// issue level ("", info, warning, critical) = max(open-alert severity, device
// offline→warning, a down connection→warning).
type DeviceRow struct {
	ID            uint      `json:"id"`
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	Status        string    `json:"status"`
	WorstSeverity string    `json:"worst_severity"`
	BitsPerSecond float64   `json:"bits_per_second"`
	LastPolled    time.Time `json:"last_polled"`
}

// SiteBreakdown is one site's rolled-up health. SiteID nil = the synthetic
// "Unassigned" bucket (devices with no site, or a site_id pointing at a deleted
// site). WorstSeverity additionally folds in probe-offline (→critical).
type SiteBreakdown struct {
	SiteID         *uint       `json:"site_id"`
	SiteName       string      `json:"site_name"`
	WorstSeverity  string      `json:"worst_severity"`
	DevicesOnline  int         `json:"devices_online"`
	DevicesOffline int         `json:"devices_offline"`
	AlertsCritical int         `json:"alerts_critical"`
	AlertsWarning  int         `json:"alerts_warning"`
	ProbeOffline   bool        `json:"probe_offline"`
	BitsPerSecond  float64     `json:"bits_per_second"`
	TotalBytes     uint64      `json:"total_bytes"`
	ThreatFlows    int64       `json:"threat_flows"`
	Devices        []DeviceRow `json:"devices"`
}

// NOC "Live Detections" feed window/limit. A 15-minute window left the feed almost
// always empty: ~90% of detections escalate to alerts (excluded here by design) and
// the un-alerted remainder averages only a few per hour, so nearly every 15-minute
// window had zero rows. A 6h window keeps the feed live and populated without
// overwhelming it (the Flows-page detections card uses the same 24h-class lookback).
const (
	nocDetectionsWindow = 6 * time.Hour
	nocDetectionsLimit  = 30
)

// GetNOCSnapshot computes the fleet-wide NOCSnapshot over the trailing window
// (what the hub broadcasts to every viewer). It includes the per-site breakdown.
func (d *Database) GetNOCSnapshot(window time.Duration) (*NOCSnapshot, error) {
	return d.GetNOCSnapshotFiltered(window, NOCFilter{})
}

// GetNOCSnapshotFiltered computes a NOCSnapshot, optionally narrowed to a single
// site or device for the NOC drill-down. All flow aggregates are bounded (top-N)
// and run against the raw flow_samples indexes. Errors on optional sub-queries
// are tolerated (the field stays zero) so a single failing aggregate doesn't
// blank the whole dashboard. In filtered mode the fleet-only fields (detections,
// probe counts, threat-intel, Sites) are omitted so a drill-down never shows
// unrelated fleet data; the device online/offline counts are scoped to the filter.
func (d *Database) GetNOCSnapshotFiltered(window time.Duration, filter NOCFilter) (*NOCSnapshot, error) {
	if window <= 0 {
		window = 5 * time.Minute
	}
	secs := window.Seconds()
	cutoff := time.Now().Add(-window)
	filtered := filter.SiteID != nil || filter.DeviceID != nil
	snap := &NOCSnapshot{
		GeneratedAt:   time.Now().UTC(),
		WindowSeconds: int(secs),
	}

	base := func() *gorm.DB {
		q := d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff)
		switch {
		case filter.DeviceID != nil:
			q = q.Where("device_id = ?", *filter.DeviceID)
		case filter.SiteID != nil:
			q = q.Where("device_id IN (SELECT id FROM devices WHERE site_id = ?)", *filter.SiteID)
		}
		return q
	}

	var agg struct {
		Flows  int64
		Bytes  uint64
		Srcs   int64
		Dsts   int64
		Threat int64
	}
	// M10 of the 2026-07-01 audit: the core aggregate's error MUST propagate.
	// Pre-fix every .Error in this function was discarded and it always
	// returned (snap, nil), so during a DB failure (statement_timeout on the
	// COUNT(DISTINCT), transient outage) the hub broadcast an all-zero
	// snapshot — overwriting the last good one — while the dashboard badge
	// said "live". The handlers' keep-last-good/500 branches were dead code.
	if err := base().Select("COUNT(*) as flows, COALESCE(SUM(bytes),0) as bytes, COUNT(DISTINCT src_addr) as srcs, COUNT(DISTINCT dst_addr) as dsts, COALESCE(SUM(CASE WHEN threat_flag <> 0 THEN 1 ELSE 0 END),0) as threat").
		Scan(&agg).Error; err != nil {
		return nil, fmt.Errorf("noc snapshot: core flow aggregate: %w", err)
	}
	snap.TotalFlows = agg.Flows
	snap.TotalBytes = agg.Bytes
	snap.UniqueSources = agg.Srcs
	snap.UniqueDests = agg.Dsts
	snap.ThreatFlows = agg.Threat
	if secs > 0 {
		snap.BitsPerSecond = float64(agg.Bytes) * 8 / secs
	}

	snap.TopSources = topAddrsByBytes(base, "src_addr", 8)
	snap.TopDestinations = topAddrsByBytes(base, "dst_addr", 8)
	snap.ByCategory = groupCountKey(base, "app_category", 8)
	snap.ByDirection = groupCountKey(base, "direction", 6)

	// Top destination countries (geo enrichment) — skip blanks.
	{
		type row struct {
			C     string
			Total int64
		}
		var rows []row
		base().Where("dst_country <> ''").
			Select("dst_country as c, SUM(bytes) as total").
			Group("dst_country").Order("total DESC").Limit(8).Scan(&rows)
		snap.TopCountries = make([]KeyCount, 0, len(rows))
		for _, r := range rows {
			snap.TopCountries = append(snap.TopCountries, KeyCount{Key: r.C, Count: r.Total})
		}
	}

	// Device online/offline counts, scoped to the filter.
	{
		q := d.db.Model(&models.Device{})
		switch {
		case filter.DeviceID != nil:
			q = q.Where("id = ?", *filter.DeviceID)
		case filter.SiteID != nil:
			q = q.Where("site_id = ?", *filter.SiteID)
		}
		type sc struct {
			Status string
			Cnt    int
		}
		var scs []sc
		// M10: device online/offline counts are core dashboard state — a
		// failure here must not render as "0 devices".
		if err := q.Select("status, COUNT(*) as cnt").Group("status").Scan(&scs).Error; err != nil {
			return nil, fmt.Errorf("noc snapshot: device status counts: %w", err)
		}
		for _, s := range scs {
			if s.Status == "online" || s.Status == "up" {
				snap.DevicesOnline += s.Cnt
			} else {
				snap.DevicesOffline += s.Cnt
			}
		}
	}

	// Fleet-only signals: detections, probe counts, threat-intel, and the site
	// breakdown. Omitted on a filtered drill-down.
	if !filtered {
		if dets, err := d.GetRecentDetections(time.Now().Add(-nocDetectionsWindow), nocDetectionsLimit, false, false); err == nil {
			snap.Detections = dets
		}
		if probes, err := d.GetAllProbes(); err == nil {
			for _, p := range probes {
				if p.Status == "online" {
					snap.ProbesOnline++
				} else {
					snap.ProbesOffline++
				}
			}
		}
		snap.ActiveThreatIntel, _ = d.CountActiveThreatIntel()
		// M10: the site grid is the NOC's primary surface — a device-query
		// failure must not render as "No sites or devices yet".
		sites, err := d.buildSiteBreakdown(cutoff, secs)
		if err != nil {
			return nil, fmt.Errorf("noc snapshot: site breakdown: %w", err)
		}
		snap.Sites = sites
	}

	return snap, nil
}

// sevRank ranks the composite issue severity so worst-of comparisons are cheap.
func sevRank(s string) int {
	switch s {
	case string(models.SeverityCritical):
		return 3
	case string(models.SeverityWarning):
		return 2
	case string(models.SeverityInfo):
		return 1
	default:
		return 0
	}
}

// worseSev returns whichever of a/b is the more severe ("" = none).
func worseSev(a, b string) string {
	if sevRank(b) > sevRank(a) {
		return b
	}
	return a
}

// deviceOnline reports whether a device status string counts as up.
func deviceOnline(status string) bool { return status == "online" || status == "up" }

// openAlertsQuery scopes to alerts that are actually surfaced to the operator —
// the SAME predicate the Alerts list uses (unresolved, not suppressed, not
// acknowledged, not currently snoozed). The NOC badges and the map node colours
// both derive from this so they can never disagree.
func (d *Database) openAlertsQuery() *gorm.DB {
	return d.db.Model(&models.Alert{}).
		Where("resolved_at IS NULL AND suppressed = ? AND acknowledged = ? AND (snoozed_until IS NULL OR snoozed_until < ?)",
			false, false, time.Now())
}

// GetDeviceAlertSeverities returns the worst open-alert severity per device
// (device_id → "info"|"warning"|"critical"). Devices with no open alert are
// absent from the map. Feeds the connection map's node pulse; device offline and
// down connections are already reflected on the map by the border/edge colour,
// so this intentionally carries only the alert overlay.
func (d *Database) GetDeviceAlertSeverities() (map[uint]string, error) {
	type row struct {
		DeviceID uint
		Severity string
	}
	var rows []row
	if err := d.openAlertsQuery().
		Select("device_id, severity").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]string, len(rows))
	for _, r := range rows {
		out[r.DeviceID] = worseSev(out[r.DeviceID], r.Severity)
	}
	return out, nil
}

// buildSiteBreakdown rolls per-device health up into per-site cards for the NOC
// grid. It runs a fixed, small set of grouped queries (one flow scan, one alert
// scan, plus device/probe/connection lists) and composes the result in Go — no
// per-device N+1 and no extra flow_samples scan beyond the one the snapshot
// already does. Any sub-query error degrades to zero for that dimension.
func (d *Database) buildSiteBreakdown(cutoff time.Time, secs float64) ([]SiteBreakdown, error) {
	// Device rows (lightweight: no preloads).
	devs, err := d.GetDeviceStatusRows()
	if err != nil {
		// M10: swallowing this rendered "No sites or devices yet" on a live
		// fleet during any DB hiccup.
		return nil, err
	}

	// Valid site ids + names (so an orphaned site_id falls into Unassigned).
	siteName := map[uint]string{}
	if sites, err := d.GetAllSites(); err == nil {
		for _, s := range sites {
			siteName[s.ID] = s.Name
		}
	}

	// Per-device flow bytes + threat flows over the window (single grouped scan).
	flowByDev := map[uint]struct {
		Bytes  uint64
		Threat int64
	}{}
	{
		type fr struct {
			DeviceID uint
			Bytes    uint64
			Threat   int64
		}
		var rows []fr
		d.db.Model(&models.FlowSample{}).Where("timestamp > ?", cutoff).
			Select("device_id, COALESCE(SUM(bytes),0) as bytes, COALESCE(SUM(CASE WHEN threat_flag <> 0 THEN 1 ELSE 0 END),0) as threat").
			Group("device_id").Scan(&rows)
		for _, r := range rows {
			flowByDev[r.DeviceID] = struct {
				Bytes  uint64
				Threat int64
			}{r.Bytes, r.Threat}
		}
	}

	// Per-device open-alert counts by severity (single grouped scan).
	type alertAgg struct {
		worst string
		crit  int
		warn  int
	}
	alertByDev := map[uint]*alertAgg{}
	{
		type ar struct {
			DeviceID uint
			Severity string
			Cnt      int
		}
		var rows []ar
		d.openAlertsQuery().Select("device_id, severity, COUNT(*) as cnt").
			Group("device_id, severity").Scan(&rows)
		for _, r := range rows {
			a := alertByDev[r.DeviceID]
			if a == nil {
				a = &alertAgg{}
				alertByDev[r.DeviceID] = a
			}
			a.worst = worseSev(a.worst, r.Severity)
			switch r.Severity {
			case string(models.SeverityCritical):
				a.crit += r.Cnt
			case string(models.SeverityWarning):
				a.warn += r.Cnt
			}
		}
	}

	// Devices touching a down connection → warning overlay.
	downConnDev := map[uint]bool{}
	if conns, err := d.GetAllConnections(); err == nil {
		for _, c := range conns {
			if c.Status == "down" {
				downConnDev[c.SourceDeviceID] = true
				downConnDev[c.DestDeviceID] = true
			}
		}
	}

	// Sites whose (enabled) probe is offline → critical overlay at the site level.
	probeOfflineSite := map[uint]bool{}
	if probes, err := d.GetAllProbes(); err == nil {
		for _, p := range probes {
			if p.Enabled && p.Status == "offline" {
				probeOfflineSite[p.SiteID] = true
			}
		}
	}

	// Bucket devices by site (nil key = Unassigned).
	buckets := map[uint]*SiteBreakdown{}
	var unassigned *SiteBreakdown
	getBucket := func(dev models.Device) *SiteBreakdown {
		if dev.SiteID != nil {
			if name, ok := siteName[*dev.SiteID]; ok {
				sb := buckets[*dev.SiteID]
				if sb == nil {
					id := *dev.SiteID
					sb = &SiteBreakdown{SiteID: &id, SiteName: name, ProbeOffline: probeOfflineSite[id]}
					buckets[id] = sb
				}
				return sb
			}
		}
		if unassigned == nil {
			unassigned = &SiteBreakdown{SiteName: "Unassigned"}
		}
		return unassigned
	}

	for _, dev := range devs {
		sb := getBucket(dev)
		online := deviceOnline(dev.Status)
		if online {
			sb.DevicesOnline++
		} else {
			sb.DevicesOffline++
		}

		// Composite per-device severity.
		sev := ""
		if a := alertByDev[dev.ID]; a != nil {
			sev = a.worst
			sb.AlertsCritical += a.crit
			sb.AlertsWarning += a.warn
		}
		if !online {
			sev = worseSev(sev, string(models.SeverityWarning))
		}
		if downConnDev[dev.ID] {
			sev = worseSev(sev, string(models.SeverityWarning))
		}

		bps := 0.0
		var bytes uint64
		if f, ok := flowByDev[dev.ID]; ok {
			bytes = f.Bytes
			if secs > 0 {
				bps = float64(f.Bytes) * 8 / secs
			}
			sb.ThreatFlows += f.Threat
		}
		sb.TotalBytes += bytes
		sb.BitsPerSecond += bps
		sb.WorstSeverity = worseSev(sb.WorstSeverity, sev)

		sb.Devices = append(sb.Devices, DeviceRow{
			ID: dev.ID, Name: dev.Name, IP: dev.IPAddress, Status: dev.Status,
			WorstSeverity: sev, BitsPerSecond: bps, LastPolled: dev.LastPolled,
		})
	}

	// Fold probe-offline (critical) into each affected site's worst severity.
	for id, sb := range buckets {
		if probeOfflineSite[id] {
			sb.WorstSeverity = worseSev(sb.WorstSeverity, string(models.SeverityCritical))
		}
	}

	// Assemble: real sites sorted by severity desc then name, Unassigned last.
	out := make([]SiteBreakdown, 0, len(buckets)+1)
	for _, sb := range buckets {
		out = append(out, *sb)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := sevRank(out[i].WorstSeverity), sevRank(out[j].WorstSeverity); ri != rj {
			return ri > rj
		}
		return out[i].SiteName < out[j].SiteName
	})
	if unassigned != nil {
		out = append(out, *unassigned)
	}
	return out, nil
}

// GetDeviceStatusRows returns the lightweight device fields the NOC breakdown
// needs (id, name, ip, status, site, last_polled) without preloads. Kept
// separate from GetDeviceStatuses (id+status only), which feeds hot paths.
func (d *Database) GetDeviceStatusRows() ([]models.Device, error) {
	var rows []models.Device
	err := d.db.Model(&models.Device{}).
		Select("id, name, ip_address, status, site_id, last_polled").
		Find(&rows).Error
	return rows, err
}

// groupCountKey returns the top-N values of a numeric column by flow count, with
// the numeric value rendered as the KeyCount.Key (the client maps id→label).
func groupCountKey(base func() *gorm.DB, col string, limit int) []KeyCount {
	type row struct {
		K     int64
		Total int64
	}
	var rows []row
	base().Select(col + " as k, COUNT(*) as total").Group(col).
		Order("total DESC").Limit(limit).Scan(&rows)
	out := make([]KeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyCount{Key: itoaInt64(r.K), Count: r.Total})
	}
	return out
}

func itoaInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	pos := len(b)
	for v > 0 {
		pos--
		b[pos] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
