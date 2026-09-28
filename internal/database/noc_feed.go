package database

import (
	"fmt"
	"sync"
	"time"

	"firewall-mon/internal/models"
)

// NOC live feed (v0.11.269). The NOC page's ticker shows alerts and flow
// detections as they arrive. It is built once per hub tick and shared by every
// viewer, so the server sends each kind as its own capped list and the browser
// merges, filters and slices them: a single merged cap would let detections
// (about 100 per alert on production) crowd every alert out.
const (
	nocFeedAlertWindow     = 7 * 24 * time.Hour
	nocFeedAlertLimit      = 100
	nocFeedDetectionWindow = 6 * time.Hour
	nocFeedDetectionLimit  = 100
	nocFeedSilencedLimit   = 50

	// nocEpisodeGapMinutes splits one dedup key's rows into episodes. The
	// detector re-inserts every active finding each 5-minute cycle, so a gap
	// longer than two cycles means the finding stopped and later started again.
	nocEpisodeGapMinutes = 12

	// nocDetectionGrace hides detections younger than this from the un-silenced
	// list. The poller inserts each finding un-acknowledged and un-linked, then
	// acknowledges the suppressed ones and links the alerted ones in the same
	// cycle; a hub tick inside that gap would otherwise flash the whole batch
	// into the feed for one frame. DetectedAt is stamped (UTC) when the detector
	// run ends, just before the inserts, so the grace also covers the run.
	nocDetectionGrace = 90 * time.Second

	// nocDetectionCacheTTL reuses the detection episode lists between hub
	// ticks. They change only on the 5-minute detector cycle, but grouping 6 h
	// of re-fires into episodes is window-function work (~40–120 ms on
	// production); alerts and the threat lists stay live every tick.
	nocDetectionCacheTTL = 60 * time.Second
)

// nocDetCache holds the last detection episode lists. A pointer on Database for
// the same reason as ingest: WithContext copies the struct, and every copy must
// share one cache. nil disables caching.
type nocDetCache struct {
	mu       sync.Mutex
	at       time.Time
	dets     []NOCFeedItem
	silenced []NOCFeedItem
	total    int
}

func newNOCDetCache() *nocDetCache { return &nocDetCache{} }

// detectionLists returns the live and silenced episode lists, recomputed at
// most every nocDetectionCacheTTL. The returned slices are copies the caller
// may modify.
func (d *Database) detectionLists(now time.Time) (dets, silenced []NOCFeedItem, total int, err error) {
	c := d.nocDetCache
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.at.IsZero() && now.Sub(c.at) >= 0 && now.Sub(c.at) < nocDetectionCacheTTL {
			return append([]NOCFeedItem(nil), c.dets...), append([]NOCFeedItem(nil), c.silenced...), c.total, nil
		}
	}
	windowStart := now.Add(-nocFeedDetectionWindow)
	if dets, _, err = d.detectionEpisodes(windowStart, now.Add(-nocDetectionGrace), false, nocFeedDetectionLimit); err != nil {
		return nil, nil, 0, fmt.Errorf("detections: %w", err)
	}
	if silenced, total, err = d.detectionEpisodes(windowStart, now, true, nocFeedSilencedLimit); err != nil {
		return nil, nil, 0, fmt.Errorf("silenced detections: %w", err)
	}
	if c != nil {
		c.at, c.dets, c.silenced, c.total = now, dets, silenced, total
		return append([]NOCFeedItem(nil), dets...), append([]NOCFeedItem(nil), silenced...), total, nil
	}
	return dets, silenced, total, nil
}

// nocNow is the clock the NOC feed and threat lists read; tests replace it.
var nocNow = time.Now

// NOCFeedItem is one row of the live feed: an alert, or one episode of a flow
// detection (consecutive re-fires of the same finding, collapsed).
type NOCFeedItem struct {
	Kind     string    `json:"kind"` // alert | detection
	DedupKey string    `json:"dedup_key,omitempty"`
	ID       uint      `json:"id"` // alert id, or the episode's newest detection row
	At       time.Time `json:"at"` // alert timestamp, or the episode's first row
	// Truncated marks an episode that was already running when the window
	// began: its first row is not in view, so "first seen" is older than At.
	Truncated bool      `json:"truncated,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
	Repeat    int       `json:"repeat"` // episode rows, or escalation_count+1 for an alert

	Severity   string `json:"severity"`
	Type       string `json:"type"` // alert_type, or the detector
	Category   string `json:"category,omitempty"`
	DeviceID   uint   `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	SiteName   string `json:"site_name,omitempty"`
	Src        string `json:"src,omitempty"`
	Dst        string `json:"dst,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
	Message    string `json:"message"`

	Acknowledged bool `json:"acknowledged"`
}

// NOCFeed is the live feed payload. GeneratedAt is filled in by the broadcaster
// after it has compared the lists with the previous frame, so an unchanged feed
// is not re-sent every tick.
type NOCFeed struct {
	GeneratedAt   time.Time     `json:"generated_at"`
	Alerts        []NOCFeedItem `json:"alerts"`
	Detections    []NOCFeedItem `json:"detections"`
	Silenced      []NOCFeedItem `json:"silenced"`
	SilencedTotal int           `json:"silenced_total"`
}

// GetNOCFeed builds the three feed lists. A failing list is returned empty with
// the error, so the caller can keep the last good feed.
func (d *Database) GetNOCFeed() (*NOCFeed, error) {
	now := nocNow().UTC()
	feed := &NOCFeed{Alerts: []NOCFeedItem{}, Detections: []NOCFeedItem{}, Silenced: []NOCFeedItem{}}

	var alerts []models.Alert
	if err := d.db.Where("suppressed = ? AND timestamp > ?", false, now.Add(-nocFeedAlertWindow)).
		Order("timestamp DESC, id DESC").Limit(nocFeedAlertLimit).Find(&alerts).Error; err != nil {
		return nil, fmt.Errorf("noc feed: alerts: %w", err)
	}

	dets, silenced, silencedTotal, err := d.detectionLists(now)
	if err != nil {
		return nil, fmt.Errorf("noc feed: %w", err)
	}
	feed.SilencedTotal = silencedTotal

	// One batched name lookup for both kinds.
	idset := map[uint]struct{}{}
	var siteIDs []uint
	for _, a := range alerts {
		if a.DeviceID != 0 {
			idset[a.DeviceID] = struct{}{}
		}
		if a.SiteID != nil {
			siteIDs = append(siteIDs, *a.SiteID)
		}
	}
	for _, list := range [][]NOCFeedItem{dets, silenced} {
		for _, it := range list {
			if it.DeviceID != 0 {
				idset[it.DeviceID] = struct{}{}
			}
		}
	}
	ids := make([]uint, 0, len(idset))
	for id := range idset {
		ids = append(ids, id)
	}
	devByID, siteName := deviceSiteNames(d.db, ids, siteIDs)
	name := func(it *NOCFeedItem, alertSite *uint) {
		if dv, ok := devByID[it.DeviceID]; ok {
			it.DeviceName = dv.Name
			if dv.SiteID != nil {
				it.SiteName = siteName[*dv.SiteID]
			}
		}
		if it.SiteName == "" && alertSite != nil {
			it.SiteName = siteName[*alertSite]
		}
	}

	for _, a := range alerts {
		it := NOCFeedItem{
			Kind: "alert", ID: a.ID, At: a.Timestamp.UTC(), LastSeen: a.Timestamp.UTC(),
			Repeat:   a.EscalationCount + 1,
			Severity: string(a.Severity), Type: string(a.AlertType),
			DeviceID: a.DeviceID, Src: a.SourceAddr, Message: a.Message,
			Acknowledged: a.Acknowledged,
		}
		name(&it, a.SiteID)
		feed.Alerts = append(feed.Alerts, it)
	}
	for i := range dets {
		name(&dets[i], nil)
	}
	for i := range silenced {
		name(&silenced[i], nil)
	}
	feed.Detections = append(feed.Detections, dets...)
	feed.Silenced = append(feed.Silenced, silenced...)
	return feed, nil
}

// detectionEpisodes groups un-alerted detections in [from, to) by dedup key
// into episodes — runs of rows no more than nocEpisodeGapMinutes apart — and
// returns the newest `limit` by first-seen time, plus the total episode count.
// acknowledged selects the silenced (true) or live (false) rows.
//
// The episode's first and newest rows are chosen by time (row ids need not
// follow detection time: a replayed or back-filled batch inserts out of order)
// and read back by id rather than scanned out of the aggregate, so their
// timestamps parse the same on both dialects.
func (d *Database) detectionEpisodes(from, to time.Time, acknowledged bool, limit int) ([]NOCFeedItem, int, error) {
	gap := d.dialect.MinutesBetween("detected_at", "prev_at")
	q := fmt.Sprintf(`
		SELECT dedup_key, first_id, newest_id, rows_n, COUNT(*) OVER () AS total
		FROM (
			SELECT dedup_key, ep, MIN(detected_at) AS first_at, MIN(first_id) AS first_id,
				MIN(newest_id) AS newest_id, COUNT(*) AS rows_n
			FROM (
				SELECT dedup_key, ep, detected_at,
					FIRST_VALUE(id) OVER (PARTITION BY dedup_key, ep ORDER BY detected_at, id) AS first_id,
					FIRST_VALUE(id) OVER (PARTITION BY dedup_key, ep ORDER BY detected_at DESC, id DESC) AS newest_id
				FROM (
			SELECT id, dedup_key, detected_at,
					SUM(is_start) OVER (PARTITION BY dedup_key ORDER BY detected_at, id ROWS UNBOUNDED PRECEDING) AS ep
				FROM (
					SELECT id, dedup_key, detected_at,
						CASE WHEN prev_at IS NULL OR %s > %d THEN 1 ELSE 0 END AS is_start
					FROM (
						SELECT id, dedup_key, detected_at,
							LAG(detected_at) OVER (PARTITION BY dedup_key ORDER BY detected_at, id) AS prev_at
						FROM flow_detections
						WHERE detected_at >= ? AND detected_at < ? AND alert_id IS NULL AND acknowledged = ?
					) AS lagged
				) AS starts
				) AS numbered
			) AS bounded
			GROUP BY dedup_key, ep
		) AS episodes
		ORDER BY first_at DESC, dedup_key ASC
		LIMIT ?`, gap, nocEpisodeGapMinutes)

	var rows []struct {
		DedupKey string
		FirstID  uint
		NewestID uint
		RowsN    int
		Total    int
	}
	if err := d.db.Raw(q, from.UTC(), to.UTC(), acknowledged, limit).Scan(&rows).Error; err != nil {
		return nil, 0, err
	}
	if len(rows) == 0 {
		return []NOCFeedItem{}, 0, nil
	}

	ids := make([]uint, 0, 2*len(rows))
	for _, r := range rows {
		ids = append(ids, r.FirstID, r.NewestID)
	}
	var dets []models.FlowDetection
	if err := d.db.Where("id IN ?", ids).Find(&dets).Error; err != nil {
		return nil, 0, err
	}
	byID := make(map[uint]*models.FlowDetection, len(dets))
	for i := range dets {
		byID[dets[i].ID] = &dets[i]
	}

	// An episode whose first in-window row sits within one gap of the window
	// start may have begun before the window: its true first sighting is out of
	// view. It is flagged, and the browser keys it on the dedup key alone, so it
	// does not re-key every cycle as its oldest rows age out.
	truncatedBefore := from.Add(nocEpisodeGapMinutes * time.Minute)
	items := make([]NOCFeedItem, 0, len(rows))
	for _, r := range rows {
		first, newest := byID[r.FirstID], byID[r.NewestID]
		if first == nil || newest == nil {
			continue // deleted by retention between the two reads
		}
		items = append(items, NOCFeedItem{
			Kind: "detection", DedupKey: r.DedupKey, ID: newest.ID,
			At: first.DetectedAt.UTC(), Truncated: !first.DetectedAt.After(truncatedBefore),
			LastSeen: newest.DetectedAt.UTC(), Repeat: r.RowsN,
			Severity: newest.Severity, Type: newest.Detector, Category: newest.Category,
			DeviceID: newest.DeviceID, Src: newest.SrcAddr, Dst: newest.DstAddr, DstPort: newest.DstPort,
			Message: newest.Message, Acknowledged: newest.Acknowledged,
		})
	}
	return items, rows[0].Total, nil
}
