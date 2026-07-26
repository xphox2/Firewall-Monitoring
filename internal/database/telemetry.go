package database

import (
	"errors"
	"log"
	"time"

	"firewall-mon/internal/l2infer"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// VPN evidence freshness windows, deliberately the SAME values the L2 link
// staircase uses (l2infer.FreshWindow / GraceWindow) so both edge families on
// the connection map age at one cadence and one amber "stale" state means the
// same thing regardless of which detector produced the edge.
//
// Fresh (≤30m) → the tunnel's real up/down status. Between fresh and grace → the
// connection is held with status "stale" rather than trusted or deleted. Past
// grace (>3h) → not state at all: invisible to every reader here, so the poller
// stops re-stamping last_check and the existing CleanupStaleAutoConnectionsBefore
// sweep reaps the row.
//
// 30m is not arbitrary: VPN rows arrive from two writers at different cadences
// (SNMP ~60s, FortiGate SSH at SSHPollInterval, default 900s). A tighter window —
// e.g. the alert path's 3×PollInterval / 5-minute floor — would mark every
// SSH-fed tunnel stale for two thirds of every interval and flap the map.
const (
	VPNEvidenceFresh = l2infer.FreshWindow
	VPNEvidenceGrace = l2infer.GraceWindow
)

// vpnZoneSlack widens the SQL-side lower bound so it can only ever be too
// generous, never too strict.
//
// SQLite stores a timestamp as TEXT in whatever zone it was written with —
// "…T12:24:58-04:00" vs "…T16:24:58Z" for the same instant — and compares it
// lexicographically, so a bound in one zone silently mis-filters rows written in
// another. The collector stamps rows with local time, so this is real. Postgres
// (timestamptz) normalizes and is unaffected, but the query must be correct on
// both dialects.
//
// So SQL only PRUNES (keeping the partition scan bounded, which is why the bound
// exists at all) and the exact horizon is applied in Go, where comparison is
// instant-based and zone-proof.
//
// The slack must cover the worst-case WALL-CLOCK SPREAD between the bound and a
// row — not the largest absolute offset. The bound is always built from
// time.Now().UTC() (offset 0), so a row can trail it by at most the most western
// real offset, UTC-12; 24h clears that with a wide margin. Building the bound
// from local time instead would make the worst case 14 - (-12) = 26h and this
// constant too small — which is why the UTC() call at each use site is load
// bearing, not cosmetic.
const vpnZoneSlack = 24 * time.Hour

// withinVPNGrace drops rows outside the evidence horizon. This — not the SQL
// bound — is the authoritative gate; see vpnZoneSlack.
func withinVPNGrace(in []models.VPNStatus, now time.Time) []models.VPNStatus {
	out := in[:0]
	for _, s := range in {
		if now.Sub(s.Timestamp) <= VPNEvidenceGrace {
			out = append(out, s)
		}
	}
	return out
}

func (d *Database) SaveSystemStatus(status *models.SystemStatus) error {
	return d.db.Create(status).Error
}

// SaveSystemStatuses batch-inserts a slice of system-status rows in a single
// statement, instead of one Create per row (M4 of the 2026-06-23 audit) — the
// ingestion handler accepts up to 100 rows per request. Mirrors the other
// high-volume batch savers (SaveInterfaceStats, SaveFlowSamples, …).
func (d *Database) SaveSystemStatuses(statuses []models.SystemStatus) error {
	return batchInsertWithFallback(d.db, "system_status", statuses)
}

func (d *Database) GetSystemStatus(limit int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&statuses).Error
	return statuses, err
}

func (d *Database) SaveInterfaceStats(stats []models.InterfaceStats) error {
	return batchInsertWithFallback(d.db, "interface_stats", stats)
}

func (d *Database) GetInterfaceStats(limit int) ([]models.InterfaceStats, error) {
	var stats []models.InterfaceStats
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&stats).Error
	return stats, err
}

func (d *Database) SaveInterfaceAddresses(addrs []models.InterfaceAddress) error {
	if len(addrs) == 0 {
		return nil
	}
	// AUDIT-030: pre-fix this was a plain `Create` that appended
	// a row on every probe poll, even when the (device_id,
	// ip_address) pair was unchanged. With 50 devices × 4
	// polls/min × 90 days that's ~25M rows of mostly-redundant
	// data — the table grew unbounded.
	//
	// The fix is a portable UPSERT: GORM's `clause.OnConflict`
	// emits `INSERT ... ON CONFLICT (device_id, ip_address) DO
	// UPDATE SET ...` on Postgres, and the equivalent UPSERT
	// syntax on SQLite. The unique index `idx_ifaddr_dev_ip`
	// (declared on the InterfaceAddress model) is the conflict
	// target. We update `timestamp` (so the row reflects the
	// most recent poll), `if_index` (in case the IP moved
	// interfaces), and `net_mask` (in case the subnet was
	// reconfigured). The `id` field is left alone — GORM handles
	// the insert-vs-update distinction via the conflict clause.
	//
	// Operators who relied on the historical "this device had
	// this IP at this time" view (e.g. for forensics) will see
	// only the latest state. The intent of the table is current-
	// state, not history — historical IP data was always
	// effectively a time series, and the audit's "rows: 25M"
	// estimate showed that the original design was unusable at
	// scale. The proper historical view belongs in a separate
	// audit-log table if/when it's needed.
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "device_id"}, {Name: "ip_address"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"timestamp", "if_index", "net_mask",
		}),
	}).Create(&addrs).Error
}

// GetLatestInterfaceAddresses returns the latest interface address snapshot per device.
func (d *Database) GetLatestInterfaceAddresses() ([]models.InterfaceAddress, error) {
	var addrs []models.InterfaceAddress
	err := d.db.Raw(`
		SELECT a.* FROM interface_addresses a
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
		ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts
	`).Scan(&addrs).Error
	return addrs, err
}

// GetAllLatestInterfaces returns the latest interface stats snapshot across all devices.
func (d *Database) GetAllLatestInterfaces() ([]models.InterfaceStats, error) {
	var ifaces []models.InterfaceStats
	err := d.db.Raw(`
		SELECT i.* FROM interface_stats i
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
		ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts
	`).Scan(&ifaces).Error
	return ifaces, err
}

// GetAllLatestSystemStatuses returns the latest system_status row per device,
// considering only rows newer than since. The bound is applied in SQL — not
// post-filtered — so the MAX(timestamp) scan stays inside recent partitions
// and a long-dead device's ancient rows are never fetched at all. Used by the
// poller's checkRelayedTelemetry pass (v0.11.74) as its freshness gate.
func (d *Database) GetAllLatestSystemStatuses(since time.Time) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	err := d.db.Raw(`
		SELECT s.* FROM system_status s
		INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM system_status WHERE timestamp > ? GROUP BY device_id) latest
		ON s.device_id = latest.device_id AND s.timestamp = latest.max_ts
		WHERE s.timestamp > ?
	`, since, since).Scan(&statuses).Error
	return statuses, err
}

func (d *Database) GetLatestSystemStatus() (*models.SystemStatus, error) {
	var status models.SystemStatus
	err := d.db.Order("timestamp DESC").First(&status).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (d *Database) GetLatestInterfaceStats() ([]models.InterfaceStats, error) {
	// Get the most recent timestamp
	var latest models.InterfaceStats
	if err := d.db.Order("timestamp DESC").First(&latest).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	// Get all interfaces from that timestamp
	var stats []models.InterfaceStats
	err := d.db.Where("timestamp = ?", latest.Timestamp).Find(&stats).Error
	return stats, err
}

func (d *Database) SaveVPNStatuses(statuses []models.VPNStatus) error {
	return batchInsertWithFallback(d.db, "vpn_status", statuses)
}

// GetLatestVPNStatuses returns a device's current tunnels: the newest row per
// tunnel_name that is still within the evidence horizon (see vpnLatestSubquery).
// Tunnels the device has stopped reporting age out; tunnels on a slower writer
// are no longer masked by a faster one.
//
// Two of the three enrichment passes below are bounded too, and for different
// reasons. LastUpAt reads unbounded history on purpose: "when was this last up"
// is a historical annotation of a current tunnel, and the answer is only useful
// when it IS old. The peer read that feeds subnet cross-fill and RemoteDeviceID
// is bounded to the evidence horizon, because its cost grew with retention
// rather than with tunnel count, and because a peer row older than the horizon
// is one this same function would refuse to return as that peer's own state —
// enriching from it would launder aged-out data back in as current.
//
// The consequence is deliberate: if a peer stops reporting for longer than the
// horizon while this device keeps reporting, its rows lose the peer's subnets
// and the peer-device deep-link, rather than showing a stale pairing.
func (d *Database) GetLatestVPNStatuses(deviceID uint) ([]models.VPNStatus, error) {
	now := time.Now()
	// UTC: see vpnZoneSlack — a local-zone bound widens the worst case past the slack.
	prune := now.UTC().Add(-VPNEvidenceGrace - vpnZoneSlack)
	var statuses []models.VPNStatus
	err := d.db.Where("device_id = ? AND timestamp >= ? AND (tunnel_name, timestamp) IN (?)",
		deviceID, prune, vpnLatestSubquery(d.db, deviceID, prune)).
		Find(&statuses).Error
	if err == nil {
		statuses = withinVPNGrace(statuses, now)
	}
	if err != nil {
		return nil, err
	}
	if len(statuses) == 0 {
		return []models.VPNStatus{}, nil
	}

	// Cross-fill Phase 2 subnets from peer devices
	// Find connections involving this device
	var connections []models.DeviceConnection
	d.db.Where("source_device_id = ? OR dest_device_id = ?", deviceID, deviceID).Find(&connections)

	// Get all peer device IDs
	peerIDs := make(map[uint]bool)
	for _, conn := range connections {
		if conn.SourceDeviceID != deviceID {
			peerIDs[conn.SourceDeviceID] = true
		}
		if conn.DestDeviceID != deviceID {
			peerIDs[conn.DestDeviceID] = true
		}
	}

	// Pre-fetch all peer tunnels indexed by remote IP (more reliable than name matching)
	// A tunnel on device A with RemoteIP=X matched to device B means device B likely has
	// a tunnel with RemoteIP pointing back to A. Match by IP, not name.
	peerTunnelsByRemoteIP := make(map[string]models.VPNStatus) // remoteIP -> latest tunnel with subnets
	// AUDIT-035: previously this ran one `WHERE device_id = ? ORDER BY
	// timestamp DESC` full scan PER peer (e.g. 30 peers = 30 scans per
	// connection-map click). Now a single `device_id IN (...)` query covering
	// all peers, with the subnet filter pushed into SQL (the loop already
	// skipped rows without a subnet, so this also fetches fewer rows than the
	// original). `ORDER BY device_id, timestamp DESC` reproduces the original
	// per-peer / newest-first processing order, so the "first row per remote_ip,
	// preferring one that carries a LocalSubnet" result is unchanged — and more
	// deterministic than before (the old peer loop iterated a Go map in random
	// order). Cross-dialect; no window function required.
	if len(peerIDs) > 0 {
		ids := make([]uint, 0, len(peerIDs))
		for id := range peerIDs {
			ids = append(ids, id)
		}
		// Bounded to the evidence horizon, like every other read in this file.
		//
		// Without the bound this reads the ENTIRE history of every peer that
		// carries subnet text, just to keep the newest row per remote_ip — so its
		// cost grows with RETENTION rather than with tunnel count. Measured on a
		// seeded database, one chart request went 5ms → 81ms → 324ms at 300 →
		// 5,000 → 20,000 rows per peer, and production retains far more than
		// that. The page issues several such calls every 30 seconds per viewer.
		//
		// This is a bug fix rather than a semantic change: cross-filling from a
		// peer row older than the grace window means enriching a "latest status"
		// with data the rest of this file has already declared not to be state.
		// The only rows it stops using are ones no other reader here would trust.
		peerPrune := time.Now().UTC().Add(-VPNEvidenceGrace - vpnZoneSlack)
		var peerVPNs []models.VPNStatus
		d.db.Where("device_id IN ? AND timestamp >= ? AND (local_subnet != '' OR remote_subnet != '')", ids, peerPrune).
			Order("device_id, timestamp DESC").Find(&peerVPNs)
		for _, pv := range peerVPNs {
			if pv.RemoteIP == "" {
				continue
			}
			existing, exists := peerTunnelsByRemoteIP[pv.RemoteIP]
			if !exists || (pv.LocalSubnet != "" && existing.LocalSubnet == "") {
				peerTunnelsByRemoteIP[pv.RemoteIP] = pv
			}
		}
	}

	// Collect this device's known IPs for matching
	deviceIPSet := make(map[uint]map[string]bool)
	for _, s := range statuses {
		if _, ok := deviceIPSet[s.DeviceID]; !ok {
			deviceIPSet[s.DeviceID] = make(map[string]bool)
			var dev models.Device
			if err := d.db.Select("ip_address").First(&dev, s.DeviceID).Error; err == nil {
				deviceIPSet[s.DeviceID][dev.IPAddress] = true
			}
		}
	}

	// Cross-fill: for each tunnel missing subnets, find a peer tunnel whose RemoteIP matches our device
	for i := range statuses {
		if statuses[i].LocalSubnet == "" || statuses[i].RemoteSubnet == "" {
			// Try matching by our device's IPs against peer tunnels' RemoteIP
			myIPs := deviceIPSet[statuses[i].DeviceID]
			var peerTunnel *models.VPNStatus
			for ip := range myIPs {
				if pt, ok := peerTunnelsByRemoteIP[ip]; ok {
					peerTunnel = &pt
					break
				}
			}
			// Also try matching by this tunnel's RemoteIP
			if peerTunnel == nil && statuses[i].RemoteIP != "" {
				if pt, ok := peerTunnelsByRemoteIP[statuses[i].RemoteIP]; ok {
					peerTunnel = &pt
				}
			}
			if peerTunnel != nil {
				if statuses[i].LocalSubnet == "" && peerTunnel.LocalSubnet != "" {
					statuses[i].LocalSubnet = peerTunnel.LocalSubnet
				}
				if statuses[i].RemoteSubnet == "" && peerTunnel.RemoteSubnet != "" {
					statuses[i].RemoteSubnet = peerTunnel.RemoteSubnet
				}
				// Surface the resolved peer device id (v0.10.218, bundle G3).
				// Frontend uses this to link the remote_ip cell to the peer's
				// /admin/devices/:id detail page.
				if peerTunnel.DeviceID != 0 && peerTunnel.DeviceID != statuses[i].DeviceID {
					pid := peerTunnel.DeviceID
					statuses[i].RemoteDeviceID = &pid
				}
			}
		}
	}

	// Second-pass peer resolution (v0.10.218, bundle G3). The block above
	// only populates RemoteDeviceID when a subnet cross-fill was needed.
	// Tunnels that already had complete subnet info skipped that path but
	// can still benefit from a peer link in the UI. Re-run the same match
	// logic for RemoteDeviceID only.
	for i := range statuses {
		if statuses[i].RemoteDeviceID != nil {
			continue
		}
		var peerTunnel *models.VPNStatus
		myIPs := deviceIPSet[statuses[i].DeviceID]
		for ip := range myIPs {
			if pt, ok := peerTunnelsByRemoteIP[ip]; ok {
				peerTunnel = &pt
				break
			}
		}
		if peerTunnel == nil && statuses[i].RemoteIP != "" {
			if pt, ok := peerTunnelsByRemoteIP[statuses[i].RemoteIP]; ok {
				peerTunnel = &pt
			}
		}
		if peerTunnel != nil && peerTunnel.DeviceID != 0 && peerTunnel.DeviceID != statuses[i].DeviceID {
			pid := peerTunnel.DeviceID
			statuses[i].RemoteDeviceID = &pid
		}
	}

	// last_up_at enrichment (v0.10.217, bundle D4). For every tunnel in
	// the latest snapshot, look up the most-recent historical timestamp
	// at which the same (device, tunnel_name) reported status='up'. Lets
	// the frontend show "last seen up 2h ago" for tunnels currently down
	// instead of just "down".
	//
	// Single grouped query rather than N per-tunnel queries — for a fleet
	// with 200 tunnels per device the difference is meaningful. Skipped
	// for tunnels that are currently up (LastUpAt would just equal the
	// snapshot timestamp anyway and the UI doesn't render the chip).
	// Scanned through database/sql rather than mapped into a struct: an aggregate
	// loses the column's declared type, so the SQLite driver returns
	// MAX(timestamp) as a string while Postgres returns time.Time, and GORM can
	// map neither into a portable field (time.Time rejects the string; `any` is
	// an unsupported field type). database/sql DOES support scanning into *any,
	// handing back the driver's native value, which coerceDBTime then normalizes.
	//
	// The previous code swallowed the resulting scan error with an `err == nil`
	// guard, so last_up_at silently never populated on SQLite.
	byName := make(map[string]time.Time)
	if rows, err := d.db.Model(&models.VPNStatus{}).
		Select("tunnel_name, MAX(timestamp) as max_ts").
		Where("device_id = ? AND status = ?", deviceID, "up").
		Group("tunnel_name").
		Rows(); err != nil {
		log.Printf("GetLatestVPNStatuses: last_up_at lookup for device %d failed: %v", deviceID, err)
	} else {
		for rows.Next() {
			var name string
			var raw any
			if serr := rows.Scan(&name, &raw); serr != nil {
				log.Printf("GetLatestVPNStatuses: last_up_at scan for device %d failed: %v", deviceID, serr)
				break
			}
			if ts, ok := coerceDBTime(raw); ok {
				byName[name] = ts
			}
		}
		if rerr := rows.Err(); rerr != nil {
			log.Printf("GetLatestVPNStatuses: last_up_at rows for device %d: %v", deviceID, rerr)
		}
		rows.Close()
	}
	d.ResolveTunnelGroups(statuses)
	for i := range statuses {
		if ts, ok := byName[statuses[i].TunnelName]; ok {
			t := ts
			statuses[i].LastUpAt = &t
		}
	}

	return statuses, err
}

// coerceDBTime converts an aggregate timestamp value into a time.Time. Postgres
// returns time.Time directly; SQLite returns the stored text, in one of a few
// layouts depending on how the row was written.
func coerceDBTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	case []byte:
		return coerceDBTime(string(t))
	case string:
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
		} {
			if ts, err := time.Parse(layout, t); err == nil {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

// GetAllLatestVPNStatuses returns the newest row for every tunnel still within
// the evidence horizon, across all devices. See the vpnLatestSubquery doc for
// why this is per-TUNNEL rather than per-device, and why the horizon lives in
// the query rather than at the call sites.
func (d *Database) GetAllLatestVPNStatuses() ([]models.VPNStatus, error) {
	now := time.Now()
	// UTC: see vpnZoneSlack — a local-zone bound widens the worst case past the slack.
	prune := now.UTC().Add(-VPNEvidenceGrace - vpnZoneSlack)
	var statuses []models.VPNStatus
	sub := d.db.Model(&models.VPNStatus{}).
		Select("device_id, tunnel_name, MAX(timestamp) as max_ts").
		Where("timestamp >= ?", prune).
		Group("device_id, tunnel_name")
	if err := d.db.Where("timestamp >= ? AND (device_id, tunnel_name, timestamp) IN (?)", prune, sub).
		Find(&statuses).Error; err != nil {
		return nil, err
	}
	return withinVPNGrace(statuses, now), nil
}

// GetVPNTunnelCounts returns the up and total tunnel counts for a device using
// the same horizon-bounded per-tunnel snapshot as the other readers, so a badge
// can never disagree with the device page about which tunnels exist.
//
// A tunnel whose state is neither up nor down (FortiGate reports "unknown" for a
// phase1 whose phase2 has no SA) counts toward total but not up — it is present
// on the device, just not carrying traffic.
func (d *Database) GetVPNTunnelCounts(deviceID uint) (up, total int, err error) {
	now := time.Now()
	// UTC: see vpnZoneSlack — a local-zone bound widens the worst case past the slack.
	prune := now.UTC().Add(-VPNEvidenceGrace - vpnZoneSlack)
	var statuses []models.VPNStatus
	if err = d.db.Select("status, timestamp").
		Where("device_id = ? AND timestamp >= ? AND (tunnel_name, timestamp) IN (?)",
			deviceID, prune, vpnLatestSubquery(d.db, deviceID, prune)).
		Find(&statuses).Error; err != nil {
		return 0, 0, err
	}
	for _, s := range withinVPNGrace(statuses, now) {
		total++
		if s.Status == "up" {
			up++
		}
	}
	return up, total, nil
}

// vpnLatestSubquery selects the newest timestamp per tunnel_name for one device
// within the evidence horizon.
//
// Per-TUNNEL, deliberately. The previous device-wide MAX(timestamp) assumed each
// collector batch is one complete atomic snapshot of the device. That is false
// whenever two writers report VPN state at different cadences — a FortiGate feeds
// both the ~60s SNMP path and the SSH path (SSHPollInterval, default 900s), so
// the slower writer's tunnels were permanently masked by the faster writer's
// newer rows and vanished from the UI while genuinely up.
//
// The horizon then does the other half: a tunnel that has stopped being reported
// altogether ages out instead of being served as current state forever. Together
// these fix opposite failures — one query used to resurrect deleted tunnels, the
// other buried live ones.
func vpnLatestSubquery(db *gorm.DB, deviceID uint, prune time.Time) *gorm.DB {
	return db.Model(&models.VPNStatus{}).
		Select("tunnel_name, MAX(timestamp) as max_ts").
		Where("device_id = ? AND timestamp >= ?", deviceID, prune).
		Group("tunnel_name")
}

// RecentHAFailover reports whether the device's HA cluster changed its active
// member (master serial) within the window — i.e. a failover happened recently.
// True when the ha_status history for the device holds two or more distinct
// non-empty master serials in the window. Used to classify a newly-observed SSH
// host key as an expected HA failover (member units have distinct host keys) vs
// a possible MITM. Returns false for non-HA devices (no ha_status rows) and on
// any query error, so the caller defaults to the more suspicious classification.
func (d *Database) RecentHAFailover(deviceID uint, window time.Duration) bool {
	if d.db == nil {
		return false
	}
	var distinct int64
	if err := d.db.Model(&models.HAStatus{}).
		Where("device_id = ? AND timestamp >= ? AND master_serial <> ''", deviceID, time.Now().Add(-window)).
		Distinct("master_serial").
		Count(&distinct).Error; err != nil {
		return false
	}
	return distinct >= 2
}
