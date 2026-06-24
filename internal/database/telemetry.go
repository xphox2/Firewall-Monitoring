package database

import (
	"errors"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (d *Database) SaveSystemStatus(status *models.SystemStatus) error {
	return d.db.Create(status).Error
}

// SaveSystemStatuses batch-inserts a slice of system-status rows in a single
// statement, instead of one Create per row (M4 of the 2026-06-23 audit) — the
// ingestion handler accepts up to 100 rows per request. Mirrors the other
// high-volume batch savers (SaveInterfaceStats, SaveFlowSamples, …).
func (d *Database) SaveSystemStatuses(statuses []models.SystemStatus) error {
	if len(statuses) == 0 {
		return nil
	}
	return d.db.Create(&statuses).Error
}

func (d *Database) GetSystemStatus(limit int) ([]models.SystemStatus, error) {
	var statuses []models.SystemStatus
	err := d.db.Order("timestamp DESC").Limit(limit).Find(&statuses).Error
	return statuses, err
}

func (d *Database) SaveInterfaceStats(stats []models.InterfaceStats) error {
	if len(stats) == 0 {
		return nil
	}
	return d.db.Create(&stats).Error
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
	if len(statuses) == 0 {
		return nil
	}
	return d.db.Create(&statuses).Error
}

func (d *Database) GetLatestVPNStatuses(deviceID uint) ([]models.VPNStatus, error) {
	var latest models.VPNStatus
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latest).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []models.VPNStatus{}, nil
		}
		return nil, err
	}
	var statuses []models.VPNStatus
	err := d.db.Where("device_id = ? AND timestamp = ?", deviceID, latest.Timestamp).Find(&statuses).Error
	if err != nil || len(statuses) == 0 {
		return statuses, err
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
		var peerVPNs []models.VPNStatus
		d.db.Where("device_id IN ? AND (local_subnet != '' OR remote_subnet != '')", ids).
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
	type lastUpRow struct {
		TunnelName string    `gorm:"column:tunnel_name"`
		MaxTs      time.Time `gorm:"column:max_ts"`
	}
	var rows []lastUpRow
	if err := d.db.Model(&models.VPNStatus{}).
		Select("tunnel_name, MAX(timestamp) as max_ts").
		Where("device_id = ? AND status = ?", deviceID, "up").
		Group("tunnel_name").
		Scan(&rows).Error; err == nil {
		byName := make(map[string]time.Time, len(rows))
		for _, r := range rows {
			byName[r.TunnelName] = r.MaxTs
		}
		for i := range statuses {
			if ts, ok := byName[statuses[i].TunnelName]; ok {
				t := ts
				statuses[i].LastUpAt = &t
			}
		}
	}

	return statuses, err
}

// GetAllLatestVPNStatuses returns the latest VPN tunnel snapshot for every device.
func (d *Database) GetAllLatestVPNStatuses() ([]models.VPNStatus, error) {
	var statuses []models.VPNStatus
	// Subquery: max timestamp per device
	sub := d.db.Model(&models.VPNStatus{}).Select("device_id, MAX(timestamp) as max_ts").Group("device_id")
	err := d.db.Where("(device_id, timestamp) IN (?)", sub).Find(&statuses).Error
	return statuses, err
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
