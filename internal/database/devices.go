package database

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

func (d *Database) GetAllDevices() ([]models.Device, error) {
	var devices []models.Device
	err := d.db.Preload("Site").Preload("Probe").Find(&devices).Error
	for i := range devices {
		d.DecryptDeviceSecrets(&devices[i])
	}
	return devices, err
}

func (d *Database) GetDevice(id uint) (*models.Device, error) {
	var device models.Device
	err := d.db.Preload("Site").Preload("Probe").First(&device, id).Error
	if err != nil {
		return nil, err
	}
	d.DecryptDeviceSecrets(&device)
	return &device, nil
}

// ResolveDeviceByIP finds a device ID by management IP or interface address.
func (d *Database) ResolveDeviceByIP(ip string) uint {
	// Check management IP first
	var device models.Device
	if err := d.db.Where("ip_address = ?", ip).Select("id").First(&device).Error; err == nil {
		return device.ID
	}
	// Check interface addresses
	var addr models.InterfaceAddress
	if err := d.db.Where("ip_address = ?", ip).Select("device_id").First(&addr).Error; err == nil {
		return addr.DeviceID
	}
	return 0
}

func (d *Database) CreateDevice(device *models.Device) error {
	d.EncryptDeviceSecrets(device)
	err := d.db.Create(device).Error
	// Decrypt back so the caller sees plaintext
	d.DecryptDeviceSecrets(device)
	if err != nil {
		return fmt.Errorf("create device: %w", err)
	}
	return nil
}

func (d *Database) UpdateDevice(device *models.Device) error {
	return d.db.Save(device).Error
}

// UpdateDeviceStatus performs a targeted update of only status and last_polled fields.
func (d *Database) UpdateDeviceStatus(id uint, status string, lastPolled time.Time) error {
	return d.db.Model(&models.Device{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":      status,
		"last_polled": lastPolled,
	}).Error
}

// UpdateDeviceSSLVPN updates SSL-VPN user/session counts for a device.
func (d *Database) UpdateDeviceSSLVPN(id uint, users, tunnels int) error {
	return d.db.Model(&models.Device{}).Where("id = ?", id).Updates(map[string]interface{}{
		"sslvpn_users":   users,
		"sslvpn_tunnels": tunnels,
	}).Error
}

// MarkStaleProbeDevicesOffline marks probe-assigned devices as "offline" if
// their last_polled timestamp is older than the given threshold, and returns
// the devices that transitioned online -> offline on this call.
//
// It returns the flipped devices (not just a count) so the caller can fire a
// DEVICE_OFFLINE alert + critical email per transition — the same notification
// path that updateDeviceStatus drives for directly-polled devices. The WHERE
// clause already restricts to rows currently `status = 'online'`, so the
// selected set IS the online->offline transition set: a device that is already
// offline is not re-selected, which keeps this to one alert per offline
// episode (recovery is handled by the poller calling CheckDeviceOnline on the
// devices that come back fresh).
//
// Implemented as SELECT-then-UPDATE rather than a bare UPDATE so the caller
// gets the affected rows; the two statements are not wrapped in a transaction
// because a probe device that flips back to online between them simply isn't
// alerted this cycle (the next cycle re-evaluates), which is the desired
// fail-safe — we would rather miss a flap than emit a spurious offline alert.
func (d *Database) MarkStaleProbeDevicesOffline(staleThreshold time.Time) ([]models.Device, error) {
	var stale []models.Device
	if err := d.db.
		Where("probe_id IS NOT NULL AND enabled = ? AND status = ? AND last_polled < ?", true, "online", staleThreshold).
		Find(&stale).Error; err != nil {
		return nil, err
	}
	if len(stale) == 0 {
		return nil, nil
	}
	ids := make([]uint, len(stale))
	for i := range stale {
		ids[i] = stale[i].ID
		stale[i].Status = "offline"
	}
	if err := d.db.Model(&models.Device{}).Where("id IN ?", ids).Update("status", "offline").Error; err != nil {
		return nil, err
	}
	return stale, nil
}

// DeleteDevice removes the device row and its user-drawn connection-map entries,
// but DELIBERATELY preserves all historical telemetry (system_status,
// interface_stats, vpn_status, ha_status, hardware_sensors, processor_stats,
// alerts, uptime_records, trap_events, device_tunnels, interface_addresses).
// Those rows are orphaned (their device_id no longer resolves) but kept, so the
// data is never destroyed just because a device was removed — matching how
// syslog/flow/ping rows already survive a device delete, and the project rule
// that telemetry is a running total. DeviceConnection IS removed: it is pure
// user-drawn map config that is meaningless once an endpoint device is gone.
func (d *Database) DeleteDevice(id uint) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("source_device_id = ? OR dest_device_id = ?", id, id).Delete(&models.DeviceConnection{}).Error; err != nil {
			return fmt.Errorf("delete device %d: delete connections: %w", id, err)
		}
		return tx.Delete(&models.Device{}, id).Error
	})
}

func (d *Database) GetAllConnections() ([]models.DeviceConnection, error) {
	var conns []models.DeviceConnection
	err := d.db.Preload("SourceDevice").Preload("DestDevice").Find(&conns).Error
	return conns, err
}

// GetConnectionStatuses returns only id and status for all connections (lightweight).
func (d *Database) GetConnectionStatuses() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := d.db.Model(&models.DeviceConnection{}).Select("id, status").Find(&results).Error
	return results, err
}

// GetDeviceStatuses returns only id and status for all devices (lightweight).
func (d *Database) GetDeviceStatuses() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := d.db.Model(&models.Device{}).Select("id, status").Find(&results).Error
	return results, err
}

// ConnectionEvent represents a unified event from alerts, traps, or syslog.
type ConnectionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "alert", "trap", "syslog"
	DeviceID  uint      `json:"device_id"`
	Severity  string    `json:"severity"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
}

// GetConnectionEvents returns correlated events (alerts, traps, syslog) for two devices.
func (d *Database) GetConnectionEvents(srcDeviceID, dstDeviceID uint, hours int) ([]ConnectionEvent, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	deviceIDs := []uint{srcDeviceID, dstDeviceID}
	var events []ConnectionEvent

	// Alerts
	var alerts []models.Alert
	d.db.Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(50).Find(&alerts)
	for _, a := range alerts {
		events = append(events, ConnectionEvent{
			Timestamp: a.Timestamp,
			Source:    "alert",
			DeviceID:  a.DeviceID,
			Severity:  a.Severity,
			Type:      a.AlertType,
			Message:   a.Message,
		})
	}

	// Traps
	var traps []models.TrapEvent
	d.db.Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(50).Find(&traps)
	for _, t := range traps {
		events = append(events, ConnectionEvent{
			Timestamp: t.Timestamp,
			Source:    "trap",
			DeviceID:  t.DeviceID,
			Severity:  t.Severity,
			Type:      t.TrapType,
			Message:   t.Message,
		})
	}

	// Syslog (severity <= 4 = warning and above)
	var syslogs []models.SyslogMessage
	d.db.Where("device_id IN ? AND severity <= 4 AND timestamp > ?", deviceIDs, cutoff).
		Order("timestamp DESC").Limit(30).Find(&syslogs)
	for _, s := range syslogs {
		sev := "info"
		if s.Severity <= 2 {
			sev = "critical"
		} else if s.Severity <= 4 {
			sev = "warning"
		}
		events = append(events, ConnectionEvent{
			Timestamp: s.Timestamp,
			Source:    "syslog",
			DeviceID:  s.DeviceID,
			Severity:  sev,
			Type:      "syslog",
			Message:   s.Message,
		})
	}

	// Sort by timestamp descending
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if len(events) > 100 {
		events = events[:100]
	}

	return events, nil
}

// FindConnectionByDevicePairAndType finds a connection between two devices of a specific type.
func (d *Database) FindConnectionByDevicePairAndType(deviceA, deviceB uint, connType string) (*models.DeviceConnection, error) {
	var conn models.DeviceConnection
	err := d.db.Where(
		"((source_device_id = ? AND dest_device_id = ?) OR (source_device_id = ? AND dest_device_id = ?)) AND connection_type = ?",
		deviceA, deviceB, deviceB, deviceA, connType,
	).First(&conn).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &conn, err
}

// UpsertAutoConnection creates or updates an auto-detected connection.
// Uses device pair + connection_type as the unique key, allowing multiple
// connection types between the same pair (e.g. ipsec + l2vlan).
// Manual connections (AutoDetected=false) are never overwritten.
func (d *Database) UpsertAutoConnection(sourceID, destID uint, status, tunnelNames, name, connType, matchMethod string) error {
	if connType == "" {
		connType = "ipsec"
	}
	if matchMethod == "" {
		matchMethod = "ip_match"
	}

	existing, err := d.FindConnectionByDevicePairAndType(sourceID, destID, connType)
	if err != nil {
		return fmt.Errorf("upsert auto connection: lookup existing pair: %w", err)
	}

	if existing != nil {
		if !existing.AutoDetected {
			return nil // don't touch manual connections
		}
		// Update existing auto-detected connection
		return d.db.Model(existing).Updates(map[string]interface{}{
			"status":          status,
			"tunnel_names":    tunnelNames,
			"connection_type": connType,
			"match_method":    matchMethod,
			"last_check":      time.Now(),
		}).Error
	}

	// Create new auto-detected connection with normalized direction
	conn := &models.DeviceConnection{
		Name:           name,
		SourceDeviceID: sourceID,
		DestDeviceID:   destID,
		ConnectionType: connType,
		Status:         status,
		AutoDetected:   true,
		TunnelNames:    tunnelNames,
		MatchMethod:    matchMethod,
		LastCheck:      time.Now(),
	}
	return d.db.Create(conn).Error
}

func (d *Database) CreateConnection(conn *models.DeviceConnection) error {
	return d.db.Create(conn).Error
}

func (d *Database) UpdateConnection(conn *models.DeviceConnection) error {
	return d.db.Save(conn).Error
}

func (d *Database) DeleteConnection(id uint) error {
	return d.db.Delete(&models.DeviceConnection{}, id).Error
}

// CleanupStaleAutoConnections removes auto-detected connections with tunnel names
// that should never have been matched (e.g., ssl.root present on every FortiGate).
func (d *Database) CleanupStaleAutoConnections(skipNames []string) int64 {
	if len(skipNames) == 0 {
		return 0
	}
	result := d.db.Where("auto_detected = ? AND tunnel_names IN ?", true, skipNames).
		Delete(&models.DeviceConnection{})
	return result.RowsAffected
}

// CleanupStaleAutoConnectionsBefore deletes auto-detected connections whose
// last_check is older than the given timestamp. Called after each detection
// cycle to remove connections whose interfaces no longer exist.
func (d *Database) CleanupStaleAutoConnectionsBefore(before time.Time) int64 {
	result := d.db.Where("auto_detected = ? AND last_check < ?", true, before).
		Delete(&models.DeviceConnection{})
	return result.RowsAffected
}
