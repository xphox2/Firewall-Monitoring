package main

import (
	"errors"
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// fakePollerSNMP is a deviceSNMP returning one canned record per metric type so
// a successful poll exercises every collect→stamp→save block in pollDevice.
type fakePollerSNMP struct{}

func (fakePollerSNMP) GetSystemStatus(...string) (*models.SystemStatus, error) {
	return &models.SystemStatus{CPUUsage: 30}, nil
}
func (fakePollerSNMP) GetInterfaceStats() ([]models.InterfaceStats, error) {
	return []models.InterfaceStats{{Name: "port1", Status: "up"}}, nil
}
func (fakePollerSNMP) GetInterfaceAddresses() ([]models.InterfaceAddress, error) {
	return []models.InterfaceAddress{{IPAddress: "10.0.0.1"}}, nil
}
func (fakePollerSNMP) GetAllVPNTunnels() ([]models.VPNStatus, int, int, error) {
	return []models.VPNStatus{{}}, 0, 0, nil
}
func (fakePollerSNMP) GetHardwareSensors(...string) ([]models.HardwareSensor, error) {
	return []models.HardwareSensor{{}}, nil
}
func (fakePollerSNMP) GetProcessorStats(...string) ([]models.ProcessorStats, error) {
	return []models.ProcessorStats{{}}, nil
}
func (fakePollerSNMP) Close() error { return nil }

func newTestPoller(t *testing.T, dial snmpDialer) (*Poller, *database.Database) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	p := &Poller{
		cfg:            &config.Config{}, // spike detection off, no alert manager
		db:             db,
		prevIfaceStats: make(map[string]*models.InterfaceStats),
		newSNMP:        dial,
	}
	return p, db
}

// TestPollDevice_SavesAllMetrics characterizes the happy path: each metric type
// the SNMP client returns is stamped and persisted, and the device is marked
// online. This is the safety net for the sendMetric/pollAndSave extraction.
func TestPollDevice_SavesAllMetrics(t *testing.T) {
	p, db := newTestPoller(t, func(*config.Config) (deviceSNMP, error) {
		return fakePollerSNMP{}, nil
	})

	dev := &models.Device{Name: "test", IPAddress: "1.2.3.4", SNMPPort: 161, SNMPCommunity: "public", SNMPVersion: "2c", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	p.pollDevice(dev)

	count := func(model any) int64 {
		t.Helper()
		var n int64
		if err := db.Gorm().Model(model).Where("device_id = ?", dev.ID).Count(&n).Error; err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	for _, c := range []struct {
		name  string
		model any
	}{
		{"system_status", &models.SystemStatus{}},
		{"interface_stats", &models.InterfaceStats{}},
		{"interface_addresses", &models.InterfaceAddress{}},
		{"vpn_status", &models.VPNStatus{}},
		{"hardware_sensors", &models.HardwareSensor{}},
		{"processor_stats", &models.ProcessorStats{}},
	} {
		if got := count(c.model); got != 1 {
			t.Errorf("%s: %d rows for device, want 1", c.name, got)
		}
	}

	if dev.Status != "online" {
		t.Errorf("device status = %q, want online", dev.Status)
	}
}

// TestPollDevice_ConnectFailureMarksOffline characterizes the connect-error
// path: the device is marked offline and nothing is persisted.
func TestPollDevice_ConnectFailureMarksOffline(t *testing.T) {
	p, db := newTestPoller(t, func(*config.Config) (deviceSNMP, error) {
		return nil, errors.New("connect refused")
	})

	dev := &models.Device{Name: "test", IPAddress: "1.2.3.4"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	p.pollDevice(dev)

	if dev.Status != "offline" {
		t.Errorf("device status = %q, want offline", dev.Status)
	}
	var n int64
	db.Gorm().Model(&models.SystemStatus{}).Count(&n)
	if n != 0 {
		t.Errorf("system_status rows = %d after connect failure, want 0", n)
	}
}
