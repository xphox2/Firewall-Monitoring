package report

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The weekly report's CPU/memory figures came from GetSystemStatusHistory,
// which returns the OLDEST 2,000 rows — about 31 hours at production's rate —
// so a peak later in the week never reached the report, and disk usage came
// from a 31-hour-old row.
func TestGatherDeviceData_WeeklyCPUCoversTheWholeWeek(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.9", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	to := time.Now()
	from := to.Add(-168 * time.Hour)
	rows := make([]models.SystemStatus, 0, 2600)
	for i := 0; i < 2600; i++ {
		cpu := 10.0
		if i == 2400 { // day 6
			cpu = 97
		}
		rows = append(rows, models.SystemStatus{DeviceID: dev.ID, Timestamp: from.Add(time.Duration(i)*230*time.Second + time.Minute), CPUUsage: cpu, MemoryUsage: 40, DiskUsage: float64(i), SessionCount: i})
	}
	if err := db.Gorm().CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatal(err)
	}
	d := GatherDeviceData(db, dev, 168, 60, 0, 0)
	if d.CPUMax != 97 {
		t.Fatalf("CPUMax = %v, want the day-6 peak 97", d.CPUMax)
	}
	if d.DiskUsage != 2599 || d.SessionCount != 2599 {
		t.Fatalf("disk/sessions = %v/%d, want the newest row's 2599", d.DiskUsage, d.SessionCount)
	}
	if d.MemAvg != 40 {
		t.Fatalf("MemAvg = %v, want 40", d.MemAvg)
	}
}

func TestGatherDeviceData_NoStatusRowsLeavesZero(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.9", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	d := GatherDeviceData(db, dev, 168, 60, 0, 0)
	if d.CPUAvg != 0 || d.CPUMax != 0 || d.MemAvg != 0 || d.DiskUsage != 0 || d.SessionCount != 0 {
		t.Fatalf("empty window gave %+v, want zeros", d)
	}
}
