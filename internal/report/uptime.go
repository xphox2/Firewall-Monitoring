package report

import (
	"time"

	"firewall-mon/internal/database"
)

// UptimeResult holds the calculated uptime for a device.
type UptimeResult struct {
	Percent     float64 // e.g. 99.9900
	DaysTracked int     // how many days of data we have
	MaxDays     int     // requested window (e.g. 30)
}

// CalculateDeviceUptime derives uptime from system_status row density.
// successfulPolls / expectedPolls * 100
// pollIntervalSec is the configured poll interval in seconds.
func CalculateDeviceUptime(db *database.Database, deviceID uint, days int, pollIntervalSec int) (*UptimeResult, error) {
	if pollIntervalSec <= 0 {
		pollIntervalSec = 60
	}

	firstPoll, err := db.GetDeviceFirstPoll(deviceID)
	if err != nil {
		return nil, err
	}
	if firstPoll.IsZero() {
		return &UptimeResult{Percent: 0, DaysTracked: 0, MaxDays: days}, nil
	}

	now := time.Now()
	windowStart := now.Add(-time.Duration(days) * 24 * time.Hour)

	// If the device was first seen after our window start, narrow the window
	since := windowStart
	if firstPoll.After(windowStart) {
		since = firstPoll
	}

	daysTracked := int(now.Sub(since).Hours() / 24)
	if daysTracked < 1 {
		daysTracked = 1
	}
	if daysTracked > days {
		daysTracked = days
	}

	pollCount, err := db.GetDevicePollCount(deviceID, since)
	if err != nil {
		return nil, err
	}

	totalSeconds := now.Sub(since).Seconds()
	expectedPolls := totalSeconds / float64(pollIntervalSec)
	if expectedPolls < 1 {
		expectedPolls = 1
	}

	percent := (float64(pollCount) / expectedPolls) * 100
	if percent > 100 {
		percent = 100
	}

	return &UptimeResult{
		Percent:     percent,
		DaysTracked: daysTracked,
		MaxDays:     days,
	}, nil
}
