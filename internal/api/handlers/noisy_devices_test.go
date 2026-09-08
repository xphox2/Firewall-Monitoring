package handlers

import (
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// noisyDevices was rewritten in v0.11.245 from a `GROUP BY device_id` over
// syslog_messages into a per-device correlated subquery driven from the devices
// table. The grouped form walked all 135M index entries because the only index
// carrying device_id has timestamp TRAILING, so the predicate could not bound
// the scan: 15,704ms reading 5.4GB on production, with one execution killed by
// the 30s statement_timeout.
//
// The rewrite puts a bound parameter inside Select(), alongside separate Where()
// arguments. That is a well-known GORM footgun — if the placeholders bind in the
// wrong order the query still RUNS and still returns plausible numbers, just the
// wrong ones. Hence a behavioural test rather than trusting the build.

// TestNoisyDevices_WindowIsActuallyApplied pins the binding. A mis-bound
// parameter would count every row ever (5 here) or none (0); only correct
// binding yields the 3 rows inside the window.
func TestNoisyDevices_WindowIsActuallyApplied(t *testing.T) {
	d := database.NewDatabaseForTesting(t)
	g := d.Gorm()

	for _, n := range []string{"loud", "silent"} {
		if err := g.Create(&models.Device{Name: n}).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}

	now := time.Now()
	rows := []models.SyslogMessage{
		{DeviceID: 1, Timestamp: now.Add(-time.Hour), Message: "in-window-1"},
		{DeviceID: 1, Timestamp: now.Add(-2 * time.Hour), Message: "in-window-2"},
		{DeviceID: 1, Timestamp: now.Add(-3 * time.Hour), Message: "in-window-3"},
		{DeviceID: 1, Timestamp: now.Add(-90 * 24 * time.Hour), Message: "ancient-1"},
		{DeviceID: 1, Timestamp: now.Add(-91 * 24 * time.Hour), Message: "ancient-2"},
	}
	for i := range rows {
		if err := g.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed syslog: %v", err)
		}
	}

	got := noisyDevices(g, 24, 10)
	if len(got) != 1 {
		t.Fatalf("got %d rows (%+v), want exactly 1", len(got), got)
	}
	if got[0].Syslog != 3 {
		t.Errorf("syslog count = %d, want 3. 5 means the time bound was not applied (the parameter bound to the "+
			"wrong placeholder); 0 means it was applied to the wrong column.", got[0].Syslog)
	}
}

// TestNoisyDevices_SkipsSilentDevices pins the second deliberate decision.
//
// The grouped form only ever produced rows for devices that actually had syslog.
// The rewrite returns a row per device INCLUDING zeros, so folding them in
// unfiltered would put silent devices on a "noisy devices" leaderboard with a
// total of 0. Production has 6 devices and the card's default limit is 10, so
// every device would appear.
func TestNoisyDevices_SkipsSilentDevices(t *testing.T) {
	d := database.NewDatabaseForTesting(t)
	g := d.Gorm()

	for _, n := range []string{"loud", "silent-1", "silent-2", "silent-3"} {
		if err := g.Create(&models.Device{Name: n}).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}
	if err := g.Create(&models.SyslogMessage{DeviceID: 1, Timestamp: time.Now().Add(-time.Hour), Message: "x"}).Error; err != nil {
		t.Fatalf("seed syslog: %v", err)
	}

	got := noisyDevices(g, 24, 10)
	if len(got) != 1 {
		t.Fatalf("got %d rows (%+v), want only the device with traffic — silent devices must not reach a noisy-device board", len(got), got)
	}
	if got[0].Name != "loud" {
		t.Errorf("name = %q, want \"loud\"", got[0].Name)
	}
}

// TestNoisyDevices_IncludesRetiredDevices pins the third: the driving scan must
// NOT be scoped to active devices. The existing name lookup is unscoped, so a
// retired device still producing syslog appears in today's leaderboard —
// production has exactly one. Excluding retired devices may be the better
// product behaviour, but it is a product decision and must not ride in on a
// performance fix.
func TestNoisyDevices_IncludesRetiredDevices(t *testing.T) {
	d := database.NewDatabaseForTesting(t)
	g := d.Gorm()

	retiredAt := time.Now().Add(-24 * time.Hour)
	if err := g.Create(&models.Device{Name: "retired-but-chatty", RetiredAt: &retiredAt}).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := g.Create(&models.SyslogMessage{DeviceID: 1, Timestamp: time.Now().Add(-time.Hour), Message: "x"}).Error; err != nil {
		t.Fatalf("seed syslog: %v", err)
	}

	got := noisyDevices(g, 24, 10)
	if len(got) != 1 {
		t.Fatalf("retired device dropped from the leaderboard (got %+v); the driving devices scan must not be scoped to active devices", got)
	}
}
