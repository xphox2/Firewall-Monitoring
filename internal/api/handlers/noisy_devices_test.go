package handlers

import (
	"strings"
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
// The rewrite puts a bound parameter inside Select(), which is the interesting
// part: a time bound in a projection rather than in the WHERE clause. If it were
// ever dropped or rebound the query would still RUN and still return plausible
// numbers, just the wrong ones — no build or vet error, no panic. (As written
// the statement carries exactly one parameter, so ordering against WHERE args
// cannot currently go wrong; that is a property of today's code, not a guarantee,
// which is why the assertion is on the counts.)

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

	got := noisyDevices(g, 24, 10, nil)
	if len(got) != 1 {
		t.Fatalf("got %d rows (%+v), want exactly 1", len(got), got)
	}
	if got[0].Syslog != 3 {
		t.Errorf("syslog count = %d, want 3. 5 means the time bound was not applied at all; "+
			"0 means it landed on the wrong column.", got[0].Syslog)
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

	got := noisyDevices(g, 24, 10, nil)
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

	got := noisyDevices(g, 24, 10, nil)
	if len(got) != 1 {
		t.Fatalf("retired device dropped from the leaderboard (got %+v); the driving devices scan must not be scoped to active devices", got)
	}
}

// TestNoisyDevices_FailureMarksSnapshotPartial closes the gap that made the
// whole `partial` flag half-useless when it was first written.
//
// computeStatus exists because of ONE production incident: the noisy-devices
// scan was killed at 30,006ms by the statement timeout, and the dashboard then
// published an empty leaderboard that was indistinguishable from a genuinely
// quiet fleet. In the first version of this change noisyDevices still swallowed
// its own errors and reported nothing, so that exact incident would still have
// published `partial: false` — the flag was blind to the case it was built for.
//
// Dropping the table is a stand-in for the timeout: both surface as a failed
// query on that block, which is all the tracker distinguishes.
func TestNoisyDevices_FailureMarksSnapshotPartial(t *testing.T) {
	d := database.NewDatabaseForTesting(t)
	g := d.Gorm()

	if err := g.Create(&models.Device{Name: "loud"}).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := g.Exec("DROP TABLE syslog_messages").Error; err != nil {
		t.Fatalf("drop syslog_messages: %v", err)
	}

	cs := &computeStatus{}
	_ = noisyDevices(g, 24, 10, cs)

	if !cs.partial() {
		t.Fatal("a failed noisy-devices scan did not mark the snapshot partial — the empty leaderboard would " +
			"publish under partial:false and read as a quiet fleet, which is the exact incident this flag exists for")
	}
	var named bool
	for _, f := range cs.failed {
		if strings.Contains(f, "noisy") {
			named = true
		}
	}
	if !named {
		t.Errorf("failed blocks = %v, want one naming the noisy scan so the UI can say which reading is missing", cs.failed)
	}
}

// A nil tracker is the request path (GET /api/dashboard/noisy), which has no
// snapshot to mark. It must degrade exactly as before rather than panic.
func TestNoisyDevices_NilTrackerDoesNotPanic(t *testing.T) {
	d := database.NewDatabaseForTesting(t)
	g := d.Gorm()
	if err := g.Exec("DROP TABLE syslog_messages").Error; err != nil {
		t.Fatalf("drop syslog_messages: %v", err)
	}
	if got := noisyDevices(g, 24, 10, nil); got == nil {
		t.Error("noisyDevices returned nil with a nil tracker; callers range over the result")
	}
}
