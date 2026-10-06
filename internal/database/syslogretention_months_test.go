package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// RETENTION_SYSLOG_MONTHS (archive plan PR 6): a rolling calendar-month window
// for raw syslog. The cutoff is the same UTC instant N months earlier,
// clamped to that month's last day; Go's AddDate(0, -N, 0) normalises the
// overflow instead and would keep only 28 days on 31 March.

func TestMonthsAgo_Table(t *testing.T) {
	plus2 := time.FixedZone("UTC+2", 2*3600)
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata: %v", err)
	}
	utc := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, time.UTC) }
	cases := []struct {
		name string
		now  time.Time
		n    int
		want time.Time
	}{
		{"mid-month, no clamp", utc(2026, 3, 15, 10, 30), 1, utc(2026, 2, 15, 10, 30)},
		{"31 Mar clamps to 28 Feb", utc(2026, 3, 31, 12, 0), 1, utc(2026, 2, 28, 12, 0)},
		{"31 Mar of a leap year clamps to 29 Feb", utc(2024, 3, 31, 12, 0), 1, utc(2024, 2, 29, 12, 0)},
		{"30 Mar clamps to 28 Feb", utc(2026, 3, 30, 0, 0), 1, utc(2026, 2, 28, 0, 0)},
		{"29 Feb minus 12 months clamps to 28 Feb", utc(2024, 2, 29, 23, 59), 12, utc(2023, 2, 28, 23, 59)},
		{"31 May clamps to 30 Apr", utc(2026, 5, 31, 6, 0), 1, utc(2026, 4, 30, 6, 0)},
		{"31 Dec clamps to 30 Nov", utc(2026, 12, 31, 23, 0), 1, utc(2026, 11, 30, 23, 0)},
		{"year boundary", utc(2026, 1, 15, 0, 0), 1, utc(2025, 12, 15, 0, 0)},
		{"31 Jan across the year clamps nothing", utc(2026, 1, 31, 1, 0), 1, utc(2025, 12, 31, 1, 0)},
		{"two months across the year with clamp", utc(2026, 1, 31, 1, 0), 2, utc(2025, 11, 30, 1, 0)},
		{"1st at midnight", utc(2026, 12, 1, 0, 0), 1, utc(2026, 11, 1, 0, 0)},
		{"120 months", utc(2030, 2, 28, 4, 0), 120, utc(2020, 2, 28, 4, 0)},
		// 31 Mar 01:00 +02:00 is 30 Mar 23:00 UTC: the UTC calendar decides, so
		// the clamp gives 28 Feb 23:00 UTC (the local calendar would give
		// 27 Feb 23:00 UTC).
		{"non-UTC input uses the UTC calendar", time.Date(2026, 3, 31, 1, 0, 0, 0, plus2), 1, utc(2026, 2, 28, 23, 0)},
		// 9 Mar 2026 12:00 EDT = 16:00 UTC; a month earlier New York is on EST.
		// DST-free: 16:00 UTC (11:00 EST), not 12:00 EST.
		{"DST does not shift the hour", time.Date(2026, 3, 9, 12, 0, 0, 0, newYork), 1, utc(2026, 2, 9, 16, 0)},
	}
	for _, c := range cases {
		got := monthsAgo(c.now, c.n)
		if !got.Equal(c.want) {
			t.Errorf("%s: monthsAgo(%s, %d) = %s, want %s", c.name, c.now, c.n, got.UTC(), c.want)
		}
		if got.Location() != c.now.Location() {
			t.Errorf("%s: location %s, want the input's %s", c.name, got.Location(), c.now.Location())
		}
	}
}

// Every day 2023-2026 (a leap year inside), at an awkward time of day, in the
// process's zone: one month back is always 28-31 whole days, lands in the
// previous calendar month (UTC), never after Go's AddDate result (so never
// less than a calendar month), and is the clamped same day.
func TestMonthsAgo_EveryDay(t *testing.T) {
	start := time.Date(2023, 1, 1, 23, 45, 12, 345, time.UTC)
	for i := 0; i < 4*366; i++ {
		u := start.AddDate(0, 0, i)
		now := u.In(time.Local)
		got := monthsAgo(now, 1)
		gu := got.UTC()
		span := now.Sub(got)
		if span%(24*time.Hour) != 0 || span < 28*24*time.Hour || span > 31*24*time.Hour {
			t.Fatalf("%s: span %s, want 28-31 whole days", u, span)
		}
		prev := time.Date(u.Year(), u.Month()-1, 1, 0, 0, 0, 0, time.UTC)
		if gu.Year() != prev.Year() || gu.Month() != prev.Month() {
			t.Fatalf("%s: cutoff %s is not in %s", u, gu, prev.Format("2006-01"))
		}
		if got.After(u.AddDate(0, -1, 0)) {
			t.Fatalf("%s: cutoff %s is after AddDate's %s — less than a calendar month", u, gu, u.AddDate(0, -1, 0))
		}
		wantDay := u.Day()
		if last := prev.AddDate(0, 1, -1).Day(); wantDay > last {
			wantDay = last
		}
		if gu.Day() != wantDay || gu.Hour() != 23 || gu.Minute() != 45 || gu.Nanosecond() != 345 {
			t.Fatalf("%s: cutoff %s, want day %d at 23:45:12.000000345", u, gu, wantDay)
		}
	}
}

// Days mode is numerically what cleanup and the aggregation cycle computed
// before (now.AddDate(0, 0, -days)), and the partition-drop bound is now minus
// the longest window.
func TestSyslogWindow_DaysModeCutoffUnchanged(t *testing.T) {
	now := time.Now()
	for _, days := range []int{1, 7, 30, 31, 90, 365} {
		if got, want := (SyslogWindow{Days: days}).Cutoff(now), now.AddDate(0, 0, -days); !got.Equal(want) {
			t.Errorf("%dd: cutoff %s, want %s", days, got, want)
		}
	}
	d := NewDatabaseForTesting(t)
	w := d.SyslogRetentionWindows(prodLike())
	got, ok := syslogDropCutoff(w[:], now)
	if want := now.AddDate(0, 0, -30); !ok || !got.Equal(want) {
		t.Errorf("drop cutoff %s (%v), want %s", got, ok, want)
	}
	for sev, win := range w {
		if win.Months != 0 {
			t.Errorf("severity %d: %+v — months mode with RETENTION_SYSLOG_MONTHS unset", sev, win)
		}
	}
}

func monthsLike() config.RetentionConfig {
	r := prodLike()
	r.SyslogDays = 90
	r.SyslogMonths = 1
	return r
}

// Months replaces every env day window, for every severity — including the
// legacy "0 = forever" critical band and the 7-day informational band.
func TestSyslogRetentionMonths_OverridesEnvDays(t *testing.T) {
	d := NewDatabaseForTesting(t)
	for i, ret := range []config.RetentionConfig{monthsLike(), {SyslogCriticalDays: 0, SyslogInfoDays: 0, SyslogMonths: 1}} {
		for sev, w := range d.SyslogRetentionWindows(ret) {
			if w != (SyslogWindow{Months: 1}) {
				t.Errorf("case %d severity %d = %s, want 1mo (critical %dd, info %dd, all %dd must be ignored)",
					i, sev, w, ret.SyslogCriticalDays, ret.SyslogInfoDays, ret.SyslogDays)
			}
		}
	}
	days := d.SyslogRetentionDays(monthsLike())
	for sev, n := range days {
		if n < 28 || n > 31 {
			t.Errorf("severity %d spans %d days, want 28-31", sev, n)
		}
	}
}

// Precedence: per-severity setting > default setting > months > legacy days.
func TestSyslogRetentionMonths_SettingsStillWin(t *testing.T) {
	t.Run("default setting", func(t *testing.T) {
		d := NewDatabaseForTesting(t)
		setRetention(t, d, SyslogRetentionDefaultKey, "45")
		for sev, w := range d.SyslogRetentionWindows(monthsLike()) {
			if w != (SyslogWindow{Days: 45}) {
				t.Errorf("severity %d = %+v, want the 45-day default setting", sev, w)
			}
		}
	})
	t.Run("per-severity setting", func(t *testing.T) {
		d := NewDatabaseForTesting(t)
		setRetention(t, d, SyslogRetentionKey(5), "7")
		setRetention(t, d, SyslogRetentionKey(0), "0") // forever
		setRetention(t, d, SyslogRetentionKey(3), "")  // blank inherits
		setRetention(t, d, SyslogRetentionKey(4), "-5")
		w := d.SyslogRetentionWindows(monthsLike())
		want := [SyslogSeverityCount]SyslogWindow{{}, {Months: 1}, {Months: 1}, {Months: 1}, {Months: 1}, {Days: 7}, {Months: 1}, {Months: 1}}
		if w != want {
			t.Errorf("windows %+v, want %+v", w, want)
		}
	})
}

// End to end on the daily pass and the 5-minute aggregation: with months on,
// a 40-day-old critical row is deleted although RETENTION_SYSLOG_CRITICAL_DAYS
// is 0 (forever), a 20-day-old one is kept, and severity 6 stays raw for the
// month (the legacy 7 days would consume it) and is summarised after it.
// 20 and 40 days are inside / outside every month length (28-31).
func TestSyslogRetentionMonths_CleanupAndAggregation(t *testing.T) {
	d := NewDatabaseForTesting(t)
	ret := config.RetentionConfig{DefaultDays: 90, SyslogCriticalDays: 0, SyslogInfoDays: 7, SyslogMonths: 1}
	seedSyslog(t, d, 3, 40)
	seedSyslog(t, d, 3, 20)
	seedSyslog(t, d, 6, 40)
	seedSyslog(t, d, 6, 20)

	if err := d.RunSyslogAggregationCycle(ret); err != nil {
		t.Fatal(err)
	}
	if err := d.CleanupOldData(ret); err != nil {
		t.Fatal(err)
	}
	if n := countSyslog(t, d, 3); n != 1 {
		t.Errorf("severity 3: %d rows left, want 1 (the 40-day-old row past the month deleted, the 20-day-old kept)", n)
	}
	var old int64
	d.Gorm().Model(&models.SyslogMessage{}).Where("severity = ? AND timestamp < ?", 3, timeNowAddDays(-30)).Count(&old)
	if old != 0 {
		t.Errorf("the 40-day-old severity 3 row survived: months must override RETENTION_SYSLOG_CRITICAL_DAYS=0")
	}
	if n := countSyslog(t, d, 6); n != 1 {
		t.Errorf("severity 6: %d raw rows left, want 1 (kept raw for the month, the 40-day-old one summarised)", n)
	}
	var summaries int64
	d.Gorm().Model(&models.SyslogSummary{}).Where("severity = ?", 6).Count(&summaries)
	if summaries == 0 {
		t.Error("the 40-day-old severity 6 row was deleted without a summary")
	}
}
