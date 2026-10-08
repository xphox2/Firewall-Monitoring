package status

import (
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
)

// Lateness (0.11.316). A table's archive is judged by how late its next
// chunk is, not by the age of its verified data: a daily table's data is
// 24 h old at midnight and its day can only be cut ARCHIVE_MIN_AGE_HOURS
// later, so the raw age of a perfectly healthy syslog archive peaks past
// 26 h every night — more on a heavy day still exporting. The schedule says
// when the chunk after the verified data is due:
//
//	due     = verified-through end + period (1 h flows, 24 h syslog and
//	          counters) + the minimum age (ARCHIVE_MIN_AGE_HOURS for syslog
//	          and counters, 5 min for flows) + SettleSlack, moved to the next
//	          ARCHIVE_WINDOW opening for syslog when it falls outside it
//	overdue = max(0, now − due)
//
// The lag thresholds (archive_lag_alert_hours_*, default 3 h for every
// table) are compared with overdue, by the verdict (Assess), the
// ARCHIVE_LAG alert (Evaluator.Conditions) and the first-chunk checks alike.

// SettleSlack is the time a cut chunk may take to settle before its export
// starts (the settle window: statement_timeout plus a margin) — part of the
// schedule, not lateness.
const SettleSlack = 10 * time.Minute

// ScheduleView is a table's chunk schedule.
type ScheduleView struct {
	PeriodSeconds float64 `json:"period_seconds"`
	MinAgeSeconds float64 `json:"min_age_seconds"`
	SlackSeconds  float64 `json:"slack_seconds"`
	// Window: ARCHIVE_WINDOW for syslog ("" = any time; flows and counters
	// always run).
	Window string `json:"window,omitempty"`
}

func scheduleOf(a config.ArchiveConfig, table string) ScheduleView {
	period, minAge, _ := database.ArchiveSchedule(table, a.MinAgeHours)
	v := ScheduleView{PeriodSeconds: period.Seconds(), MinAgeSeconds: minAge.Seconds(), SlackSeconds: SettleSlack.Seconds()}
	if table == export.TableSyslog {
		if _, _, on, err := a.WindowMinutes(); err == nil && on {
			v.Window = a.Window
		}
	}
	return v
}

// DueAfter is when the chunk after data verified through end is due to be
// verified.
func (s ScheduleView) DueAfter(end time.Time) time.Time {
	cut := end.Add(secs(s.PeriodSeconds + s.MinAgeSeconds))
	if s.Window != "" {
		if start, stop, on, err := (config.ArchiveConfig{Window: s.Window}).WindowMinutes(); err == nil && on {
			cut = nextInWindow(cut, start, stop)
		}
	}
	return cut.Add(secs(s.SlackSeconds))
}

// Overdue is how late the chunk after data verified through end is at now
// (0 while it is not due yet).
func (s ScheduleView) Overdue(end, now time.Time) time.Duration {
	return max(0, now.Sub(s.DueAfter(end)))
}

// nextInWindow is t, or the next instant at or after it inside the UTC
// window [start, stop) minutes (it may wrap midnight).
func nextInWindow(t time.Time, start, stop int) time.Time {
	t = t.UTC()
	in := func(m int) bool {
		if start < stop {
			return m >= start && m < stop
		}
		return m >= start || m < stop
	}
	if in(t.Hour()*60 + t.Minute()) {
		return t
	}
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	open := day.Add(time.Duration(start) * time.Minute)
	if !open.After(t) {
		open = open.AddDate(0, 0, 1)
	}
	return open
}
