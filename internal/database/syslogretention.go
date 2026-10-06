package database

import (
	"fmt"
	"time"

	"firewall-mon/internal/config"
)

// Per-severity syslog retention.
//
// Retention used to be two hard-coded bands — "critical" below a boundary and
// "informational" at or above it — which is far too blunt for the real shape of
// the data. On a production fleet ONE severity (5, notice) is ~97% of all syslog
// by volume; everything else together costs under 2 GB per 30 days. Two bands
// force the operator to choose between keeping the noise and losing the signal.
// Per-severity windows let them cut only what is spamming and EXTEND what is
// worth keeping.

// SyslogRetentionKeyPrefix + severity is the per-severity setting key.
const SyslogRetentionKeyPrefix = "syslog_retention_days_"

// SyslogRetentionDefaultKey is the window applied to any severity that has not
// been uncoupled.
const SyslogRetentionDefaultKey = "syslog_retention_days_default"

// SyslogSeverityCount is the number of syslog severities (0..7).
const SyslogSeverityCount = 8

// aggregatedSeverityFloor is the severity at and above which the aggregation
// cycle owns rows: it summarises them into syslog_summaries and then deletes the
// raw rows, on its own 5-minute cadence.
//
// This is a fixed property of the pipeline, NOT the operator-set retention
// boundary. The two were conflated before: because aggregation runs every 5
// minutes and cleanup every 24 hours, aggregation always won for these
// severities, which is why the old band boundary had to be clamped so it could
// never claim them.
const aggregatedSeverityFloor = 6

// syslogRetentionInherit is the sentinel meaning "no value stored".
//
// It has to be a sentinel rather than the real default because GetIntSetting
// returns its default argument for absent, empty AND unparseable values — so
// asking for the true default would collapse "blank" and "0" into one answer,
// and those mean opposite things here (inherit vs keep forever).
const syslogRetentionInherit = -1

// SyslogRetentionKey returns the settings key for one severity.
func SyslogRetentionKey(severity int) string {
	return fmt.Sprintf("%s%d", SyslogRetentionKeyPrefix, severity)
}

// SyslogWindow is one severity's resolved raw retention window: Months > 0 is
// a calendar-month window (RETENTION_SYSLOG_MONTHS), otherwise Days. Both zero
// means KEEP FOREVER. Comparable, so cleanup groups severities by it.
type SyslogWindow struct {
	Days   int
	Months int
}

// Forever reports whether the window keeps rows forever.
func (w SyslogWindow) Forever() bool { return w.Days <= 0 && w.Months <= 0 }

// Cutoff is the instant before which rows of this window have expired. A day
// window is now.AddDate(0, 0, -Days) — exactly the arithmetic cleanup and the
// aggregation cycle have always used — and a month window is monthsAgo.
// Callers skip Forever windows.
func (w SyslogWindow) Cutoff(now time.Time) time.Time {
	if w.Months > 0 {
		return monthsAgo(now, w.Months)
	}
	return now.AddDate(0, 0, -w.Days)
}

// String labels the window in logs and errors: "30d" (as before) or "1mo".
func (w SyslogWindow) String() string {
	if w.Months > 0 {
		return fmt.Sprintf("%dmo", w.Months)
	}
	return fmt.Sprintf("%dd", w.Days)
}

// spanDays is the window's length in days at now: Days, or for a month window
// the whole days back to its cutoff (28-31 per month; computed in UTC, so
// always a whole number). 0 means forever.
func (w SyslogWindow) spanDays(now time.Time) int {
	if w.Months <= 0 {
		return w.Days
	}
	return int(now.Sub(monthsAgo(now, w.Months)).Hours() / 24)
}

// monthsAgo is the same instant n calendar months before now, clamped to the
// last day of the target month, computed on the UTC calendar (no DST) and
// returned in now's location (the same instant either way; the location only
// keeps a SQLite text comparison consistent with the rows' writers).
//
// Go's now.AddDate(0, -n, 0) is NOT this: it normalises the overflow, so 31
// March minus one month is "31 February" = 3 March, a window of only 28 days.
// Clamped, 31 March gives 28 (29) February: never less than one calendar month.
func monthsAgo(now time.Time, n int) time.Time {
	u := now.UTC()
	y, m, d := u.Date()
	// The 1st never overflows, so Go's month normalisation is safe here.
	first := time.Date(y, m-time.Month(n), 1, 0, 0, 0, 0, time.UTC)
	if last := first.AddDate(0, 1, -1).Day(); d > last {
		d = last
	}
	return time.Date(first.Year(), first.Month(), d, u.Hour(), u.Minute(), u.Second(), u.Nanosecond(), time.UTC).In(now.Location())
}

// SyslogRetentionWindows resolves the retention window for every severity.
//
// A day window of 0 means KEEP FOREVER — the established meaning of
// SyslogCriticalDays == 0, which must survive this change or an upgrade starts
// silently deleting logs an operator chose to keep indefinitely.
//
// Resolution, highest priority first:
//
//  1. the per-severity setting          (an "uncoupled" severity)
//  2. the default setting               (applies to everything not uncoupled)
//  3. RETENTION_SYSLOG_MONTHS, when > 0 (one month window for every severity)
//  4. the existing legacy model         (env windows + the DB band boundary)
//
// Read-through, never seeded. Writing resolved values into the database on first
// run would invert precedence — an operator changing RETENTION_SYSLOG_CRITICAL_DAYS
// afterwards would see nothing happen — which is the opposite of how every other
// env-backed knob here behaves, and it would race the poller's startup cleanup
// besides.
func (d *Database) SyslogRetentionWindows(ret config.RetentionConfig) [SyslogSeverityCount]SyslogWindow {
	var out [SyslogSeverityCount]SyslogWindow

	defaultDays := d.GetIntSetting(SyslogRetentionDefaultKey, syslogRetentionInherit)
	var fallback [SyslogSeverityCount]SyslogWindow
	if ret.SyslogMonths > 0 {
		for sev := range fallback {
			fallback[sev] = SyslogWindow{Months: ret.SyslogMonths}
		}
	} else {
		for sev, days := range d.legacySyslogDays(ret) {
			fallback[sev] = SyslogWindow{Days: days}
		}
	}

	for sev := 0; sev < SyslogSeverityCount; sev++ {
		days := d.GetIntSetting(SyslogRetentionKey(sev), syslogRetentionInherit)
		if days == syslogRetentionInherit {
			days = defaultDays
		}
		// A stored "-5" parses cleanly and would otherwise flow through as a
		// negative window; only the sentinel is meaningful, and both fall back.
		if days < 0 {
			out[sev] = fallback[sev]
			continue
		}
		out[sev] = SyslogWindow{Days: days}
	}
	return out
}

// SyslogRetentionDays is SyslogRetentionWindows in days, for the volume
// report: a month window counts the days it spans today (28-31 for one
// month). A returned 0 means KEEP FOREVER.
func (d *Database) SyslogRetentionDays(ret config.RetentionConfig) [SyslogSeverityCount]int {
	var out [SyslogSeverityCount]int
	now := time.Now()
	for sev, w := range d.SyslogRetentionWindows(ret) {
		out[sev] = w.spanDays(now)
	}
	return out
}

// legacySyslogDays expresses the pre-existing two-band model as per-severity
// windows, so an operator who has never touched the UI keeps exactly the
// retention they have today.
//
// ZERO IS ASYMMETRIC HERE AND MUST STAY THAT WAY. In the legacy model
// SyslogCriticalDays == 0 means keep forever, but SyslogInfoDays <= 0 is clamped
// to 7 — in cleanup and in the aggregation cycle alike. Folding both into the
// new uniform "0 = forever" would turn an explicit RETENTION_SYSLOG_INFO_DAYS=0
// into keep-forever for severities 6-7, inverting today's behaviour.
func (d *Database) legacySyslogDays(ret config.RetentionConfig) [SyslogSeverityCount]int {
	var out [SyslogSeverityCount]int

	infoDays := ret.SyslogInfoDays
	if infoDays <= 0 {
		infoDays = 7 // the legacy clamp — NOT "forever"
	}

	// Legacy single-window mode: one window for everything, active only when
	// neither of the newer knobs is set.
	if ret.SyslogDays > 0 && ret.SyslogCriticalDays == 0 && ret.SyslogInfoDays == 0 {
		for sev := range out {
			out[sev] = ret.SyslogDays
		}
		return out
	}

	boundary := d.SyslogCriticalBelow()
	for sev := range out {
		if sev < boundary {
			out[sev] = ret.SyslogCriticalDays // 0 here genuinely means forever
		} else {
			out[sev] = infoDays
		}
	}
	return out
}

// syslogWindowGroups inverts the per-severity windows into one entry per
// DISTINCT window, so cleanup issues one delete per window rather than eight.
// Keep-forever severities are omitted entirely — they are never deleted.
//
// In the common case where nothing is uncoupled this collapses to a single
// group, so the query count is no worse than the two-band model it replaces.
func syslogWindowGroups(windows [SyslogSeverityCount]SyslogWindow) map[SyslogWindow][]int {
	groups := make(map[SyslogWindow][]int)
	for sev, w := range windows {
		if w.Forever() {
			continue // keep forever
		}
		groups[w] = append(groups[w], sev)
	}
	return groups
}

// syslogDropCutoff returns the OLDEST cutoff across all severities, or
// ok=false if ANY severity is kept forever.
//
// This is the bound for dropping a whole partition: a partition may only be
// dropped once every severity inside it has expired, so one keep-forever
// severity pins every partition permanently. With day windows only it is
// now minus the longest window, as before; with RETENTION_SYSLOG_MONTHS=1 a
// monthly leaf drops once its upper bound (the 1st of the next month) is at or
// before the same instant a month ago — October's leaf on 1 December.
func syslogDropCutoff(windows []SyslogWindow, now time.Time) (cutoff time.Time, ok bool) {
	for _, w := range windows {
		if w.Forever() {
			return time.Time{}, false // some severity is kept forever — never drop
		}
		if c := w.Cutoff(now); !ok || c.Before(cutoff) {
			cutoff, ok = c, true
		}
	}
	return cutoff, ok
}

// syslogMonthsOverridden names, while RETENTION_SYSLOG_MONTHS is on, every
// severity whose window is NOT the month window — with months on, the only
// source of any other window is a Retention-page setting (per severity or the
// default) — as "severity 5 uses Retention-page 7d". Empty when months is off.
func syslogMonthsOverridden(ret config.RetentionConfig, windows [SyslogSeverityCount]SyslogWindow) []string {
	if ret.SyslogMonths <= 0 {
		return nil
	}
	var out []string
	for sev, w := range windows {
		switch {
		case w.Months > 0:
			continue
		case w.Forever():
			out = append(out, fmt.Sprintf("severity %d uses Retention-page keep-forever (0)", sev))
		default:
			out = append(out, fmt.Sprintf("severity %d uses Retention-page %s", sev, w))
		}
	}
	return out
}
