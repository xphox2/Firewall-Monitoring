package database

import (
	"fmt"

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

// SyslogRetentionDays resolves the retention window for every severity, in days.
//
// A returned 0 means KEEP FOREVER — the established meaning of
// SyslogCriticalDays == 0, which must survive this change or an upgrade starts
// silently deleting logs an operator chose to keep indefinitely.
//
// Resolution, highest priority first:
//
//  1. the per-severity setting          (an "uncoupled" severity)
//  2. the default setting               (applies to everything not uncoupled)
//  3. the existing legacy model         (env windows + the DB band boundary)
//
// Read-through, never seeded. Writing resolved values into the database on first
// run would invert precedence — an operator changing RETENTION_SYSLOG_CRITICAL_DAYS
// afterwards would see nothing happen — which is the opposite of how every other
// env-backed knob here behaves, and it would race the poller's startup cleanup
// besides.
func (d *Database) SyslogRetentionDays(ret config.RetentionConfig) [SyslogSeverityCount]int {
	var out [SyslogSeverityCount]int

	defaultDays := d.GetIntSetting(SyslogRetentionDefaultKey, syslogRetentionInherit)
	legacy := d.legacySyslogDays(ret)

	for sev := 0; sev < SyslogSeverityCount; sev++ {
		days := d.GetIntSetting(SyslogRetentionKey(sev), syslogRetentionInherit)
		if days == syslogRetentionInherit {
			days = defaultDays
		}
		if days == syslogRetentionInherit {
			days = legacy[sev]
		}
		// A stored "-5" parses cleanly and would otherwise flow through as a
		// negative window; only the sentinel is meaningful.
		if days < 0 {
			days = legacy[sev]
		}
		out[sev] = days
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
func syslogWindowGroups(days [SyslogSeverityCount]int) map[int][]int {
	groups := make(map[int][]int)
	for sev, d := range days {
		if d <= 0 {
			continue // keep forever
		}
		groups[d] = append(groups[d], sev)
	}
	return groups
}

// syslogMaxWindow returns the longest window across all severities, or 0 if ANY
// severity is kept forever.
//
// This is the bound for dropping a whole partition: a partition may only be
// dropped once every severity inside it has expired, so one keep-forever
// severity pins every partition permanently.
func syslogMaxWindow(days []int) int {
	max := 0
	for _, d := range days {
		if d <= 0 {
			return 0 // some severity is kept forever — never drop
		}
		if d > max {
			max = d
		}
	}
	return max
}
