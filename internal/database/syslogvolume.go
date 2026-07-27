package database

import (
	"firewall-mon/internal/config"
)

// SyslogSeverityVolume is one severity's estimated share of the table, for the
// Retention settings page.
//
// ESTIMATED, deliberately. A real `SELECT severity, COUNT(*) … GROUP BY severity`
// over 68M rows would flirt with — and on a busy box exceed — the 30s
// statement_timeout on every page load, which is the exact failure class this
// feature exists to remove. Sampling is no good either: severities 0-3 are ~0.01%
// of rows, so even a 0.1% sample expects a handful and would routinely report
// ZERO for the emergency and error severities an operator most wants to protect.
//
// Postgres already has the answer in the catalog, for free.
type SyslogSeverityVolume struct {
	Severity int    `json:"severity"`
	Name     string `json:"name"`

	// Days is the resolved effective window: 0 means keep forever.
	Days      int  `json:"days"`
	Forever   bool `json:"forever"`
	Inherited bool `json:"inherited"` // no per-severity override set

	// Tracked is false when the severity is too rare to appear in the
	// statistics. Rendered as "fewer than statistics track" rather than a
	// fabricated zero — a hard 0 on EMERG invites shortening it.
	Tracked  bool  `json:"tracked"`
	EstRows  int64 `json:"est_rows"`
	EstBytes int64 `json:"est_bytes"`
}

// SyslogVolumeReport backs the Retention page.
type SyslogVolumeReport struct {
	Severities []SyslogSeverityVolume `json:"severities"`
	DefaultDay int                    `json:"default_days"`
	// StatsAvailable is false before ANALYZE has run. The page says so rather
	// than showing a distribution it invented.
	StatsAvailable bool  `json:"stats_available"`
	TotalRows      int64 `json:"total_rows"`
}

var syslogSeverityNames = [SyslogSeverityCount]string{
	"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug",
}

// SyslogVolume reports each severity's resolved retention window alongside an
// estimate of what it costs, so an operator can see which severity is actually
// drowning them before choosing a window.
func (d *Database) SyslogVolume(ret config.RetentionConfig) SyslogVolumeReport {
	days := d.SyslogRetentionDays(ret)
	defaultDays := d.GetIntSetting(SyslogRetentionDefaultKey, syslogRetentionInherit)

	out := SyslogVolumeReport{DefaultDay: defaultDays}
	total, freqs, ok := d.syslogSeverityStats()
	out.StatsAvailable = ok
	out.TotalRows = total

	avgWidth := d.syslogAvgRowWidth()

	for sev := 0; sev < SyslogSeverityCount; sev++ {
		override := d.GetIntSetting(SyslogRetentionKey(sev), syslogRetentionInherit)
		v := SyslogSeverityVolume{
			Severity:  sev,
			Name:      syslogSeverityNames[sev],
			Days:      days[sev],
			Forever:   days[sev] <= 0,
			Inherited: override == syslogRetentionInherit,
		}
		if f, present := freqs[sev]; present && ok {
			v.Tracked = true
			v.EstRows = int64(f * float64(total))
			v.EstBytes = v.EstRows * avgWidth
		}
		out.Severities = append(out.Severities, v)
	}
	return out
}

// syslogSeverityStats reads the severity distribution straight from the planner
// statistics — no table access at all.
func (d *Database) syslogSeverityStats() (total int64, freqs map[int]float64, ok bool) {
	freqs = make(map[int]float64)
	if !d.dialect.IsPostgres() {
		// Dev databases are tiny; an exact count is cheap and avoids depending
		// on catalog statistics that SQLite does not keep.
		var rows []struct {
			Severity int
			N        int64
		}
		if err := d.db.Raw(`SELECT severity, COUNT(*) AS n FROM syslog_messages GROUP BY severity`).
			Scan(&rows).Error; err != nil {
			return 0, freqs, false
		}
		for _, r := range rows {
			total += r.N
		}
		if total == 0 {
			return 0, freqs, false
		}
		for _, r := range rows {
			freqs[r.Severity] = float64(r.N) / float64(total)
		}
		return total, freqs, true
	}

	// Partitions OR the relation — never both.
	//
	// A fresh install converts syslog_messages to a partitioned parent whose rows
	// live in the children, so the parent alone reports ~0. But summing parent
	// AND children double-counts, because an explicit ANALYZE on a partitioned
	// parent populates its reltuples with the whole total as well. (Observed:
	// 20,000 seeded rows reported as 40,000.) Production is a plain heap and so
	// was unaffected — every fresh install would have been wrong.
	//
	// GREATEST also absorbs the never-analyzed -1 sentinel.
	if err := d.db.Raw(`
		SELECT COALESCE(CASE
			WHEN EXISTS (SELECT 1 FROM pg_inherits i
			             JOIN pg_class p ON p.oid = i.inhparent
			             WHERE p.relname = 'syslog_messages')
			THEN (SELECT SUM(GREATEST(c.reltuples, 0))
			      FROM pg_inherits i
			      JOIN pg_class c ON c.oid = i.inhrelid
			      JOIN pg_class p ON p.oid = i.inhparent
			      WHERE p.relname = 'syslog_messages')
			ELSE (SELECT GREATEST(c.reltuples, 0)
			      FROM pg_class c WHERE c.relname = 'syslog_messages')
		END, 0)::bigint`).Scan(&total).Error; err != nil {
		return 0, freqs, false
	}
	if total <= 0 {
		return 0, freqs, false
	}

	var stats []struct {
		Severity int
		Freq     float64
	}
	// Only a handful of distinct severities exist, so they all fit inside the
	// tracked most-common set.
	if err := d.db.Raw(`
		SELECT unnest(most_common_vals::text::int[]) AS severity,
		       unnest(most_common_freqs)             AS freq
		FROM pg_stats
		WHERE tablename = 'syslog_messages' AND attname = 'severity'`).Scan(&stats).Error; err != nil {
		return total, freqs, false
	}
	for _, s := range stats {
		freqs[s.Severity] = s.Freq
	}
	return total, freqs, len(freqs) > 0
}

// syslogAvgRowWidth returns the planner's average row width, for turning an
// estimated row count into an estimated size.
func (d *Database) syslogAvgRowWidth() int64 {
	if !d.dialect.IsPostgres() {
		return 0
	}
	var w int64
	if err := d.db.Raw(`
		SELECT COALESCE(SUM(avg_width), 0)::bigint
		FROM pg_stats WHERE tablename = 'syslog_messages'`).Scan(&w).Error; err != nil {
		return 0
	}
	return w
}
