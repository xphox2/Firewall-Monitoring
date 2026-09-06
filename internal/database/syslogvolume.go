package database

import (
	"errors"
	"log"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
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

	// Ingest rate, measured by the ingest meter (syslog_ingest.go) over the
	// last SyslogVolumeReport.RateHours. RateAvailable is false until the
	// meter has landed its first bucket; the page says "collecting" rather
	// than showing a zero rate as if nothing arrives.
	RateAvailable bool  `json:"rate_available"`
	RowsPerDay    int64 `json:"rows_per_day"`
	BytesPerDay   int64 `json:"bytes_per_day"` // ingest payload bytes, not on-disk

	// ProjectedBytes is the steady-state on-disk size at the resolved window:
	// RowsPerDay × Days × DiskBytesPerRow. ProjectedForever is set instead
	// when the window is keep-forever and rows are arriving — the size grows
	// without bound and no single number is honest.
	ProjectedBytes   int64 `json:"projected_bytes"`
	ProjectedForever bool  `json:"projected_forever"`
}

// SyslogVolumeReport backs the Retention page.
type SyslogVolumeReport struct {
	Severities []SyslogSeverityVolume `json:"severities"`
	// DefaultDay is the explicit default window, and is meaningful only when
	// DefaultSet is true — the internal "inherit" sentinel is never exposed.
	// With no explicit default each severity falls back to the server's
	// configured retention, which is NOT a single number, so the page must not
	// present one. Each row's resolved window is in the severity entry.
	DefaultDay int  `json:"default_days"`
	DefaultSet bool `json:"default_set"`
	// StatsAvailable is false before ANALYZE has run. The page says so rather
	// than showing a distribution it invented.
	StatsAvailable bool  `json:"stats_available"`
	TotalRows      int64 `json:"total_rows"`

	// RateHours is how many hours of ingest buckets the per-severity rates
	// rest on (≤ 24; 0 = no buckets yet, every RateAvailable is false).
	RateHours float64 `json:"rate_hours"`

	// DiskBytesPerRow turns a row rate into a size. DiskWidthMeasured=true
	// means it is the table's true on-disk cost per row (heap + indexes +
	// TOAST, from the catalog); false means it is the meter's own
	// bytes-per-row, which understates the on-disk cost.
	DiskBytesPerRow   int64 `json:"disk_bytes_per_row"`
	DiskWidthMeasured bool  `json:"disk_width_measured"`

	// CurrentSyslogBytes is the syslog table's on-disk size now; DatabaseBytes
	// the whole database's. Their difference is "everything else", which the
	// projection carries forward unchanged.
	CurrentSyslogBytes int64 `json:"current_syslog_bytes"`
	DatabaseBytes      int64 `json:"database_bytes"`

	// ProjectedSyslogBytes sums the severities' ProjectedBytes; ProjectedForever
	// is true when any severity is kept forever and still receiving rows.
	ProjectedSyslogBytes int64 `json:"projected_syslog_bytes"`
	ProjectedForever     bool  `json:"projected_forever"`

	// The volume the database lives on, from the newest server_metrics sample
	// that saw it. VolumeKnown=false (external database, first minutes after
	// install) means the page omits the verdict rather than inventing one.
	// VolumeTotalDerived=true means the sample predates the stored size and the
	// total was derived from percent and free — which excludes ext4's reserved
	// blocks, so it can read a few percent under what df shows.
	VolumeTotalBytes   int64 `json:"volume_total_bytes"`
	VolumeFreeBytes    int64 `json:"volume_free_bytes"`
	VolumeKnown        bool  `json:"volume_known"`
	VolumeTotalDerived bool  `json:"volume_total_derived"`
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

	out := SyslogVolumeReport{}
	if defaultDays != syslogRetentionInherit {
		out.DefaultDay, out.DefaultSet = defaultDays, true
	}
	total, freqs, ok := d.syslogSeverityStats()
	out.StatsAvailable = ok
	out.TotalRows = total

	avgWidth := d.syslogAvgRowWidth()

	rate, hours := d.SyslogIngestRate(time.Now())
	out.RateHours = hours

	// On-disk cost per row. The catalog figure includes indexes and TOAST
	// (production: ~1,010 B against a planner avg_width of ~800); when it is
	// unavailable — never analyzed, SQLite, a catalog error — fall back to what
	// the meter saw arrive, and say so.
	width, tableBytes, measured := d.syslogDiskFootprint()
	if !measured {
		var totalRows, totalBytes int64
		for sev := range rate {
			totalRows += rate[sev].Rows
			totalBytes += rate[sev].Bytes
		}
		if totalRows > 0 {
			width = totalBytes / totalRows
		}
	}
	out.DiskBytesPerRow, out.DiskWidthMeasured = width, measured
	out.CurrentSyslogBytes = tableBytes
	out.DatabaseBytes = d.databaseSizeBytes()

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
		if hours > 0 {
			v.RateAvailable = true
			v.RowsPerDay = int64(float64(rate[sev].Rows) * 24 / hours)
			v.BytesPerDay = int64(float64(rate[sev].Bytes) * 24 / hours)
			if v.Days <= 0 {
				v.ProjectedForever = v.RowsPerDay > 0
			} else {
				v.ProjectedBytes = v.RowsPerDay * int64(v.Days) * width
			}
			out.ProjectedSyslogBytes += v.ProjectedBytes
			out.ProjectedForever = out.ProjectedForever || v.ProjectedForever
		}
		out.Severities = append(out.Severities, v)
	}

	out.VolumeTotalBytes, out.VolumeFreeBytes, out.VolumeKnown, out.VolumeTotalDerived = d.latestDataVolume()
	return out
}

// syslogDiskFootprint reads the syslog table's on-disk size and cost per row
// from the catalog — heap, indexes and TOAST included — over the same
// partitions-XOR-parent set syslogSeverityStats uses. measured is false when
// the width cannot be trusted: never analyzed (reltuples = -1 on every
// relation), a query error, or SQLite. It never touches the table itself.
//
// The width divides only relations the planner has counted: a partition that
// has received rows but never been analyzed contributes its bytes to the
// total, not to the per-row cost, or a fresh month would inflate the width.
func (d *Database) syslogDiskFootprint() (bytesPerRow, tableBytes int64, measured bool) {
	if !d.dialect.IsPostgres() {
		return 0, 0, false
	}
	var row struct {
		TotalBytes  int64
		BytesPerRow *int64
	}
	if err := d.db.Raw(`
		WITH rels AS (
			SELECT c.oid, c.reltuples
			FROM pg_inherits i
			JOIN pg_class c ON c.oid = i.inhrelid
			JOIN pg_class p ON p.oid = i.inhparent
			WHERE p.relname = 'syslog_messages'
			UNION ALL
			SELECT c.oid, c.reltuples
			FROM pg_class c
			WHERE c.relname = 'syslog_messages'
			  AND NOT EXISTS (SELECT 1 FROM pg_inherits i
			                  JOIN pg_class p ON p.oid = i.inhparent
			                  WHERE p.relname = 'syslog_messages')
		)
		SELECT COALESCE(SUM(pg_total_relation_size(oid)), 0)::bigint AS total_bytes,
		       (SUM(CASE WHEN reltuples >= 0 THEN pg_total_relation_size(oid) END)
		        / NULLIF(SUM(GREATEST(reltuples, 0)), 0))::bigint AS bytes_per_row
		FROM rels`).Scan(&row).Error; err != nil {
		log.Printf("syslog volume: disk footprint read failed: %v", err)
		return 0, 0, false
	}
	if row.BytesPerRow == nil || *row.BytesPerRow <= 0 {
		return 0, row.TotalBytes, false
	}
	return *row.BytesPerRow, row.TotalBytes, true
}

// databaseSizeBytes is the whole database's on-disk size (0 when unknown).
func (d *Database) databaseSizeBytes() int64 {
	var n int64
	q := `SELECT pg_database_size(current_database())`
	if !d.dialect.IsPostgres() {
		q = `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`
	}
	if err := d.db.Raw(q).Scan(&n).Error; err != nil {
		log.Printf("syslog volume: database size read failed: %v", err)
		return 0
	}
	return n
}

// latestDataVolume is the database volume as the newest server_metrics sample
// that could see it reports it. known is false with no such sample (an
// external database; the first minutes after install). Samples written before
// v59 stored no total: derive one from percent and free (flagged derived) —
// gopsutil's percent is Used/(Used+Free), so this excludes the filesystem's
// reserved blocks and reads a few percent under df.
func (d *Database) latestDataVolume() (total, free int64, known, derived bool) {
	var m models.ServerMetric
	err := d.db.Where("data_disk_free_bytes IS NOT NULL").Order("timestamp DESC").First(&m).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("syslog volume: server_metrics read failed: %v", err)
		}
		return 0, 0, false, false
	}
	if m.DataDiskFreeBytes == nil {
		return 0, 0, false, false
	}
	free = int64(*m.DataDiskFreeBytes)
	switch {
	case m.DataDiskTotalBytes != nil && *m.DataDiskTotalBytes > 0:
		return int64(*m.DataDiskTotalBytes), free, true, false
	case m.DataDiskPercent != nil && *m.DataDiskPercent >= 0 && *m.DataDiskPercent < 100:
		return int64(float64(free) / (1 - *m.DataDiskPercent/100)), free, true, true
	}
	return 0, free, false, false
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
	// Follow the rows into the leaves.
	//
	// autovacuum does NOT analyze a partitioned parent — PostgreSQL only
	// processes leaves automatically — so on a partitioned install
	// pg_stats for the parent is simply EMPTY, and stays empty forever unless
	// somebody runs ANALYZE on the parent by hand. Since a fresh install
	// converts syslog_messages to a partitioned table, reading the parent alone
	// meant the estimates never appeared on precisely the shape every new
	// deployment has. (This survived initial testing only because seeding the
	// harness ran an explicit ANALYZE on the parent.)
	//
	// So: use the parent's own statistics when they exist, and otherwise
	// combine the leaves'. A leaf's frequency is a fraction OF THAT LEAF, so
	// the leaves must be weighted by their row counts rather than averaged —
	// an unweighted mean would let a nearly-empty month distort the whole
	// table. Only a handful of distinct severities exist, so they all fit
	// inside each relation's tracked most-common set.
	if err := d.db.Raw(`
		WITH parent AS (
			SELECT c.oid, c.relname, n.nspname,
			       GREATEST(c.reltuples, 0) AS rows
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relname = 'syslog_messages'
		), parent_has_stats AS (
			SELECT EXISTS (
				SELECT 1 FROM pg_stats st JOIN parent p
				  ON st.tablename = p.relname AND st.schemaname = p.nspname
				WHERE st.attname = 'severity'
			) AS ok
		), src AS (
			SELECT p.relname, p.nspname, p.rows FROM parent p
			WHERE (SELECT ok FROM parent_has_stats)
			UNION ALL
			SELECT c.relname, n.nspname, GREATEST(c.reltuples, 0)
			FROM pg_inherits i
			JOIN pg_class c ON c.oid = i.inhrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN parent p ON p.oid = i.inhparent
			WHERE NOT (SELECT ok FROM parent_has_stats)
		), tot AS (
			SELECT SUM(rows) AS all_rows FROM src
		), per_rel AS (
			SELECT src.rows,
			       unnest(st.most_common_vals::text::int[]) AS severity,
			       unnest(st.most_common_freqs)             AS freq
			FROM src
			JOIN pg_stats st ON st.tablename = src.relname
			                AND st.schemaname = src.nspname
			                AND st.attname = 'severity'
		)
		SELECT severity,
		       SUM(freq * rows) / NULLIF((SELECT all_rows FROM tot), 0) AS freq
		FROM per_rel
		GROUP BY severity`).Scan(&stats).Error; err != nil {
		return total, freqs, false
	}
	// GROUP BY yields one row per severity; the accumulate is defensive.
	for _, s := range stats {
		freqs[s.Severity] += s.Freq
	}
	return total, freqs, len(freqs) > 0
}

// syslogAvgRowWidth returns the planner's average row width, for turning an
// estimated row count into an estimated size.
func (d *Database) syslogAvgRowWidth() int64 {
	if !d.dialect.IsPostgres() {
		return 0
	}
	// Same parent-has-no-statistics problem as syslogSeverityStats: prefer the
	// parent's own row width, and fall back to a leaf's when the parent has
	// never been analyzed. Row width barely varies between partitions, so any
	// analyzed leaf is a good enough source — no weighting needed.
	var w int64
	if err := d.db.Raw(`
		SELECT COALESCE((
			SELECT SUM(avg_width) FROM pg_stats WHERE tablename = 'syslog_messages'
		), (
			SELECT SUM(st.avg_width)
			FROM pg_stats st
			WHERE st.tablename = (
				SELECT c.relname
				FROM pg_inherits i
				JOIN pg_class c ON c.oid = i.inhrelid
				JOIN pg_class p ON p.oid = i.inhparent
				WHERE p.relname = 'syslog_messages'
				  AND EXISTS (SELECT 1 FROM pg_stats s2 WHERE s2.tablename = c.relname)
				ORDER BY c.reltuples DESC
				LIMIT 1
			)
		), 0)::bigint`).Scan(&w).Error; err != nil {
		return 0
	}
	return w
}
