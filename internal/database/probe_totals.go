package database

import (
	"fmt"
	"strconv"
	"strings"

	"firewall-mon/internal/models"
)

// ProbeTotals is one probe's stored-row count per telemetry table, as the
// Probes page cards show it. Approx names the figures that are estimates
// ("syslog", "traps", "flows", "pings"), so the page marks only those.
type ProbeTotals struct {
	Syslog int64    `json:"syslog"`
	Traps  int64    `json:"traps"`
	Flows  int64    `json:"flows"`
	Pings  int64    `json:"pings"`
	Approx []string `json:"approx"`
}

// probeEstimateMinRows is the table size above which per-probe totals come
// from planner statistics. Below it the exact grouped count is cheap.
const probeEstimateMinRows = 1_000_000

// ProbeTelemetryTotals returns, per requested probe, how many rows each
// telemetry table holds for it.
//
// The exact form — `count(*) … WHERE probe_id IN (…) GROUP BY probe_id` — read
// all 136M syslog_messages index entries on production: 20.2 s on every Probes
// page load. For a large table the per-probe figure is instead the planner's
// own estimate: reltuples × the probe's frequency in pg_stats' most-common
// values, per partition leaf. With a handful of probes against millions of
// rows every probe that matters is a most-common value. The estimate is as
// fresh as the last autoanalyze — up to ~10% stale per leaf at the default
// scale factor, 2% observed on production — and is marked Approx, which the
// page renders with a "~" like the global Data Totals card.
//
// A probe that is not a most-common value in ANY leaf holds too small a share
// to have made the list, so it is counted exactly (probe_id is indexed). The
// exact form is used throughout on SQLite, below probeEstimateMinRows, and
// whenever no leaf has statistics yet.
func (d *Database) ProbeTelemetryTotals(ids []uint) (map[uint]ProbeTotals, error) {
	out := make(map[uint]ProbeTotals, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	for _, id := range ids {
		out[id] = ProbeTotals{Approx: []string{}}
	}
	for _, s := range []struct {
		model interface{}
		table string
		field string
		set   func(*ProbeTotals, int64)
	}{
		{&models.SyslogMessage{}, "syslog_messages", "syslog", func(p *ProbeTotals, n int64) { p.Syslog = n }},
		{&models.TrapEvent{}, "trap_events", "traps", func(p *ProbeTotals, n int64) { p.Traps = n }},
		{&models.FlowSample{}, "flow_samples", "flows", func(p *ProbeTotals, n int64) { p.Flows = n }},
		{&models.PingResult{}, "ping_results", "pings", func(p *ProbeTotals, n int64) { p.Pings = n }},
	} {
		counts, approx, err := d.probeCounts(s.model, s.table, ids)
		if err != nil {
			return nil, fmt.Errorf("probe totals: %s: %w", s.table, err)
		}
		for _, id := range ids {
			p := out[id]
			s.set(&p, counts[id])
			if approx[id] {
				p.Approx = append(p.Approx, s.field)
			}
			out[id] = p
		}
	}
	return out, nil
}

// probeCounts returns the per-probe count for one table, and which of those
// counts are estimates.
func (d *Database) probeCounts(model interface{}, table string, ids []uint) (map[uint]int64, map[uint]bool, error) {
	approx := make(map[uint]bool)
	exactIDs := ids
	counts := make(map[uint]int64, len(ids))

	if total, ok := d.estimateRowCount(table); ok && total >= probeEstimateMinRows {
		est, have, err := d.probeEstimates(table)
		if err != nil {
			return nil, nil, err
		}
		if have {
			exactIDs = nil
			for _, id := range ids {
				if n, found := est[id]; found {
					counts[id] = n
					approx[id] = true
				} else {
					exactIDs = append(exactIDs, id)
				}
			}
		}
	}
	if len(exactIDs) == 0 {
		return counts, approx, nil
	}

	var rows []struct {
		ProbeID uint
		Cnt     int64
	}
	if err := d.db.Model(model).Select("probe_id, count(*) AS cnt").
		Where("probe_id IN ?", exactIDs).Group("probe_id").Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	for _, r := range rows {
		counts[r.ProbeID] = r.Cnt
	}
	return counts, approx, nil
}

// probeEstimates reads reltuples and the probe_id most-common values of every
// leaf of table — its partitions, or the table itself when it has none — and
// sums reltuples × frequency per probe. It never reads a partitioned parent's
// own statistics: autovacuum never analyzes a parent, and when someone does,
// adding them to the leaves' would count every row twice.
//
// A leaf that has never been analyzed (reltuples -1) contributes nothing.
// That is deliberate: the partition manager pre-creates future months, which
// stay unanalyzed until rows arrive, so treating them as "unknown" would push
// every load back onto the exact count. A leaf that has just started filling
// is analyzed after its first few dozen row changes.
//
// have is false when no leaf carries probe_id statistics at all.
func (d *Database) probeEstimates(table string) (map[uint]int64, bool, error) {
	var leaves []struct {
		Reltuples float64
		Vals      *string
		Freqs     *string
	}
	if err := d.db.Raw(`
		WITH leaves AS (
			SELECT c.relname, n.nspname, c.reltuples
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = to_regclass(?))
			   OR (c.oid = to_regclass(?)
			       AND NOT EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent = to_regclass(?)))
		)
		SELECT l.reltuples::float8 AS reltuples,
		       s.most_common_vals::text AS vals,
		       s.most_common_freqs::text AS freqs
		FROM leaves l
		LEFT JOIN pg_stats s ON s.schemaname = l.nspname AND s.tablename = l.relname
		     AND s.attname = 'probe_id' AND s.inherited = false`,
		table, table, table).Scan(&leaves).Error; err != nil {
		return nil, false, err
	}

	est := make(map[uint]float64)
	have := false
	for _, l := range leaves {
		if l.Reltuples <= 0 || l.Vals == nil || l.Freqs == nil {
			continue
		}
		vals, freqs := splitPGArray(*l.Vals), splitPGArray(*l.Freqs)
		if len(vals) != len(freqs) {
			continue
		}
		have = true
		for i := range vals {
			id, err1 := strconv.ParseUint(vals[i], 10, 64)
			f, err2 := strconv.ParseFloat(freqs[i], 64)
			if err1 != nil || err2 != nil {
				continue
			}
			est[uint(id)] += l.Reltuples * f
		}
	}
	out := make(map[uint]int64, len(est))
	for id, n := range est {
		out[id] = int64(n + 0.5)
	}
	return out, have, nil
}

// splitPGArray splits a one-dimensional numeric array literal such as
// "{2,5}" or "{0.97,0.03}".
func splitPGArray(s string) []string {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "{"), "}")
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
