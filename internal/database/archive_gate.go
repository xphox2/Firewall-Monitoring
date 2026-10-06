package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The verified-id retention gate (archive plan PR 5, §4.2).
//
// While a stream's archiving is enabled, every path that deletes or consumes
// raw rows of its tables only touches rows with id <= V, where V is the id_hi
// of the last chunk in the gapless run of verified chunks from seq 1
// (ArchiveTableProgress). A chunk that is pending, exporting, uploading,
// verifying, failed or needs_attention — or a gap in seq or id — stops V there:
// the rows above it are only ever held, never deleted. The gated paths:
//
//   - syslog retention: the batched DELETE ANDs `id <= V`, and a monthly
//     partition is dropped only when its max(id) <= V (checked again under the
//     DROP's lock);
//   - the severity 6/7 aggregation and the flow rollup: their MAX(id)
//     watermark is capped at V, so held rows are neither summarised nor
//     deleted (every read and delete there is already `id <= watermark`);
//   - flow_samples and flow_if_counters retention: the same AND and drop check.
//
// The device purge is not gated (operator decision). With the stream disabled
// nothing here runs a query and the SQL is byte-identical to the ungated code
// (the andFloor pattern). There is no automatic bypass under disk pressure:
// SERVER_DISK_HIGH pages, and an admin can release one stream's gate for at
// most ArchiveGateOverrideMaxHours (re-authenticated API or CLI, audited).

// Gate streams: the archive's enable switches. flows covers flow_samples and
// flow_if_counters (ARCHIVE_FLOWS_ENABLED).
const (
	ArchiveGateSyslog = "syslog"
	ArchiveGateFlows  = "flows"
)

// ArchiveGateStreams are the gate streams, in a fixed order.
var ArchiveGateStreams = []string{ArchiveGateSyslog, ArchiveGateFlows}

// ArchiveGateOverrideMaxHours bounds an override: an operator's release of a
// stream's gate expires on its own after at most this long.
const ArchiveGateOverrideMaxHours = 24

// archiveGateOverridePrefix + stream is the system_settings key holding the
// instant (RFC 3339, UTC) an override of that stream ends. It is not in the
// settings page's allowlist (UpdateSettings), so only the re-authenticated
// override route and the CLI write it.
const archiveGateOverridePrefix = "archive_gate_override_until_"

// ArchiveGateOverrideKey is the system_settings key of stream's override.
func ArchiveGateOverrideKey(stream string) string { return archiveGateOverridePrefix + stream }

// ParseArchiveGateStreams resolves an override target: "syslog", "flows" or
// "all".
func ParseArchiveGateStreams(name string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ArchiveGateSyslog:
		return []string{ArchiveGateSyslog}, nil
	case ArchiveGateFlows:
		return []string{ArchiveGateFlows}, nil
	case "all":
		return append([]string(nil), ArchiveGateStreams...), nil
	}
	return nil, fmt.Errorf("stream must be syslog, flows or all, got %q", name)
}

// ArchiveGateConfig is which gate streams' archiving is enabled
// (ARCHIVE_SYSLOG_ENABLED / ARCHIVE_FLOWS_ENABLED). Connect sets it from the
// configuration; the zero value gates nothing.
type ArchiveGateConfig struct {
	Syslog bool
	Flows  bool
}

func (c ArchiveGateConfig) enabled(stream string) bool {
	switch stream {
	case ArchiveGateSyslog:
		return c.Syslog
	case ArchiveGateFlows:
		return c.Flows
	}
	return false
}

// archiveGateStream is the gate stream of a raw table ("" when the table is
// not archived).
func archiveGateStream(table string) string {
	switch table {
	case export.TableSyslog:
		return ArchiveGateSyslog
	case export.TableFlows, export.TableCounters:
		return ArchiveGateFlows
	}
	return ""
}

// archiveGateTables are the raw tables of a gate stream.
func archiveGateTables(stream string) []string {
	switch stream {
	case ArchiveGateSyslog:
		return []string{export.TableSyslog}
	case ArchiveGateFlows:
		return []string{export.TableFlows, export.TableCounters}
	}
	return nil
}

// archiveGateState is the gate of one table for one delete statement (or one
// pass of the aggregation / rollup). The zero value is "off".
type archiveGateState struct {
	on bool
	v  int64
	// tmax (PostgreSQL only; zero = none) is ArchiveProgress.VerifiedMaxTs:
	// no row at or below V is newer. It changes no result — `id <= V`
	// already implies it — but it gives the planner a time bound: a
	// partitioned table prunes the leaves above it, and an index walk in
	// timestamp order stops there instead of reading every held row past
	// it. Without it a Merge Append over the leaves starts every child
	// scan, and a leaf holding only rows above V was read to the end once
	// per retention batch (measured in the PostgreSQL lane).
	tmax time.Time
}

// andID ANDs `id <= V` (and `timestamp <= tmax` when known) onto a delete
// predicate when the gate is on, without touching the caller's args; off,
// where and args come back untouched, so the statement is byte-identical to
// the ungated one. Every gated table ages on its `timestamp` column.
func (g archiveGateState) andID(where string, args []interface{}) (string, []interface{}) {
	if !g.on {
		return where, args
	}
	pred, add := "id <= ?", []interface{}{g.v}
	if !g.tmax.IsZero() {
		pred, add = "id <= ? AND timestamp <= ?", []interface{}{g.v, g.tmax}
	}
	if where == "" {
		return pred, add
	}
	return where + " AND " + pred, append(append([]interface{}{}, args...), add...)
}

// capWatermark caps an aggregation's MAX(id) watermark at V when the gate is
// on.
func (g archiveGateState) capWatermark(watermark int64) int64 {
	if g.on && g.v < watermark {
		return g.v
	}
	return watermark
}

// capCutoff lowers an aggregation's `timestamp < cutoff` bound to just past
// tmax when the gate knows one: the rows it excludes are all above V (held
// anyway); what it saves is the walk over them (see tmax).
func (g archiveGateState) capCutoff(cutoff time.Time) time.Time {
	if g.on && !g.tmax.IsZero() && g.tmax.Before(cutoff) {
		return g.tmax.Add(time.Microsecond)
	}
	return cutoff
}

// archiveGateOverrideUntil reads stream's override. active is true while
// now < until. A value that does not parse, or that ends more than
// ArchiveGateOverrideMaxHours (plus a minute of clock slack) after now — it
// was not written by the override route — is ignored with a WARNING: the gate
// stays on.
func (d *Database) archiveGateOverrideUntil(stream string, now time.Time) (until time.Time, active bool) {
	// A Pluck, not GetSettingValue: the key is normally absent, and First's
	// "record not found" would log an error line on every gated pass.
	var vals []string
	if err := d.db.Model(&models.SystemSetting{}).Where("\"key\" = ?", ArchiveGateOverrideKey(stream)).Limit(1).Pluck("value", &vals).Error; err != nil {
		log.Printf("archive gate: read %s: %v (deletes of %s stay gated)", ArchiveGateOverrideKey(stream), err, stream)
		return time.Time{}, false
	}
	if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
		return time.Time{}, false
	}
	v := vals[0]
	until, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		log.Printf("WARNING: archive gate: %s = %q is not an RFC 3339 time; ignored, deletes of %s stay gated", ArchiveGateOverrideKey(stream), v, stream)
		return time.Time{}, false
	}
	if until.After(now.Add(ArchiveGateOverrideMaxHours*time.Hour + time.Minute)) {
		log.Printf("WARNING: archive gate: %s ends %s, more than %d h from now; ignored, deletes of %s stay gated",
			ArchiveGateOverrideKey(stream), until.UTC().Format(time.RFC3339), ArchiveGateOverrideMaxHours, stream)
		return time.Time{}, false
	}
	return until, now.Before(until)
}

// archiveGate resolves the gate of table's raw deletes now. Off when the
// table is not archived or its stream is disabled (no query at all), or while
// an override of the stream is active (logged). On, v is V; when V cannot be
// derived the gate stays on with V = 0, so nothing is deleted (fail closed).
func (d *Database) archiveGate(ctx context.Context, table string) archiveGateState {
	stream := archiveGateStream(table)
	if stream == "" || !d.archiveGateCfg.enabled(stream) {
		return archiveGateState{}
	}
	if until, active := d.archiveGateOverrideUntil(stream, time.Now()); active {
		log.Printf("WARNING: archive gate of %s RELEASED by an operator override until %s: rows of %s are deleted whether or not they are archived",
			stream, until.UTC().Format(time.RFC3339), table)
		return archiveGateState{}
	}
	p, err := d.ArchiveTableProgress(ctx, table)
	if err != nil {
		log.Printf("archive gate: verified-through id of %s: %v (nothing of it is deleted this time)", table, err)
		return archiveGateState{on: true}
	}
	g := archiveGateState{on: true, v: p.VerifiedThroughID}
	if p.VerifiedMaxTs != nil && d.dialect.IsPostgres() {
		g.tmax = *p.VerifiedMaxTs
	}
	return g
}

// archivePartitionMaxID is max(id) of one leaf — a backward walk of its
// primary key, stopping at the first tuple (0 when empty). leaf is a relation
// name read back from pg_inherits, never input.
func archivePartitionMaxID(tx *gorm.DB, leaf string) (int64, error) {
	var n int64
	err := tx.Raw(fmt.Sprintf("SELECT COALESCE(max(id), 0) FROM %s", leaf)).Scan(&n).Error
	return n, err
}

// errArchivePartitionHeld: a leaf's max(id) is above V under the DROP's lock.
var errArchivePartitionHeld = errors.New("archive gate: partition holds rows above the verified-through id")

// SetArchiveGateOverride releases the gate of stream until until (UTC), or
// re-engages it now when until is zero. It only writes the setting; the
// caller validates the bound and writes the audit row.
func (d *Database) SetArchiveGateOverride(stream string, until time.Time) error {
	if archiveGateTables(stream) == nil {
		return fmt.Errorf("archive gate: unknown stream %q", stream)
	}
	val := ""
	if !until.IsZero() {
		val = until.UTC().Format(time.RFC3339)
	}
	return d.UpsertSetting(&models.SystemSetting{Key: ArchiveGateOverrideKey(stream), Value: val, Type: "string", Category: "archive",
		Label: "Archive retention gate released until (set only by the re-authenticated override)"})
}

// ArchiveGateOverride reports stream's override at now: the end instant, and
// whether it is active.
func (d *Database) ArchiveGateOverride(stream string, now time.Time) (until time.Time, active bool) {
	return d.archiveGateOverrideUntil(stream, now)
}

// ErrArchiveChunkNotParked: the chunk to reset is not in needs_attention.
var ErrArchiveChunkNotParked = errors.New("archive: the chunk is not in needs_attention")

// GetArchiveChunk loads one chunk by id (gorm.ErrRecordNotFound when absent).
func (d *Database) GetArchiveChunk(id uint) (*models.ArchiveChunk, error) {
	var c models.ArchiveChunk
	if err := d.db.Where("id = ?", id).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

// ListArchiveChunksNeedingAttention lists the parked chunks, oldest first.
func (d *Database) ListArchiveChunksNeedingAttention(limit int) ([]models.ArchiveChunk, error) {
	var cs []models.ArchiveChunk
	err := d.db.Where("status = ?", models.ArchiveChunkNeedsAttention).Order("table_name, seq").Limit(limit).Find(&cs).Error
	return cs, err
}

// ResetArchiveChunk is the operator's escape for a chunk parked in
// needs_attention (it stops V, so the gate would otherwise hold its table's
// deletes forever): the chunk goes back to pending with its mismatch and
// verify counters cleared, and the worker exports it again on its next pass
// (its earlier objects were superseded when it was parked; Object Lock keeps
// them). A compare-and-set on the status: any other status is
// ErrArchiveChunkNotParked, an unknown id gorm.ErrRecordNotFound. Attempts
// are kept (history).
func (d *Database) ResetArchiveChunk(ctx context.Context, id uint, note string, at time.Time) (*models.ArchiveChunk, error) {
	if len(note) > archiveErrorMax {
		note = note[:archiveErrorMax]
	}
	res := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).
		Where("id = ? AND status = ?", id, models.ArchiveChunkNeedsAttention).
		Updates(map[string]interface{}{"status": models.ArchiveChunkPending, "mismatches": 0, "verify_failures": 0,
			"runner_id": "", "error": note, "updated_at": at})
	if res.Error != nil {
		return nil, res.Error
	}
	c, err := d.GetArchiveChunk(id)
	if err != nil {
		return nil, err
	}
	if res.RowsAffected != 1 {
		return c, ErrArchiveChunkNotParked
	}
	return c, nil
}

// LogArchiveGateState writes the startup lines of the gate: for an enabled
// stream, that its deletes wait for the archive and V of each table; for a
// disabled stream whose tables already have chunks, a WARNING that its deletes
// are no longer gated (the archive manifest is not empty).
func (d *Database) LogArchiveGateState(ctx context.Context) {
	for _, stream := range ArchiveGateStreams {
		for _, table := range archiveGateTables(stream) {
			p, err := d.ArchiveTableProgress(ctx, table)
			if err != nil {
				log.Printf("archive gate: progress of %s: %v", table, err)
				continue
			}
			switch {
			case d.archiveGateCfg.enabled(stream):
				log.Printf("archive gate: deletes of %s wait for the archive (verified through id %d)", table, p.VerifiedThroughID)
			case p.Chunks:
				log.Printf("WARNING: archiving of %s is disabled but archive_chunks has chunks of %s: its retention, aggregation and rollup deletes are NOT gated on the archive any more",
					stream, table)
			}
		}
		if until, active := d.archiveGateOverrideUntil(stream, time.Now()); active {
			log.Printf("WARNING: archive gate of %s is released by an operator override until %s", stream, until.UTC().Format(time.RFC3339))
		}
	}
}
