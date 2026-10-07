package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/config"
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
// (ARCHIVE_SYSLOG_ENABLED / ARCHIVE_FLOWS_ENABLED). Connect sets the
// environment's as the default; the admin settings override it
// (archiveGateConfig). The zero value gates nothing.
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
	until, active, err := d.ArchiveGateOverrideState(stream, now)
	if err != nil {
		log.Printf("archive gate: %v (deletes of %s stay gated)", err, stream)
		return time.Time{}, false
	}
	return until, active
}

// ArchiveGateOverrideState is ArchiveGateOverride that also reports a failed
// read (the gate fails closed on it; the archive status must not show it as
// "not overridden").
func (d *Database) ArchiveGateOverrideState(stream string, now time.Time) (until time.Time, active bool, err error) {
	// A Pluck, not GetSettingValue: the key is normally absent.
	var vals []string
	if err := d.db.Model(&models.SystemSetting{}).Where("\"key\" = ?", ArchiveGateOverrideKey(stream)).Limit(1).Pluck("value", &vals).Error; err != nil {
		return time.Time{}, false, fmt.Errorf("read %s: %w", ArchiveGateOverrideKey(stream), err)
	}
	if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
		return time.Time{}, false, nil
	}
	v := vals[0]
	until, perr := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if perr != nil {
		log.Printf("WARNING: archive gate: %s = %q is not an RFC 3339 time; ignored, deletes of %s stay gated", ArchiveGateOverrideKey(stream), v, stream)
		return time.Time{}, false, nil
	}
	if until.After(now.Add(ArchiveGateOverrideMaxHours*time.Hour + time.Minute)) {
		log.Printf("WARNING: archive gate: %s ends %s, more than %d h from now; ignored, deletes of %s stay gated",
			ArchiveGateOverrideKey(stream), until.UTC().Format(time.RFC3339), ArchiveGateOverrideMaxHours, stream)
		return time.Time{}, false, nil
	}
	return until, now.Before(until), nil
}

// archiveGate resolves the gate of table's raw deletes now. Off when the
// table is not archived or its stream is disabled (no query at all), or while
// an override of the stream is active (logged). On, v is V; when V cannot be
// derived the gate stays on with V = 0, so nothing is deleted (fail closed).
func (d *Database) archiveGate(ctx context.Context, table string) archiveGateState {
	stream := archiveGateStream(table)
	if !d.archiveGateActive(stream) {
		return archiveGateState{}
	}
	if until, active := d.archiveGateOverrideUntil(stream, archiveGateClock()); active {
		archiveReleasedWarning(stream, table, until)
		return archiveGateState{}
	}
	if _, err := d.archiveLeafsClear(ctx, table); err != nil {
		log.Printf("archive gate: %s: %v (nothing of it is deleted this time)", table, err)
		return archiveGateState{on: true}
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

// archiveGateClock is the gate's clock for override expiry; a variable so a
// test can let an override expire in the middle of a pass.
var archiveGateClock = time.Now

// archiveReleasedLog rate-limits the RELEASED warning: the gate is re-read
// before every retention batch, so one line per table a minute is plenty.
var archiveReleasedLog = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

func archiveReleasedWarning(stream, table string, until time.Time) {
	archiveReleasedLog.Lock()
	defer archiveReleasedLog.Unlock()
	now := time.Now()
	if t, ok := archiveReleasedLog.last[table]; ok && now.Sub(t) < time.Minute {
		return
	}
	archiveReleasedLog.last[table] = now
	log.Printf("WARNING: archive gate of %s RELEASED by an operator override until %s: rows of %s are deleted whether or not they are archived",
		stream, until.UTC().Format(time.RFC3339), table)
}

// archiveGateFn is archiveGate of table as a function the delete loops call
// before every batch / leaf; nil when the table is not archived. A stream's
// switch is resolved again before every batch (archiveGateConfig, cached
// briefly), so a stream enabled from the admin page while a long retention
// pass runs gates that pass's next batch; while it is off the gate is the zero
// state and the statements are untouched.
func (d *Database) archiveGateFn(table string) func() archiveGateState {
	if archiveGateStream(table) == "" {
		return nil
	}
	return func() archiveGateState { return d.archiveGate(context.Background(), table) }
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
// re-engages it now when until is zero. It writes the setting and records the
// interval in archive_gate_events (a release ends any earlier one now and
// starts a new one ending at until; re-engaging ends the open one now), so the
// month seal can tell which months' rows may have been deleted unarchived.
// The caller validates the bound and writes the audit row.
func (d *Database) SetArchiveGateOverride(stream string, until time.Time) error {
	if archiveGateTables(stream) == nil {
		return fmt.Errorf("archive gate: unknown stream %q", stream)
	}
	val := ""
	if !until.IsZero() {
		val = until.UTC().Format(time.RFC3339)
	}
	now := archiveGateClock().UTC()
	// One transaction: an override is never active without its interval
	// recorded, nor recorded without being set.
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := d.endArchiveGateEvents(tx, stream, models.ArchiveGateEventOverride, now); err != nil {
			return err
		}
		if !until.IsZero() && until.After(now) {
			u := until.UTC()
			if err := tx.Create(&models.ArchiveGateEvent{Stream: stream, Kind: models.ArchiveGateEventOverride, From: now, To: &u}).Error; err != nil {
				return fmt.Errorf("archive gate: record the override of %s: %w", stream, err)
			}
		}
		key := ArchiveGateOverrideKey(stream)
		existing := models.SystemSetting{Key: key}
		if err := tx.FirstOrCreate(&existing, models.SystemSetting{Key: key}).Error; err != nil {
			return fmt.Errorf("upsert setting %q: %w", key, err)
		}
		existing.Value, existing.Type, existing.Category = val, "string", "archive"
		existing.Label = "Archive retention gate released until (set only by the re-authenticated override)"
		return tx.Save(&existing).Error
	})
}

// endArchiveGateEvents ends stream's events of kind that are still running
// at now (open, or ending later) at now.
func (d *Database) endArchiveGateEvents(tx *gorm.DB, stream, kind string, now time.Time) error {
	if err := tx.Model(&models.ArchiveGateEvent{}).Where("stream = ? AND kind = ? AND (to_ts IS NULL OR to_ts > ?)", stream, kind, now).
		Update("to_ts", now).Error; err != nil {
		return fmt.Errorf("archive gate: end the %s events of %s: %w", kind, stream, err)
	}
	return nil
}

// RecordArchiveGateState records, at the poller's start, whether each gate
// stream's deletes wait for the archive from now on: an enabled stream ends
// its open "disabled" interval; a disabled stream whose tables already have
// chunks (the archive had begun) opens one unless one is open. Deletes run in
// the poller, so its start is exactly when the switch takes effect.
//
// A disabled stream whose interval cannot be recorded is HELD: its deletes
// stay gated (as if it were enabled) until the record succeeds — retried by
// the delete paths at most once a minute, with the poller's start as the
// interval's start — so no row is deleted ungated without the seal knowing.
// An enabled stream whose open interval cannot be ended is only logged: the
// interval stays open, which marks months partial (the safe direction).
func (d *Database) RecordArchiveGateState(ctx context.Context) error {
	cfg, err := d.readArchiveGateConfig(ctx)
	if err != nil {
		// Unknown switches: both streams stay gated until a read succeeds,
		// and that read records the start then (archiveGateConfig) — even if
		// an earlier read (LogArchiveGateState) already filled the cache.
		if c := d.archiveGateCache; c != nil {
			c.mu.Lock()
			c.startupPending, c.ok = true, false
			c.readFailed(archiveGateClock(), err)
			c.mu.Unlock()
		}
		return fmt.Errorf("archive gate: %w", err)
	}
	if c := d.archiveGateCache; c != nil {
		c.mu.Lock()
		c.cfg, c.at, c.ok = cfg, archiveGateClock(), true
		c.observed, c.seeded, c.startupPending = cfg, true, false
		c.mu.Unlock()
	}
	return d.recordArchiveGateStartup(ctx, cfg, archiveGateClock().UTC())
}

// recordArchiveGateStartup is RecordArchiveGateState's recording for the
// switches cfg at now.
func (d *Database) recordArchiveGateStartup(ctx context.Context, cfg ArchiveGateConfig, now time.Time) error {
	var errs []error
	for _, stream := range ArchiveGateStreams {
		if cfg.enabled(stream) {
			if err := d.endArchiveGateEvents(d.db.WithContext(ctx), stream, models.ArchiveGateEventDisabled, now); err != nil {
				log.Printf("ERROR: archive gate: %v (the open \"disabled\" interval of %s stays open: its months are sealed partial)", err, stream)
				errs = append(errs, err)
			}
			continue
		}
		if err := d.recordArchiveDisabled(ctx, stream, now); err != nil {
			d.archiveHold.set(stream, now)
			log.Printf("ERROR: archive gate: %v — the deletes of %s stay GATED although its archiving is disabled, until it is recorded (retried every minute)", err, stream)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// recordArchiveDisabled opens stream's "disabled" interval at from, unless
// one is open or the stream has no chunk (the archive never began).
func (d *Database) recordArchiveDisabled(ctx context.Context, stream string, from time.Time) error {
	return recordArchiveDisabledTx(d.db.WithContext(ctx), stream, from)
}

// recordArchiveDisabledTx is recordArchiveDisabled in tx (the admin save
// records it in the transaction that turns the stream off).
func recordArchiveDisabledTx(tx *gorm.DB, stream string, from time.Time) error {
	var chunks, open int64
	if err := tx.Model(&models.ArchiveChunk{}).Where("table_name IN ?", archiveGateTables(stream)).Count(&chunks).Error; err != nil {
		return fmt.Errorf("record that %s is disabled: %w", stream, err)
	}
	if chunks == 0 {
		return nil
	}
	if err := tx.Model(&models.ArchiveGateEvent{}).Where("stream = ? AND kind = ? AND to_ts IS NULL", stream, models.ArchiveGateEventDisabled).
		Count(&open).Error; err != nil {
		return fmt.Errorf("record that %s is disabled: %w", stream, err)
	}
	if open > 0 {
		return nil
	}
	if err := tx.Create(&models.ArchiveGateEvent{Stream: stream, Kind: models.ArchiveGateEventDisabled, From: from}).Error; err != nil {
		return fmt.Errorf("record that %s is disabled: %w", stream, err)
	}
	return nil
}

// archiveHoldState is the disabled streams whose "disabled" interval is not
// recorded yet (stream → the poller's start), and when it was last tried.
type archiveHoldState struct {
	mu      sync.Mutex
	pending map[string]time.Time
	tried   map[string]time.Time
}

func (h *archiveHoldState) set(stream string, from time.Time) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == nil {
		h.pending, h.tried = map[string]time.Time{}, map[string]time.Time{}
	}
	h.pending[stream] = from
	h.tried[stream] = archiveGateClock()
}

// archiveHoldRetry is how often a held stream's record is retried.
const archiveHoldRetry = time.Minute

// archiveGateHeld reports whether disabled stream's deletes must stay gated
// because its "disabled" interval is not recorded yet; it retries the record
// (at most once a minute) and releases the hold once it succeeds.
func (d *Database) archiveGateHeld(stream string) bool {
	h := d.archiveHold
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	from, ok := h.pending[stream]
	if !ok {
		return false
	}
	now := archiveGateClock()
	if now.Sub(h.tried[stream]) < archiveHoldRetry {
		return true
	}
	h.tried[stream] = now
	if err := d.recordArchiveDisabled(context.Background(), stream, from); err != nil {
		log.Printf("ERROR: archive gate: %v — the deletes of %s stay GATED", err, stream)
		return true
	}
	delete(h.pending, stream)
	log.Printf("archive gate: recorded that %s is disabled since %s; its deletes are no longer gated", stream, from.UTC().Format(time.RFC3339))
	return false
}

// archiveGateActive reports whether stream's deletes go through the gate: its
// archiving is enabled, or it is held (archiveGateHeld).
func (d *Database) archiveGateActive(stream string) bool {
	return stream != "" && (d.archiveGateConfig().enabled(stream) || d.archiveGateHeld(stream))
}

// archiveGateCacheTTL is how long a resolved pair of stream switches is
// reused. The gate is consulted before every delete batch; the switches only
// change when an admin saves the archive settings, and this bounds how long
// the poller takes to notice (the save itself records a disabled interval at
// once; enabling only ever holds rows longer).
const archiveGateCacheTTL = 30 * time.Second

// archiveGateCacheState is the resolved stream switches (shared by pointer
// with every WithContext copy) and the switches the gate last acted on, so a
// change made on the admin page at runtime is recorded the way the poller's
// start records one (RecordArchiveGateState). nil (a Database{} literal, the
// test harness) resolves on every call and records no transition.
type archiveGateCacheState struct {
	mu  sync.Mutex
	cfg ArchiveGateConfig
	at  time.Time
	ok  bool
	// observed: the switches the transitions were last recorded for;
	// seeded once RecordArchiveGateState (or a first read) set it.
	observed ArchiveGateConfig
	seeded   bool
	// startupPending: RecordArchiveGateState could not read the switches;
	// both streams stay gated until a read succeeds and records the start.
	startupPending bool
	// failedAt: the last failed read (retried after archiveGateRetry);
	// lastErrLog rate-limits its log line.
	failedAt, lastErrLog time.Time
	// failingSince: the first of the failed reads in a row (zero after a
	// read succeeds), lastErr the latest one's error
	// (ArchiveGateReadHealth).
	failingSince time.Time
	lastErr      string
}

// readFailed records a failed read of the switches at now.
func (c *archiveGateCacheState) readFailed(now time.Time, err error) {
	if c.failingSince.IsZero() {
		c.failingSince = now
	}
	c.lastErr = err.Error()
	if len(c.lastErr) > archiveErrorMax {
		c.lastErr = c.lastErr[:archiveErrorMax]
	}
}

// readArchiveGateConfig resolves the two stream switches now: the admin
// setting when stored, else the environment's (archiveGateCfg). A stored
// switch that does not parse counts as ON for the gate (its deletes wait: the
// safe direction; the worker refuses the same value, so nothing is archived
// until it is fixed).
func (d *Database) readArchiveGateConfig(ctx context.Context) (ArchiveGateConfig, error) {
	cfg := d.archiveGateCfg
	var fields []config.ArchiveField
	for _, env := range []string{"ARCHIVE_SYSLOG_ENABLED", "ARCHIVE_FLOWS_ENABLED"} {
		f, _ := config.ArchiveFieldByEnv(env)
		fields = append(fields, f)
	}
	vals, _, err := d.archiveSettingValues(ctx, fields)
	if err != nil {
		return cfg, err
	}
	for _, f := range fields {
		raw, ok := vals[f.Env]
		if !ok {
			continue
		}
		v, set, perr := config.ParseArchiveValue(f, raw)
		if !set && perr == nil {
			continue
		}
		on := perr != nil || v == "true"
		if perr != nil {
			log.Printf("WARNING: archive gate: %v (stored on the admin page); its deletes stay gated until it is fixed", perr)
		}
		if f.Env == "ARCHIVE_SYSLOG_ENABLED" {
			cfg.Syslog = on
		} else {
			cfg.Flows = on
		}
	}
	return cfg, nil
}

// archiveGateConfig returns the stream switches in effect, re-resolved at
// most every archiveGateCacheTTL. When the switches differ from the ones last
// acted on it records the change before returning — a stream turned on ends
// its open "disabled" interval, a stream turned off opens one (or is held,
// archiveGateHeld, until that succeeds) — so a delete is never ungated
// without the seal knowing. A failed read keeps the last switches, or before
// any read gates both streams (fails closed).
func (d *Database) archiveGateConfig() ArchiveGateConfig {
	c := d.archiveGateCache
	now := archiveGateClock()
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.ok && !now.Before(c.at) && now.Sub(c.at) < archiveGateCacheTTL {
			return c.cfg
		}
		// A failed read is retried at most every archiveGateRetry, not
		// before every delete batch.
		if !c.failedAt.IsZero() && !now.Before(c.failedAt) && now.Sub(c.failedAt) < archiveGateRetry {
			return c.failedResult()
		}
	}
	cfg, err := d.readArchiveGateConfig(context.Background())
	if err != nil {
		if c == nil {
			log.Printf("archive gate: %v (deletes of the archived tables wait until it can be read)", err)
			return ArchiveGateConfig{Syslog: true, Flows: true}
		}
		if c.failedAt.IsZero() || now.Sub(c.lastErrLog) >= time.Minute {
			c.lastErrLog = now
			log.Printf("archive gate: %v (deletes of the archived tables wait until it can be read)", err)
		}
		c.failedAt = now
		c.readFailed(now, err)
		return c.failedResult()
	}
	if c == nil {
		return cfg
	}
	c.failedAt, c.failingSince, c.lastErr = time.Time{}, time.Time{}, ""
	switch {
	case c.startupPending:
		// The poller's start could not read the switches: record it now.
		if err := d.recordArchiveGateStartup(context.Background(), cfg, now.UTC()); err != nil {
			log.Printf("archive gate: record the start: %v", err)
		}
		c.startupPending = false
	case c.seeded:
		for _, stream := range ArchiveGateStreams {
			if cfg.enabled(stream) != c.observed.enabled(stream) {
				d.recordArchiveGateSwitch(stream, cfg.enabled(stream), now.UTC())
			}
		}
	}
	c.cfg, c.at, c.ok = cfg, now, true
	c.observed, c.seeded = cfg, true
	return cfg
}

// ArchiveGateHealthKey is the system setting the poller records the retention
// gate's reads of the stream switches in (JSON, ArchiveGateHealth) on its
// server-health tick, so the status card in the API process can show a gate
// that cannot read them.
const ArchiveGateHealthKey = "archive_gate_health"

// ArchiveGateHealth is whether the retention gate can read the archive's
// stream switches. FailingSince: the first failed read in a row (nil while
// they succeed); HoldingAll: meanwhile both streams' deletes wait (no read
// has succeeded since the poller started) — otherwise the gate keeps the
// switches it read last.
type ArchiveGateHealth struct {
	SeenAt       time.Time  `json:"seen_at"`
	FailingSince *time.Time `json:"failing_since,omitempty"`
	Error        string     `json:"error,omitempty"`
	HoldingAll   bool       `json:"holding_all,omitempty"`
}

// ArchiveGateReadHealth reads the stream switches as the gate does (at most
// once per archiveGateCacheTTL, or archiveGateRetry after a failure — a read
// now, when due, keeps the answer current although no delete ran) and
// reports whether the gate can read them. Only the process that runs the
// deletes (the poller) has a meaningful answer.
func (d *Database) ArchiveGateReadHealth(now time.Time) ArchiveGateHealth {
	h := ArchiveGateHealth{SeenAt: now.UTC()}
	c := d.archiveGateCache
	if c == nil {
		return h
	}
	d.archiveGateConfig()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.failingSince.IsZero() {
		t := c.failingSince.UTC()
		h.FailingSince, h.Error = &t, c.lastErr
		h.HoldingAll = !c.ok || c.startupPending
	}
	return h
}

// SaveArchiveGateHealth stores the poller's record of the gate's reads.
func (d *Database) SaveArchiveGateHealth(ctx context.Context, h ArchiveGateHealth) error {
	js, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return d.WithContext(ctx).UpsertSetting(&models.SystemSetting{
		Key: ArchiveGateHealthKey, Value: string(js), Type: "json", Category: "archive",
		Label: "Archive retention gate: reads of the stream switches (written by the poller)",
	})
}

// ArchiveGateHealthRecord reads the poller's record (nil when none was
// written, or it does not parse).
func (d *Database) ArchiveGateHealthRecord(ctx context.Context) (*ArchiveGateHealth, error) {
	var vals []string
	if err := d.db.WithContext(ctx).Model(&models.SystemSetting{}).Where("\"key\" = ?", ArchiveGateHealthKey).
		Limit(1).Pluck("value", &vals).Error; err != nil {
		return nil, err
	}
	if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
		return nil, nil
	}
	var h ArchiveGateHealth
	if err := json.Unmarshal([]byte(vals[0]), &h); err != nil {
		return nil, nil
	}
	return &h, nil
}

// archiveGateRetry is how soon a failed read of the switches is retried.
const archiveGateRetry = 5 * time.Second

// failedResult is what the gate uses while the switches cannot be read: the
// last switches read, or — before any read, or while the poller's start is
// still unrecorded — both streams gated.
func (c *archiveGateCacheState) failedResult() ArchiveGateConfig {
	if c.ok && !c.startupPending {
		return c.cfg
	}
	return ArchiveGateConfig{Syslog: true, Flows: true}
}

// recordArchiveGateSwitch records a stream switched on or off while the
// process runs, as RecordArchiveGateState does at the poller's start.
func (d *Database) recordArchiveGateSwitch(stream string, enabled bool, now time.Time) {
	if enabled {
		log.Printf("archive gate: archiving of %s switched on: its deletes wait for the archive from now on", stream)
		if err := d.endArchiveGateEvents(d.db, stream, models.ArchiveGateEventDisabled, now); err != nil {
			log.Printf("ERROR: archive gate: %v (the open \"disabled\" interval of %s stays open: its months are sealed partial)", err, stream)
		}
		return
	}
	log.Printf("WARNING: archiving of %s switched off: its retention, aggregation and rollup deletes are no longer gated on the archive", stream)
	if err := d.recordArchiveDisabled(context.Background(), stream, now); err != nil {
		d.archiveHold.set(stream, now)
		log.Printf("ERROR: archive gate: %v — the deletes of %s stay GATED until it is recorded (retried every minute)", err, stream)
	}
}

// ArchiveGateEventsOverlapping returns the events of gate stream that overlap
// [from, to), oldest first.
func (d *Database) ArchiveGateEventsOverlapping(ctx context.Context, stream string, from, to time.Time) ([]models.ArchiveGateEvent, error) {
	var evs []models.ArchiveGateEvent
	err := d.db.WithContext(ctx).Where("stream = ? AND from_ts < ? AND (to_ts IS NULL OR to_ts > ?)", stream, to, from).
		Order("from_ts, id").Find(&evs).Error
	return evs, err
}

// ArchiveGateStreamOfTable is the gate stream of a raw table ("" when the
// table is not archived).
func ArchiveGateStreamOfTable(table string) string { return archiveGateStream(table) }

// ArchiveGateOverride reports stream's override at now: the end instant, and
// whether it is active.
func (d *Database) ArchiveGateOverride(stream string, now time.Time) (until time.Time, active bool) {
	return d.archiveGateOverrideUntil(stream, now)
}

// ErrArchiveChunkNotParked: the chunk to reset is not in needs_attention.
var ErrArchiveChunkNotParked = errors.New("archive: the chunk is not in needs_attention")

// ErrArchiveChunkSealed: the chunk to reset belongs to a sealed month. Its
// folder takes no further write, so a re-export could only be refused and
// parked again; see docs/OPERATIONS.md "Raw archive: the monthly seal".
var ErrArchiveChunkSealed = errors.New("archive: the chunk belongs to a sealed month, whose folder is never written again; it does not hold the retention gate (see docs/OPERATIONS.md, the monthly seal)")

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
// ErrArchiveChunkNotParked, an unknown id gorm.ErrRecordNotFound, a chunk of
// a sealed month ErrArchiveChunkSealed. Attempts are kept (history).
func (d *Database) ResetArchiveChunk(ctx context.Context, id uint, note string, at time.Time) (*models.ArchiveChunk, error) {
	if len(note) > archiveErrorMax {
		note = note[:archiveErrorMax]
	}
	c, err := d.GetArchiveChunk(id)
	if err != nil {
		return nil, err
	}
	if sealed, err := d.archiveChunkMonthSealed(ctx, c); err != nil {
		return nil, err
	} else if sealed {
		return c, ErrArchiveChunkSealed
	}
	res := d.db.WithContext(ctx).Model(&models.ArchiveChunk{}).
		Where("id = ? AND status = ?", id, models.ArchiveChunkNeedsAttention).
		Updates(map[string]interface{}{"status": models.ArchiveChunkPending, "mismatches": 0, "verify_failures": 0,
			"runner_id": "", "error": note, "updated_at": at})
	if res.Error != nil {
		return nil, res.Error
	}
	if c, err = d.GetArchiveChunk(id); err != nil {
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
			case d.archiveGateConfig().enabled(stream):
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

// Unattached leaves (partition maintenance racing the archive).
//
// When the DEFAULT child already holds rows for a leaf EnsurePartitions is
// about to create, ensureLeaf creates the leaf as a STANDALONE table, moves
// those rows into it in committed batches and only then attaches it — and a
// failed attach leaves them there until the next pass. Meanwhile the rows are
// invisible to every read through the parent: an export would miss them and,
// worse, a count check run then would agree with that export, so a chunk could
// be verified without them and, once the leaf is attached, the gate would
// delete them unarchived. So, per table, while any unattached leaf exists or a
// move started during a count:
//   - the worker does not cut, export or verify (ErrArchiveLeafMove — a
//     transient wait, never a mismatch);
//   - CheckArchiveChunkCount reads the move epoch before and after its count
//     and refuses when it moved (a move that began and ended in between);
//   - the gate holds every row of the table (V = 0).

// ErrArchiveLeafMove: partition maintenance is moving rows of the table
// through a standalone leaf, so its rows cannot all be seen through the
// parent right now.
var ErrArchiveLeafMove = errors.New("archive: a partition leaf of the table is not attached (rows are being moved out of the DEFAULT child)")

// archiveLeafMovePrefix + table is the system_settings counter ensureLeaf
// increments before it starts moving rows into a standalone leaf.
const archiveLeafMovePrefix = "archive_leaf_move_epoch_"

// archiveLeafState is the table's move epoch and its unattached leaves.
type archiveLeafState struct {
	epoch      int64
	unattached []string
}

// archiveLeafStateOf reads it (PostgreSQL only; zero elsewhere). A leaf is a
// table named <table>_YYYYMM or <table>_YYYYMMDD; one that pg_inherits does
// not list as a partition is unattached.
func (d *Database) archiveLeafStateOf(ctx context.Context, table string) (archiveLeafState, error) {
	var s archiveLeafState
	if !d.dialect.IsPostgres() {
		return s, nil
	}
	db := d.db.WithContext(ctx)
	// The epoch FIRST, then the leaves. ensureLeaf commits the bump before it
	// creates the standalone leaf, so a move that begins between the two
	// reads is seen either as the leaf (still unattached) or, once attached,
	// as a changed epoch at the caller's next read. Read the other way round,
	// a move could start after the leaf query and finish before the next
	// one, with its bump already in the epoch read here — invisible.
	var vals []string
	if err := db.Model(&models.SystemSetting{}).Where("\"key\" = ?", archiveLeafMovePrefix+table).Limit(1).Pluck("value", &vals).Error; err != nil {
		return s, fmt.Errorf("archive: leaf move epoch of %s: %w", table, err)
	}
	if len(vals) > 0 {
		fmt.Sscan(vals[0], &s.epoch) //nolint:errcheck // unparseable reads as 0; only a change matters
	}
	if archiveLeafReadHook != nil {
		archiveLeafReadHook(table)
	}
	if err := db.Raw(`SELECT c.relname FROM pg_class c
		WHERE c.relkind IN ('r', 'p') AND c.relnamespace = current_schema()::regnamespace
		  AND c.relname ~ ('^' || ? || '_[0-9]{6}([0-9]{2})?$')
		  AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid)
		ORDER BY c.relname`, table).Scan(&s.unattached).Error; err != nil {
		return s, fmt.Errorf("archive: unattached leaves of %s: %w", table, err)
	}
	return s, nil
}

// archiveLeafReadHook, when non-nil, runs between the epoch read and the leaf
// query of archiveLeafStateOf (test seam: a move racing the read). Never set
// in production.
var archiveLeafReadHook func(table string)

// ArchiveLeafEpoch returns table's partition-move epoch, or an error wrapping
// ErrArchiveLeafMove while a leaf of it is unattached. The archive worker
// reads it around an export: a changed epoch means a move ran meanwhile and
// the export may lack rows — a reason to wait and export again, never a
// mismatch.
func (d *Database) ArchiveLeafEpoch(ctx context.Context, table string) (int64, error) {
	s, err := d.archiveLeafsClear(ctx, table)
	return s.epoch, err
}

// archiveLeafsClear returns ErrArchiveLeafMove (naming the leaves) while table
// has an unattached leaf.
func (d *Database) archiveLeafsClear(ctx context.Context, table string) (archiveLeafState, error) {
	s, err := d.archiveLeafStateOf(ctx, table)
	if err != nil {
		return s, err
	}
	if len(s.unattached) > 0 {
		return s, fmt.Errorf("%w: %s", ErrArchiveLeafMove, strings.Join(s.unattached, ", "))
	}
	return s, nil
}

// bumpArchiveLeafMoveEpoch is called by ensureLeaf before it moves any row
// into a standalone leaf of table; an error stops the move (fail closed).
func (d *Database) bumpArchiveLeafMoveEpoch(table string) error {
	return d.db.Exec(`INSERT INTO system_settings ("key", value, type, category, label, updated_at)
		VALUES (?, '1', 'int', 'archive', 'Partition leaf moves started (the raw archive pauses while one runs)', now())
		ON CONFLICT ("key") DO UPDATE SET value = (COALESCE(NULLIF(system_settings.value, ''), '0')::bigint + 1)::text, updated_at = now()`,
		archiveLeafMovePrefix+table).Error
}
