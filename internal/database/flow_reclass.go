package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// Reclassifying stored flow history.
//
// Direction and service port are stamped at ingest (classify.InternalSet,
// classify.ServicePort), and every row records the classification revision it
// was made under (class_rev). When the operator's networks change — or when
// history predates them — rows carry an old revision. This job walks both flow
// tables and re-stamps every row whose class_rev is below the target, with the
// SAME Go classifier ingest uses, so history and new traffic cannot disagree.
//
// It runs from the poller a couple of minutes per rollup tick and resumes from
// a persisted state, so a restart or a deploy loses nothing. Correctness rests
// on four facts:
//   - rows are immutable in every column the classifier reads, and the write is
//     conditional on class_rev < target, so read-classify-write per slice needs
//     no lock: a promotion that deletes the row first simply wins;
//   - promotion inserts only at new ids and carries its sources' class_rev, so
//     an old-revision row can only appear ABOVE ids already walked;
//   - termination is decided by a count taken while holding the maintenance
//     lock, which the rollup tick and retention also take, so no promotion is
//     in flight while it runs;
//   - the target is pinned for a whole run; if it moves, the run restarts.

// Settings the job keeps. None is user-editable (none is in allowedKeys).
const (
	FlowReclassDoneRevKey          = "flow_reclass_done_rev"
	FlowReclassStatusKey           = "flow_reclass_status"
	FlowReclassRearmKey            = "flow_reclass_rearm"
	flowReclassStateKey            = "flow_reclass_state"
	flowReclassRollupFloorKey      = "flow_reclass_rollup_floor"
	flowReclassSamplesProbeKey     = "flow_reclass_samples_probe_id"
	flowReclassRollupsProbeKey     = "flow_reclass_rollups_probe_id"
	flowReclassVerifyTimeoutsKey   = "flow_reclass_verify_timeouts"
	flowSummaryRecomputeRequestKey = "flow_summary_recompute_request"
)

const (
	reclassTableSamples = "flow_samples"
	reclassTableRollups = "flow_rollups"
	reclassPhaseVerify  = "verify"
)

// Tunables, package vars so tests can shrink them.
var (
	// reclassSliceLimit is how many rows one slice reads and writes.
	reclassSliceLimit = 50000
	// reclassInitialWindow is the first id span a slice may cover. The id
	// space is sparse — on production flow_rollups spans 2.8x its row count,
	// because promotion consumes ids — so a slice covers about twice the ids
	// it expects rows. The window adapts: it widens over sparse stretches and
	// narrows when a read times out.
	reclassInitialWindow int64 = 280000
	reclassMaxWindow     int64 = 5_000_000
	// reclassWriteFloor is the smallest write batch a timed-out write is
	// split down to.
	reclassWriteFloor = 1000
	// reclassInterSliceSleep paces full slices beside live ingest.
	reclassInterSliceSleep = 200 * time.Millisecond
	// reclassVerifyRange is the id span one verification statement counts.
	reclassVerifyRange int64 = 20_000_000
	// reclassMaxVerifyRounds bounds verify -> re-pass -> verify per step: each
	// verification is a whole-table count under the maintenance lock.
	reclassMaxVerifyRounds = 2
	// reclassDiskMinFree pauses the job below this fraction of free space.
	reclassDiskMinFree = 0.15
	// reclassDiskStale: a server_metrics row older than this is not trusted.
	reclassDiskStale = 15 * time.Minute
	// reclassLockRetries / reclassLockRetrySleep mirror the retention batch
	// delete for a slice that meets a row lock or a deadlock.
	reclassLockRetries    = 10
	reclassLockRetrySleep = time.Second

	// Test seams.
	reclassSleep      = time.Sleep
	reclassReadHook   func(table string, lo, hi int64) error
	reclassWriteHook  func(table string, n int) error
	reclassVerifyHook func()
	// reclassRearmReadHook runs between reading the re-arm mark and deleting
	// it — the window a concurrent API write can land in.
	reclassRearmReadHook func()
)

// ErrReclassRevLimit is returned when the target revision cannot be raised.
var ErrReclassRevLimit = errors.New("the classification revision limit (65535) is reached")

// reclassState is the persisted progress of one run.
type reclassState struct {
	Rev   uint16 `json:"rev"`
	Phase string `json:"phase"` // flow_samples, flow_rollups, verify
	// Cursor is the last id walked in the current table; PassMax the table's
	// MAX(id) captured when the pass began (0 = not captured yet).
	Cursor  int64 `json:"cursor"`
	PassMax int64 `json:"pass_max"`
	// Floor: flow_rollups ids at or below it are known reclassified (an
	// incremental run); 0 for a full run.
	Floor int64 `json:"floor"`
	// SamplesPassMax is the samples walk's pass-start MAX, for the rev-0
	// stall check (ids, never collector timestamps).
	SamplesPassMax int64 `json:"samples_pass_max"`
	// SamplesMaxLocked is flow_samples' MAX(id) read under the lock by the
	// last clean samples verification; it seeds the samples probe.
	SamplesMaxLocked int64      `json:"samples_max_locked"`
	MinRollupTS      *time.Time `json:"min_rollup_ts,omitempty"`
	Incremental      bool       `json:"incremental"`
	// RePass: the current table walk is a re-pass seeded by verification, so
	// it returns straight to verification — a samples re-pass must not fall
	// through into another walk of flow_rollups.
	RePass   bool      `json:"repass"`
	Started  time.Time `json:"started"`
	Rows     int64     `json:"rows"`
	Updated  int64     `json:"updated"`
	Estimate int64     `json:"estimate"`
	Window   int64     `json:"window"`
}

// FlowReclassStatus is what the status endpoint and the pages show.
type FlowReclassStatus struct {
	// Rev is the revision the run that wrote this status works on; a status
	// of an older revision says nothing about the current target.
	Rev          uint16     `json:"rev"`
	Phase        string     `json:"phase"` // reclassifying, paused, waiting, done
	Table        string     `json:"table,omitempty"`
	Rows         int64      `json:"rows"`
	Updated      int64      `json:"updated"`
	Estimate     int64      `json:"estimate"`
	Incremental  bool       `json:"incremental"`
	Started      *time.Time `json:"started,omitempty"`
	Finished     *time.Time `json:"finished,omitempty"`
	PausedReason string     `json:"paused_reason,omitempty"`
	VacuumHint   bool       `json:"vacuum_hint,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// FlowReclassDoneRev is the last revision a run completed.
func (d *Database) FlowReclassDoneRev() uint16 {
	raw, ok := d.GetSettingValue(FlowReclassDoneRevKey)
	if !ok {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < 0 || v > 65535 {
		return 0
	}
	return uint16(v)
}

// GetFlowReclassStatus returns the last written status (zero value when none).
func (d *Database) GetFlowReclassStatus() FlowReclassStatus {
	var st FlowReclassStatus
	if raw, ok := d.GetSettingValue(FlowReclassStatusKey); ok {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	return st
}

// MarkFlowReclassRearm records that the API stamped rows with revision 0
// because no internal-network set was loaded. The value is unique per write,
// so the poller's conditional delete never removes a newer mark written
// between its read and its delete.
func (d *Database) MarkFlowReclassRearm() error {
	host, _ := os.Hostname()
	return d.UpsertSetting(&models.SystemSetting{
		Key:      FlowReclassRearmKey,
		Value:    fmt.Sprintf("%s:%d:%d", host, os.Getpid(), time.Now().UnixNano()),
		Category: "system", Type: "string",
	})
}

// BumpFlowReclassTargetRev raises the target revision by one with a
// compare-and-swap, identical on both dialects, and returns the new value. An
// absent or unparseable value counts as 1. At 65535 it refuses: a wrap to 1
// would leave rows with class_rev above the target that nothing revisits.
func (d *Database) BumpFlowReclassTargetRev() (uint16, error) {
	for attempt := 0; attempt < 5; attempt++ {
		var row models.SystemSetting
		err := d.db.Where(`"key" = ?`, FlowReclassTargetRevKey).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			cErr := d.db.Create(&models.SystemSetting{Key: FlowReclassTargetRevKey, Value: "2", Category: "system", Type: "number"}).Error
			if cErr == nil {
				return 2, nil
			}
			if !IsUniqueViolation(cErr) {
				return 0, cErr
			}
			continue // created concurrently: fall into the swap
		}
		if err != nil {
			return 0, err
		}
		cur := parseTargetRev(row.Value)
		if cur == 65535 {
			return 0, ErrReclassRevLimit
		}
		next := cur + 1
		res := d.db.Model(&models.SystemSetting{}).
			Where(`"key" = ? AND value = ?`, FlowReclassTargetRevKey, row.Value).
			Update("value", strconv.Itoa(int(next)))
		if res.Error != nil {
			return 0, res.Error
		}
		if res.RowsAffected == 1 {
			return next, nil
		}
	}
	return 0, errors.New("the classification revision changed concurrently; try again")
}

func (d *Database) loadReclassState() (reclassState, bool) {
	var st reclassState
	raw, ok := d.GetSettingValue(flowReclassStateKey)
	if !ok || raw == "" || json.Unmarshal([]byte(raw), &st) != nil || st.Rev == 0 {
		return reclassState{}, false
	}
	return st, true
}

func (d *Database) saveReclassState(st reclassState) error {
	b, _ := json.Marshal(st)
	return d.UpsertSetting(&models.SystemSetting{Key: flowReclassStateKey, Value: string(b), Category: "system", Type: "string"})
}

func (d *Database) setReclassSetting(key, value string) error {
	return d.UpsertSetting(&models.SystemSetting{Key: key, Value: value, Category: "system", Type: "string"})
}

func (d *Database) writeReclassStatus(st reclassState, phase, reason string, finished bool) {
	s := FlowReclassStatus{
		Rev: st.Rev, Phase: phase, Rows: st.Rows, Updated: st.Updated, Estimate: st.Estimate,
		Incremental: st.Incremental, PausedReason: reason, UpdatedAt: time.Now().UTC(),
	}
	if st.Phase == reclassTableSamples || st.Phase == reclassTableRollups {
		s.Table = st.Phase
	}
	if !st.Started.IsZero() {
		started := st.Started.UTC()
		s.Started = &started
	}
	if finished {
		now := time.Now().UTC()
		s.Finished = &now
		// A full reclass rewrites every row (~141M in-place updates on
		// production, 2026-09-28). Autovacuum usually keeps up (flow_rollups
		// has a 0.01 scale factor), but a one-off VACUUM (ANALYZE) afterwards
		// refreshes statistics and the visibility map without waiting on it.
		s.VacuumHint = !st.Incremental && st.Updated > 0
	}
	b, _ := json.Marshal(s)
	if err := d.setReclassSetting(FlowReclassStatusKey, string(b)); err != nil {
		log.Printf("Flow reclassification: status write failed: %v", err)
	}
}

// reclassDiskFree reads the newest server_metrics row: the database volume
// when it was probed, else the root volume (meaningful only when PostgreSQL
// shares it). ok is false when nothing recent is known — the job then
// proceeds rather than stalling on a missing metric.
func (d *Database) reclassDiskFree() (free float64, ok bool) {
	var m models.ServerMetric
	if err := d.db.Order("timestamp DESC").First(&m).Error; err != nil {
		return 0, false
	}
	if time.Since(m.Timestamp) > reclassDiskStale {
		return 0, false
	}
	if m.DataDiskPercent != nil {
		return 1 - *m.DataDiskPercent/100, true
	}
	if m.RootDiskPercent > 0 {
		return 1 - m.RootDiskPercent/100, true
	}
	return 0, false
}

// reclassEstimate is a cheap row estimate for the progress percentage: the
// planner's reltuples on PostgreSQL (summed over a partitioned table's
// leaves), COUNT(*) on SQLite.
func (d *Database) reclassEstimate(table string, aboveID int64) int64 {
	if !d.dialect.IsPostgres() || aboveID > 0 {
		var n int64
		d.db.Table(table).Where("id > ?", aboveID).Count(&n)
		return n
	}
	var n float64
	d.db.Raw(`SELECT COALESCE(SUM(GREATEST(c.reltuples, 0)), 0)::float8 FROM pg_class c
		WHERE c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = to_regclass(?))
		   OR (c.oid = to_regclass(?) AND NOT EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent = to_regclass(?)))`,
		table, table, table).Scan(&n)
	return int64(n)
}

func (d *Database) tableMaxID(table string) (int64, error) {
	var mx int64
	err := d.db.Table(table).Select("COALESCE(MAX(id), 0)").Scan(&mx).Error
	return mx, err
}

// reclassWanted decides whether an idle job has anything to do: a re-arm mark
// from the API (consumed when the run starts, in newReclassRun). Failing that, each
// table is probed for old-revision rows above the id it was last checked to:
// MAX(id) is read FIRST, so a row inserted between the probe and the advance
// can never be skipped. Probing both tables makes the order against promotion
// irrelevant — a stale sample already promoted is found in flow_rollups.
func (d *Database) reclassWanted(target uint16) (bool, error) {
	if tok, ok := d.GetSettingValue(FlowReclassRearmKey); ok && tok != "" {
		log.Printf("Flow reclassification: the API stamped flows before its internal networks loaded; re-checking recent history")
		return true, nil
	}
	found := false
	for _, p := range []struct{ table, key string }{
		{reclassTableSamples, flowReclassSamplesProbeKey},
		{reclassTableRollups, flowReclassRollupsProbeKey},
	} {
		mx, err := d.tableMaxID(p.table)
		if err != nil {
			return false, err
		}
		from := int64(d.GetIntSetting(p.key, 0))
		if mx <= from {
			continue
		}
		var ids []int64
		if err := d.db.Table(p.table).Where("id > ? AND id <= ? AND class_rev < ?", from, mx, target).
			Limit(1).Pluck("id", &ids).Error; err != nil {
			return false, err
		}
		if len(ids) > 0 {
			found = true
		}
		if err := d.setReclassSetting(p.key, strconv.FormatInt(mx, 10)); err != nil {
			return false, err
		}
	}
	return found, nil
}

// reclassRow is one row of a slice.
type reclassRow struct {
	ID          int64
	Timestamp   time.Time
	Protocol    uint8
	SrcAddr     string
	DstAddr     string
	SrcPort     uint16
	DstPort     uint16
	ServicePort uint16
}

func (d *Database) reclassReadSlice(table string, lo, hi int64, rev uint16) ([]reclassRow, error) {
	if reclassReadHook != nil {
		if err := reclassReadHook(table, lo, hi); err != nil {
			return nil, err
		}
	}
	cols := "id, timestamp, protocol, src_addr, dst_addr, src_port, dst_port, service_port"
	if table == reclassTableRollups {
		cols = "id, timestamp, protocol, src_addr, dst_addr, 0 AS src_port, dst_port, service_port"
	}
	var rows []reclassRow
	err := d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			if e := tx.Exec("SET LOCAL statement_timeout = '120s'").Error; e != nil {
				return e
			}
		}
		return tx.Table(table).Select(cols).
			Where("id > ? AND id <= ? AND class_rev < ?", lo, hi, rev).
			Order("id").Limit(reclassSliceLimit).Scan(&rows).Error
	})
	return rows, err
}

// reclassUpdate is one row's new classification.
type reclassUpdate struct {
	id  int64
	dir uint8
	svc uint16
}

// reclassWrite stamps a slice's rows. One statement per batch on PostgreSQL:
// the arrays travel as array-literal STRINGS (GORM would expand a Go slice
// into a list), and the id range keeps the plan a bounded index range scan
// whatever the unnest estimate. A batch that times out is split in half down
// to reclassWriteFloor; a lock timeout or deadlock is retried as retention's
// batch delete does.
func (d *Database) reclassWrite(table string, rev uint16, ups []reclassUpdate) (int64, error) {
	if len(ups) == 0 {
		return 0, nil
	}
	for retries := 0; ; retries++ {
		n, err := d.reclassWriteOnce(table, rev, ups)
		switch {
		case err == nil:
			return n, nil
		case sqlState(err) == "57014" && len(ups) > reclassWriteFloor:
			mid := len(ups) / 2
			log.Printf("Flow reclassification: a %d-row write to %s timed out; splitting it", len(ups), table)
			a, e := d.reclassWrite(table, rev, ups[:mid])
			if e != nil {
				return a, e
			}
			b, e := d.reclassWrite(table, rev, ups[mid:])
			return a + b, e
		case lockRetryable(err) && retries < reclassLockRetries:
			reclassSleep(reclassLockRetrySleep * time.Duration(1+retries%5))
			continue
		default:
			return 0, err
		}
	}
}

// reclassWriteOnce returns how many rows it actually re-stamped: a row that a
// promotion or retention deleted since the read is not counted.
func (d *Database) reclassWriteOnce(table string, rev uint16, ups []reclassUpdate) (int64, error) {
	if reclassWriteHook != nil {
		if err := reclassWriteHook(table, len(ups)); err != nil {
			return 0, err
		}
	}
	var affected int64
	err := d.db.Transaction(func(tx *gorm.DB) error {
		if !d.dialect.IsPostgres() {
			for _, u := range ups {
				res := tx.Exec("UPDATE "+table+" SET direction = ?, service_port = ?, class_rev = ? WHERE id = ? AND class_rev < ?",
					u.dir, u.svc, rev, u.id, rev)
				if res.Error != nil {
					return res.Error
				}
				affected += res.RowsAffected
			}
			return nil
		}
		if err := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; err != nil {
			return err
		}
		if err := tx.Exec("SET LOCAL statement_timeout = '120s'").Error; err != nil {
			return err
		}
		var ids, dirs, svcs strings.Builder
		ids.WriteByte('{')
		dirs.WriteByte('{')
		svcs.WriteByte('{')
		lo, hi := ups[0].id, ups[0].id
		for i, u := range ups {
			if i > 0 {
				ids.WriteByte(',')
				dirs.WriteByte(',')
				svcs.WriteByte(',')
			}
			ids.WriteString(strconv.FormatInt(u.id, 10))
			dirs.WriteString(strconv.Itoa(int(u.dir)))
			svcs.WriteString(strconv.Itoa(int(u.svc)))
			lo, hi = min(lo, u.id), max(hi, u.id)
		}
		ids.WriteByte('}')
		dirs.WriteByte('}')
		svcs.WriteByte('}')
		res := tx.Exec("UPDATE "+table+` AS r SET direction = v.d, service_port = v.s, class_rev = ?
			FROM unnest(?::bigint[], ?::smallint[], ?::integer[]) AS v(id, d, s)
			WHERE r.id = v.id AND r.id >= ? AND r.id <= ? AND r.class_rev < ?`,
			rev, ids.String(), dirs.String(), svcs.String(), lo, hi, rev)
		affected = res.RowsAffected
		return res.Error
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// reclassClassify computes the new classification of a slice with the ingest
// classifier. flow_rollups keep no source port: a service port already
// recorded (every row since v0.11.263) is exact and kept; a zero is inferred
// from the destination port alone.
func reclassClassify(table string, set *classify.InternalSet, rows []reclassRow) []reclassUpdate {
	ups := make([]reclassUpdate, len(rows))
	for i, r := range rows {
		svc := classify.ServicePort(r.Protocol, r.SrcPort, r.DstPort)
		if table == reclassTableRollups {
			svc = r.ServicePort
			if svc == 0 {
				svc = classify.ServicePortFromDst(r.Protocol, r.DstPort)
			}
		}
		ups[i] = reclassUpdate{id: r.ID, dir: set.Direction(r.SrcAddr, r.DstAddr), svc: svc}
	}
	return ups
}

// reclassVerifyResult is one locked verification of one table.
type reclassVerifyResult struct {
	acquired     bool
	count        int64
	minID, maxID int64 // of the old-revision rows
	tableMax     int64 // MAX(id) of the whole table, read under the lock
}

// reclassVerify counts old-revision rows above floor while holding the
// maintenance lock as a transaction-level lock (the rollup tick and retention
// take the same key as a session lock; PostgreSQL keeps both in one lock
// space), so no promotion is in flight during the count.
func (d *Database) reclassVerify(table string, floor int64, rev uint16, timeout string) (reclassVerifyResult, error) {
	var res reclassVerifyResult
	err := d.db.Transaction(func(tx *gorm.DB) error {
		if d.dialect.IsPostgres() {
			var got bool
			if e := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", int64(maintenanceLockKey)).Scan(&got).Error; e != nil {
				return e
			}
			if !got {
				return nil
			}
			if e := tx.Exec("SET LOCAL statement_timeout = '" + timeout + "'").Error; e != nil {
				return e
			}
		}
		res.acquired = true
		if e := tx.Table(table).Select("COALESCE(MAX(id), 0)").Scan(&res.tableMax).Error; e != nil {
			return e
		}
		// Counted in primary-key ranges, each its own statement under the
		// timeout: a slow disk then costs one range, not one statement over
		// the whole table. The lock is held for the whole transaction, so no
		// promotion can slip in between ranges.
		// Start at the lowest live id: flow_samples keeps only about an hour
		// of rows while its sequence runs far ahead, so ranges from 0 would
		// mostly count empty id space.
		var first int64
		if e := tx.Table(table).Select("COALESCE(MIN(id), 0)").Where("id > ?", floor).Scan(&first).Error; e != nil {
			return e
		}
		if first == 0 {
			return nil
		}
		for lo := first - 1; lo < res.tableMax; lo += reclassVerifyRange {
			var agg struct {
				N    int64
				MinI int64
				MaxI int64
			}
			if e := tx.Table(table).Select("COUNT(*) AS n, COALESCE(MIN(id), 0) AS min_i, COALESCE(MAX(id), 0) AS max_i").
				Where("id > ? AND id <= ? AND class_rev < ?", lo, lo+reclassVerifyRange, rev).Scan(&agg).Error; e != nil {
				return e
			}
			if agg.N == 0 {
				continue
			}
			if res.count == 0 || agg.MinI < res.minID {
				res.minID = agg.MinI
			}
			res.maxID = max(res.maxID, agg.MaxI)
			res.count += agg.N
		}
		return nil
	})
	return res, err
}

// RunFlowReclassStep advances the reclassification job for at most budget.
// setFor builds the classifier for a revision (the poller loads the operator's
// networks); a failure skips the step — a set built from defaults alone must
// never be stamped with the current revision.
func (d *Database) RunFlowReclassStep(setFor func(rev uint16) (*classify.InternalSet, error), budget time.Duration) error {
	deadline := time.Now().Add(budget)
	target := d.FlowReclassTargetRev()
	st, running := d.loadReclassState()

	if !running || st.Rev != target {
		start := d.FlowReclassDoneRev() < target
		incremental := false
		if !start {
			wanted, err := d.reclassWanted(target)
			if err != nil {
				return err
			}
			start, incremental = wanted, wanted
		}
		if !start {
			if running { // a leftover state of a superseded revision
				d.db.Where(`"key" = ?`, flowReclassStateKey).Delete(&models.SystemSetting{})
			}
			return nil
		}
		st = d.newReclassRun(target, incremental)
		if err := d.saveReclassState(st); err != nil {
			return err
		}
		kind := "full"
		if incremental {
			kind = fmt.Sprintf("incremental (flow_rollups above id %d)", st.Floor)
		}
		log.Printf("Flow reclassification: starting a %s run for revision %d (about %d rows)", kind, target, st.Estimate)
	}

	if free, ok := d.reclassDiskFree(); ok && free < reclassDiskMinFree {
		log.Printf("Flow reclassification: paused — the database volume has %.0f%% free (needs %.0f%%)", free*100, reclassDiskMinFree*100)
		d.writeReclassStatus(st, "paused", fmt.Sprintf("low disk space (%.0f%% free)", free*100), false)
		return nil
	}

	set, err := setFor(st.Rev)
	if err != nil {
		d.writeReclassStatus(st, "paused", "the internal networks could not be loaded", false)
		return fmt.Errorf("flow reclassification: load internal networks: %w", err)
	}
	if st.Window == 0 {
		st.Window = reclassInitialWindow
	}
	verifyRounds := 0
	lastStatus := time.Time{}
	status := func(phase, reason string) {
		d.writeReclassStatus(st, phase, reason, false)
		lastStatus = time.Now()
	}
	defer func() {
		if st.Rev != 0 {
			_ = d.saveReclassState(st)
		}
	}()

	for time.Now().Before(deadline) {
		if t := d.FlowReclassTargetRev(); t != st.Rev {
			log.Printf("Flow reclassification: the target moved from %d to %d; restarting", st.Rev, t)
			st = d.newReclassRun(t, false)
			if set, err = setFor(st.Rev); err != nil {
				d.writeReclassStatus(st, "paused", "the internal networks could not be loaded", false)
				return fmt.Errorf("flow reclassification: load internal networks: %w", err)
			}
			st.Window = reclassInitialWindow
		}

		if st.Phase == reclassPhaseVerify {
			if verifyRounds >= reclassMaxVerifyRounds {
				status("reclassifying", "")
				return nil
			}
			verifyRounds++
			doneNow, yield, err := d.reclassVerifyStep(&st)
			if err != nil {
				return err
			}
			if doneNow {
				st = reclassState{} // the deferred save is skipped
				return nil
			}
			if yield {
				return nil
			}
			continue
		}

		table := st.Phase
		if st.PassMax == 0 {
			mx, err := d.tableMaxID(table)
			if err != nil {
				return err
			}
			st.PassMax = mx
			if table == reclassTableSamples {
				st.SamplesPassMax = mx
			}
		}
		if st.Cursor >= st.PassMax {
			d.reclassNextPhase(&st)
			continue
		}
		hi := min(st.Cursor+st.Window, st.PassMax)
		rows, err := d.reclassReadSlice(table, st.Cursor, hi, st.Rev)
		if err != nil {
			if sqlState(err) == "57014" {
				if st.Window > int64(reclassSliceLimit) {
					st.Window = max(st.Window/2, int64(reclassSliceLimit))
					log.Printf("Flow reclassification: a read of %s timed out; narrowing to %d ids", table, st.Window)
					continue
				}
				log.Printf("Flow reclassification: a read of %s timed out at the smallest window; retrying next tick", table)
				return nil
			}
			return fmt.Errorf("flow reclassification: read %s: %w", table, err)
		}
		written, err := d.reclassWrite(table, st.Rev, reclassClassify(table, set, rows))
		if err != nil {
			return fmt.Errorf("flow reclassification: write %s: %w", table, err)
		}
		st.Rows += int64(len(rows))
		st.Updated += written
		if table == reclassTableRollups {
			for _, r := range rows {
				if st.MinRollupTS == nil || r.Timestamp.Before(*st.MinRollupTS) {
					ts := r.Timestamp
					st.MinRollupTS = &ts
				}
			}
		}
		full := len(rows) == reclassSliceLimit
		if full {
			st.Cursor = rows[len(rows)-1].ID
		} else {
			st.Cursor = hi
			if len(rows) < reclassSliceLimit/2 && st.Window < reclassMaxWindow {
				st.Window = min(st.Window*2, reclassMaxWindow)
			}
		}
		if err := d.saveReclassState(st); err != nil {
			return err
		}
		if time.Since(lastStatus) > 30*time.Second {
			status("reclassifying", "")
		}
		if full {
			reclassSleep(reclassInterSliceSleep)
		}
	}
	status("reclassifying", "")
	return nil
}

func (d *Database) newReclassRun(rev uint16, incremental bool) reclassState {
	st := reclassState{Rev: rev, Phase: reclassTableSamples, Incremental: incremental, Started: time.Now().UTC()}
	if incremental {
		st.Floor = int64(d.GetIntSetting(flowReclassRollupFloorKey, 0))
	}
	st.Estimate = d.reclassEstimate(reclassTableSamples, 0) + d.reclassEstimate(reclassTableRollups, st.Floor)
	// A mark written before this run started is covered by it; one written
	// after is not, and survives to start another run. The delete matches the
	// value read, and every mark is unique, so a newer mark is never removed.
	if tok, ok := d.GetSettingValue(FlowReclassRearmKey); ok && tok != "" {
		if reclassRearmReadHook != nil {
			reclassRearmReadHook()
		}
		if err := d.db.Where(`"key" = ? AND value = ?`, FlowReclassRearmKey, tok).Delete(&models.SystemSetting{}).Error; err != nil {
			log.Printf("Flow reclassification: could not clear the re-arm mark: %v", err)
		}
	}
	return st
}

func (d *Database) reclassNextPhase(st *reclassState) {
	if st.Phase == reclassTableSamples && !st.RePass {
		st.Phase, st.Cursor, st.PassMax = reclassTableRollups, st.Floor, 0
		return
	}
	st.Phase, st.Cursor, st.PassMax, st.RePass = reclassPhaseVerify, 0, 0, false
}

// reclassVerifyStep runs the locked counts, samples then rollups. A non-zero
// count re-walks that table from just below its lowest old-revision id —
// never from 0. done reports a completed run; yield ends the step.
func (d *Database) reclassVerifyStep(st *reclassState) (done, yield bool, err error) {
	if reclassVerifyHook != nil {
		reclassVerifyHook()
	}
	timeout := "300s"
	if d.GetIntSetting(flowReclassVerifyTimeoutsKey, 0) >= 3 {
		timeout = "900s"
	}
	onTimeout := func(table string) (bool, bool, error) {
		n := d.GetIntSetting(flowReclassVerifyTimeoutsKey, 0) + 1
		_ = d.setReclassSetting(flowReclassVerifyTimeoutsKey, strconv.Itoa(n))
		log.Printf("Flow reclassification: verifying %s timed out (%s, %d in a row); retrying next tick", table, timeout, n)
		if n >= 5 {
			d.writeReclassStatus(*st, "paused", fmt.Sprintf("the final check of %s keeps timing out (%d times) — the table may need VACUUM", table, n), false)
		}
		return false, true, nil
	}

	sv, err := d.reclassVerify(reclassTableSamples, 0, st.Rev, timeout)
	if err != nil {
		if sqlState(err) == "57014" {
			return onTimeout(reclassTableSamples)
		}
		return false, false, err
	}
	if !sv.acquired {
		d.writeReclassStatus(*st, "waiting", "for maintenance (retention cleanup or rollup) to finish", false)
		return false, true, nil
	}
	if sv.count > 0 {
		stalled := sv.maxID > st.SamplesPassMax
		st.Phase, st.Cursor, st.PassMax, st.RePass = reclassTableSamples, sv.minID-1, 0, true
		if stalled {
			// Rows newer than the walk still carry an older revision: an API
			// instance is stamping without its networks loaded (or has not
			// picked up a Reapply yet). Re-walk next tick rather than every few
			// seconds.
			d.writeReclassStatus(*st, "waiting", "new flows still carry an older revision — an API instance has not loaded its networks yet", false)
			return false, true, nil
		}
		return false, false, nil
	}
	st.SamplesMaxLocked = sv.tableMax

	rv, err := d.reclassVerify(reclassTableRollups, st.Floor, st.Rev, timeout)
	if err != nil {
		if sqlState(err) == "57014" {
			return onTimeout(reclassTableRollups)
		}
		return false, false, err
	}
	if !rv.acquired {
		d.writeReclassStatus(*st, "waiting", "for maintenance (retention cleanup or rollup) to finish", false)
		return false, true, nil
	}
	if rv.count > 0 {
		st.Phase, st.Cursor, st.PassMax, st.RePass = reclassTableRollups, rv.minID-1, 0, true
		return false, false, nil
	}
	return true, false, d.completeReclassRun(*st, rv.tableMax)
}

// completeReclassRun records the finished revision, the rollup floor (MAX id
// read under the lock: no row at or below it can later carry an old
// revision) and the probe starting points, and asks the summary rebuild to
// recompute from the oldest re-stamped bucket — these were in-place updates,
// which the summary's id watermark cannot see.
func (d *Database) completeReclassRun(st reclassState, rollupsMax int64) error {
	sets := map[string]string{
		FlowReclassDoneRevKey:        strconv.Itoa(int(st.Rev)),
		flowReclassRollupFloorKey:    strconv.FormatInt(rollupsMax, 10),
		flowReclassSamplesProbeKey:   strconv.FormatInt(st.SamplesMaxLocked, 10),
		flowReclassRollupsProbeKey:   strconv.FormatInt(rollupsMax, 10),
		flowReclassVerifyTimeoutsKey: "0",
	}
	if st.MinRollupTS != nil {
		sets[flowSummaryRecomputeRequestKey] = fmt.Sprintf("%d|%s", st.Rev, st.MinRollupTS.UTC().Truncate(time.Hour).Format(time.RFC3339))
	}
	for k, v := range sets {
		if err := d.setReclassSetting(k, v); err != nil {
			return err
		}
	}
	d.writeReclassStatus(st, "done", "", true)
	if err := d.db.Where(`"key" = ?`, flowReclassStateKey).Delete(&models.SystemSetting{}).Error; err != nil {
		return err
	}
	log.Printf("Flow reclassification: revision %d complete — %d rows re-stamped", st.Rev, st.Updated)
	return nil
}
