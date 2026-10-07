package status

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Runtime is what the archive worker knows that the database does not: why a
// table's next chunk waits (and who holds it up), the last failure of each
// stage, whether the bucket preflight passed, and the staging directory's free
// space. The worker (internal/archive/worker) records it in a Recorder and
// writes it to the system setting database.ArchiveWorkerStateKey about once a
// minute while it holds the archive lock; the status API, the CLI and the
// alerts read it back. SeenAt says how fresh it is: a snapshot older than
// StaleAfter is shown as stale and alerts that depend on it hold their state.
type Runtime struct {
	SeenAt      time.Time               `json:"seen_at"`
	Runner      string                  `json:"runner"`
	PreflightOK bool                    `json:"preflight_ok"`
	Staging     Staging                 `json:"staging"`
	Tables      map[string]TableRuntime `json:"tables,omitempty"`
	Stages      map[string]StageError   `json:"stages,omitempty"`
	// LastPassAt / NextPassAt: when the worker last planned and worked
	// chunks, and when it will next (sooner when a settling chunk's window
	// ends first). nil until the first pass. While a pass runs PassRunning
	// is set, LastPassAt is its start and NextPassAt is nil: a pass lasts as
	// long as there is work (hours through a syslog backlog), re-planning
	// the tables it ran out of at most every minute, so no next pass is due.
	LastPassAt  *time.Time `json:"last_pass_at,omitempty"`
	NextPassAt  *time.Time `json:"next_pass_at,omitempty"`
	PassRunning bool       `json:"pass_running,omitempty"`
	// Activity is the chunk being worked right now (nil between chunks).
	Activity *Activity `json:"activity,omitempty"`
	// PreflightIssue classifies a failing preflight the health verdict
	// treats on its own (PreflightMarkerMissing, PreflightMarkerForeign; ""
	// otherwise, and once the preflight passed).
	PreflightIssue string `json:"preflight_issue,omitempty"`
	// ConfigFingerprint is config.ArchiveConfig.Fingerprint of the
	// configuration this worker was built with: the status compares it with
	// the configuration in effect ("saved, not applied yet").
	ConfigFingerprint string `json:"config_fingerprint,omitempty"`
	// Failing: the failures still going on, per stage and subject (a table
	// or a stream): since when, the last one, how many. A success of that
	// stage for that subject ends it (Recorder.OK). Kept across worker
	// rebuilds and poller restarts (Recorder.Restore), so the health
	// verdict's escalation does not start again at every restart.
	Failing map[string]Streak `json:"failing,omitempty"`
	// NoChunkSince: since when an archived table has had no chunk at all
	// (kept across restarts; removed once it has one).
	NoChunkSince map[string]time.Time `json:"no_chunk_since,omitempty"`
}

// Streak is a failure still going on: Stage (an errors label) for Subject
// (a table, a stream, or "" for the whole worker).
type Streak struct {
	Stage   string    `json:"stage"`
	Subject string    `json:"subject,omitempty"`
	Since   time.Time `json:"since"`
	At      time.Time `json:"at"`
	Error   string    `json:"error"`
	Count   int64     `json:"count"`
}

func streakKey(stage, subject string) string { return stage + "/" + subject }

// restoreMaxAge bounds what Restore keeps of a previous snapshot: a failure
// last seen longer ago than this is history, not a streak.
const restoreMaxAge = 24 * time.Hour

// Preflight issues (Runtime.PreflightIssue).
const (
	// PreflightMarkerMissing: a local target without its marker while the
	// archive holds chunks — usually a share that is not mounted.
	PreflightMarkerMissing = "marker_missing"
	// PreflightMarkerForeign: a local target another install initialised.
	PreflightMarkerForeign = "marker_foreign"
)

// ConfigProblemRunner is the runner of the snapshot written when the
// configuration in effect cannot run (no worker: its "config" stage says
// why).
const ConfigProblemRunner = "not running"

// Activity is the chunk the worker is working and how far it got. The
// worker updates it in memory as it goes and writes it with the rest of the
// snapshot at most every ProgressEvery (plus the minute's write), so the
// status shows a long export or upload moving without a database write per
// page.
type Activity struct {
	Table       string    `json:"table"`
	ChunkID     uint      `json:"chunk_id"`
	Seq         int64     `json:"seq"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	// Stage: start (claimed; checks before the export), export (reading
	// the rows into the staging files), upload,
	// verify (reading every object back), count (recounting the range in
	// the table), manifest (the chunk.json files).
	Stage          string    `json:"stage"`
	StartedAt      time.Time `json:"started_at"`
	StageStartedAt time.Time `json:"stage_started_at"`
	// Export: RowsDone rows read so far; IDSpan the chunk's id range
	// (id_hi − id_lo, an upper bound of its rows) and IDsDone how much of
	// it is read — their ratio is the export's fraction.
	RowsDone int64 `json:"rows_done"`
	IDSpan   int64 `json:"id_span"`
	IDsDone  int64 `json:"ids_done"`
	// Rows: the chunk's row count once exported (0 before).
	Rows int64 `json:"rows"`
	// Upload and verify: bytes sent / read back of BytesTotal, objects done
	// of ObjectsTotal.
	BytesDone    int64 `json:"bytes_done"`
	BytesTotal   int64 `json:"bytes_total"`
	ObjectsDone  int   `json:"objects_done"`
	ObjectsTotal int   `json:"objects_total"`
}

// ProgressEvery is how often the worker writes its snapshot while a chunk
// makes progress (rows read, bytes sent or read back).
const ProgressEvery = 15 * time.Second

// StaleAfter is how old the worker's snapshot may be before it is reported
// stale. The worker writes it every minute, also during a long pass.
const StaleAfter = 15 * time.Minute

// Staging is the staging directory's free space when the snapshot was taken.
type Staging struct {
	Dir          string  `json:"dir"`
	FreeBytes    *uint64 `json:"free_bytes,omitempty"`
	MinFreeBytes uint64  `json:"min_free_bytes"`
	Error        string  `json:"error,omitempty"`
}

// TableRuntime is why a table's next chunk is not being exported: Reason is
// one of the fwmon_archive_unsettled reasons (settling, open_writer,
// no_statement_timeout, unattached_leaf), Since when it began (reset when the
// reason changes), Detail the worker's message (for open_writer the session
// holding the oldest running transaction, when visible). Until: when a
// settling chunk's window ends — the status counts down to it, so the
// snapshot never carries a "time left" that goes stale.
type TableRuntime struct {
	Reason string     `json:"reason,omitempty"`
	Since  *time.Time `json:"since,omitempty"`
	Until  *time.Time `json:"until,omitempty"`
	Detail string     `json:"detail,omitempty"`
}

// StageError is the last failure of one stage (the fwmon_archive_errors_total
// stage label) and how many were counted; Since is the first of them (nil in
// a snapshot written before 0.11.316). Both are kept across worker rebuilds
// and poller restarts (Recorder.Restore).
type StageError struct {
	At    time.Time  `json:"at"`
	Since *time.Time `json:"since,omitempty"`
	Error string     `json:"error"`
	Count int64      `json:"count"`
}

// errorMax bounds a recorded message.
const errorMax = 500

// Recorder holds a worker's Runtime; safe for concurrent use (the worker's
// mark ticker writes the snapshot while a pass records into it).
type Recorder struct {
	mu     sync.Mutex
	rt     Runtime
	redact []string
}

// NewRecorder starts the runtime of a worker. redact lists values that must
// never appear in a recorded message (the bucket credentials): an error from
// the service or the SDK is not trusted to leave them out.
func NewRecorder(runner, stagingDir string, minFree uint64, redact ...string) *Recorder {
	r := &Recorder{rt: Runtime{Runner: runner, Staging: Staging{Dir: stagingDir, MinFreeBytes: minFree},
		Tables: map[string]TableRuntime{}, Stages: map[string]StageError{}, Failing: map[string]Streak{}, NoChunkSince: map[string]time.Time{}}}
	for _, s := range redact {
		if s != "" {
			r.redact = append(r.redact, s)
		}
	}
	return r
}

func (r *Recorder) clean(msg string) string {
	for _, s := range r.redact {
		msg = strings.ReplaceAll(msg, s, "[redacted]")
	}
	if len(msg) > errorMax {
		msg = strings.ToValidUTF8(msg[:errorMax], "") + "…"
	}
	return msg
}

// SetUnsettled records table's wait reason ("" = not waiting) and its detail.
func (r *Recorder) SetUnsettled(table, reason, detail string, now time.Time) {
	r.SetWait(table, reason, detail, nil, now)
}

// SetWait is SetUnsettled with the instant the wait ends, when known (a
// settling chunk's window).
func (r *Recorder) SetWait(table, reason, detail string, until *time.Time, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason == "" {
		delete(r.rt.Tables, table)
		return
	}
	cur := r.rt.Tables[table]
	if cur.Reason != reason || cur.Since == nil {
		t := now.UTC()
		cur.Since = &t
	}
	cur.Reason, cur.Detail, cur.Until = reason, r.clean(detail), nil
	if until != nil {
		u := until.UTC()
		cur.Until = &u
	}
	r.rt.Tables[table] = cur
}

// SetPasses records when the last pass ran and when the next one is due (no
// pass is running).
func (r *Recorder) SetPasses(last, next time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, n := last.UTC(), next.UTC()
	r.rt.LastPassAt, r.rt.NextPassAt, r.rt.PassRunning = &l, &n, false
}

// PassStarted records that a pass began at at and is running (no next pass
// until it ends: SetPasses).
func (r *Recorder) PassStarted(at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := at.UTC()
	r.rt.LastPassAt, r.rt.NextPassAt, r.rt.PassRunning = &l, nil, true
}

// StartActivity records that chunk work began on a (nil: none).
func (r *Recorder) StartActivity(a *Activity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a == nil {
		r.rt.Activity = nil
		return
	}
	v := *a
	r.rt.Activity = &v
}

// UpdateActivity applies f to the current activity (a no-op when none).
func (r *Recorder) UpdateActivity(f func(a *Activity)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rt.Activity != nil {
		f(r.rt.Activity)
	}
}

// Failed records a failure of stage (err may be nil: the stage is counted
// with no message).
func (r *Recorder) Failed(stage string, err error, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.rt.Stages[stage]
	e.At, e.Count = now.UTC(), e.Count+1
	if e.Since == nil {
		first := e.At
		e.Since = &first
	}
	e.Error = ""
	if err != nil {
		e.Error = r.clean(err.Error())
	}
	r.rt.Stages[stage] = e
}

// Fail records a failure of stage for subject (a table, a stream, "" for the
// whole worker): Failed, and the streak that lasts until OK.
func (r *Recorder) Fail(stage, subject string, err error, now time.Time) {
	r.Failed(stage, err, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	k := streakKey(stage, subject)
	f, ok := r.rt.Failing[k]
	if !ok {
		f = Streak{Stage: stage, Subject: subject, Since: now.UTC()}
	}
	f.At, f.Count, f.Error = now.UTC(), f.Count+1, r.rt.Stages[stage].Error
	r.rt.Failing[k] = f
}

// OK records that stage succeeded for subject: its streak ends.
func (r *Recorder) OK(stage, subject string) {
	r.mu.Lock()
	delete(r.rt.Failing, streakKey(stage, subject))
	r.mu.Unlock()
}

// SetNoChunk records whether table has no chunk at all (the earliest
// instant is kept until it has one).
func (r *Recorder) SetNoChunk(table string, none bool, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !none {
		delete(r.rt.NoChunkSince, table)
		return
	}
	if _, ok := r.rt.NoChunkSince[table]; !ok {
		r.rt.NoChunkSince[table] = now.UTC()
	}
}

// Restore carries the failures of a previous worker's snapshot (prev, the
// one stored before this worker was built: a poller restart or a settings
// change) into this one: each stage's last failure with its first (Since)
// and count, the streaks still going on, and since when a table has had no
// chunk — so the health verdict's escalation ("failing for 15 min, 1 h")
// survives a restart. A failure last seen more than restoreMaxAge before now
// is dropped. Call it before the worker records anything.
func (r *Recorder) Restore(prev *Runtime, now time.Time) {
	if prev == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, e := range prev.Stages {
		if now.Sub(e.At) <= restoreMaxAge {
			if _, ok := r.rt.Stages[k]; !ok {
				r.rt.Stages[k] = e
			}
		}
	}
	for k, f := range prev.Failing {
		if now.Sub(f.At) <= restoreMaxAge {
			if _, ok := r.rt.Failing[k]; !ok {
				r.rt.Failing[k] = f
			}
		}
	}
	for t, since := range prev.NoChunkSince {
		if _, ok := r.rt.NoChunkSince[t]; !ok {
			r.rt.NoChunkSince[t] = since
		}
	}
}

// SetPreflight records whether the bucket preflight has passed (passing
// clears the preflight issue).
func (r *Recorder) SetPreflight(ok bool) {
	r.mu.Lock()
	r.rt.PreflightOK = ok
	if ok {
		r.rt.PreflightIssue = ""
	}
	r.mu.Unlock()
}

// SetPreflightIssue records what kind of preflight failure is current
// (Runtime.PreflightIssue; "" = none of the classified ones).
func (r *Recorder) SetPreflightIssue(issue string) {
	r.mu.Lock()
	r.rt.PreflightIssue = issue
	r.mu.Unlock()
}

// SetConfigFingerprint records the fingerprint of the worker's configuration.
func (r *Recorder) SetConfigFingerprint(fp string) {
	r.mu.Lock()
	r.rt.ConfigFingerprint = fp
	r.mu.Unlock()
}

// SetStagingFree records the staging directory's free space (or why it could
// not be read).
func (r *Recorder) SetStagingFree(free uint64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.rt.Staging.FreeBytes, r.rt.Staging.Error = nil, r.clean(err.Error())
		return
	}
	r.rt.Staging.FreeBytes, r.rt.Staging.Error = &free, ""
}

// Snapshot is a copy of the runtime stamped SeenAt = now.
func (r *Recorder) Snapshot(now time.Time) Runtime {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.rt
	out.SeenAt = now.UTC()
	out.Tables = make(map[string]TableRuntime, len(r.rt.Tables))
	for k, v := range r.rt.Tables {
		out.Tables[k] = v
	}
	out.Stages = make(map[string]StageError, len(r.rt.Stages))
	for k, v := range r.rt.Stages {
		out.Stages[k] = v
	}
	out.Failing = make(map[string]Streak, len(r.rt.Failing))
	for k, v := range r.rt.Failing {
		out.Failing[k] = v
	}
	out.NoChunkSince = make(map[string]time.Time, len(r.rt.NoChunkSince))
	for k, v := range r.rt.NoChunkSince {
		out.NoChunkSince[k] = v
	}
	if f := r.rt.Staging.FreeBytes; f != nil {
		v := *f
		out.Staging.FreeBytes = &v
	}
	if a := r.rt.Activity; a != nil {
		v := *a
		out.Activity = &v
	}
	return out
}

// JSON is Snapshot(now) encoded for database.SaveArchiveWorkerState.
func (r *Recorder) JSON(now time.Time) (string, error) {
	b, err := json.Marshal(r.Snapshot(now))
	return string(b), err
}

// ParseRuntime decodes a stored snapshot.
func ParseRuntime(s string) (*Runtime, error) {
	var rt Runtime
	if err := json.Unmarshal([]byte(s), &rt); err != nil {
		return nil, err
	}
	if rt.SeenAt.IsZero() {
		return nil, errors.New("archive worker state has no seen_at")
	}
	return &rt, nil
}
