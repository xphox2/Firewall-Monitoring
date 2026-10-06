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
}

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
// holding the oldest running transaction, when visible).
type TableRuntime struct {
	Reason string     `json:"reason,omitempty"`
	Since  *time.Time `json:"since,omitempty"`
	Detail string     `json:"detail,omitempty"`
}

// StageError is the last failure of one stage (the fwmon_archive_errors_total
// stage label) and how many this worker process has counted.
type StageError struct {
	At    time.Time `json:"at"`
	Error string    `json:"error"`
	Count int64     `json:"count"`
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
		Tables: map[string]TableRuntime{}, Stages: map[string]StageError{}}}
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
	cur.Reason, cur.Detail = reason, r.clean(detail)
	r.rt.Tables[table] = cur
}

// Failed records a failure of stage (err may be nil: the stage is counted
// with no message).
func (r *Recorder) Failed(stage string, err error, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.rt.Stages[stage]
	e.At, e.Count = now.UTC(), e.Count+1
	e.Error = ""
	if err != nil {
		e.Error = r.clean(err.Error())
	}
	r.rt.Stages[stage] = e
}

// SetPreflight records whether the bucket preflight has passed.
func (r *Recorder) SetPreflight(ok bool) {
	r.mu.Lock()
	r.rt.PreflightOK = ok
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
	if f := r.rt.Staging.FreeBytes; f != nil {
		v := *f
		out.Staging.FreeBytes = &v
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
