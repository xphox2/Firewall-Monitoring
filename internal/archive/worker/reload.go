package worker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"reflect"
	"time"

	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
)

// Hot reload (A-10). The archive's configuration is the environment's with
// the admin page's settings applied (database.ResolveArchiveConfig), and an
// admin can change it while the poller runs. The poller therefore does not
// build its workers once at start: a Reloader resolves the configuration at
// every tick and, when it differs from the one its worker was built with,
// builds a new worker — a fresh preflight with the new keys, a fresh runtime
// record — before ticking it. Ticks run one at a time on the poller's
// goroutine, so a worker is never replaced in the middle of its pass; every
// step of a chunk is a database state, so the new worker resumes whatever
// the old one left exactly as after a restart.

// ticker is a worker the reloader drives.
type ticker interface{ Tick(ctx context.Context) }

// reloader drives one worker of type T over the resolved configuration.
type reloader[T ticker] struct {
	name    string
	resolve func(ctx context.Context) (config.ArchiveConfig, error)
	// ready: whether cfg asks for this worker (false, nil: off) or why it
	// cannot run with it.
	ready func(cfg config.ArchiveConfig) (bool, error)
	build func(cfg config.ArchiveConfig) (T, error)
	// problem records why the configuration cannot run (nil: only logged).
	problem func(ctx context.Context, cfg config.ArchiveConfig, err error)

	cur    T
	active bool
	// failing: why the current configuration cannot run (recorded again
	// every tick, so the status does not show the record as stale).
	failing error
	cfg     config.ArchiveConfig
	have    bool
	lastLog string
}

func (r *reloader[T]) logOnce(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if msg != r.lastLog {
		r.lastLog = msg
		log.Print(r.name + ": " + msg)
	}
}

// Tick resolves the configuration, rebuilds the worker when it changed (or
// could not be built), and ticks it. A configuration that cannot be read
// keeps the current worker.
func (r *reloader[T]) Tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	cfg, err := r.resolve(ctx)
	if err != nil {
		r.logOnce("resolve the configuration: %v (the current worker keeps its settings)", err)
	} else if !r.have || r.failing != nil || !reflect.DeepEqual(cfg, r.cfg) {
		// A failed build is retried every tick (a staging volume mounted
		// late); a configuration that does not validate fails again at once.
		r.apply(cfg)
	}
	switch {
	case r.active:
		r.cur.Tick(ctx)
	case r.failing != nil && r.problem != nil:
		r.problem(ctx, r.cfg, r.failing)
	}
}

func (r *reloader[T]) apply(cfg config.ArchiveConfig) {
	r.cfg, r.have = cfg, true
	var zero T
	wasActive := r.active
	r.cur, r.active, r.failing = zero, false, nil
	on, err := r.ready(cfg)
	switch {
	case err != nil:
		r.logOnce("not running: %v", err)
		r.failing = err
		return
	case !on:
		if wasActive {
			r.logOnce("stopped: the configuration no longer asks for it")
		}
		return
	}
	w, err := r.build(cfg)
	if err != nil {
		r.logOnce("not started: %v", err)
		r.failing = err
		return
	}
	r.cur, r.active = w, true
	if wasActive {
		r.logOnce("configuration changed: restarted with the new settings")
	} else {
		r.logOnce("started")
	}
}

// Reloader is the archive worker under the resolved configuration: it runs
// while a stream is enabled and the configuration validates. Tick it every
// TickInterval.
type Reloader struct{ r *reloader[*Worker] }

// NewReloader builds the reloader of the archive worker over db; env is the
// environment's archive configuration.
func NewReloader(db *database.Database, env config.ArchiveConfig, opts ...s3.Option) *Reloader {
	return &Reloader{r: &reloader[*Worker]{
		name:    "archive",
		resolve: resolver(db, env),
		ready: func(cfg config.ArchiveConfig) (bool, error) {
			if !cfg.Enabled() {
				return false, nil
			}
			return true, cfg.Validate()
		},
		build: func(cfg config.ArchiveConfig) (*Worker, error) {
			warnArchiveLocation(db, cfg)
			w, err := New(db, cfg, opts...)
			if err == nil {
				log.Printf("archive: worker for %v", w.Tables())
			}
			return w, err
		},
		problem: func(ctx context.Context, cfg config.ArchiveConfig, err error) {
			recordConfigProblem(ctx, db, cfg, err)
		},
	}}
}

// Tick resolves the configuration and ticks the worker it asks for.
func (r *Reloader) Tick(ctx context.Context) { r.r.Tick(ctx) }

// RestoreReloader is the restore worker under the resolved configuration: it
// runs whenever the target (bucket keys, or the local directory) and the
// staging directory are set, archiving
// enabled or not. Tick it every RestoreTickInterval.
type RestoreReloader struct{ r *reloader[*RestoreWorker] }

// NewRestoreReloader builds the reloader of the restore worker over db.
func NewRestoreReloader(db *database.Database, env config.ArchiveConfig, opts ...s3.Option) *RestoreReloader {
	return &RestoreReloader{r: &reloader[*RestoreWorker]{
		name:    "archive restore",
		resolve: resolver(db, env),
		ready: func(cfg config.ArchiveConfig) (bool, error) {
			return cfg.ValidateTarget() == nil && filepath.IsAbs(cfg.StagingDir), nil
		},
		build: func(cfg config.ArchiveConfig) (*RestoreWorker, error) { return NewRestoreWorker(db, cfg, opts...) },
	}}
}

// Tick resolves the configuration and ticks the restore worker it asks for.
func (r *RestoreReloader) Tick(ctx context.Context) { r.r.Tick(ctx) }

func resolver(db *database.Database, env config.ArchiveConfig) func(ctx context.Context) (config.ArchiveConfig, error) {
	return func(ctx context.Context) (config.ArchiveConfig, error) {
		res, err := db.ResolveArchiveConfig(ctx, env)
		return res.Config, err
	}
}

// recordConfigProblem writes a runtime snapshot whose "config" stage carries
// err, so the status page and the CLI say why nothing is archived although a
// stream is enabled (the worker that would write it is not running).
func recordConfigProblem(ctx context.Context, db *database.Database, cfg config.ArchiveConfig, err error) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	rec := status.NewRecorder("not running", cfg.StagingDir, stagingMinFree, cfg.SecretAccessKey.Reveal(), cfg.AccessKeyID)
	now := time.Now()
	rec.Failed("config", err, now)
	js, jerr := rec.JSON(now)
	if jerr == nil {
		jerr = db.SaveArchiveWorkerState(ctx, js)
	}
	if jerr != nil {
		log.Printf("archive: record the configuration problem: %v", jerr)
	}
}

// warnArchiveLocation logs a WARNING when the archive's chunks were written
// to another location (endpoint, bucket, prefix) than the configuration now
// names — a change made in the environment, which the admin form refuses:
// the manifest's objects are not where the worker will write and read.
func warnArchiveLocation(db *database.Database, cfg config.ArchiveConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	recorded, mismatch, err := db.CheckArchiveLocation(ctx, cfg.Location())
	switch {
	case err != nil:
		log.Printf("archive: check the archive's location: %v", err)
	case mismatch:
		log.Printf("WARNING: archive: its chunks were written to %s but the configuration now names %s; restores and seals of the earlier months will fail (docs/OPERATIONS.md, \"Raw archive: moving the bucket\")", recorded, cfg.Location())
	}
}
