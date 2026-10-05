package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// runNormalizeBackfillCmd implements `fwmon-api normalize-backfill` (v0.11.297),
// the CLI twin of POST /admin/api/normalize/backfill: it connects straight to
// the database and QUEUES a job — the poller's NormalizeBackfillWorker runs
// it — or reports / cancels / resumes the latest one. Like reset-auth it needs
// the server's database environment (run it where fwmon-api runs: `docker exec
// <container> fwmon-api normalize-backfill --since 30d`) and no web session;
// host access to the database credentials is the authorization here, where the
// API route re-verifies the operator's password.
//
//	normalize-backfill [--since 30d] [--device <id>] [--rate 2000] [--window 22:00-06:00]
//	normalize-backfill --status | --cancel | --resume
//
// Returns the process exit code.
func runNormalizeBackfillCmd(args []string) int {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "normalize-backfill: configuration error: %v\n", err)
		return 1
	}
	return normalizeBackfill(cfg, args, os.Stdout, os.Stderr, func() (backfillStore, error) {
		db, err := database.Connect(cfg)
		if err != nil {
			return nil, err
		}
		return db, nil
	})
}

// backfillStore is the slice of *database.Database the command needs.
type backfillStore interface {
	NormalizeBackfillBounds(sinceDays int, now time.Time) (since, until time.Time, err error)
	EstimateNormalizeBackfill(since, until time.Time) (database.NormalizeBackfillEstimate, error)
	CreateNormalizeBackfillJob(job *models.NormalizeBackfillJob) error
	GetLatestNormalizeBackfillJob() (*models.NormalizeBackfillJob, error)
	GetActiveNormalizeBackfillJob() (*models.NormalizeBackfillJob, error)
	CancelNormalizeBackfillJob(id uint) (status string, applied bool, err error)
	ResumeNormalizeBackfillJob(id uint) (applied bool, err error)
	GetSettingValue(key string) (string, bool)
	GetDevice(id uint) (*models.Device, error)
	Close() error
}

// normalizeBackfill is the testable core of runNormalizeBackfillCmd.
func normalizeBackfill(cfg *config.Config, args []string, stdout, stderr io.Writer, open func() (backfillStore, error)) int {
	fs := flag.NewFlagSet("normalize-backfill", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.String("since", "30d", "how far back to backfill: <n>d or <n>, 1..30 days")
	device := fs.Uint("device", 0, "restrict the backfill to one device id (0 = every device)")
	rate := fs.Int("rate", database.NormalizeBackfillDefaultRate, "raw rows scanned per second")
	window := fs.String("window", "", "local-time run window HH:MM-HH:MM (default: the normalize_backfill_window setting, if set)")
	status := fs.Bool("status", false, "print the latest job and exit")
	cancel := fs.Bool("cancel", false, "cancel the active job")
	resume := fs.Bool("resume", false, "resume the latest cancelled / failed job from its cursor")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: fwmon-api normalize-backfill [--since 30d] [--device <id>] [--rate 2000] [--window 22:00-06:00]")
		fmt.Fprintln(stderr, "       fwmon-api normalize-backfill --status | --cancel | --resume")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, m := range []bool{*status, *cancel, *resume} {
		if m {
			modes++
		}
	}
	if modes > 1 || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	var sinceDays int
	if modes == 0 {
		n, err := database.SinceDaysArg(*since)
		if err != nil {
			fmt.Fprintf(stderr, "normalize-backfill: %v\n", err)
			return 2
		}
		sinceDays = n
		if *rate < database.NormalizeBackfillMinRate || *rate > database.NormalizeBackfillMaxRate {
			fmt.Fprintf(stderr, "normalize-backfill: --rate must be %d..%d\n", database.NormalizeBackfillMinRate, database.NormalizeBackfillMaxRate)
			return 2
		}
		if err := database.ValidateRunWindow(*window); err != nil {
			fmt.Fprintf(stderr, "normalize-backfill: %v\n", err)
			return 2
		}
	}
	if cfg != nil && cfg.Normalize.Disabled && modes == 0 {
		fmt.Fprintln(stderr, "normalize-backfill: normalization is disabled (NORMALIZE_ENABLED=false); enable it and let the ingest record its start before backfilling")
		return 1
	}

	db, err := open()
	if err != nil {
		fmt.Fprintf(stderr, "normalize-backfill: connect: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	switch {
	case *status:
		job, err := db.GetLatestNormalizeBackfillJob()
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				fmt.Fprintln(stdout, "no backfill job has been queued")
				return 0
			}
			fmt.Fprintf(stderr, "normalize-backfill: %v\n", err)
			return 1
		}
		printBackfillJob(stdout, job)
		return 0
	case *cancel:
		job, err := db.GetActiveNormalizeBackfillJob()
		if err != nil {
			fmt.Fprintf(stderr, "normalize-backfill: %v\n", err)
			return 1
		}
		if job == nil {
			fmt.Fprintln(stderr, "normalize-backfill: no active job to cancel")
			return 1
		}
		st, applied, err := db.CancelNormalizeBackfillJob(job.ID)
		if err != nil {
			fmt.Fprintf(stderr, "normalize-backfill: cancel: %v\n", err)
			return 1
		}
		if !applied {
			fmt.Fprintf(stderr, "normalize-backfill: job %d is %s and cannot be cancelled\n", job.ID, job.Status)
			return 1
		}
		fmt.Fprintf(stdout, "job %d: %s\n", job.ID, st)
		return 0
	case *resume:
		job, err := db.GetLatestNormalizeBackfillJob()
		if err != nil {
			fmt.Fprintf(stderr, "normalize-backfill: no job to resume (%v)\n", err)
			return 1
		}
		if job.Status == database.NormalizeBackfillStatusCancelled || job.Status == database.NormalizeBackfillStatusFailed {
			// The disk precheck again, over what is left (as the API's resume).
			from, until := database.NormalizeBackfillRemaining(job)
			est, err := db.EstimateNormalizeBackfill(from, until)
			if err != nil {
				fmt.Fprintf(stderr, "normalize-backfill: estimate: %v\n", err)
				return 1
			}
			if !est.Enough {
				fmt.Fprintf(stderr, "normalize-backfill: insufficient disk headroom: ~%d MB left to write, %d MB free (twice the estimate is required)\n", est.Bytes>>20, est.FreeBytes>>20)
				return 1
			}
		}
		applied, err := db.ResumeNormalizeBackfillJob(job.ID)
		if err != nil {
			fmt.Fprintf(stderr, "normalize-backfill: resume: %v\n", err)
			return 1
		}
		if !applied {
			fmt.Fprintf(stderr, "normalize-backfill: job %d is %s and cannot be resumed\n", job.ID, job.Status)
			return 1
		}
		fmt.Fprintf(stdout, "job %d: pending (resumes from %s/%d)\n", job.ID, job.CurrentPartition, job.CursorID)
		return 0
	}

	if *device != 0 {
		// Same check as the API: a job scoped to a device that does not exist
		// would walk the whole window to write nothing.
		if _, err := db.GetDevice(uint(*device)); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				fmt.Fprintf(stderr, "normalize-backfill: device %d not found\n", *device)
			} else {
				fmt.Fprintf(stderr, "normalize-backfill: look up device %d: %v\n", *device, err)
			}
			return 1
		}
	}
	from, until, err := db.NormalizeBackfillBounds(sinceDays, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "normalize-backfill: %v\n", err)
		return 1
	}
	if active, err := db.GetActiveNormalizeBackfillJob(); err != nil {
		fmt.Fprintf(stderr, "normalize-backfill: %v\n", err)
		return 1
	} else if active != nil {
		fmt.Fprintf(stderr, "normalize-backfill: job %d is already %s (use --status / --cancel)\n", active.ID, active.Status)
		return 1
	}
	est, err := db.EstimateNormalizeBackfill(from, until)
	if err != nil {
		fmt.Fprintf(stderr, "normalize-backfill: estimate: %v\n", err)
		return 1
	}
	if !est.Enough {
		fmt.Fprintf(stderr, "normalize-backfill: insufficient disk headroom: ~%d MB to write, %d MB free (twice the estimate is required)\n", est.Bytes>>20, est.FreeBytes>>20)
		return 1
	}
	win := *window
	if win == "" {
		win, _ = db.GetSettingValue(database.NormalizeBackfillWindowSetting)
	}
	job := &models.NormalizeBackfillJob{RequestedBy: "cli", Since: from, Until: until, Window: win, RateRowsPerSec: *rate}
	if *device != 0 {
		id := uint(*device)
		job.DeviceID = &id
	}
	if err := db.CreateNormalizeBackfillJob(job); err != nil {
		fmt.Fprintf(stderr, "normalize-backfill: queue: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "queued backfill job %d: [%s, %s) ~%d raw rows (~%d MB), %d rows/s, window %q; the poller picks it up within %s\n",
		job.ID, from.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339), est.Rows, est.Bytes>>20, job.RateRowsPerSec, win, "15s")
	return 0
}

func printBackfillJob(w io.Writer, job *models.NormalizeBackfillJob) {
	fmt.Fprintf(w, "job %d: %s\n", job.ID, job.Status)
	fmt.Fprintf(w, "  window    [%s, %s)\n", job.Since.UTC().Format(time.RFC3339), job.Until.UTC().Format(time.RFC3339))
	if job.DeviceID != nil {
		fmt.Fprintf(w, "  device    %d\n", *job.DeviceID)
	}
	fmt.Fprintf(w, "  rate      %d rows/s", job.RateRowsPerSec)
	if job.Window != "" {
		fmt.Fprintf(w, ", run window %s", job.Window)
	}
	fmt.Fprintln(w)
	cursor := "-"
	if job.CursorTs != nil {
		cursor = fmt.Sprintf("%s id %d", job.CursorTs.UTC().Format(time.RFC3339), job.CursorID)
	}
	fmt.Fprintf(w, "  cursor    %s (%s)\n", job.CurrentPartition, cursor)
	fmt.Fprintf(w, "  rows      scanned %d, written %d, skipped %d, unparsed %d\n", job.RowsScanned, job.RowsWritten, job.RowsSkipped, job.RowsUnparsed)
	if job.StartedAt != nil {
		fmt.Fprintf(w, "  started   %s\n", job.StartedAt.UTC().Format(time.RFC3339))
	}
	if job.FinishedAt != nil {
		fmt.Fprintf(w, "  finished  %s\n", job.FinishedAt.UTC().Format(time.RFC3339))
	}
	if job.Error != "" {
		fmt.Fprintf(w, "  error     %s\n", job.Error)
	}
}
