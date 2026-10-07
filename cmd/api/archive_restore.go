package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The restore commands of `fwmon-api archive` (archive plan PR 9), the CLI
// twin of /admin/api/archive/restores (handlers_archive_restore.go):
//
//	--restore <stream> --from <YYYY-MM-DD> --to <YYYY-MM-DD>   queue a restore of those message days
//	    [--device <id>]          one device's rows only
//	    [--renormalize]          syslog: then re-normalize the staged rows (normalized-event backfill)
//	    [--replace]              with --renormalize: rewrite the normalized rows they already have
//	    [--from-bucket]          select from the bucket's sealed months instead of the database manifest
//	    [--force]                queue past a refused disk precheck (free space unknown / too small)
//	    [--rate <rows/s>]        load pace (default 5000)
//	    [--ttl-days <n>]         the staging table is dropped after (default 7, max 90)
//	--restores                 list the restores with their staging tables' sizes
//	--cancel-restore <id>      stop a queued or running restore (cursors kept)
//	--resume-restore <id>      resume a failed or cancelled restore
//	--drop-restore <id>        drop a finished restore's staging table

// restoreOpts are the restore flags.
type restoreOpts struct {
	stream      *string
	from, to    *string
	device      *uint
	renormalize *bool
	replace     *bool
	fromBucket  *bool
	force       *bool
	rate        *int
	ttlDays     *int
	list        *bool
	cancel      *uint
	resume      *uint
	drop        *uint
}

func (o *restoreOpts) register(fs *flag.FlagSet) {
	o.stream = fs.String("restore", "", "restore archived days of a stream (syslog, sflow, netflow, sflow-counters) to a staging table; needs --from and --to")
	o.from = fs.String("from", "", "with --restore: the first message day, YYYY-MM-DD (UTC)")
	o.to = fs.String("to", "", "with --restore: the last message day, YYYY-MM-DD (UTC, inclusive)")
	o.device = fs.Uint("device", 0, "with --restore: one device's rows only")
	o.renormalize = fs.Bool("renormalize", false, "with --restore syslog: re-normalize the staged rows into net_events / sec_events once loaded")
	o.replace = fs.Bool("replace", false, "with --renormalize: rewrite the normalized rows those raw rows already have (after a parser fix)")
	o.fromBucket = fs.Bool("from-bucket", false, "with --restore: select the objects from the bucket's sealed months (_MONTH.json), not the database manifest")
	o.force = fs.Bool("force", false, "with --restore: queue it although the disk precheck refuses (the database volume's free space unknown or too small)")
	o.rate = fs.Int("rate", 0, fmt.Sprintf("with --restore: rows per second (%d-%d, default %d)", database.ArchiveRestoreMinRate, database.ArchiveRestoreMaxRate, database.ArchiveRestoreDefaultRate))
	o.ttlDays = fs.Int("ttl-days", 0, fmt.Sprintf("with --restore: days before the staging table is dropped (1-%d, default %d)", database.ArchiveRestoreMaxTTLDays, database.ArchiveRestoreDefaultTTLDays))
	o.list = fs.Bool("restores", false, "list the restores")
	o.cancel = fs.Uint("cancel-restore", 0, "cancel a queued or running restore")
	o.resume = fs.Uint("resume-restore", 0, "resume a failed or cancelled restore")
	o.drop = fs.Uint("drop-restore", 0, "drop a finished restore's staging table")
}

// commands counts the restore commands given.
func (o *restoreOpts) commands() int {
	n := 0
	for _, m := range []bool{*o.stream != "", *o.list, *o.cancel != 0, *o.resume != 0, *o.drop != 0} {
		if m {
			n++
		}
	}
	return n
}

// mode reports whether a restore command was given (counted as one mode
// beside the archive command's others).
func (o *restoreOpts) mode() bool { return o.commands() > 0 }

// check validates a restore command's options ("" when fine).
func (o *restoreOpts) check() string {
	if o.commands() != 1 {
		return "one restore command at a time"
	}
	if *o.stream == "" {
		return o.stray()
	}
	if *o.from == "" || *o.to == "" {
		return "--restore needs --from and --to"
	}
	return ""
}

// stray reports a --restore option given without --restore.
func (o *restoreOpts) stray() string {
	if *o.from != "" || *o.to != "" || *o.device != 0 || *o.renormalize || *o.replace || *o.fromBucket || *o.force || *o.rate != 0 || *o.ttlDays != 0 {
		return "--from, --to, --device, --renormalize, --replace, --from-bucket, --force, --rate and --ttl-days go with --restore"
	}
	return ""
}

// run executes the restore command against db.
func (o *restoreOpts) run(db archiveStore, cfg *config.Config, audit func(action, target string), stdout, stderr io.Writer) int {
	ctx := context.Background()
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "archive: "+format+"\n", args...)
		return 1
	}
	jobOf := func(id uint) (*models.ArchiveRestoreJob, int) {
		j, err := db.GetArchiveRestoreJob(id)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fail("restore %d not found", id)
		}
		if err != nil {
			return nil, fail("%v", err)
		}
		return j, 0
	}
	switch {
	case *o.list:
		jobs, err := db.ListArchiveRestoreJobs(50)
		if err != nil {
			return fail("%v", err)
		}
		if len(jobs) == 0 {
			fmt.Fprintln(stdout, "no restores")
		}
		for i := range jobs {
			printRestore(stdout, &jobs[i], db.ArchiveRestoreTableBytes(ctx, jobs[i].StagingTable))
		}
		return 0
	case *o.cancel != 0:
		j, code := jobOf(*o.cancel)
		if j == nil {
			return code
		}
		st, ok, err := db.CancelArchiveRestoreJob(j.ID)
		if err != nil {
			return fail("%v", err)
		}
		if !ok {
			return fail("restore %d is %s and cannot be cancelled", j.ID, j.Status)
		}
		audit("archive_restore_cancel", fmt.Sprintf("restore_id=%d", j.ID))
		fmt.Fprintf(stdout, "restore %d: %s\n", j.ID, st)
		return 0
	case *o.resume != 0:
		j, code := jobOf(*o.resume)
		if j == nil {
			return code
		}
		ok, err := db.ResumeArchiveRestoreJob(j.ID)
		if err != nil {
			return fail("%v", err)
		}
		if !ok {
			return fail("restore %d is %s; only a failed or cancelled restore resumes", j.ID, j.Status)
		}
		audit("archive_restore_resume", fmt.Sprintf("restore_id=%d", j.ID))
		fmt.Fprintf(stdout, "restore %d is pending again: it continues from its cursors\n", j.ID)
		return 0
	case *o.drop != 0:
		j, code := jobOf(*o.drop)
		if j == nil {
			return code
		}
		if _, err := db.DropArchiveRestore(ctx, j.ID, time.Now()); err != nil {
			if errors.Is(err, database.ErrArchiveRestoreBusy) || errors.Is(err, database.ErrArchiveRestoreInUse) {
				return fail("restore %d is %s: %v", j.ID, j.Status, err)
			}
			return fail("drop: %v", err)
		}
		audit("archive_restore_drop", fmt.Sprintf("restore_id=%d staging=%s", j.ID, j.StagingTable))
		fmt.Fprintf(stdout, "restore %d: %s dropped\n", j.ID, j.StagingTable)
		return 0
	}

	if err := cfg.Archive.ValidateTarget(); err != nil {
		return fail("the archive target is not configured (the poller restores with the same ARCHIVE_* keys): %v", err)
	}
	if !filepath.IsAbs(cfg.Archive.StagingDir) {
		return fail("ARCHIVE_STAGING_DIR is not set: the poller downloads the objects there")
	}
	from, err := database.ParseArchiveRestoreDay(*o.from)
	if err != nil {
		return fail("--from: %v", err)
	}
	to, err := database.ParseArchiveRestoreDay(*o.to)
	if err != nil {
		return fail("--to: %v", err)
	}
	req := database.ArchiveRestoreRequest{Stream: *o.stream, From: from, To: to, FromBucket: *o.fromBucket, Renormalize: *o.renormalize,
		Replace: *o.replace, Rate: *o.rate, TTLDays: *o.ttlDays, Force: *o.force, RequestedBy: "cli"}
	if *o.device != 0 {
		d := *o.device
		req.DeviceID = &d
	}
	plan, err := db.PlanArchiveRestore(ctx, req)
	if err != nil {
		return fail("restore: %v", err)
	}
	job, err := db.CreateArchiveRestoreJob(ctx, plan, time.Now())
	if err != nil {
		return fail("restore: %v", err)
	}
	audit("archive_restore", fmt.Sprintf("restore_id=%d stream=%s days=%s..%s staging=%s force=%t", job.ID, job.Stream, job.FromDay, job.ToDay, job.StagingTable, job.Force))
	fmt.Fprintf(stdout, "restore %d queued: %s %s..%s into %s; the poller's restore worker runs it (fwmon-api archive --restores)\n",
		job.ID, job.Stream, job.FromDay, job.ToDay, job.StagingTable)
	if job.FromBucket {
		fmt.Fprintln(stdout, "  objects are selected from the bucket's sealed months on its first run")
	} else {
		fmt.Fprintf(stdout, "  %d objects, ~%d rows of those days, ~%d MiB staged\n", job.ObjectsTotal, job.RowsEstimate, plan.Estimate.Bytes>>20)
	}
	if job.Note != "" {
		fmt.Fprintf(stdout, "  NOTE: %s\n", job.Note)
	}
	return 0
}

// printRestore writes one restore job as text.
func printRestore(w io.Writer, j *models.ArchiveRestoreJob, bytes int64) {
	dev := "every device"
	if j.DeviceID != nil {
		dev = "device " + strconv.FormatUint(uint64(*j.DeviceID), 10)
	}
	size := "absent"
	if bytes >= 0 {
		size = fmt.Sprintf("%.1f MiB", float64(bytes)/(1<<20))
	}
	fmt.Fprintf(w, "restore %d %s: %s %s..%s (%s) -> %s [%s], objects %d/%d, rows %d of ~%d, expires %s\n", j.ID, j.Status, j.Stream,
		j.FromDay, j.ToDay, dev, j.StagingTable, size, j.ObjectsDone, j.ObjectsTotal, j.RowsLoaded, j.RowsEstimate, j.ExpiresAt.UTC().Format(time.RFC3339))
	if j.Renormalize {
		mode := "skip already normalized rows"
		if j.Replace {
			mode = "replace"
		}
		bf := "not queued yet"
		if j.BackfillJobID != nil {
			bf = "backfill job " + strconv.FormatUint(uint64(*j.BackfillJobID), 10)
		}
		fmt.Fprintf(w, "  renormalize (%s): %s\n", mode, bf)
	}
	if j.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", j.Note)
	}
	if j.Error != "" {
		fmt.Fprintf(w, "  error: %s\n", j.Error)
	}
}
