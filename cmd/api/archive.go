package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/archive/worker"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// runArchiveCmd implements `fwmon-api archive` (archive plan PR 5), the CLI
// twin of the retention gate's admin routes (handlers_archive.go):
//
//	archive --override syslog|flows|all --for 6h --reason "<why>"   release the gate (max 24h)
//	archive --override syslog|flows|all --clear [--reason "<why>"]  re-engage it now
//	archive --reset-chunk <id> --reason "<why>"                     needs_attention → pending
//	archive --gate-status                                           overrides + parked chunks
//	archive --status [--json]                                       the whole archive (as GET /admin/api/archive/status)
//	archive --verify-month <stream> <YYYY-MM>                       re-check a sealed month from the bucket
//	archive --restore <stream> --from <day> --to <day> [...]        restore archived days to a staging table
//	archive --restores                                              list the restores
//	archive --cancel-restore <id> | --resume-restore <id> | --drop-restore <id>
//	archive --env-only <any of the above>                            ignore the admin page's archive settings
//
// Like reset-auth and normalize-backfill it connects straight to the database
// with the server's environment (`docker exec <container> fwmon-api archive
// ...`). Host access to the database credentials is the authentication here
// — whoever has it can already run reset-auth on any admin account, so a
// password prompt would add nothing — while the API routes re-verify the
// operator's password (+ TOTP). Every change writes an audit_logs row (actor
// "cli") with the reason.
//
// --restore (archive plan PR 9) queues a restore to a staging table
// (restore_<id>_<table>; see archive_restore.go): the poller's restore worker
// downloads, verifies and stages the rows. It, --resume-restore and
// --drop-restore are audit-logged like the API's re-authenticated routes.
//
// --verify-month (archive plan PR 7) needs no database: it reads the month's
// _MONTH.json and every chunk.json and object it pins from the bucket
// (ARCHIVE_S3_* keys) and re-checks them all (worker.VerifyMonth). It only
// reads; its exit code is 0 when every check passed, 1 otherwise.
//
// Every subcommand uses the archive configuration in effect: the ARCHIVE_*
// environment with the admin page's settings applied (A-10), read once from
// the database at start (resolveArchiveForCLI), unless --env-only is given.
//
// Returns the process exit code.
func runArchiveCmd(args []string) int {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "archive: configuration error: %v\n", err)
		return 1
	}
	args, envOnly := stripArchiveEnvOnly(args)
	if !envOnly {
		cfg = resolveArchiveForCLI(cfg, os.Stderr)
	}
	return archiveCmd(args, os.Stdout, os.Stderr, cfg, func() (archiveStore, error) {
		db, err := database.Connect(cfg)
		if err != nil {
			return nil, err
		}
		return db, nil
	}, func() (worker.MonthReader, error) {
		return s3.New(cfg.Archive)
	})
}

// resolveArchiveForCLI applies the admin page's archive settings (A-10) to
// cfg, as the poller and the API do. When the database cannot be reached the
// environment's settings are used, with a note: --verify-month needs only the
// bucket.
func resolveArchiveForCLI(cfg *config.Config, stderr io.Writer) *config.Config {
	db, err := database.Connect(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "archive: note: database unreachable (%v); using the ARCHIVE_* environment only, not the admin page's settings\n", err)
		return cfg
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := db.ResolveArchiveConfig(ctx, cfg.Archive)
	if err != nil {
		fmt.Fprintf(stderr, "archive: note: %v; using the ARCHIVE_* environment only\n", err)
		return cfg
	}
	return cfg.WithArchive(res.Config)
}

// stripArchiveEnvOnly removes --env-only from args: the command then uses the
// ARCHIVE_* environment as given, without the admin page's settings (to
// check a bucket other than the one in effect, e.g. while moving the archive).
func stripArchiveEnvOnly(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	for _, a := range args {
		if a == "--env-only" || a == "-env-only" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// archiveStore is the slice of *database.Database the command needs.
type archiveStore interface {
	SetArchiveGateOverride(stream string, until time.Time) error
	ArchiveGateOverride(stream string, now time.Time) (until time.Time, active bool)
	GetArchiveChunk(id uint) (*models.ArchiveChunk, error)
	ListArchiveChunksNeedingAttention(limit int) ([]models.ArchiveChunk, error)
	ResetArchiveChunk(ctx context.Context, id uint, note string, at time.Time) (*models.ArchiveChunk, error)
	SaveAuditLog(entry *models.AuditLog) error
	Close() error
	// --status reads what the status API reads.
	status.Store
	// --restore and the restore job commands.
	database.ArchiveRestoreStore
}

// archiveCmdReasonMax matches the API's bound on the reason.
const archiveCmdReasonMax = 500

// archiveCmd is the testable core of runArchiveCmd.
func archiveCmd(args []string, stdout, stderr io.Writer, cfg *config.Config, open func() (archiveStore, error), openBucket func() (worker.MonthReader, error)) int {
	fs := flag.NewFlagSet("archive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	override := fs.String("override", "", "release the retention gate of a stream: syslog, flows or all")
	dur := fs.Duration("for", 0, fmt.Sprintf("with --override: how long the gate stays released (max %dh)", database.ArchiveGateOverrideMaxHours))
	clearOv := fs.Bool("clear", false, "with --override: re-engage the gate now")
	resetChunk := fs.Uint("reset-chunk", 0, "put a chunk parked in needs_attention back to pending (re-exported on the worker's next pass)")
	reason := fs.String("reason", "", "why (required to release the gate or reset a chunk; recorded in the audit log)")
	gateStatus := fs.Bool("gate-status", false, "print each stream's override and the chunks in needs_attention")
	fullStatus := fs.Bool("status", false, "print the whole archive: per table V, lag, chunks, waits; per stream the months; gates, parked chunks, the worker's last failures")
	asJSON := fs.Bool("json", false, "with --status: print the JSON of GET /admin/api/archive/status")
	verifyMonth := fs.String("verify-month", "", "re-check a sealed month from the bucket alone: --verify-month <stream> <YYYY-MM> (read-only)")
	var ro restoreOpts
	ro.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: fwmon-api archive --override syslog|flows|all --for 6h --reason \"<why>\"")
		fmt.Fprintln(stderr, "       fwmon-api archive --override syslog|flows|all --clear [--reason \"<why>\"]")
		fmt.Fprintln(stderr, "       fwmon-api archive --reset-chunk <id> --reason \"<why>\"")
		fmt.Fprintln(stderr, "       fwmon-api archive --gate-status")
		fmt.Fprintln(stderr, "       fwmon-api archive --status [--json]")
		fmt.Fprintln(stderr, "       fwmon-api archive --verify-month syslog|sflow|netflow|sflow-counters <YYYY-MM>")
		fmt.Fprintln(stderr, "       fwmon-api archive --restore syslog|sflow|netflow|sflow-counters --from <YYYY-MM-DD> --to <YYYY-MM-DD>")
		fmt.Fprintln(stderr, "             [--device <id>] [--renormalize [--replace]] [--from-bucket] [--force] [--rate <rows/s>] [--ttl-days <n>]")
		fmt.Fprintln(stderr, "       fwmon-api archive --restores | --cancel-restore <id> | --resume-restore <id> | --drop-restore <id>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, m := range []bool{*override != "", *resetChunk != 0, *gateStatus, *fullStatus, *verifyMonth != "", ro.mode()} {
		if m {
			modes++
		}
	}
	why := strings.TrimSpace(*reason)
	usage := func(msg string) int {
		if msg != "" {
			fmt.Fprintf(stderr, "archive: %s\n", msg)
		}
		fs.Usage()
		return 2
	}
	if *verifyMonth != "" {
		if modes != 1 || fs.NArg() != 1 || *reason != "" || *clearOv || *dur != 0 {
			return usage("--verify-month takes a stream and a month, and nothing else")
		}
		return verifyMonthCmd(*verifyMonth, fs.Arg(0), stdout, stderr, openBucket)
	}
	if modes != 1 || fs.NArg() > 0 {
		return usage("")
	}
	if ro.mode() {
		if *reason != "" || *clearOv || *dur != 0 || *asJSON {
			return usage("the restore commands take no --reason, --for, --clear or --json")
		}
		if msg := ro.check(); msg != "" {
			return usage(msg)
		}
	} else if msg := ro.stray(); msg != "" {
		return usage(msg)
	}
	if *asJSON && !*fullStatus {
		return usage("--json goes with --status")
	}
	if *fullStatus && (*reason != "" || *clearOv || *dur != 0) {
		return usage("--status takes no other option but --json")
	}
	if len(why) > archiveCmdReasonMax {
		return usage(fmt.Sprintf("--reason must be at most %d characters", archiveCmdReasonMax))
	}
	var streams []string
	if *override != "" {
		var err error
		if streams, err = database.ParseArchiveGateStreams(*override); err != nil {
			return usage(err.Error())
		}
		switch {
		case *clearOv && *dur != 0:
			return usage("--clear and --for are exclusive")
		case !*clearOv && (*dur <= 0 || *dur > database.ArchiveGateOverrideMaxHours*time.Hour):
			return usage(fmt.Sprintf("--for must be more than 0 and at most %dh", database.ArchiveGateOverrideMaxHours))
		case !*clearOv && why == "":
			return usage("--reason is required to release the gate")
		}
	} else if *clearOv || *dur != 0 {
		return usage("--for and --clear go with --override")
	}
	if *resetChunk != 0 && why == "" {
		return usage("--reason is required to reset a chunk")
	}

	db, err := open()
	if err != nil {
		fmt.Fprintf(stderr, "archive: connect: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	audit := func(action, target string) {
		if err := db.SaveAuditLog(&models.AuditLog{CreatedAt: time.Now(), Actor: "cli", Method: "CLI",
			Action: action, Target: target, Status: 200}); err != nil {
			fmt.Fprintf(stderr, "archive: WARNING: audit log write failed: %v\n", err)
		}
	}
	now := time.Now().UTC()

	switch {
	case ro.mode():
		return ro.run(db, cfg, audit, stdout, stderr)
	case *fullStatus:
		st, err := status.Build(context.Background(), db, cfg, time.Now())
		if err != nil {
			fmt.Fprintf(stderr, "archive: status: %v\n", err)
			return 1
		}
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(st); err != nil {
				fmt.Fprintf(stderr, "archive: status: %v\n", err)
				return 1
			}
			return 0
		}
		printArchiveStatus(stdout, st)
		return 0
	case *gateStatus:
		for _, s := range database.ArchiveGateStreams {
			if until, active := db.ArchiveGateOverride(s, now); active {
				fmt.Fprintf(stdout, "%-7s gate RELEASED until %s\n", s, until.UTC().Format(time.RFC3339))
			} else {
				fmt.Fprintf(stdout, "%-7s gate engaged (when the stream's archiving is enabled)\n", s)
			}
		}
		parked, err := db.ListArchiveChunksNeedingAttention(100)
		if err != nil {
			fmt.Fprintf(stderr, "archive: %v\n", err)
			return 1
		}
		if len(parked) == 0 {
			fmt.Fprintln(stdout, "no chunk needs attention")
		}
		for _, c := range parked {
			fmt.Fprintf(stdout, "chunk %d: %s seq %d (%d, %d] %s, %d mismatches: %s\n", c.ID, c.SourceTable, c.Seq, c.IDLo, c.IDHi,
				c.PeriodStart.UTC().Format(time.RFC3339), c.Mismatches, c.Error)
		}
		return 0
	case *override != "":
		var until time.Time
		if !*clearOv {
			until = now.Add(*dur).Truncate(time.Second)
		}
		for _, s := range streams {
			if err := db.SetArchiveGateOverride(s, until); err != nil {
				fmt.Fprintf(stderr, "archive: %v\n", err)
				return 1
			}
			if *clearOv {
				audit("archive_gate_override", fmt.Sprintf("stream=%s re-engaged reason=%q", s, why))
				fmt.Fprintf(stdout, "%s: gate re-engaged\n", s)
				continue
			}
			audit("archive_gate_override", fmt.Sprintf("stream=%s until=%s reason=%q", s, until.Format(time.RFC3339), why))
			fmt.Fprintf(stdout, "%s: gate RELEASED until %s — rows deleted meanwhile may never reach the archive\n", s, until.Format(time.RFC3339))
		}
		return 0
	}

	c, err := db.GetArchiveChunk(*resetChunk)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			fmt.Fprintf(stderr, "archive: chunk %d not found\n", *resetChunk)
		} else {
			fmt.Fprintf(stderr, "archive: %v\n", err)
		}
		return 1
	}
	if _, err := db.ResetArchiveChunk(context.Background(), c.ID, "reset for re-export from the CLI: "+why, time.Now()); err != nil {
		switch {
		case errors.Is(err, database.ErrArchiveChunkSealed):
			fmt.Fprintf(stderr, "archive: chunk %d (%s %s): %v\n", c.ID, c.SourceTable, c.Month, err)
		case errors.Is(err, database.ErrArchiveChunkNotParked):
			fmt.Fprintf(stderr, "archive: chunk %d is %s, not %s\n", c.ID, c.Status, models.ArchiveChunkNeedsAttention)
		default:
			fmt.Fprintf(stderr, "archive: reset: %v\n", err)
		}
		return 1
	}
	audit("archive_chunk_reset", fmt.Sprintf("chunk_id=%d table=%s seq=%d mismatches=%d reason=%q", c.ID, c.SourceTable, c.Seq, c.Mismatches, why))
	fmt.Fprintf(stdout, "chunk %d (%s seq %d) is pending again: the archive worker exports it on its next pass\n", c.ID, c.SourceTable, c.Seq)
	return 0
}

// verifyMonthCmd runs --verify-month and prints its report.
func verifyMonthCmd(stream, month string, stdout, stderr io.Writer, openBucket func() (worker.MonthReader, error)) int {
	store, err := openBucket()
	if err != nil {
		fmt.Fprintf(stderr, "archive: bucket: %v\n", err)
		return 1
	}
	rep, err := worker.VerifyMonth(context.Background(), store, stream, month, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "archive: verify-month: %v\n", err)
		return 1
	}
	kind := "full month"
	if rep.Partial {
		kind = "PARTIAL month: " + rep.PartialNote
	}
	fmt.Fprintf(stdout, "%s %s (schema v%d, %s)\n", rep.Stream, rep.Month, rep.SchemaVersion, rep.ManifestKey)
	fmt.Fprintf(stdout, "  %s\n  ids (%d, %d], %d chunks, %d objects, %d rows, %d bytes stored\n  month digest %s\n",
		kind, rep.FirstID, rep.LastID, rep.Chunks, rep.Objects, rep.Rows, rep.Bytes, rep.Digest)
	if rep.OK() {
		fmt.Fprintln(stdout, "OK: every object, chunk manifest and the month manifest match")
		return 0
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(stdout, "PROBLEM: %s\n", p)
	}
	fmt.Fprintf(stdout, "FAILED: %d problem(s)\n", len(rep.Problems))
	return 1
}

// printArchiveStatus writes st as text (--status).
func printArchiveStatus(w io.Writer, st *status.Status) {
	ts := func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return t.UTC().Format(time.RFC3339)
	}
	dur := func(sec float64) string {
		d := time.Duration(sec * float64(time.Second))
		if d >= 48*time.Hour {
			return fmt.Sprintf("%.1f days", d.Hours()/24)
		}
		return fmt.Sprintf("%.1f h", d.Hours())
	}
	gib := func(b uint64) string { return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30)) }
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	c := st.Config
	fmt.Fprintf(w, "raw archive at %s: syslog %s, flows %s\n", st.GeneratedAt.Format(time.RFC3339), onOff(c.SyslogEnabled), onOff(c.FlowsEnabled))
	if st.Enabled {
		lock := "no Object Lock"
		if c.ObjectLockDays > 0 {
			lock = fmt.Sprintf("Object Lock %s %d days", c.ObjectLockMode, c.ObjectLockDays)
		}
		fmt.Fprintf(w, "  bucket %s prefix %s at %s (region %s, key %s), %s; seal grace %d h (%s)\n",
			c.Bucket, c.Prefix, c.Endpoint, c.Region, c.AccessKeyID, lock, c.SealGraceHours, c.SealReverify)
	}
	if wk := st.Worker; wk == nil && st.WorkerError != "" {
		fmt.Fprintf(w, "worker: state unreadable: %s\n", st.WorkerError)
	} else if wk == nil {
		fmt.Fprintln(w, "worker: no state recorded (the poller's archive worker has not run)")
	} else {
		stale := ""
		if wk.Stale {
			stale = " — STALE: no archive worker is writing its state (poller down or wedged)"
		}
		pre := "preflight passed"
		if !wk.PreflightOK {
			pre = "PREFLIGHT NOT PASSED (nothing is archived)"
		}
		fmt.Fprintf(w, "worker: %s, seen %s (%s ago)%s; %s\n", wk.Runner, wk.SeenAt.Format(time.RFC3339), dur(wk.AgeSeconds), stale, pre)
		switch {
		case wk.Staging.Error != "":
			fmt.Fprintf(w, "  staging %s: free space unknown: %s\n", wk.Staging.Dir, wk.Staging.Error)
		case wk.Staging.FreeBytes != nil:
			low := ""
			if *wk.Staging.FreeBytes < wk.Staging.MinFreeBytes {
				low = " — BELOW THE FLOOR: no chunk is exported"
			}
			fmt.Fprintf(w, "  staging %s: %s free (floor %s)%s\n", wk.Staging.Dir, gib(*wk.Staging.FreeBytes), gib(wk.Staging.MinFreeBytes), low)
		}
		if a := wk.Activity; a != nil {
			line := fmt.Sprintf("  working: %s chunk %d (%s), %s for %s", a.Table, a.Seq, a.PeriodStart.Format(time.RFC3339), a.Stage, dur(a.StageElapsedSeconds))
			switch {
			case a.Stage == "export":
				line += fmt.Sprintf(", %d rows read", a.RowsDone)
			case a.ObjectsTotal > 0:
				line += fmt.Sprintf(", %d of %d objects", a.ObjectsDone, a.ObjectsTotal)
			}
			if a.Fraction != nil {
				line += fmt.Sprintf(" (%.0f%%)", *a.Fraction*100)
			}
			fmt.Fprintln(w, line)
		}
		switch {
		case wk.PassRunning:
			fmt.Fprintf(w, "  pass running since %s\n", ts(wk.LastPassAt))
		case wk.NextPassAt != nil:
			fmt.Fprintf(w, "  last pass %s; next %s\n", ts(wk.LastPassAt), ts(wk.NextPassAt))
		}
		for _, e := range wk.Stages {
			fmt.Fprintf(w, "  last %s failure %s (%d since the worker started): %s\n", e.Stage, e.At.Format(time.RFC3339), e.Count, e.Error)
		}
	}
	if g := st.GateRead; g != nil {
		what := "keeps the switches it read last"
		if g.HoldingAll {
			what = "HOLDS every archived table's deletes"
		}
		fmt.Fprintf(w, "retention gate: CANNOT READ the stream switches for %s (since %s); it %s: %s\n", dur(g.ForSeconds), g.FailingSince.Format(time.RFC3339), what, g.Error)
	}
	fmt.Fprintln(w, "gates:")
	for _, g := range st.Gates {
		switch {
		case g.OverrideActive:
			fmt.Fprintf(w, "  %-7s RELEASED by an override until %s: rows are deleted whether or not they are archived\n", g.Stream, ts(g.OverrideUntil))
		case g.Gated:
			fmt.Fprintf(w, "  %-7s engaged: deletes take only verified rows\n", g.Stream)
		default:
			fmt.Fprintf(w, "  %-7s archiving disabled: deletes are not gated\n", g.Stream)
		}
	}
	fmt.Fprintln(w, "tables:")
	for _, t := range st.Tables {
		if !t.Enabled && !t.HasChunks {
			continue
		}
		lag := "no chunk yet"
		if t.LagSeconds != nil {
			lag = "lag " + dur(*t.LagSeconds)
		}
		fmt.Fprintf(w, "  %s (%s): verified through id %d (%s), %s\n", t.Table, onOff(t.Enabled), t.VerifiedThroughID, ts(t.VerifiedThroughEnd), lag)
		var counts []string
		for _, s := range status.ChunkStatuses {
			if n := t.Chunks[s]; n > 0 {
				counts = append(counts, fmt.Sprintf("%s %d", s, n))
			}
		}
		if len(counts) == 0 {
			counts = []string{"none"}
		}
		fmt.Fprintf(w, "    chunks: %s; last verified %s", strings.Join(counts, ", "), ts(t.LastVerifiedAt))
		if t.LastMarkAt != nil {
			fmt.Fprintf(w, "; last id mark %s", ts(t.LastMarkAt))
		}
		fmt.Fprintln(w)
		if b := t.Backlog; b != nil {
			line := fmt.Sprintf("    backlog: %d of %d chunks verified", b.Verified, b.Chunks)
			if b.Remaining > 0 {
				line += fmt.Sprintf(", %d left from %s (up to %d rows)", b.Remaining, ts(b.OldestRemaining), b.RemainingRows)
			}
			if b.RateRowsPerSec != nil {
				line += fmt.Sprintf("; %.0f rows/s", *b.RateRowsPerSec)
			}
			if b.ETASeconds != nil {
				line += "; about " + dur(*b.ETASeconds) + " of work left"
			}
			fmt.Fprintln(w, line)
		}
		if u := t.Unsettled; u != nil {
			left := ""
			if u.LeftSeconds != nil {
				left = fmt.Sprintf(" (%s left)", dur(*u.LeftSeconds))
			}
			fmt.Fprintf(w, "    waiting: %s for %s%s: %s\n", u.Reason, dur(u.ForSeconds), left, u.Detail)
		}
		if r := t.Retention; r != nil && r.HeldSeconds > 0 {
			fmt.Fprintf(w, "    retention %s: the gate holds unarchived rows up to %s past the cutoff %s\n", r.Window, dur(r.HeldSeconds), r.Cutoff.Format(time.RFC3339))
		}
	}
	fmt.Fprintln(w, "streams:")
	for _, s := range st.Streams {
		if !s.Enabled && len(s.Months) == 0 {
			continue
		}
		line := fmt.Sprintf("  %s: last sealed %s", s.Stream, ts(s.LastSealedAt))
		if s.OldestUnsealed != "" {
			line += fmt.Sprintf("; %s is due and NOT sealed (%.1f days past its seal time)", s.OldestUnsealed, s.UnsealedDays)
		}
		fmt.Fprintln(w, line)
		for _, m := range s.Months {
			var flags []string
			if m.Partial {
				flags = append(flags, "PARTIAL")
			}
			if len(m.Degraded) > 0 {
				flags = append(flags, fmt.Sprintf("%d gate event(s)", len(m.Degraded)))
			}
			if m.Status == models.ArchiveMonthSealed {
				flags = append(flags, fmt.Sprintf("%d chunks, %d rows, %s, sealed %s", m.ChunkCount, m.RowCount, gib(uint64(max(0, m.ObjectBytes))), ts(m.SealedAt)))
			} else if m.Due {
				flags = append(flags, "due")
			}
			if m.Error != "" {
				flags = append(flags, m.Error)
			}
			fmt.Fprintf(w, "    %s %s %s\n", m.Month, m.Status, strings.Join(flags, "; "))
		}
	}
	if len(st.NeedsAttention) == 0 {
		fmt.Fprintln(w, "no chunk needs attention")
	}
	for _, p := range st.NeedsAttention {
		holds := "does not hold the gate"
		if p.HoldsGate {
			holds = "HOLDS its table's deletes"
		}
		fmt.Fprintf(w, "needs attention: chunk %d %s seq %d (%d, %d] %s, %d mismatches, %s: %s\n",
			p.ID, p.Table, p.Seq, p.IDLo, p.IDHi, p.PeriodStart.Format(time.RFC3339), p.Mismatches, holds, p.Error)
	}
	for _, p := range st.Problems {
		fmt.Fprintf(w, "PROBLEM reading the status: %s\n", p)
	}
}
