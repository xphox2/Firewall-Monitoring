package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
//
// Like reset-auth and normalize-backfill it connects straight to the database
// with the server's environment (`docker exec <container> fwmon-api archive
// ...`). Host access to the database credentials is the authentication here
// — whoever has it can already run reset-auth on any admin account, so a
// password prompt would add nothing — while the API routes re-verify the
// operator's password (+ TOTP). Every change writes an audit_logs row (actor
// "cli") with the reason.
//
// Returns the process exit code.
func runArchiveCmd(args []string) int {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "archive: configuration error: %v\n", err)
		return 1
	}
	return archiveCmd(args, os.Stdout, os.Stderr, func() (archiveStore, error) {
		db, err := database.Connect(cfg)
		if err != nil {
			return nil, err
		}
		return db, nil
	})
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
}

// archiveCmdReasonMax matches the API's bound on the reason.
const archiveCmdReasonMax = 500

// archiveCmd is the testable core of runArchiveCmd.
func archiveCmd(args []string, stdout, stderr io.Writer, open func() (archiveStore, error)) int {
	fs := flag.NewFlagSet("archive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	override := fs.String("override", "", "release the retention gate of a stream: syslog, flows or all")
	dur := fs.Duration("for", 0, fmt.Sprintf("with --override: how long the gate stays released (max %dh)", database.ArchiveGateOverrideMaxHours))
	clearOv := fs.Bool("clear", false, "with --override: re-engage the gate now")
	resetChunk := fs.Uint("reset-chunk", 0, "put a chunk parked in needs_attention back to pending (re-exported on the worker's next pass)")
	reason := fs.String("reason", "", "why (required to release the gate or reset a chunk; recorded in the audit log)")
	status := fs.Bool("gate-status", false, "print each stream's override and the chunks in needs_attention")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: fwmon-api archive --override syslog|flows|all --for 6h --reason \"<why>\"")
		fmt.Fprintln(stderr, "       fwmon-api archive --override syslog|flows|all --clear [--reason \"<why>\"]")
		fmt.Fprintln(stderr, "       fwmon-api archive --reset-chunk <id> --reason \"<why>\"")
		fmt.Fprintln(stderr, "       fwmon-api archive --gate-status")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, m := range []bool{*override != "", *resetChunk != 0, *status} {
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
	if modes != 1 || fs.NArg() > 0 {
		return usage("")
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
	case *status:
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
		if errors.Is(err, database.ErrArchiveChunkNotParked) {
			fmt.Fprintf(stderr, "archive: chunk %d is %s, not %s\n", c.ID, c.Status, models.ArchiveChunkNeedsAttention)
		} else {
			fmt.Fprintf(stderr, "archive: reset: %v\n", err)
		}
		return 1
	}
	audit("archive_chunk_reset", fmt.Sprintf("chunk_id=%d table=%s seq=%d mismatches=%d reason=%q", c.ID, c.SourceTable, c.Seq, c.Mismatches, why))
	fmt.Fprintf(stdout, "chunk %d (%s seq %d) is pending again: the archive worker exports it on its next pass\n", c.ID, c.SourceTable, c.Seq)
	return 0
}
