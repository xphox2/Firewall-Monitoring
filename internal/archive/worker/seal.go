package worker

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- the S3 ETag of a single-part object
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/objstore"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
)

// The month seal (archive plan PR 7, §3.1). At the first pass at or after the
// 1st of month M+1, 00:00 UTC, + ARCHIVE_SEAL_GRACE_HOURS, the worker seals
// month M of every stream, oldest month first:
//
//  1. Completeness, in the database: every chunk of the table cut for M is
//     verified, the chunks are gapless (seq, id range and period each continue
//     the previous one), the last ends exactly at the 1st of M+1, and the
//     first continues the previous month's last chunk — whose month must be
//     sealed with that id as its last_id. Only the month of the table's first
//     chunk (id_lo 0) has no predecessor: it is sealed as PARTIAL, because the
//     archive cannot prove that rows ingested before it began were not deleted
//     by retention first.
//  2. Re-verification in the bucket: every object of the month (HEAD: size
//     and ETag, and the Object Lock state when reported; ARCHIVE_SEAL_REVERIFY
//     =full also reads it back and re-hashes the stored bytes) and every
//     chunk.json (the stored one must be byte for byte what the database
//     describes).
//  3. _MONTH.json: the chunk list with every object's key, version id, hashes
//     and row count, the totals and the month digest. Uploaded with Object
//     Lock, read back, and only then is the month recorded sealed.
//
// An incomplete month is never sealed: the month is recorded seal_failed with
// the reason, fwmon_archive_seal_blocked{stream,reason} is set and the next
// pass tries again; later months of the stream wait for it (each month proves
// it joins the previous one). Once sealed, the worker refuses any write into
// the month's folder (put). The seal gates no delete: the retention gate is
// per verified chunk (archive_gate.go).
//
// _MONTH.json holds no wall-clock field, so sealing again after a crash
// between the upload and the database record writes the same bytes: the
// stored copy is then read back instead of written again. A different
// _MONTH.json already in the folder is never overwritten.

// MonthManifestKind identifies a _MONTH.json.
const MonthManifestKind = "fwmon-archive-month"

// monthDigestInput documents month_digest inside every _MONTH.json, so the
// folder can be checked without this code.
const monthDigestInput = "sha256 over, for each chunk in seq order, the line \"chunk <seq> <id_lo> <id_hi>\\n\" followed, for each of its objects in the order listed, by the line \"<object key below the month folder> <rows> <sha256_content>\\n\""

// monthManifest is _MONTH.json.
type monthManifest struct {
	Kind            string `json:"kind"`
	ManifestVersion int    `json:"manifest_version"`
	Stream          string `json:"stream"`
	Month           string `json:"month"`
	Table           string `json:"table"`
	SchemaVersion   int    `json:"schema_version"`
	Compression     string `json:"compression"`
	// Partial: the archive began in this month (see PartialNote).
	Partial     bool   `json:"partial"`
	PartialNote string `json:"partial_note,omitempty"`
	// The month's chunks cover the source table's ids (first_id, last_id]:
	// first_id is the previous month's last_id (0 for the first archived
	// month). FirstRowID is the smallest id of a row of this stream in the
	// month (absent when it has none).
	FirstID     int64  `json:"first_id"`
	LastID      int64  `json:"last_id"`
	FirstRowID  *int64 `json:"first_row_id,omitempty"`
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	// BoundaryLateByMs: how late the id mark that closes the month was taken
	// (flow streams); rows that arrived meanwhile are in this month.
	BoundaryLateByMs *int64           `json:"boundary_late_by_ms,omitempty"`
	ChunkCount       int              `json:"chunk_count"`
	ObjectCount      int              `json:"object_count"`
	Rows             int64            `json:"rows"`
	RawBytes         int64            `json:"raw_bytes"`
	ObjectBytes      int64            `json:"object_bytes"`
	MsgDayHistogram  map[string]int64 `json:"msg_day_histogram"`
	// Degraded lists the intervals the stream's raw deletes did not (or may
	// not) wait for the archive while rows of this month were not all
	// archived — before the archive began, an unrecorded time before
	// 0.11.307, an override, archiving disabled — clamped to [month start,
	// the month's last chunk verification]. A month with any is partial.
	Degraded         []degradedInterval `json:"degraded,omitempty"`
	MonthDigestInput string             `json:"month_digest_input"`
	MonthDigest      string             `json:"month_digest"`
	Chunks           []monthChunk       `json:"chunks"`
}

// Kinds of a "degraded" interval besides the gate events' (override,
// disabled): before the table's archive began, and a time before 0.11.307 in
// which a disabled period would not have been recorded.
const (
	degradedBeforeArchive = "before_archive"
	degradedUnrecorded    = "unrecorded"
)

// degradedInterval is one entry of _MONTH.json's "degraded".
type degradedInterval struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
}

// monthManifestShaMeta is the object metadata key the seal stores
// _MONTH.json's own sha256 under.
const monthManifestShaMeta = "fwmon-archive-sha256-content"

// degradedIntervals returns the gate events of table's gate stream that
// overlap the month's archiving: from the month's start (its first row can be
// no older by ingest time) to the verification of its last chunk (after it,
// every row of the month is archived). Each is clamped to that window, so
// the list — and _MONTH.json — does not change when an interval is ended
// later.
func (w *Worker) degradedIntervals(ctx context.Context, table, month string, cs []models.ArchiveChunk) ([]degradedInterval, error) {
	start, _, err := monthBounds(month)
	if err != nil {
		return nil, err
	}
	var done time.Time
	for _, c := range cs {
		if c.VerifiedAt != nil && c.VerifiedAt.After(done) {
			done = c.VerifiedAt.UTC()
		}
	}
	if !done.After(start) {
		return nil, nil
	}
	var out []degradedInterval
	clampTo := func(t time.Time) time.Time {
		if t.After(done) {
			return done
		}
		return t
	}
	// Before the archive of the table began (its first chunk verified; the
	// stream was enabled no later), nothing waited for it: rows of the month
	// deleted then — by retention, or by the severity 6/7 aggregation after
	// 7 days — are not in the archive.
	began, ok, err := w.db.ArchiveTableBegan(ctx, table)
	if err != nil {
		return nil, err
	}
	if ok && start.Before(began) {
		out = append(out, degradedInterval{Kind: degradedBeforeArchive, From: rfc3339(start), To: rfc3339(clampTo(began))})
	}
	// Before archive_gate_events existed (migration v77) a disabled period
	// was not recorded (overrides were, in the audit log, and are rebuilt):
	// if the archive had begun by then, the time from then (or the month's
	// start) to v77 is unaccounted for.
	since, ok2, err := w.db.ArchiveGateRecordedSince(ctx)
	if err != nil {
		return nil, err
	}
	if ok && ok2 && began.Before(since) && start.Before(since) {
		from := start
		if from.Before(began) {
			from = began
		}
		if from.Before(done) {
			out = append(out, degradedInterval{Kind: degradedUnrecorded, From: rfc3339(from), To: rfc3339(clampTo(since))})
		}
	}
	evs, err := w.db.ArchiveGateEventsOverlapping(ctx, database.ArchiveGateStreamOfTable(table), start, done)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		from, to := e.From.UTC(), done
		if from.Before(start) {
			from = start
		}
		if e.To != nil && e.To.Before(to) {
			to = e.To.UTC()
		}
		out = append(out, degradedInterval{Kind: e.Kind, From: rfc3339(from), To: rfc3339(to)})
	}
	return out, nil
}

// monthChunk is one chunk of the month: its range and period, its chunk.json
// as stored, and this stream's objects of it.
type monthChunk struct {
	Seq          int64            `json:"seq"`
	IDLo         int64            `json:"id_lo"`
	IDHi         int64            `json:"id_hi"`
	PeriodStart  string           `json:"period_start"`
	PeriodEnd    string           `json:"period_end"`
	MarkLateByMs *int64           `json:"mark_late_by_ms,omitempty"`
	Rows         int64            `json:"rows"`
	Manifest     monthFile        `json:"manifest"`
	Objects      []manifestObject `json:"objects"`
}

// monthFile is a stored file the month manifest pins: key, version, size and
// hashes.
type monthFile struct {
	Key       string `json:"key"`
	VersionID string `json:"version_id,omitempty"`
	Size      int64  `json:"size"`
	Sha256    string `json:"sha256"`
	ETag      string `json:"etag"`
}

// monthDigest computes month_digest (monthDigestInput) of chunks whose object
// keys are under folderKey + "/".
func monthDigest(folderKey string, chunks []monthChunk) (string, error) {
	h := sha256.New()
	for _, c := range chunks {
		fmt.Fprintf(h, "chunk %d %d %d\n", c.Seq, c.IDLo, c.IDHi)
		for _, o := range c.Objects {
			name, ok := strings.CutPrefix(o.Key, folderKey+"/")
			if !ok || name == "" {
				return "", fmt.Errorf("object %s is not in the month folder %s", o.Key, folderKey)
			}
			fmt.Fprintf(h, "%s %d %s\n", name, o.Rows, o.Sha256Content)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Seal refusal reasons (fwmon_archive_seal_blocked's reason label).
const (
	sealIncomplete     = "incomplete"
	sealNeedsAttention = "needs_attention"
	sealGap            = "gap"
	sealObjects        = "objects"
	sealReverify       = "reverify"
	sealConflict       = "conflict"
	sealBucket         = "bucket"
)

// sealRefusal is why a month cannot be sealed now.
type sealRefusal struct {
	reason string
	msg    string
}

func (r *sealRefusal) Error() string { return r.reason + ": " + r.msg }

func refuse(reason, format string, args ...any) error {
	return &sealRefusal{reason: reason, msg: fmt.Sprintf(format, args...)}
}

// monthBounds is the UTC start of month ("YYYY-MM") and of the next.
func monthBounds(month string) (time.Time, time.Time, error) {
	start, err := time.Parse("2006-01", month)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("month %q: %w", month, err)
	}
	return start, start.AddDate(0, 1, 0), nil
}

// checkMonth is step 1: whether month of table can be sealed for stream from
// the database alone. cs are the table's chunks of the month in seq order,
// prev the chunk before them (nil for none) and prevMonth stream's row for
// prev's month; objs the non-superseded objects of every chunk in cs. It
// reports whether the month is the archive's first (partial).
func checkMonth(stream, month string, schema int, cs []models.ArchiveChunk, prev *models.ArchiveChunk, prevMonth *models.ArchiveMonth,
	objs map[uint][]models.ArchiveObject) (partial bool, err error) {
	start, end, err := monthBounds(month)
	if err != nil {
		return false, err
	}
	if len(cs) == 0 {
		return false, refuse(sealIncomplete, "no chunk of %s has been cut", month)
	}
	first := cs[0]
	if prev == nil {
		if first.Seq != 1 || first.IDLo != 0 {
			return false, refuse(sealGap, "the month's first chunk is seq %d from id %d, but no chunk precedes it", first.Seq, first.IDLo)
		}
		partial = true
	} else {
		switch {
		case first.Seq != prev.Seq+1 || first.IDLo != prev.IDHi || !first.PeriodStart.Equal(prev.PeriodEnd):
			return false, refuse(sealGap, "chunk %d (ids from %d, period from %s) does not continue chunk %d of %s (ids to %d, period to %s)",
				first.Seq, first.IDLo, rfc3339(first.PeriodStart), prev.Seq, prev.Month, prev.IDHi, rfc3339(prev.PeriodEnd))
		case !first.PeriodStart.Equal(start):
			return false, refuse(sealGap, "the month's first chunk starts at %s, not at %s", rfc3339(first.PeriodStart), rfc3339(start))
		case prevMonth == nil || prevMonth.Status != models.ArchiveMonthSealed:
			return false, refuse(sealGap, "the previous month %s of %s is not sealed", prev.Month, stream)
		case prevMonth.LastID == nil || *prevMonth.LastID != first.IDLo:
			return false, refuse(sealGap, "the previous month %s of %s ends at id %v, this month starts after id %d", prev.Month, stream, ptrVal(prevMonth.LastID), first.IDLo)
		}
	}
	unverified, parked := 0, 0
	for i, c := range cs {
		if i > 0 {
			p := cs[i-1]
			if c.Seq != p.Seq+1 || c.IDLo != p.IDHi || !c.PeriodStart.Equal(p.PeriodEnd) {
				return false, refuse(sealGap, "chunk %d (ids from %d, period from %s) does not continue chunk %d (ids to %d, period to %s)",
					c.Seq, c.IDLo, rfc3339(c.PeriodStart), p.Seq, p.IDHi, rfc3339(p.PeriodEnd))
			}
		}
		if c.IDHi < c.IDLo || c.Month != month || export.MonthOf(c.PeriodStart) != month {
			return false, refuse(sealGap, "chunk %d: ids (%d, %d], month %s, period from %s", c.Seq, c.IDLo, c.IDHi, c.Month, rfc3339(c.PeriodStart))
		}
		switch c.Status {
		case models.ArchiveChunkVerified:
		case models.ArchiveChunkNeedsAttention:
			parked++
		default:
			unverified++
		}
	}
	last := cs[len(cs)-1]
	switch {
	case parked > 0:
		return false, refuse(sealNeedsAttention, "%d of the month's %d chunks need attention", parked, len(cs))
	case unverified > 0:
		return false, refuse(sealIncomplete, "%d of the month's %d chunks are not verified yet", unverified, len(cs))
	case !last.PeriodEnd.Equal(end):
		return false, refuse(sealIncomplete, "the month's chunks reach %s, the month ends at %s", rfc3339(last.PeriodEnd), rfc3339(end))
	}
	for _, c := range cs {
		var rows int64
		for _, o := range objs[c.ID] {
			rows += o.RowCount
			if o.Stream != stream {
				continue
			}
			switch {
			case o.Status != models.ArchiveObjectVerified:
				return false, refuse(sealObjects, "object %s of chunk %d is %s, not verified", o.ObjectKey, c.Seq, o.Status)
			case o.SchemaVersion != schema || o.Compression != export.Compression:
				return false, refuse(sealObjects, "object %s has schema %d / %s, the month %d / %s", o.ObjectKey, o.SchemaVersion, o.Compression, schema, export.Compression)
			case o.RowCount > 0 && (o.MinID <= c.IDLo || o.MaxID > c.IDHi || o.MinID > o.MaxID):
				return false, refuse(sealObjects, "object %s holds ids %d-%d, outside chunk %d's (%d, %d]", o.ObjectKey, o.MinID, o.MaxID, c.Seq, c.IDLo, c.IDHi)
			}
		}
		if rows != c.RowCount {
			return false, refuse(sealObjects, "chunk %d records %d rows, its objects hold %d", c.Seq, c.RowCount, rows)
		}
	}
	return partial, nil
}

func ptrVal(p *int64) any {
	if p == nil {
		return "none"
	}
	return *p
}

// sealGrace is ARCHIVE_SEAL_GRACE_HOURS (48 when unset).
func (w *Worker) sealGrace() time.Duration { return w.cfg.SealGrace() }

// sealDue seals every month that is due, per stream oldest first; a month
// that cannot be sealed stops its stream's later months until it is.
func (w *Worker) sealDue(ctx context.Context) {
	now := w.now()
	due := export.MonthOf(now.Add(-w.sealGrace())) // months before it are due
	for _, t := range w.tables {
		var months []string
		for _, s := range export.StreamsOf(t) {
			if ctx.Err() != nil {
				return
			}
			if months == nil {
				var err error
				if months, err = w.db.ArchiveChunkMonths(ctx, t); err != nil {
					if ctx.Err() == nil {
						w.fail("seal", err)
						w.logf("seal-"+t, "months of %s: %v", t, err)
					}
					return
				}
			}
			sealed, err := w.db.ArchiveSealedMonths(ctx, s)
			if err != nil {
				if ctx.Err() == nil {
					w.fail("seal", err)
					w.logf("seal-"+s, "sealed months of %s: %v", s, err)
				}
				continue
			}
			oldest := ""
			for _, m := range months {
				if m >= due {
					break
				}
				if !sealed[m] {
					oldest = m
					break
				}
			}
			if until, ok := w.cooldown["seal-"+s]; ok && now.Before(until) {
				w.setUnsealedDays(s, oldest, now) // after a refusal or a failure: its backoff
				continue
			}
			blocked, stuck := "", ""
			for _, m := range months {
				if m >= due || ctx.Err() != nil {
					break
				}
				if sealed[m] {
					continue
				}
				if err := w.sealMonth(ctx, t, s, m); err != nil {
					if ctx.Err() != nil {
						return
					}
					blocked, stuck = w.sealFailed(ctx, s, m, err), m
					break
				}
				w.clearLog("seal-" + s)
				delete(w.sealFailures, s)
			}
			metrics.SetArchiveSealBlocked(s, blocked)
			w.setUnsealedDays(s, stuck, now)
		}
	}
}

// setUnsealedDays sets fwmon_archive_month_unsealed_days of stream: how far
// month (the oldest due month that is not sealed; "" for none) is past its
// seal time, the 1st of the next month + the grace.
func (w *Worker) setUnsealedDays(stream, month string, now time.Time) {
	metrics.SetArchiveMonthUnsealedDays(stream, status.UnsealedDays(month, w.sealGrace(), now))
}

// sealFailed records why stream's month was not sealed and returns the
// reason label. The stream then rests for the chunks' retry backoff (1, 5,
// 30 minutes, then every 2 hours), refusal or failure alike: a month refused
// for a reason that persists (a conflicting _MONTH.json, a changed object) must
// not be re-verified — with ARCHIVE_SEAL_REVERIFY=full, re-downloaded — on
// every pass.
func (w *Worker) sealFailed(ctx context.Context, stream, month string, err error) string {
	reason := sealBucket
	var r *sealRefusal
	if errors.As(err, &r) {
		reason = r.reason
	} else {
		w.fail("seal", fmt.Errorf("month %s of %s: %w", month, stream, err))
	}
	w.sealFailures[stream]++
	w.cooldown["seal-"+stream] = w.now().Add(database.ArchiveRetryBackoff(w.sealFailures[stream]))
	w.logf("seal-"+stream, "month %s of %s is not sealed (%s): %v", month, stream, reason, err)
	if rerr := w.db.RefuseArchiveMonth(ctx, stream, month, err.Error(), w.now()); rerr != nil && ctx.Err() == nil {
		w.fail("db", rerr)
		log.Printf("archive: record why month %s of %s is not sealed: %v", month, stream, rerr)
	}
	return reason
}

// sealMonth seals stream's month of table (steps 1-3), or returns why not:
// a *sealRefusal, or the error of the service or the database.
func (w *Worker) sealMonth(ctx context.Context, table, stream, month string) error {
	cs, prev, err := w.db.ArchiveMonthChunks(ctx, table, month)
	if err != nil {
		return err
	}
	if len(cs) == 0 {
		return refuse(sealIncomplete, "no chunk of %s has been cut", month)
	}
	var prevMonth *models.ArchiveMonth
	if prev != nil {
		if prevMonth, err = w.db.ArchiveMonthState(ctx, stream, prev.Month); err != nil {
			return err
		}
	}
	schema, err := w.schemaFor(ctx, &cs[0])
	if err != nil {
		return err
	}
	ids := make([]uint, len(cs))
	for i := range cs {
		ids[i] = cs[i].ID
	}
	objs, err := w.db.ArchiveMonthObjects(ctx, ids)
	if err != nil {
		return err
	}
	first, err := checkMonth(stream, month, schema, cs, prev, prevMonth, objs)
	if err != nil {
		return err
	}

	folderRel := export.MonthFolderRel(stream, schema, month)
	folderKey, err := w.store.Key(folderRel)
	if err != nil {
		return err
	}
	rel := folderRel + "/" + export.MonthManifestName
	// A _MONTH.json this worker did not record writing (its sha256, stored
	// with it, is not the one of this month's last seal attempt) is a
	// conflict: refuse before any re-verification work.
	if info, err := w.store.Head(ctx, rel, ""); err == nil {
		st, err := w.db.ArchiveMonthState(ctx, stream, month)
		if err != nil {
			return err
		}
		if st == nil || st.ManifestSha256 == "" || info.Metadata[monthManifestShaMeta] != st.ManifestSha256 {
			return refuse(sealConflict, "a %s this archive did not write is already stored (%d bytes, ETag %s): it is never overwritten", rel, info.Size, info.ETag)
		}
	} else if !errors.Is(err, objstore.ErrNotFound) {
		return err
	}
	degraded, err := w.degradedIntervals(ctx, table, month, cs)
	if err != nil {
		return err
	}
	partial := first || len(degraded) > 0
	last := cs[len(cs)-1]
	m := monthManifest{
		Kind: MonthManifestKind, ManifestVersion: 1, Stream: stream, Month: month, Table: table, SchemaVersion: schema,
		Compression: export.Compression, Partial: partial, FirstID: cs[0].IDLo, LastID: last.IDHi,
		PeriodStart: rfc3339(cs[0].PeriodStart), PeriodEnd: rfc3339(last.PeriodEnd), BoundaryLateByMs: last.MarkLateByMs,
		ChunkCount: len(cs), MsgDayHistogram: map[string]int64{}, MonthDigestInput: monthDigestInput, Chunks: make([]monthChunk, 0, len(cs)),
		Degraded: degraded,
	}
	full := w.cfg.SealReverify == config.SealReverifyFull
	for i := range cs {
		c := &cs[i]
		mc, err := w.sealChunk(ctx, c, stream, schema, objs[c.ID], full)
		if err != nil {
			return err
		}
		for _, o := range mc.Objects {
			if o.Rows > 0 && (m.FirstRowID == nil || o.MinID < *m.FirstRowID) {
				id := o.MinID
				m.FirstRowID = &id
			}
			for d, n := range o.MsgDayHistogram {
				m.MsgDayHistogram[d] += n
			}
			m.ObjectCount++
			m.Rows += o.Rows
			m.RawBytes += o.RawBytes
			m.ObjectBytes += o.ObjectBytes
		}
		m.Chunks = append(m.Chunks, mc)
	}
	var notes []string
	if first {
		row := "no row of this stream"
		if m.FirstRowID != nil {
			row = "id " + strconv.FormatInt(*m.FirstRowID, 10) + " as its first row"
		}
		notes = append(notes, fmt.Sprintf("the archive of %s began in this month: its first chunk starts at %s (ingest time) with %s; rows ingested before were deleted by retention before archiving began, or never existed",
			table, m.PeriodStart, row))
	}
	if len(degraded) > 0 {
		notes = append(notes, fmt.Sprintf("raw deletes may not have waited for the archive during %d interval(s) listed in \"degraded\" (before_archive: before the archive began; unrecorded: before 0.11.307, when a disabled period was not recorded; override; disabled) while rows of this month were not all archived yet: rows deleted then are not in the archive",
			len(degraded)))
	}
	m.PartialNote = strings.Join(notes, "; ")
	if m.MonthDigest, err = monthDigest(folderKey, m.Chunks); err != nil {
		return refuse(sealObjects, "%v", err)
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	sha := sha256.Sum256(body)
	shaHex := hex.EncodeToString(sha[:])
	key, err := w.store.Key(rel)
	if err != nil {
		return err
	}

	row := &models.ArchiveMonth{
		Stream: stream, Month: month, Partial: m.Partial, PartialNote: m.PartialNote, FirstID: &m.FirstID, LastID: &m.LastID,
		BoundaryLateByMs: m.BoundaryLateByMs, ChunkCount: int64(m.ChunkCount), RowCount: m.Rows, ObjectBytes: m.ObjectBytes,
		MonthDigest: m.MonthDigest, ManifestKey: key, ManifestSha256: shaHex,
	}
	if err := w.db.BeginArchiveMonthSeal(ctx, row, w.now()); err != nil {
		return err
	}
	if err := w.putMonthManifest(ctx, rel, body, shaHex, stream, schema); err != nil {
		return err
	}
	if err := w.db.MarkArchiveMonthSealed(ctx, row, w.now()); err != nil {
		return err
	}
	metrics.IncArchiveMonthSealed(stream)
	kind := "full"
	if m.Partial {
		kind = "PARTIAL"
	}
	log.Printf("archive: sealed month %s of %s (%s): %d chunks, %d objects, %d rows, ids (%d, %d], digest %s", month, stream, kind,
		m.ChunkCount, m.ObjectCount, m.Rows, m.FirstID, m.LastID, m.MonthDigest)
	return nil
}

// sealChunk re-verifies chunk c's objects of stream and its chunk.json in the
// bucket (step 2) and returns its entry of the month manifest.
func (w *Worker) sealChunk(ctx context.Context, c *models.ArchiveChunk, stream string, schema int, objs []models.ArchiveObject, full bool) (monthChunk, error) {
	body, err := chunkManifestJSON(c, stream, schema, objs)
	if err != nil {
		return monthChunk{}, refuse(sealObjects, "chunk %d: %v", c.Seq, err)
	}
	// chunkManifestJSON is the chunk.json the verification wrote, byte for
	// byte (it depends only on the chunk and its objects).
	var mc chunkManifest
	if err := json.Unmarshal(body, &mc); err != nil {
		return monthChunk{}, err
	}
	out := monthChunk{
		Seq: c.Seq, IDLo: c.IDLo, IDHi: c.IDHi, PeriodStart: rfc3339(c.PeriodStart), PeriodEnd: rfc3339(c.PeriodEnd),
		MarkLateByMs: c.MarkLateByMs, Rows: mc.Rows, Objects: mc.Objects,
	}
	rel := export.FolderRel(stream, schema, c.PeriodStart, hourly(c.SourceTable)) + "/" + export.ChunkManifestName
	info, err := w.store.Head(ctx, rel, "")
	if err != nil {
		if errors.Is(err, objstore.ErrNotFound) {
			return monthChunk{}, refuse(sealReverify, "chunk %d: %s is missing", c.Seq, rel)
		}
		return monthChunk{}, err
	}
	sum := md5.Sum(body) // #nosec G401 -- the S3 ETag of a single-part object
	sha := sha256.Sum256(body)
	out.Manifest = monthFile{Key: info.Key, VersionID: info.VersionID, Size: int64(len(body)), Sha256: hex.EncodeToString(sha[:]), ETag: hex.EncodeToString(sum[:])}
	if info.Size != out.Manifest.Size || info.ETag != out.Manifest.ETag {
		return monthChunk{}, refuse(sealReverify, "chunk %d: the stored %s (%d bytes, ETag %s) is not the chunk's manifest (%d bytes, ETag %s)",
			c.Seq, rel, info.Size, info.ETag, out.Manifest.Size, out.Manifest.ETag)
	}
	if full {
		if err := w.store.VerifyFull(ctx, objstore.PutResult{Rel: rel, Key: info.Key, Size: out.Manifest.Size, SHA256: out.Manifest.Sha256,
			ETag: out.Manifest.ETag, VersionID: info.VersionID}, nil); err != nil {
			return monthChunk{}, sealVerifyErr(c, rel, err)
		}
	}
	for i := range objs {
		o := &objs[i]
		if o.Stream != stream {
			continue
		}
		want, err := w.putResult(o)
		if err != nil {
			return monthChunk{}, refuse(sealObjects, "%v", err)
		}
		if err := w.store.VerifyHead(ctx, want); err != nil {
			return monthChunk{}, sealVerifyErr(c, o.ObjectKey, err)
		}
		// Full: the stored bytes against sha256_object. Their content was
		// checked line by line at the chunk's verification, and the chunk.json
		// above pins the same hashes.
		if full {
			if err := w.store.VerifyFull(ctx, want, nil); err != nil {
				return monthChunk{}, sealVerifyErr(c, o.ObjectKey, err)
			}
		}
	}
	return out, nil
}

// sealVerifyErr is a re-verification failure: a refusal when the stored
// object differs or is gone, the error itself when the service failed.
func sealVerifyErr(c *models.ArchiveChunk, what string, err error) error {
	if errors.Is(err, objstore.ErrMismatch) {
		return refuse(sealReverify, "chunk %d: %s: %v", c.Seq, what, err)
	}
	return err
}

// putMonthManifest writes _MONTH.json once and reads it back: a copy already
// stored with the same bytes (a seal interrupted after its upload) is read
// back instead of written again; a different one is never overwritten.
func (w *Worker) putMonthManifest(ctx context.Context, rel string, body []byte, shaHex, stream string, schema int) error {
	sum := md5.Sum(body) // #nosec G401 -- the S3 ETag of a single-part object
	etag := hex.EncodeToString(sum[:])
	info, err := w.store.Head(ctx, rel, "")
	switch {
	case err == nil && info.Size == int64(len(body)) && info.ETag == etag:
		if err := w.store.VerifyFull(ctx, objstore.PutResult{Rel: rel, Key: info.Key, Size: info.Size, SHA256: shaHex, ETag: etag, VersionID: info.VersionID}, nil); err != nil {
			return sealManifestErr(rel, err)
		}
		return nil
	case err == nil:
		return refuse(sealConflict, "a different %s is already stored (%d bytes, ETag %s; this seal's is %d bytes, ETag %s): it is never overwritten",
			rel, info.Size, info.ETag, len(body), etag)
	case !errors.Is(err, objstore.ErrNotFound):
		return err
	}
	put, err := w.put(ctx, rel, bytes.NewReader(body), int64(len(body)), map[string]string{
		"fwmon-archive-schema": strconv.Itoa(schema), "fwmon-archive-stream": stream,
		monthManifestShaMeta: shaHex,
	})
	if err != nil {
		return err
	}
	if put.SHA256 != shaHex {
		return fmt.Errorf("archive: %s hashed %s at upload, the seal wrote %s", rel, put.SHA256, shaHex)
	}
	if err := w.store.VerifyHead(ctx, put); err != nil {
		return sealManifestErr(rel, err)
	}
	if err := w.store.VerifyFull(ctx, put, nil); err != nil {
		return sealManifestErr(rel, err)
	}
	return nil
}

func sealManifestErr(rel string, err error) error {
	if errors.Is(err, objstore.ErrMismatch) {
		return refuse(sealReverify, "%s read back: %v", rel, err)
	}
	return err
}

// errSealedWrite: the worker was about to write into a sealed month's folder.
var errSealedWrite = errors.New("write into a sealed month refused")

// monthFolderRe matches the start of every archive key below the prefix:
// <stream>/v<schema>/<YYYY-MM>/.
var monthFolderRe = regexp.MustCompile(`^([a-z-]+)/v[0-9]+/([0-9]{4}-[0-9]{2})/[^/]`)

// refuseSealed returns errSealedWrite when the month of chunk c is sealed for
// any of its streams, before the attempt changes anything (in the database or
// the bucket): a sealed month's chunks are all verified, so one being worked
// again was reset by hand.
func (w *Worker) refuseSealed(ctx context.Context, c *models.ArchiveChunk) error {
	for _, s := range export.StreamsOf(c.SourceTable) {
		sealed, err := w.db.ArchiveMonthSealed(ctx, s, c.Month)
		if err != nil {
			return fmt.Errorf("archive: is month %s of %s sealed: %w", c.Month, s, err)
		}
		if sealed {
			metrics.IncArchiveSealedWrite(s)
			return fmt.Errorf("%w: %s chunk %d belongs to month %s of %s", errSealedWrite, c.SourceTable, c.Seq, c.Month, s)
		}
	}
	return nil
}

// put is the only way the worker writes an object: it refuses (errSealedWrite,
// counted in fwmon_archive_sealed_write_refused_total) a key in the folder of
// a sealed month, and any key that is not in a month folder at all.
func (w *Worker) put(ctx context.Context, rel string, body io.ReaderAt, size int64, meta map[string]string) (objstore.PutResult, error) {
	mm := monthFolderRe.FindStringSubmatch(rel)
	if mm == nil {
		return objstore.PutResult{}, fmt.Errorf("archive: %s is not in a month folder", rel)
	}
	sealed, err := w.db.ArchiveMonthSealed(ctx, mm[1], mm[2])
	if err != nil {
		return objstore.PutResult{}, fmt.Errorf("archive: is month %s of %s sealed: %w", mm[2], mm[1], err)
	}
	if sealed {
		metrics.IncArchiveSealedWrite(mm[1])
		log.Printf("archive: REFUSED to write %s: month %s of %s is sealed", rel, mm[2], mm[1])
		return objstore.PutResult{}, fmt.Errorf("%w: %s (month %s of %s)", errSealedWrite, rel, mm[2], mm[1])
	}
	return w.store.Put(ctx, rel, body, size, meta)
}
