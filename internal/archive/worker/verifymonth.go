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
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/models"
)

// MonthReader is the bucket as VerifyMonth reads it: no call writes.
// *s3.Client implements it.
type MonthReader interface {
	Key(rel string) (string, error)
	GetBytes(ctx context.Context, rel, versionID string, limit int64) ([]byte, s3.ObjectInfo, error)
	Versions(ctx context.Context, rel string) (int, error)
	VerifyFull(ctx context.Context, want s3.PutResult, w io.Writer) error
}

// manifestLimit bounds a downloaded manifest (a month of hourly flow chunks
// lists ~750 chunks; far below this).
const manifestLimit = 64 << 20

// MonthReport is what VerifyMonth found.
type MonthReport struct {
	Stream, Month   string
	ManifestKey     string
	SchemaVersion   int
	Partial         bool
	PartialNote     string
	FirstID, LastID int64
	Chunks, Objects int
	Rows, Bytes     int64
	Digest          string
	// Problems lists every check that failed; none means the month is intact.
	Problems []string
}

// OK reports whether every check passed.
func (r *MonthReport) OK() bool { return len(r.Problems) == 0 }

func (r *MonthReport) fail(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

var monthArgRe = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)

// VerifyMonth checks a sealed month from the bucket alone (no database):
// it downloads stream's _MONTH.json for month (checking its ETag and the
// sha256 recorded with it, and that it has one version), re-derives the
// chain (seq, ids and periods gapless, covering the month, joined to the
// sealed months beside it; partial exactly for the archive's first month or a
// degraded one), the totals and the month digest, downloads
// every chunk.json the manifest pins (by version, hash checked, its content
// matching the month manifest's entry) and every object (by version: stored
// bytes against sha256_object, decompressed bytes against sha256_content,
// row count, every line JSON with an id in the chunk's range, in order).
// It only reads. progress, when not nil, gets one line per chunk. An error is
// returned only when no check could be made (bad arguments, no manifest); a
// failed check is a Problem in the report.
func VerifyMonth(ctx context.Context, store MonthReader, stream, month string, progress io.Writer) (*MonthReport, error) {
	if progress == nil {
		progress = io.Discard
	}
	schemas := export.SchemasOf(stream)
	if schemas == nil {
		return nil, fmt.Errorf("unknown stream %q (syslog, sflow, netflow or sflow-counters)", stream)
	}
	if !monthArgRe.MatchString(month) {
		return nil, fmt.Errorf("month %q: want YYYY-MM", month)
	}
	start, end, err := monthBounds(month)
	if err != nil {
		return nil, err
	}
	rep := &MonthReport{Stream: stream, Month: month}

	var body []byte
	var info s3.ObjectInfo
	var folderRel string
	for _, sv := range schemas {
		rel := export.MonthFolderRel(stream, sv, month) + "/" + export.MonthManifestName
		b, in, err := store.GetBytes(ctx, rel, "", manifestLimit)
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if body != nil {
			rep.fail("both %s and %s exist", info.Key, in.Key)
			continue
		}
		body, info, folderRel, rep.SchemaVersion = b, in, export.MonthFolderRel(stream, sv, month), sv
	}
	if body == nil {
		return nil, fmt.Errorf("no %s for %s %s in the bucket: the month is not sealed", export.MonthManifestName, stream, month)
	}
	rep.ManifestKey = info.Key
	// The seal writes _MONTH.json exactly once: another version means it was
	// written over (the GET above read the latest).
	if n, err := store.Versions(ctx, folderRel+"/"+export.MonthManifestName); err != nil {
		rep.fail("%s: cannot list its versions: %v", info.Key, err)
	} else if n != 1 {
		rep.fail("%s has %d versions; the seal writes it once", info.Key, n)
	}
	sum, sha := md5.Sum(body), sha256.Sum256(body) // #nosec G401 -- the S3 ETag of a single-part object
	if info.ETag != hex.EncodeToString(sum[:]) {
		rep.fail("%s: ETag %s is not the MD5 of the bytes read (%x)", info.Key, info.ETag, sum)
	}
	if want := info.Metadata["fwmon-archive-sha256-content"]; want != hex.EncodeToString(sha[:]) {
		rep.fail("%s: sha256 %x, recorded at the seal %q", info.Key, sha, want)
	}
	var m monthManifest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		rep.fail("%s is not a month manifest: %v", info.Key, err)
		return rep, nil
	}
	rep.Partial, rep.PartialNote, rep.FirstID, rep.LastID, rep.Digest = m.Partial, m.PartialNote, m.FirstID, m.LastID, m.MonthDigest
	if m.Kind != MonthManifestKind || m.ManifestVersion != 1 || m.Stream != stream || m.Month != month || m.SchemaVersion != rep.SchemaVersion ||
		m.Compression != export.Compression || !slices.Contains(export.StreamsOf(m.Table), stream) {
		rep.fail("%s describes kind %q v%d, stream %q, month %q, table %q, schema %d, compression %q", info.Key, m.Kind, m.ManifestVersion,
			m.Stream, m.Month, m.Table, m.SchemaVersion, m.Compression)
	}
	folderKey, err := store.Key(folderRel)
	if err != nil {
		return nil, err
	}

	// The chain and the totals, from the manifest alone.
	if len(m.Chunks) == 0 || m.ChunkCount != len(m.Chunks) {
		rep.fail("chunk_count %d, %d chunks listed", m.ChunkCount, len(m.Chunks))
	}
	var rows, raw, objBytes int64
	var objects int
	var firstRow *int64
	hist := map[string]int64{}
	for i, c := range m.Chunks {
		ps, pe, perr := parseRFC3339Pair(c.PeriodStart, c.PeriodEnd)
		switch {
		case perr != nil:
			rep.fail("chunk %d: %v", c.Seq, perr)
		case export.MonthOf(ps) != month || !pe.After(ps) || c.IDHi < c.IDLo:
			rep.fail("chunk %d: period %s-%s, ids (%d, %d]", c.Seq, c.PeriodStart, c.PeriodEnd, c.IDLo, c.IDHi)
		}
		if i == 0 {
			if c.IDLo != m.FirstID || c.PeriodStart != m.PeriodStart {
				rep.fail("the first chunk starts at id %d, %s; the manifest says %d, %s", c.IDLo, c.PeriodStart, m.FirstID, m.PeriodStart)
			}
			if !m.Partial && (perr != nil || !ps.Equal(start)) {
				rep.fail("the month is not partial but its first chunk starts at %s, not %s", c.PeriodStart, rfc3339(start))
			}
		} else if p := m.Chunks[i-1]; c.Seq != p.Seq+1 || c.IDLo != p.IDHi || c.PeriodStart != p.PeriodEnd {
			rep.fail("chunk %d (ids from %d, period from %s) does not continue chunk %d (ids to %d, period to %s)",
				c.Seq, c.IDLo, c.PeriodStart, p.Seq, p.IDHi, p.PeriodEnd)
		}
		if i == len(m.Chunks)-1 && (c.IDHi != m.LastID || c.PeriodEnd != m.PeriodEnd || perr != nil || !pe.Equal(end)) {
			rep.fail("the last chunk ends at id %d, %s; the manifest says %d, %s, the month ends at %s", c.IDHi, c.PeriodEnd, m.LastID, m.PeriodEnd, rfc3339(end))
		}
		var crows int64
		for _, o := range c.Objects {
			crows += o.Rows
			rows += o.Rows
			raw += o.RawBytes
			objBytes += o.ObjectBytes
			objects++
			if o.Rows > 0 && (firstRow == nil || o.MinID < *firstRow) {
				id := o.MinID
				firstRow = &id
			}
			for d, n := range o.MsgDayHistogram {
				hist[d] += n
			}
		}
		if crows != c.Rows {
			rep.fail("chunk %d: rows %d, its objects hold %d", c.Seq, c.Rows, crows)
		}
	}
	rep.Chunks, rep.Objects, rep.Rows, rep.Bytes = len(m.Chunks), objects, rows, objBytes
	if rows != m.Rows || raw != m.RawBytes || objBytes != m.ObjectBytes || objects != m.ObjectCount {
		rep.fail("totals: %d rows, %d raw bytes, %d object bytes, %d objects listed; the manifest says %d, %d, %d, %d",
			rows, raw, objBytes, objects, m.Rows, m.RawBytes, m.ObjectBytes, m.ObjectCount)
	}
	if (firstRow == nil) != (m.FirstRowID == nil) || (firstRow != nil && *firstRow != *m.FirstRowID) {
		rep.fail("first_row_id %v, the objects start at %v", ptrVal(m.FirstRowID), ptrVal(firstRow))
	}
	if !maps.Equal(hist, m.MsgDayHistogram) {
		rep.fail("msg_day_histogram is not the sum of the objects'")
	}
	// Partial: the archive's first month (from id 0, seq 1), or one with
	// degraded intervals; nothing else.
	firstMonth := m.FirstID == 0
	if len(m.Chunks) > 0 && firstMonth && m.Chunks[0].Seq != 1 {
		rep.fail("the month starts at id 0 but its first chunk is seq %d, not 1", m.Chunks[0].Seq)
	}
	if m.Partial != (firstMonth || len(m.Degraded) > 0) {
		rep.fail("partial is %t, but the month starts at id %d with %d degraded interval(s)", m.Partial, m.FirstID, len(m.Degraded))
	}
	verifyNeighbours(ctx, store, stream, month, &m, rep)
	if digest, err := monthDigest(folderKey, m.Chunks); err != nil {
		rep.fail("%v", err)
	} else if digest != m.MonthDigest {
		rep.fail("month digest %s, recomputed %s", m.MonthDigest, digest)
	}

	// Every chunk.json and every object, from the bucket.
	for i := range m.Chunks {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c := &m.Chunks[i]
		before := len(rep.Problems)
		verifyMonthChunk(ctx, store, folderKey, folderRel, stream, month, rep.SchemaVersion, c, rep)
		status := "ok"
		if len(rep.Problems) > before {
			status = fmt.Sprintf("FAILED (%d)", len(rep.Problems)-before)
		}
		fmt.Fprintf(progress, "chunk %d %s ids (%d, %d]: %d objects, %d rows: %s\n", c.Seq, c.PeriodStart, c.IDLo, c.IDHi, len(c.Objects), c.Rows, status)
	}
	return rep, nil
}

// verifyMonthChunk checks one chunk of the month manifest against the bucket.
func verifyMonthChunk(ctx context.Context, store MonthReader, folderKey, folderRel, stream, month string, schema int, c *monthChunk, rep *MonthReport) {
	rel := func(key string) (string, bool) {
		name, ok := strings.CutPrefix(key, folderKey+"/")
		return folderRel + "/" + name, ok && name != ""
	}
	mrel, ok := rel(c.Manifest.Key)
	if !ok || !strings.HasSuffix(mrel, "/"+export.ChunkManifestName) {
		rep.fail("chunk %d: manifest key %s is not a chunk.json in the month folder", c.Seq, c.Manifest.Key)
	} else if b, in, err := store.GetBytes(ctx, mrel, c.Manifest.VersionID, manifestLimit); err != nil {
		rep.fail("chunk %d: %s: %v", c.Seq, c.Manifest.Key, err)
	} else {
		sha := sha256.Sum256(b)
		if int64(len(b)) != c.Manifest.Size || hex.EncodeToString(sha[:]) != c.Manifest.Sha256 || in.ETag != c.Manifest.ETag {
			rep.fail("chunk %d: %s is %d bytes, sha256 %x, ETag %s; the month manifest pins %d, %s, %s", c.Seq, c.Manifest.Key,
				len(b), sha, in.ETag, c.Manifest.Size, c.Manifest.Sha256, c.Manifest.ETag)
		}
		var cm chunkManifest
		if err := json.Unmarshal(b, &cm); err != nil {
			rep.fail("chunk %d: %s: %v", c.Seq, c.Manifest.Key, err)
		} else if cm.Kind != ChunkManifestKind || cm.Stream != stream || cm.Month != month || cm.SchemaVersion != schema || cm.Seq != c.Seq ||
			cm.IDLo != c.IDLo || cm.IDHi != c.IDHi || cm.PeriodStart != c.PeriodStart || cm.PeriodEnd != c.PeriodEnd || cm.Rows != c.Rows ||
			!sameObjects(cm.Objects, c.Objects) {
			rep.fail("chunk %d: %s does not describe the chunk the month manifest lists", c.Seq, c.Manifest.Key)
		}
	}
	ch := &models.ArchiveChunk{Seq: c.Seq, IDLo: c.IDLo, IDHi: c.IDHi}
	for _, o := range c.Objects {
		orel, ok := rel(o.Key)
		if !ok {
			rep.fail("chunk %d: object %s is not in the month folder", c.Seq, o.Key)
			continue
		}
		want := s3.PutResult{Rel: orel, Key: o.Key, Size: o.ObjectBytes, SHA256: o.Sha256Object, ETag: o.ETag, Parts: o.PartCount, VersionID: o.VersionID}
		chk := newContentCheck(ch, &models.ArchiveObject{ObjectKey: o.Key, Sha256Content: o.Sha256Content, RowCount: o.Rows,
			RawBytes: o.RawBytes, MinID: o.MinID, MaxID: o.MaxID})
		verr := store.VerifyFull(ctx, want, chk)
		cerr := chk.finish()
		switch {
		case verr != nil:
			rep.fail("chunk %d: %v", c.Seq, verr)
		case cerr != nil:
			rep.fail("chunk %d: %s: %v", c.Seq, o.Key, cerr)
		}
	}
}

// sameObjects compares the identifying fields of two object lists.
func sameObjects(a, b []manifestObject) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Key != y.Key || x.Rows != y.Rows || x.RawBytes != y.RawBytes || x.ObjectBytes != y.ObjectBytes || x.Sha256Content != y.Sha256Content ||
			x.Sha256Object != y.Sha256Object || x.ETag != y.ETag || x.VersionID != y.VersionID || x.MinID != y.MinID || x.MaxID != y.MaxID {
			return false
		}
	}
	return true
}

func parseRFC3339Pair(a, b string) (time.Time, time.Time, error) {
	x, err := time.Parse(time.RFC3339Nano, a)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	y, err := time.Parse(time.RFC3339Nano, b)
	return x, y, err
}

// neighbour is what VerifyMonth reads of an adjacent month's _MONTH.json.
type neighbour struct {
	FirstID int64 `json:"first_id"`
	LastID  int64 `json:"last_id"`
	Chunks  []struct {
		Seq int64 `json:"seq"`
	} `json:"chunks"`
}

// readNeighbour downloads stream's sealed _MONTH.json of month, if any.
func readNeighbour(ctx context.Context, store MonthReader, stream, month string) (*neighbour, error) {
	for _, sv := range export.SchemasOf(stream) {
		b, _, err := store.GetBytes(ctx, export.MonthFolderRel(stream, sv, month)+"/"+export.MonthManifestName, "", manifestLimit)
		if errors.Is(err, s3.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var n neighbour
		if err := json.Unmarshal(b, &n); err != nil {
			return nil, err
		}
		return &n, nil
	}
	return nil, nil
}

// verifyNeighbours checks that the month joins the sealed months beside it:
// the previous one ends where it starts (it must exist unless this is the
// archive's first month), the next one, when sealed, starts where it ends.
func verifyNeighbours(ctx context.Context, store MonthReader, stream, month string, m *monthManifest, rep *MonthReport) {
	start, end, err := monthBounds(month)
	if err != nil || len(m.Chunks) == 0 {
		return
	}
	prevMonth, nextMonth := export.MonthOf(start.AddDate(0, -1, 0)), export.MonthOf(end)
	prev, err := readNeighbour(ctx, store, stream, prevMonth)
	switch {
	case err != nil:
		rep.fail("previous month %s: %v", prevMonth, err)
	case prev == nil && m.FirstID != 0:
		rep.fail("the month starts after id %d, but the previous month %s has no %s", m.FirstID, prevMonth, export.MonthManifestName)
	case prev != nil && (prev.LastID != m.FirstID || len(prev.Chunks) == 0 || prev.Chunks[len(prev.Chunks)-1].Seq+1 != m.Chunks[0].Seq):
		rep.fail("the previous month %s does not end where this one starts (its last id %d, this first id %d)", prevMonth, prev.LastID, m.FirstID)
	}
	next, err := readNeighbour(ctx, store, stream, nextMonth)
	switch {
	case err != nil:
		rep.fail("next month %s: %v", nextMonth, err)
	case next != nil && (next.FirstID != m.LastID || len(next.Chunks) == 0 || next.Chunks[0].Seq != m.Chunks[len(m.Chunks)-1].Seq+1):
		rep.fail("the next month %s does not start where this one ends (its first id %d, this last id %d)", nextMonth, next.FirstID, m.LastID)
	}
}
