package worker

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/models"
)

// contentCheck is the io.Writer a read-back is teed into: it gunzips the
// stream as it arrives and checks the NDJSON against the object's row —
// sha256 of the decompressed bytes, byte and row counts, every line one JSON
// object whose "id" is in the chunk's range (lo, hi] and strictly increasing,
// first and last id — and sums the ids and their hash terms for the count
// check, so the count compares the table against what the bucket holds, not
// against what the exporter meant to write.
type contentCheck struct {
	pw   *io.PipeWriter
	done chan error

	lo, hi int64
	obj    *models.ArchiveObject

	rows, rawBytes, idSum, idHash int64
}

func newContentCheck(c *models.ArchiveChunk, o *models.ArchiveObject) *contentCheck {
	pr, pw := io.Pipe()
	k := &contentCheck{pw: pw, done: make(chan error, 1), lo: c.IDLo, hi: c.IDHi, obj: o}
	go func() {
		err := k.read(pr)
		// Drain whatever is still written so the writer side never blocks.
		_, _ = io.Copy(io.Discard, pr)
		pr.CloseWithError(err)
		k.done <- err
	}()
	return k
}

func (k *contentCheck) Write(p []byte) (int, error) { return k.pw.Write(p) }

// finish ends the stream and returns the check's verdict.
func (k *contentCheck) finish() error {
	k.pw.Close()
	return <-k.done
}

func (k *contentCheck) read(r io.Reader) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	zr.Multistream(false)
	h := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(zr, h), 64<<10)
	var first, last int64
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			k.rawBytes += int64(len(line))
			if line[len(line)-1] != '\n' {
				return fmt.Errorf("line %d is not newline-terminated", k.rows+1)
			}
			var row struct {
				ID *int64 `json:"id"`
			}
			if jerr := json.Unmarshal(line, &row); jerr != nil {
				return fmt.Errorf("line %d is not JSON: %w", k.rows+1, jerr)
			}
			switch {
			case row.ID == nil:
				return fmt.Errorf("line %d has no id", k.rows+1)
			case *row.ID <= k.lo || *row.ID > k.hi:
				return fmt.Errorf("line %d: id %d is outside the chunk (%d, %d]", k.rows+1, *row.ID, k.lo, k.hi)
			case k.rows > 0 && *row.ID <= last:
				return fmt.Errorf("line %d: id %d after %d", k.rows+1, *row.ID, last)
			}
			if k.rows == 0 {
				first = *row.ID
			}
			last = *row.ID
			k.rows++
			k.idSum += *row.ID
			k.idHash += export.IDHashTerm(*row.ID)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
	}
	if err := zr.Close(); err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	o := k.obj
	switch {
	case hex.EncodeToString(h.Sum(nil)) != o.Sha256Content:
		return fmt.Errorf("decompressed sha256 differs from sha256_content %s", o.Sha256Content)
	case k.rows != o.RowCount:
		return fmt.Errorf("%d rows, the manifest says %d", k.rows, o.RowCount)
	case k.rawBytes != o.RawBytes:
		return fmt.Errorf("%d decompressed bytes, the manifest says %d", k.rawBytes, o.RawBytes)
	case k.rows > 0 && (first != o.MinID || last != o.MaxID):
		return fmt.Errorf("ids %d-%d, the manifest says %d-%d", first, last, o.MinID, o.MaxID)
	}
	return nil
}

// histogramJSON renders a message-day histogram (encoding/json sorts the
// keys, so the text is deterministic).
func histogramJSON(days map[string]int64) (string, error) {
	if days == nil {
		days = map[string]int64{}
	}
	b, err := json.Marshal(days)
	return string(b), err
}

// chunkManifest is chunk.json: one per stream folder of a chunk, uploaded
// after the chunk's objects were read back and its count matched, so a
// folder with a chunk.json is complete and one without is not. "objects" is
// [] for a stream that had no rows in the period, which tells "empty" from
// "missing". The content is a function of the chunk and its objects only
// (no wall-clock field), so writing it again after a crash writes the same
// bytes — except version ids, which the service assigns per upload.
type chunkManifest struct {
	Kind            string           `json:"kind"`
	ManifestVersion int              `json:"manifest_version"`
	Stream          string           `json:"stream"`
	SchemaVersion   int              `json:"schema_version"`
	Compression     string           `json:"compression"`
	Table           string           `json:"table"`
	Seq             int64            `json:"seq"`
	IDLo            int64            `json:"id_lo"`
	IDHi            int64            `json:"id_hi"`
	PeriodStart     string           `json:"period_start"`
	PeriodEnd       string           `json:"period_end"`
	Month           string           `json:"month"`
	MarkLateByMs    *int64           `json:"mark_late_by_ms,omitempty"`
	ChunkRows       int64            `json:"chunk_rows"`
	Rows            int64            `json:"rows"`
	MsgDayHistogram map[string]int64 `json:"msg_day_histogram"`
	Objects         []manifestObject `json:"objects"`
}

type manifestObject struct {
	Key             string           `json:"key"`
	DeviceID        *uint            `json:"device_id,omitempty"`
	Rows            int64            `json:"rows"`
	RawBytes        int64            `json:"raw_bytes"`
	ObjectBytes     int64            `json:"object_bytes"`
	Sha256Content   string           `json:"sha256_content"`
	Sha256Object    string           `json:"sha256_object"`
	ETag            string           `json:"etag"`
	PartCount       int              `json:"part_count"`
	VersionID       string           `json:"version_id,omitempty"`
	MinID           int64            `json:"min_id"`
	MaxID           int64            `json:"max_id"`
	MinTs           *string          `json:"min_ts,omitempty"`
	MaxTs           *string          `json:"max_ts,omitempty"`
	MsgDayHistogram map[string]int64 `json:"msg_day_histogram"`
}

// ChunkManifestKind identifies a chunk.json.
const ChunkManifestKind = "fwmon-archive-chunk"

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func chunkManifestJSON(c *models.ArchiveChunk, stream string, schema int, objs []models.ArchiveObject) ([]byte, error) {
	m := chunkManifest{
		Kind: ChunkManifestKind, ManifestVersion: 1, Stream: stream, SchemaVersion: schema, Compression: export.Compression,
		Table: c.SourceTable, Seq: c.Seq, IDLo: c.IDLo, IDHi: c.IDHi,
		PeriodStart: rfc3339(c.PeriodStart), PeriodEnd: rfc3339(c.PeriodEnd), Month: c.Month, MarkLateByMs: c.MarkLateByMs,
		MsgDayHistogram: map[string]int64{}, Objects: []manifestObject{},
	}
	for i := range objs {
		o := &objs[i]
		m.ChunkRows += o.RowCount
		if o.Stream != stream {
			continue
		}
		if o.SchemaVersion != schema {
			return nil, fmt.Errorf("object %s has schema %d, the chunk %d", o.ObjectKey, o.SchemaVersion, schema)
		}
		mo := manifestObject{
			Key: o.ObjectKey, DeviceID: o.DeviceID, Rows: o.RowCount, RawBytes: o.RawBytes, ObjectBytes: o.ObjectBytes,
			Sha256Content: o.Sha256Content, Sha256Object: o.Sha256Object, ETag: o.ETag, PartCount: o.PartCount,
			VersionID: o.VersionID, MinID: o.MinID, MaxID: o.MaxID, MsgDayHistogram: map[string]int64{},
		}
		if o.MinTs != nil {
			s := rfc3339(*o.MinTs)
			mo.MinTs = &s
		}
		if o.MaxTs != nil {
			s := rfc3339(*o.MaxTs)
			mo.MaxTs = &s
		}
		if o.MsgDayHistogram != nil {
			if err := json.Unmarshal([]byte(*o.MsgDayHistogram), &mo.MsgDayHistogram); err != nil {
				return nil, fmt.Errorf("histogram of %s: %w", o.ObjectKey, err)
			}
		}
		for d, n := range mo.MsgDayHistogram {
			m.MsgDayHistogram[d] += n
		}
		m.Rows += o.RowCount
		m.Objects = append(m.Objects, mo)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
