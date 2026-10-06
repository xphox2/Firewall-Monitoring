package export

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"time"
)

// Compression is the codec of every object (gzip at the default level, Go
// standard library: no dependency, readable everywhere). Recorded per object
// so another codec can be added later.
const Compression = "gzip"

// ObjectID names one object of a chunk: per device for syslog
// (HasDevice), per stream for the flow tables.
type ObjectID struct {
	Stream    string
	DeviceID  uint
	HasDevice bool
}

// OpenFunc returns the writer one object's compressed bytes go to (a staging
// file, or a buffer in tests). It is called once per object, on the object's
// first row.
type OpenFunc func(id ObjectID) (io.Writer, error)

// ObjectResult describes one finished object.
type ObjectResult struct {
	ID            ObjectID
	SchemaVersion int
	Compression   string
	Rows          int64
	// RawBytes / Sha256Content: the uncompressed NDJSON. ObjectBytes /
	// Sha256Object: the gzip stream written to the OpenFunc's writer.
	RawBytes      int64
	ObjectBytes   int64
	Sha256Content string
	Sha256Object  string
	MinID, MaxID  int64
	// IDSum is the sum of the row ids: with Rows, what the count check
	// compares against the table.
	IDSum int64
	// MinTs / MaxTs / MsgDays are by message (sample) time, UTC.
	MinTs, MaxTs time.Time
	MsgDays      map[string]int64
}

// countWriter counts and hashes what passes through to w.
type countWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

// objectWriter streams one object: rows → sha256 of the content and gzip →
// (sha256 of the object) → the caller's writer.
type objectWriter struct {
	res     ObjectResult
	content hash.Hash
	out     *countWriter
	gz      *gzip.Writer
}

// gzipComment is the header comment of every object: stream and schema, so a
// lone file names its own format without a data line (the files stay pure
// NDJSON for `zcat | jq` and DuckDB).
func gzipComment(stream string, schema int) string {
	return fmt.Sprintf("fwmon-archive %s schema=%d", stream, schema)
}

func newObjectWriter(id ObjectID, schema int, w io.Writer) (*objectWriter, error) {
	out := &countWriter{w: w, h: sha256.New()}
	gz, err := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	// Fixed header: no name, no modification time (MTIME 0), OS "unknown"
	// (the library default) — nothing that varies between runs or hosts.
	gz.Comment = gzipComment(id.Stream, schema)
	return &objectWriter{
		res: ObjectResult{
			ID: id, SchemaVersion: schema, Compression: Compression,
			MsgDays: map[string]int64{},
		},
		content: sha256.New(),
		out:     out,
		gz:      gz,
	}, nil
}

// write adds one encoded line (terminated by '\n') of row id with message
// time ts; the chunk writer guarantees ids strictly increase.
func (o *objectWriter) write(id int64, ts time.Time, line []byte) error {
	if _, err := o.gz.Write(line); err != nil {
		return err
	}
	o.content.Write(line)
	o.res.RawBytes += int64(len(line))
	ts = ts.UTC()
	if o.res.Rows == 0 {
		o.res.MinID, o.res.MinTs, o.res.MaxTs = id, ts, ts
	}
	o.res.MaxID = id
	o.res.IDSum += id
	if ts.Before(o.res.MinTs) {
		o.res.MinTs = ts
	}
	if ts.After(o.res.MaxTs) {
		o.res.MaxTs = ts
	}
	o.res.MsgDays[ts.Format(time.DateOnly)]++
	o.res.Rows++
	return nil
}

func (o *objectWriter) close() (ObjectResult, error) {
	if err := o.gz.Close(); err != nil {
		return ObjectResult{}, err
	}
	o.res.ObjectBytes = o.out.n
	o.res.Sha256Content = hex.EncodeToString(o.content.Sum(nil))
	o.res.Sha256Object = hex.EncodeToString(o.out.h.Sum(nil))
	return o.res, nil
}
