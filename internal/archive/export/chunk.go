package export

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"firewall-mon/internal/models"
)

// Source tables.
const (
	TableSyslog   = "syslog_messages"
	TableFlows    = "flow_samples"
	TableCounters = "flow_if_counters"
)

// Streams: the bucket's top-level folders.
const (
	StreamSyslog        = "syslog"
	StreamSFlow         = "sflow"
	StreamNetFlow       = "netflow"
	StreamSFlowCounters = "sflow-counters"
)

// StreamsOf lists the streams a table's chunk is exported to. Every listed
// stream gets a chunk manifest even when it received no rows, so an empty
// netflow hour is told apart from a missing one.
func StreamsOf(table string) []string {
	switch table {
	case TableSyslog:
		return []string{StreamSyslog}
	case TableFlows:
		return []string{StreamSFlow, StreamNetFlow}
	case TableCounters:
		return []string{StreamSFlowCounters}
	}
	return nil
}

// flowStream is the stream of a flow_samples row by its flow_source: 0 sFlow,
// 1-3 NetFlow v5 / v9 / IPFIX. Ingest clamps anything else to 0, so another
// value means the table gained a source the archive does not know yet — the
// chunk fails loudly rather than file it under a guess.
func flowStream(src uint8) (string, error) {
	switch {
	case src == models.FlowSourceSFlow:
		return StreamSFlow, nil
	case src >= models.FlowSourceNetFlowV5 && src <= models.FlowSourceIPFIX:
		return StreamNetFlow, nil
	}
	return "", fmt.Errorf("flow_source %d has no archive stream", src)
}

// MonthOf is the month folder "YYYY-MM" of an instant (UTC).
func MonthOf(t time.Time) string { return t.UTC().Format("2006-01") }

// ObjectKey is the bucket key of one object of the chunk whose period starts
// at periodStart (hourly: the flow_samples cadence):
//
//	<prefix>/<stream>/v<schema>/<YYYY-MM>/<YYYY-MM-DD>[THH]/<name>.ndjson.gz
//
// with name device-<id> (syslog), flows or counters. No hostnames or names:
// device ids are internal integers.
func ObjectKey(prefix string, id ObjectID, schema int, periodStart time.Time, hourly bool) string {
	p := periodStart.UTC()
	folder := p.Format(time.DateOnly)
	if hourly {
		folder = p.Format("2006-01-02T15")
	}
	name := "counters"
	switch {
	case id.HasDevice:
		name = "device-" + strconv.FormatUint(uint64(id.DeviceID), 10)
	case id.Stream == StreamSFlow || id.Stream == StreamNetFlow:
		name = "flows"
	}
	return fmt.Sprintf("%s/%s/v%d/%s/%s/%s.ndjson.gz", prefix, id.Stream, schema, MonthOf(p), folder, name)
}

// ChunkResult describes one exported chunk: its objects (sorted by stream,
// then device) and their totals.
type ChunkResult struct {
	Table   string
	Objects []ObjectResult
	Rows    int64
	IDSum   int64
	// MinTs / MaxTs / MsgDays over every object (message time, UTC); zero
	// times when the chunk is empty.
	MinTs, MaxTs time.Time
	MsgDays      map[string]int64
}

// ChunkWriter routes one chunk's rows, in id order, to its objects.
//
// Memory: every object is open until Close, and each holds a gzip (flate)
// writer at the default level — about 0.8 MiB. A syslog chunk opens one per
// device that logged that day (6 on the reference fleet: ~5 MiB; 100 devices:
// ~80 MiB); a flow chunk at most two, a counter chunk one. Objects are not
// closed and reopened to bound this: a gzip stream cannot be resumed, and
// splitting an object would change its bytes and hash.
type ChunkWriter struct {
	table   string
	schema  int
	open    OpenFunc
	objects map[ObjectID]*objectWriter
	enc     rowEncoder
	rows    int64
	lastID  int64
}

// NewChunkWriter starts the export of one chunk of table. schema is the
// stream schema version to write (SyslogSchemaV1 / V2 for syslog; FlowSchemaV1,
// CounterSchemaV1 for the flow tables).
func NewChunkWriter(table string, schema int, open OpenFunc) (*ChunkWriter, error) {
	ok := false
	switch table {
	case TableSyslog:
		ok = schema == SyslogSchemaV1 || schema == SyslogSchemaV2
	case TableFlows:
		ok = schema == FlowSchemaV1
	case TableCounters:
		ok = schema == CounterSchemaV1
	default:
		return nil, fmt.Errorf("export: %q is not an archived table", table)
	}
	if !ok {
		return nil, fmt.Errorf("export: %s has no schema version %d", table, schema)
	}
	return &ChunkWriter{table: table, schema: schema, open: open, objects: map[ObjectID]*objectWriter{}}, nil
}

func (c *ChunkWriter) object(id ObjectID) (*objectWriter, error) {
	if o, ok := c.objects[id]; ok {
		return o, nil
	}
	w, err := c.open(id)
	if err != nil {
		return nil, fmt.Errorf("export: open %s object: %w", id.Stream, err)
	}
	o, err := newObjectWriter(id, c.schema, w)
	if err != nil {
		return nil, err
	}
	c.objects[id] = o
	return o, nil
}

func (c *ChunkWriter) emit(id ObjectID, rowID int64, ts time.Time) error {
	// Rows in strictly increasing id order is what makes the content
	// deterministic; anything else is a caller bug.
	if c.rows > 0 && rowID <= c.lastID {
		return fmt.Errorf("export: %s row id %d after %d: rows must arrive in strictly increasing id order", c.table, rowID, c.lastID)
	}
	c.rows++
	c.lastID = rowID
	line, err := c.enc.line()
	if err != nil {
		return fmt.Errorf("export: %s row %d: %w", c.table, rowID, err)
	}
	o, err := c.object(id)
	if err != nil {
		return err
	}
	return o.write(rowID, ts, line)
}

func (c *ChunkWriter) want(table string) error {
	if c.table != table {
		return fmt.Errorf("export: %s rows fed to a %s chunk", table, c.table)
	}
	return nil
}

// AddSyslog writes syslog_messages rows (one object per device).
func (c *ChunkWriter) AddSyslog(rows []models.SyslogMessage) error {
	if err := c.want(TableSyslog); err != nil {
		return err
	}
	for i := range rows {
		m := &rows[i]
		c.enc.encodeSyslog(m, c.schema)
		if err := c.emit(ObjectID{Stream: StreamSyslog, DeviceID: m.DeviceID, HasDevice: true}, int64(m.ID), m.Timestamp); err != nil {
			return err
		}
	}
	return nil
}

// AddFlows writes flow_samples rows (sflow / netflow by flow_source).
func (c *ChunkWriter) AddFlows(rows []models.FlowSample) error {
	if err := c.want(TableFlows); err != nil {
		return err
	}
	for i := range rows {
		f := &rows[i]
		stream, err := flowStream(f.FlowSource)
		if err != nil {
			return fmt.Errorf("export: flow_samples row %d: %w", f.ID, err)
		}
		c.enc.encodeFlow(f)
		if err := c.emit(ObjectID{Stream: stream}, int64(f.ID), f.Timestamp); err != nil {
			return err
		}
	}
	return nil
}

// AddCounters writes flow_if_counters rows (one object).
func (c *ChunkWriter) AddCounters(rows []models.FlowInterfaceCounter) error {
	if err := c.want(TableCounters); err != nil {
		return err
	}
	for i := range rows {
		r := &rows[i]
		c.enc.encodeCounter(r)
		if err := c.emit(ObjectID{Stream: StreamSFlowCounters}, int64(r.ID), r.Timestamp); err != nil {
			return err
		}
	}
	return nil
}

// Close finishes every object and returns the chunk's result. An object is
// only created for a stream / device that had rows.
func (c *ChunkWriter) Close() (*ChunkResult, error) {
	res := &ChunkResult{Table: c.table, MsgDays: map[string]int64{}}
	for _, o := range c.objects {
		r, err := o.close()
		if err != nil {
			return nil, fmt.Errorf("export: close %s object: %w", o.res.ID.Stream, err)
		}
		res.Objects = append(res.Objects, r)
	}
	sort.Slice(res.Objects, func(i, j int) bool {
		a, b := res.Objects[i].ID, res.Objects[j].ID
		if a.Stream != b.Stream {
			return a.Stream < b.Stream
		}
		return a.DeviceID < b.DeviceID
	})
	for _, o := range res.Objects {
		if res.Rows == 0 || o.MinTs.Before(res.MinTs) {
			res.MinTs = o.MinTs
		}
		if res.Rows == 0 || o.MaxTs.After(res.MaxTs) {
			res.MaxTs = o.MaxTs
		}
		res.Rows += o.Rows
		res.IDSum += o.IDSum
		for d, n := range o.MsgDays {
			res.MsgDays[d] += n
		}
	}
	return res, nil
}
