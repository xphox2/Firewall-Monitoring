package export

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"firewall-mon/internal/models"

	"gorm.io/gorm/schema"
)

// Synthetic fixtures only (public repo): RFC 5737 / 3849 addresses,
// fw-example-NN, example.com, alice.

var t0 = time.Date(2026, 10, 4, 13, 5, 6, 789000000, time.UTC)

func ptrTime(t time.Time) *time.Time { return &t }
func ptrI16(v int16) *int16          { return &v }

func syslogRow(id uint, dev uint, ts time.Time) models.SyslogMessage {
	return models.SyslogMessage{
		ID: id, Timestamp: ts, DeviceID: dev, ProbeID: 3, Hostname: "fw-example-01", AppName: "traffic",
		ProcessID: "-", MessageID: "0000000013", StructuredData: `[meta src="192.0.2.10"]`,
		Message:  `date=2026-10-04 srcip=192.0.2.10 dstip=198.51.100.7 user="alice" url="https://example.com/a?b=1&c=<2>" note="tab	quote\" back\\ ` + "\u2028" + `"`,
		Priority: 189, Facility: 23, Severity: 5, SourceIP: "203.0.113.4",
		CreatedAt: ts.Add(1500 * time.Millisecond), StoredFormat: ptrI16(models.SyslogFormatFortiOSKV),
	}
}

func flowRow(id uint, src uint8, ts time.Time) models.FlowSample {
	return models.FlowSample{
		ID: id, Timestamp: ts, DeviceID: 7, ProbeID: 3, SamplerAddress: "192.0.2.1",
		SequenceNumber: 4000000000, SamplingRate: 1000, SrcAddr: "192.0.2.10", DstAddr: "2001:db8::7",
		SrcPort: 51234, DstPort: 443, Protocol: 6, Bytes: 1 << 40, Packets: 12, InputIfIndex: 4000000001,
		OutputIfIndex: 2, TCPFlags: 0x18, Drops: 3, AppCategory: 1, Direction: 2, ServicePort: 443, ClassRev: 9,
		ScopeLocal: true, SrcCountry: "", DstCountry: "ZZ", SrcASN: 64496, DstASN: 4200000000,
		SrcASNOrg: "Example Org", DstASNOrg: "", ThreatFlag: 2, ASPath: "64496 64497", NextHop: "198.51.100.1",
		FlowSource: src, FlowStart: ptrTime(ts.Add(-30 * time.Second)), FlowEnd: nil, FirewallEvent: 3,
		FlowEndReason: 2, PostNATSrcAddr: "203.0.113.9", PostNATDstAddr: "", PostNATSrcPort: 40000,
		PostNATDstPort: 0, ICMPTypeCode: 0, TOS: 32, SrcVLAN: 10, DstVLAN: 20, AppName: "HTTPS.BROWSER",
		BGPSrcAS: 99, BGPDstAS: 98, // inbound-only, not persisted: must not appear
		CreatedAt: ts.Add(time.Second),
	}
}

func counterRow(id uint, ts time.Time) models.FlowInterfaceCounter {
	return models.FlowInterfaceCounter{
		ID: id, Timestamp: ts, DeviceID: 7, ProbeID: 3, SamplerAddress: "192.0.2.1", IfIndex: 4000000001,
		IfType: 6, IfSpeed: 10000000000, IfDirection: 1, IfStatus: 3, InOctets: 1 << 50, InErrors: 1,
		InDiscards: 2, OutOctets: 99, OutErrors: 0, OutDiscards: 4, CreatedAt: ts.Add(time.Second),
	}
}

// memSink collects each object's compressed bytes.
type memSink struct {
	mu   sync.Mutex
	bufs map[ObjectID]*bytes.Buffer
}

func newMemSink() *memSink { return &memSink{bufs: map[ObjectID]*bytes.Buffer{}} }

func (s *memSink) open(id ObjectID) (io.Writer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &bytes.Buffer{}
	s.bufs[id] = b
	return b, nil
}

func gunzip(t *testing.T, b []byte) ([]byte, *gzip.Reader) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out, zr
}

// TestAppendJSONString_MatchesEncodingJSON: the hand-written escaper writes
// exactly what encoding/json writes with SetEscapeHTML(false), for every
// class of character (and random valid strings).
func TestAppendJSONString_MatchesEncodingJSON(t *testing.T) {
	cases := []string{
		"", "plain", `quote " back \ slash`, "<script>&amp;</script>", "\b\f\n\r\t", "\x00\x01\x1f\x7f",
		"\u2028 line \u2029 para", "multié中\U0001F600", strings.Repeat("x", 300) + "\"",
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		rs := make([]rune, rng.Intn(12))
		for j := range rs {
			switch rng.Intn(4) {
			case 0:
				rs[j] = rune(rng.Intn(0x80))
			case 1:
				rs[j] = rune(0x2020 + rng.Intn(16))
			case 2:
				rs[j] = rune(rng.Intn(0xD7FF))
			default:
				rs[j] = rune(0x10000 + rng.Intn(0xFFFF))
			}
		}
		cases = append(cases, string(rs))
	}
	for _, s := range cases {
		var want bytes.Buffer
		enc := json.NewEncoder(&want)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(s); err != nil {
			t.Fatal(err)
		}
		got := string(appendJSONString(nil, s))
		if got != strings.TrimSuffix(want.String(), "\n") {
			t.Fatalf("appendJSONString(%q) = %s, encoding/json = %s", s, got, want.String())
		}
	}
}

// persistedColumns lists a model's columns in struct order (gorm:"-" fields
// excluded).
func persistedColumns(t *testing.T, model interface{}) []string {
	t.Helper()
	s, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for _, f := range s.Fields {
		if f.DBName != "" {
			cols = append(cols, f.DBName)
		}
	}
	return cols
}

// lineKeys returns the keys of a JSON object line in order.
func lineKeys(t *testing.T, line []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("line is not an object: %s", line)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k.(string))
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// TestRowFields_AreTheModelsPersistedColumns pins every row format to its
// model: exactly the persisted columns, in struct order, keyed by column name.
// A column added to a model fails here until the archive decides (with a new
// schema version) whether and how to carry it.
func TestRowFields_AreTheModelsPersistedColumns(t *testing.T) {
	var e rowEncoder
	sys := syslogRow(1, 7, t0)
	cases := []struct {
		name  string
		model interface{}
		enc   func()
		drop  string
	}{
		{"syslog v2", &models.SyslogMessage{}, func() { e.encodeSyslog(&sys, SyslogSchemaV2) }, ""},
		{"syslog v1", &models.SyslogMessage{}, func() { e.encodeSyslog(&sys, SyslogSchemaV1) }, "format"},
		{"flow", &models.FlowSample{}, func() { f := flowRow(1, 0, t0); e.encodeFlow(&f) }, ""},
		{"counter", &models.FlowInterfaceCounter{}, func() { c := counterRow(1, t0); e.encodeCounter(&c) }, ""},
	}
	for _, c := range cases {
		c.enc()
		line, err := e.line()
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, col := range persistedColumns(t, c.model) {
			if col != c.drop {
				want = append(want, col)
			}
		}
		got := lineKeys(t, line)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s fields:\n got %v\nwant %v", c.name, got, want)
		}
	}
}

// Golden lines: the exact bytes of one row per format. Changing any of these
// is a new schema version, not an edit.
const (
	goldenSyslogV2 = `{"id":42,"timestamp":"2026-10-04T13:05:06.789Z","device_id":7,"probe_id":3,"hostname":"fw-example-01","app_name":"traffic","process_id":"-","message_id":"0000000013","structured_data":"[meta src=\"192.0.2.10\"]","message":"date=2026-10-04 srcip=192.0.2.10 dstip=198.51.100.7 user=\"alice\" url=\"https://example.com/a?b=1&c=<2>\" note=\"tab\tquote\\\" back\\\\ \u2028\"","priority":189,"facility":23,"severity":5,"source_ip":"203.0.113.4","created_at":"2026-10-04T13:05:08.289Z","format":1}` + "\n"
	goldenFlow     = `{"id":43,"timestamp":"2026-10-04T13:05:06.789Z","device_id":7,"probe_id":3,"sampler_address":"192.0.2.1","sequence_number":4000000000,"sampling_rate":1000,"src_addr":"192.0.2.10","dst_addr":"2001:db8::7","src_port":51234,"dst_port":443,"protocol":6,"bytes":1099511627776,"packets":12,"input_if_index":4000000001,"output_if_index":2,"tcp_flags":24,"drops":3,"app_category":1,"direction":2,"service_port":443,"class_rev":9,"scope_local":true,"src_country":"","dst_country":"ZZ","src_asn":64496,"dst_asn":4200000000,"src_asn_org":"Example Org","dst_asn_org":"","threat_flag":2,"as_path":"64496 64497","next_hop":"198.51.100.1","flow_source":2,"flow_start":"2026-10-04T13:04:36.789Z","flow_end":null,"firewall_event":3,"flow_end_reason":2,"post_nat_src_addr":"203.0.113.9","post_nat_dst_addr":"","post_nat_src_port":40000,"post_nat_dst_port":0,"icmp_type_code":0,"tos":32,"src_vlan":10,"dst_vlan":20,"app_name":"HTTPS.BROWSER","created_at":"2026-10-04T13:05:07.789Z"}` + "\n"
	goldenCounter  = `{"id":44,"timestamp":"2026-10-04T13:05:06.789Z","device_id":7,"probe_id":3,"sampler_address":"192.0.2.1","if_index":4000000001,"if_type":6,"if_speed":10000000000,"if_direction":1,"if_status":3,"in_octets":1125899906842624,"in_errors":1,"in_discards":2,"out_octets":99,"out_errors":0,"out_discards":4,"created_at":"2026-10-04T13:05:07.789Z"}` + "\n"
)

// TestGoldenRows: the exact bytes of one row of each table, from a timestamp
// in another zone (the line is always UTC). Syslog v1 is v2 without format.
func TestGoldenRows(t *testing.T) {
	zone := time.FixedZone("UTC-4", -4*3600)
	ts := t0.In(zone)
	var e rowEncoder
	sys := syslogRow(42, 7, ts)
	e.encodeSyslog(&sys, SyslogSchemaV2)
	if got, _ := e.line(); string(got) != goldenSyslogV2 {
		t.Errorf("syslog v2:\n got %s\nwant %s", got, goldenSyslogV2)
	}
	e.encodeSyslog(&sys, SyslogSchemaV1)
	if got, _ := e.line(); string(got) != strings.Replace(goldenSyslogV2, `,"format":1}`, `}`, 1) {
		t.Errorf("syslog v1:\n got %s", got)
	}
	sys.StoredFormat = nil
	e.encodeSyslog(&sys, SyslogSchemaV2)
	if got, _ := e.line(); !strings.HasSuffix(string(got), `,"format":null}`+"\n") {
		t.Errorf("syslog v2 without a stored format: %s", got)
	}
	f := flowRow(43, models.FlowSourceNetFlowV9, ts)
	e.encodeFlow(&f)
	if got, _ := e.line(); string(got) != goldenFlow {
		t.Errorf("flow:\n got %s\nwant %s", got, goldenFlow)
	}
	c := counterRow(44, ts)
	e.encodeCounter(&c)
	if got, _ := e.line(); string(got) != goldenCounter {
		t.Errorf("counter:\n got %s\nwant %s", got, goldenCounter)
	}
	// Each golden line is valid JSON that decodes back to the row's strings.
	var back map[string]any
	if err := json.Unmarshal([]byte(goldenSyslogV2), &back); err != nil || back["message"] != sys.Message {
		t.Fatalf("golden syslog line does not round-trip: %v %q", err, back["message"])
	}
}

func exportSyslog(t *testing.T, rows []models.SyslogMessage, schemaV int) (*ChunkResult, *memSink) {
	t.Helper()
	sink := newMemSink()
	w, err := NewChunkWriter(TableSyslog, schemaV, sink.open)
	if err != nil {
		t.Fatal(err)
	}
	// Two pages, as the database layer feeds them.
	if err := w.AddSyslog(rows[:len(rows)/2]); err != nil {
		t.Fatal(err)
	}
	if err := w.AddSyslog(rows[len(rows)/2:]); err != nil {
		t.Fatal(err)
	}
	res, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	return res, sink
}

// TestChunk_DeterministicAndSelfDescribing: the same rows give byte-identical
// objects and hashes twice; sha256_content is the hash of the decompressed
// bytes and sha256_object of the stored ones; the gzip header names stream
// and schema and carries nothing run-specific; objects split per device.
func TestChunk_DeterministicAndSelfDescribing(t *testing.T) {
	var rows []models.SyslogMessage
	for i := 0; i < 300; i++ {
		rows = append(rows, syslogRow(uint(1000+i*3), uint(1+i%3), t0.Add(time.Duration(i)*time.Minute)))
	}
	a, sinkA := exportSyslog(t, rows, SyslogSchemaV2)
	b, sinkB := exportSyslog(t, rows, SyslogSchemaV2)
	if len(a.Objects) != 3 || a.Rows != 300 {
		t.Fatalf("objects=%d rows=%d, want 3 per-device objects of 300 rows", len(a.Objects), a.Rows)
	}
	for i, o := range a.Objects {
		if o.ID != (ObjectID{Stream: StreamSyslog, DeviceID: uint(i + 1), HasDevice: true}) {
			t.Fatalf("object %d is %+v: want devices 1..3 in order", i, o.ID)
		}
		if o.Sha256Content != b.Objects[i].Sha256Content || o.Sha256Object != b.Objects[i].Sha256Object || o.ObjectBytes != b.Objects[i].ObjectBytes {
			t.Fatalf("object %d differs between two exports of the same rows", i)
		}
		if !bytes.Equal(sinkA.bufs[o.ID].Bytes(), sinkB.bufs[o.ID].Bytes()) {
			t.Fatalf("object %d bytes differ between two exports", i)
		}
		stored := sinkA.bufs[o.ID].Bytes()
		raw, zr := gunzip(t, stored)
		if zr.Comment != "fwmon-archive syslog schema=2" || zr.Name != "" || !zr.ModTime.IsZero() || zr.OS != 255 {
			t.Fatalf("gzip header = %+v", zr.Header)
		}
		sc, so := sha256.Sum256(raw), sha256.Sum256(stored)
		if o.Sha256Content != hex.EncodeToString(sc[:]) || o.Sha256Object != hex.EncodeToString(so[:]) {
			t.Fatal("sha256_content / sha256_object do not hash the content / the stored bytes")
		}
		if o.RawBytes != int64(len(raw)) || o.ObjectBytes != int64(len(stored)) || o.Rows != 100 {
			t.Fatalf("sizes %+v vs raw %d stored %d", o, len(raw), len(stored))
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if int64(len(lines)) != o.Rows {
			t.Fatalf("%d lines, %d rows", len(lines), o.Rows)
		}
		var prev float64
		for _, l := range lines {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("line is not JSON: %v", err)
			}
			if m["device_id"].(float64) != float64(i+1) || m["id"].(float64) <= prev {
				t.Fatalf("object %d holds a row of device %v or out of id order", i, m["device_id"])
			}
			prev = m["id"].(float64)
		}
	}
	// Schema 1 is a different content (no format), and says so in its header.
	v1, sink1 := exportSyslog(t, rows, SyslogSchemaV1)
	if v1.Objects[0].Sha256Content == a.Objects[0].Sha256Content {
		t.Fatal("schema 1 and 2 produced the same content")
	}
	if _, zr := gunzip(t, sink1.bufs[v1.Objects[0].ID].Bytes()); zr.Comment != "fwmon-archive syslog schema=1" {
		t.Fatalf("schema 1 header comment %q", zr.Comment)
	}
}

// TestChunk_StatsAndHistogram: min/max ids and message times and the per-day
// histogram, per object and per chunk, with a row whose message clock is a
// day behind (it counts under its own day).
func TestChunk_StatsAndHistogram(t *testing.T) {
	day := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	rows := []models.SyslogMessage{
		syslogRow(10, 1, day.Add(23*time.Hour+59*time.Minute)),
		// Skewed: 3 Oct 23:00 UTC, carried in UTC+5 (4 Oct locally) — it
		// counts under its UTC day.
		syslogRow(11, 2, day.Add(-time.Hour).In(time.FixedZone("UTC+5", 5*3600))),
		syslogRow(12, 1, day.Add(24*time.Hour+time.Minute)),
		syslogRow(13, 1, day.Add(time.Hour)),
	}
	res, _ := exportSyslog(t, rows, SyslogSchemaV2)
	if res.Rows != 4 || !res.MinTs.Equal(day.Add(-time.Hour)) || !res.MaxTs.Equal(day.Add(24*time.Hour+time.Minute)) {
		t.Fatalf("chunk %+v", res)
	}
	want := map[string]int64{"2026-10-03": 1, "2026-10-04": 2, "2026-10-05": 1}
	if len(res.MsgDays) != 3 || res.MsgDays["2026-10-03"] != 1 || res.MsgDays["2026-10-04"] != 2 || res.MsgDays["2026-10-05"] != 1 {
		t.Fatalf("histogram %v, want %v", res.MsgDays, want)
	}
	d1 := res.Objects[0]
	if d1.MinID != 10 || d1.MaxID != 13 || d1.Rows != 3 || !d1.MinTs.Equal(day.Add(time.Hour)) || !d1.MaxTs.Equal(day.Add(24*time.Hour+time.Minute)) {
		t.Fatalf("device 1 object %+v", d1)
	}
	if d1.MinTs.Location() != time.UTC {
		t.Fatal("object times are not UTC")
	}
}

// TestChunk_FlowSplitBySource: flow_source 0 → sflow, 1-3 → netflow, one
// object per stream; an unknown source fails the chunk.
func TestChunk_FlowSplitBySource(t *testing.T) {
	sink := newMemSink()
	w, err := NewChunkWriter(TableFlows, FlowSchemaV1, sink.open)
	if err != nil {
		t.Fatal(err)
	}
	var rows []models.FlowSample
	for i, src := range []uint8{0, 1, 0, 2, 3, 0} {
		rows = append(rows, flowRow(uint(i+1), src, t0))
	}
	if err := w.AddFlows(rows); err != nil {
		t.Fatal(err)
	}
	res, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 2 || res.Objects[0].ID.Stream != StreamNetFlow || res.Objects[0].Rows != 3 ||
		res.Objects[1].ID.Stream != StreamSFlow || res.Objects[1].Rows != 3 || res.Objects[0].ID.HasDevice {
		t.Fatalf("objects %+v", res.Objects)
	}
	if res.Objects[0].MinID != 2 || res.Objects[0].MaxID != 5 || res.Objects[1].MinID != 1 || res.Objects[1].MaxID != 6 {
		t.Fatalf("id ranges %+v", res.Objects)
	}
	w2, _ := NewChunkWriter(TableFlows, FlowSchemaV1, newMemSink().open)
	if err := w2.AddFlows([]models.FlowSample{flowRow(1, 4, t0)}); err == nil || !strings.Contains(err.Error(), "flow_source 4") {
		t.Fatalf("unknown flow_source: %v", err)
	}
	// Counters: one object.
	w3, _ := NewChunkWriter(TableCounters, CounterSchemaV1, newMemSink().open)
	if err := w3.AddCounters([]models.FlowInterfaceCounter{counterRow(5, t0), counterRow(9, t0)}); err != nil {
		t.Fatal(err)
	}
	r3, _ := w3.Close()
	if len(r3.Objects) != 1 || r3.Objects[0].ID.Stream != StreamSFlowCounters || r3.Rows != 2 {
		t.Fatalf("counters %+v", r3)
	}
}

// TestChunk_Refusals: rows out of id order (across objects too), invalid
// UTF-8, the wrong table, an unknown schema.
func TestChunk_Refusals(t *testing.T) {
	w, _ := NewChunkWriter(TableSyslog, SyslogSchemaV2, newMemSink().open)
	if err := w.AddSyslog([]models.SyslogMessage{syslogRow(5, 1, t0), syslogRow(4, 2, t0)}); err == nil || !strings.Contains(err.Error(), "increasing id order") {
		t.Fatalf("out of order across devices: %v", err)
	}
	w, _ = NewChunkWriter(TableSyslog, SyslogSchemaV2, newMemSink().open)
	if err := w.AddSyslog([]models.SyslogMessage{syslogRow(5, 1, t0), syslogRow(5, 1, t0)}); err == nil {
		t.Fatal("a repeated id was accepted")
	}
	bad := syslogRow(6, 1, t0)
	bad.Message = "ok \xff not utf-8"
	if utf8.ValidString(bad.Message) {
		t.Fatal("fixture is valid UTF-8")
	}
	w, _ = NewChunkWriter(TableSyslog, SyslogSchemaV2, newMemSink().open)
	if err := w.AddSyslog([]models.SyslogMessage{bad}); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("invalid UTF-8: %v", err)
	}
	if err := w.AddFlows(nil); err == nil {
		t.Fatal("flow rows accepted by a syslog chunk")
	}
	if _, err := NewChunkWriter(TableFlows, 2, nil); err == nil {
		t.Fatal("flow schema 2 accepted")
	}
	if _, err := NewChunkWriter("interface_stats", 1, nil); err == nil {
		t.Fatal("an unarchived table accepted")
	}
}

// TestObjectKey_MonthAndFolder: keys come from the UTC period start whatever
// zone the time carries, so a period at a month edge in another zone files
// under its UTC month.
func TestObjectKey_MonthAndFolder(t *testing.T) {
	ny := time.FixedZone("UTC-4", -4*3600)
	kol := time.FixedZone("UTC+5:30", 5*3600+1800)
	cases := []struct {
		id     ObjectID
		start  time.Time
		hourly bool
		want   string
	}{
		{ObjectID{Stream: StreamSyslog, DeviceID: 7, HasDevice: true}, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), false,
			"pfx/a/syslog/v2/2026-10/2026-10-04/device-7.ndjson.gz"},
		// 31 Oct 20:00 in UTC-4 is 1 Nov 00:00 UTC.
		{ObjectID{Stream: StreamSyslog, DeviceID: 7, HasDevice: true}, time.Date(2026, 10, 31, 20, 0, 0, 0, ny), false,
			"pfx/a/syslog/v2/2026-11/2026-11-01/device-7.ndjson.gz"},
		// 1 Oct 05:00 in UTC+5:30 is 30 Sep 23:30 UTC → the 23:00 hour of September.
		{ObjectID{Stream: StreamSFlow}, time.Date(2026, 10, 1, 5, 0, 0, 0, kol).Truncate(time.Hour), true,
			"pfx/a/sflow/v2/2026-09/2026-09-30T23/flows.ndjson.gz"},
		{ObjectID{Stream: StreamNetFlow}, time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC), true,
			"pfx/a/netflow/v2/2026-12/2026-12-31T23/flows.ndjson.gz"},
		{ObjectID{Stream: StreamSFlowCounters}, time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC), false,
			"pfx/a/sflow-counters/v2/2028-02/2028-02-29/counters.ndjson.gz"},
	}
	for _, c := range cases {
		if got := ObjectKey("pfx/a", c.id, 2, c.start, c.hourly); got != c.want {
			t.Errorf("ObjectKey(%+v, %s) = %s, want %s", c.id, c.start, got, c.want)
		}
	}
	if MonthOf(time.Date(2026, 10, 31, 22, 0, 0, 0, ny)) != "2026-11" {
		t.Error("MonthOf ignores the zone")
	}
	if s := StreamsOf(TableFlows); len(s) != 2 || s[0] != StreamSFlow || s[1] != StreamNetFlow {
		t.Errorf("StreamsOf(flow_samples) = %v", s)
	}
}
