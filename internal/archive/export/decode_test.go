package export

import (
	"reflect"
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// TestDecode_RoundTripsTheGoldenRows: every golden line decodes to exactly
// the row it was written from (all persisted columns, the original id), for
// syslog schema v1 and v2, flows and counters.
func TestDecode_RoundTripsTheGoldenRows(t *testing.T) {
	sysV2, err := NewDecoder(TableSyslog, SyslogSchemaV2)
	if err != nil {
		t.Fatal(err)
	}
	var m models.SyslogMessage
	if err := sysV2.Syslog([]byte(goldenSyslogV2), &m); err != nil {
		t.Fatal(err)
	}
	if want := syslogRow(42, 7, t0); !reflect.DeepEqual(m, want) {
		t.Fatalf("syslog v2:\n got %+v\nwant %+v", m, want)
	}

	sysV1, err := NewDecoder(TableSyslog, SyslogSchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	v1 := strings.Replace(goldenSyslogV2, `,"format":1}`, `}`, 1)
	if err := sysV1.Syslog([]byte(v1), &m); err != nil {
		t.Fatal(err)
	}
	want := syslogRow(42, 7, t0)
	want.StoredFormat = nil
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("syslog v1:\n got %+v\nwant %+v", m, want)
	}

	fd, err := NewDecoder(TableFlows, FlowSchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	var f models.FlowSample
	if err := fd.Flow([]byte(goldenFlow), &f); err != nil {
		t.Fatal(err)
	}
	wf := flowRow(43, 2, t0)
	wf.BGPSrcAS, wf.BGPDstAS = 0, 0 // inbound-only, never archived
	if !reflect.DeepEqual(f, wf) {
		t.Fatalf("flow:\n got %+v\nwant %+v", f, wf)
	}

	cd, err := NewDecoder(TableCounters, CounterSchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	var c models.FlowInterfaceCounter
	if err := cd.Counter([]byte(goldenCounter), &c); err != nil {
		t.Fatal(err)
	}
	if wc := counterRow(44, t0); !reflect.DeepEqual(c, wc) {
		t.Fatalf("counter:\n got %+v\nwant %+v", c, wc)
	}
}

// TestDecode_Refusals: a line that is not exactly what the exporter writes
// is refused, whatever the difference.
func TestDecode_Refusals(t *testing.T) {
	sysV2, _ := NewDecoder(TableSyslog, SyslogSchemaV2)
	sysV1, _ := NewDecoder(TableSyslog, SyslogSchemaV1)
	v1 := strings.Replace(goldenSyslogV2, `,"format":1}`, `}`, 1)
	var m models.SyslogMessage
	for name, tc := range map[string]struct {
		d    *Decoder
		line string
	}{
		"v1 line, v2 decoder (format missing)":  {sysV2, v1},
		"v2 line, v1 decoder (format is extra)": {sysV1, goldenSyslogV2},
		"unknown key":                           {sysV2, strings.Replace(goldenSyslogV2, `"id":42,`, `"id":42,"extra":1,`, 1)},
		"key order":                             {sysV2, strings.Replace(goldenSyslogV2, `"device_id":7,"probe_id":3`, `"probe_id":3,"device_id":7`, 1)},
		"not UTC":                               {sysV2, strings.Replace(goldenSyslogV2, `"2026-10-04T13:05:06.789Z"`, `"2026-10-04T15:05:06.789+02:00"`, 1)},
		"number as string":                      {sysV2, strings.Replace(goldenSyslogV2, `"severity":5`, `"severity":"5"`, 1)},
		"no newline":                            {sysV2, strings.TrimSuffix(goldenSyslogV2, "\n")},
		"not JSON":                              {sysV2, "{\"id\":42\n"},
	} {
		if err := tc.d.Syslog([]byte(tc.line), &m); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
	fd, _ := NewDecoder(TableFlows, FlowSchemaV1)
	var f models.FlowSample
	if err := fd.Flow([]byte(strings.Replace(goldenFlow, `"protocol":6`, `"protocol":300`, 1)), &f); err == nil {
		t.Error("an out-of-range protocol decoded")
	}
	if err := fd.Syslog([]byte(goldenSyslogV2), &m); err == nil {
		t.Error("a flow decoder decoded a syslog row")
	}
	if _, err := NewDecoder(TableFlows, 2); err == nil {
		t.Error("flow schema 2 accepted")
	}
	if _, err := NewDecoder("restore_1_syslog_messages", 1); err == nil {
		t.Error("a staging table accepted as an archived table")
	}
}
