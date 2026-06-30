package database

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestFlowSample_UnsignedColumnsAreWideEnough pins the gorm column-type
// overrides that keep UNSIGNED fields from overflowing a too-narrow SIGNED
// Postgres column. GORM's Postgres dialect picks a column type from a Go int's
// bit width and ignores signedness, so without these tags uint16 ports land in
// `smallint` (max 32767, but ports reach 65535) and uint32 fields land in
// `integer` (max 2.15B, but sFlow sequence numbers pass 2^31). A single
// out-of-range value aborts the whole pgx COPY batch with a 500 and the
// collector re-queues forever. If this test fails, a refactor dropped a tag —
// restore it AND keep migration v9 (flow_samples_widen_int_columns) in sync.
func TestFlowSample_UnsignedColumnsAreWideEnough(t *testing.T) {
	want := map[string]string{
		"SrcPort":        "integer",
		"DstPort":        "integer",
		"SequenceNumber": "bigint",
		"SamplingRate":   "bigint",
		"InputIfIndex":   "bigint",
		"OutputIfIndex":  "bigint",
	}
	ty := reflect.TypeOf(models.FlowSample{})
	for fieldName, wantType := range want {
		f, ok := ty.FieldByName(fieldName)
		if !ok {
			t.Errorf("FlowSample has no field %q", fieldName)
			continue
		}
		gormTag := f.Tag.Get("gorm")
		if !strings.Contains(gormTag, "type:"+wantType) {
			t.Errorf("FlowSample.%s gorm tag = %q, want it to contain %q", fieldName, gormTag, "type:"+wantType)
		}
	}
}

// TestFlowSamplesCopyColumns_OrderAndFieldTypes pins the column order used
// by saveFlowSamplesPGX. The pgx CopyFromRows binds columns POSITIONALLY —
// any reorder of FlowSample fields silently corrupts the table. This static
// test catches the bug at compile time of the test, not at runtime of a
// production bulk insert.
//
// The expected order matches the FlowSample struct's column-tagged field
// order (with `id` excluded — filled by the SERIAL sequence — and
// `created_at` appended — stamped server-side at CopyFrom time). If this
// test fails, update BOTH the struct AND flowSamplesCopyColumns.
func TestFlowSamplesCopyColumns_OrderAndFieldTypes(t *testing.T) {
	// Expected DB column order, omitting `id` (SERIAL fills it).
	want := []string{
		"timestamp",
		"device_id",
		"probe_id",
		"sampler_address",
		"sequence_number",
		"sampling_rate",
		"src_addr",
		"dst_addr",
		"src_port",
		"dst_port",
		"protocol",
		"bytes",
		"packets",
		"input_if_index",
		"output_if_index",
		"tcp_flags",
		"drops",
		"app_category",
		"direction",
	}

	if got, want := len(flowSamplesCopyColumns), len(want)+1; got != want {
		// +1 for the trailing created_at column.
		t.Fatalf("flowSamplesCopyColumns has %d entries, want %d (+ created_at)", got, want)
	}

	// Check the prefix (excluding created_at) matches the expected order.
	gotNames := flowSamplesCopyColumns[:len(want)]
	for i, wantName := range want {
		if gotNames[i] != wantName {
			t.Errorf("flowSamplesCopyColumns[%d] = %q, want %q (matches FlowSample field order)", i, gotNames[i], wantName)
		}
	}

	// Verify created_at is the last column.
	last := flowSamplesCopyColumns[len(flowSamplesCopyColumns)-1]
	if last != "created_at" {
		t.Errorf("flowSamplesCopyColumns last entry = %q, want \"created_at\"", last)
	}
}

// TestSaveFlowSamples_EmptyInputShortCircuits pins the empty-batch contract:
// SaveFlowSamples(nil) and SaveFlowSamples([]) both return nil without
// touching the DB. This is true for BOTH the pgx and GORM paths but the test
// uses the SQLite lane (no pgx pool), so it covers the GORM short-circuit.
// The pgx path's empty-slice behavior is exercised by integration tests on a
// real Postgres.
func TestSaveFlowSamples_EmptyInputShortCircuits(t *testing.T) {
	db := NewDatabaseForTesting(t)
	if err := db.SaveFlowSamples(nil); err != nil {
		t.Errorf("SaveFlowSamples(nil) = %v, want nil", err)
	}
	if err := db.SaveFlowSamples([]models.FlowSample{}); err != nil {
		t.Errorf("SaveFlowSamples(empty slice) = %v, want nil", err)
	}
}

// TestSaveFlowSamples_GORMFallbackOnSQLite pins the SQLite/GORM-fallback path:
// when d.pgxPool is nil (the test backend), SaveFlowSamples uses GORM Create
// exactly as before — no behavior change for non-Postgres callers. This test
// also exercises the column-order contract indirectly (a malformed row would
// fail the GORM insert).
func TestSaveFlowSamples_GORMFallbackOnSQLite(t *testing.T) {
	db := NewDatabaseForTesting(t)

	now := time.Now().UTC()
	samples := []models.FlowSample{
		{
			Timestamp:      now,
			DeviceID:       1,
			ProbeID:        1,
			SamplerAddress: "10.0.0.1",
			SequenceNumber: 42,
			SamplingRate:   512,
			SrcAddr:        "10.0.0.1",
			DstAddr:        "10.0.0.2",
			SrcPort:        12345,
			DstPort:        443,
			Protocol:       6,
			Bytes:          1500 * 512,
			Packets:        512,
			InputIfIndex:   1,
			OutputIfIndex:  2,
			TCPFlags:       0x12,
		},
		{
			Timestamp:    now.Add(-1 * time.Second),
			DeviceID:     2,
			ProbeID:      1,
			SrcAddr:      "10.0.0.3",
			DstAddr:      "10.0.0.4",
			SrcPort:      53,
			DstPort:      53,
			Protocol:     17,
			Bytes:        200,
			Packets:      1,
			InputIfIndex: 3,
		},
	}
	if err := db.SaveFlowSamples(samples); err != nil {
		t.Fatalf("SaveFlowSamples: %v", err)
	}

	var got []models.FlowSample
	if err := db.Gorm().Order("device_id ASC").Find(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("round-trip got %d rows, want 2", len(got))
	}
	if got[0].Bytes != 1500*512 {
		t.Errorf("row[0].Bytes = %d, want %d", got[0].Bytes, 1500*512)
	}
	if got[0].SamplingRate != 512 {
		t.Errorf("row[0].SamplingRate = %d, want 512", got[0].SamplingRate)
	}
	if got[1].Protocol != 17 {
		t.Errorf("row[1].Protocol = %d, want 17 (UDP)", got[1].Protocol)
	}
}
