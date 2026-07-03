//go:build integration

// Ingestion load benchmarks (deferred follow-up of the 2026-07-02 audit).
// Measures the sFlow ingest hot path on a real Postgres so the "COPY is 5-10x
// faster than row-by-row" claim in SaveFlowSamples' doc comment rests on
// numbers, not folklore. Three write shapes, worst to best:
//
//	GORMPerRow  — one INSERT per row (the pre-M4/M5 shape the claim compares against)
//	GORMBatch   — one multi-row INSERT via batchInsertWithFallback (SQLite fallback path)
//	CopyFrom    — pgx COPY protocol (saveFlowSamplesPGX, the production PG path)
//
// Needs TEST_PG_DSN (skips otherwise). Run via `make bench-ingest` or the
// manual Benchmark workflow (.github/workflows/benchmark.yml). Like the rest
// of the integration suite this resets the TEST_PG_DSN schema — never point it
// at a real database, and keep `-p 1` (see NewIntegrationDB).
package database

import (
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// benchSeedDevice readies a freshly migrated DB for ingest writes: monthly
// partitions first — RunMigrations does NOT create them (EnsurePartitions is
// a runtime concern of the poller/API; a fresh schema has zero partitions and
// every flow_samples/syslog_messages insert fails 23514 "no partition found",
// as the first CI benchmark run proved) — then the one device the sample rows
// reference, so any present-or-future FK on device_id holds (PG enforces FKs;
// SQLite habits don't transfer — see the integration-test lessons).
func benchSeedDevice(b *testing.B, d *Database) uint {
	b.Helper()
	if err := d.EnsurePartitions(); err != nil {
		b.Fatalf("EnsurePartitions: %v", err)
	}
	dev := models.Device{
		Name:      "bench-fw1",
		IPAddress: "192.0.2.1",
		Vendor:    "fortigate",
		Status:    "online",
	}
	if err := d.db.Create(&dev).Error; err != nil {
		b.Fatalf("seed device: %v", err)
	}
	return dev.ID
}

// benchFlowSamples fabricates n deterministic samples. Timestamps sit within
// ~one second of now so every row routes into the current monthly partition
// (there is no DEFAULT partition — an out-of-range row aborts a COPY batch).
func benchFlowSamples(deviceID uint, n int) []models.FlowSample {
	now := time.Now()
	rows := make([]models.FlowSample, n)
	for i := range rows {
		rows[i] = models.FlowSample{
			Timestamp:      now.Add(time.Duration(i) * time.Millisecond),
			DeviceID:       deviceID,
			ProbeID:        1,
			SamplerAddress: "192.0.2.1",
			SequenceNumber: uint32(3_000_000_000 + i), // past 2^31 on purpose (migration v9 regression guard)
			SamplingRate:   512,
			SrcAddr:        fmt.Sprintf("10.0.%d.%d", i/250%250, i%250+1),
			DstAddr:        fmt.Sprintf("198.51.100.%d", i%250+1),
			SrcPort:        uint16(40_000 + i%25_000),
			DstPort:        443,
			Protocol:       6,
			Bytes:          uint64(1500 * (i%40 + 1)),
			Packets:        uint64(i%40 + 1),
			InputIfIndex:   uint32(i%4 + 1),
			OutputIfIndex:  uint32(i%4 + 5),
			TCPFlags:       0x18,
			AppCategory:    uint8(i % 8),
			Direction:      uint8(i % 4),
		}
	}
	return rows
}

// benchSyslogMessages fabricates n plausible syslog rows (the dominant-volume
// table in prod — see docs/OPERATIONS.md sizing model).
func benchSyslogMessages(deviceID uint, n int) []models.SyslogMessage {
	now := time.Now()
	rows := make([]models.SyslogMessage, n)
	for i := range rows {
		rows[i] = models.SyslogMessage{
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			DeviceID:  deviceID,
			ProbeID:   1,
			Hostname:  "bench-fw1",
			AppName:   "kernel",
			Message:   fmt.Sprintf("date=2026-07-02 action=accept srcip=10.0.0.%d dstip=198.51.100.%d dstport=443 proto=6 sentbyte=%d", i%250+1, i%250+1, 1500*(i%40+1)),
			Priority:  134,
			Facility:  16,
			Severity:  6,
			SourceIP:  "192.0.2.1",
		}
	}
	return rows
}

// resetIDs zeroes primary keys between iterations: GORM's Create writes the
// generated ID back into the row, and re-Creating a slice with populated IDs
// would insert explicit duplicate PKs (unique violation → M26 per-row
// fallback → garbage timings). The COPY path never sets IDs but zeroing is
// harmless there. In-timing cost is a linear pass over n uints — noise.
func resetIDs[T any](rows []T, zero func(*T)) {
	for i := range rows {
		zero(&rows[i])
	}
}

var flowBatchSizes = []int{100, 500, 1000}

// reportRows attaches a rows/s metric so the workflow summary reads directly
// as throughput instead of ns/op-per-batch.
func reportRows(b *testing.B, batch int) {
	b.ReportMetric(float64(b.N*batch)/b.Elapsed().Seconds(), "rows/s")
}

func BenchmarkSaveFlowSamples_CopyFrom(b *testing.B) {
	d := NewIntegrationDB(b)
	if d.pgxPool == nil {
		b.Fatal("pgx pool not initialized — CopyFrom path unavailable")
	}
	devID := benchSeedDevice(b, d)
	for _, size := range flowBatchSizes {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			rows := benchFlowSamples(devID, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := d.SaveFlowSamples(rows); err != nil {
					b.Fatalf("SaveFlowSamples (COPY): %v", err)
				}
			}
			reportRows(b, size)
		})
	}
}

func BenchmarkSaveFlowSamples_GORMBatch(b *testing.B) {
	d := NewIntegrationDB(b)
	devID := benchSeedDevice(b, d)
	for _, size := range flowBatchSizes {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			rows := benchFlowSamples(devID, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resetIDs(rows, func(s *models.FlowSample) { s.ID = 0 })
				if err := batchInsertWithFallback(d.db, "flow_samples", rows); err != nil {
					b.Fatalf("batchInsertWithFallback: %v", err)
				}
			}
			reportRows(b, size)
		})
	}
}

func BenchmarkSaveFlowSamples_GORMPerRow(b *testing.B) {
	d := NewIntegrationDB(b)
	devID := benchSeedDevice(b, d)
	// Smaller batches only — this is the deliberately-slow shape the COPY
	// claim compares against, and 1000 individual INSERTs per iteration
	// makes the benchmark run unreasonably long for no extra signal.
	for _, size := range []int{100, 500} {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			rows := benchFlowSamples(devID, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resetIDs(rows, func(s *models.FlowSample) { s.ID = 0 })
				for j := range rows {
					if err := d.db.Create(&rows[j]).Error; err != nil {
						b.Fatalf("per-row Create: %v", err)
					}
				}
			}
			reportRows(b, size)
		})
	}
}

func BenchmarkSaveSyslogMessages_GORMBatch(b *testing.B) {
	d := NewIntegrationDB(b)
	devID := benchSeedDevice(b, d)
	for _, size := range []int{500, 1000} {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			rows := benchSyslogMessages(devID, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resetIDs(rows, func(m *models.SyslogMessage) { m.ID = 0 })
				if err := d.SaveSyslogMessages(rows); err != nil {
					b.Fatalf("SaveSyslogMessages: %v", err)
				}
			}
			reportRows(b, size)
		})
	}
}
