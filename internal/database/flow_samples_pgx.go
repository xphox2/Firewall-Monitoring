package database

import (
	"context"
	"fmt"
	"time"

	"firewall-mon/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// flowSamplesCopyColumns is the column order for the COPY operation against
// flow_samples. It deliberately omits `id` (the SERIAL column fills it from
// the sequence) and includes `created_at` (the server-side stamp that GORM's
// BeforeCreate hook would normally set; with COPY we provide it directly).
//
// Order MUST match saveFlowSamplesPGX's per-row slice exactly — pgx's
// CopyFromRows binds columns positionally.
var flowSamplesCopyColumns = []string{
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
	"src_country",
	"dst_country",
	"src_asn",
	"dst_asn",
	"threat_flag",
	"as_path",
	"next_hop",
	"created_at",
}

// saveFlowSamplesPGX inserts the slice via the Postgres COPY protocol.
// Equivalent to a row-by-row INSERT but in a single round-trip and without
// per-row transaction overhead. Measured (bench_ingest_integration_test.go,
// 2026-07-03): ~30-70x faster than per-row INSERTs and ~2x faster than one
// multi-row INSERT, reaching ~120k rows/s at batch 1000 on a 4-vCPU runner —
// numbers in docs/OPERATIONS.md. Returns any error from COPY.
//
// The created_at column is server-stamped (one time.Now() call amortized
// across the whole batch) so every row in a batch shares the same creation
// time. That's fine for audit ordering — flows already have their own
// authoritative `timestamp` column from the sFlow sample.
//
// Caller must ensure d.pgxPool != nil.
func saveFlowSamplesPGX(ctx context.Context, pool *pgxpool.Pool, samples []models.FlowSample) error {
	now := time.Now()
	rows := make([][]any, len(samples))
	for i, s := range samples {
		rows[i] = []any{
			s.Timestamp,
			s.DeviceID,
			s.ProbeID,
			s.SamplerAddress,
			s.SequenceNumber,
			s.SamplingRate,
			s.SrcAddr,
			s.DstAddr,
			s.SrcPort,
			s.DstPort,
			s.Protocol,
			s.Bytes,
			s.Packets,
			s.InputIfIndex,
			s.OutputIfIndex,
			s.TCPFlags,
			s.Drops,
			s.AppCategory,
			s.Direction,
			s.SrcCountry,
			s.DstCountry,
			s.SrcASN,
			s.DstASN,
			s.ThreatFlag,
			s.ASPath,
			s.NextHop,
			now,
		}
	}

	// pgx.Identifier wraps the table name so any future rename to a
	// reserved-word identifier is handled at the pgx level. For
	// `flow_samples` (lowercase, no special chars) it's equivalent to
	// the unquoted identifier.
	n, err := pool.CopyFrom(
		ctx,
		pgx.Identifier{"flow_samples"},
		flowSamplesCopyColumns,
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("pgx CopyFrom flow_samples (%d rows): %w", len(samples), err)
	}
	if int(n) != len(samples) {
		return fmt.Errorf("pgx CopyFrom short write: inserted %d of %d", n, len(samples))
	}
	return nil
}
