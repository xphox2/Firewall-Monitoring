//go:build integration

package status

import (
	"context"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestBuild_PG runs the archive status reads on PostgreSQL (TEST_PG_DSN): the
// manifest aggregates, the worker state's upsert and read-back, the gate
// events of the shown months, and the database volume's sample lookup the
// RETENTION_HELD trend uses. Same fixture as TestBuild.
func TestBuild_PG(t *testing.T) {
	db := database.NewIntegrationDB(t)
	seed(t, db)
	saveRuntime(t, db, at.Add(-time.Minute), at.Add(-7*time.Hour))
	saveRuntime(t, db, at.Add(-time.Minute), at.Add(-7*time.Hour)) // the upsert path
	st := build(t, db, testConfig(true, true), at)

	sys := tableOf(t, st, export.TableSyslog)
	if sys.VerifiedThroughID != 300 || sys.LastVerifiedAt == nil || sys.Unsettled == nil || sys.Unsettled.Reason != "open_writer" {
		t.Fatalf("syslog: %+v", sys)
	}
	ss := streamOf(t, st, export.StreamSyslog)
	if ss.OldestUnsealed != "2026-09" || len(ss.Months) != 3 || len(ss.Months[1].Degraded) != 1 || ss.LastSealedAt == nil {
		t.Fatalf("syslog stream: %+v", ss)
	}
	if len(st.NeedsAttention) != 1 || !st.NeedsAttention[0].HoldsGate || st.Worker == nil || len(st.Worker.Stages) != 1 {
		t.Fatalf("status: %+v", st)
	}
	cs := NewEvaluator().Conditions(st, ReadThresholds(stored(t, db)), DiskTrend{})
	if c := conditionOf(t, cs, models.AlertTypeArchiveSealOverdue, export.StreamSyslog); !c.Breached {
		t.Fatalf("seal overdue: %+v", c)
	}

	now := time.Now()
	free := uint64(80) << 30
	if err := db.SaveServerMetric(&models.ServerMetric{Timestamp: now.Add(-2 * time.Hour), DataDiskFreeBytes: &free}); err != nil {
		t.Fatal(err)
	}
	got, err := db.ServerDataDiskFreeAt(context.Background(), now.Add(-3*time.Hour), now.Add(-time.Hour))
	if err != nil || got == nil || *got != free {
		t.Fatalf("data disk sample: %v %v", got, err)
	}
	if got, err := db.ServerDataDiskFreeAt(context.Background(), now.Add(-time.Hour), now); err != nil || got != nil {
		t.Fatalf("a sample outside the window: %v %v", got, err)
	}
}
