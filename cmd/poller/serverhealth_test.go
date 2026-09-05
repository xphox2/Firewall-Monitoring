package main

import (
	"testing"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/serverhealth"
)

// dataVol / rootVol build already-probed volumes for the metric recorder.
func dataVol(pct float64, free, total uint64) alerts.ServerVolume {
	return alerts.ServerVolume{Label: "data", Volume: serverhealth.Volume{Path: "/data", Percent: pct, FreeBytes: free, TotalBytes: total}}
}

func rootVol(pct float64, free uint64) alerts.ServerVolume {
	return alerts.ServerVolume{Label: "root", Volume: serverhealth.Volume{Path: "/", Percent: pct, FreeBytes: free}}
}

// lastServerMetric reads back the single most recent saved sample.
func lastServerMetric(t *testing.T, db *database.Database) models.ServerMetric {
	t.Helper()
	var m models.ServerMetric
	if err := db.Gorm().Order("id desc").First(&m).Error; err != nil {
		t.Fatalf("read back ServerMetric: %v", err)
	}
	return m
}

// TestRecordServerMetrics_DataOKPopulatesDataDiskFields: when the database
// volume was measured, its pointer fields are populated (not nil).
func TestRecordServerMetrics_DataOKPopulatesDataDiskFields(t *testing.T) {
	p, db := newTestPoller(t)

	p.recordServerMetrics([]alerts.ServerVolume{rootVol(60, 100), dataVol(42, 7<<30, 350<<30)}, true)

	m := lastServerMetric(t, db)
	if m.DataDiskPercent == nil {
		t.Fatal("DataDiskPercent = nil, want a value when dataOK=true")
	}
	if *m.DataDiskPercent != 42 {
		t.Fatalf("*DataDiskPercent = %v, want 42", *m.DataDiskPercent)
	}
	if m.DataDiskFreeBytes == nil {
		t.Fatal("DataDiskFreeBytes = nil, want a value when dataOK=true")
	}
	if *m.DataDiskFreeBytes != 7<<30 {
		t.Fatalf("*DataDiskFreeBytes = %v, want %v", *m.DataDiskFreeBytes, uint64(7<<30))
	}
	if m.DataDiskPath != "/data" {
		t.Fatalf("DataDiskPath = %q, want %q", m.DataDiskPath, "/data")
	}
	// v59: the volume SIZE is stored, not derived — the Retention page's
	// projection verdict must agree with df, and free ÷ (1 − pct) does not.
	if m.DataDiskTotalBytes == nil {
		t.Fatal("DataDiskTotalBytes = nil, want the probed volume size when dataOK=true")
	}
	if *m.DataDiskTotalBytes != 350<<30 {
		t.Fatalf("*DataDiskTotalBytes = %v, want %v", *m.DataDiskTotalBytes, uint64(350<<30))
	}
}

// TestRecordServerMetrics_DataNotOKLeavesDataDiskFieldsNil is the highest-value
// guard: even when a stale/racy "data"-labeled volume is passed, dataOK=false
// MUST win and leave the pointer fields nil. A zero here would draw a
// "disk empty" flatline — the failure-reads-as-healthy shape of the outage.
func TestRecordServerMetrics_DataNotOKLeavesDataDiskFieldsNil(t *testing.T) {
	p, db := newTestPoller(t)

	// A data volume IS present in vols, but dataOK is false.
	p.recordServerMetrics([]alerts.ServerVolume{rootVol(60, 100), dataVol(99, 1, 100)}, false)

	m := lastServerMetric(t, db)
	if m.DataDiskPercent != nil {
		t.Fatalf("DataDiskPercent = %v (non-nil), want nil when dataOK=false", *m.DataDiskPercent)
	}
	if m.DataDiskFreeBytes != nil {
		t.Fatalf("DataDiskFreeBytes = %v (non-nil), want nil when dataOK=false", *m.DataDiskFreeBytes)
	}
	if m.DataDiskTotalBytes != nil {
		t.Fatalf("DataDiskTotalBytes = %v (non-nil), want nil when dataOK=false", *m.DataDiskTotalBytes)
	}
	if m.DataDiskPath != "" {
		t.Fatalf("DataDiskPath = %q, want empty when dataOK=false", m.DataDiskPath)
	}
}

// TestRecordServerMetrics_RootAlwaysPopulatedIndependentOfDataOK: the root
// filesystem is recorded regardless of dataOK, so a PGDATA fault never leaves
// the server entirely unwatched.
func TestRecordServerMetrics_RootAlwaysPopulatedIndependentOfDataOK(t *testing.T) {
	for _, dataOK := range []bool{true, false} {
		p, db := newTestPoller(t)
		p.recordServerMetrics([]alerts.ServerVolume{rootVol(73, 12345)}, dataOK)

		m := lastServerMetric(t, db)
		if m.RootDiskPercent != 73 {
			t.Fatalf("dataOK=%v: RootDiskPercent = %v, want 73", dataOK, m.RootDiskPercent)
		}
		if m.RootDiskFreeBytes != 12345 {
			t.Fatalf("dataOK=%v: RootDiskFreeBytes = %v, want 12345", dataOK, m.RootDiskFreeBytes)
		}
	}
}

// TestCollectServerVolumes_DBNilReturnsDataNotOK covers the first false-producer
// (p.db == nil) without needing a live Postgres.
func TestCollectServerVolumes_DBNilReturnsDataNotOK(t *testing.T) {
	p := &Poller{db: nil}
	_, dataOK := p.collectServerVolumes()
	if dataOK {
		t.Fatal("collectServerVolumes with nil db returned dataOK=true, want false")
	}
}
