package database

import (
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

// Projection arithmetic and the volume verdict's inputs, on SQLite. The
// catalog-backed footprint has its own integration tests; here the width is the
// meter's own bytes-per-row (DiskWidthMeasured=false), which makes the expected
// figures exact.

// seedIngestBucket writes one bucket for the CURRENT hour, so it is always
// under 1 h old, the rate window is the 1 h floor and rows/day = rows × 24
// exactly. (Seeding "30 minutes ago" and truncating made the bucket 1-1.5 h old
// for the first half of every wall-clock hour, and the test flaked.)
func seedIngestBucket(t *testing.T, d *Database, sev int, rows, bytes int64) {
	t.Helper()
	hour := time.Now().UTC().Truncate(time.Hour)
	if err := d.db.Create(&models.SyslogIngestHourly{Timestamp: hour, Severity: sev, RowCount: rows, ByteCount: bytes}).Error; err != nil {
		t.Fatalf("seed bucket: %v", err)
	}
}

func severity(rep SyslogVolumeReport, sev int) SyslogSeverityVolume {
	for _, s := range rep.Severities {
		if s.Severity == sev {
			return s
		}
	}
	return SyslogSeverityVolume{}
}

func TestSyslogVolume_ProjectionIsRateTimesWindowTimesWidth(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedIngestBucket(t, d, 5, 1000, 100000) // 100 bytes/row

	rep := d.SyslogVolume(config.RetentionConfig{SyslogCriticalDays: 30, SyslogInfoDays: 7})

	if rep.RateHours < 1 || rep.RateHours > 1.001 {
		t.Fatalf("RateHours = %v, want the 1 h floor for a single 30-minute-old bucket", rep.RateHours)
	}
	if rep.DiskWidthMeasured {
		t.Error("DiskWidthMeasured = true on SQLite; there is no catalog to measure from")
	}
	if rep.DiskBytesPerRow != 100 {
		t.Errorf("DiskBytesPerRow = %d, want 100 (meter fallback: bytes ÷ rows)", rep.DiskBytesPerRow)
	}

	s5 := severity(rep, 5)
	if !s5.RateAvailable {
		t.Fatal("severity 5 RateAvailable = false with a bucket present")
	}
	if s5.RowsPerDay != 24000 || s5.BytesPerDay != 2400000 {
		t.Errorf("severity 5 rate = %d rows/day, %d bytes/day; want 24000 / 2400000 (× 24 over a 1 h window)",
			s5.RowsPerDay, s5.BytesPerDay)
	}
	if s5.Days != 30 {
		t.Fatalf("severity 5 Days = %d, want 30", s5.Days)
	}
	if want := int64(24000) * 30 * 100; s5.ProjectedBytes != want {
		t.Errorf("severity 5 ProjectedBytes = %d, want %d (rows/day × days × width)", s5.ProjectedBytes, want)
	}
	if s5.ProjectedForever {
		t.Error("severity 5 ProjectedForever = true on a 30-day window")
	}
	if rep.ProjectedSyslogBytes != s5.ProjectedBytes {
		t.Errorf("ProjectedSyslogBytes = %d, want %d (only severity 5 receives rows)", rep.ProjectedSyslogBytes, s5.ProjectedBytes)
	}
	if rep.ProjectedForever {
		t.Error("report ProjectedForever = true with no forever severity receiving rows")
	}

	// A quiet severity on the same install: the rate is known (zero), and so
	// is the projection.
	s3 := severity(rep, 3)
	if !s3.RateAvailable || s3.RowsPerDay != 0 || s3.ProjectedBytes != 0 {
		t.Errorf("severity 3 = %+v, want rate available with zero rows/day and zero projection", s3)
	}
}

func TestSyslogVolume_ForeverWindowWithIngestProjectsForever(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedIngestBucket(t, d, 5, 10, 1000)

	// SyslogCriticalDays == 0 keeps severities below the boundary forever.
	rep := d.SyslogVolume(config.RetentionConfig{})

	s5 := severity(rep, 5)
	if s5.Days != 0 {
		t.Fatalf("severity 5 Days = %d, want 0 (forever) under an all-zero RetentionConfig", s5.Days)
	}
	if !s5.ProjectedForever || s5.ProjectedBytes != 0 {
		t.Errorf("severity 5 = %+v, want ProjectedForever with no finite projection", s5)
	}
	if !rep.ProjectedForever {
		t.Error("report ProjectedForever = false while a forever severity receives rows")
	}
	// Forever with NOTHING arriving is not "grows without bound".
	if s3 := severity(rep, 3); s3.ProjectedForever {
		t.Errorf("severity 3 = %+v, ProjectedForever must need a non-zero rate", s3)
	}
}

func TestSyslogVolume_RateUnavailableBeforeFirstBucket(t *testing.T) {
	d := NewDatabaseForTesting(t)
	rep := d.SyslogVolume(config.RetentionConfig{SyslogCriticalDays: 30})
	if rep.RateHours != 0 {
		t.Errorf("RateHours = %v with no buckets, want 0", rep.RateHours)
	}
	for _, s := range rep.Severities {
		if s.RateAvailable || s.ProjectedBytes != 0 || s.ProjectedForever {
			t.Errorf("severity %d = %+v, want no rate and no projection before the first bucket", s.Severity, s)
		}
	}
}

func TestSyslogVolume_VolumeKnownOnlyWithAServerSample(t *testing.T) {
	d := NewDatabaseForTesting(t)

	if rep := d.SyslogVolume(config.RetentionConfig{}); rep.VolumeKnown {
		t.Errorf("VolumeKnown = true with no server_metrics row: %+v", rep)
	}

	// An old sample (pre-v59: no stored total) is usable but derived.
	pct, free := 40.0, uint64(60<<30)
	old := models.ServerMetric{Timestamp: time.Now().Add(-10 * time.Minute), DataDiskPercent: &pct, DataDiskFreeBytes: &free}
	if err := d.db.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	rep := d.SyslogVolume(config.RetentionConfig{})
	if !rep.VolumeKnown || !rep.VolumeTotalDerived {
		t.Errorf("pre-v59 sample: VolumeKnown=%v VolumeTotalDerived=%v, want true/true", rep.VolumeKnown, rep.VolumeTotalDerived)
	}
	if want := int64(100 << 30); rep.VolumeTotalBytes != want {
		t.Errorf("derived total = %d, want %d (free ÷ (1 − pct))", rep.VolumeTotalBytes, want)
	}

	// The newest sample carries the stored size: used verbatim.
	total := uint64(350 << 30)
	fresh := models.ServerMetric{Timestamp: time.Now(), DataDiskPercent: &pct, DataDiskFreeBytes: &free, DataDiskTotalBytes: &total}
	if err := d.db.Create(&fresh).Error; err != nil {
		t.Fatal(err)
	}
	rep = d.SyslogVolume(config.RetentionConfig{})
	if !rep.VolumeKnown || rep.VolumeTotalDerived {
		t.Errorf("stored-total sample: VolumeKnown=%v VolumeTotalDerived=%v, want true/false", rep.VolumeKnown, rep.VolumeTotalDerived)
	}
	if rep.VolumeTotalBytes != int64(total) || rep.VolumeFreeBytes != int64(free) {
		t.Errorf("volume = %d total / %d free, want %d / %d", rep.VolumeTotalBytes, rep.VolumeFreeBytes, total, free)
	}
	if rep.DatabaseBytes <= 0 {
		t.Errorf("DatabaseBytes = %d, want the SQLite page_count × page_size", rep.DatabaseBytes)
	}
}
