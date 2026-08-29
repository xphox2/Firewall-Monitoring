package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// setZScorePolicy installs a CPU rule in zscore mode with the given K and
// static floor.
func setZScorePolicy(am *AlertManager, k, floor float64) {
	policy := models.AlertPolicy{
		ID:        1,
		Name:      "test",
		IsDefault: true,
		Rules: []models.AlertRule{{
			PolicyID:  1,
			AlertType: models.AlertTypeCPUHigh,
			Enabled:   true,
			Threshold: floor,
			Mode:      "zscore",
			ZScoreK:   k,
		}},
	}
	am.policyCache = PolicyCache{
		policies:      []models.AlertPolicy{policy},
		policyByID:    map[uint]*models.AlertPolicy{1: &policy},
		deviceConfigs: map[uint]*models.DeviceAlertConfig{},
		siteConfigs:   map[uint]*models.SiteAlertConfig{},
		defaultPolicy: &policy,
		anyZScore:     true,
		loaded:        true,
	}
}

// seedHistory writes n SystemStatus rows for the device with the given CPU
// values, spread over the last hour.
func seedHistory(t *testing.T, am *AlertManager, dev uint, cpus []float64) {
	t.Helper()
	base := time.Now().Add(-time.Hour)
	rows := make([]models.SystemStatus, len(cpus))
	for i, v := range cpus {
		rows[i] = models.SystemStatus{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			DeviceID:  dev,
			CPUUsage:  v,
		}
	}
	if err := am.db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed history: %v", err)
	}
}

// TestZScore_FiresAboveBaseline_F17: with a stable baseline (mean 40, small
// σ), K=3 fires on a genuine excursion but not on ordinary values that a
// static-90 threshold would also ignore — and the alert row carries the
// DYNAMIC threshold.
func TestZScore_FiresAboveBaseline_F17(t *testing.T) {
	am, _ := newTestManager(t)
	setZScorePolicy(am, 3, 0)
	const dev = 90

	// mean 40, alternating ±2 → σ=2; fire level ≈ 46.
	cpus := make([]float64, 24)
	for i := range cpus {
		if i%2 == 0 {
			cpus[i] = 38
		} else {
			cpus[i] = 42
		}
	}
	seedHistory(t, am, dev, cpus)

	// 44 is above mean but inside 3σ — no alert.
	if err := am.CheckSystemStatus(cpuStatus(dev, 44), nil); err != nil {
		t.Fatalf("in-band check: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("in-band value fired: %d open alerts", n)
	}

	// 60 is far outside 3σ — fires, with the dynamic threshold recorded.
	if err := am.CheckSystemStatus(cpuStatus(dev, 60), nil); err != nil {
		t.Fatalf("excursion check: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("excursion did not fire: %d open alerts", n)
	}
	got := latestCPUFire(t, am, dev)
	if got.Threshold < 44 || got.Threshold > 48 {
		t.Errorf("dynamic threshold = %.2f, want ≈46 (mean+3σ)", got.Threshold)
	}
}

// TestZScore_StaticFloor: the rule's Threshold is a floor — even when the
// baseline would put the fire level lower, values under the floor never fire.
func TestZScore_StaticFloor(t *testing.T) {
	am, _ := newTestManager(t)
	setZScorePolicy(am, 3, 80) // floor 80
	const dev = 91

	cpus := make([]float64, 24)
	for i := range cpus {
		cpus[i] = 10 + float64(i%3) // mean ~11, tiny σ → dyn ≈ 14
	}
	seedHistory(t, am, dev, cpus)

	// 50 beats the dynamic level (≈14) but NOT the floor (80) — the
	// effective threshold is max(floor, dyn) = 80, so no fire.
	if err := am.CheckSystemStatus(cpuStatus(dev, 50), nil); err != nil {
		t.Fatalf("check: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("value below the static floor fired: %d open", n)
	}
}

// TestZScore_NoBaseline_FallsBackStatic: with no history the rule behaves as
// a plain static rule (fires at Threshold; Threshold=0 means disabled).
func TestZScore_NoBaseline_FallsBackStatic(t *testing.T) {
	am, _ := newTestManager(t)
	setZScorePolicy(am, 3, 90)
	const dev = 92 // no seeded history

	if err := am.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("check: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 1 {
		t.Fatalf("static fallback did not fire at floor: %d open", n)
	}

	// And with floor 0 + no baseline the rule is inert.
	am2, _ := newTestManager(t)
	setZScorePolicy(am2, 3, 0)
	if err := am2.CheckSystemStatus(cpuStatus(dev, 95), nil); err != nil {
		t.Fatalf("check2: %v", err)
	}
	if n := openCPUAlerts(t, am2, dev); n != 0 {
		t.Fatalf("no-baseline zero-floor rule fired: %d open", n)
	}
}

// seedMixedWriterHistory writes n SNMP-shaped rows (cpu + disk) and n
// SSH-perf-shaped rows (cpu only, disk 0 — that writer never measures disk),
// interleaved over the last hour.
func seedMixedWriterHistory(t *testing.T, am *AlertManager, dev uint, n int, disk float64) {
	t.Helper()
	base := time.Now().Add(-time.Hour)
	rows := make([]models.SystemStatus, 0, 2*n)
	for i := 0; i < n; i++ {
		rows = append(rows,
			models.SystemStatus{Timestamp: base.Add(time.Duration(2*i) * time.Minute), DeviceID: dev, CPUUsage: 30, DiskUsage: disk},
			models.SystemStatus{Timestamp: base.Add(time.Duration(2*i+1) * time.Minute), DeviceID: dev, CPUUsage: 32, DiskUsage: 0},
		)
	}
	if err := am.db.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed mixed history: %v", err)
	}
}

// TestZScore_DiskBaselineIgnoresZeroDiskRows (AUDIT-172): system_status has
// two writers with disjoint fields — the FortiGate SSH perf rows always carry
// disk_usage=0. The disk baseline must be built from real (>0) disk samples
// only, or the mean halves and zscore mode pages DISK_HIGH on ordinary levels.
func TestZScore_DiskBaselineIgnoresZeroDiskRows(t *testing.T) {
	am, _ := newTestManager(t)
	const dev = 94
	seedMixedWriterHistory(t, am, dev, 20, 70) // 20 SNMP rows disk≈70 + 20 SSH rows disk=0

	am.ensureBaseline(dev)
	mean, _, ok := am.baselineFor(dev, "disk_usage")
	if !ok {
		t.Fatal("disk baseline missing — 20 real disk samples exceed baselineMinPts")
	}
	if mean < 65 || mean > 75 {
		t.Fatalf("disk baseline mean = %.2f, want ≈70 (SSH zero-disk rows polluted it)", mean)
	}
	// cpu is measured by BOTH writers — all 40 rows count, no filtering.
	if cpuMean, _, cpuOK := am.baselineFor(dev, "cpu_usage"); !cpuOK || cpuMean < 30 || cpuMean > 32 {
		t.Fatalf("cpu baseline = %.2f ok=%v, want ≈31 from all rows", cpuMean, cpuOK)
	}
}

// Companion: a window with NO real disk samples (SSH-only device) must yield
// NO disk baseline (ok=false → static floor governs) — the per-series
// baselineMinPts gate. A whole-window gate would bless an empty/tiny disk
// series here, which is worse than the original bug.
func TestZScore_AllZeroDiskRowsYieldNoDiskBaseline(t *testing.T) {
	am, _ := newTestManager(t)
	const dev = 95
	seedMixedWriterHistory(t, am, dev, 20, 0) // every row disk=0

	am.ensureBaseline(dev)
	if _, _, ok := am.baselineFor(dev, "disk_usage"); ok {
		t.Fatal("all-zero disk window produced a disk baseline; want ok=false (static fallback)")
	}
	if _, _, ok := am.baselineFor(dev, "cpu_usage"); !ok {
		t.Fatal("cpu baseline must still exist — the min-points gate is per series, not per window")
	}
}

// TestBaseline_UsesNewestSamples (AUDIT-245): with more rows in the window
// than the 2000-row cap, the baseline must be built from the NEWEST samples.
// The old ASC+LIMIT read kept the oldest 2000, so the newest activity never
// entered the baseline: here the 100 newest rows read CPU 80 and the mean
// would stay pinned at exactly 20 without the fix; with it, the newest 2000
// rows (100×80 + 1900×20) average 23.
func TestBaseline_UsesNewestSamples(t *testing.T) {
	am, _ := newTestManager(t)
	const dev = 96
	base := time.Now().Add(-time.Hour)
	rows := make([]models.SystemStatus, 2100)
	for i := range rows {
		cpu := 20.0
		if i >= 2000 { // the 100 newest samples
			cpu = 80
		}
		rows[i] = models.SystemStatus{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			DeviceID:  dev,
			CPUUsage:  cpu,
		}
	}
	if err := am.db.Gorm().CreateInBatches(&rows, 200).Error; err != nil {
		t.Fatalf("seed 2100 rows: %v", err)
	}

	am.ensureBaseline(dev)
	mean, _, ok := am.baselineFor(dev, "cpu_usage")
	if !ok {
		t.Fatal("cpu baseline missing")
	}
	if mean < 22 || mean > 24 {
		t.Fatalf("cpu baseline mean = %.2f, want ≈23 (newest 2000 rows); 20.00 means the limit kept the OLDEST samples", mean)
	}
}

// TestZScore_FlatBaselineGuard: a perfectly flat line (σ=0) must not turn
// microscopic noise into alerts — zscore disables itself, static floor rules.
func TestZScore_FlatBaselineGuard(t *testing.T) {
	am, _ := newTestManager(t)
	setZScorePolicy(am, 3, 90)
	const dev = 93

	cpus := make([]float64, 24)
	for i := range cpus {
		cpus[i] = 30 // σ = 0
	}
	seedHistory(t, am, dev, cpus)

	// 31 would exceed mean+3σ=30 — but σ≈0 disables the dynamic path; the
	// static floor (90) governs, so no fire.
	if err := am.CheckSystemStatus(cpuStatus(dev, 31), nil); err != nil {
		t.Fatalf("check: %v", err)
	}
	if n := openCPUAlerts(t, am, dev); n != 0 {
		t.Fatalf("flat-baseline noise fired: %d open", n)
	}
}
