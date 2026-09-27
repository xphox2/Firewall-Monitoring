package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestRollupLadder_CarriesServicePortAndClassRev pins the two v68 columns
// through every promotion: raw → 5m → 1h. A column added to the model but not
// to the ladder would be written as 0 on the first promotion, silently
// reverting a server's replies to "no service" after an hour. Rows that differ
// only in service_port or class_rev must stay separate groups.
func TestRollupLadder_CarriesServicePortAndClassRev(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().Add(-72 * time.Hour).Truncate(time.Hour).Add(10 * time.Minute)
	mk := func(svc, rev uint16, bytes uint64) models.FlowSample {
		return models.FlowSample{
			Timestamp: base, DeviceID: 1, Protocol: 6,
			SrcAddr: "66.179.9.156", DstAddr: "8.8.8.8", SrcPort: 443, DstPort: 51234,
			Bytes: bytes, Packets: 1, SamplingRate: 1,
			ServicePort: svc, ClassRev: rev,
		}
	}
	samples := []models.FlowSample{mk(443, 1, 1000), mk(443, 1, 500), mk(0, 0, 70), mk(443, 0, 30)}
	if err := d.Gorm().Create(&samples).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	d.aggregateFlowsToRollup(time.Now().Add(-time.Hour), "5m")
	d.aggregateRollupsUp("5m", "1h", time.Now().Add(-48*time.Hour))

	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "1h").Order("bytes_sum DESC").Find(&rows).Error; err != nil {
		t.Fatalf("read 1h rollups: %v", err)
	}
	type key struct{ svc, rev uint16 }
	got := map[key]uint64{}
	for _, r := range rows {
		got[key{r.ServicePort, r.ClassRev}] += r.BytesSum
	}
	want := map[key]uint64{{443, 1}: 1500, {0, 0}: 70, {443, 0}: 30}
	if len(got) != len(want) {
		t.Fatalf("1h groups = %v, want %v (service_port and class_rev must each split groups)", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("1h group service_port=%d class_rev=%d holds %d bytes, want %d; all=%v", k.svc, k.rev, got[k], v, got)
		}
	}
	var left int64
	d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", "5m").Count(&left)
	if left != 0 {
		t.Errorf("%d 5m rows left; the promotion did not run", left)
	}
}
