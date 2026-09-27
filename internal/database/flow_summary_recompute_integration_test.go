//go:build integration

// Real-PostgreSQL proof of the summary rebuild after a reclassification
// (v0.11.266): the request hand-off with its conditional delete, the
// recompute step's summariseBucket calls and the removal of the service
// boundary, on the engine production runs. Runs in the integration lane.
package database

import (
	"testing"

	"firewall-mon/internal/classify"
)

func TestPostgresSummaryRecompute(t *testing.T) {
	d := NewIntegrationDB(t)
	oldReserve := flowSummaryRecomputeReserve
	flowSummaryRecomputeReserve = 0
	t.Cleanup(func() { flowSummaryRecomputeReserve = oldReserve; recomputeBlockedCycles = 0 })

	day, _ := seedTwoTiers(t, d)
	postRecomputeRequest(t, d, 1, day)
	runCycles(d, 10)

	got := cubeBytesByDirection(t, d)
	if got[classify.DirExternal] != 0 || got[classify.DirOutbound] == 0 {
		t.Errorf("summary bytes by direction on PostgreSQL = %v, want all Outbound", got)
	}
	if sinceSet(d) {
		t.Error("the service boundary survived a complete rebuild on PostgreSQL")
	}
	if _, ok := d.GetSettingValue(flowSummaryRecomputeRequestKey); ok {
		t.Error("the request was not consumed")
	}
}
