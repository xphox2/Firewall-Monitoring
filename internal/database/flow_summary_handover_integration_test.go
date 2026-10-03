//go:build integration

package database

import "testing"

// The two-late-days handover on the engine production runs: the low marker,
// the acquiring flag and the REPEATABLE READ ownership snapshot all go through
// PostgreSQL here. See runTwoLateDaysScenario.
func TestFlowSummaryIntegration_TwoLateDaysBelowTheFloor(t *testing.T) {
	runTwoLateDaysScenario(t, NewIntegrationDB(t))
}
