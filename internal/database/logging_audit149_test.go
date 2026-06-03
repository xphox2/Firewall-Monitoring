package database

import (
	"testing"

	"gorm.io/gorm/logger"
)

// TestDBLogLevel_DefaultIsWarn_AUDIT149 — the headline regression
// for the audit: pre-fix the GORM logger was hardcoded to
// `logger.Silent`, which swallowed every log line including
// slow-query warnings, errors, and migration warnings.
// Operators had no visibility into slow queries, no error
// trail, and no way to debug "the dashboard is slow" reports
// without enabling debug logging at the code level.
//
// The new default is `logger.Warn`, configurable via
// `DB_LOG_LEVEL`. The test pins the env-var → level mapping.
func TestDBLogLevel_DefaultIsWarn_AUDIT149(t *testing.T) {
	// The default (no env var) must be Warn.
	t.Setenv("DB_LOG_LEVEL", "")
	if got := dbLogLevelFromEnv(); got != logger.Warn {
		t.Errorf("default DB log level = %v, want logger.Warn (AUDIT-149: was logger.Silent, swallowed every log line)", got)
	}
}

// TestDBLogLevel_AllValidValues_AUDIT149 — the four valid
// values must map correctly. A future agent who adds a fifth
// value (e.g. `trace`) but forgets to update the test would
// fail here.
func TestDBLogLevel_AllValidValues_AUDIT149(t *testing.T) {
	tests := []struct {
		env  string
		want logger.LogLevel
	}{
		{"silent", logger.Silent},
		{"error", logger.Error},
		{"warn", logger.Warn},
		{"info", logger.Info},
		{"WARN", logger.Warn},   // case-insensitive
		{" Info ", logger.Info}, // trim whitespace
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("DB_LOG_LEVEL", tc.env)
			if got := dbLogLevelFromEnv(); got != tc.want {
				t.Errorf("DB_LOG_LEVEL=%q → %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

// TestDBLogLevel_UnknownFallsBackToWarn_AUDIT149 — defensive
// sibling: an unknown `DB_LOG_LEVEL` value (typo, etc.) must
// fall back to `warn` (the safe default) rather than to
// `silent` (the worst-case default — silent logging is the
// bug the audit was about). The fallback also logs a notice
// so the operator can spot the typo.
func TestDBLogLevel_UnknownFallsBackToWarn_AUDIT149(t *testing.T) {
	t.Setenv("DB_LOG_LEVEL", "vibing")
	if got := dbLogLevelFromEnv(); got != logger.Warn {
		t.Errorf("DB_LOG_LEVEL=vibing → %v, want logger.Warn (silent would be the wrong fallback — that's the audit's bug)", got)
	}
}
