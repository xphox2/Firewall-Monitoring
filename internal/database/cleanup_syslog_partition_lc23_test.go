package database

import (
	"testing"

	"firewall-mon/internal/config"
)

// LC-23 (2026-07-04 audit): syslog_messages is one of the six partitioned
// tables but its retention was DELETE-only — the old "never partition-drop
// syslog" rule over-generalized from the straddling case. A monthly partition
// whose entire range is older than BOTH severity windows (critical 0-5 AND
// informational 6-7) holds only expired rows and is safe to drop wholesale.
// syslogPartitionDropDays computes that provably-safe bound; 0 = never drop
// (some severity class is kept forever).
func TestSyslogPartitionDropDays_LC23(t *testing.T) {
	cases := []struct {
		name string
		ret  config.RetentionConfig
		want int
	}{
		{
			// The documented prod recommendation: critical 30, info 7 →
			// anything past 30 days is expired under both windows.
			name: "critical longer than info",
			ret:  config.RetentionConfig{SyslogCriticalDays: 30, SyslogInfoDays: 7},
			want: 30,
		},
		{
			// Info window longer than critical: the bound must be the MAX of
			// the two — dropping at the critical cutoff would destroy
			// informational rows still inside their window.
			name: "info longer than critical",
			ret:  config.RetentionConfig{SyslogCriticalDays: 7, SyslogInfoDays: 30},
			want: 30,
		},
		{
			// The code default: critical kept FOREVER → no partition is ever
			// wholly expired, never drop (the pre-LC-23 behavior, still
			// correct here).
			name: "critical kept forever",
			ret:  config.RetentionConfig{SyslogCriticalDays: 0, SyslogInfoDays: 7},
			want: 0,
		},
		{
			// Legacy single-window mode (SyslogDays only): every row ages out
			// by SyslogDays, info also by the effective 7-day default.
			name: "legacy single window",
			ret:  config.RetentionConfig{SyslogDays: 45},
			want: 45,
		},
		{
			// Legacy window shorter than the always-on info default: info
			// rows survive until day 7, so the safe bound is 7, not 3.
			name: "legacy shorter than info default",
			ret:  config.RetentionConfig{SyslogDays: 3},
			want: 7,
		},
		{
			// Nothing configured: critical kept forever → never drop.
			name: "all zero",
			ret:  config.RetentionConfig{},
			want: 0,
		},
		{
			// Info knob set without critical: NOT legacy mode, and critical
			// is still kept forever → never drop.
			name: "info set critical forever",
			ret:  config.RetentionConfig{SyslogInfoDays: 14, SyslogDays: 45},
			want: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			effInfo := c.ret.SyslogInfoDays
			if effInfo <= 0 {
				effInfo = 7 // mirror CleanupOldData's effective default
			}
			if got := syslogPartitionDropDays(c.ret, effInfo); got != c.want {
				t.Errorf("syslogPartitionDropDays(%+v, effInfo=%d) = %d, want %d",
					c.ret, effInfo, got, c.want)
			}
		})
	}
}
