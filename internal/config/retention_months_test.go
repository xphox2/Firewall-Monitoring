package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// RETENTION_SYSLOG_MONTHS: default 0 (off), 0-120, strictly parsed — a typo
// must stop the start, not silently fall back to the day windows.
func TestSyslogMonths_ParseAndValidate(t *testing.T) {
	cases := []struct {
		value   string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1", 1, false},
		{" 12 ", 12, false},
		{"120", 120, false},
		{"121", 121, true},
		{"-1", -1, true},
		{"1m", 0, true},
		{"one", 0, true},
	}
	for _, c := range cases {
		t.Setenv("RETENTION_SYSLOG_MONTHS", c.value)
		r := Load().Retention
		if r.SyslogMonths != c.want {
			t.Errorf("%q: SyslogMonths %d, want %d", c.value, r.SyslogMonths, c.want)
		}
		err := r.validateSyslogMonths()
		if (err != nil) != c.wantErr {
			t.Errorf("%q: validate error %v, want error %v", c.value, err, c.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "RETENTION_SYSLOG_MONTHS") {
			t.Errorf("%q: error %q does not name the key", c.value, err)
		}
	}
}

// The startup NOTICE names the env windows months replaces, with their values,
// and says the Retention page still wins; nothing is logged when it is off.
func TestSyslogMonths_StartupNotice(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	r := RetentionConfig{SyslogMonths: 1, SyslogCriticalDays: 30, SyslogInfoDays: 7}
	if err := r.validateSyslogMonths(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"NOTICE: RETENTION_SYSLOG_MONTHS=1", "RETENTION_SYSLOG_CRITICAL_DAYS=30",
		"RETENTION_SYSLOG_INFO_DAYS=7", "RETENTION_SYSLOG_DAYS=0", "are ignored", "Retention page"} {
		if !strings.Contains(out, want) {
			t.Errorf("notice %q lacks %q", out, want)
		}
	}
	buf.Reset()
	if err := (&RetentionConfig{SyslogCriticalDays: 30}).validateSyslogMonths(); err != nil || buf.Len() != 0 {
		t.Errorf("months off: err %v, logged %q", err, buf.String())
	}
}
