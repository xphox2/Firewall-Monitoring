package logging

import (
	"bytes"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// TestRedactSecrets pins the credential-redaction contract (AUDIT-076): an attr
// whose key names a secret is masked; an ordinary attr is left untouched.
func TestRedactSecrets(t *testing.T) {
	cases := map[string]bool{
		"password":       true,
		"Password":       true, // case-insensitive
		"snmp_community":  true,
		"auth_token":     true,
		"api_key":        true,
		"private_key":    true,
		"method":         false,
		"latency":        false,
		"req":            false,
		"status":         false,
	}
	for key, wantRedacted := range cases {
		got := redactSecrets(nil, slog.String(key, "supersecret")).Value.String()
		if wantRedacted && got != redactValue {
			t.Errorf("key %q: expected redaction, got %q", key, got)
		}
		if !wantRedacted && got == redactValue {
			t.Errorf("key %q: unexpected redaction", key)
		}
	}
}

// TestRedactionEndToEnd proves a real slog handler built with redactSecrets
// never emits a secret value but keeps non-secret attrs.
func TestRedactionEndToEnd(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: redactSecrets}))
	logger.Info("login", "password", "hunter2", "user", "alice")

	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret value leaked into log output: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("non-secret attr was dropped: %s", out)
	}
	if !strings.Contains(out, redactValue) {
		t.Fatalf("redaction marker missing: %s", out)
	}
}

// TestStdlibBridge proves the zero-churn mechanism the whole audit relies on:
// slog.SetDefault routes the legacy `log` package through the slog handler, so
// every existing log.Printf gains structured output with no per-site edit.
func TestStdlibBridge(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	log.Printf("bridged %d", 42)

	if !strings.Contains(buf.String(), "bridged 42") {
		t.Fatalf("log.Printf was not routed through slog: %q", buf.String())
	}
}

// TestParseLevel covers the LOG_LEVEL mapping including the info default.
func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"ERROR":   slog.LevelError,
		"":        slog.LevelInfo, // default
		"bogus":   slog.LevelInfo, // unknown → default
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
