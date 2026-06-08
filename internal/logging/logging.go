// Package logging configures the application's structured logger (AUDIT-076).
//
// Before AUDIT-076 the codebase emitted a flat `log.Printf` stream: no levels,
// no machine-parseable fields, no request correlation, no credential redaction.
// A flat stream is not searchable, which the v0.10.236 / v0.10.238 incident
// chain showed is the team's primary diagnostic surface.
//
// This package adopts the stdlib `log/slog` as the single logging backend.
// The key design choice is the zero-churn bridge: Init calls slog.SetDefault,
// which (Go 1.21+) also redirects the standard `log` package through the slog
// handler. So all ~460 legacy `log.Printf` call sites immediately gain
// structured, levelled, redacted output without per-site edits, and new code
// plus the hot chokepoints (middleware.RequestLogger, httputil.InternalError)
// emit native slog records with queryable attributes.
//
// Two env vars control the output:
//
//	LOG_FORMAT = text (default) | json
//	    text  → logfmt (key=value), human-readable, the default.
//	    json  → one JSON object per line, for ingestion into Loki/ELK/Splunk.
//	LOG_LEVEL  = debug | info (default) | warn | error
//	    Legacy `log.Printf` lines bridge in at info, so the default keeps the
//	    pre-AUDIT-076 verbosity; raising to warn will suppress them.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// redactValue replaces the value of any attribute whose key names a secret.
const redactValue = "REDACTED"

// secretKeySubstrings are matched (case-insensitive substring) against every
// slog attribute key; a hit replaces the value with redactValue so credentials
// never reach the log sink (AUDIT-076). This mirrors the masking already
// applied to API responses (httputil.RedactDevice/RedactProbe).
//
// NOTE: redaction is keyed on the attribute name, so it protects native slog
// attrs (the path new code and the chokepoints take). Secrets formatted into a
// bridged `log.Printf` message string are NOT caught — the message arrives as a
// single opaque "msg" attr. The fix there is to stop interpolating secrets into
// log strings, not to regex-scrub messages (which would be fragile and could
// mangle legitimate content).
var secretKeySubstrings = []string{
	"password", "passwd", "secret", "token",
	"apikey", "api_key", "community", "private_key",
}

// Init configures slog as the process-wide logger and redirects the legacy
// `log` package through it. Call once, as early as possible in main(), before
// any other package logs. It returns the installed logger (also reachable via
// slog.Default()).
func Init() *slog.Logger {
	logger := slog.New(newHandler(os.Stderr))
	slog.SetDefault(logger) // also routes the stdlib `log` package through slog
	return logger
}

// newHandler builds the slog handler for w from the LOG_FORMAT / LOG_LEVEL env
// vars. Split out from Init so tests can target a buffer instead of stderr.
func newHandler(w *os.File) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:       parseLevel(os.Getenv("LOG_LEVEL")),
		ReplaceAttr: redactSecrets,
	}
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// parseLevel maps a LOG_LEVEL string to a slog.Level, defaulting to info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// redactSecrets is the slog ReplaceAttr hook: any attribute whose key contains a
// secret-naming substring has its value replaced with redactValue. Group nodes
// are passed through so their children are still visited.
func redactSecrets(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		return a
	}
	lower := strings.ToLower(a.Key)
	for _, s := range secretKeySubstrings {
		if strings.Contains(lower, s) {
			a.Value = slog.StringValue(redactValue)
			return a
		}
	}
	return a
}
