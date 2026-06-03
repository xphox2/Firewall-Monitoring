package database

import (
	"log"
	"os"
	"strings"

	"gorm.io/gorm/logger"
)

// dbLogLevelFromEnv maps the `DB_LOG_LEVEL` env var to a GORM
// logger.LogLevel. AUDIT-149: pre-fix the GORM logger was hard
// set to `logger.Silent`, which swallowed every log line
// including slow-query warnings, errors, and migration
// notifications. The new default is `warn` (logs slow queries,
// errors, and migration warnings; doesn't log every
// successful statement). Operators who want more visibility
// can set `DB_LOG_LEVEL=info` (every statement) or
// `DB_LOG_LEVEL=error` (errors only).
//
// Valid values:
//   - `silent`: no logging at all (pre-fix default; rarely useful)
//   - `error`:  only errors
//   - `warn`:   slow queries, errors, migration warnings (NEW DEFAULT)
//   - `info`:   every statement (high-volume; debug only)
//
// Unknown values fall back to `warn` (the safe default) and
// the fallback is logged so the operator can spot a typo.
func dbLogLevelFromEnv() logger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DB_LOG_LEVEL"))) {
	case "silent":
		return logger.Silent
	case "error":
		return logger.Error
	case "info":
		return logger.Info
	case "warn", "":
		// Empty is the default case — no env var set.
		return logger.Warn
	default:
		// Unknown value: fall back to warn (safe default) and
		// log a notice so a typo doesn't silently disable
		// logging. We use log.Printf directly because this
		// runs before the logger is configured.
		// (We use the standard library's log here rather
		// than a GORM logger because the GORM logger is
		// what we're configuring.)
		//nolint:forbidigo // stdlib log is the right call here
		log.Printf("DB_LOG_LEVEL=%q is not a known level; defaulting to 'warn' (valid: silent, error, warn, info)", os.Getenv("DB_LOG_LEVEL"))
		return logger.Warn
	}
}
