# Changelog

## [0.8.3] - 2026-02-28

### Security
- CSRF tokens are now HMAC-signed and tied to auth session (replaces double-submit cookie)
- `GetAdminByUsername` now queries by username parameter instead of returning first admin
- Admin password no longer logged in plaintext at startup (printed once to stderr only)
- Error messages from SNMP test connections are sanitized (no internal error leaks)
- Port range validation added for SNMP test device endpoint

### Fixed
- `ChangePassword` uses actual admin ID from JWT claims instead of hardcoded ID=1
- `Login` uses actual admin ID from database for JWT token generation
- SQLite `MaxOpenConns` set to 1 with WAL mode to prevent "database is locked" errors
- SNMP `Close()` guards against nil `Conn` to prevent panic
- `AdminAuth` middleware returns 401 JSON for API routes instead of HTML redirect
- `UpdateFortiGate` and `UpdateFortiGateConnection` return fresh data after update
- `snmp_version` added to allowed fields for FortiGate updates
- Alert cooldown keys no longer include metric values (cooldown now works correctly)
- Email notifications include proper MIME headers (From, To, Content-Type)
- `FormatUptime` uses `uint64` arithmetic to prevent int overflow on 32-bit systems
- Uptime percentage capped at 100% and guarded against uint64 underflow
- `HashPassword` error is now fatal at startup instead of silently ignored
- Poller polls immediately on startup instead of waiting for first interval
- `loadEnvFile` errors are now logged to stderr
- Removed duplicate `saveBaseline` method in uptime tracker

## [0.8.2] - 2026-02-28

### Security
- Removed hardcoded JWT fallback secret key; JWT now fails without configured secret
- Removed hardcoded CSRF fallback token; CSRF generation now fails safely on error
- Removed all debug log lines that leaked usernames, JWT secrets, and config state
- Password change now validates current password before allowing update
- Added minimum 8-character password requirement server-side
- Sanitized error messages to avoid leaking internal DB errors
- Removed panic recovery blocks that silently swallowed errors
- Login lockout now properly expires after configured duration (default 15 min)
- Uses bcrypt cost from config instead of hardcoded default
- JWT token validation now checks signing method
- Default admin password is now randomly generated on first startup (logged to console)
- Per-IP rate limiting replaces global rate limiter to prevent single-IP abuse

### Fixed
- Public dashboard falls back to database when SNMP is unavailable (no more 503)
- Public interfaces endpoint falls back to database when SNMP is unavailable
- Admin dashboard falls back to database when SNMP is unavailable
- FortiGate deletion is now transactional (tunnels, connections, device)
- Connection update now accepts `connection_type`, `notes`, and `status` fields
- FortiGateConnection model now has proper SourceFG/DestFG relation fields for Preload
- Poller now saves SystemStatus and InterfaceStats to database on each poll
- Fixed self-assignment bug in SNMP interface stats
- Fixed admin checkbox settings using `input.checked` instead of `input.value`
- Fixed settings loading for checkbox display (checked attribute)
- Fixed footer year to use dynamic `new Date().getFullYear()`
- Admin sidebar title changed from "FortiGate Admin" to "Firewall Monitor"
- Removed incorrect "restart container" message from password change
- Admin dashboard auto-refreshes every 30 seconds

### Added
- Admin-configurable public display settings (show/hide hostname, uptime, CPU, memory, sessions, interfaces)
- Configurable public dashboard refresh interval
- `GET /api/public/display-settings` endpoint for public display config
- `GET /admin/api/display-settings` endpoint for admin display config management
- `GetLatestSystemStatus()` and `GetLatestInterfaceStats()` database helpers
- Error handling with 401 redirect for failed admin API calls

### Changed
- Moved `glebarez/sqlite` and `gorm.io/gorm` from indirect to direct dependencies
- Removed unused `mattn/go-sqlite3` and `gorm.io/driver/sqlite` dependencies

## [0.8.1] - 2026-02-25

### Fixed
- Login 500 error: Improved password validation logic in auth.go
- CSRF validation failed: Changed csrf_token cookie to be accessible by JavaScript (HttpOnly: false)
- CookieSecure default: Changed default from true to false to allow HTTP login

## [0.8.0] - 2026-02-25

### Added
- Public dashboard with system status
- Admin panel with authentication
- FortiGate device management
- Connection tracking
- Alert management
- Uptime tracking with 99.9% calculation
- SNMP monitoring
- Email/Slack/Discord notifications
