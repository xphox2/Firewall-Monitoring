# Changelog

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
