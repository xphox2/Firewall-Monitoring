# Changelog

## [0.8.7] - 2026-02-28

### Security
- Logout endpoint moved inside CSRF-protected admin group (`POST /admin/api/logout`)
- Request body size limit middleware (1MB) prevents memory exhaustion via oversized JSON
- `MaxHeaderBytes` (64KB) set on HTTP server to limit header-based DoS
- Login attempts map periodically pruned (10-minute ticker) to prevent unbounded memory growth

### Fixed
- **Admin settings now applied at runtime**: `AlertManager.RefreshThresholds()` reads threshold settings from DB before each poll cycle, making admin UI changes effective without restart
- Trap OID prefix includes leading dot (`.1.3.6.1.4.1.12356.101.2.0`) to match gosnmp output format
- `GetHardwareSensors` now parses sensor name, value, and alarm status from FortiGate HW sensor sub-OIDs instead of returning empty structs
- Admin HTML logout button uses `apiFetch` with CSRF token instead of plain `fetch`

## [0.8.6] - 2026-02-28

### Security
- Login-specific rate limiter (1 req/s, burst 5) added to `/api/auth/login` endpoint
- Email subject headers sanitized to prevent header injection via alert fields
- Module-level `defaultPassword` variable cleared after config load
- Auth cookie `MaxAge` synced with JWT `TokenExpiry` config (was hardcoded 86400s)

### Fixed
- OID prefix collision: `HasPrefix` checks now use OID+`"."` to prevent `.2` matching `.20`
- Type assertions in `ChangePassword` use two-value form (prevents panic on invalid session data)
- `DeleteFortiGateConnection` checks `RowsAffected` and returns 404 when connection not found
- `UpdateFortiGateConnection` validates source and dest won't be the same device after update
- SNMP port range validated in `NewSNMPClient` (rejects port < 1 or > 65535)

### Removed
- Unused `GetRealIP` middleware (blindly trusted `X-Real-IP`/`X-Forwarded-For` headers)
- Unused `CORSMiddleware` function
- Unused `AlertManager` and `Notifier` creation in API server (alerts are handled by poller)

### Changed
- Alert cooldown map pruning now runs periodically in poller cleanup ticker

## [0.8.5] - 2026-02-28

### Security
- Login handler rejects passwords >1024 chars to prevent bcrypt CPU exhaustion DoS
- SSRF fix: `isValidExternalIP` now resolves hostnames and validates all resolved IPs (blocks DNS rebinding)
- SNMP community strings redacted in `GetDashboardAll` response (was only redacted in `GetFortiGates`)
- Logout requires valid `auth_token` cookie before clearing session (prevents cross-origin logout)
- Removed untrusted `GetRealIP` middleware that blindly trusted `X-Real-IP`/`X-Forwarded-For` headers
- Rate limiter cleanup goroutine now stoppable via channel (prevents goroutine leak)
- Login attempts map entries deleted when empty (prevents unbounded memory growth from username spraying)

### Fixed
- SNMP OIDs for ifOutUcastPkts/NUcastPkts/Discards/Errors corrected (were off by one, producing wrong interface stats)
- `getIndexFromOID` returns -1 on parse failure instead of 0 (no longer collides with valid index 0)
- `formatNumber(0)` now displays `0` instead of `--` on public dashboard
- Double refresh timer eliminated on public dashboard (settings timer replaces default)
- `UpdateSettings` reports errors to client instead of silently continuing with "Settings updated"
- `CreateFortiGate` defaults SNMP port to 161 when 0 (prevents invalid port 0 in database)
- `CreateFortiGateConnection` validates SourceFGID/DestFGID exist and are different
- `UpdateFortiGateConnection` validates FK references when source/dest IDs are changed
- `DeleteFortiGate` cascades delete to all related records (SystemStatus, InterfaceStats, VPN, HA, sensors, alerts, uptime, traps)
- `GenerateSecureToken` computes correct random byte count for any output length (prevents potential panic)
- Uptime baseline directory created with 0700 permissions (was 0755)
- Trap receiver stores `addr.IP.String()` instead of `addr.String()` (removes port from stored IP)
- `SystemStatus.ToJSON()` returns `{}` on marshal error instead of empty string
- Alert cooldown map pruning added to prevent unbounded growth

### Added
- AlertManager integrated into poller: threshold alerts and interface-down alerts now fire on each poll
- Concurrent device polling with semaphore (max 5 simultaneous SNMP connections)

## [0.8.4] - 2026-02-28

### Security
- SSRF prevention: IP validation blocks loopback, unspecified, and link-local addresses in TestDevice and CreateFortiGate
- Input validation for `UpdateFortiGate`: validates `snmp_port` range, `ip_address` format, and `enabled` boolean type
- Required field validation for `CreateFortiGate` (name and IP address)
- SNMP community string validated on incoming traps (rejects mismatched community)
- HSTS header only sent over TLS connections (prevents issues with plain HTTP setups)
- Database directory created with 0700 permissions instead of 0755
- 72-character max password length enforced (bcrypt limit)
- `SameSite=Strict` on auth and CSRF cookies via `http.SetCookie`
- SNMP community strings redacted in `GetFortiGates` API response
- Status enum validation for connection updates (only `unknown`, `up`, `down` allowed)
- Plaintext admin password cleared from config memory after hashing

### Fixed
- Database initialization is now fatal in both API server and poller (prevents nil pointer panics)
- Login handler nil-deref guard when database unavailable for admin lookup
- `generateRandomPassword` exits on `crypto/rand` failure instead of nil pointer panic
- `CalculateFiveNines` target downtime corrected from 3.1536 to 315.576 seconds/year
- `updateDeviceStatus` errors now logged in poller
- Admin initialization logs when admin already exists instead of silently skipping
- Env file parser strips surrounding quotes from values (single and double)

### Added
- Periodic data cleanup in poller (removes data older than 90 days, runs daily)

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
