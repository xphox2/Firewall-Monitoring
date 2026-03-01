# Changelog

## [0.10.11] - 2026-03-01

### Changed
- **Admin UI consistency**: Unified sidebar design across all standalone pages (sites, network, probes, probe-pending) to match admin.html's GitHub-dark theme — 240px flex sidebar with section headers, icons, and grouped navigation
- **CSS class unification**: Replaced `.status-badge` with `.badge` and `.btn.small` with `.btn.sm` across all standalone pages for consistent styling with admin.html
- **Color palette alignment**: Changed body text from `#fff` to `#c9d1d9`, header accent from `#00d4ff` to `#58a6ff`, and active nav style to use `rgba(56,139,253,0.15)` across all admin pages
- **network.html legacy rename**: Renamed `.firewall-node`/`.firewall-name`/`.firewall-ip` CSS classes to `.device-node`/`.device-name`/`.device-ip`, changed "Firewall Details" → "Device Details" and "Firewalls:" → "Devices:"

### Fixed
- **Login redirect**: Changed post-login redirect from `/admin/dashboard` to `/admin` for cleaner URL

## [0.10.10] - 2026-03-01

### Fixed
- **Ping destination unreachable**: `Ping()` now returns `fmt.Errorf("destination unreachable")` instead of stale nil error, which caused unreachable hosts to be reported as successful

## [0.10.9] - 2026-03-01

### Fixed
- **Syslog TCP read deadline**: Moved `SetReadDeadline` inside read loop so it resets per-read instead of expiring 60s after connection start
- **Syslog TCP IPv6 source IP**: Use `net.SplitHostPort()` instead of `strings.LastIndex(":")` which breaks on IPv6 addresses

## [0.10.8] - 2026-03-01

### Fixed
- **Site DB race condition**: Added `sync.RWMutex` to protect `siteDBConnections` map — concurrent access would crash with map corruption
- **Site DB connection leak**: `GetOrCreateSiteDB` now properly closes the connection if `db.DB()` fails after `gorm.Open` succeeds
- **Site DB deletion leak**: `DeleteSiteDatabase` now closes cached DB connection before removing the file
- **GetProbeStats error handling**: All four `Count()` queries now check for errors instead of silently returning zeros

## [0.10.7] - 2026-03-01

### Fixed
- **Syslog ParsePriority**: Rewrote to parse full `<NNN>` priority format (e.g. `<134>` → facility 16, severity 6) instead of only single-digit priorities 0–9
- **Relay sendBatch body leak**: Changed `defer resp.Body.Close()` inside retry loop to direct close, preventing response body accumulation on retries
- **Heartbeat endpoint security**: Added probe existence check — unknown probe IDs now return 404 instead of silently updating
- **GetProbeDevices security**: Added `validateProbe()` call so unapproved or nonexistent probes cannot enumerate devices

## [0.10.6] - 2026-03-01

### Changed
- **Full vendor-agnostic rebrand**: Renamed all "FortiGate" references to generic "Device" terminology throughout models, API routes, handlers, database, config, UI, and deployment files
- **Go module rename**: `fortiGate-Mon` → `firewall-mon`
- **Model renames**: `FortiGate` → `Device`, `FortiGateTunnel` → `DeviceTunnel`, `FortiGateConnection` → `DeviceConnection`, `SiteFortiGate` → `SiteDevice`
- **DB table renames**: `fortigates` → `devices`, `fortigate_tunnels` → `device_tunnels`, `fortigate_connections` → `device_connections`, `site_fortigates` → `site_devices`
- **API route renames**: `/api/fortigates` → `/api/devices`
- **JSON field renames**: `fortigate_id` → `device_id`, `source_fg_id` → `source_device_id`, `dest_fg_id` → `dest_device_id`, `fortigates` → `devices`
- **Config field renames**: `FortiGateHost`/`FortiGatePort` → `SNMPHost`/`SNMPPort`, env vars `FORTIGATE_HOST` → `SNMP_HOST`, `FORTIGATE_SNMP_PORT` → `SNMP_PORT`
- **Binary renames**: `fortigate-api` → `fwmon-api`, `fortigate-poller` → `fwmon-poller`, `fortigate-trap` → `fwmon-trap`, `fortigate-probe` → `fwmon-probe`
- **Docker renames**: service/image/container `fortigate-mon` → `firewall-mon`
- **Default paths**: `/data/fortigate.db` → `/data/firewall-mon.db`, `/etc/fortigate-mon/` → `/etc/firewall-mon/`, `/var/lib/fortigate-mon/` → `/var/lib/firewall-mon/`
- **SNMP OIDs**: FortiGate-specific OID constants and vendor-specific trap logic remain unchanged with clarifying comments added
- **Note**: Pre-production DB migration — GORM AutoMigrate creates new tables but won't rename old ones; users should reinitialize

## [0.10.5] - 2026-03-01

### Added
- **Probe data ingestion endpoints**: Server now accepts data from probes via `POST /api/probes/:id/{syslog,traps,flows,pings,system-status,interface-stats}` — probes no longer get 404 when relaying data
- **FlowSample model & DB methods**: Full GORM model for sFlow data with `SaveFlowSamples()`, `GetFlowSamples()`, AutoMigrate, and cleanup
- **FortiGate-to-Probe assignment**: `ProbeID` field on FortiGate model allows assigning devices to specific probes for SNMP polling
- **TrapEvent ProbeID**: Trap events now track which probe sent them
- **Probe device endpoint**: `GET /api/probes/:id/devices` lets probes fetch their assigned FortiGates with SNMP credentials
- **Probe SNMP polling**: Probe now fetches assigned devices every 5 minutes and polls each via SNMP every 60 seconds, relaying SystemStatus and InterfaceStats back to server
- **Admin syslog page**: New `/admin/syslog` page with filters (probe, device, severity, text search), expandable messages, pagination, and auto-refresh toggle
- **Admin flows page**: New `/admin/flows` page with filters (probe, protocol, src/dst IP) and pagination
- **Admin probe stats endpoint**: `GET /admin/api/probes/:id/stats` returns syslog/trap/flow/ping counts per probe
- **Admin syslog/flows API endpoints**: `GET /admin/api/syslog` and `GET /admin/api/flows` with query filtering
- **Dashboard probe health cards**: Each probe shows name, site, status (animated pulse dot), last seen, and data counts
- **Dashboard recent activity feed**: Combined syslog + trap events sorted by timestamp
- **Device form probe/site dropdowns**: Add/edit device modal now includes Probe and Site selection
- **Device table columns**: Probe and Site columns shown in device list with preloaded data

### Changed
- **Admin UI overhaul**: Redesigned sidebar with sectioned navigation (Monitoring, Data, Infrastructure), stat cards on dashboard, improved typography and spacing
- **Body size limit**: Increased from 1MB to 5MB to handle syslog/sFlow batch submissions
- **GetAllFortiGates/GetFortiGate**: Now preload Site and Probe associations
- **UpdateFortiGate**: Allowed fields now include `probe_id` and `site_id`
- **Styling**: Animated pulsing status dots, color-coded severity badges, monospace font for IPs, sticky table headers, page transition animations, expandable syslog messages

## [0.10.4] - 2026-02-28

### Fixed
- **404 on /admin/devices**: Added missing route so navigating directly to `/admin/devices` works
- **URL-based tab activation**: Navigating to `/admin/devices`, `/admin/connections`, or `/admin/settings` now activates the correct tab in the SPA instead of always showing dashboard

## [0.10.3] - 2026-02-28

### Fixed
- **Broken probe registration flow**: `CreateProbe` now creates the `SystemSetting` entry that `RegisterProbe` expects, so remote probes can actually register
- **Duplicate probe on registration**: `RegisterProbe` now links to the existing admin-created probe instead of creating a duplicate with an auto-generated name
- **Probe auto-approval**: When a remote probe registers with an admin-created key, it is automatically approved and set online

### Added
- **Regenerate registration key**: New endpoint `POST /api/probes/:id/regenerate-key` lets admins regenerate a lost key (old key is immediately invalidated)
- **Deploy Instructions modal**: After creating a probe, shows copy-paste-ready environment variables (`PROBE_NAME`, `PROBE_SITE_ID`, `PROBE_REGISTRATION_KEY`, `PROBE_SERVER_URL`) for the remote machine
- **Deploy Info button**: Each probe in the table has a "Deploy Info" button to retrieve deployment instructions at any time

### Changed
- **Simplified Add Probe form**: Removed technical deployment fields (Listen Address, Listen Port, Server URL) that belong on the remote machine, not in admin config
- **Cleaner probe table**: Replaced Listen Address and Registration Key columns with Approval status column; shows description inline under probe name
- **Filter tabs**: Now filter by approval status (pending/approved/rejected) instead of connection status

## [0.10.2] - 2026-02-28

### Fixed
- **CSRF token reliability**: Replaced fragile cookie-based CSRF token reading with server-side `/admin/api/csrf-token` endpoint across all admin pages (admin, sites, probes, network, probe-pending)
- **Logout button broken on sites and probe-pending pages**: Changed from dead `<a href="/admin/logout">` link (GET to non-existent route) to proper JS-driven POST to `/admin/api/logout`
- **CSRF debug logging**: Added server-side logging when CSRF validation fails showing token lengths and values for diagnosis

### Improved
- **Full world coverage for sites**: Expanded country dropdown from 11 to 140+ countries organized by geographic region (Americas, Europe, Middle East, Africa, Asia, Oceania)
- **Comprehensive region list**: Expanded from 7 to 24 regions covering all continents
- **Complete timezone coverage**: Expanded from 16 to 100+ IANA timezones covering every UTC offset worldwide

## [0.10.0] - 2026-02-28

### Added
- **Probe Approval System**: Approve/reject workflow for probes before they can send data
- **Probe Registration**: Unique registration key for probe authentication
- **Probe Relay Client**: Client that collects all data and forwards to central server
- **Probe Command**: New `cmd/probe` for running probe collectors at remote sites
- **Per-Site Databases**: Database-per-site architecture for easier device cleanup
- **Probe Heartbeat**: Track probe online/offline status
- **Server URL**: Default set to stats.technicallabs.org

### Admin UI
- **Probes Page**: Full CRUD, approval actions, registration key management
- **Sites Page**: Tree view of hierarchical sites with firewall/probe listing
- **Network Diagram**: Visual SVG-based network topology
- **Pending Approvals Page**: Dedicated page for approving/rejecting probes

### Configuration
- PROBE_NAME, PROBE_SITE_ID, PROBE_REGISTRATION_KEY (required for probe)
- PROBE_SERVER_URL (default: https://stats.technicallabs.org)

## [0.9.0] - 2026-02-28

### Added
- **Site Model**: Hierarchical location support with parent-child relationships (Region > Data Center > Rack)
- **Probe Model**: Distributed collector architecture for multi-location monitoring
- **Probe API Endpoints**: Full CRUD operations for probe management
- **Site API Endpoints**: Full CRUD operations for site management
- **FortiGate-Site Linking**: FortiGate model now supports SiteID for organization
- **TLS/mTLS Support**: Configuration for secure probe-to-server communication
- **ICMP Ping Collector**: Active ping monitoring with latency tracking and statistics
- **Syslog Receiver**: RFC 5424 compliant syslog collection (UDP/TCP/TLS)
- **sFlow Receiver**: Basic sFlow v5 skeleton for flow sampling
- **Network Diagram Support**: Connection tracking between firewalls enhanced

### Configuration
- New `ProbeConfig` section with:
  - `PROBE_SERVER_ENABLED` - Enable probe mode
  - `PROBE_LISTEN_ADDRESS/PORT` - Local listener config
  - `PROBE_SERVER_URL` - Central server URL
  - `PROBE_TLS_ENABLED` / `PROBE_MTLS_ENABLED` - TLS options
  - `PROBE_ICMP_ENABLED` - ICMP ping toggle
  - `PROBE_SYSLOG_ENABLED` / `PROBE_SYSLOG_PORT` - Syslog config
  - `PROBE_SFLOW_ENABLED` / `PROBE_SFLOW_PORT` - sFlow config

## [0.8.8] - 2026-02-28

### Added
- **SNMPv3 support**: Full USM security with auth (MD5/SHA/SHA224-512) and privacy (DES/AES/AES192/AES256) protocols via `SNMP_V3_*` env vars

### Security
- Stored XSS fix: settings values escaped with `escapeHtml()` in admin UI form inputs
- SNMP community string redacted in `CreateFortiGate` and `UpdateFortiGate` responses
- `GetSettings` masks `IsSecret=true` values as `"********"`
- `UpdateSettings` validates value types: numeric ranges for thresholds, booleans for toggles, minimum 5 for refresh interval
- Rate limiter bypass fixed: `SetTrustedProxies(nil)` prevents `X-Forwarded-For` spoofing
- `ChangePassword` no longer triggers login rate-limiter lockout (uses `CheckPassword` directly)
- `CurrentPassword` length capped at 1024 bytes in `ChangePassword`
- Username length capped at 255 characters in login to prevent map/DB bloat
- User-Agent truncated to 512 characters before storage
- `Referrer-Policy: strict-origin-when-cross-origin` header added
- `Cache-Control: no-store` header added to prevent caching of authenticated responses
- Password form fields have proper `autocomplete` attributes

### Fixed
- `ProcessTrap` now uses cooldown to prevent notification floods from trap storms
- Alert notification failure no longer aborts remaining alerts in the same cycle (logs error, continues)
- Trap OID loop breaks on first match instead of silently overwriting with last varbind
- `parseTrap` returns nil when no FortiGate trap OID matches (prevents empty trap objects)
- Bare type assertions in `UpdateFortiGateConnection` replaced with safe two-value form

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
