# Changelog

## [0.10.102] - 2026-03-07

### Changed
- IRC !status: per-device side-by-side boxes with individual CPU/MEM/VPN/alerts/sessions
- Progress bars use color thresholds: green (≤60%), yellow (60-85%), red (>85%) on black background
- Wider 16-char bars for better visual resolution
- Device uptime shown in header: ┌─ NAME ──── (Up: 45d 3h) ─┐
- Status provider now returns per-device data instead of aggregates
- Monospace toggle (\x11) wrapping for proper alignment across IRC clients

## [0.10.101] - 2026-03-07

### Fixed
- IRC: seed default commands (!status, !stats, !help) on startup so they work without manual creation
- IRC: added !help command type that lists all available commands

## [0.10.100] - 2026-03-07

### Fixed
- IRC disconnect panic: Bot.Stop() no longer panics on double-close of quit channel

## [0.10.99] - 2026-03-07

### Added
- IRC !status command now shows a 6-line visual ASCII health dashboard with:
  - Device counts (online/offline/total) with color indicators
  - CPU and memory usage with visual progress bars
  - VPN tunnel status (up/total), active alerts, and session count
  - IRC color codes for green (healthy), red (alerts/down), orange (bars)
- Status provider now includes CPU/memory averages, session totals, and VPN tunnel counts

## [0.10.98] - 2026-03-07

### Fixed
- Standardized navigation sidebar across all admin pages (consistent order, icons, sections)
- Added "System" section with Settings and IRC links to all admin pages
- Fixed Connections/Interfaces order in device-detail and connection-detail pages
- IRC: renamed model field `Password` to `ServerPassword` with explicit gorm column tags
- IRC: fixed frontend sending wrong JSON key (`password` instead of `server_password`)
- IRC: fixed server card not showing channels (was using empty global array instead of preloaded data)
- IRC: removed broken manual column migration code, replaced with one-time schema fix
- IRC: fixed update handler returning stale data after save
- IRC page sidebar now matches all other admin pages
- IRC page logout link now uses standard data-action="logout" pattern

## [0.10.97] - 2026-03-07

### Fixed
- Fixed OID index extraction for VPN tunnels (getIndexFromOID now correctly extracts multi-part indices)
- Device VPN page now cross-fills Phase 2 subnets from peer devices

## [0.10.96] - 2026-03-07

### Fixed
- Device VPN page now cross-fills Phase 2 subnets from peer devices when local device doesn't expose them (HUB limitation)

## [0.10.88] - 2026-03-04

### Added
- WAN link speed setting per device (for usage percentage calculations)
- Bandwidth charts now show usage percentage based on configured WAN speed

### Fixed
- Fixed bandwidth chart ranges (now uses proper time-bucketed aggregation)
- Removed 1-minute range option (minimum is now 5 minutes)
- Fixed negative Mbps values in aggregated bandwidth charts
- Fixed API response format for bandwidth charts

### Added (0.10.87)
- Public dashboard bandwidth layout options (grid/full width)
- Public dashboard chart height configuration
- Admin controls on public page to customize bandwidth layout
- Admin detection middleware for public API

## [0.10.86] - 2026-03-04

### Fixed
- Removed orphaned duplicate code in public-dashboard.js that caused syntax error

## [0.10.85] - 2026-03-04

### Fixed
- Critical: Race condition - settings now load before fetching data
- Fixed toFixed() crash on undefined bandwidth data
- Added missing null checks for DOM elements
- Added 90d range support for bandwidth charts

## [0.10.84] - 2026-03-04

### Fixed
- Public interface checkbox now saves properly (added missing switch case in backend)
- Fixed race condition in public dashboard loading (now waits for devices before loading data)
- Fixed duplicate device fetch in bandwidth section

### Changed
- Public dashboard shows all device data together without waiting for dropdown

## [0.10.83] - 2026-03-04

### Changed
- Public dashboard now shows ALL devices in combined table view (no dropdown)
- Combined CPU/Memory/Uptime/Sessions table for all firewalls
- All public interfaces from all devices shown in grid
- Fixed bandwidth charts to only show public interfaces

## [0.10.82] - 2026-03-04

### Added
- Fancy interface bandwidth charts on public dashboard with Chart.js
- View types: Throughput (Mbps), Total Transferred, Mix (Both)
- Time ranges: 1m, 5m, 15m, 1h, 6h, 24h, 7d
- Interface selector to switch between public interfaces

## [0.10.81] - 2026-03-04

### Changed
- Simplified public dashboard interface selection - now "Show Public" checkbox directly on device detail page
- Per-device interface selection stored as JSON: {"1":["wan1","wan2"],"2":["dmz"]}
- Removed complex Settings page dropdowns - just check "Public" box on each interface

## [0.10.80] - 2026-03-04

### Added
- Configurable public dashboard modules - pick and choose what to show on stats.technicallabs.org
- New public APIs: `/api/public/vpn` (IPSec tunnel status), `/api/public/connections` (connection map)
- New display settings: bandwidth graphs, VPN tunnels, connection map
- Interface selection now grouped by type (Physical, VLAN, IPSec, VXLAN, Tunnel, etc.)
- Connection map shows animated links between devices (read-only, no private details)

### Admin
- Settings page now allows enabling/disabling individual public dashboard modules
- Multi-select dropdowns to pick specific interfaces and VPN tunnels per module
- Bandwidth graphs show RX/TX as percentage of interface speed

## [0.10.79] - 2026-03-04

### Fixed
- Fix sFlow "Top Conversations" showing ALL device traffic instead of connection-specific VPN traffic
- Primary filtering now uses VPN subnet pairs (local_subnet/remote_subnet → SQL LIKE patterns) instead of unreliable interface index matching
- Improved fallback: include Phase1Names in interface name matching when subnets unavailable
- Removed overly broad Strategy 2 that grabbed all tunnel-type interfaces from both devices

## [0.10.78] - 2026-03-04

### Fixed
- Fix 500 on VPN chart queries — raw SQL used `vpn_statuses` but actual table name is `vpn_status`

## [0.10.77] - 2026-03-04

### Fixed
- Fix LAG() delta queries: use manual SQL placeholders for IN clauses (GORM Raw doesn't reliably expand slices in subqueries)
- Fix first-row delta bug: LAG() returning NULL on first row was falling through to ELSE branch returning raw cumulative counter instead of NULL — now explicitly returns NULL so first row is properly filtered
- Add error logging to traffic and VPN chart handlers for debugging 500s

## [0.10.76] - 2026-03-04

### Fixed
- Fix CSP violation blocking Chart.js — add `'unsafe-inline'` to script-src directive
- Add inline SVG favicon to prevent 404 on `/favicon.ico`

## [0.10.75] - 2026-03-04

### Added
- Syslog-driven alerts: critical syslog messages (severity 0-2) now auto-generate alerts with notifications
- Recovery/resolved notifications for all alert types: CPU, memory, disk, sessions, VPN tunnels, interfaces, and device offline
- Interface error/discard alerting: detects new errors between poll cycles and fires warning alerts
- API endpoints for security stats, SD-WAN health, and HA status per device (`GET /api/devices/:id/security-stats`, `/sdwan-health`, `/ha-status`)
- Dashboard enrichment includes HA mode/member count and SD-WAN alive/total per device
- Database query functions: `GetLatestSecurityStats`, `GetSecurityStatsHistory`, `GetLatestSDWANHealth`, `GetLatestHAStatus`
- Cross-fill VPN tunnel uptime from paired tunnels in connection detail (same pattern as subnet backfill)

### Fixed
- Fix 500 error on connection traffic chart — GORM `IN ?` placeholder was double-parenthesized in raw SQL
- Fix CSP `script-src` to allow Chart.js internal eval (`'unsafe-eval'`)

## [0.10.74] - 2026-03-04

### Fixed
- Fix VPN traffic charts showing meaningless cumulative counter sums — now uses LAG() window function to compute actual per-interval byte/packet deltas from SNMP counters
- Fix per-tunnel chart data (GetVPNChartData) using AVG of cumulative counters — same LAG() delta fix
- Fix throughput gauges showing wrong values with no real units — now displays server-computed Mbps with % of 1 Gbps capacity
- Tighten sFlow filtering in connection detail to only show flows matching this connection's specific tunnels, not all tunnels from both devices

### Added
- Server-side throughput computation (bytes/sec) in connection detail API from latest VPN status samples

## [0.10.73] - 2026-03-04

### Fixed
- Fix doubled total bytes/packets in connection detail — was summing both source and dest tunnels but they represent the same traffic from opposite perspectives

## [0.10.72] - 2026-03-04

### Fixed
- Cross-fill empty Phase 2 subnets from paired tunnel in connection detail — hub-side ADVPN tunnels (e.g. NUDAY_LAN) now show local/remote subnet inferred from the spoke side's data

## [0.10.71] - 2026-03-04

### Fixed
- Fix connection detail page showing empty dest tunnels for NAT'd hub-spoke VPNs (tunnel_indirect/wan_inferred matches)
  - Infers source device WAN IPs from dest tunnel remote IPs for indirectly matched connections
  - Example: NUDAY-FW's `dialup-76.64.79.217` tunnel now correctly appears as dest tunnel for DC2-FW1 ↔ NUDAY-FW
- Fix overlay detector assigning wrong connection type ("ipsec") to vxlan-named interfaces with empty/non-overlay TypeName
  - Interfaces accepted by name prefix (e.g., vxlan500) now get effective type "vxlan" if their SNMP TypeName isn't an overlay type

## [0.10.70] - 2026-03-04

### Fixed
- Fix SQLite "readonly database" error caused by non-root container user unable to write to bind-mounted data volume
- Entrypoint now starts as root, fixes `/data` and `/config` ownership, then drops to `fwmon` user via `su-exec`
- Removed `USER fwmon` from Dockerfile — privilege drop happens at runtime in entrypoint instead

## [0.10.69] - 2026-03-04

### Fixed
- Add server-side error logging for all probe data ingestion handlers (security stats, flow samples, interface stats, VPN statuses, etc.) — previously DB errors returned 500 without logging the cause

## [0.10.68] - 2026-03-03

### Added
- Physical (Ethernet/LAG) connection auto-detection via shared IP subnet matching
  - Detects same-site devices with Ethernet (ifType 6) or LAG (ifType 161) interfaces on the same subnet
  - Skips /30, /31, /32 point-to-point WAN links — only matches LAN segments
  - Accumulates interface names per device pair (e.g., "port1, port2")
  - Uses `subnet_match` discovery method badge
- `ethernet` connection type styling in all frontend style maps (gray #6e7681, solid, width 2)
- `subnet_match` discovery badge in connection tables and network diagram

## [0.10.67] - 2026-03-03

### Fixed
- L2VLAN connections now accumulate ALL matching interface names (was stopping after first match)
- buildCIDR now preserves wildcard subnets (0.0.0.0/0) for Phase 2 selectors
- Connection detail panel now shows dest tunnels for NAT'd VPN scenarios via WAN IP cross-referencing

### Added
- WAN IP inference phase in VPN auto-detection — catches NAT'd hub-spoke tunnels (e.g., dialup-x.x.x.x)
- Site grouping in connection diagram — dashed rounded rectangles around same-site device clusters
- Straight lines for same-site connections with parallel offsets for multiple connections
- Tunnels column in connections table with count badge and abbreviated names
- Multi-line tunnel list in connection detail panel
- Discovery badges for `wan_inferred` and `overlay_name` match methods

## [0.10.66] - 2026-03-03

### Security
- **Remove CSP `unsafe-inline` for scripts**: Removed `'unsafe-inline'` from CSP `script-src` directive, hardening XSS protection. All scripts are now external with `defer`.

### Refactor
- **Extract all inline JS to external files**: Created 10 new external JS files, eliminating every inline `<script>` block across 9 HTML pages:
  - `admin-common.js` — shared utilities (escapeHtml, apiFetch, CSRF, delegateEvent)
  - `admin-login.js`, `public-dashboard.js` (standalone pages)
  - `admin-sites.js`, `admin-probe-pending.js`, `admin-probes.js`, `admin-network.js` (admin pages)
  - `admin-connection-detail.js`, `admin-device-detail.js`, `admin-main.js` (detail/dashboard pages)
- **Convert ~114 inline event handlers to data-action delegation**: Replaced every `onclick`, `onchange`, `onsubmit` across all HTML files and dynamically-generated JS strings with `data-action` + `data-*` attributes.
- **Update diagram JS files**: Converted ~30 inline handlers in `diagram-panels.js`, 4 in `diagram-core.js`, and 1 in `diagram-tunnel-zoom.js` to data-action delegation.

## [0.10.65] - 2026-03-03

### Security (P1 — High)
- **H3: SNMP credentials encrypted at rest**: Added AES-256-GCM encryption for `SNMPCommunity`, `SNMPV3AuthPass`, and `SNMPV3PrivPass` in the database. Encryption key is derived from `JWT_SECRET_KEY` via SHA-256. Existing plaintext values are automatically migrated on startup. Encrypted values use a `{enc}` prefix for backward-compatible detection.
- **H4: Remove insecure SNMP defaults**: Removed `default:public` from SNMP community GORM tags. `TestDeviceConnection` now requires an explicit community string for SNMPv1/v2c instead of defaulting to "public". SNMP trap community default changed from "public" to empty string.
- **H7: Cookie Secure flag auto-detection**: `COOKIE_SECURE` now defaults to match `SERVER_ENABLE_TLS` instead of always defaulting to `false`. When TLS is enabled, cookies are automatically marked Secure without explicit configuration.
- **H10: SNMP error detail redaction**: `TestDeviceConnection` now returns generic error messages ("unable to reach device", "device did not respond to SNMP query") instead of leaking internal SNMP error details. Detailed errors are still logged server-side.

## [0.10.64] - 2026-03-03

### Security (P2 — Medium)
- **M2+M3: JWT token revocation**: Added `token_version` field to Admin model and JWT claims. Tokens are now server-side invalidated on password change and logout by incrementing the version counter. `ValidateToken` checks the current version against the database, rejecting stale tokens immediately rather than waiting for expiry.
- **M4: Docker non-root user**: Dockerfile now creates a dedicated `fwmon` user/group and runs the container as non-root via `USER fwmon`, reducing the blast radius of container escapes.
- **M5: Remove Docker host networking**: Replaced `network_mode: "host"` in docker-compose.yml with explicit port mappings (8080, 162/udp, 514/tcp+udp, 6343/udp, 8089), providing network isolation between the container and host.
- **M6: Go version bump**: Updated Go directive from 1.21 to 1.22 in both `go.mod` and Dockerfile builder stage. Operators should run `go get -u ./... && go mod tidy` to refresh dependencies.
- **M7: Syslog source IP allowlist**: Both TCP and UDP syslog receivers now support an `AllowedSourceIPs` config field (`SYSLOG_ALLOWED_SOURCES` env var, comma-separated). When set, packets/connections from non-listed IPs are silently dropped.
- **M8: sFlow source IP allowlist**: sFlow receiver now supports an allowed source IP list (`SFLOW_ALLOWED_SOURCES` env var, comma-separated). When set, datagrams from non-listed IPs are silently dropped.

## [0.10.63] - 2026-03-03

### Security (P3 — Low)
- **L1: CSRF fix in connection-detail.html**: Added CSRF token fetching and `X-CSRF-Token` header to all API requests including logout. Upgraded `apiFetch` to match the pattern used in other admin pages.
- **L2: CSRF token parsing fix in device-detail.html**: Changed `d.data?.token` to `d.csrf_token` to match the actual API response format from `/admin/api/csrf-token`.
- **L3: Tightened CSP directives**: Added `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, and `frame-ancestors 'none'` to Content-Security-Policy header. `unsafe-inline` for scripts/styles remains necessary due to inline usage across all admin pages.
- **L4: Per-IP account lockout**: Login lockout is now tracked per `username:IP` composite key instead of per-username only, preventing remote attackers from locking out the admin account from a different IP.
- **L5: config.env in .gitignore**: Added `config.env` to `.gitignore` to prevent accidental commit of production secrets.
- **L6: Text field length validation**: Added maximum length checks on all string fields in CreateDevice, UpdateDevice, CreateSite, and UpdateSite handlers (name: 255, description: 1000, address: 500, etc.).
- **L7: Mass assignment prevention**: `CreateDevice` now zeroes `ID`, `CreatedAt`, `UpdatedAt`, `LastPolled` before insert. `CreateSite` now zeroes `ID` before insert.
- **L8: Rate limiter dead code cleanup**: Removed unused `stop` channel from `ipRateLimiter` struct; simplified cleanup goroutine to use `for range ticker.C`.
- **L9: Composite DB indexes**: Added `(device_id, timestamp)` composite indexes to `PingResult`, `SyslogMessage`, and `FlowSample` models. Added `(device_id, probe_id, target_ip)` composite index to `PingStats` for efficient lookups.

## [0.10.62] - 2026-03-03

### Security (P2 — Medium)
- **SameSite cookie from config**: Login/logout cookies now use the `COOKIE_SAMESITE` env var (default `Strict`) instead of hardcoded `Lax`, strengthening CSRF protection.
- **SMTP SSRF prevention**: `TestEmail` now validates the SMTP host against loopback, private, and link-local addresses before connecting, preventing server-side request forgery to internal services.
- **Private IP SSRF block**: `isValidExternalIP` now rejects RFC 1918 / RFC 4193 private IP ranges (10.x, 172.16-31.x, 192.168.x, fc00::/7) in addition to loopback and link-local, closing the DNS rebinding SSRF bypass.
- **Device ownership validation**: All 14 probe data-ingestion handlers now verify submitted `device_id` values against the probe's assigned device list, preventing a compromised probe from injecting data into unrelated devices. Unauthorized records are silently filtered before database writes.
- **Site circular reference detection**: `UpdateSite` now walks up the parent chain (max depth 50) to detect circular parent references, preventing infinite loops in site hierarchy.
- **TCP syslog WaitGroup**: `SyslogReceiver.Stop()` now waits for all active TCP connections to finish via `sync.WaitGroup`, ensuring clean shutdown without orphaned goroutines.

### Fixed (Collector)
- **Relay batch re-queue**: Failed data batches (traps, pings, syslog, flows) are now re-queued for the next sync cycle instead of being silently dropped after 3 retries, improving data delivery reliability.

## [0.10.61] - 2026-03-03

### Security (P0 — Critical)
- **Probe endpoint authentication**: All 14 probe data-ingestion endpoints (`/api/probes/:id/syslog`, `/traps`, `/flows`, etc.), the heartbeat endpoint, and the device-list endpoint now require `Authorization: Bearer <registration_key>` — previously these were completely unauthenticated, allowing anyone who guessed a probe ID to inject fake monitoring data or read SNMP credentials. The collector already sends this header, so no collector changes are needed.
- **Probe heartbeat validation**: `ProbeHeartbeat` now authenticates the caller by Bearer token, validates probe_id matches the authenticated probe, and restricts status to `online`/`offline`/`degraded`.
- **Mass assignment prevention in CreateProbe**: Forces `ApprovalStatus = "pending"`, `ID = 0`, and clears all server-controlled fields before database insert — previously an attacker could POST `{"approval_status":"approved"}` to bypass the admin approval workflow.

### Security (P1 — High)
- **Hardcoded credentials removed**: Removed `changeme123!` default password from `entrypoint.sh`; cleared `JWT_SECRET_KEY`, `ADMIN_SECRET_KEY`, and `ADMIN_PASSWORD` values from `config.env.example`. Dockerfile now copies the example file as `config.env.example` (not `config.env`), so auto-generated secrets are used by default.
- **TLS minimum version enforced**: Added `MinVersion: tls.VersionTLS12` to TLS configs in syslog receiver and relay client — previously TLS 1.0 (vulnerable to BEAST/POODLE) was accepted.
- **Data race fix (AlertManager/Notifier)**: `Notifier.SendAlert()` now receives a `NotifyConfig` value snapshot taken under the AlertManager's lock, instead of reading shared `config.Alerts.*` fields without synchronization. Eliminates a race between `RefreshThresholds()` writes and notification reads.
- **LIKE wildcard injection fix**: Syslog search now escapes `%` and `_` metacharacters before constructing LIKE patterns, preventing query manipulation and DoS via expensive full-table scans.

## [0.10.60] - 2026-03-03

### Fixed
- **CSP data: URI images**: Added `img-src 'self' data:` to Content-Security-Policy so Chart.js inline data-URI images are not blocked
- **Panel traffic chart crash**: All `window.apiFetch()` calls in `diagram-panels.js` and `diagram-tunnel-zoom.js` now unwrap the `{success, data}` response envelope — fixes `data.map is not a function` errors on traffic, detail, flows, and tunnel chart panels

## [0.10.59] - 2026-03-03

### Fixed
- **CSP source map block**: Added `connect-src 'self' https://cdn.jsdelivr.net` to Content-Security-Policy header so Chart.js can fetch its `.js.map` source map without being blocked by the `default-src 'self'` fallback

## [0.10.58] - 2026-03-03

### Fixed
- **Static JS 404 fix**: Embedded `static/js/` diagram modules into the Go binary via `go:embed`, eliminating 404 errors when running from Docker or from a different working directory. Moved JS files from `static/js/` to `cmd/api/static/js/` so they are included by the existing `COPY cmd ./cmd` in the Dockerfile.

## [0.10.57] - 2026-03-03

### Added
- **Modular diagram library**: Extracted ~900 lines of connection diagram JavaScript from admin.html into 6 library files under `static/js/`: `diagram-core.js` (SVG setup, zoom/pan), `diagram-layout.js` (circular layout, drag-and-drop), `diagram-connections.js` (path rendering, UP-only filter), `diagram-particles.js` (traffic-proportional rAF animation), `diagram-panels.js` (rich detail panels), `diagram-tunnel-zoom.js` (per-tunnel SVG overlay)
- **Scroll-wheel zoom**: Zoom into diagram around cursor point (0.3x–3x range), +/- buttons and 1:1 reset in top-right overlay
- **Ctrl+drag pan**: Pan the diagram viewport with Ctrl+click-drag
- **Drag-and-drop device nodes**: Drag devices to rearrange the diagram; positions persist in localStorage. "Reset Layout" button restores circular default
- **UP-only connection lines**: Only connections with `status === 'up'` are drawn as paths, decluttering the diagram for NOC operators. DOWN tunnels remain visible via VPN badge counts and detail panels
- **Outward same-site arcs**: Direct connections between same-site devices bulge away from center, clearly bypassing the cloud node
- **Cross-site angular fan spread**: Cross-site paths fan across a 60-degree arc through unique cloud transit points, providing 15–30px minimum separation between paths
- **Traffic-proportional particles**: Particle count (1–6) and speed scale with `log10(bytesIn + bytesOut)` using `requestAnimationFrame` + `getPointAtLength()` instead of `<animateMotion>` elements
- **Tunnel zoom overlay**: "Zoom In" button in connection detail panel opens an SVG overlay with source/dest nodes and each tunnel drawn as a separate labeled horizontal path with UP animation and DOWN dashed gray. Click any tunnel for details tooltip
- **VPN map bytes**: `bytes_in`/`bytes_out` fields added to `/api/connections/vpn-map` tunnelInfo response

### Changed
- admin.html reduced from 2,980 to ~2,115 lines (net -865 lines) via modular library extraction
- Panel onclick handlers now route through `FWDiagram.Panels` namespace with global bridge functions for inline HTML compatibility

## [0.10.56] - 2026-03-03

### Added
- **Cross-site VPN routing**: Connections between devices in different sites now route through the Internet cloud node with two-segment bezier paths (Source→Cloud + Cloud→Dest), each with unique offsets to avoid overlap. Same-site connections remain direct curves.
- **Rich connection detail panel**: Clicking any connection line opens a full diagnostic panel inline with bridge SVG animation, KPI cards (bytes in/out, tunnel count, status), and four tabs: Overview (traffic chart with 1h/24h/7d/30d range pills), Tunnels (two-column expandable table with per-tunnel bandwidth charts), Phase 2 (IPSec selector match SVG diagrams), and Flows (protocol doughnut, traffic timeline, top sources/destinations bar charts, conversations table)
- **Rich VPN badge panel**: Clicking a device VPN badge shows tunnels grouped into Matched (linked to known devices) and Off-Net sections, each with expandable rows containing inline Chart.js bandwidth charts with range pills
- **Chart lifecycle management**: All panel charts tracked in `panelChartInstances` with proper cleanup on panel open/close/switch to prevent memory leaks
- **Cloud node scaling**: Cloud node width now scales based on the number of cross-site connections and off-net tunnels

### Changed
- Off-net tunnel dashed lines now use `2,4,8,4` dot-dash pattern to visually distinguish from cross-site connection paths
- Old `showConnDetailPanel` and `showVPNDetailPanel` replaced entirely by rich panel versions
- Diagram re-render preserves open panel when `currentPanelConnId` is set

## [0.10.55] - 2026-03-03

### Added
- New API endpoint `GET /api/connections/vpn-map` returning per-device VPN tunnel summaries with remote IP matching
- VPN badge on each device node in connection map showing up/total tunnel counts (green/amber/red)
- Internet cloud node at center of connection map when any device has off-net (unmatched) VPN tunnels
- Dashed green/gray lines from devices to cloud node for off-net tunnel visualization with particle animation
- VPN detail panel (table) opened by clicking device VPN badge — shows tunnel name, type, status, remote IP, destination, and uptime
- Off-net filter mode when clicking cloud connection lines to show only unmatched tunnels

## [0.10.54] - 2026-03-03

### Fixed
- **False tunnel connections from name-matching**: Renamed `detectTunnelConnections` → `detectOverlayConnections` and restricted it to only L2VLAN, L3IPVLAN, and VXLAN types. Tunnel/IPSec/GRE connections are now handled exclusively by `detectVPNConnections` which uses actual VPN tunnel data (IPs, status) rather than error-prone interface name matching. This eliminates false connections from generic names like "Remote Access" appearing on unrelated devices.
- **Down tunnels indistinguishable from up tunnels on network map**: DOWN connections in `network.html` now render with dimmed gray (#484f58) stroke at 50% opacity instead of full type color. In `admin.html`, DOWN connection paths also use dimmed gray instead of the type color (opacity pulse animation was already correct).

## [0.10.53] - 2026-03-03

### Added
- **Indirect VPN detection for NAT'd tunnels**: When VPN tunnel remote IPs don't match any known device (common with NAT'd IPSec), the poller now tries matching the VPN tunnel name against device names (e.g., tunnel "NUDAY_LAN" on DC2-FW1 matches device "NUDAY-FW"). Creates connections with match method `tunnel_indirect`.
- **Database-backed `hasDirectLink` fallback**: The overlay validation check now also queries the database for existing tunnel/ipsec connections, not just in-memory VPN status data. This allows overlays (l3ipvlan/vxlan) to be detected once the underlying IPSec tunnel is established by any method (IP match, tunnel_indirect, or manual).

## [0.10.52] - 2026-03-03

### Fixed
- **Tunnel connections (HUB↔SPOKES) not detected**: v0.10.51 was too aggressive — requiring `hasDirectLink()` for ALL non-l2vlan types blocked legitimate tunnel detection since tunnel/ipsec/gre interfaces ARE the tunnels themselves. Restored three-category validation: l2vlan requires sameSite, overlays (l3ipvlan/vxlan) require hasDirectLink, tunnels (ipsec/gre/tunnel) use name-match only. The `isSystemIface` filter (*.root/*.vdom) already prevents false matches from system interfaces.

## [0.10.51] - 2026-03-03

### Fixed
- **False triangle from FortiGate system interfaces (naf.root, l2t.root, ssl.root)**: Added pattern-based `isSystemIface` filter that skips all `*.root` and `*.vdom` suffixed interfaces — these are generic system interfaces present on every FortiGate and created false connections between all devices
- **Unified validation for all non-local types**: All connection types except l2vlan now require `hasDirectLink()` (a verified VPN tunnel between endpoints). Previously only overlay types (l3ipvlan/vxlan) required this check, allowing generic "tunnel" type interfaces like `naf.root` to bypass validation
- **Expanded startup cleanup**: Added `naf.root` and `l2t.root` to the list of stale connection names cleaned up on poller startup

## [0.10.50] - 2026-03-03

### Fixed
- **False triangle connections between all firewalls**: Overlay types (l3ipvlan, vxlan) now require a direct VPN tunnel link (`hasDirectLink`) between the device pair. Previously, devices sharing a VLAN name got l3ipvlan connections even without a tunnel between them (e.g., FW1↔FW3 got a false l3ipvlan when only FW1↔FW2 had an IPSec tunnel). Now: l2vlan requires same-site, l3ipvlan/vxlan requires a direct tunnel, preventing false cross-site overlay connections.

## [0.10.49] - 2026-03-03

### Fixed
- **Stale cleanup deleting VPN connections**: The `CleanupStaleAutoConnectionsBefore` call was inside `detectTunnelConnections` with a `cycleStart` timestamp set AFTER `detectVPNConnections` had already run — causing it to delete the VPN-detected connections every cycle. Moved the cycle timestamp and cleanup to the parent `pollAllDevices` function so both detectors' connections survive.

## [0.10.48] - 2026-03-03

### Improved
- **Robust connection auto-detection overhaul**:
  - **Name normalization**: Interface names are stripped of separators (spaces, dots, dashes, underscores) before matching — `vlan500`, `vlan 500`, `vlan.500`, `vlan-500`, `VLAN_500` all match correctly
  - **Per-pair type determination**: Connection type is now determined from each pair's own interface types instead of the whole group, so FW2↔FW3 (both l2vlan) get "l2vlan" while FW1↔FW2 (l3ipvlan + l2vlan) get "l3ipvlan"
  - **Multi-type per pair**: Database upsert key changed from device-pair to device-pair+type, allowing the same pair to have both an ipsec AND l2vlan connection
  - **Stale cleanup**: Auto-detected connections not refreshed in the current poll cycle are automatically deleted — connections disappear when interfaces are removed
  - **Same-site scoping**: L2VLAN connections only created between devices assigned to the same site

## [0.10.47] - 2026-03-03

### Fixed
- **L2VLAN auto-detection scoped to same-site devices**: L2VLAN connections are now only auto-detected between devices assigned to the same site. Devices at different sites sharing a VLAN name are skipped, preventing false cross-site L2 connections. L3IPVLAN and other tunnel types remain unrestricted.

## [0.10.46] - 2026-03-02

### Fixed
- **Remove L2VLAN from tunnel auto-detection**: L2VLAN is a local segment, not a tunnel — auto-detecting it by interface name created false connections between devices that share a VLAN name but aren't on the same physical segment. L3IPVLAN (overlay extending L2 through IPSec/GRE) remains auto-detected.

## [0.10.45] - 2026-03-02

### Added
- **Network type-aware connection visualization**: Connection map now renders distinct colors, dash patterns, and line widths for each network layer type (IPSec, SSL VPN, VXLAN, L2VLAN, L3IPVLAN, GRE, LAG, Tunnel, WAN)
- **Poller auto-detection for L2VLAN/L3IPVLAN**: `detectTunnelConnections` now recognizes `l2vlan` and `l3ipvlan` interface types with priority-based type determination (l3ipvlan > vxlan > l2vlan > gre > ipsec > tunnel)
- **Connection type legend/filter expansion**: All connection type dropdowns and legends across network.html, admin.html, and connection-detail.html include the new types
- **Type-specific bridge rendering**: Connection detail page bridge SVG uses per-type colors, dash patterns, and particle colors instead of hardcoded vxlan/default logic

## [0.10.44] - 2026-03-02

### Fixed
- **Auto-cleanup stale `ssl.root` connections**: Poller now deletes auto-detected connections with generic tunnel names (`ssl.root`, `ssl.vdom`) on startup via `CleanupStaleAutoConnections()`

## [0.10.43] - 2026-03-02

### Fixed
- **Browser autofill ignoring `autocomplete="off"`**: Replaced all `autocomplete="off"` with `autocomplete="one-time-code"` across all HTML pages — Chrome/Edge ignore `off` but respect `one-time-code`, preventing email/credential autofill into IP address, search, and name fields

## [0.10.42] - 2026-03-02

### Fixed
- **False tunnel connections from `ssl.root`**: Added FortiGate default SSL VPN interfaces (`ssl.root`, `ssl.vdom`) to the tunnel auto-detection skip list — these exist on every FortiGate and were causing spurious pairwise connections between all devices

## [0.10.41] - 2026-03-02

### Added
- **Indirect tunnel connection detection**: `detectTunnelConnections` now cross-checks name-matched device pairs against VPN tunnel remote IPs; pairs with no direct IP evidence are marked as "tunnel_indirect" instead of "tunnel_name"
- **Indirect connection rendering**: Indirect connections show as amber/orange dotted lines (#f0883e) with slower, smaller amber particles — visually distinct from direct connections (green) and VXLAN (purple)
- **"Indirect" match method badge**: Orange badge displayed across admin, network, and connection detail pages for tunnel-name-only connections without direct IP verification
- **Phase 2 selector inverse matching**: `GetConnectionDetail` now matches Phase 2 selectors between connected devices — if source's `local_subnet` equals destination's `remote_subnet` (and vice versa), a `Phase2Match` is created confirming end-to-end IPSec SA alignment
- **Phase 2 Selectors tab**: New tab on the connection detail page showing matched Phase 2 pairs with animated SVG diagrams — green particles flow between matching subnets when both tunnels are up, with bidirectional TX/RX animation
- **`Phase2Match` struct**: Backend data structure for matched Phase 2 selector pairs (source/dest tunnel names, Phase 1 names, local/remote subnets, status)

### Fixed
- **False VXLAN connections**: Previously, two devices with the same VXLAN interface name (e.g., "vxlan1") were auto-connected even if they communicated through an intermediate hub device; now correctly detected as indirect

## [0.10.40] - 2026-03-02

### Added
- **IPSec Phase 2 selector support**: VPNStatus model now includes `phase1_name`, `local_subnet`, `remote_subnet`, and `tunnel_uptime` fields collected via FortiGate SNMP OIDs (.2, .5-.8, .21)
- **Phase 2 subnet display**: Connection detail and device detail VPN tables now show Phase 1 name, Phase 2 name, local/remote subnets in CIDR notation, and tunnel uptime
- **Bidirectional traffic animation**: SVG connection diagram and connection detail bridge now show particles flowing both directions — TX (connection color, source→dest) and RX (blue, dest→source)
- **Expanded tunnel auto-detection**: Renamed `detectVXLANConnections` → `detectTunnelConnections` to support IPSec, GRE, L2TP, WireGuard, and hub/spoke topologies — creates pairwise connections for multi-device tunnel groups
- **Tunnel Name match method badge**: Auto-detected tunnel connections display "Tunnel Name" discovery badge in orange across admin, network, and connection detail pages
- **`buildCIDR()` helper**: Combines IP address and subnet mask from SNMP into CIDR notation (e.g., "10.0.0.0/24")

### Fixed
- **sFlow tunnel interface matching**: Broadened matching strategy with three fallback layers — name/description/alias match, VPN-type interface match, and tunnel remote IP fallback — so "no traffic samples match" message is far less likely when sFlow is enabled
- **Broken build**: Fixed dangling call to removed `detectVXLANConnections` function (renamed to `detectTunnelConnections`)

## [0.10.39] - 2026-03-02

### Fixed
- **Connection detail page showing zero data**: Fixed broken GORM `Group("ip_address")` query on InterfaceAddress table that returned empty results; replaced with `Distinct().Pluck()` for correct IP collection
- **Tunnel matching fallback**: Connection detail and traffic queries now also match tunnels by name from the auto-discovered `TunnelNames` field, not just by IP address
- **Browser autofill populating search fields**: Added `autocomplete="off"` to all text inputs across admin.html, network.html, probes.html, sites.html, and dynamic settings forms to prevent browser from filling search/form fields with saved login credentials
- **Server-side sFlow device resolution**: Flow samples arriving with `device_id=0` are now resolved server-side by matching `sampler_address` against device management IPs and interface addresses

### Added
- **sFlow per-device filtering**: Device dropdown filter on the Flows page filters both the flow samples table and all stats charts (protocol distribution, top talkers, bytes over time) by selected device
- **`GetFlowStats` device filter**: Flow stats aggregation query now accepts optional `device_id` parameter (`?device_id=X`)
- **`ResolveDeviceByIP()` database function**: Resolves IP address to device ID by checking management IP and interface addresses table
- **`collectDeviceIPs()` helper**: Centralized function for collecting all known IPs for a device (management + interface addresses)

## [0.10.38] - 2026-03-02

### Added
- **NOC-style animated SVG connection diagram**: Replaced CSS DIV-based connection map with full SVG canvas featuring bezier curves, glow filters, device status indicators, and click-to-detail panels
- **Animated traffic particles**: "Up" connections show flowing particle animations along paths using SVG `animateMotion`; down connections pulse red
- **VXLAN visual distinction**: VXLAN connections render in purple with dashed stroke pattern
- **Connection detail page** (`/admin/connections/:id`): Full standalone page with animated bridge header, aggregate bandwidth charts, live throughput gauges, tunnel tabs, and sFlow traffic analysis
- **Per-tunnel bandwidth charts**: Expandable tunnel rows with lazy-loaded Chart.js charts and time range selectors (1h/24h/7d/30d)
- **sFlow traffic analysis tab**: Protocol distribution doughnut, top sources/destinations horizontal bars, top conversations table, bytes-over-time chart — conditionally shown when sFlow data exists
- **VPN chart data API** (`GET /admin/api/devices/:id/vpn/:tunnel/chart`): Time-bucketed VPN tunnel bandwidth data
- **Connection detail API** (`GET /admin/api/connections/:id/detail`): Full connection info with matching source/dest tunnels, aggregate stats, and sFlow availability flag
- **Connection traffic API** (`GET /admin/api/connections/:id/traffic`): Aggregate bandwidth chart data across all matching tunnels
- **Connection flows API** (`GET /admin/api/connections/:id/flows`): sFlow traffic analysis filtered to connection tunnel interfaces with protocol breakdown, top talkers, conversations, and time series
- **View Details links**: Added connection detail navigation from connections table, SVG diagram click panel, and network page detail sidebar

## [0.10.37] - 2026-03-02

### Added
- **Enhanced VPN auto-discovery via interface IP collection**: Walks standard IP-MIB `ipAddrTable` on every device to collect all interface IP addresses, enabling VPN connection matching even when a device's WAN IP differs from its configured management/SNMP IP
- **New `InterfaceAddress` model**: Stores per-device interface IPs with ifIndex, IP address, and netmask; auto-migrated, cleaned up with other time-series data
- **Bidirectional VPN detection**: When both sides of a VPN pair have tunnels pointing at each other, the connection is upgraded to "bidirectional" match method for higher confidence
- **VXLAN connection auto-discovery**: New `detectVXLANConnections()` finds VXLAN/tunnel interfaces with matching names across exactly 2 devices and creates auto-detected connections with type "vxlan"
- **`MatchMethod` field on `DeviceConnection`**: Tracks how each connection was discovered — `ip_match` (management IP), `interface_ip` (WAN/interface IP), `bidirectional` (both sides confirmed), `vxlan_name` (matching interface names), or `manual`
- **Connection type inference from VPN tunnel type**: IPSec tunnels set `connection_type = "ipsec"`, SSL-VPN tunnels set `connection_type = "ssl"`
- **Discovery column in connections UI**: Both admin.html and network.html connections tables show color-coded badges for match method (gray=IP Match, blue=WAN IP, green=Bidirectional, purple=VXLAN)
- **VXLAN visual differentiation**: VXLAN connections render purple in admin.html diagram and with dashed purple lines in network.html SVG map
- **Connection detail tooltips**: Admin diagram tooltips and network.html detail panel now show discovery method and tunnel names
- **Probe endpoint**: `POST /api/probes/:id/interface-addresses` for remote probe interface address ingestion
- **Database methods**: `SaveInterfaceAddresses`, `GetLatestInterfaceAddresses`, `GetAllLatestInterfaces`

### Changed
- `UpsertAutoConnection()` now accepts `connType` and `matchMethod` parameters instead of hardcoding `"ipsec"`, enabling proper type/method tracking for all auto-detected connections

## [0.10.36] - 2026-03-02

### Added
- **Device detail UI**: 4 new data tabs — HA Cluster, Security, SD-WAN, Licenses
  - **HA Cluster tab**: Shows cluster mode, member table with serial, hostname, CPU/memory %, network usage, sessions, sync status, and primary/secondary role
  - **Security tab**: Stat-grid layout for AV (detected/blocked, HTTP/SMTP), IPS (detected/blocked + severity breakdown), and WebFilter (HTTP/HTTPS/URL blocked)
  - **SD-WAN tab**: Per-link table with name, interface, state badges (alive/dead), latency, packet loss, sent/received counters
  - **Licenses tab**: Description and expiry date with color-coded expiry (expired=red, <30d=yellow, ok=green)
- **VPN tab**: Added "Type" column with color-coded badges for `ipsec` (blue), `ipsec-dialup` (yellow), `sslvpn` (green)
- **Extended system status cards**: Conditionally shows Session Rate (1m/10m/30m/60m), IPv6 Sessions, SSL-VPN (users/tunnels), AV Signature version, IPS Signature version when data is present
- **API**: `GetDeviceDetail()` now returns `ha_status`, `security_stats`, `sdwan_health`, `license_info` alongside existing data

## [0.10.35] - 2026-03-02

### Added
- **Comprehensive FortiGate SNMP monitoring expansion** across 6 areas:
  - **Extended SystemStatus**: Session setup rates (1/10/30/60 min averages), IPv6 session count, low memory utilization, AV/IPS signature versions, SSL-VPN aggregate user/tunnel counts
  - **SSL-VPN tunnels**: SSL-VPN client sessions now appear in VPN status with `tunnel_type: "sslvpn"` alongside IPSec tunnels (`ipsec`, `ipsec-dialup`)
  - **HA cluster monitoring**: Redesigned `HAStatus` model with per-member rows — CPU, memory, network, sessions, packets, bytes, sync status, master serial per HA member
  - **Security stats**: New `SecurityStats` model tracking AV detected/blocked (total, HTTP, SMTP), IPS detected/blocked by severity, and WebFilter HTTP/HTTPS/URL blocked counts
  - **SD-WAN health checks**: New `SDWANHealth` model with per-link name, interface, state (alive/dead), latency, packet loss, send/recv counters
  - **License/contract tracking**: New `LicenseInfo` model with contract description and expiry date
- `TunnelType` field on `VPNStatus` model to distinguish IPSec site-to-site, IPSec dialup, and SSL-VPN tunnels
- 4 new probe data ingestion endpoints: `POST /api/probes/:id/ha-status`, `/security-stats`, `/sdwan-health`, `/license-info`
- Database save methods: `SaveHAStatuses`, `SaveSecurityStats`, `SaveSDWANHealth`, `SaveLicenseInfo`
- Auto-migration for new tables: `security_stats`, `sdwan_health`, `license_info`

## [0.10.34] - 2026-03-02

### Added
- **Ping latency in Status History chart**: Device detail status history chart now includes ICMP latency (ms) as a 4th dataset on a secondary Y-axis, combining CPU/Memory/Disk percentages with ping response times in one view
- `GetPingResultHistory()` database method for time-series ping result queries

### Changed
- `GET /api/devices/:id/status-history` now returns `{ system_status: [...], ping_history: [...] }` instead of a flat array (breaking change for API consumers)

## [0.10.33] - 2026-03-02

### Fixed
- **Disk usage percentage calculation**: FortiGate `fgSysDiskUsage`/`fgSysDiskCapacity` OIDs return values in MB, not percentage — now correctly computes `usage/capacity * 100` instead of storing raw MB as percentage
- **SNMP PDU type guard**: Added `isValidPDU()` check to skip `NoSuchObject`/`NoSuchInstance`/`EndOfMibView` responses instead of silently treating unsupported OIDs as zero values

## [0.10.32] - 2026-03-02

### Fixed
- **Probe-assigned devices stay "online" forever**: Server poller now checks for stale probe-assigned devices each poll cycle and marks them "offline" if no data received for 3× the poll interval (minimum 5 minutes)

## [0.10.31] - 2026-03-02

### Added
- `POST /api/probes/:id/processor-stats` endpoint for receiving per-core processor stats from probes
- Probe-polled devices now display processor usage data (previously only worked for server-polled devices)

## [0.10.30] - 2026-03-02

### Added
- Diagnostic endpoint `/admin/api/dashboard/diag` showing per-device system_status row counts and latest values
- `status_rows` count in device enrichment API response for data availability visibility
- Enhanced logging in `ReceiveSystemStatuses` showing probe ID, saved count, and device IDs per batch
- Device table CPU/Memory/Sessions tooltips now show record count and last polled time

### Fixed
- Improved "No data" tooltip to include device_id for easier cross-referencing with collector logs

## [0.10.29] - 2026-03-02

### Fixed
- CPU/memory/session data showing "-" for devices with valid polling data due to `> 0` check filtering out 0% values
- Added `has_status` flag to device enrichment so frontend can distinguish "no data" from "0% CPU"
- Devices without polling data now show "No data" with diagnostic tooltip instead of ambiguous "-"
- Added `status_time` to enrichment for last-polled timestamp visibility on hover

## [0.10.28] - 2026-03-02

### Added
- Auto-detect IPsec VPN connections between devices by matching tunnel remote IPs to known device addresses
- New `AutoDetected` and `TunnelNames` fields on DeviceConnection model
- Database methods: `GetAllLatestVPNStatuses`, `FindConnectionByDevicePair`, `UpsertAutoConnection`
- Poller `detectVPNConnections()` runs after each poll cycle to upsert auto-detected connections
- Connections table: new "Tunnels" column, AUTO badge for auto-detected entries, "Auto-managed" label instead of delete button
- Network diagram: dashed lines for auto-detected connections, tunnel name tooltips on hover

## [0.10.27] - 2026-03-02

### Fixed
- **CPU/Disk detection on 2/3 firewalls**: Added required `.0` instance suffix to all 9 FortiGate scalar OIDs — SNMP GET responses include `.0` in PDU names, so switch cases in `ParseSystemStatus()` were never matching
- **Flows page loads empty**: Added `autocomplete="off"` to Src/Dst IP filter inputs to prevent browser autofill from injecting email addresses into query params

### Added
- **Hardware sensor collection in server poller**: Locally-polled devices (no probe assigned) now collect hardware sensor data via SNMP, matching what the collector/probe already does
- **Processor/SPU monitoring**: New `ProcessorStats` model and full pipeline — walks FortiGate `fgProcessorTable` to collect per-core CPU and NP/SPU ASIC usage; new Processors tab on device detail page with visual bar charts
- **VPN diagnostic logging**: Poller now logs "VPN: 0 tunnels" vs "VPN walk error" to help distinguish no-tunnels-configured from SNMP failures

### Changed
- **Data cleanup**: `CleanupOldData()` now also prunes old `processor_stats` and `hardware_sensors` records (>90 days)
- **Device deletion**: Cascade delete now includes `processor_stats` table

## [0.10.26] - 2026-03-02

### Added
- **Multi-vendor SNMP architecture**: New `VendorProfile` interface and registry (`internal/snmp/vendor.go`) enabling vendor-specific SNMP OID handling; FortiGate profile (`vendor_fortigate.go`) is the first implementation
- **Vendor field on devices**: `Device` model now has a `vendor` field (default: `fortigate`); existing devices are backfilled on startup; API validates vendor on create/update (fortigate, paloalto, cisco_asa, generic)
- **Vendor dropdown in admin UI**: Device add/edit modal now includes a vendor selector
- **Flow time range selector**: Flows page now has Today/1 Week/1 Month/1 Year buttons for stats and charts
- **Expanded protocol names**: Frontend and backend now recognize 22 protocols (added HOPOPT, IGMP, IPv4, EGP, IPv6, IPv6-Route, IPv6-Frag, ICMPv6, IPv6-NoNxt, IPv6-Opts, EIGRP, PIM, VRRP, SCTP, MPLS-in-IP)
- **More flow filter options**: Protocol dropdown now includes ICMPv6, GRE, ESP, OSPF

### Fixed
- **Dashboard syslog/trap counts**: Now uses `/api/syslog/stats` and `/api/traps/stats` for real totals instead of capped `?limit=10` array length
- **Top talkers chart unreadable**: Y-axis and tooltips now format bytes as human-readable (KB/MB/GB)
- **Disk gauge 0/0 confusion**: Device detail page shows "N/A" with dimmed gauge when device reports 0 usage and 0 total

### Removed
- **Recent Activity section**: Redundant dashboard section removed (syslog/traps pages provide better detail)

### Changed
- **SNMP refactoring**: FortiGate-specific OIDs moved from `snmp.go` to `vendor_fortigate.go`; `GetSystemStatus()`, `GetVPNStatus()`, `GetHardwareSensors()` now accept optional vendor parameter
- **Trap receiver**: Uses vendor profile registry to look up trap OIDs instead of hardcoded switch statements

## [0.10.25] - 2026-03-02

### Fixed
- **Interfaces nav item missing on standalone pages**: Added "Interfaces" link to sidebar navigation on probes, sites, network, and probe-pending pages
- **Alerts show DEV-{id} instead of device name**: `renderAlertsTable` now resolves device names from `currentDevices` cache via `getDeviceName()` helper
- **Debug console.log statements**: Removed all `console.log('[Sites]...')` (11 occurrences) and `console.log('[Pending]...')` (5 occurrences) from sites.html and probe-pending.html

## [0.10.24] - 2026-03-02

### Improved
- **Composite database indexes**: Added `(device_id, timestamp)` composite indexes to `system_status`, `vpn_status`, `hardware_sensors`, `trap_events`, and `alerts` tables for faster time-range queries; GORM AutoMigrate creates indexes on startup

## [0.10.23] - 2026-03-02

### Fixed
- **GetAllInterfaces pagination bug**: `ParsePagination` returns `(limit, offset)` but code treated them as `(page, pageSize)`; response now returns `limit`/`offset`/`total` instead of `page`/`page_size`
- **SSRF on TestWebhook**: User-supplied webhook URL now validated (scheme + hostname) via `isValidExternalIP` before making outbound HTTP request
- **SSRF on TestProbeConnection**: `ListenAddress` now validated via `isValidExternalIP` before `net.DialTimeout` to prevent internal port scanning
- **RegistrationKey leaked in probe responses**: `RedactProbe` now masks `RegistrationKey` with `********`
- **RedactDevice inconsistency**: SNMPv3 auth/priv passwords now masked with `********` instead of empty string
- **CSRF token values logged**: Middleware no longer logs full token values on mismatch, only lengths
- **Debug log statements in main.go**: Removed `DEBUG: Serving sites.html` and `DEBUG: Serving probe-pending.html` log lines
- **Poller full-row overwrite**: `updateDeviceStatus` now uses targeted `UpdateDeviceStatus(id, status, lastPolled)` instead of `db.Save(device)` which overwrote all columns
- **Dead VPN dashboard code**: Removed VPN summary block that wrote to `#trap-count` only to be immediately overwritten by trap count
- **CSRF token path mismatch in device-detail.html**: `loadStatusHistoryChart` no longer fetches/parses CSRF token redundantly for a GET request
- **Implicit `event` variable**: `testDeviceConnection` now receives `event` parameter explicitly; onclick passes `event`
- **TestEmail missing smtpFrom validation**: Now requires sender address in addition to host and recipient
- **Unbounded queries**: Added `Limit(2000)` to `GetSystemStatusHistory` and `Limit(100)` to device detail ping stats query

## [0.10.22] - 2026-03-02

### Added
- **Interface charts with downsampling**: Replaced tiny sparklines with full Chart.js charts (200px height) on device detail interface expand panel, with 24h/7d/30d/90d range selector buttons; backend uses AVG() aggregation with time-bucketed downsampling (per-minute, per-hour, per-day)
- **Admin "All Interfaces" page**: New cross-device interface overview at `/admin/interfaces` with device name column, device/status/type dropdown filters, and pagination; accessible from sidebar under Monitoring
- **Public multi-device support**: Device selector dropdown on public dashboard; new `/api/public/devices` endpoint returns enabled devices (id, name, status only); `GetPublicDashboard` and `GetPublicInterfaces` accept `?device_id=X` query param
- **SMTP settings in admin UI**: New SMTP Configuration card in Settings page with host, port, username, password, from address, and to address fields; settings stored in `system_settings` DB table
- **Email test button**: "Send Test Email" button in Settings sends a real SMTP test message using DB settings (falling back to env vars)
- **Webhook test buttons**: "Test Slack", "Test Discord", and "Test Webhook" buttons send test payloads to configured webhook URLs
- **Webhook URL field in settings**: Added `webhook_url` to notification settings UI (was previously env-var only)

### Improved
- **Composite database indexes**: Added `idx_iface_device_ts` on `(device_id, timestamp)` and `idx_iface_device_idx_ts` on `(device_id, index, timestamp)` to `interface_stats` table, eliminating full table scans for device detail and chart queries
- **Notification settings from DB**: `RefreshThresholds` in alerts.go now reads all notification keys (`email_enabled`, `smtp_*`, `slack_webhook`, `discord_webhook`, `webhook_url`) from DB, so admin UI changes take effect without server restart

## [0.10.21] - 2026-03-02

### Fixed
- **Interface names missing**: SNMP ifXTable walk now reads `ifName` (`.1.3.6.1.2.1.31.1.1.1.1`) and uses it to override the generic `ifDescr` value; on FortiGate devices, `ifDescr` returns generic descriptions while `ifName` returns the actual interface names (`port1`, `wan1`, etc.)

## [0.10.20] - 2026-03-01

### Fixed
- **PingStats not populated from probe data**: `ReceivePingResults` now aggregates each incoming ping result into `PingStats` (min/max/avg latency, packet loss, sample count), so the Ping tab on device detail shows actual data instead of "Awaiting ping data from probe..."
- **VLAN interface filter broken**: Changed VLAN filter from `vlan_id > 0` (Q-BRIDGE-MIB, unsupported on FortiGate) to matching `type_name === 'l2vlan' || type_name === 'l3ipvlan'`

### Added
- **Hardware sensor receive endpoint**: `POST /api/probes/:id/hardware-sensors` accepts sensor data from probes and saves to database, completing the hardware sensor pipeline so the Hardware tab shows actual sensor readings
- **Dynamic interface type filters**: Interface filter buttons are now generated dynamically from actual interface types present in the data (with counts), instead of hardcoded ethernet/tunnel/vxlan/lag/vlan buttons

## [0.10.19] - 2026-03-01

### Fixed
- **Password change error not shown**: Changed HTTP status from 401 to 403 when the current password is wrong during password change, preventing the frontend's session-expiry interceptor from silently redirecting to login instead of displaying the error message

## [0.10.18] - 2026-03-01

### Fixed
- **Chart.js blocked by CSP**: Added `https://cdn.jsdelivr.net` to Content-Security-Policy `script-src` directive so Chart.js CDN scripts load correctly on admin and device-detail pages

## [0.10.17] - 2026-03-01

### Fixed
- **Critical bug**: `UDPSyslogReceiver.Stop()` now correctly calls `running.Store(false)` instead of `running.Load()`, which caused the UDP read loop to continue indefinitely after stop
- **Thread safety**: `SFlowReceiver` changed from plain `bool` to `atomic.Bool` for the `running` field, preventing data races between Start/Stop/readLoop goroutines; added `sync.WaitGroup` for clean shutdown

### Refactored
- **Split `handlers.go`** (2,716 lines) into 10 domain-specific files: `handlers_auth.go`, `handlers_dashboard.go`, `handlers_devices.go`, `handlers_sites.go`, `handlers_connections.go`, `handlers_probes.go`, `handlers_settings.go`, `handlers_data.go`, `handlers_analytics.go`, plus the trimmed core `handlers.go`
- **New `internal/httputil/` package**: Shared handler helpers (`ParsePagination`, `ParseID`, `ParseHours`, `RequireDB`, `FilterAllowedFields`) and credential redaction (`RedactDevice`, `RedactDevices`, `RedactProbe`, `RedactProbes`) — eliminates ~200 lines of copy-paste across handlers
- **Notifier dedup**: Extracted `postJSON` helper in `internal/notifier/notifier.go`, replacing identical JSON POST logic in `sendSlack`, `sendDiscord`, and `sendWebhook`
- **Alerts dedup**: Extracted `checkThreshold` helper in `internal/alerts/alerts.go`, reducing 4 near-identical threshold check blocks in `CheckSystemStatus`
- **Database dedup**: Extracted `timeSeriesCount` and `groupByString` helpers in `internal/database/database.go`, deduplicating `GetAlertStats`, `GetTrapStats`, `GetSyslogStats`, and `GetDashboardTimeSeries`

## [0.10.16] - 2026-03-01

### Added
- **Chart.js integration**: All major pages now include interactive charts and graphs via Chart.js 4.4.7 CDN
- **Dashboard charts**: Activity trend line chart (syslog + traps + alerts per hour) and device status doughnut chart
- **Flows analytics**: Summary stat cards (total flows, bytes, unique sources/destinations), protocol distribution doughnut, top talkers bar chart, bytes-over-time line chart
- **Alerts overhaul**: Stat cards, alert trend line chart, alert type distribution doughnut, severity/acknowledged filters, per-alert acknowledge button, pagination
- **Traps overhaul**: Stat cards, trap frequency bar chart, severity distribution doughnut, severity/type filters, pagination
- **Syslog charts**: Stat cards, message trend bar chart, severity distribution doughnut
- **Device status history**: 24-hour CPU/memory/disk line chart on device detail page below gauge cards
- **VLAN interface filter**: New VLAN filter button on device detail interfaces tab (filters by vlan_id > 0)
- **6 new API stats endpoints**: `/api/flows/stats`, `/api/alerts/stats`, `/api/traps/stats`, `/api/syslog/stats`, `/api/dashboard/stats`, `/api/devices/:id/status-history`
- **Alert acknowledge endpoint**: `POST /api/alerts/:id/acknowledge`
- **Offset/pagination support**: Added offset query parameter to alerts, traps, syslog, and flows endpoints
- **Filtering**: Device ID and severity filters on alerts; severity and trap type filters on traps; device ID filter on flows

### Improved
- **Database layer**: 6 new aggregation methods for time-series stats (GetSystemStatusHistory, GetFlowStats, GetAlertStats, GetTrapStats, GetSyslogStats, GetDashboardTimeSeries)

## [0.10.15] - 2026-03-01

### Fixed
- **Test Device for probe-managed devices**: Test connection no longer fails with "Failed to poll device" for devices managed by a remote probe; instead returns an informational message explaining the probe polls the device automatically
- **Test Device error detail**: Connect and poll errors now include the actual error message instead of generic "Failed to connect/poll" text

### Improved
- **Device detail empty states**: System status, interfaces, VPN, sensors, and ping tabs now show "Awaiting data from probe…" when no data has arrived yet, instead of silent dashes
- **Alerts empty state**: Shows "No recent alerts — device is healthy" when alert list is empty

## [0.10.14] - 2026-03-02

### Fixed
- **Database migration crash on upgrade**: GORM AutoMigrate with SQLite fails with "table already exists" when adding new columns to existing tables; migration now runs per-model and logs warnings instead of crashing, so existing databases upgrade cleanly

## [0.10.13] - 2026-03-01

### Fixed
- **Docker compose**: Added `build: .` directive so `docker-compose up -d --build` rebuilds the image and detects changes without needing a separate `docker build` step

## [0.10.12] - 2026-03-01

### Added
- **Per-device SNMPv3 support**: Devices can now be configured with SNMPv3 credentials (username, auth protocol/password, privacy protocol/password) stored per-device rather than globally
- **SNMPv3 UI**: Device modal now includes SNMP version selector with conditional v3 fields (username, auth type, auth password, privacy type, privacy password)
- **Enhanced interface data collection**: Collects ifXTable data (ifAlias, ifHighSpeed, ifHCInOctets, ifHCOutOctets), ifMtu, ifPhysAddress (MAC), and Q-BRIDGE VLAN IDs from SNMP
- **Interface type names**: Maps IANA ifType values to human-readable names (ethernet, tunnel, vxlan, lag, loopback, etc.)
- **IPSec VPN tunnel polling**: New `GetVPNStatus()` SNMP method walks FortiGate VPN tunnel MIB for tunnel name, remote gateway, status, and byte counters
- **VPN data pipeline**: VPN statuses flow through poller, probe, relay, and API (`POST /api/probes/:id/vpn-status`)
- **Device detail page**: New `/admin/devices/:id` page with system status gauges (CPU/memory/disk), tabbed interface for interfaces, VPN tunnels, hardware sensors, alerts, and ping stats
- **Interface detail expansion**: Clicking an interface row expands to show full counters, VLAN ID, high speed, and a 24-hour sparkline chart
- **Interface history API**: `GET /admin/api/devices/:id/interfaces/:ifIndex/history?hours=24` returns time-series interface data
- **Device detail API**: `GET /admin/api/devices/:id/detail` returns comprehensive device info with latest system status, interfaces, VPN, sensors, alerts, and ping stats
- **Dashboard enrichment**: Dashboard API now returns per-device CPU, memory, sessions, interface up/down counts, and VPN tunnel summary
- **Device table columns**: Devices table now shows CPU, Memory, and Sessions columns with color-coded values
- **Alert persistence**: All alerts (CPU, memory, disk, session, interface down, VPN down, device offline) are now saved to the database
- **VPN down alert**: `VPN_TUNNEL_DOWN` critical alert fires when a VPN tunnel is detected as down
- **Device offline alert**: `DEVICE_OFFLINE` critical alert fires when the poller marks a device offline
- **Device name links**: Device names in the admin table are now clickable links to the device detail page

### Fixed
- **Probe-assigned devices marked offline**: Server poller no longer polls devices that have a `ProbeID` set — those are polled by the remote probe instead
- **Probe data doesn't update device status**: `ReceiveSystemStatuses` and `ReceiveInterfaceStats` handlers now mark devices as online with updated `last_polled` timestamp when probe data arrives
- **Alerts missing DeviceID**: All alert checks now set `DeviceID` on generated alerts and use per-device cooldown keys to avoid cross-device cooldown conflicts
- **Alerts not persisted**: `AlertManager` now accepts a database reference and calls `SaveAlert()` for every generated alert

### Changed
- **AlertManager constructor**: `NewAlertManager()` now takes a `*database.Database` parameter (nil-safe for trap-receiver)
- **Dashboard API format**: `GetDashboardAll` response now includes `enrichments` map alongside `dashboard` data

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
