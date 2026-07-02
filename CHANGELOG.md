# Changelog
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.559] - 2026-07-02

### Added
- **Prometheus monitoring pack** (`docs/monitoring/`): a ready-to-adapt `prometheus.yml` scrape config for all three daemons, plus a README documenting the real exposed metrics (`fwmon_http_request_duration_seconds`, Go runtime/process, DB pool), example PromQL (request rate, p95 latency, 5xx ratio, goroutine/mem watch, pool saturation), and starter alerting rules.

## [0.10.558] - 2026-07-02

### Added
- **"Report an issue" link in the admin sidebar** — opens the GitHub issue chooser in a new tab, giving alpha operators a one-click path to file bugs/feedback.
- **Resource-footprint & DB-sizing guidance in `docs/OPERATIONS.md`** — explains that PostgreSQL disk (not the daemons) is what grows, gives the `rows ≈ ingest_rate × retention` model and the dominant tables, and shows the exact `pg_total_relation_size` / per-day-count queries to size from real data instead of guessing.

## [0.10.557] - 2026-07-02

### Added
- **`gosec` security static-analysis is now a CI gate** (`.github/workflows/ci.yml`, pinned v2.27.1). High-signal rules (SQL injection, command execution, SSRF via variable URL, weak-randomness-for-tokens, unhandled crypto) are enforced. A curated exclude list (`G115,G124,G203,G304,G401,G501,G703`) drops the rules that are systematically false-positive for this app category — each documented in the workflow and reviewed in the 2026-07-02 audit (integer conversions on DB counters, the TLS-driven `Secure` cookie flag, report-SVG `template.HTML` over server-computed numbers, config/secret file reads by path, and the non-cryptographic MD5 config-change fingerprint).

### Docs
- Documented in-code why `configdiff` config-change checksums stay on MD5 (a non-cryptographic content fingerprint; switching algorithms would false-fire a CONFIG_CHANGE alert on every device once at upgrade). Marked all three collector findings of the 2026-07-02 audit resolved (collector v1.2.162) in `docs/audit-2026-07-02-consolidated.md`.

## [0.10.556] - 2026-07-02

### Security
Fixes for the confirmed server-side findings of the 2026-07-02 engineering security audit (adversarially verified). See `docs/audit-2026-07-02-consolidated.md`.

- **HIGH — IRC credentials were returned in cleartext by the IRC API.** `GetIRCServer(ByID)`, `GetIRCChannels`, and the create/update echo responses decrypted the stored server/NickServ/SASL/ChanServ/oper/channel-key secrets and serialized the plaintext into the JSON body — defeating the at-rest encryption for anything that sees an admin response (browser cache, proxy logs, admin-context XSS). Added `RedactIRCServer`/`RedactIRCChannel` (`internal/httputil/redact.go`); all IRC read/echo paths now mask secrets with `********`. The update handlers gained the redaction write-back guard (an incoming `********` means "unchanged" and is never re-encrypted over the real secret), mirroring the device path. The Connect/Test flows still read plaintext server-side.
- **HIGH — session revocation failed open under DB stress.** `AuthManager.ValidateToken` only rejected a token when the token-version lookup returned `err == nil`; on any DB error (transient failure, `statement_timeout`, missing row) it accepted the token regardless of version, so a stolen-but-unexpired JWT survived logout / password-change revocation exactly when the DB was stressed. It now fails closed — any lookup error rejects the token. Regression test `TestValidateToken_FailsClosedOnDBError`.
- **HIGH — unauthenticated IDOR on `/api/public/*`.** `resolvePublicDeviceID` returned any `?device_id` verbatim with no `public_visible` check, so an anonymous caller could enumerate device IDs and pull telemetry (hostnames, firmware/signature versions, interface details, VPN peers) for devices explicitly marked non-public. The param is now gated on `enabled AND public_visible`, closing it across every per-device public endpoint at once.
- **HIGH — public display toggles were enforced client-side only.** `GetPublicVPN` and `GetPublicConnections` ignored `public_show_vpn` / `public_show_connections` (default off) and the connections endpoint had no device filter at all, dumping the full inter-device topology to anyone. Both toggles are now enforced server-side, and public connections are restricted to pairs where BOTH endpoints are public-visible.
- **HIGH — webhook test endpoint was a DNS-rebind SSRF.** The notification test client used a plain `http.Client`, so the pre-flight IP check could be defeated by short-TTL DNS re-resolving to an internal target on `client.Do`. It now uses the same `httputil.SafeDialContext` guarded transport as the real notifier delivery path.
- **MEDIUM — probe device allow-list failed open.** `probeDeviceIDs` returned `nil` on a device-lookup error, and every ingestion guard enforced only when the allow-list was non-nil — so during a DB-error window an authenticated probe could push telemetry (including forged config revisions) attributed to devices assigned to a different probe. It now returns a non-nil empty set (deny-all) on error, so all ~18 ingestion guards fail closed and the collector retries.
- **MEDIUM — `config.env` was world-readable in Docker.** `entrypoint.sh` wrote `/config/config.env` (holding `JWT_SECRET_KEY`, from which the AES-256 at-rest key is derived) at the default 0644 under a root umask; `/config` is bind-mounted to the host, so any local user could read the master secret. It is now `chmod 0600` + `chown fwmon`, matching the pg-credentials file.
- **LOW — two unescaped `innerHTML` status sinks.** The VPN tunnel status/state on the device-detail page and the VPN status on the unauthenticated public dashboard were interpolated without escaping (enum-constrained today, but the public one is internet-facing). Both now route through the escape helper.

## [0.10.555] - 2026-07-02

### Added
- **Forced password change on first login when the admin password was auto-generated.** A fresh install auto-generates the admin password and writes it to the container log and `.admin-password` file; previously it stayed valid forever unless the operator manually rotated it. The admin is now flagged `must_change_password` at bootstrap (only when the password was generated — an operator who set `ADMIN_PASSWORD` deliberately is trusted as-is), and the server **enforces the rotation**: a new `RequirePasswordChanged` gate on the admin group returns `403 {code:"password_change_required"}` for every admin API route except the change-password, logout, and CSRF endpoints (and the SPA pages), so the change cannot be skipped by calling the API directly. The admin console detects that code in `apiFetch` and pops a blocking change-password modal; on success the token version is bumped and the operator re-authenticates. New migration v19 (`admin_must_change_password`, idempotent `ADD COLUMN IF NOT EXISTS`). The gate fails closed — if the flag can't be read, the action is blocked. Regression tests `TestAdminMustChangePassword_Lifecycle` / `TestInitAdmin_OperatorPasswordNotForced`.

## [0.10.554] - 2026-07-02

### Added
- **`staticcheck` is now a CI gate** (`.github/workflows/ci.yml` `static-analysis` job, pinned to v0.7.0). A `staticcheck.conf` inherits the full default check set and disables only ST1005 (trailing-punctuation on error strings), which the codebase's deliberately multi-sentence operator-facing diagnostics legitimately trip.
- **SNMP vendor parsers now have a hostile-input robustness suite** (`internal/snmp/vendor_robustness_test.go`). Every registered vendor profile (firewalla, fortigate, opnsense, paloalto, pfsense, sonicwall) has all five parse methods (`ParseSystemStatus`/`ParseVPNStatus`/`ParseHardwareSensors`/`ParseProcessors`/`ParseHAStatus`) hammered with adversarial PDUs — malformed OIDs, truncated indices, wrong ASN.1 types, overflow/NaN/nil values, SNMP exception tags — asserting no parser panics. Previously only fortigate had any parser test; a panic here would take down a poll goroutine on a malfunctioning or hostile device's response. All parsers pass.

### Fixed
- **Removed dead code flagged by staticcheck.** Unused OID constants not read by any parser (FortiGate HA scalars, Palo Alto HA + app/wildfire version OIDs, Firewalla HOST-RESOURCES storage OIDs, an unused SNMP-trap admin-status OID), an unused `AlertManager.canAlert` (superseded by `canAlertWithCooldown`), an unused `bucketResult` type, an unused `autoScale` report helper, and an empty switch case. Also simplified two `append`-in-loop bodies and a `== false` comparison. No behavior change; the OIDs remain in git history and the vendor MIBs for when those capabilities are wired.

## [0.10.553] - 2026-07-02

### Added
- **Alpha-launch community & landing-page polish.** Added GitHub issue forms (`.github/ISSUE_TEMPLATE/bug_report.yml`, `feature_request.yml`, `config.yml` routing security reports to the private policy and questions to Discussions), a pull-request template, and a Dependabot config (`.github/dependabot.yml`) covering the gomod, github-actions, docker, and npm ecosystems. The README now carries an explicit **alpha** status banner + a **Project status** section, a live CI-status badge (replacing the static "passing" image), and a corrected version badge (was pinned at 0.10.495).
- **`PRIVACY.md` — no-telemetry statement.** Documents that Firewall-Mon does not phone home, enumerates every default and opt-in outbound connection, and points privacy concerns at the security-disclosure process. Linked from the README.

### Fixed
- **`.playwright-mcp/` dev-dump directory is now git-ignored.** Its contents were already ignored but the directory itself showed as untracked; added an explicit ignore rule. Clarified the `CODEOWNERS` header (the `@xphox2` owner is the current maintainer, not a placeholder to replace).

## [0.10.552] - 2026-07-02

### Docs
- **Marked audit finding L13 resolved in the consolidated report.** L13 (collector flow-counter backlog flapping probe approval after a server schema-v1 rollback) was fixed in collector v1.2.160; this records its `✅ RESOLVED` banner in the server-repo copy of `docs/audit-2026-07-01-consolidated.md`, which now carries the resolved markers for all 64 findings of the 2026-07-01 audit (10 HIGH + 30 MEDIUM + 24 LOW — the full audit is complete). No code change.

## [0.10.551] - 2026-07-02

### Added
- **sFlow `if_direction` now persists on interface counters (audit 2026-07-01 finding L12).** The collector has always sent the sFlow ifDirection field as JSON `if_direction` on the schema-v2 counter-sample wire form, but `FlowInterfaceCounter` had no matching column, so GORM's bind silently dropped it at ingest. Added the `IfDirection uint32` field and migration v18 (`flow_if_counters_add_direction`, `bigint NOT NULL DEFAULT 0`, metadata-only on PostgreSQL 11+).
- **Device-detail page surfaces sFlow-only interfaces (audit 2026-07-01 finding L18).** The interface list was built solely from `interface_stats` (SNMP), so a device that is SNMP host-restricted but pushes sFlow if_counters rendered zero interface cards and the sflow-chart endpoint — the whole point of the feature — was never called. The handler now unions the SNMP list with the latest sFlow counter per distinct `if_index` (`GetLatestInterfaceCountersByDevice`), synthesizing a card for each flow-only interface so it appears and its bandwidth chart is reachable.

### Fixed
- **A malformed `?focus=` no longer breaks the NOC/Connections pages (audit 2026-07-01 finding L6).** `parseFocus` (NOC) and `getConnFocusParam` (Connections) ran `decodeURIComponent` on the URL fragment unguarded, so a hand-edited or truncated escape (e.g. `?focus=device:%ZZ`) threw an uncaught `URIError` that aborted NOC initialization and wiped the just-rendered connection map. Both now wrap the decode in try/catch and treat a bad value as "no focus".
- **`SNMP_TRAP_COMMUNITY` ships empty instead of `public` (audit 2026-07-01 finding L14).** `config.env.example` shipped `SNMP_TRAP_COMMUNITY=public`, and deploy.sh seeds `config.env` from the example verbatim on first install — so a fresh native deploy opened 162/udp accepting the world's best-known community, letting anyone on the network inject spoofed trap events into the alert pipeline. It now ships empty, so the trap receiver keeps its listener closed and idles (AUDIT-012) until the operator sets their devices' real community.
- **Interface/tunnel bandwidth charts drop stale overlapping responses (audit 2026-07-01 finding L19).** `loadInterfaceChart`/`loadTunnelChart` had no in-flight guard, so quickly changing the range fired overlapping fetches whose responses could land out of order — a slower earlier response overwrote the live chart with stale buckets and leaked the newer Chart.js instance. Each request now carries a per-key sequence token and a response that is no longer the latest is discarded.
- **The "Awaiting data from probe…" banner no longer stacks (audit 2026-07-01 finding L20).** `renderSystemStatus` appended the banner via `insertAdjacentHTML` on every 60s poll for a device with no system status, stacking copies without bound, and never removed it once data arrived. It now clears any prior banner before (re)rendering, so exactly one shows while awaiting data and none lingers afterward.
- **The Flows bandwidth chart no longer resurrects the previous filter over "No data" (audit 2026-07-01 finding L21).** `showChartEmpty` replaced the chart host's innerHTML without destroying `charts.bandwidth` or clearing `lastBwData`, orphaning the Chart instance and leaving stale cached data that a theme/mode toggle (which re-renders from `lastBwData`) would draw over the empty state. Both the empty-message path and the no-points path now destroy the chart and null the cache first.

## [0.10.550] - 2026-07-02

### Fixed
- **GeoLite2 partial loads are no longer reported as "disabled", and a MaxMind update now applies without a restart (audit 2026-07-01 finding L4).** When only one of the Country/ASN databases opened, startup logged "geo/ASN enrichment disabled" even though enrichment was in fact running on the DB that loaded; it now logs "partial load … enabled … with reduced coverage". Each reader is held behind an `atomic.Pointer`, and a new `GeoResolver.Reload()` (wired to a 6-hour ticker in `cmd/api`) re-stats the `.mmdb` files and hot-swaps any that changed on disk. The swapped-out reader is retired and closed only on the *following* reload cycle, never while an in-flight lookup could still be dereferencing its memory-map (an immediate `Close()` unmaps the region and would SIGBUS a concurrent lookup). Operators updating the databases by hand must rename the new file into place rather than overwriting it — documented in the reload path.
- **A stalled NOC dashboard client can no longer pin its SSE handler goroutine forever (audit 2026-07-01 finding L5).** The stream previously cleared the write deadline outright to avoid the 30s `SERVER_WRITE_TIMEOUT` force-closing the long-lived connection — but that left a client which stopped reading (zero TCP receive window) blocking the handler's `Write` indefinitely, leaking one goroutine per such client. It now arms a rolling 15-second per-write deadline before each snapshot/keepalive flush: a healthy reader resets it on every message so a live stream is never truncated, while a genuinely stuck write eventually errors out and the handler returns and unsubscribes.
- **Concurrent ping-stats folds can no longer lose or double-count a whole batch (audit 2026-07-01 finding L16).** `updatePingStatsBatch` did a read (`GetPingStatsByTarget`) → modify → write (`SavePingStats`) with no locking, so two batches folding the same `(device_id, target_ip)` concurrently both read the same base row and the last writer erased the other's entire batch from the lifetime series (the M4 batch rewrite widened the loss unit from one sample to the whole batch). The fold is now a single atomic `FoldPingStats` — `INSERT … ON CONFLICT (device_id, target_ip) DO UPDATE` — that recomputes min/max and the running average `(avg·samples + Σ)/(samples + K)` in-SQL against the row's pre-update values under the upsert's row lock, so interleaved folds accumulate exactly. Dialect-aware scalar `min`/`max` (SQLite) vs `LEAST`/`GREATEST` (PostgreSQL). Regression tests `TestFoldPingStats_AtomicAccumulation_L16` and `TestFoldPingStats_ManyFoldsSumSamples_L16`.

## [0.10.549] - 2026-07-01

### Fixed
- **Operator-set alert cooldowns longer than ~10 minutes are no longer truncated by the prune (audit 2026-07-01 finding L2).** `PruneExpiredCooldowns` evicted every cooldown-map entry older than a fixed `alertCooldown*2` (≈10 min), so a per-policy cooldown of, say, 60 minutes (set to quiet a noisy flow/syslog/trap detector) was dropped at the next prune and the following detection re-alerted before the configured window elapsed. The map now records each key's effective cooldown alongside its timestamp and prune evicts only entries past their **own** cooldown; the poller also prunes hourly (rather than only on the daily cleanup).
- **A truncated threat feed is now a fetch failure, not a silent partial sync (audit 2026-07-01 finding L3).** `threatfeed.Parse` ignored `bufio.Scanner` errors, so a line longer than the 1 MiB buffer (`bufio.ErrTooLong` — e.g. an HTML error page served with HTTP 200 as one giant line) or a mid-body read error stopped the scan silently and the smaller result was treated as a successful sync, quietly expiring the feed's indicators out of the matcher after the TTL. `Parse` now returns the scanner error and `Fetch` propagates it.
- **Critical-alert emails with a chart image no longer risk mangled HTML (audit 2026-07-01 finding L7).** The `multipart/related` HTML part declared `Content-Transfer-Encoding: quoted-printable` but wrote the body raw, so a compliant client/MTA QP-decoded it — turning `=XX` sequences in alert text (e.g. `threshold=90`) into raw bytes and choking on 8-bit UTF-8 / long lines. The part is now written through `mime/quotedprintable.NewWriter` so the body matches its declared encoding.
- **Report SVG charts no longer break on a single data point (audit 2026-07-01 finding L8).** `RenderThroughputChart` / `RenderCPUMemSVGChart` divided the X axis by `nPoints-1`, so a 1-point series (a newly added device, or sparse data at report time) produced `NaN` path coordinates — an invalid SVG path browsers drop, breaking the report preview and print-to-PDF for that device. Both now require ≥2 points and fall back to the "no statistics" placeholder otherwise.

## [0.10.548] - 2026-07-01

### Fixed
- **`/api/flows/stats` no longer double-scales `estimated_bytes` (audit 2026-07-01 finding L1).** `flow_samples.bytes` is already multiplied by `sampling_rate` at ingest (collector + server parser, plus the migration-v7 backfill), so multiplying `SUM(bytes)` by `AvgSamplingRate` again over-reported by roughly the sampling rate (512× at 1:512). `estimated_bytes` now equals the (already-scaled) total; the stale scaling comment is removed.
- **Manually-added threat-intel entries are stored in canonical (masked) form (audit 2026-07-01 finding L22).** `AddThreatIntel` stored the CIDR verbatim while the matcher masks it, so `203.0.113.9/24` was stored but enforced as `203.0.113.0/24` — equivalent prefixes created duplicate `(cidr,source)` rows (deleting the visible one left a hidden duplicate still escalating detections) and the displayed scope didn't match the enforced scope. The CIDR is now canonicalized before storage, so the stored key, the displayed value, and the enforced prefix are identical.
- **Detector thresholds reject `NaN`/`Inf` instead of silently ignoring them (audit 2026-07-01 finding L23).** `strconv.ParseFloat("NaN")` succeeds and every comparison against NaN is false, so `detect_beacon_max_cv` / `detect_capacity_threshold` accepted `NaN` — persisted and shown as the active override, but silently ignored by the poller (its `v > 0` guard is false for NaN), so the displayed threshold diverged from the effective one. The range checks are inverted to `!(v > 0 && v <= max)`, which non-finite values fail.
- **A non-numeric Flows filter no longer 500s on PostgreSQL (audit 2026-07-01 finding L24).** `GetFlowSamples` bound the raw `protocol` (and `probe_id`/`device_id`/`site_id`) query strings against integer columns, so a hand-edited or stale URL like `?protocol=tcp` threw `22P02` (→ 500) on Postgres while SQLite silently matched nothing — a dialect divergence. These are now parsed with `strconv` and applied only on success, matching the sibling numeric filters (dst_port, app_category, direction, dst_asn).

## [0.10.547] - 2026-07-01

### Fixed
- **Native/systemd installs no longer inherit the "keep critical syslog forever" default that caused the DB-bloat incident (audit 2026-07-01 finding M21).** The `RETENTION_SYSLOG_CRITICAL_DAYS` mitigation lived only in `docker-compose.yml`; `config.env.example` — which `deploy.sh` seeds verbatim as the live config on native installs — documented none of the core retention knobs, so severity-0–5 syslog (FortiGate traffic logs are severity 5) accumulated forever. Added a documented core-retention block (`RETENTION_SYSLOG_CRITICAL_DAYS=30` with the incident rationale, plus `SYSLOG_INFO`/`FLOW`/`STATUS`/`TRAP`/`PING`/`ALERT`/`DEFAULT` days) so every install path gets the safe value. *(The code default is intentionally left at 0 to avoid silently deleting existing installs' critical syslog on upgrade — the fix is opt-in via the seeded config.)*

### Added
- **CI now fails if the committed `tailwind.css` is out of date (audit 2026-07-01 finding M22).** The embedded `cmd/api/static/css/tailwind.css` is generated from `styles.css` by `npm run tailwind`, but the Dockerfile only COPYs the committed artifact and no CI gate existed, so a `styles.css` edit without regeneration could ship stale/broken theming to prod (the v0.10.500→526 regression). A new `Tailwind CSS freshness` CI job regenerates the file and fails on any diff, so a stale artifact can never merge — which keeps the file the Dockerfile copies always fresh.

## [0.10.546] - 2026-07-01

### Fixed
- **Connection-traffic charts no longer break permanently after an empty range (audit 2026-07-01 finding M13).** The empty-state overwrote `canvas.parentElement.innerHTML`, removing the canvas from the DOM; a later range switch then either threw (`FwmonBwChart.mount` on a null canvas → a false "Failed to load" toast on every 30s re-poll until reload) on the connection-detail page, or silently never rendered again (`if (!canvas) return`) on the diagram side panel. Both now use a stable host container (`#traffic-chart-host` / `#panel-traffic-chart-host`) and re-create the canvas on the data path if a prior empty-state removed it.
- **Fixed a data race between the report scheduler and the alert manager (audit 2026-07-01 finding M15).** Both mutated the same shared `config.Config.Alerts` fields under two different mutexes (`rs.mu` vs `am.mu`) — no mutual exclusion, so concurrent string writes/reads were a data race (a torn string header could send a report to a garbage recipient or panic). The `ReportScheduler` now owns a private copy of `AlertsConfig`, seeded at construction and refreshed from the database (report, email/SMTP/webhook, and spike settings — the same source the alert manager reads), so it never touches the shared config.
- **The device-detail bandwidth chart no longer lets stale sFlow hide live SNMP data (audit 2026-07-01 finding M27).** `loadInterfaceChart` preferred the sFlow series whenever it had ≥2 buckets anywhere in the window, with no recency check — so a stopped sFlow export (collector down mid-incident), a brief past sFlow trial stretched across a 7d/30d view, or a zoom sub-window with sparse sFlow silently ended the chart in the past and hid the current SNMP-measured traffic. It now fetches both sources and prefers sFlow only when its last bucket is at least as recent as SNMP's; otherwise SNMP wins.

## [0.10.545] - 2026-07-01

### Fixed
- **Webhook failure logs no longer leak the Slack/Discord secret token (audit 2026-07-01 finding M14).** Slack incoming-webhook and Discord webhook URLs carry their auth token in the URL path; `postJSON` embedded the full URL in both its non-2xx error and — via Go's `*url.Error` — its transport error, writing the secret to container logs on every failed send (hundreds of lines during an alert storm). Both paths now redact to `scheme://host`.
- **A LINK_UP trap no longer auto-resolves every device's LINK_DOWN (audit 2026-07-01 finding M24).** The direct trap-receiver pipeline never populated `DeviceID`, so every direct trap had `DeviceID=0` + `MetricName="snmp_trap"` and a LINK_UP's recovery `UPDATE … WHERE device_id=0 AND metric_name='snmp_trap'` matched **all** direct-trap LINK_DOWN alerts — firewall B's LINK_UP silently closed (and auto-acknowledged) firewall A's still-open LINK_DOWN. `ProcessTrap` now resolves the device from the trap's source IP (so per-device policies apply and `device_id` scopes recovery) and scopes each trap alert's `MetricName` to `snmp_trap_<sourceIP>`, so recovery can never cross devices.
- **The trap-receiver's alert-cooldown map is now bounded (audit 2026-07-01 finding M25).** The trap-receiver embeds its own `AlertManager` whose `lastAlert` map is keyed by spoofable source IPs, and — unlike the poller — it never ran `PruneExpiredCooldowns`, so a spoof-flood grew it ~unbounded (hundreds of MB/day). Two layers now bound it: the trap-receiver runs a 1-minute prune ticker, and `AlertManager` hard-caps the map at 50k entries (every cooldown write routes through a bounded helper that prunes expired entries then evicts the oldest), so any process embedding it is safe by construction.

## [0.10.544] - 2026-07-01

### Fixed
- **Flow-detection alert storms fixed (audit 2026-07-01 finding M3).** Two causes: (1) an `AlertPolicy`/`AlertRule` with `CooldownMinutes=0` zeroed the effective cooldown — `now.Sub(lastAlert) > 0` is always true, so every alert type on that policy re-fired every cycle. The policy- and rule-level cooldown copies now use the same `> 0` floor the site/device overrides already had (0 inherits the default instead of disabling the cooldown). (2) The SFLOW_* flow detections run a 15-minute window scanned every 5 minutes, so one event is re-detected in ~3 cycles and the old flat 5-minute default (== the cycle period) let each re-detection notify; SFLOW_* alert types now default to a 15-minute cooldown (≥ the window), collapsing the duplicates and pacing a persistent condition to once per window. Operators can still override lower.
- **Multicast/broadcast/unspecified addresses no longer misclassified as external traffic (audit 2026-07-01 finding M6).** `classify.Direction` treated IPv4/IPv6 multicast, the limited broadcast (255.255.255.255), and the unspecified address (0.0.0.0 / ::) as "external", so periodic SSDP/mDNS announcements to 239.255.255.250, IPTV multicast, and DHCP DISCOVER were stamped Outbound/External — feeding false `c2_beacon` ("periodic small callout") and `data_exfil` ("large outbound transfer") detections and skewing the Flows ByDirection widget on any LAN. These are now correctly classified as local/internal scope.
- **A slow threat feed no longer stalls the poller (audit 2026-07-01 finding M9).** `runThreatFeedSync` ran inline in the poller's single `select` loop — sequential fetches (90s ctx each, up to 5 default feeds) plus large upserts — so a blackholed feed host froze SNMP polling, alert evaluation, offline detection, rollups, and cleanup for minutes, and `stopChan` wasn't serviced (shutdown hung). It now runs in a `SafeGo` goroutine guarded against overlapping intervals, with the cross-process leader lock taken inside the goroutine; the select loop stays free of network I/O.

## [0.10.543] - 2026-07-01

### Docs
- **Marked audit findings M16, M17, M18 resolved in `docs/audit-2026-07-01-consolidated.md`** — all three fixed collector-side in v1.2.157 (TCP syslog now rate-limited/connection-capped/backoff-on-accept-error; corrupt spillover files quarantine-and-recreate instead of disabling all seven queues; the throttled fsync moved off the queue mutex shared by UDP workers). See the collector CHANGELOG for details.

## [0.10.542] - 2026-07-01

### Fixed
- **sFlow agent drop monitoring actually works now (audit 2026-07-01 finding M2).** The `sampling_backoff` detector read `flow_agent_drops`, but nothing in production ever wrote it — the promised aggregation of `FlowSample.Drops` was a TODO — so `SFLOW_SAMPLING_BACKOFF` could never fire while operators believed drop monitoring was active, and agent-side traffic under-reporting went unnoticed. The flow-ingest handler now folds each batch's drops counters into `flow_agent_drops`. The sFlow v5 drops field is a **cumulative** per-agent counter, so the handler tracks the last seen value per agent and stores only the positive delta per batch (counter regression = agent restart → re-baseline), in a bounded tracking map. End-to-end regression test: ingest two batches with a growing counter → the detector fires.
- **Threat-intel matching is no longer an O(feed-size) scan on the ingest hot path (audit 2026-07-01 finding M4).** `Matcher.Match` — called twice per flow sample, synchronously, in the ingest handler — scanned a flat slice to the end on every miss; with the default feeds' tens of thousands of prefixes that burned a full CPU core at a few thousand samples/sec. Prefixes are now bucketed by bit length into maps keyed on the masked prefix: a lookup is one map probe per distinct prefix length present in the feed (a handful), independent of feed size, still lock-free and allocation-free. Overlapping prefixes now return the most specific match, and IPv4-mapped IPv6 addresses match the IPv4 buckets.
- **A duplicate feed entry no longer aborts an entire threat-feed sync on PostgreSQL (audit 2026-07-01 finding M5).** Feed normalization masks prefixes, so distinct lines can collapse to the same (cidr, source) key — and PostgreSQL rejects a multi-row `INSERT ... ON CONFLICT DO UPDATE` that touches the same key twice, rolling back the whole feed's upsert every sync until the feed's indicators silently TTL-expired out of the matcher (SQLite tolerated it, so dev/tests never caught it — the invariant-4 dialect divergence). `UpsertThreatIntelBatch` now dedups the batch first, keeping the first occurrence.

## [0.10.541] - 2026-07-01

### Fixed
- **DB failures no longer render as an all-zero "live" NOC dashboard (audit 2026-07-01 finding M10).** `GetNOCSnapshotFiltered` discarded every query error and always returned `(snap, nil)`, so during a statement-timeout or outage the hub broadcast a zeroed snapshot — overwriting the last good frame — while the badge said "● live" and the site grid claimed "No sites or devices yet"; the hub's keep-last-good branch and the one-shot handler's 500 branch were dead code. The core flow aggregate, device status counts, and site breakdown now propagate errors (the top-N/country sub-queries stay tolerant by design), the hub keeps the last good snapshot, and compute failures are logged rate-limited to once per minute.
- **The NOC broadcaster no longer taxes the database while nobody is watching (audit 2026-07-01 finding M11).** The hub ran its ~15 aggregate scans — including two `COUNT(DISTINCT)` over the 5-minute flow window — every 5 seconds, 24/7, subscriber or not, and every `ALLOW_MULTI_API` follower duplicated the full load against the shared prod Postgres. Ticks now compute only while at least one SSE subscriber is connected; the first subscriber (0→1) gets a freshly computed snapshot inline. This also zeroes the follower duplication without breaking follower SSE the way primary-gating the hub would have.
- **Trap rate-limiter drops are now operator-visible (audit 2026-07-01 finding M29).** Drops from token exhaustion and from the 10k-source map cap were completely silent — no log, no metric — despite three code/CHANGELOG claims to the contrary, so legitimate traps lost during a link-flap storm or a spoof-flood lockout left zero trace. Every drop now increments `fwmon_trap_ratelimit_drops_total{reason="rate"|"cap"}` on the trap-receiver's `/metrics`, and a summary log line fires at most once per minute so a flood can't turn the defense into a log-volume DoS.

## [0.10.540] - 2026-07-01

### Fixed
- **Rejected and decommissioned probes can no longer resurrect themselves from the network side (audit 2026-07-01 finding M7).** Three gates were missing:
  - The unauthenticated key-based **register** endpoint unconditionally flipped any not-already-online probe back to `approved`+`online` — so a probe the admin explicitly REJECTED (rejection leaves the registration key valid) restored full ingestion just by re-POSTing register. It now returns **403** for rejected and **410** for decommissioned/disabled probes; reactivation goes only through the admin UI (approve / re-commission).
  - The **heartbeat** wrote `status='online'` + fresh `last_seen` unconditionally, undoing an admin decommission within 30 seconds — permanently, since the fresh `last_seen` also kept the probe immune to the stale-probe sweep. It now returns **410**.
  - **validateProbe** (gating every ingestion endpoint) checked only `approval_status` — which decommission deliberately leaves `approved` to preserve telemetry attribution — so retired/disabled probes kept ingesting and looking live. It now refuses when `decommissioned_at` is set or `enabled` is false. `RecommissionProbe` already restores both flags, so the re-commission flow is unchanged. Regression tests: `handlers_probes_lifecycle_m7_test.go`.
- **Decommissioning a probe no longer produces a PROBE_DATA_LAG alert storm forever (audit 2026-07-01 finding M28).** `CheckProbeDataFlow` iterated all `approval_status='approved'` probes — including soft-decommissioned ones, whose `last_data_received` is frozen by design — so every retired probe re-fired the lag alert on each cooldown expiry until hard-deleted (exactly what soft-decommission exists to avoid). Retired/disabled probes are now skipped; regression test with an active-lagging-probe positive control.

## [0.10.539] - 2026-07-01

### Fixed
- **Direct-send metric endpoints now have batch idempotency (audit 2026-07-01 finding L17, server half of the M19 pair).** The eight time-series metric endpoints (system status, interface stats, VPN statuses, HA statuses, processor stats, hardware sensors, security stats, SD-WAN health) run the same AUDIT-042 `batchDedupCheck`/`markBatchIfOK` pair the event endpoints use — previously a collector timeout after a server-side commit meant the buffered replay inserted every row twice, with duplicated cumulative interface counters skewing all delta-based bandwidth math. Pairs with collector v1.2.156, which sends a content-derived `X-Probe-Batch-ID` on those routes; a no-op for older collectors (no header ⇒ no dedup), so mixed-version deployments are unaffected. The current-state upsert endpoints (interface addresses, license info) are deliberately excluded — replays there are idempotent by design.

## [0.10.538] - 2026-07-01

### Fixed
- **One bad row can no longer reject (and poison-loop) an entire ingestion batch (audit 2026-07-01 finding M26).** The M4/M5 batch rewrites made the plural savers all-or-nothing: on partitioned prod Postgres a single row outside the existing partition range — a clock-skewed collector, or a spillover replay after its month's partition was dropped (no DEFAULT partition exists) — failed the whole INSERT, the handler 500'd, the collector buffered the batch as retryable, and its drain requeued the poison item forever: that metric type's ingestion stopped entirely. All **14** plural batch savers now share `batchInsertWithFallback`: the multi-row INSERT remains the fast path; on failure it retries per-row, logging and dropping only the unsalvageable rows (the pre-rewrite semantics), and returns an error only when *every* row fails. Regression test `TestBatchInsertWithFallback_M26` forces a poison batch through a unique-index violation.
- **Ingestion batch truncation is no longer silent (audit 2026-07-01 finding M1).** Flows, flow counters, pings, interface addresses, interface stats, and system statuses truncated oversize batches with no log or alert — then returned 200 and marked the idempotency batch ID processed, so the collector could never resend the tail: permanent, invisible loss whenever `PROBE_MAX_BATCH_SIZE` was raised above the server's cap. All eight capped endpoints now share `truncateProbeBatch`, which logs every truncation and records the operator-visible probe alert (the pre-existing traps/syslog behavior) on >20% overshoot. A 413-reject was deliberately avoided — live pre-fix collectors treat non-2xx as retryable and would requeue oversize batches forever.

## [0.10.537] - 2026-07-01

### Fixed
- **Direct-link connection traffic charts no longer render cumulative counters as per-bucket transfer (audit 2026-07-01 finding H10 — the last open HIGH).** `GetConnectionTraffic`'s direct-family path (ethernet/lag/l2vlan/bridge/wan) summed `interface_stats` bucket averages straight through — but those are **raw cumulative SNMP counters**, while the endpoint's `VPNChartBucket` contract is per-bucket deltas (the tunnel path LAG()s; both the connection-detail page and the diagram side panel divide `in_bytes` by the bucket interval for Mbps). A member interface with 2 TB lifetime InBytes rendered every hour bucket as ~2 TB transferred / a monotonically growing multi-Gbps flat line. `interfaceTrafficWindow` now deltas consecutive buckets **per interface** before summing across interfaces, clamping negative differences (counter resets/wraps) to 0 and dropping each interface's baseline bucket — identical semantics to the tunnel path. The regression test that previously pinned the cumulative pass-through now asserts exact delta totals, including a mid-series counter-reset clamp and that the dest endpoint's large cumulative counters no longer leak into the aggregate.
- **Tunnel/overlay connection traffic now populates `bucket_ms` (audit 2026-07-01 finding M12, same endpoint).** The LAG() SELECT had no bucket_ms column, so every row serialized 0 and the 3-mode charts' `normalizeDeltas` fell back to a hardcoded 60-second interval — exactly 60× inflated Mbps on the hourly-bucketed 7d/30d ranges (5× on a 5-minute poll cadence), and inconsistent with the direct path side by side. Backfilled from the bucket string via `parseBucketToMillis`, the same way `GetInterfaceChartWindow` does.

## [0.10.536] - 2026-07-01

### Docs
- **Marked audit findings H6 and H7 resolved in `docs/audit-2026-07-01-consolidated.md`** — both fixed collector-side in v1.2.154 (per-source rate-limiter idle eviction was dead code due to an unsatisfiable stored-tokens predicate; spillover-queue replay loaded the entire spool into RAM at startup). See the collector CHANGELOG for the full details. All ten HIGH findings of the 2026-07-01 audit except H10 are now resolved.

## [0.10.535] - 2026-07-01

### Fixed
- **An IRC outage can no longer wedge admin handlers, alert delivery, and graceful shutdown (audit 2026-07-01 finding H5).** `sendAutoStatus` held `Manager.mu.RLock` across the N+1-query status provider *and* every `Privmsg` send. In the pinned go-ircevent version a send parks forever once the connection's write channel loses its consumer during an outage (and the `DISCONNECTED` callback that would nil the conn never fires in this library version) — so statusLoop parked while holding the read lock, the next writer (`ReloadCommands`/`RestartBot` from admin HTTP handlers) blocked, and RWMutex writer-queueing then hung every subsequent reader: IRC alert delivery, `GetBot`, `Manager.Stop`, and shutdown, until SIGKILL. The due (conn, channel) pairs are now snapshotted under the lock and all DB/network work runs lock-free, gated on `conn.Connected()` — a parked send can stall auto-status only, nothing else.
- **A panic or nil-deref in an IRC event callback no longer crashes the whole fwmon-api process (audit 2026-07-01 finding M8).** go-ircevent runs each callback in a bare goroutine with no recover, bypassing the REL-01 SafeGo containment — and the callbacks dereferenced `b.Conn` without the bot mutex while `Stop`/`RestartBot`/`onQuit` nil it concurrently, so an admin restarting a bot mid-`!status` nil-deref'd and took down ingestion, the admin UI, SSE NOC, and alerting. Every `AddCallback` closure now recovers first (`logging.Recover("irc-callback-*")`), and `onConnected`/`onPrivmsg`/`handleCommand`/`isAdmin`/`onJoin` snapshot `b.Conn` under `b.mu.RLock` with a nil-check before use — the pattern `SendMessage` and `onQuit` already followed.

## [0.10.534] - 2026-07-01

### Fixed
- **Poller advisory work-lock no longer leaks across pooled connections (audit 2026-07-01 finding H9).** `pg_try_advisory_lock`/`pg_advisory_unlock` are session-scoped, but both ran through GORM's connection pool, so during a busy poll cycle the unlock routinely landed on a *different* Postgres backend than the lock. `pg_advisory_unlock` on a non-owning session returns `false` with only a WARNING — no SQL error — so the failed release was invisible: the lock sat on an idle pooled connection for up to 5 minutes and the next tick logged "Skipping poll cycle: another poller holds the work lock" and silently skipped the **entire** cycle (polling, offline detection, rollups, flow detection, threat feeds, cleanup) in a single-poller deployment. `TryAcquirePollerWorkLock` now pins a dedicated `*sql.Conn` — the exact pattern its sibling `AcquireAPISingletonLock` documents for this exact hazard — and returns a release func that unlocks on that same backend, checks the unlock's boolean, and returns the connection to the pool.
- **A panicked poller loop no longer becomes a permanent zombie behind green health checks (audit 2026-07-01 finding M30).** REL-01's SafeGo contained a `Start()`-loop panic but never restarted the loop, and `/readyz` only pinged the DB — so one bad tick silently killed polling, alerting, rollups, and cleanup forever while orchestrators and Prometheus saw green. Two complementary fixes: (1) the loop goroutine is now **supervised** — panic recovered per attempt, restarted with capped exponential backoff (1s→1m), clean exit only on `Stop()`; (2) `/readyz` now also requires a **loop heartbeat** within max(3× poll interval, 10 min), stamped at loop start, before each select wait, and when leader-locked work is picked up — a halted *or wedged* loop flips the daemon to not-ready. Regression test `TestPollerLoopHeartbeat_M30`.
- **`/readyz` DB probes are now bounded and the observability server has a write timeout (audit 2026-07-01 finding L15, same lines as M30).** Both the poller's and trap-receiver's readiness closures use `PingContext` with a 2-second deadline instead of an unbounded `Ping()` (which blocked forever when the pool was wedged — hanging the probe and leaking a goroutine per scrape instead of answering 503), and `StartObservabilityServer` sets `WriteTimeout: 30s`.

## [0.10.533] - 2026-07-01

### Fixed
- **The three sFlow-analytics tables with no retention path no longer grow without bound (audit 2026-07-01 finding H4).** `flow_rollups` terminal `'1d'` rows (one row per distinct conversation per day — 10^5–10^6 rows/day on a busy network), `flow_detections` (appended every 5-minute detection cycle, only ever flagged acknowledged), and `flow_agent_drops` (one row per agent/sampling-rate/window; the "bounded by agent count" model comment was wrong) were all absent from `CleanupOldData` — the same unbounded-growth shape as the historical `syslog_messages` incident. They now age out through the batched-delete cleanup path behind three new knobs, each documented in `config.env.example` (0 inherits `RETENTION_DEFAULT_DAYS`):
  - `RETENTION_FLOW_ROLLUP_DAYS` (default **365** — rollups are the long-term flow history; the cutoff covers every interval_type so stale 5m/1h rows are also dropped even if promotion were broken)
  - `RETENTION_FLOW_DETECTION_DAYS` (default **90**, ages on `detected_at`)
  - `RETENTION_AGENT_DROPS_DAYS` (default **30**, ages on `window_start`)
  - The batched cleanup helper is now column-parameterized (`batchedDeleteOlderThanOn`) since these tables age on non-`timestamp` columns. Regression test: `cleanup_flow_tables_h4_test.go`.

## [0.10.532] - 2026-07-01

### Fixed
- **Flow-rollup and syslog-summary aggregation can no longer silently double-count, lose, or destroy historical data (audit 2026-07-01 findings H1, H2, H3).** All four paginated GROUP BY aggregations (`aggregateFlowsToRollup`, `aggregateRollupsUp`, `aggregateSyslogToSummary`, `promoteSyslogSummaries`) now share one correctness shape:
  - **Deterministic pagination (H1):** every paged aggregate carries an `ORDER BY` over its full group key — previously PostgreSQL's hash/parallel aggregation gave no cross-query ordering, so `LIMIT/OFFSET` pages could overlap (double-counted bytes) or skip groups (silently lost) whenever a cycle exceeded one page (>50k flow groups — guaranteed in backlog-recovery cycles after downtime).
  - **Watermark-scoped immutable source set (H2b):** a `MAX(id)` watermark is captured first and every read AND the final delete are scoped to `id <= watermark`, so rows arriving mid-pass — e.g. a collector replaying its store-and-forward backlog with old timestamps — are never deleted un-aggregated; they wait for the next cycle. Previously the blanket `timestamp < cutoff` delete destroyed them.
  - **Single-transaction all-or-nothing pass (H2a):** page inserts and the consumed-row delete commit in one transaction. A mid-pass failure now rolls back completely and the next cycle retries identical work — previously committed pages survived while raw rows stayed, so the retry double-counted every already-inserted group.
  - **Promote-step page-1 destruction (H3):** `promoteSyslogSummaries` ran an *unscoped* delete inside each page's transaction, so page 1's commit destroyed every still-un-promoted hourly group beyond the first 5000 — unrecoverably, since the raw syslog behind them was already consumed. This was the same bug fixed in `aggregateSyslogToSummary` as M2 of the 2026-06-23 audit; the promote step had been missed. It now uses the shared shape with one scoped delete after all pages.
  - Regression tests: `rollup_integrity_h1h2h3_test.go` (multi-page no-loss/no-double-count on all three paths, byte-total preservation) with page sizes now test-shrinkable package vars (`flowRollupPageSize`, `syslogPromotePageSize`).

## [0.10.531] - 2026-07-01

### Docs
- **Recorded a maintainer-workflow lesson in `tasks/lessons.md`:** inspect external PR commit messages for attribution trailers before merging; when present, squash-merge and hand-edit the squash message rather than merge-committing the original commit verbatim. (Context: PR #50's commit body carried an attribution trailer that a plain merge preserved into master history; resolved via a one-time authorized history rewrite that kept the contributor's authorship intact.)

## [0.10.530] - 2026-07-01

### Fixed
- **Fresh `docker compose up` no longer crash-loops on first boot when no `ADMIN_PASSWORD` is set (audit 2026-07-01 finding H8).** The `/data` bind mount is auto-created `root:root` by Docker, shadowing the image-layer chown, and the entrypoint only chowned `/data/firewall-mon.db*` + `/config` — so `fwmon-api` hit EACCES persisting the auto-generated admin password to `/data/.admin-password`, `log.Fatalf`'d, and `restart: unless-stopped` looped forever. The entrypoint now applies a runtime **non-recursive** `chown fwmon:fwmon /data` (leaving `/data/pgdata` postgres-owned). *Contributed by @rovicomm in [#50](https://github.com/xphox2/Firewall-Monitoring/pull/50), who independently found and fixed the issue the audit flagged as H8 — the audit report is updated to mark H8 resolved with credit.*

## [0.10.529] - 2026-07-01

### Docs
- **Recorded a tooling lesson in `tasks/lessons.md`:** never round-trip a UTF-8 source file through Windows PowerShell 5.1 `Get-Content`/`Set-Content` — a BOM-less UTF-8 file is read as ANSI and every non-ASCII character is double-encoded into mojibake (this corrupted 38 comment lines in the collector's `main.go` during the v1.2.153 version bump before being caught by `git show --stat` and reverted). Single-line source edits go through a proper editor tool; scripted rewrites must be followed by a `git diff --stat` sanity check.

## [0.10.528] - 2026-07-01

### Added
- **Engineering audit 2026-07-01 (dual-repo, multi-agent consensus): `docs/audit-2026-07-01-consolidated.md`.** Deep adversarial audit of everything shipped since the fully-resolved 2026-06-23 audit (sFlow analytics R1–R6, SSE NOC, Console UI, probe lifecycle, collector rate-limiting/queue work). **64 confirmed findings** (server 52 / collector 12; 10 HIGH, 30 MEDIUM, 24 LOW), every one surviving adversarial refutation-based verification. Highest-risk clusters: paginated GROUP BY aggregations that can silently double-count or destroy rollup/syslog history (H1–H3), missing retention for the new flow tables (H4), the poller advisory work-lock leaking across pooled connections so a single poller skips its own ticks (H9), direct-link connection charts rendering cumulative counters as per-bucket deltas (H10), and collector rate-limiter/queue hardening gaps (H6/H7). Findings are documentation-only in this version — fixes land in follow-up commits per the report's suggested order. A collector-scoped copy ships in the collector repo.

## [0.10.527] - 2026-07-01

### Added
- **Wired the Tailwind CSS compile into the build (`make build`/`make docker`/`deploy.sh`).** These now run `npm install` + `npm run build` before `go build`, so `cmd/api/static/css/tailwind.css` is regenerated from source. This is safe now that `styles.css` is tokenized (v0.10.526): rebuilding no longer reverts the theming. `deploy.sh` skips the step with a warning if `npm` is unavailable, falling back to the committed `tailwind.css`.

### Changed
- **Expanded the design-token system into the chart/JS layer (continues the ~5%→ tokenization effort).** Replaced hardcoded hex in the admin JS with `AdminCommon.cssVar('--fwmon-*', fallback)` and `var(--fwmon-*)` so Chart.js axes/legends/tooltips and inline-styled widgets follow the Day/Night theme instead of a fixed dark palette (`admin-bw-chart.js`, `admin-device-detail.js`, `admin-probes.js`, `admin-sites.js`, `admin-irc.js`, `admin-main.js`). Each call keeps its previous hex as a fallback, so a missing `AdminCommon` degrades gracefully. Minor form-focus/toast polish in `admin-shared.css`.
- **Hid the redundant page-title `<h1>` header on the admin SPA and the standalone Probes/IRC pages.** The left-nav already names the current page, so the duplicate title row was removed (`display:none`) on `admin.html`, `probes.html`, and `irc.html`. *(Purely visual; revert the `display:none`/`justify-end` edits on those three files if the title row is wanted back.)*

_Note: regenerating `tailwind.css` against this settled markup produced no change — the edits only swapped already-present utilities and added inline styles/token vars, so the committed `tailwind.css` stays byte-for-byte reproducible._

## [0.10.526] - 2026-07-01

### Fixed
- **Made the Tailwind build reproducible so it no longer reverts the v0.10.500 theming fix.** The precompiled `cmd/api/static/css/tailwind.css` had been *hand-tokenized* at v0.10.500 (component classes `.card`/`.btn`/`.sidebar`/`.badge`/`.modal-content`/`.form-group`/… rewritten from hardcoded GitHub-dark hex to `var(--fwmon-*)` so standalone admin pages resolve in light mode), but its Tailwind **input** `styles.css` was never updated — it still emitted hardcoded `#0d1117`/`#30363d`/etc. Any `npm run tailwind` (now wired into `make build`/`make docker`/`deploy.sh`) regenerated `tailwind.css` from that stale input and silently reverted the tokenization, breaking light mode.
  - Tokenized `styles.css`'s `@layer base` + `@layer components` values to `var(--fwmon-*)` (the same mapping applied by hand at v0.10.500; `#fff` and the `rgba()` tints left intact), and regenerated `tailwind.css`.
  - Verified: the regenerated output's base+component layer is **byte-identical** to the committed tokenized file (theming preserved exactly, zero hardcoded component-class hex), the build is **deterministic** (two runs produce identical bytes), and it is now reproducible from committed sources. The only additive changes are utility-layer classes the content-scan picks up from markup that evolved since v0.10.500.

## [0.10.525] - 2026-07-01

### Fixed
- **NOC By Site | By Device toggle now hides the inactive grid.** Browser verification of the 0.10.524 NOC rework caught that switching to *By Device* left the site cards visible above the device cards: the `hidden` attribute on the grid was overridden by `.fwmon-noc-grid { display: grid }` (equal CSS specificity, author rule wins over the UA `[hidden]` rule). Added `.fwmon-noc-grid[hidden] { display: none }`.

## [0.10.524] - 2026-07-01

### Added
- **NOC reworked into a per-site → per-device operations breakdown, synced with the Connections map.** The NOC tab moves under **Monitoring** (right below Connections) and becomes a live health breakdown instead of a flow-analytics dashboard. The two Monitoring tabs now stay in sync:
  - **By Site | By Device** toggle. *By Site* shows one card per site (+ an **Unassigned** bucket for devices with no site): status dot, open-alert badges, devices up/total, and live throughput, colour-keyed to a **composite worst severity** — `max(open-alert severity, offline device → warning, offline probe → critical, down connection → warning)`, so a site with a dark device but no alert row no longer shows green. Clicking a site opens an in-page drill-down (device rows + site mini-vitals) that stays live. *By Device* is a flat, severity-sorted device grid.
  - **Alerts/issues reflect in the animation graph.** Device nodes on the connection map now pulse amber/critical-red from the same open-alert state shown on the NOC page (already-alerting nodes pulse on first open; a cleared/acked/snoozed alert stops pulsing within one status poll). The open-alert predicate matches the Alerts list exactly (excludes resolved / acknowledged / suppressed / snoozed).
  - **Cross-tab focus.** Selecting a site/device in the NOC focuses & zooms that node on the map (dimming the rest, with a **Clear focus** toolbar button); tapping a node on the map opens that device's NOC detail — both via seamless SPA navigation, no full reload.
  - **sFlow is now filterable by site.** Added a `site_id` filter to the flow samples/stats endpoints (an uncorrelated `device_id IN (SELECT id FROM devices WHERE site_id = ?)` subquery — no schema change) and a **Site** selector + active chip on the Flows page. NOC drill-downs link straight to the pre-filtered Flows and map views.
  - The per-site/device breakdown rides the existing NOC Server-Sent-Events hub (one computation serves every viewer — no new per-client poll), and the NOC snapshot endpoint accepts `?site_id=`/`?device_id=` for drill-down detail. The Live Detections feed is retained (collapsible); flow src/dst top-talkers now live on the Flows page.
  - Fixed a latent routing bug exposed by the new deep-links: `activateTabFromUrl()` omitted `noc`, so a hard-refresh/back onto `/admin/noc` resolved to the Dashboard.
- Regression tests: per-site rollup + Unassigned/orphan bucketing + composite severity (`GetNOCBreakdown`), the open-alert predicate feeding the map pulse (`GetDeviceAlertSeverities`), the site-scoped snapshot, and the `?site_id=` handler parse.

## [0.10.523] - 2026-07-01

### Fixed
- **Connection-page interface chart no longer just climbs.** The interface chart in the network-map side panel (and its twin on the connection-detail page) was plotting the **raw cumulative** SNMP octet counter as a line, so it only ever went up. It now delta+rates the counter (clamped across resets) through the shared component, like every other interface chart.

### Changed
- **Completed the 3-mode sweep across the remaining connection-page bandwidth charts.** The 0.10.522 sweep left the connection-page interface / VPN-tunnel / traffic charts as plain two-line Chart.js graphs; they are now the same 3-mode `FwmonBwChart` (Throughput Mbps / Transfer bytes-per-interval / Combined) used on the public dashboard and device-detail pages, each with its own mode toggle:
  - Network-map side panel: interface, VPN-tunnel, and connection-traffic charts (`diagram-panels.js`).
  - Connection-detail page: VPN-tunnel and connection-traffic charts (`admin-connection-detail.js`).
  - `FwmonBwChart.mount()` (new) renders a normalized series and injects the mode toggle above the chart box, preserving the selected mode across the 30s poll / range changes. Shared `normalizeCumulative` / `normalizeDeltas` helpers moved into the component so cumulative-counter vs. per-bucket-delta series are handled consistently everywhere. `admin-bw-chart.js` is now also loaded by the standalone connection-detail page.
- **Line graphs are now pointy, not curvy.** Every hand-written admin line chart had bezier smoothing (`tension` 0.3–0.4), which rounds corners and can visually overshoot real sample values. Set `tension: 0` across the admin UI (straight segments between points), matching monitoring-dashboard best practice. The device-detail uPlot charts already rendered straight lines (no spline).

## [0.10.522] - 2026-07-01

### Changed
- **Admin bandwidth graphs now match the public dashboard's 3-mode style.** Full sweep of every bandwidth/throughput-over-time chart in the admin panel:
  - **Flows page "Bandwidth Over Time"** — was a single-line uPlot chart; now uses the shared 3-mode `FwmonBwChart` (Throughput Mbps line / Transfer bytes-per-interval bars / Combined) with a mode toggle, exactly like the public dashboard. Flow traffic is a bidirectional aggregate, so it renders as one "Traffic" series — `FwmonBwChart` gained single-series support for this. (`admin-bw-chart.js` is now loaded by the admin SPA.)
  - **Connection side-panel + connection-detail "flows over time"** — was plotting the raw per-bucket byte total labeled "Total Bytes" (which reads like an ever-climbing line); now renders **throughput in Mbps** (per-bucket SUM ÷ bucket interval) with a Mbps axis/tooltip. `GetConnectionFlowStats` now returns `bucket_seconds` so the UI can compute the rate.
  - Already conforming, left unchanged: device-detail interface + VPN-tunnel charts (already 3-mode `FwmonBwChart`), device-detail system network throughput and connection tunnel-traffic (already per-interval rates, not cumulative).
  - No cumulative counters are plotted raw anywhere anymore. Backend behavior otherwise unchanged (one additive JSON field).

## [0.10.521] - 2026-07-01

### Fixed
- **Probe registration no longer 404s after a probe is renamed.** `RegisterProbe` looked the probe up by the *name* stored in its `probe_registration_<hash>` setting at create time; renaming the probe (allowed by `UpdateProbe`) left that name stale, so a collector re-registering got `404 "Probe not found — it may have been deleted"` even though the probe still existed. It now looks the probe up **directly by its stored (hashed) `registration_key`** — the same column heartbeat auth uses — and only falls back to the legacy name lookup. This self-heals existing diverged installs (no DB surgery needed) and eliminates the rename-divergence class of failure. An unknown key still returns 401.
- **Probes are now marked offline when their collector stops checking in.** A probe's `status` was stored and never re-derived, so a probe whose collector crashed/restarted-into-a-bad-state/lost-network stayed `"online"` in the UI indefinitely (its devices correctly went offline, but the probe itself didn't). The poller now runs `MarkStaleProbesOffline` each cycle on the same staleness threshold as its devices (3× poll interval, min 5 min), flipping stale `online` probes to `offline` and logging the transition. Mirrors the existing `MarkStaleProbeDevicesOffline` device sweep.
  - Tests: `MarkStaleProbesOffline` (only stale-online probes flip, idempotent) and register-by-key surviving a stale registration setting.

## [0.10.520] - 2026-07-01

### Docs
- **Documented the new runtime env knobs in `config.env.example`** so they're discoverable at deploy time: the sFlow detector thresholds (`DETECT_*`, with a note that the admin Settings page overrides them live) and the opt-in threat-intel auto-feed (`THREAT_FEEDS_*`). No behavior change — all have working defaults; this only surfaces them for operators. (GeoIP vars were already documented.)

## [0.10.519] - 2026-07-01

### Added
- **sFlow-native interface bandwidth on the device-detail page (R5b finish).** Each interface's throughput chart now prefers agent-pushed sFlow counters (`flow_if_counters`, R5b/schema v2) and transparently falls back to the SNMP-polled `interface_stats` when no sFlow data exists — so sFlow deployments get interface bandwidth even where SNMP is unreachable or host-restricted, while SNMP-only deployments are unchanged. A small "bandwidth source: sFlow/SNMP" label shows which feed is active.
  - Backend: `GetFlowInterfaceChartWindow` mirrors `GetInterfaceChartWindow` over `flow_if_counters`, exposing cumulative octets as `in_bytes`/`out_bytes` in the identical `InterfaceChartBucket` shape — so the frontend's existing delta+rate normalisation renders both sources the same way and they stay visually consistent. New `GET /admin/api/devices/:id/interfaces/:ifIndex/sflow-chart` (same response shape + adaptive bucketing + drag-to-zoom window as the SNMP endpoint).
  - Frontend: `loadInterfaceChart` fetches the sFlow endpoint first and falls back to the SNMP one; both go through the same `FwmonBwChart` render path.
  - Test: `GetFlowInterfaceChartWindow` window/interface scoping + cumulative-octet round-trip + empty-window fallback signal.

## [0.10.518] - 2026-07-01

### Fixed
- **PostgreSQL integration test time-bomb (`TestPostgresIntegration/TimeBucketRoundTrip`).** The test inserted a `system_status` row with a hard-coded `2026-06-02` timestamp, but that table is monthly RANGE-partitioned and `EnsurePartitions` only creates the current + future months — so once the calendar rolled into July the June partition no longer existed and the insert failed with SQLSTATE 23514 ("no partition of relation found for row"), turning the Integration (PostgreSQL) CI lane red on the first run of the new month. The test now derives the row's day from `time.Now()` (always inside a live partition) at a fixed intra-day time, keeping the to_char↔Go bucket-layout assertions deterministic. Server-behavior unchanged; test-only fix.

## [0.10.517] - 2026-06-30

### Removed
- **Removed the last vestigial `cmd/probe` remnants.** The `cmd/probe/` binary itself was deleted long ago (v0.10.412), but two `internal/shell` static-guard tests (`probectx_audit087_test.go`, `probe_audit159_test.go`) still `os.ReadFile("../../cmd/probe/main.go")` and silently `t.Skip`ped since the file no longer exists — dead weight testing a deleted binary. Both are removed. (The `schema_version` handshake guard and the backoff/jitter test that merely *mention* cmd/probe in comments are kept — they test current code.)

## [0.10.516] - 2026-06-30

### Added
- **sFlow analytics R6 — real-time NOC dashboard.** A new **NOC** page (`/admin/noc`, in the Data nav section) streams live operations via Server-Sent Events: one in-process broadcaster recomputes a snapshot every 5s over a trailing 5-minute window and fans it out to all connected dashboards (one DB computation serves every viewer). Six zones: throughput vitals (live bps, flows, unique src→dst, threat-flow count, probe up/down, active threat-intel IPs), Top Sources, Top Destinations, By Application, By Direction, Top Countries (hidden without GeoIP), and a live Detections feed (last 15 min, most-severe first).
  - Backend: `GetNOCSnapshot(window)` lightweight aggregate (bounded top-N over raw flow_samples) + `nocHub` broadcaster + `GET /admin/api/noc/stream` (SSE, cookie-auth so EventSource just works) and `GET /admin/api/noc/snapshot` (one-shot fallback). The SSE handler clears the per-connection write deadline so the stream isn't severed by `SERVER_WRITE_TIMEOUT`, sends keepalive comments, and tears down cleanly on client disconnect.
  - Frontend: `admin-noc.js` EventSource consumer with auto-reconnect + a live/reconnecting status pill; the stream is closed when navigating away from the page.
  - Tests: `GetNOCSnapshot` window aggregation (throughput, threat-flow count, top talkers, old-flow exclusion).

  Note: data refreshes each collector batch (~30s), so flow aggregates step per batch while detections/threat counts feel live. Deferred from the R6 plan (separate follow-ups): collector-side SO_REUSEPORT worker pool + per-agent rate limit, and removal of the stale `cmd/probe`.

## [0.10.515] - 2026-06-30

### Added
- **Admin-UI control for the sFlow detection thresholds.** A new "sFlow Detection Thresholds" card on the Settings page exposes all seven detector knobs (port-scan ports, super-spreader hosts, data-exfil bytes, the three C2-beacon params, and capacity utilisation) as editable fields. Edits are stored in `system_settings` (category `detection`) and the poller reads them **live at the start of each detection cycle**, so a change takes effect within ~5 minutes with no restart. A blank field falls back to the `DETECT_*` env value and then the built-in default (shown as the input placeholder), so DB > env > default. This makes the v0.10.514 env knobs editable from the UI without redeploying.
  - Backend: the seven `detect_*` keys are added to the settings allowlist with range validation; the poller overlays them onto the env baseline via a pure, unit-tested `applyDetectSettings`.

## [0.10.514] - 2026-06-30

### Added
- **Configurable sFlow detector thresholds (`DETECT_*` env).** The detection-engine thresholds are now operator-tunable instead of hard-coded: `DETECT_PORT_SCAN_PORTS`, `DETECT_SUPER_SPREADER_HOSTS`, `DETECT_DATA_EXFIL_BYTES`, `DETECT_BEACON_MIN_SAMPLES`, `DETECT_BEACON_MAX_AVG_BYTES`, `DETECT_BEACON_MAX_CV`, `DETECT_CAPACITY_THRESHOLD`. Any unset knob keeps the built-in default.
- **Threat-intel auto-population from free open-source feeds (opt-in `THREAT_FEEDS_ENABLED`).** A poller job (leader-locked, default every 12h, initial sync ~1 min after start) fetches reputable free bad-IP lists — blocklist.de, CINS Army, Spamhaus DROP, Emerging Threats compromised, and Tor exit nodes — and upserts them into the threat-intel feed with a TTL (`THREAT_FEEDS_TTL_DAYS`, default 14). Indicators that drop off a feed expire and are pruned; permanent manual entries are never touched. Tunable with `THREAT_FEEDS_INTERVAL`, `THREAT_FEEDS_EXTRA_URLS` (custom `name|url|category|severity` records), and `THREAT_FEEDS_DISABLE_BUNDLE`. The ingest matcher picks up new indicators on its normal ~15-min refresh. New `internal/threatfeed` package (bounded download + tolerant parser).

### Changed
- **`port_scan` default threshold raised 20 → 100 distinct destination ports** to stop false positives (20 ports in a 15-minute window is easily reached by a busy legitimate host). Override with `DETECT_PORT_SCAN_PORTS`.
- **`port_scan` now escalates to `critical` and is labelled "KNOWN-BAD source" when the scanning IP is on the threat-intel feed** (the flow's `threat_flag`), so a real attacker scan stands out from a tuning false-positive.

### Fixed
- **Latent v14 bug: the `threat_intel` CIDR column was named `c_id_r` by GORM** while every `ON CONFLICT` clause referenced `cidr` — so a duplicate `(cidr, source)` upsert errored (manual re-adds and any feed re-population). The column is now pinned to `cidr` (migration v17 renames it on Postgres; the unique index follows).

## [0.10.513] - 2026-06-29

### Added
- **sFlow analytics R5b — interface counter samples (schema_version 2).** The server now ingests sFlow `counters_sample` interface counters (the agent-pushed equivalent of SNMP ifSpeed/ifInOctets/ifOutOctets), gated behind a relay schema-version bump.
  - **Schema v2**: `SchemaVersionMax` 1→2 (Min stays 1). The new `POST /api/probes/:id/flow-counters` endpoint is only used by collectors that negotiated v2, so a v1 collector ↔ v2 server and v2 collector ↔ v1 server both keep working unchanged. Requires Collector v1.2.145+ to send the data.
  - **`flow_if_counters` table** (migration v16, not partitioned): per-interface ifSpeed + cumulative in/out octets, errors, and discards. Retention-pruned alongside `flow_samples` (`RETENTION_FLOW_DAYS`).
  - **Capacity detector** now falls back to the sFlow-reported ifSpeed when SNMP `interface_stats` has no speed for the interface (e.g. when SNMP is host-restricted) — so utilisation alerts work even where SNMP can't reach the device.
  - Tests: counter round-trip + latest-lookup; capacity detector firing via sFlow ifSpeed fallback; schema-handshake assertions updated to v2.

## [0.10.512] - 2026-06-29

### Added
- **sFlow analytics R5a — BGP/AS-path enrichment from sFlow `extended_gateway`.** When the collector forwards BGP routing context (from the sFlow extended_gateway record), the server now stores it and prefers BGP-sourced AS numbers over the GeoLite2 lookup.
  - `FlowSample` gains `as_path` (space-separated dst AS path) and `next_hop` (BGP next-hop, varchar(45)) columns — migration v15. Both stay empty for non-BGP samplers, so the cost on the flow firehose is negligible.
  - Ingest precedence: BGP `src_as`/`dst_as` (sent by the collector as `omitempty` wire fields, like `drops`) populate `src_asn`/`dst_asn`; GeoLite2 then fills only the AS numbers BGP didn't provide. The Top ASNs widget automatically reflects the more accurate routing-sourced ASNs.
  - Backward-compatible both directions: the BGP fields are additive `omitempty` JSON on the existing `/flows` endpoint, so old collector ↔ new server and new collector ↔ old server both work unchanged (no schema-version bump). Requires Collector v1.2.144+ to populate the new data.
  - Tests: as_path/next_hop column round-trip + BGP-derived ASN persistence; COPY-column guard updated.

## [0.10.511] - 2026-06-29

### Added
- **Threat Intelligence management UI** on the Flows page. A collapsible "Threat Intelligence" card lets operators curate the known-bad address feed by hand — no more API/curl-only. Add a CIDR or IP with category, severity, optional source, and optional expiry; the table lists current entries with per-row Delete. A status line shows the active entry count and how many prefixes are live in the in-memory matcher, so you can confirm the ingest path is using the feed. Adds/deletes refresh the matcher immediately (server-side) and the list re-loads. Backed by the v0.10.510 `GET/POST/DELETE /admin/api/flows/threat-intel` endpoints.

## [0.10.510] - 2026-06-29

### Added
- **sFlow analytics R4 — threat intelligence + security detectors.** Adds a curated known-bad address feed and five security detectors to the existing detection engine.
  - **Threat-intel feed** (`threat_intel` table, migration v14): CIDR/IP entries tagged with category, source, severity, and optional expiry, keyed unique on (cidr, source). Loaded into an in-memory CIDR matcher (`internal/threatintel`) and consulted at ingest — no per-row DB lookup. The API process reloads the matcher every 15 minutes so feed edits and expiries take effect without a restart.
  - **`threat_flag` bitfield** on `flow_samples` (migration v14): set at ingest (bit 0 = source known-bad, bit 1 = destination known-bad).
  - **Security detectors** (`internal/detect`): `port_scan` (many distinct dst ports from one source), `super_spreader` (many distinct destinations), `data_exfil` (large outbound transfer to a single external host), `threat_intel` (aggregates threat-flagged flows), and `c2_beacon` (periodic small callouts via inter-arrival coefficient-of-variation — info-severity heuristic, documented sampling caveat). All run in the poller detection cycle under the leader lock and surface in the Detections panel + as `SFLOW_*` alerts.
  - **Threat-intel API**: `GET /admin/api/flows/threat-intel` (list + active/loaded counts), `POST` (upsert one entry, validates CIDR, refreshes matcher), `DELETE /:id`. Intended as the feed-curation surface for manual entries or automation.
  - Tests: matcher (CIDR/IPv6/expiry/nil-safety), all five detectors against synthetic flows, threat-intel filter narrowing, COPY-column guard.

## [0.10.509] - 2026-06-29

### Changed
- **Flows page "Top Countries" and "Top ASNs" widgets are now click-to-filter too.** Clicking a country or ASN narrows the whole Flows page (top talkers, conversations, chart, raw samples) to traffic destined for that country/AS, with a removable chip and URL-mirrored state; clicking the active row clears it. Completes the click-to-filter coverage for all classification/geo breakdowns.
  - Backend: `FlowStatsFilter` gains `DstCountry`/`DstASN`; `GetFlowStats` and `GetFlowSamples` honor `dst_country` / `dst_asn` query params.
  - Frontend: country rows filter by their ISO code; ASN rows display `AS<n>` but filter by the bare number. Reuses the existing click-to-filter / URL-hash / chip machinery.
  - Test: `GetFlowStats` destination-country and destination-ASN filter narrowing.

## [0.10.508] - 2026-06-29

### Fixed
- **Flows page "By Application" and "By Direction" widgets are now click-to-filter** (they were read-only in v0.10.505). Clicking a category or direction row now narrows the entire Flows page — top talkers, conversations, chart, and the raw samples list — and adds a removable filter chip; clicking the active row clears it. State is mirrored in the URL like the other filters, so the view is shareable/reload-safe.
  - Backend: `FlowStatsFilter` gains `AppCategory`/`Direction`; `GetFlowStats` and `GetFlowSamples` honor the new `app_category` / `direction` query params.
  - Frontend: the two widgets map their display labels to the numeric ids the backend stores (mirroring `internal/classify`), wired through the existing click-to-filter / URL-hash / chip machinery.
  - Test: `GetFlowStats` category + direction filter narrowing.

## [0.10.507] - 2026-06-29

### Added
- **sFlow detection engine — good-vs-bad traffic findings (sFlow analytics expansion, increment 3).** A pluggable engine now scans recent flows on a timer and surfaces operational and policy problems as reviewable detections that also feed the alert system.
  - New `internal/detect` package: a `Detector` interface + `Window` + ordered `Registry`, each detector a bounded SQL aggregation over recent `flow_samples` (using the R1/R2 classification columns). Ships four detectors:
    - **cleartext** (policy) — legacy unencrypted protocols (Telnet, FTP, TFTP, POP3, IMAP).
    - **unexpected_egress** (policy) — admin/DB protocols (SMB, RDP, SQL engines, Redis, Mongo) leaving the network outbound to public addresses.
    - **sampling_backoff** (operational) — sFlow agents dropping samples (under-reported traffic / overloaded agent), from `flow_agent_drops`.
    - **capacity** (operational) — per-interface egress estimated from sampled bytes vs SNMP link speed; warning ≥80%, critical ≥95% (handles the ifSpeed 2³²−1 saturation → ifHighSpeed fallback).
  - The poller runs the engine every 5 minutes under its leader lock over a 15-minute window, persists every finding, then feeds each to the alert engine. Detections are stored even when no alert fires, so the NOC sees sub-threshold signal.
  - Migration **v13** (`flow_detections_table`) adds the bounded (non-partitioned) `flow_detections` table.
  - New `AlertManager.ProcessFlowDetection` mirrors `ProcessSyslog`/`ProcessTrap` — same cooldown / policy-resolution / notify path, AlertType `SFLOW_<DETECTOR>`. **Observe-mode:** detectors ship at info/warning so a noisy detector can't page anyone; tune later via alert policies.
  - API: `GET /admin/api/flows/detections` (window/limit/unacked filters) + `POST /admin/api/flows/detections/:id/ack`. The Flows page gains a Detections panel (severity-ranked, acknowledge-to-dismiss) that appears only when there are findings; detections also surface on the alerts page via the new `SFLOW_*` types.
  - Regression tests: each detector (fire / don't-fire boundaries), `RunAll` model mapping, and the persistence Save→GetRecent→Ack round-trip with window + unacked filters.

## [0.10.506] - 2026-06-29

### Added
- **sFlow Geo-IP + ASN enrichment (sFlow analytics expansion, increment 2).** Flows are now tagged at ingest with the source/destination country and autonomous-system number, so the Flows page can answer "where is this traffic going, and on whose network."
  - New `classify.GeoResolver` wraps MaxMind GeoLite2 (`github.com/oschwald/geoip2-golang`): memory-mapped, goroutine-safe `Country()`/`ASN()` lookups. Fully nil-safe — a disabled or failed-to-open resolver returns empty results instead of panicking, so geo is a no-op when not configured.
  - Opt-in via `GEOIP_ENABLED` (default false) + `GEOIP_DB_DIR`. The `.mmdb` files are licensed and not shipped; in Docker they're an optional read-only volume mount (`GEOIP_DIR` → `/etc/firewall-mon/geoip`). When off or the files are absent, the columns stay empty and the Flows page hides the geo widgets — no crash, no hard dependency.
  - `ReceiveFlowSamples` stamps `src_country`/`dst_country` (ISO alpha-2) and `src_asn`/`dst_asn` per sample (server-side; no collector change). GeoLite2 maps only public IPs, so internal/RFC1918 endpoints simply stay empty.
  - Migration **v12** (`flow_geoip_columns`) adds the four columns to `flow_samples` (`varchar(2)` country, `bigint` ASN) and the destination pair (`dst_country`/`dst_asn`) to `flow_rollups` — carried through the rollup `GROUP BY` (no cardinality increase; both are determined by `dst_addr`) so the Top Countries / Top ASNs views survive after raw samples age out.
  - `GET /admin/api/flows/stats` returns `top_countries` and `top_asns` (destination bytes, raw + rollup merge, unmapped excluded); the Flows page shows two new "Top Countries" / "Top ASNs" widgets that appear only when geo data is present.
  - Regression tests: `GeoResolver` disabled/missing-file graceful paths, `GetFlowStats` Top-Countries/Top-ASNs aggregation, and the updated COPY-column-order guard.

## [0.10.505] - 2026-06-29

### Added
- **sFlow traffic classification — "what kind of traffic, and which way" (sFlow analytics expansion, increment 1).** Flow records are now classified at ingest into an application/L7 category and a direction, turning the Flows page from "IPs, ports, and protocol numbers" into traffic the operator can reason about.
  - New `internal/classify` package: `Classify(proto, srcPort, dstPort, tcpFlags)` maps a flow to an application `Category` (Web, DNS, Email, File Share, VPN, Database, Remote Access, Streaming, VoIP, Backup, Management, P2P, ICMP) via a curated `(proto, port)` table plus protocol-only fallbacks for portless protocols; `Direction(src, dst, …)` classifies the flow as Inbound / Outbound / Internal / External from RFC1918/ULA/link-local/CGNAT membership. Pure, allocation-free functions with full truth-table unit tests.
  - `ReceiveFlowSamples` stamps `app_category` and `direction` on every sample at ingest (cheap per-sample, server-side — no collector change). Both ride the existing pgx `CopyFrom` bulk insert as two new narrow `SMALLINT` columns.
  - Migration **v11** (`flow_classification_columns`) adds `app_category`/`direction` to `flow_samples` and `flow_rollups` (`smallint NOT NULL DEFAULT 0`, metadata-only on PG11+, routed through `execMaintenanceDDL`). The columns are carried onto rollups (added to the rollup `GROUP BY`, no cardinality increase since they're functionally determined by the 5-tuple) so the breakdowns survive after raw samples age out.
  - `GET /admin/api/flows/stats` now returns `by_category` and `by_direction` (raw + rollup merge), and the Flows page shows two new breakdown widgets ("By Application", "By Direction"). Read-only for now; click-to-filter on these dimensions is a planned follow-up.
  - Regression tests: classification truth tables (`internal/classify`), `GetFlowStats` By-Category/By-Direction aggregation, and the updated COPY-column-order guard.

## [0.10.504] - 2026-06-28

### Changed
- **Palette refresh — professional blue accent, neutral graphite base.** Replaced the "volt" aqua-cyan interaction accent and the teal-tinted base with a clean professional blue (Tailscale/GitHub register) on a neutral graphite base. Night accent `#4c8dff` / base `#0d1117`+`#161b22`; day accent `#2563eb` / base `#f2f4f7`. `--fwmon-series-1` follows the accent so chart line 1 + its fill are on-brand. The thermal severity ramp (jade/amber/orange/red/magenta for status) is unchanged. Surface depth/elevation from v0.10.502 retained.
- **Theme toggle now on every admin page, in the same place.** The Day/Night switch previously lived only in the SPA sidebar footer; the standalone pages (device-detail, connection-detail, probes, sites, irc) had none. Moved the `.theme-switch` styles into the shared `admin-design-system.css`, added the toggle markup to every standalone footer, and added the pre-paint theme script (`{{ .Nonce }}`-guarded) + `data-theme` to each so the saved choice applies flash-free everywhere.

### Fixed
- **Day-theme contrast on the device-detail page.** `admin-device-detail.css` had hardcoded dark surfaces (`.device-banner`, `.kpi-card`/`.kpi-subcard`, table headers, core-bar wrappers) that never flipped for the light theme, plus hardcoded light-blue/green/white text (`#7dd3fc`, `#86efac`, `#fff`) that went invisible on light tints. Repointed all of them to theme tokens via `color-mix(...)` so the page themes correctly in both Day and Night (root cause: hardcoded hex instead of role tokens).
- **Chart area-fill gradients now rebuild on theme toggle.** The Day/Night recolor pass (`recolorChartsForTheme`) previously updated axes/legend/tooltip but left the line-fill gradient baked at creation time. It now rebuilds each line dataset's fill from a shared `AdminCommon.fillGradient()` helper (also used by `createChart()`), so flipping the theme updates the fill intensity and point borders, not just the axes.

`go build ./...` + `go test ./...` green; AUDIT-066/067 contrast tests pass; verified both themes by headless screenshot.

## [0.10.503] - 2026-06-28

### Changed
- **Punchier chart area-fill gradients in the night theme.** The dashboard Activity Trend line fills were a faint flat-alpha ramp that the dark surfaces swallowed. `createChart()` now derives the fill from each line's own color via a `hexToRgb()` helper (no per-color hardcoding) and builds a richer **theme-aware multi-stop gradient** — dark gets a stronger `0.46 → 0.16 → 0` ramp for real presence, light stays tasteful at `0.22 → 0.06 → 0`. Point markers now border with the `--fwmon-card-bg` token so they read on either theme, and the Activity Trend line colors were aligned to the Console palette (volt `#38e1ff` / amber `#e7b53c` / red `#f2555a`, replacing the pre-redesign blues). Verified both themes by headless screenshot. `go build ./...` + `go test ./...` green.

## [0.10.502] - 2026-06-28

### Changed
- **Night theme polish — depth and crispness to match the day theme.** The dark theme read flat/washed next to light: cards barely separated from the base (both near-identical luminance) and the dim/engraved labels looked faded. Tuned the **dark token set only** (day theme untouched): deepened the base (`--fwmon-bg` → `#080d12`), lifted the card/panel surfaces (`--fwmon-card-bg` → `#141f29`) and strengthened the steel hairline (`--fwmon-border` → `#2c3c47`) so surfaces separate clearly; brightened the text ramp (`--fwmon-text` `#e8eff3`, `-faint` `#9eb2bb`, `-mute` `#748892`) so labels stay crisp; and reworked elevation to a Linear/Grafana-style **inset top-highlight + deeper drop shadow**. Applied `box-shadow: var(--fwmon-elev-1)` to `.card` / `.stat-card` / `.chart-card` / `.probe-card` (theme-aware: a soft light shadow in day, the lift treatment in night). Verified both themes by headless screenshot; AUDIT-066/067 contrast regression tests stay green. `go build ./...` + `go test ./...` green.

## [0.10.501] - 2026-06-28

### Changed
- **Charts redraw instantly on Day/Night toggle.** Previously a theme switch only recolored CSS-styled elements; already-rendered charts kept their old axis/grid/legend colors until the next data refresh. Now the `fwmon:themechange` event drives an immediate repaint:
  - **Chart.js** (dashboard, connections, device-detail, diagram panels): `setupChartDefaults()` reads Console tokens via a new `AdminCommon.cssVar()` helper instead of hardcoded hex, and a `recolorChartsForTheme()` listener walks every live instance (`Chart.getChart`) — recoloring scales/grid/ticks/legend/tooltip and calling `update('none')` (no animation, no refetch).
  - **uPlot** (device-detail time-series, flows bandwidth): axis/grid/tick colors are now read from `--fwmon-axis-stroke` / `--fwmon-grid-stroke` / `--fwmon-tick-stroke` at build time (the old hardcoded white-on-dark values were invisible in light mode). On theme change each page rebuilds its uPlot charts from cached data (`state.lastBuckets` / `lastBwData`) — instant, no network — destroying first so the device-detail overview's in-place `setData` reuse path doesn't retain the stale axis stroke.
  - Verified end-to-end with a headless browser: toggling the switch flips `Chart.defaults.color` and repaints live instances to the new theme tokens. `go build ./...` + `go test ./...` green.

## [0.10.500] - 2026-06-28

### Changed
- **Console design language — coverage extended to every admin page + Day/Night now correct site-wide.** Follow-up to v0.10.499. The standalone admin pages (`device-detail`, `connection-detail`, `probes`, `sites`, `irc`) had their own inline-`<style>` and Tailwind arbitrary-hex colors still on the old GitHub-dark palette; these are now tokenized to `var(--fwmon-*)`, and a new **`admin-tw-bridge.css`** (linked last on every admin page) maps the precompiled Tailwind arbitrary-hex utilities (`bg-[#161b22]`, `text-[#8b949e]`, …) to Console tokens. `admin-device-detail.css` tokenized too.
- **Root-cause fix in `tailwind.css`.** The precompiled `tailwind.css` carried a hardcoded `body{background:#0d1117}` plus a full set of hardcoded-GitHub-dark **component classes** (`.card`, `.btn`, `.sidebar`, `.badge`, `.modal-content`, `.form-group`, `.probe-card`, …) that — on pages where it loads after `admin-shared.css` — overrode the tokenized styles and forced the light theme to render dark. The component-class **values** are now tokenized to `var(--fwmon-*)` (the escaped arbitrary-value utility *selectors* are left intact and handled by the bridge). Light mode now resolves correctly on every admin page. `login.html` (a separate self-contained surface) is intentionally untouched.
- Added white-text-safe `--fwmon-btn-ok` / `--fwmon-btn-ok-hover` action-green tokens (legacy create/confirm buttons keep white text). Updated `TestIRCTab_ActiveRuleExists_AUDIT049` to assert the tokenized `border-bottom-color: var(--fwmon-accent)`. `go build ./...` + `go test ./...` green.

## [0.10.499] - 2026-06-28

### Changed
- **Admin SPA visual identity redesign — the "Console" design language.** Replaced the templated GitHub-dark (`#0d1117` + single blue `#58a6ff` accent) look — and the ~850-line `!important` "Premium NOC" override block that defeated the design tokens — with an instrument-console identity built on a real token system. **Palette:** a deep teal-graphite "instrument bezel" base (not GitHub near-black); state is carried by a functional **thermal severity ramp** (jade → amber → orange → red → magenta = heat rising = severity rising) instead of one accent; a single cool "volt" cyan (`#38e1ff`) reserved strictly for interaction (focus/active-nav/links). **Typography:** self-hosted **Archivo** (new `cmd/api/static/fonts/archivo-latin.woff2`) as the broadcast/instrument display face for titles and readouts (replacing the long-dangling, never-loaded "Plus Jakarta Sans" reference); **JetBrains Mono** promoted to first-class for all network data (IPs, ports, byte counts, rates, counts) with `tabular-nums`; a real type/spacing scale replaces ~22 ad-hoc sizes. **Signature element:** a persistent **Vitals Rail** across every SPA view (`#vitals-rail`, populated by `AdminCommon.refreshVitals()` from `/dashboard` + `/probes` + `/syslog/stats`) whose ambient left edge warms with the single worst active severity. **Sidebar** restyled as an instrument channel-strip (engraved section labels, volt signal-tick on the active item, `FIREWALL·MON` lockup + live status dot).
- **Day/Night theme.** Added a light "daylight brushed-aluminium" variant alongside the default dark NOC theme; both live as `:root[data-theme]` token sets in `admin-design-system.css` (signal ramp + volt darkened for AA on light). A DAY/NIGHT switch in the sidebar footer persists to `localStorage` via `AdminCommon.setTheme()`, with a pre-paint inline script in `admin.html` to avoid a flash. Chart-axis tokens are now theme-aware and a `fwmon:themechange` event is dispatched on toggle.
- **Token consolidation.** The `admin.html` inline `<style>`, `admin-shared.css`, and `admin-flows.css` now consume `var(--fwmon-*)` role tokens instead of hardcoded hex, so the whole shared design system (and every page that links it) reskins from one place and honors the active theme. Tailwind arbitrary-hex utilities baked into the precompiled `tailwind.css` are bridged to tokens in `admin-design-system.css`. No structural HTML/JS behavior changes. `go build ./...` green.

## [0.10.498] - 2026-06-27

### Changed
- **Operations report redesign — modernized the email/preview HTML and made the email body Gmail-safe.** The shared `internal/report` template (`template_report.go`) was reworked with a Plus Jakarta Sans type system, a gradient brand accent, refreshed verdict/KPI/bandwidth/spike/device styling, a mobile-responsive `@media (max-width:600px)` layout, and a full dark-themed `.admin-preview` skin (plus print-mode overrides) so the in-admin preview matches the console's dark UI. SVG throughput and CPU/Mem charts gained subtle `feDropShadow` filters. **New `IsEmail` rendering mode** (`ReportModel.IsEmail` / `DeviceCard.IsEmail`, set in `BuildReport` when not collapsible): the emailed body now omits all embedded SVG charts — which Gmail clips on large messages — and substitutes compact text summaries (a "Resource Trends" CPU/Mem/busiest-link block, an alert-totals paragraph, and a "view in Web Console" footer note), while the admin web preview keeps the full interactive SVG charts. Email reports remain image-free with zero CID attachments. Tests updated: `report_test.go` asserts the web preview contains `<svg>` and the email body contains none (plus the "Resource Trends" fallback); `render_validate_test.go` skips the strict SVG-XML well-formedness check for `IsEmail` reports and instead asserts no SVG fragments are emitted. `gofmt` / `go build ./...` / `go test ./...` green.

## [0.10.497] - 2026-06-25

### Fixed
- **Flow samples actually failed because the `drops` column was missing from existing `flow_samples` tables — added it (migration v10).** This is the real cause of the probe `Failed to send flows batch: status 500 {"error":"Failed to save flow samples"}` loop; the server log showed `column "drops" of relation "flow_samples" does not exist (SQLSTATE 42703)`. The `Drops` field (sFlow v5 §3.1.1 sample-pool drops) was added to the `FlowSample` model and to `saveFlowSamplesPGX`'s COPY column list in the 2026-06-22 audit, but **no migration ever added the column to databases created before the field existed**: `cmd/api` boots with `RunMigrations()` only (there is no per-startup `AutoMigrate`), and the baseline `AutoMigrate` (v1) had already been recorded as applied, so it never re-ran to pick up the new field. Every COPY then named a column the table lacked and failed at parse time, before any row data was evaluated, so the whole batch 500'd and the collector re-queued it forever. Fix: migration **v10 `flow_samples_add_drops_column`** runs `ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS drops bigint NOT NULL DEFAULT 0` (metadata-only on PostgreSQL 11+, no table rewrite; routed through `execMaintenanceDDL` so the lifted `statement_timeout` covers a partitioned table propagating the ADD; SQLite path uses idempotent `AutoMigrate`). Verified against the live schema with `\d flow_samples`. **Correction to 0.10.496:** the v9 "widen int columns" change was a misdiagnosis — the live schema confirmed GORM's Postgres dialect already maps the unsigned `FlowSample` fields to wide-enough columns (`src_port`/`dst_port` = `integer`, the `uint32` fields = `bigint`), so v9 is a verified no-op (every `ALTER ... TYPE` targets the type the column already has) and was never the fix. It and the explicit `gorm:"type:..."` tags are retained as harmless, defensive pinning of the column widths. `go build` / `go vet` / `go test ./...` green.

## [0.10.496] - 2026-06-25

### Fixed
- **Flow samples failed to save with HTTP 500 — `flow_samples` integer columns were too narrow for their unsigned values, aborting the whole pgx COPY batch.** Probes were logging `Failed to send flows batch: status 500 {"error":"Failed to save flow samples"}` and re-queuing the same flows every cycle, so no sFlow data was ever persisted. Root cause: GORM's Postgres dialect picks a column type from a Go int's **bit width and ignores signedness**, so the `FlowSample` UNSIGNED fields were mapped to signed columns one size too small — `src_port`/`dst_port` (`uint16`, 0–65535) → `smallint` (max 32767), and `sequence_number`/`sampling_rate`/`input_if_index`/`output_if_index` (`uint32`, 0–4.29B) → `integer` (max 2.15B). A single realistic value (an ephemeral source port of 54321, or an sFlow sequence number past 2³¹) overflows the column, and because `saveFlowSamplesPGX` inserts via a single `COPY`, that one row fails the entire batch. Fix: pinned the columns to types that hold the full unsigned range via `gorm:"type:integer"` / `gorm:"type:bigint"` tags (correct on fresh installs) and added migration **v9 `flow_samples_widen_int_columns`** — a Postgres `ALTER COLUMN ... TYPE` that widens existing deployments (ports → `integer`, the `uint32` fields → `bigint`). The widening is lossless and `ALTER ... TYPE` is a no-op when the column already matches, so the migration is idempotent; it is Postgres-only (SQLite uses dynamic typing and has nothing to overflow). Added a reflection-based regression test pinning the type tags so a future refactor can't silently drop them. Collector side needed no change — its re-queue behaviour was already correct. `go build` / `go test ./...` green.

## [0.10.495] - 2026-06-25

### Docs
- **Documentation accuracy sweep — marked the 2026-06-23 audit fully resolved and reconciled every doc with the current code.** `docs/audit-2026-06-23-consolidated.md` and `docs/FEATURE-ROADMAP.md` now show all server findings (HIGH H1–H8, the MEDIUM cluster incl. M8, REL-01/REL-04, the dependency/base bumps, and both large refactors) as ✅ resolved — the only remaining work is explicitly labelled optional engineering headroom, not audit debt. `docs/AUDIT.md` cross-references the resolved follow-up audit. Corrected stale/inaccurate claims found by a code-vs-docs verification pass: the SNMP vendor list (six registered profiles — FortiGate/Palo Alto/SonicWall/pfSense/OPNsense/Firewalla; **no "generic" SNMP profile**; Cisco ASA is config-diff only) in `README.md`, `docs/FEATURES.md` (support matrix), and the prose; the `VendorProfile` interface in `docs/custom-vendor.md` (dropped the non-existent `SSLVPN*` methods; `GetAllVPNTunnels` returns `([]models.VPNStatus, error)`); the README architecture tree (now lists all 23 `internal/` packages with accurate one-liners, incl. `relay` = probe↔server wire contract); `CONTRIBUTING.md` (Go 1.25+, real test-coverage candidates, removed the false "OPERATIONS.md is missing" note); `THIRD-PARTY-NOTICES.md` (full `go-ircevent` pseudo-version); and `docs/OPERATIONS.md` (health endpoint documents the `/api/readyz` alias, the M8 503-on-undecryptable-secrets behaviour and `"encryption"` JSON field, and the poller/trap fail-fast). Docs-only — no code or behaviour change; version bump for traceability.

## [0.10.494] - 2026-06-25

### Changed
- **Decoupled the API handlers from the `*database.Database` god-object behind a `database.Store` repository interface (2026-06-23 audit follow-up).** The high-value file-level split (the 4887-line `database.go` and the monolithic `handlers.go` into per-domain files) already shipped as AUDIT-072, leaving both structs lean (10 fields); this addresses the remaining receiver-type coupling — every one of the 171 handler methods previously hung off a concrete `*Database` exposing all 218 methods + the raw `*gorm.DB`. New `internal/database/store.go` defines `Store`, composed of narrow per-domain interfaces (`DeviceStore`, `ProbeStore`, `SiteStore`, `ConnectionStore`, `AlertStore`, `AlertPolicyStore`, `MaintenanceWindowStore`, `TelemetryReadStore`, `ChartStore`, `EventStatsStore`, `IngestStore`, `AuthStore`, `AuditStore`, `SecretStore`, `MaintenanceOpsStore`). **This is pure interface extraction — GORM stays, no query or behaviour changes:** `*database.Database` satisfies `Store` for free (`var _ Store = (*Database)(nil)`), the `Gorm() *gorm.DB` escape hatch is part of the interface, and `WithContextStore` preserves the AUDIT-032 request-context cancellation. Only `Handler.db`'s static type changed (concrete → `database.Store`); `httputil.RequireDB` and `buildReportHTML` were widened to accept the interface (the report subsystem, which needs a richer DB surface than handlers, recovers the concrete type via a single localized assertion). The daemons (poller, trap-receiver) keep the concrete `*database.Database`. Payoff: handlers are now unit-testable with a fake store and no database — demonstrated by `store_fake_test.go` running the real `GetSites` handler against an in-memory fake. Full `go build`/`go vet`/`go test ./...` green.

## [0.10.493] - 2026-06-25

### Docs
- **Marked the test-coverage backlog as substantially addressed in `FEATURE-ROADMAP.md` (Open audit follow-ups).** Updated the status-at-a-glance row to 🟡 (v0.10.492) and expanded the detail bullet with the per-package before/after numbers (notifier 1.8→48.2%, sflow 35.9→69.4%, snmp 10.8→20.1%, relay 0→wire-contract locked) and the explicit remaining headroom: the `snmp` package stays ~20% because most of it is live `Walk`/`Get` network methods that need a device or an injectable walker to exercise. Keeps the done-vs-outstanding picture current; no code change.

## [0.10.492] - 2026-06-25

### Tests
- **Test-coverage backlog (2026-06-23 audit follow-up): raised coverage on the four thin packages.** Additive tests plus one small testability refactor; no behavioural change.
  - **`internal/notifier` 1.8% → 48.2%.** Extracted the per-channel payload builders (`buildSlackPayload`/`buildDiscordPayload`/`buildWebhookPayload`/`buildEmailSubjectBody`), the severity→colour maps, and the channel-routing decision (`channelEligibility`) into pure functions (the `sendX` methods now call them — wire JSON shape unchanged), then table-tested them. Added full coverage of the LOGIN/PLAIN SMTP-auth state machines (`loginAuth`, `compoundAuth`: host/TLS gates, mechanism selection, step sequencing), `SnapshotConfig`, and an httptest-backed `SendAlert` fan-out + error-propagation test. New: `smtp_auth_test.go`, `payloads_test.go`.
  - **`internal/sflow` 35.9% → 69.4%.** New `datagram_test.go` builds raw sFlow v5 datagrams (RFC 3176) to drive the previously-0% `parseDatagram` and `parseFlowSample` end-to-end (standard + expanded flow samples), plus malformed/truncated/wrong-version/bad-address-type guards, counter-sample skipping, nil-handler early return, and the uncovered `parseRawPacketHeader` dispatch branches (VLAN-tagged IPv4, direct-IPv4, short-header guards).
  - **`internal/snmp` 10.8% → 20.1%.** New `helpers_coverage_test.go` table-tests the pure shared helpers (`safeString`, `safeFloat` incl. the DisplayString-decimal path, `formatMAC`, `getIndexFromOID`, `isValidPDU`), the per-vendor pure functions (`buildCIDR`, SonicWall IP/subnet/sensor-type formatters, Palo Alto sensor meta/scale, BSD/Linux VPN-interface classifiers, Firewalla/pfSense/OPNsense version extractors), and the PDU-driven `SonicWallProfile.ParseHardwareSensors` + default-vendor `FortiGateProfile.ParseSystemStatus` (incl. the disk-percentage and divide-by-zero guards).
  - **`internal/relay` 0% → wire-contract locked.** New `relay_test.go` pins the schema-version handshake invariants (`Min ≤ Max`, `≥ 1`) and the JSON `omitempty` contracts the collector depends on (`schema_version` absent when zero, `FlowSample.drops` forward-compat, `observed_host_keys`), plus a `FlowSample` round-trip. (Pure-DTO package — no executable statements to "cover", but the wire format is now guarded against silent drift.)

## [0.10.491] - 2026-06-24

### Added
- **M8 — startup fail-fast / health signal on an undecryptable `ENCRYPTION_KEY` (2026-06-23 audit).** A rotated or lost `ENCRYPTION_KEY` previously made every `{enc}` secret (SNMP community, SNMPv3 auth/priv, SSH password, IRC creds) silently fail-closed: `decryptFieldWithChain` returns `""` (the AUDIT-027 contract), polling/notification quietly break, and the operator only notices hours later as devices drift offline. A self encrypt→decrypt round-trip can't detect this (it succeeds with *any* valid key), so the fix persists a **key-check value**: a fixed sentinel encrypted with the key the first time encryption is enabled, stored as the `encryption_key_canary` `SystemSetting`. On every startup `Database.VerifyEncryptionKey` decrypts it with the current key chain (current + `ENCRYPTION_KEY_HISTORY` legacy keys); if it no longer decrypts, the database's real secrets are unreadable too. The verdict drives two behaviours: the **poller and trap-receiver fail-fast** (`log.Fatal` with a remediation message — set `ENCRYPTION_KEY` back, or add the old key to `ENCRYPTION_KEY_HISTORY`) since they're useless without secrets; the **API stays up** but reports `encryption:false` on `GET /api/health` (and the new `/api/readyz` alias) and returns **503** instead of serving "healthy", so an orchestrator probe trips and an operator can still reach the UI to fix the key. Infrastructure errors (can't read/write the canary row) are logged but don't trip the fail-fast — only a genuine key mismatch does. Regression test: `internal/database/crypto_canary_test.go`.

### Fixed
- **REL-01 — server daemons no longer crash on a single goroutine panic (2026-06-23 audit).** Go has no process-wide panic handler, so an unrecovered panic in any long-lived background goroutine aborted the entire binary and took every other subsystem down with it. New `logging.SafeGo(name, fn)` / `logging.Recover(name)` helpers wrap the long-lived goroutines — poller cycle, report scheduler (daily/weekly), syslog TCP-accept + per-connection + UDP-read loops, sFlow read loop, IRC manager (load/reconnect/status loops, per-bot, conn loop), the DB batch flusher, and the API login-attempt pruner — so a panic is contained to its goroutine, logged with a stack trace at error level, and the rest of the process keeps running. (The HTTP request path is already covered by `gin.Recovery()`.) Regression test: `internal/logging/safego_test.go`.
- **REL-04 — maintenance DDL no longer aborts at the 30s `statement_timeout` (2026-06-23 audit).** The `SET statement_timeout = 0` discipline (AUDIT-037) was applied to the migration-lock and interface-address dedupe paths but not to the partition-maintenance DDL, which on a large/busy database can exceed 30s and fail with SQLSTATE 57014. New `Database.execMaintenanceDDL` runs a statement with the timeout lifted (`SET LOCAL statement_timeout = 0`, Postgres-only, scoped to a short transaction so it never leaks to pooled connections); it now wraps the partition + index creates in `EnsurePartitions`, the per-table `ALTER` in `ConfigureAutovacuum`, and the per-partition `DROP` in `dropPartitionsOlderThan`, and `convertEmptyTableToPartitioned` lifts the timeout inside its existing transaction.

### Docs
- **Closed the "LOW dead-code deletions" audit follow-up as not-actionable.** Adversarial re-verification found neither flagged item is deletable: the relay `StartCollector`/`runCollectorHandler` busy-loop was already removed with `cmd/probe` in commit `493ef87`, and `linux_vpn`/`bsd_vpn` are **not** unregistered stubs but live shared helpers called by the registered `firewalla` (linux_vpn) and `pfsense`/`opnsense` (bsd_vpn) vendor profiles — deleting them breaks the build. Updated `docs/FEATURE-ROADMAP.md` (Open audit follow-ups now carries a status-at-a-glance table) and the `docs/audit-2026-06-23-consolidated.md` banner so it's clear online what is shipped vs still open: no discrete server bug findings remain — only the two large ongoing refactors (handler/database God-object split, test-coverage backlog).

## [0.10.490] - 2026-06-24

### Changed
- **Runtime base image bumped `alpine:3.19` → `alpine:3.21` (2026-06-23 audit, M13).** alpine 3.19 reached end-of-life ~Nov 2025 (no security backports). The server image bundles `postgresql16`/`postgresql16-contrib` + `su-exec`, so the bump was gated on those still resolving: verified against the alpine 3.21 package index that `postgresql16` and `postgresql16-contrib` are **16.14-r0 in 3.21 main** and `su-exec` is **0.2-r3 in 3.21 main** (the rest — ca-certificates/bash/wget — are core). **PostgreSQL stays at major 16**, so existing `PGDATA` directories remain compatible and **no `pg_upgrade` is needed** on deploy. NOTE: there is no Docker-image build in CI, so this could not be build-verified in the pipeline — the verification rests on the package-index check above; the definitive confirmation is the next image build (`docker build -t firewall-mon:latest .`). Adding a CI image-build job (and Renovate/Dependabot for the base image) is a recommended follow-up so future base bumps are build-gated.

## [0.10.489] - 2026-06-24

### Security
- **Bumped `github.com/jackc/pgx/v5` v5.6.0 → v5.10.0 to clear GO-2026-4771 / GO-2026-4772 (CVE-2026-33815 / CVE-2026-33816) (2026-06-23 audit).** v5.6.0 carried two unpatched advisories (fixed upstream in v5.9.0). `govulncheck` had been exiting 0 because the vulnerable symbols sit on the import tier and Firewall-Mon uses pgx as a *client* (the COPY/`pgxpool` path), so the code never called the affected functions — but the dependency itself was flagged by module-tier scanners. After the bump `govulncheck ./...` reports **no vulnerabilities**, `go build`/`go vet`/full `go test ./...` and the pgx COPY-path tests (`TestFlowSamplesCopyColumns_OrderAndFieldTypes`, `TestSaveFlowSamples_*`) all pass, and `THIRD-PARTY-NOTICES.md` is updated to v5.10.0. `go mod tidy` made no other direct-dependency changes.

## [0.10.488] - 2026-06-24

### Changed
- **Documentation accuracy pass + audit-report consolidation.** Brought the docs in line with current code and cut single-purpose-file sprawl (docs only — no code change):
  - **Accuracy:** README/FEATURES version markers refreshed (badge → 0.10.487); removed the long-gone `cmd/probe` from trees/stats (3 fwmon daemons, not 4); fixed the SNMP vendor tables (6 vendors with a registered `VendorProfile`; `cisco_asa` is config-diff-only; dropped dead `linux_vpn`/`bsd_vpn`) and the FEATURES stats contradiction; "21 packages"→23, "70+ shell tests"→98, "14 of 170 open audit"→0/170; added the new poller/trap `/metrics`+`/healthz`+`/readyz` (v0.10.487) to README/FEATURES/OPERATIONS/architecture; corrected OPERATIONS claims that X-Request-ID (AUDIT-135) and versioned migrations (AUDIT-044) were "not yet shipped" (both shipped); CONTRIBUTING/SECURITY `main.go:34`→`:39` and removed the bogus Dockerfile-version-bump step; removed the resolved AUDIT-118 entry from KNOWN-ISSUES.
  - **THIRD-PARTY-NOTICES:** updated all direct-dep versions to match `go.mod` and added the missing direct deps with licenses (`prometheus/client_golang`, the `go.opentelemetry.io/otel*` modules — Apache-2.0; `glebarez/sqlite` — MIT; `jackc/pgx/v5` — now direct).
  - **Consolidation:** archived the three `docs/audit-2026-06-22-*.md` reports → `docs/audit-archive/` and `tasks/{audit-2026-06-10,audit-2026-06-11,audit-2026-06-11-test-coverage,RELIABILITY-2026-06-11}.md` → `tasks/archive/` (with the still-open items — M8, alpine bump, pgx CVE, the Handler/database splits, the test-coverage backlog, REL-01/REL-04 — pulled into a new "Open audit follow-ups" section of `FEATURE-ROADMAP.md`); moved the obsolete `docs/UPGRADE-2026-06.md` → `docs/archive/` and repointed its links to `OPERATIONS.md`; folded `docs/SECURITY-VERIFICATION.md` into `OPERATIONS.md`; and annotated the live `docs/audit-2026-06-23-consolidated.md` with resolved/open status. `docs/AUDIT.md` (the AUDIT-NNN ledger), `tasks/SFLOW-NOC-REDESIGN-PLAN.md`, and `tasks/lessons.md` are unchanged.

## [0.10.487] - 2026-06-24

### Added
- **The poller and trap-receiver daemons now expose `/metrics`, `/healthz`, and `/readyz` (2026-06-23 audit, M11).** Observability previously lived only in the API binary, so the poller (AlertManager + polling + batchers) and the trap-receiver were black boxes to Prometheus and container orchestrators — less observable than the remote collector. Added `metrics.StartObservabilityServer` / `ObservabilityHandler` (in `internal/metrics`) and wired both daemons to it: `/metrics` carries the Go runtime/process collectors plus each daemon's DB-pool stats (registered as `fwmon_poller` / `fwmon_trap`), `/healthz` is liveness, and `/readyz` pings the DB (the idling trap-receiver — no `SNMP_TRAP_COMMUNITY` — still serves them and reports ready). Bind addresses default to `:9101` (poller) and `:9102` (trap-receiver); override with `POLLER_METRICS_ADDR` / `TRAP_METRICS_ADDR`, or set them to `off` to disable. Unauthenticated by design like the API `/metrics` — protect at the network layer. Tests in `observability_m11_test.go`.

## [0.10.486] - 2026-06-23

### Fixed
- **Trap-receiver rate-limiter recovers from a spoofed-IP flood instead of locking out new devices forever (2026-06-23 audit, M9).** The per-source-IP token-bucket map (`internal/snmp/trap.go`) is capped at `maxRateLimitedIPs` (10000); once a flood of unique spoofed source IPs filled it, every NEW legitimate device IP was rejected at the cap until the process restarted — a durable denial-of-trap. Before rejecting a new IP at the cap, the limiter now sweeps idle buckets (any IP not seen within `rlBucketIdleTTL` = 5m has fully refilled, so dropping it is lossless), throttled to one O(n) pass per `rlSweepInterval` (1m) so a sustained flood can't turn it into per-packet work. A flood of *active* IPs still rejects new IPs (it never evicts a currently-active bucket — legitimate active senders are not degraded), but the lockout now clears automatically once the flood subsides. Regression tests in `trap_ratelimit_sweep_test.go` (idle sweep admits a new IP; active buckets are spared).

## [0.10.485] - 2026-06-23

### Fixed
- **Syslog aggregation no longer silently drops groups beyond the first page (2026-06-23 audit, M2).** `aggregateSyslogToSummary` (`internal/database/syslog_agg.go`) deleted ALL matching raw informational rows *inside each page's transaction*, so the moment page 1 committed it wiped every still-un-summarized group — any distinct `(bucket, device, severity, facility, app)` groups beyond the first page (`pageSize=10000`) were deleted without ever being counted, losing those message counts from the summaries. The delete now happens ONCE after the whole page loop (reading over the still-intact `syslog_messages`, exactly like the working `aggregateFlowsToRollup`), so every group is summarized regardless of page count. Regression test `syslog_agg_m2_test.go` shrinks the page size and seeds more groups than one page to prove no group is lost.

### Changed
- **`aggregateRollupsUp` now paginates the high-cardinality 5-tuple GROUP BY (2026-06-23 audit, M1).** Promoting flow rollups (5min→hourly→daily) previously loaded *every* group into one slice in a single transaction with no `Limit`, unlike its sibling `aggregateFlowsToRollup` — a long backlog could materialize millions of groups in memory. It now reads in 50k-group pages (over the stable `interval_type = src` source set) and deletes the consumed source rollups once after the loop.

## [0.10.484] - 2026-06-23

### Changed
- **Probe ingestion DB round-trips cut on three hot paths (2026-06-23 audit, M3/M4/M5).**
  - **M3:** `probeDeviceIDs` (called by ~18 ingestion handlers on every request to build the per-probe device allow-list) now uses a new `GetDeviceIDsByProbe` that `Pluck`s just the IDs — skipping the `Preload("Site")` JOIN and the per-device AES-GCM secret decryption that `GetDevicesByProbe` did only to read `d.ID`.
  - **M4:** `ReceivePingResults` no longer does a serial read-modify-write per result (~2N DB round-trips for N pings). New `updatePingStatsBatch` folds the whole batch per `(device, target)` and does one read + one write per distinct target. The folded min/max/avg/sample-count is mathematically identical to the per-sample running average; last-writer `PacketLoss`/`ProbeID` semantics preserved.
  - **M5:** `ReceiveSystemStatuses` now batch-inserts via a new `SaveSystemStatuses` (one statement, up to 100 rows) instead of a `Create` per row, and marks the senders online with a single `WHERE id IN (...)` update instead of one per device.
  - Regression tests: `handlers_ingestion_perf_test.go` (fold correctness + grouping + existing-series merge; ID-only allow-list query). No wire/DB-format change.

## [0.10.483] - 2026-06-23

### Changed
- **Renamed the internal `tasks/` audit-planning notes to the `audit-*` scheme** (`tasks/audit-2026-06-10.md`, `tasks/audit-2026-06-11.md`, `tasks/audit-2026-06-11-test-coverage.md`) and swept the last internal-nickname references from `tasks/` content — completing the rename so no working nickname remains anywhere in the tree. This also fixes a pre-existing mismatch where the changelog already referenced `tasks/audit-2026-06-11.md`. Internal notes only; no code or behavior change.

## [0.10.482] - 2026-06-23

### Changed
- **Completed the audit-wording sweep across all tracked files.** Reworded every remaining internal-nickname reference to "audit" — in changelog prose, Go source comments (`internal/{database,models,alerts,api,irc,syslog,sflow}` + tests), and doc headers — and renamed the 2026-06-22 audit reports to the `docs/audit-2026-06-22-{consolidated,design-patterns,taocp}.md` scheme. Internal `tasks/` planning notes are intentionally left as-is. Docs/comments only; no code or behavior change.

## [0.10.481] - 2026-06-23

### Changed
- **Docs/wording: professionalized the public-facing references to the 2026-06-23 audit.** Reworded the v0.10.477–480 changelog entries and the roadmap header to call it the "2026-06-23 audit" (dropping an internal working nickname), and renamed the 2026-06-23 consolidated audit report to `docs/audit-2026-06-23-consolidated.md` (the sibling collector report references this path). No code change.

## [0.10.480] - 2026-06-23

### Fixed
- **The `/config` bind-mount is now parametrizable (`CONFIG_DIR`), removing the ENCRYPTION_KEY-continuity trap (2026-06-23 audit, H8).** `entrypoint.sh` seeds `/config/config.env` with a random `JWT_SECRET_KEY` on first run when none is supplied, and the AES-256 key that encrypts every `{enc}` secret (SNMP/IRC/SMTP) derives from it — but `docker-compose.yml` hardcoded `./config:/config` while `DATA_DIR` was relocatable. Deploying from a new directory therefore regenerated the key while the relocated database still held ciphertext under the old key, leaving every credential permanently undecryptable (`decryptField` logs an error and returns empty, so it surfaces later as silently-broken polling rather than a startup failure). The mount is now `${CONFIG_DIR:-./config}:/config` with a prominent continuity warning, and `.env.example` documents that `CONFIG_DIR` must move together with `DATA_DIR` — plus the safest option of pinning `JWT_SECRET_KEY`/`ENCRYPTION_KEY` explicitly so continuity never depends on a surviving bind-mount. Infra/docs only; no code or crypto-path change. (The defense-in-depth fail-fast guard for the "{enc} present but no key resolves" case — audit M8 — is tracked separately.)

## [0.10.479] - 2026-06-23

### Fixed
- **AlertManager no longer re-fires a notification storm on every poller/API restart (2026-06-23 audit, H7).** Cooldown state (`lastAlert`/`activeAlerts`) lives only in memory, and the fire path gated solely on the in-memory `canAlertWithCooldown` (true when the key is absent). After a restart those maps are empty, so every still-breaching condition (device offline, interface/VPN down, CPU/memory/disk/session thresholds) re-fired a fresh email/Slack/Discord/IRC notification at once — and under the statement-timeout crash-loop, a fresh storm every cycle. Added `dbCooldownActive(deviceID, alertType, metricName, ref, cooldown)`, consulted at the send chokepoints (`dispatchFired` for the batch state alerts; `CheckDeviceOffline` inline): if a still-open alert for the same `(device, type, metric)` already exists within the cooldown window it suppresses the duplicate save+send. A restart is now transparent (operator-chosen behavior) — the within-cooldown duplicate is dropped, but the normal periodic reminder still fires once the window elapses (older open rows fall outside it), so a long-running issue is never silently forgotten. Event/transient alerts (SNMP traps, syslog, SSH host-key change, config-change) fire on arrival and are intentionally NOT deduped. The DB read happens only on the rare about-to-notify path. Regression tests in `restart_storm_test.go` cover the window/scope/resolved semantics, end-to-end restart suppression via `dispatchFired`, and the post-cooldown reminder.

## [0.10.478] - 2026-06-23

### Fixed
- **Syslog retention no longer issues a single unbounded DELETE on the DB's largest table (2026-06-23 audit, H6).** Four syslog cleanup deletes in `internal/database/cleanup.go` (critical `severity < 6`, informational `severity >= 6`, the `syslog_summaries` purge, and the legacy `SyslogDays` path) bypassed the AUDIT-038 `batchedDeleteOlderThan` helper that every other high-volume table uses. On a populated prod database that meant one DELETE touching millions of rows in the straddling partition: a long lock window that blocks ingestion, a large WAL burst, and — under the 30s `statement_timeout` — a query that gets killed and re-attempted every cleanup tick (crash-loop shape). Added `batchedDeleteOlderThanWhere(model, cutoff, extraWhere, args...)` (the existing `batchedDeleteOlderThan` is now a thin wrapper) so the severity-scoped syslog deletes run in the same 10k-row batches with `SET LOCAL lock_timeout='5s'` and an inter-batch sleep. Same rows deleted as before — only the locking/batching changes. Regression test `cleanup_syslog_batched_test.go` verifies the severity predicate is honored and recent rows are spared.

## [0.10.477] - 2026-06-23

### Fixed
- **Syslog ingestion now enforces the per-probe device allow-list (2026-06-23 audit, H1).** `ReceiveSyslogMessages` (`internal/api/handlers/handlers_data.go`) was the only one of the ~13 probe ingestion handlers that did NOT call `h.probeDeviceIDs(probe.ID)` and filter — it filled `DeviceID` from the *global* `ResolveDevicesByIPs` lookup and passed a body-supplied `DeviceID` straight through. An approved (or compromised) probe could POST syslog attributed to ANY device: forging `SYSLOG_CRITICAL` alerts (severity ≤ 2) and config-change attribution against another site's device, plus cross-site dashboard pollution. The handler now mirrors its siblings — any positive `DeviceID` (body-supplied or IP-resolved) the probe does not own is dropped; device-less messages (`DeviceID 0`) are still stored. Regression test `handlers_syslog_devicescope_test.go` covers spoofed-cross-probe (filtered), owned-device (saved), and device-less (saved).
- **IRC command lookup no longer races the command-map reload — was an unrecoverable process crash (2026-06-23 audit, H4).** `onPrivmsg` read `Manager.commands` under the per-`Bot` mutex (`b.mu`) while `loadCommands` replaced the map under the `Manager` mutex (`m.mu`); two different locks are not mutual exclusion, so a `!command` arriving while an admin saved/reloaded commands (5 Gin handler sites call `ReloadCommands`) triggered Go's fatal `concurrent map read and map write`, aborting the whole `fwmon-api` process. The read is now centralized in `Manager.lookupCommand` under `m.mu.RLock()`. Regression test `bot_command_race_test.go` (run under `-race` in CI) hammers the reader against a concurrent map-replacing writer.
- **TLS syslog listener failures are surfaced instead of crashing with a "started successfully" log (2026-06-23 audit, H5).** In `SyslogReceiver.Start()` (`internal/syslog/syslog.go`) the `UseTLS` branch did `cert, err := tls.LoadX509KeyPair(...)`, declaring a new `err` scoped to the `if` block; the following `s.listener, err = tls.Listen(...)` wrote that shadow, so the outer `err` checked after the block stayed nil. On any TLS-path listen failure (port already bound, permission denied) `Start()` returned nil and logged "started", then `acceptLoop` nil-dereferenced `s.listener.Accept()` in an unrecovered goroutine and crashed the process. Renamed the cert-load error to `certErr` so the listen error propagates. Regression test `syslog_tls_start_test.go` asserts `Start()` errors (and does not set `running`) when the TLS listen fails on an occupied port.

## [0.10.476] - 2026-06-23

### Fixed
- **CI `Integration (PostgreSQL)` lane is no longer persistently red — root-caused to a shared-database race, not the "flake" it was labelled.** The job runs `go test -tags=integration ./internal/database/... ./internal/api/handlers/...`, and `go test` runs those two package binaries concurrently. Both call `NewIntegrationDB`, which does an unsynchronized `DROP SCHEMA public CASCADE` on the *same* `TEST_PG_DSN` database — so one process's reset would nuke the other's in-flight migration, producing nondeterministic `relation "schema_migrations"/"system_status" does not exist (SQLSTATE 42P01)` failures in `TestPostgresIntegration/PopulatedTableSkipped` (master had been red for 8+ consecutive runs; reruns never cleared it). Fix: pass `go test -p 1` in `.github/workflows/ci.yml` and the `test-integration` Make target so the integration package binaries run one at a time (a single owner of the shared schema). Documented the shared-database contract on `NewIntegrationDB` so the constraint is discoverable. No production-code change.

## [0.10.475] - 2026-06-23

### Fixed
- **Top-N lists now use `sort.SliceStable` so equal-ranked entries keep a deterministic order across otherwise-identical requests.** audit (2026-06-22, taocp [medium] #7, Lesson 5.2): `sort.Slice` is not a stable sort, so two protocols/conversations/events/talkers with identical counts could swap positions request-to-request. Converted the four count/value-ranked top-N sorts — `TopProtocols` and `mergeKeyCounts` (`internal/database/flows.go`), device `Events` (`internal/database/devices.go`), and report Fleet Top Talkers (`internal/report/model.go`). The time-bucket sort in `flows.go` (unique bucket keys, no ties) is intentionally left as `sort.Slice`. No behavior change for non-tied data; protects any future paginated top-N endpoint from non-deterministic ordering.
## [0.10.474] - 2026-06-23

### Changed
- **Alert types, severities, and IRC command types are now Go typed strings (`type AlertType string`, `type Severity string`, `type CommandType string`) backed by named constants.** Previously these were bare `string` fields and parameters threaded through `internal/{alerts,notifier,report,irc,database}` and the handlers — a typo in a switch arm (`"CPU_HGIH"`) or a crossed assignment (severity into the alert-type column) compiled cleanly and only surfaced at runtime. They are now named string types (`internal/models/models.go`) with constant sets (`AlertTypeCPUHigh`, `SeverityCritical`, `CommandTypeStatus`, …); the model fields `Alert.AlertType/Severity`, `AlertRule.AlertType/Severity`, `IRCCommand.CommandType`, and the carrier `alerts.ResolvedAlertConfig.Severity` plus the policy-resolution helpers (`resolveAlertConfig`, `defaultSeverityForType`, `globalThresholdForType`, `overrideThreshold`, `configSeverityToAlert`, `escalateSeverity`) now use the typed forms, so the compiler rejects mismatches. **No wire or DB format change** — typed strings JSON-marshal and GORM-scan to the identical underlying value, so persisted rows and API payloads are byte-for-byte unchanged. Trap- and configdiff-domain severities (different vocabularies) are converted explicitly at their boundaries. Closes the audit's [medium]/[low] stringly-typed-enum findings (`docs/audit-2026-06-22-design-patterns.md`). All existing tests pass unchanged (only two test files needed typed map keys / boundary conversions).

## [0.10.473] - 2026-06-22

### Added
- **sFlow: `drops` field is now persisted per sample, and a new `flow_agent_drops` table aggregates them per-(agent, sampling_rate, minute).** sFlow v5 §3.1.1 puts a running counter of packets the agent had to drop between samples because it couldn't keep up. The audit (2026-06-22, taocp [critical] #3 + consolidated C-3) found the server was completely blind to this signal — agent-side congestion was undetectable. This PR ships the data path: (1) `models.FlowSample.Drops uint64` (`json:"drops,omitempty"`, forward-compatible: pre-adopting collectors see no wire key) plus `relay.FlowSample.Drops` for documentation parity, (2) the COPY column list in `saveFlowSamplesPGX` extended so the new field rides the bulk path, (3) new `models.AgentDrops` + new `flow_agent_drops` table (migration v8, AutoMigrate so it's idempotent), (4) `SaveAgentDrops` / `GetAgentDropsRecent` methods on the database. The companion collector-side change (collector v1.2.131, already shipped) emits the field with `omitempty`. Alert-policy hook (`SFLOW_AGENT_DROPS`) and NOC strip widget deferred to follow-up PRs — this one ships the storage and read path only. Tests: `TestAgentDrops_RoundTrip` (inserts 4 rows, queries 5m window, verifies out-of-window rows are filtered and the 3 in-window rows are returned in DESC order), `TestAgentDrops_EmptyResultIsCleanNil` (no rows → no error), `TestFlowSamplesCopyColumns_OrderAndFieldTypes` (extended to include `drops` so the column list still pins to the struct order).

## [0.10.472] - 2026-06-22

### Changed
- **sFlow: bulk insert of `flow_samples` now uses the Postgres COPY protocol via a dedicated `*pgxpool.Pool` instead of GORM's per-row `Create`.** ~5-10× throughput on the same payload; eliminates per-row INSERT round-trips and the per-row transaction overhead. The pgx pool is opened alongside the GORM pool in `Connect` with the same connection settings and `statement_timeout` (AUDIT-037); failed pool init logs a warning and falls back to GORM `Create` (slow but correct). The SQLite test backend has `pgxPool == nil` and uses the GORM path — no test-time regression. `pgx` was already a transitive dependency on disk; this PR moves it to a direct dependency (`go.mod`). Tests: `TestFlowSamplesCopyColumns_OrderAndFieldTypes` (static check that the column list matches `models.FlowSample` field order — pgx binds columns positionally so a reorder is a silent corruption), `TestSaveFlowSamples_EmptyInputShortCircuits` (nil/empty input), `TestSaveFlowSamples_GORMFallbackOnSQLite` (the SQLite lane still works). Closes the audit's [critical] #4 (`docs/audit-2026-06-22-taocp.md`).

## [0.10.471] - 2026-06-22

### Fixed
- **sFlow: `flow_samples.bytes` and `flow_samples.packets` now store the sampled traffic volume (`frame_length × sampling_rate` and `sampling_rate`) instead of the raw frame length and 1.** The audit (2026-06-22, taocp [critical] #1 and #2) found the server's parser at `internal/sflow/sflow.go:318-326` stored `Bytes = uint64(frameLength)` and `Packets = 1`, so every dashboard chart, top-N list, and throughput figure under-reported real traffic by 1:N (e.g. 512× at 1:512 sampling). The collector (sibling `Firewall-Collector` repo) already does this on its side — the server now matches. The read paths (`SUM(bytes)` and friends in `internal/database/flows.go`) are unchanged: because `bytes` is now scaled at insert, `SUM(bytes)` is correct as-is. A new migration v7 (`migrateFlowSamplesSamplingRateScale`) backfills historical rows so old and new data agree (`WHERE sampling_rate > 1 AND packets = 1` — idempotent; rows that have already been migrated via a crash-recovery re-run never match). Tests: `TestParseRawPacketHeader_BytesScaledBySamplingRate` (scaled bytes/packets), `TestParseRawPacketHeader_BytesUnscaledWhenSamplingRateOne` (sampling_rate=1 identity), `TestParseRawPacketHeader_ZeroFrameLength` (liveness-only), `TestMigrateFlowSamplesSamplingRateScale_ScalesAndIsIdempotent` (scaling + idempotency + sampling_rate=1 leave-alone), and `TestMigrateFlowSamplesSamplingRateScale_FreshInstallNoOp`. Per `tasks/lessons.md` "sFlow packets × sampling_rate is non-negotiable".

## [0.10.470] - 2026-06-22
### Added
- **Direct-link interfaces are now grouped into logical segments by VLAN id and parent interface — a VLAN sub-interface and its parent bridge (e.g. `HOSTING-BLOCK-2` + `HOSTING_BLOCK-2`) are recognized as one thing instead of two separate items.** Each interface now carries `kind` (SNMP ifType: VLAN/Bridge/LAG/Physical/…), `vlan_id` (SNMP `dot1qPvid`, else config), and `parent` (config `set interface`) on `ConnInterfaceRef` (`internal/database/connection_detail.go`). A new `ParseFortiGateInterfaceConfig` (`internal/snmp/vendor_fortigate.go`) extracts each `config system interface` entry's parent/vlanid/type (handling nested `config` blocks).
- The Interfaces tab (`diagram-panels.js` `renderPanelInterfaceTab`) now merges interfaces into one segment via union-find over **same VLAN id**, **same IP subnet**, **same (normalized) name**, and **sub-interface↔parent when the parent is present** — so a bridge and its VLAN collapse into one card, and the same VLAN across two devices pairs even when named differently. Distinct VLANs trunked on a shared parent are NOT falsely merged. Each interface row is annotated with its kind / VLAN / parent.

## [0.10.470] - 2026-06-22
### Fixed
- **Direct-link Interfaces tab stopped pairing — it showed two unlinked columns.** Regression from v0.10.468: paired "network segment" cards required a shared **IP subnet** on both ends, but Layer-2 links (VLAN/bridge, no IP) never matched, so every interface fell into the single two-column "Other interfaces" card with nothing visibly paired. `renderPanelInterfaceTab` (`diagram-panels.js`) now pairs the way the detector actually matched the link — **two passes: first by shared IP subnet, then by shared (normalized) interface name** — so L2 `name_match` links pair by interface name (🔗 vlan100 · DC2-FW1 ↔ DC2-FW2) and ethernet/lag pair by network (🌐 10.0.5.0/24). Only interfaces that genuinely can't be paired to the other end fall into "Other interfaces".

## [0.10.469] - 2026-06-22
### Added
- **VXLAN/L3VLAN overlay links now show real overlay detail instead of just borrowing the carrier tunnel's graph.** The Overlay tab now surfaces, per endpoint device, data drawn from two sources:
  - **From the SSH-captured FortiGate config** (`config system vxlan`): the **VNI** (`vxlan-id`), the **carrier interface** the overlay is bound to (`set interface`), the **UDP port** (`dstport`, default 4789), and the **remote VTEP peer IPs** (`set remote-ip`). `ParseFortiGateVxlanConfig` (`internal/snmp/vendor_fortigate.go`) was extended to capture the VTEP list and `dstport` (it previously dropped both).
  - **From SNMP** (`interface_stats`): the overlay interface's own status, byte counters, and an expandable per-interface **traffic chart**.
  - Below the overlay cards, the **carrier tunnel** it actually rides on is still shown (the encrypted IPSec path), so you see both the overlay identity and its transport in one place.
- Backend: `OverlayInfo` on `ConnectionDetailResult`, populated by `buildOverlayInfo` (`internal/database/connection_detail.go`) which joins config + interface_stats by normalized interface name. Frontend: `renderPanelOverlayTab` (`diagram-panels.js`); overlay charts load lazily when the tab is shown.
- Tests: `TestParseFortiGateVxlanConfig_Details` (VTEP/dstport parsing), `TestBuildOverlayInfo` (config + SNMP enrichment end-to-end).

## [0.10.468] - 2026-06-22
### Fixed
- **Direct-link interfaces failed to pair, falsely showing "end not monitored" on the peer (e.g. DC2-FW1 ↔ DC2-FW2).** Three compounding causes, all fixed:
  1. **Overlay detector stored only one side's interface name** (`cmd/poller/main.go` `detectOverlayConnections`): for `name_match` links (l2vlan/bridge/vxlan/l3ipvlan) it recorded `a.name` but not `b.name`, so `TunnelNames` omitted the peer's interface and the far end couldn't be resolved. Now stores **both** endpoints' names (matching the physical detector).
  2. **The detail resolver matched interface names with exact SQL equality** while the detector matches *normalized* names — so a link named `vlan100` on one device and `VLAN-100` on the other never resolved the second end. `resolveConnectionInterfaces` (`internal/database/connection_detail.go`) now matches **normalized** names against each device's latest interface set (new `normalizeIfName`, `latestInterfacesForDevice`), resolving both ends regardless of spelling.
  3. **The UI implied an end was unmonitored whenever a subnet didn't line up.** `renderPanelInterfaceTab` (`diagram-panels.js`) now only builds a "network segment" card for a subnet present on **both** ends; all other interfaces (Layer-2 links with no IP, or one-sided subnets) go into a single **"Other interfaces"** card that still shows both devices' columns. A side only reads "no interfaces reported" when it genuinely has none — no more misleading "end not monitored".
- Tests: `TestResolveConnectionInterfaces_NormalizedBothEnds` (cross-spelling pairing).

## [0.10.467] - 2026-06-22
### Changed
- **Direct-link Interfaces tab now groups interfaces by the network that joins the two devices, instead of a flat undifferentiated list.** It was impossible to tell which interface on one side paired with which on the other. The detail now resolves each interface's IP + network from `interface_addresses` (new `ip_address`/`subnet` on `ConnInterfaceRef`, `computeNetworkCIDR` in `internal/database/connection_detail.go`) and the UI (`diagram-panels.js` `renderPanelInterfaceTab`) renders **one card per IP subnet** — e.g. `🌐 10.0.5.0/24 · switch-a ↔ switch-b` — with the source-side interface(s) and dest-side interface(s) shown side by side (interface name + IP + speed + status + in/out), each still expandable to its own traffic chart. Interfaces whose end isn't monitored show "only one end monitored"; interfaces with no IP on a shared subnet fall into a final "unpaired" card. This makes the device↔network↔device pairing explicit.
- Tests: `connection_traffic_direct_test.go` now asserts `ip_address`/`subnet` resolution; added `TestComputeNetworkCIDR`.

## [0.10.466] - 2026-06-22
### Added
- **Connection-map link details are now type-aware — a VLAN/ethernet/LAG link no longer renders the (empty) IPSec tunnel panel.** Every connection type is sorted into one of four telemetry *families* that decide which data source and detail view it gets (`internal/database/connection_detail.go` `connectionFamily`):
  - **direct** (ethernet/lag/l2vlan/bridge/wan) — graphs **`interface_stats`** for its member interfaces (resolved from the interface names in `TunnelNames`) instead of `vpn_status`, which has no rows for these links. The second tab becomes **Interfaces**: per-interface rows (device, speed, status, in/out, errors) each expandable to a per-interface traffic chart (reuses `GET /api/devices/:id/interfaces/:ifIndex/chart`).
  - **tunnel** (ipsec/ssl/gre/tunnel) — the **Tunnels** tab now groups Phase 2 selectors under their **Phase 1**: one graph per Phase 1 (selectors sharing a Phase 1 share a single counter series — there is no separate per-Phase-2 series), with the selectors listed beneath as non-graphed subnet rows. The count KPI shows Phase 1 count.
  - **overlay** (vxlan/l3ipvlan) — graphs its **carrier tunnel** (matched by peer remote IP); tab/labels read "Carrier".
  - **offnet** — labelled "Peers".
- The Overview traffic graph, range pills (1h/24h/7d/30d) and chart styling are identical across all families — `GetConnectionTraffic` now branches by family and returns the same `{in_bytes, out_bytes, bucket_ms}` shape for interface-sourced links (new `interfaceTrafficWindow`, summed over one endpoint's interfaces to keep in/out directionally coherent).
- Regression tests: `connection_traffic_direct_test.go` (direct link pulls `interface_stats`, merge/aggregation, family classifier).

## [0.10.465] - 2026-06-22
### Changed
- **The Connection Map legend now mirrors every link's line *style*, not just its color (`web/admin/admin.html`).** The two remaining dashed-on-the-map types had solid legend swatches: **VXLAN** (drawn dashed `#f0abfc`) and **Off-net** (drawn dashed `#4ade80`) now use dashed borders, matching L3VLAN. The legend is now fully faithful to the map across all seven entries — solid for IPSec/SSL/GRE/Direct, dashed for the VXLAN/L3VLAN/Off-net overlays — in both color and stroke style.

## [0.10.464] - 2026-06-22
### Changed
- **The L3VLAN legend swatch is now dashed to mirror the map (`web/admin/admin.html`).** The `l3ipvlan` overlay is drawn as a dashed pink line on the Connection Map; its legend button now uses a dashed border (`border-style:dashed`) so the swatch matches the line style, not just the color.

## [0.10.463] - 2026-06-22
### Added
- **Added an L3VLAN entry to the Connection Map legend/filter bar (`web/admin/admin.html`).** The `l3ipvlan` overlay type (VXLAN-over-IPSec, drawn pink-dashed `#f472b6` on the map) was rendered but had no legend swatch or filter toggle. Added a button (`data-type="l3ipvlan"`, label "L3VLAN") next to VXLAN, using the exact map color; it filters via the existing per-type toggle path — no JS change required.

## [0.10.462] - 2026-06-22
### Changed
- **The Connection Map legend/filter bar now matches the actual map colors and the unified direct-link color (`web/admin/admin.html`, `cmd/api/static/js/diagram-cytoscape.js`).** Two problems were fixed: (1) every legend swatch used a stale GitHub-era palette (e.g. IPSec `#58a6ff`, SSL `#d29922`, L2VLAN/Bridge `#39d4e0`, Off-net `#3fb950`) that never matched the Cytoscape `TYPE_COLORS` actually drawn on the map — swatches are now synced to the real values (IPSec `#7dd3fc`, SSL `#fdba74`, GRE `#c4b5fd`, VXLAN `#f0abfc`, Off-net `#4ade80`). (2) The separate **L2VLAN** and **Bridge** buttons are replaced by a single teal **Direct** button (`data-type="direct"`) reflecting that ethernet, LAG, L2VLAN, and bridge now render as one direct color (0.10.460–461). Clicking **Direct** toggles all four `DIRECT_TYPES` as a group (`toggleType`/`updateToolbarButtons` gained group handling), so ethernet/LAG links — previously not filterable at all — are now covered. No backend or detection changes.

## [0.10.461] - 2026-06-22
### Changed
- **All direct (same-site LAN) links on the connection map now share one teal color (`cmd/api/static/js/diagram-cytoscape.js`).** Following the bridge/l2vlan unification in 0.10.460, the two remaining direct-link types — `ethernet` (was slate `#94a3b8`) and `lag` (was amber `#fcd34d`) — are now also teal `#2dd4bf`, so every `DIRECT_TYPES` link (ethernet, lag, l2vlan, bridge) reads as the same class of connection at a glance. Physical links remain distinguishable by line width (lag = 4px, ethernet = 2px); only the color was unified. Tunnel/overlay/off-net link colors are unchanged.

## [0.10.460] - 2026-06-22
### Fixed
- **Direct VLAN-layer links on the connection map now render in one consistent color and stack instead of overlapping (`cmd/api/static/js/diagram-cytoscape.js`).** A `bridge` (FortiGate "Software Switch") link and an `l2vlan` link between the same device pair are the same VLAN-layer LAN segment, and `TYPE_COLORS` already defined both as teal `#2dd4bf` — but the Cytoscape stylesheet had a `line-color` rule only for `edge[connType="l2vlan"]`, with no matching rule for `bridge`. So bridge edges fell through to the default grey edge color while l2vlan edges were teal, making the two look like different kinds of link. Added the missing `edge[connType="bridge"]` color rule so both direct VLAN links draw teal. Separately, direct connection edges (`edgeType="connection"`) inherited the default `curve-style: straight`, so multiple parallel direct links between the same pair were drawn on top of each other; they now use `curve-style: bezier` with a `control-point-step-size`, which fans parallel same-pair direct links into a neat stack. Single direct links are unaffected (a lone bezier edge renders straight).

## [0.10.459] - 2026-06-21
### Fixed
- **Interface IP addresses are now parsed correctly on FortiOS builds that append an extra sub-identifier to the `ipAddrTable` index (`internal/snmp/snmp.go`).** Some FortiGates return `ipAdEntIfIndex`/`ipAdEntNetMask` OIDs indexed with a 5th octet — `.1.3.6.1.2.1.4.20.1.2.192.168.25.254.1` instead of `…192.168.25.254` — and `GetInterfaceAddresses` stored the whole suffix (`192.168.25.254.1`) as the IP. That fails `net.ParseIP`, so the subnet/overlay connection detectors silently skipped every address from such a device. The parser now extracts just the first four octets via `ipv4FromTableIndex` and validates them. This is the server-direct counterpart to the same fix in the collector (which polls the affected device in the field). Adds a unit test. (Operators carrying historical malformed `interface_addresses` rows can clear them with `DELETE FROM interface_addresses WHERE ip_address !~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$';` — the next poll repopulates clean rows.)

## [0.10.458] - 2026-06-21
### Added
- **IPSec hub-and-spoke tunnels are now mapped from the tunnel-interface overlay subnet, even when the FortiGate VPN table is empty (`cmd/poller/main.go` `detectVPNConnections`).** A live SNMP walk of a hub and its spokes showed the vendor `fgVpnTunTable` is unreliable for this — the spokes returned **no** tunnel-table rows at all, and the hub only a sparse one — so the four existing remote-gateway match strategies (`ip_match`/`interface_ip`/`tunnel_indirect`/`wan_inferred`, all keyed on a tunnel's remote-gateway IP) never connected them. But the tunnel interfaces themselves reliably carry an overlay IP in the standard IP-MIB (observed: hub `192.168.255.1/24`, spoke `192.168.255.2/32`). A new tunnel-overlay phase pairs two devices whose tunnel interfaces (ifType 131) share an overlay subnet — a spoke's `/32` sitting inside the hub's `/24` — producing an `ipsec` connection (`match_method: tunnel_overlay`). It is cross-site by nature (no same-site guard), excludes link-local addresses, never links two `/32` spokes to each other, and only fills pairs the remote-gateway strategies didn't already find. The empty-`fgVpnTunTable` early-return was removed so this phase runs regardless of vendor-table availability. Adds poller characterization tests for the hub↔spoke overlay match and the no-spoke-to-spoke boundary.

## [0.10.457] - 2026-06-21
### Fixed
- **Connection auto-detection no longer falsely links two FortiGates through their FortiLink fabric ports or link-local interfaces (`cmd/poller/main.go`).** A live SNMP sweep of four FortiGates showed every unit carries a `fortilink` interface (firewall↔FortiSwitch) on a *default, identical* subnet — `169.254.1.1/24` (bridge) and `10.255.1.1/24` (lag) recurred verbatim across devices. Because v0.10.456 broadened the subnet detector to accept `bridge`/`lag`/`l2vlan`, any two same-site units would otherwise be cross-connected through those shared FortiLink subnets (and the name-matching overlay detector had the same exposure, since the interface is named `fortilink` everywhere). Both detectors now exclude FortiLink interfaces (by name) and link-local `169.254.0.0/16` addresses (RFC 3927), which are never routed inter-device LAN segments. Real shared LANs (e.g. two firewalls' `internal` switches on `192.168.5.0/24`) still connect; the FortiLink/HA-sync noise does not. Adds a poller characterization test built from the observed FortiLink subnets.

## [0.10.456] - 2026-06-21
### Fixed
- **Same-LAN device pairs are no longer missed when the shared subnet lives on a FortiGate switch or VLAN interface (`cmd/poller/main.go` `detectPhysicalConnections`).** The auto-connection subnet detector only grouped interfaces typed `ethernet`/`lag`, but on FortiGate the LAN gateway IP almost never sits on a bare port — it lives on the hardware/software switch (`internal`/`lan`, reported as SNMP ifType 209 `bridge`) or a VLAN sub-interface (ifType 135 `l2vlan`). A live SNMP walk of two FortiGates sharing `192.168.25.0/24` confirmed it: one carried the subnet IP on `port3` (ethernet) and the other on `internal` (bridge), so the bridge side was filtered out, the subnet group never reached two devices, and no connection was drawn. The detector now also accepts `bridge`, `l2vlan`, and `propVirtual` (software switch/zone) as valid LAN-segment interface types, while still excluding tunnel/GRE/loopback/MPLS and the overlay-over-tunnel types (`l3ipvlan`, `vxlan`), which the VPN/overlay detectors own. The same-site, shared-subnet, and non-/30 guards are unchanged. Adds poller characterization tests covering the real ethernet↔bridge case plus the cross-site and tunnel exclusions; `DeviceConnection` added to the in-memory test harness.

## [0.10.455] - 2026-06-21
### Removed
- **Removed the dead server-side FortiGate SSL-VPN OID poll path (`internal/snmp/`, `cmd/poller`, `internal/database/devices.go`).** The server walked `.1.3.6.1.4.1.12356.101.12.3.1.1` for SSL-VPN sessions, but that subtree returns `noSuchObject` on real FortiGate firmware (the working OID lives under `…12.2.4.1`), so the walk produced nothing and the result was silently swallowed — `GetAllVPNTunnels` always returned zero SSL-VPN users/sessions and the poller's `UpdateDeviceSSLVPN` branch never fired. Since the deployment doesn't use FortiGate SSL-VPN (and Fortinet is deprecating the feature), this is removed rather than fixed: the `SSLVPNBaseOID`/`ParseSSLVPNStatus`/`ParseSSLVPNTunnels` methods are gone from the `VendorProfile` interface and all 6 vendor implementations + 2 shared helpers; `GetAllVPNTunnels` is now `([]VPNStatus, error)` (the two always-zero SSL-VPN return values dropped); the unused `SNMPClient.GetSSLVPNStatus` and `Database.UpdateDeviceSSLVPN` are deleted; and the poller's dead SSL-VPN block is removed. Behavior-preserving — every removed path already returned nothing. **Not touched:** the live SSL-VPN session counts shown on the device-detail page (sourced from `SystemStatus`, which the collector populates via the correct scalar OIDs) and the connection-map's `TunnelType=="sslvpn"` handling (operates on collector-fed VPN data). Verified by the poller characterization test + the full SNMP suite.

## [0.10.454] - 2026-06-21
### Fixed
- **Editing a device no longer forces you to re-enter secrets to save an unrelated change (`web/admin/admin.html`, `cmd/api/static/js/admin-main.js`).** The device-edit form blocked saving an SSH-polling device with *"SSH Password is required when SSH polling is enabled"* whenever the (always-blanked-on-edit) SSH password field was empty — so changing the SNMP community, say, demanded re-typing the SSH password. The backend was already correct (it's a partial update that drops blank/masked secrets — v0.10.324), so this was purely the front end. The edit flow is now consistent and professional: **every** secret field (SNMP community, SNMPv3 auth/privacy passwords, SSH password) is blank on edit with a "leave blank to keep current" hint shown only when editing, and a secret is **sent to the server only if you actually type a new value** — so unrelated edits never resend the `********` mask or overwrite a stored secret. An SSH password is required only when there are no stored credentials yet (a new device, or one with no SSH username on record), not on every edit.

## [0.10.453] - 2026-06-21
### Fixed
- **The admin Sites page (`/admin/sites`) was missing its "+ Add Site" button (`web/admin/sites.html`).** All the create-site machinery already existed — the `CreateSite` handler + `POST /api/sites` route on the backend, and `showAddModal`/the `show-add-modal` event handler/the `site-modal` form in `admin-sites.js` (the empty-state even read "Click '+ Add Site' to create one") — but no button in the page header actually triggered it, so there was no way to add a site from the UI. Added the button to the page header, matching the Probes page pattern.

## [0.10.452] - 2026-06-21
### Changed
- **SSH host-key change detection is now HA-aware and tracks a *set* of known-good keys per device (refines v0.10.451).** FortiGate HA cluster members each present their own SSH host key, so a failover legitimately changes the observed key — the previous single-pinned-key design would have fired a CRITICAL "possible MITM" on every failover. `Device.SSHHostKeys` (the same `ssh_host_key` column, now a newline-joined set) holds every key learned for a device. A reported fingerprint already in the set is a no-op (so failing back and forth between known members is silent); a never-before-seen key on a device with **no** prior keys is pinned silently (trust-on-first-use); a never-before-seen key on a device that already has keys is added to the set and classified: if it correlates with a **recent HA failover** — detected via `Database.RecentHAFailover`, which checks for ≥2 distinct `ha_status` master serials in the last hour — it raises a **WARNING** ("new HA member key learned"); otherwise it raises a **CRITICAL** ("possible MITM, rotate credentials"). The cooldown is now keyed per `(device, fingerprint)` so distinct new keys each alert once. Non-HA devices (no `ha_status`) and any query error default to the CRITICAL classification (fail-secure). Tests cover the full matrix: pin / no-op / return-to-known / unexplained-CRITICAL / HA-failover-WARNING / not-owned-by-probe.

## [0.10.451] - 2026-06-21
### Added
- **SSH host-key change detection (server side).** The collector reports the SSH host-key fingerprint it observes for each FortiGate it backs up; the server now pins, compares, and alerts on it. New `Device.SSHHostKey` column (migration v6 `device_ssh_host_key`, additive AutoMigrate — safe on a populated DB) holds the pinned `SHA256:…` fingerprint. The probe heartbeat (`ProbeHeartbeat`, `internal/api/handlers/handlers_probes.go`) gains an optional `observed_host_keys` map (device ID → fingerprint); for each device **assigned to the reporting probe** the server applies trust-on-first-use: a blank stored key is pinned with no alert, an unchanged key is a no-op, and a **changed** key fires one **CRITICAL** `SSH_HOST_KEY_CHANGED` alert (`AlertManager.CheckSSHHostKeyChanged`, modeled on `CheckDeviceOffline` as a transient/cooldown-gated alert with no recovery state) and then re-pins the new fingerprint. The alert message tells the operator to rotate the device admin credentials if the change was unplanned. Devices not owned by the reporting probe are ignored. This is the server half of the alert-only host-key MITM-detection design (the collector never blocks the connection); the collector-side capture/reporting ships separately. Severity is policy-overridable via `defaultSeverityForType`. Covered by new tests for the pin/no-op/change/ownership rule and the alert itself.

## [0.10.450] - 2026-06-21
### Removed
- **Deleted the obsolete bundled `cmd/probe` binary and its dead relay client.** `cmd/probe` (`fwmon-probe`) was a stale fork of pre-collector probe code: it never sent the `Authorization: Bearer` header the server requires, so it could not actually push data, and the production probe is the separate **Firewall-Collector** repo. It is now removed entirely — `cmd/probe/`, the `fwmon-probe` build/copy steps in the `Dockerfile`, the build/install/uninstall lines in the `Makefile` (server is now **3 binaries**: `fwmon-api`, `fwmon-poller`, `fwmon-trap`), and the binary's references in `README.md`, `SECURITY.md`, and `docs/architecture.md`. `internal/relay/relay.go` is trimmed from ~820 lines to the wire-contract definitions only — the `SchemaVersionMin/Max` handshake constants (still consumed by `handlers_probes.go`) and the JSON DTO structs that document the probe↔server contract per `MIGRATING.md`; all of the `RelayClient` send/registration/collector machinery (the only consumer of which was `cmd/probe`) is gone. The probe↔server `schema_version` handshake is unchanged and still verified on the server side. `go build ./...`, `go vet`, and the full test suite pass; four `internal/shell` static-guard tests that pinned properties of the deleted probe code were narrowed to the code that remains.

## [0.10.449] - 2026-06-21
### Changed
- **Made the SNMP poller's `pollDevice` testable and consolidated its uniform metric blocks (`cmd/poller/main.go`, `cmd/poller/polldevice_test.go`).** `pollDevice` constructed a live `*snmp.SNMPClient` directly, so it had no test coverage. A `deviceSNMP` interface now describes the getters it uses, and the `Poller` carries a `newSNMP` dialer wired to `snmp.NewSNMPClient` in `NewPoller` and overridable in tests; the device save path keeps using the real `*database.Database` (tests use the in-memory one). The two uniform `GetX → stamp → save` blocks (hardware sensors, processor stats) now go through a generic `pollAndSave` helper that preserves each block's exact log wording; the special blocks stay inline (system-status and interface-stats early-return on error and run alert/spike checks, interface-addresses logs a count, VPN has a multi-value return and SSL-VPN update). Adds the first `pollDevice` characterization tests: a full poll persists every metric type and marks the device online, and a connect failure marks it offline and saves nothing. Behavior unchanged (`*snmp.SNMPClient` satisfies the interface).

## [0.10.448] - 2026-06-21
### Fixed
- **`CheckProbeDataFlow` no longer reads the policy cache and the alert cooldown/active-state maps without holding the alert-manager lock (`internal/alerts/alerts.go`).** The probe-data-lag loop called `resolveAlertConfig` (reads `policyCache`) and wrote `lastAlert`/`activeAlerts` outside `am.mu`, while every other firing path holds the lock — a latent data race with concurrent alert checks. The resolve, cooldown check, and state writes now run under one `am.mu` section, matching the rest of the manager.
### Changed
- **Extracted the repeated post-unlock "save each fired alert and send it unless suppressed" loop into `AlertManager.dispatchFired` (`internal/alerts/alerts.go`).** `CheckSystemStatus`, `CheckInterfaceStatus`, `CheckInterfaceErrors`, and `CheckVPNStatus` each carried a byte-identical copy of this dispatch loop (differing only in the log label). They now call the shared helper. Behavior is unchanged — alerts are still collected under the lock and dispatched after release; covered by a new `CheckInterfaceStatus` characterization test asserting the fire-once-then-cooldown path.

## [0.10.447] - 2026-06-21
### Changed
- **Upgraded `gosnmp` v1.40.0 → v1.43.2 to match the version the Firewall-Collector already runs in production.** The server (poller, trap-receiver) and the collector both poll the same firewalls over SNMP; pinning them to the same `gosnmp` release removes a source of subtle protocol-parsing differences between the two SNMP stacks. No code changes were required; `go build ./...`, `go vet`, and the full test suite pass on the new version.

## [0.10.446] - 2026-06-21
### Changed
- **Probe syslog and flow ingestion resolves unknown source IPs in one batched query instead of a lookup per record (`internal/api/handlers/handlers_data.go`, `internal/database/devices.go`).** `ReceiveSyslogMessages` and `ReceiveFlowSamples` called `ResolveDeviceByIP` once per device-less record — two queries each — so a 1,000-record batch could issue up to 2,000 lookups, multiplied across every batch at high volume. They now gather the distinct unresolved IPs and call a new `Database.ResolveDevicesByIPs`, which returns an `ip → device_id` map in two queries total (management IP first, then interface addresses — same precedence as `ResolveDeviceByIP`). Resolution results are unchanged; only the query count drops. (Flow samples with a zero timestamp in a batch now share one capture instant, matching the syslog handler.) Covered by a new precedence test.

## [0.10.445] - 2026-06-20
### Fixed
- **Poller no longer accumulates previous-interface-stats entries indefinitely (`cmd/poller/main.go`).** `prevIfaceStats` — the per-interface baseline used for throughput-delta and error-rate checks — was written every poll cycle but never pruned, so a decommissioned device or a removed dynamic tunnel left its entry in the map for the life of the process (a slow memory leak in the long-running poller). Each cycle now drops entries not refreshed within a generous TTL (12× the poll interval, minimum 1h); live interfaces re-stamp every cycle so active baselines are retained. Covered by a new unit test.

## [0.10.444] - 2026-06-20
### Fixed
- **`metrics.RegisterDBPool` no longer panics (and crashes the API) on a non-duplicate registration error (`internal/metrics/metrics.go`).** A duplicate registration was already swallowed, but any *other* `prometheus.Register` error (a name collision with a different collector, registry corruption) hit a bare `panic(err)` — taking down the whole API process over a lost observability gauge. Now logged via `slog.Warn` and skipped: the pool's gauges go missing, but the process the gauges exist to monitor keeps serving. audit Tier 0 (B6).

## [0.10.443] - 2026-06-20
### Changed
- **FortiGate config-diff volatile patterns are now declared once and shared between the hash normalizer and the UI (`internal/configdiff/vendor_fortigate.go`).** Each volatile pattern body (ENC ciphertext, config-version/conf_file_ver headers, private-encryption-key, last-login, last-updated, system-time, prompt-prefix, PEM block) existed as two hand-copied copies: the compiled `regexp` used by `Normalize` (which feeds the change-detection hash) and the string returned by `VolatilePatterns()` (which the compare UI uses to highlight masked regions). Editing one but not the other would silently desync what the UI shows as masked from what the hash actually neutralizes. Extracted each body into a single `const`; the compiled regexes prepend `(?m)` (the PEM body keeps its own `(?s)`), and `VolatilePatterns` references the same consts. Verified byte-identical to the previous patterns — zero behavior change. audit Tier 0 (B3).

## [0.10.442] - 2026-06-20
### Changed
- **`GetSyslogMessages` now applies its filters through a single closure shared by the list query and the COUNT query (`internal/api/handlers/handlers_analytics.go`).** The four filters (probe_id, device_id, severity, search) plus the time-window cutoff were previously hand-copied into two separate `gorm` query builders. They were identical, so totals were correct today — but editing one block and not the other (e.g. adding a filter) would silently desync the pager total from the rows returned. Extracted one local `applyFilters(q)` so both queries provably share the same predicates. Behavior-preserving; no API change. audit Tier 0 (B2).

## [0.10.441] - 2026-06-20
### Fixed
- **`secrets.LoadOrGenerate` now fsyncs the secret before publishing it, fixing the intermittent "secret file empty after concurrent write" flake (`internal/secrets/secrets.go`).** The generate path writes the token to a temp file and `os.Link`s it into place so the final file only ever appears fully-written. But it never called `tmp.Sync()` before the link, so on some filesystems (notably Windows, and on any platform after a crash) the hard-linked directory entry could become visible while the inode's data blocks were still buffered — a racing re-reader or a post-crash reader would then see the file present but zero-length. Added `tmp.Sync()` before `os.Link`, so the content is durable before it is reachable, and made the race-loser's re-read retry a few times (5×5ms) instead of hard-failing on a transient empty read. This is a real durability fix, not only a test stabilizer (`go test -race` could never have caught it — it is filesystem visibility, not a Go memory race). First item of the v0.10.441+ adversarial audit refactor pass.

## [0.10.440] - 2026-06-20
### Added
- **Semantic, per-object config diff for FortiGate (replaces the line-only diff in the compare view).** A new object parser (`internal/configdiff/parse_fortigate.go`, exposed via the optional `configdiff.ObjectParser` capability) turns a FortiOS config into vendor-neutral `ConfigObject`s — firewall policies, address objects, interfaces, admins, IPsec tunnels, BGP neighbors, singleton settings blocks — by depth-walking `config/edit/next/end` and flattening nested blocks into dotted attribute keys. `configdiff.DiffObjects` then reports per-object **added / removed / modified** with attribute-level before/after, parsing the *normalized* text so ENC/IV churn never shows as a phantom change. The compare modal now defaults to a collapsible, risk-badged **Object view** (grouped by kind) with a **Raw diff** toggle that preserves the previous line view. Vendors without a parser fall back to the line diff automatically.
- **Security risk classification of detected changes (`internal/configdiff/classify.go`).** Each object change is tagged with a severity (`info`/`medium`/`high`/`critical`), category, and a human "security impact" summary: a firewall rule opened to ANY (src/dst/service), a rule disabled or deleted, traffic logging turned off, a new admin or widened `trusthost`, a weakened IPsec proposal/DH group, or cleartext management access (`telnet`/`http`) enabled on an interface. The rule set is data-driven with a reserved `ComplianceTags` hook so PCI/NIST/CIS packs can be layered on later. The `CONFIG_CHANGE` alert is now severity-driven (was always `warning`) and its message carries the impact summary.
- **Change attribution — who/how/from-where — without TACACS+ (`internal/configdiff/forti_audit.go`).** On a real change the server correlates the new revision with the device's FortiGate config-change syslog events (already stored in `syslog_messages`) to populate `DeviceConfigRevision.ChangedBy` / `ChangedFrom` / `ChangeMethod` (`GUI`/`CLI(ssh)`/`jsconsole`/`API`) and `Attributed`. The compare modal and a new **Changed by** column in the Config History table surface it. A real change with no matching authenticated session **escalates the alert one severity notch** with a "possible out-of-band change" note, and is shown as an **⚠ out-of-band** badge in the table/modal. A tri-state (`AttributionChecked` + `Attributed`) distinguishes "correlation attempted, no session found" (genuine out-of-band) from "never correlated" (first-seen/merged rows), so un-correlated rows are never mislabeled. Schema migration v5 (`config_revision_attribution`) adds the columns idempotently.
- **`configcheck --objects` flag** prints the per-object semantic diff + risk classification for two real backups, for validating the parser/classifier against actual fleet configs before trusting the UI.
### Changed
- `configdiff.Analyze` now also returns `ObjectChanges` + a `ChangeSummary` (per-op counts, max severity, concatenated impact) when the vendor has an object parser; the diff API (`GET /api/devices/:id/config-history/diff`) returns `object_changes`, `summary`, and per-revision attribution fields. Existing line-diff fields are unchanged (no breaking change).

## [0.10.439] - 2026-06-19
### Added
- **`configcheck` tool to validate firewall config change-detection against real backups (`cmd/configcheck`).** Point it at two config files — `go run ./cmd/configcheck --vendor fortigate old.conf new.conf` — and it normalizes both, reports whether they would raise a config-change alert, prints the exact residual line diff that survived normalization (so you can see *why* an alert fired), and flags capture-mode mismatches. Built to triage false-positive config-change alerts from the field and to confirm a new volatile pattern is neutralized before shipping. Backed by a new reusable `configdiff.Analyze(vendor, a, b) Report` engine.
### Fixed
- **Eliminated three FortiGate config-change false-positive sources discovered from real FGT60F-7.4.12 backups.** The normalizer (`internal/configdiff/vendor_fortigate.go`) now: (1) **strips the per-admin `config gui-dashboard ... end` block** — pure GUI widget layout that FortiOS omits from `show full-configuration` but includes in a plain `show`, the single largest diff source between capture modes (depth-counted `config`/`end` matching, robust to nesting/indentation); (2) **masks `set last-updated <epoch>`** GUI widget timestamps that bump on every dashboard interaction; (3) **strips an echoed CLI prompt** (e.g. `FW-HOME # `) from console-captured backups so the following `#config-version` header still normalizes. On the real sample pair these cut the residual diff from 100 lines to 10 (all remaining lines explained by capture-mode difference).
- **Capture-mode mismatch detection (`configdiff.CaptureModeDetector`).** A new optional vendor capability classifies a FortiGate backup as `full-configuration` vs `show` by counting `set` lines in `config system global` (real samples: 207 vs 18; threshold 80). When the two backups were captured in different modes, `Analyze` flags it loudly — those can never hash-match regardless of normalization, so the fix is collector-side (capture consistently), not a phantom config change.

## [0.10.438] - 2026-06-19
### Reverted
- **Reverted the v0.10.437 dashboard probe-health wrap change.** The `white-space: nowrap` added to the `.last-hour` styles in `web/admin/admin.html` is removed, restoring the original layout (which the operator preferred). No render or version-significant behavior change beyond reverting that one CSS tweak.

## [0.10.437] - 2026-06-19
### Fixed
- **Dashboard probe-health "+N / hr" values no longer wrap onto two lines.** In the narrow 4-column probe-stat grid, the space before `hr` was a valid line-break point, so a value like `+25,320 / hr` could split (`+25,320 /` on line 1, `hr` on line 2). Added `white-space: nowrap` to the `.last-hour` style in both the dashboard probe cards (`.probe-card .probe-stat .lbl .last-hour`) and the probe detail modal (`.detail-stat .detail-lbl .last-hour`) in `web/admin/admin.html`. CSS-only; the parent `.probe-stat` already has `overflow: hidden`, so extreme values clip rather than break the grid layout.

## [0.10.436] - 2026-06-18
### Added
- **Report traffic spikes now show the source/destination/port/protocol of the traffic, so you can triage from the report without logging into the firewall.** A spike is detected from SNMP interface byte counters (which carry no per-conversation detail), but that detail lives in sFlow — so the report now **correlates** each device's spikes with flow data: it queries the top conversations on the spiking interface during the spike window (`GetInterfaceFlowConversations` in `internal/database/flows.go` — matches input *or* output ifIndex, excludes port-0/0, ranks by bytes) and lists them under the device's "Traffic Spikes" as **"Top Flows During Spikes (sampled)"** (e.g. `10.0.0.5 → 203.0.113.9:443 · TCP · 12.4 GB`). Appears only when sFlow data exists for that device/window (degrades silently otherwise). Wired through `DeviceReportData.SpikeFlows` → `DeviceCard.SpikeFlows` → `template_report.go`; figures are sampled (sFlow), shown for ranking/triage. Tests: `GetInterfaceFlowConversations` (filtering/ranking/window/port-0) and report render (rows present with flows, absent without).

## [0.10.435] - 2026-06-18
### Added
- **Spike-alert settings are now editable in the admin Settings UI.** The Spike Detection section (admin → Settings) already exposed *Enable Spike Alerts* and *Standard Deviation Threshold*; added a **Minimum Sustained Duration (minutes)** field (the `spike_min_duration_minutes` knob from v0.10.434) so operators can tune how long a spike must persist before it alerts without setting an env var. The shared number-input renderer now takes per-field min/max/step (the threshold stays 1–10 step 0.1; duration is 1–1440 step 1) — `cmd/api/static/js/admin-main.js`. Backend `UpdateSettings` allows + validates the new key (1–1440), and the poller already picks it up live via `RefreshThresholds`. No env var or restart needed.

## [0.10.434] - 2026-06-18
### Fixed
- **Real-time TRAFFIC_SPIKE alerts no longer panic: fixed the counter bug, made them weekly-periodic + tolerant, and gated them on 15-minute sustained duration with cooldown/auto-resolve.** The poller's real-time spike check (`cmd/poller/main.go`) had the bug the report fixed long ago — it fed **raw cumulative SNMP octet counters** into a std-dev test (counters only climb → fired on nearly every poll), with **no cooldown/dedup/recovery** (could re-alert every 60s) and **always "warning."** Rebuilt around a new `report.SeasonalSpikeDetector`:
  - **Real throughput**: derive bps from the **delta** of consecutive counters (using the poller's existing `prevIfaceStats` + real elapsed time; clamps resets), not the cumulative value.
  - **Weekly-periodic + tolerant baseline**: judge live bps against the interface's seasonal (weekday, hour ±1h) profile — built from 30 days of hourly history (`BuildSeasonalProfileFromChart`), refreshed every 6h per interface — so recurring/scheduled traffic (even on weekends, or running a little late) isn't flagged. Falls back to a rolling band until ≥10 samples / enough history accrues.
  - **15-minute sustained gate**: a spike must persist for `SpikeMinDurationMinutes` (default **15**, env `SPIKE_MIN_DURATION_MINUTES`, runtime-overridable via the `spike_min_duration_minutes` setting) before it alerts — momentary blips are ignored.
  - **One alert per event + auto-resolve + 30-min cooldown**: edge-triggered so a sustained spike alerts once; emits a single resolve when traffic returns to normal; cooldown guards against flapping. Severity is warning/critical by how far above the band.
  - Severity now reflects magnitude (was always "warning"). New config `SpikeMinDurationMinutes`. Tests: `SeasonalSpikeDetector` sustained-gate/cooldown/resolve and rolling fallback. (Note: real-time spike alerts remain **off by default** — `SPIKE_ALERT_ENABLED=false`.)

## [0.10.433] - 2026-06-18
### Changed
- **Report spike detection is now weekly-periodic and tolerant of timing drift, so weekend pauses and slightly-late jobs don't read as anomalies.** v0.10.432 made it hour-of-day aware; it now compares each point against the same **day-of-week + hour** (e.g. a Monday-morning ramp vs. prior Mondays, not vs. the quiet weekend) and against a **±1h neighborhood** of that slot, so a backup that runs early/late/long isn't flagged. New reusable `SeasonalProfile` (`BuildSeasonalProfile`/`Band`/`IsAnomalous` in `internal/report/spike.go`) bins history by (weekday, hour) with layered fallback ((weekday,hour±1) → hour-of-day → not-enough-history), and `detectSpikesTimeOfDay` uses it. The baseline window is now 30 days of hourly history for both daily and weekly reports (`baselineRange` in `data.go`) so each (weekday, hour) slot has ~4 samples; it still falls back to the rolling-window detector with under 3 days of history. Tests: weekday-aware (normal Monday ramp not flagged, off-hours Monday surge flagged), ±1h tolerance (delayed backup not flagged), and `Band` fallback. (The real-time TRAFFIC_SPIKE alert path gets the same treatment plus a 15-minute sustained gate in a follow-up.)

## [0.10.432] - 2026-06-18
### Changed
- **Report traffic-spike detection is now time-of-day aware, so recurring scheduled traffic (e.g. nightly backups) is no longer flagged as anomalous.** The detector was a single-window rolling standard-deviation test over just the report window — a nightly backup rising above the quiet evening before it was flagged (often "critical") every night, even though it's expected. Detection now learns each interface's normal level **per hour-of-day** from a multi-day baseline (`internal/report/spike.go` `detectSpikesTimeOfDay`): the busiest interface is pulled over a longer hourly window (7 days for the daily report, 30 days for the weekly — `baselineRangeForHours` in `data.go`), and a report-window point is only flagged if it exceeds the typical level *for that hour* across prior days. So a 2am backup that looks like every other night's 2am is left alone, while an unusual surge at a normally-quiet hour is still caught. The report window is excluded from its own baseline (a surge can't normalize against itself), and detection falls back to the original rolling-window method when there's under 3 days of history (fresh installs). Tests: `spike_timeofday_test.go` (recurring backup suppressed + daytime surge flagged; fallback; `distinctDays`).

## [0.10.431] - 2026-06-18
### Changed
- **Report charts are now large and readable instead of tiny/squished.** The three SVG charts in the report (alert timeline, per-device CPU/Memory history, and throughput) were rendered in ~105–120px-tall boxes with a ~70px plot area and 9px axis labels, so the lines were flattened and the labels nearly illegible. Bumped them to ~200–220px tall with proportionally larger plot areas, 12px axis labels, thicker (2.25px) trend lines, and more spacing for the x-axis labels and CPU/Mem legend (`internal/report/svg_charts.go`). No data or layout changes elsewhere.

## [0.10.430] - 2026-06-18
### Changed
- **Redesigned the daily/weekly report (`/admin/reports`, email, and PDF) as a light, document-grade "operations brief."** The old report used a near-black dashboard look that (a) read as a generic template and (b) printed/exported badly — `@media print` forced a white background but left the near-white body text, so "Export PDF" produced washed-out, low-contrast output. The report is now light-first (white paper on a soft gray field) and prints cleanly as dark ink on white. Key changes (`internal/report/template_report.go`, `model.go`, `svg_charts.go`):
  - **Letterhead**: a serif (Georgia) report title with a brand eyebrow, dateline, range chip, and a navy rule — reads like a briefing, not a dashboard.
  - **Status verdict band** (new signature element): a plain-language fleet-health headline the report leads with — "All systems nominal" / "Operational — minor activity" / "Attention required" — colored green/amber/red by severity, with a one-line summary. Backed by new `ReportModel` fields (`StatusLevel`/`StatusHeadline`/`StatusDetail`) computed in `BuildReportModel` (offline devices or critical alerts → critical; other alert/spike activity → minor; else nominal).
  - **Typography & data**: monospace, tabular metrics for KPIs/values; system-sans body; serif section headers. KPI strip shows Offline/Critical muted at zero and in red above zero.
  - **Charts restyled for light**: alert timeline (amber/red bars), throughput (navy area), CPU/Memory (red/blue) now use light gridlines and readable dark labels instead of white-on-dark.
  - Email-safe (tables + inline styles, no external assets) and print-safe, so it renders identically in the email body, the admin iframe, and a printed PDF. Updated `render_validate_test.go` for the new section labels.

## [0.10.429] - 2026-06-18
### Changed
- **sFlow: 6in4 tunnels are now decoded to their inner protocol instead of showing as "IPv6" (proto 41).** The bundled probe decoder (`internal/sflow/sflow.go`) now, when an IPv4 packet's protocol is 41 (IPv6 encapsulation), recurses into the inner IPv6 packet so the flow reflects the real conversation — inner IPv6 src/dst, the actual upper-layer protocol (TCP/UDP/ICMPv6), and ports — rather than a generic "IPv6 / port 0/0" entry. Truncated inner headers fall back to the outer IPv4 tunnel endpoints + protocol 41 (no panic). Mirrors the remote collector decoder (Firewall-Collector v1.2.118). Tests: `TestParseIPv4_6in4InnerDecode`, `TestParseIPv4_6in4Truncated`.

## [0.10.428] - 2026-06-18
### Fixed
- **Flows page: clicking a protocol in the Protocols list now filters/unfilters for every protocol (IPv6, IGMP, AH, SCTP, …), not just TCP/UDP/ICMP/GRE/ESP — and those protocols no longer appear falsely "selected."** The frontend `PROTOCOLS` map in `admin-flows.js` only listed 7 protocols, but the breakdown comes from the backend's fuller `protoNames` map. For any protocol missing from the frontend map (e.g. **IPv6 / proto 41**), the name→number reverse lookup returned `''`, so its row had an empty filter value: clicking it set the protocol filter to `''` (= "All") — a no-op — and because the default protocol filter is also `''`, the row rendered with the `active` highlight by default (the "IPv6 is auto-selected" symptom). Expanded `PROTOCOLS` to mirror the backend map and taught `protocolNumber` to parse the backend's `"Proto N"` fallback, so every protocol the breakdown can show is now clickable/toggleable and only highlights when actually filtered. Frontend-only.

## [0.10.427] - 2026-06-18
### Fixed
- **sFlow: IPv6 traffic no longer collapses into bogus "HOPOPT" / port-0 flows, and the Flows page Protocols breakdown stops being dominated by HOPOPT.** Two parts:
  - **Decoder (`internal/sflow/sflow.go`):** the bundled probe's sFlow decoder had no IPv6 path at all (only EtherType `0x0800` / raw IPv4) and returned `Protocol = 0` for any IPv6 packet. Added IPv6 support — EtherType `0x86DD` and raw `headerProto 12` now dispatch to a new `parseIPv6` that **walks the IPv6 extension-header chain** (Hop-by-Hop/Routing/Fragment/Dest-Options/AH, bounds-checked for truncated samples, capped against malformed chains) to the real upper-layer protocol before reading ports. Hop-by-Hop Options (Next Header = 0, common for MLD/multicast/Router-Alert) was the main source of spurious HOPOPT. Factored the shared TCP/UDP port parsing into a `parseTransport` helper used by both `parseIPv4` and `parseIPv6`. (The remote collector's decoder is fixed in Firewall-Collector v1.2.117.)
  - **Aggregation (`internal/database/flows.go`):** `GetFlowStats` now excludes protocol 0 (HOPOPT) from the `by_protocol` breakdown (`WHERE protocol <> 0` on both the raw and rollup queries). HOPOPT is never a legitimate terminal protocol in a flow record, so this drops the noise — including from already-stored rows decoded before the parser fix — while keeping legitimate portless protocols (ICMP/GRE/ESP/OSPF) visible. Note this is intentionally *not* the port-0 filter used by the top-talker charts, which would also hide ICMP/GRE/ESP.
  - Regression tests: `internal/sflow/ipv6_test.go` (Hop-by-Hop→TCP asserts protocol 6 + ports not 0, Hop-by-Hop→ICMPv6, chained ext-headers→UDP, truncated chain no-panic, short header) and `internal/database/flowstats_protocol_test.go` (HOPOPT excluded from breakdown while ICMP/TCP remain).

## [0.10.426] - 2026-06-18
### Fixed
- **Flows page: the Bandwidth Over Time chart's x-axis labels and legend are no longer hidden behind the Top Sources / Top Destinations cards.** `admin.html` ships a legacy inline `<style>` rule, `.chart-card { height: 340px }` (for old fixed-size Chart.js canvases), which — being an inline block loaded after every external stylesheet — won the cascade and pinned the bandwidth card to a fixed 340px. The uPlot chart (240px) plus its live legend, header, and padding exceed 340px, so with `overflow: visible` the bottom of the chart spilled below the card and the next-in-flow top-talker cards painted over it. Added a scoped, higher-specificity override (`.fwmon-flows .fwmon-bandwidth-card { height: auto; min-height: 280px; overflow: visible }`) so the card grows to fit its content. Scoped to the bandwidth card so the legacy fixed-height behavior used elsewhere is untouched. Verified the before/after with a headless-Chrome render of the real CSS stack (overlap +15.8px → −37.0px clearance).

## [0.10.425] - 2026-06-18
### Fixed
- **Flows page: the shared filter row now actually filters Top Conversations (and the top-talkers + bandwidth chart), not just Flow Samples.** Previously the aggregate views came from `/admin/api/flows/stats`, which only honored `hours` + `device_id` — so typing a src/dst/CIDR, dst port, protocol, or probe filter changed the Samples table but left Conversations untouched. `GetFlowStats` now takes a `FlowStatsFilter` (device, probe, protocol, dst port, src/dst IP or CIDR) and applies it to every aggregate (totals, unique counts, top sources/destinations/ports/protocols, conversations, and the bytes-over-time chart). Address filters reuse the same `cidrToLikePattern` logic as the samples list, so both views match identically. Notes: a **probe filter forces raw-only** aggregation because `flow_rollups` has no `probe_id` column (so longer ranges fall back to raw `flow_samples` when a probe is selected); **src port** isn't a stats filter because rollups don't store it. The frontend `statsURL()` now forwards all shared-filter params. Regression test: `flowstats_filter_test.go` (12 cases covering device/probe/protocol/port/exact-IP/CIDR/combined).

## [0.10.424] - 2026-06-18
### Changed
- **Flows page: "Top Conversations" and "Flow Samples" are now one tabbed table with a shared filter row.** Previously they were two stacked cards, each consuming vertical space and only Flow Samples had a filter row. They're now combined into a single card with **Top Conversations / Flow Samples** tabs and one shared filter bar (device · probe · protocol pills · src/dst/CIDR · dst port · clear) above both views, so the operator picks what to focus on and the active table gets the full height (600px). Switching tabs is instant (both data sources are already fetched on each reload — no extra round-trip). Clicking a conversation now sets the src/dst/port filters **and** drops you into the Samples tab to inspect that conversation's raw flows. The active tab is persisted in the URL (`?tab=samples`) so the view is shareable and survives refresh. Conversations honor the device + range filters; Samples honor all filters (unchanged backend behavior).

## [0.10.423] - 2026-06-18
### Fixed
- **Admin → Data → Syslog now loads fast and shows a sane pager instead of "1 of 3,353,148".** The `/api/syslog` list endpoint ran an exact `COUNT(*)` over the entire partitioned `syslog_messages` table on every page load (and every Prev/Next), with no time bound — at prod volume that's millions of rows, a full scan across all monthly partitions, which both made the page slow and produced the nonsensical all-time total in the pager. The endpoint now honors the `hours` time window the admin UI already sends via its range pills (default 24h) for *both* the row list and the count, so Postgres can prune partitions and use the `timestamp` index. The "Showing X–Y of N" / "Page X of Y" totals now reflect the selected range; widen the range pill to see further back.

## [0.10.422] - 2026-06-17
### Changed
- **Telemetry is now preserved as a running total when a probe is replaced or a device is removed — no more disappearing dashboard numbers or duplicate ping rows** (v0.10.422). Three related fixes:
  - **Probes are soft-decommissioned, not hard-deleted.** Removing a replaced probe previously dropped its accumulated counts from the "Data Totals (All Probes)" card (those summed only probes that still existed). The Probes page now offers **Decommission** (for approved probes) and **Restore** instead of Delete: decommissioning sets `Probe.DecommissionedAt`, keeps the row and ALL its telemetry, disables the probe, and hides it from the active lists (new "Decommissioned" filter tab + badge) and the dashboard's active-probe count — but its data still counts. The reassign-devices-first guard (`ErrProbeHasDevices`) is kept. New `DecommissionProbe`/`RecommissionProbe` DB methods + `POST /api/probes/:id/{decommission,recommission}`. A hard `Delete` remains only for never-approved (pending/rejected) probes that never collected data.
  - **"Data Totals (All Probes)" is now orphan-safe.** It reads a new `GET /api/probes/stats/global` (`GetTelemetryTotals`) that counts ALL syslog/trap/flow/ping rows with no probe filter, so the totals never drop even if the collecting probe was decommissioned or deleted.
  - **Deleting a DEVICE no longer erases its history.** `DeleteDevice` previously physically cascade-deleted 11 telemetry tables (system_status, interface_stats, vpn_status, ha_status, hardware_sensors, processor_stats, alerts, uptime_records, trap_events, device_tunnels, interface_addresses). It now removes only the device row and its user-drawn connection-map entries; the telemetry is orphaned and preserved (matching how syslog/flow/ping already survived a device delete). `DeleteSite` already orphaned telemetry — unchanged.
  - **Ping stats are unified per (device, target).** The device-detail Ping tab showed one duplicate row per probe because `PingStats` was keyed by `(device_id, probe_id, target_ip)`. It's now a single continuous series per `(device_id, target_ip)` (probe_id kept as last-writer provenance), so a device's reachability history stays intact across probe replacements and shows one row per target.
  - **Migrations:** v3 `unify_ping_stats_by_device_target` merges existing duplicate ping rows (min/max, sample-weighted avg & loss, summed samples) and swaps the uniqueness index; v4 `probe_decommissioned_at` adds the new column to existing DBs. Both idempotent; `ping_stats` is small and unpartitioned. Regression tests cover decommission/restore + guard, device-delete telemetry preservation, orphan-safe totals, the ping merge, and the full v1→v4 chain. Embedded in the binary + schema change — redeploy required (migrations auto-apply on startup).

## [0.10.421] - 2026-06-17
### Fixed
- **Directly-polled FortiGate hardware sensors now carry a Unit and Type** (v0.10.421). Follow-up to v0.10.420: the server poller's `ParseHardwareSensors` set only Name/Value/Status, leaving Unit and Type empty, so the device-detail Hardware tab showed sensor readings with no unit label (e.g. a bare `52.5` instead of `52.5 °C`) for FortiGates polled directly by `fwmon-poller`. Ported the collector's `inferSensorUnit` helper to `internal/snmp/vendor_fortigate.go` — it derives Type/Unit from the sensor-name pattern (temp/dts/lm75 → temperature/°C, fan → fan/RPM, vcc/vdd/+N.N/volt → voltage/mV, ps+status → power) because the FortiGate `fgHwSensorTable` has no unit column. Now directly-polled and probe-collected FortiGates render identical Unit/Type. Extended the regression test (`internal/snmp/vendor_fortigate_test.go`) to assert temperature→°C and fan→RPM. No change for collector-based devices (the collector already inferred these).

## [0.10.420] - 2026-06-17
### Fixed
- **FortiGate hardware-sensor temperatures (and voltages) showed `0.0` on the device-detail Hardware tab** (v0.10.420). For directly-polled FortiGate devices, the server's SNMP poller parsed `fgHwSensorEntValue` (`.1.3.6.1.4.1.12356.101.4.3.2.1.3`) with `gosnmp.ToBigInt(pdu.Value).Int64()`. That OID is a **DisplayString** — gosnmp delivers it as a `[]byte` of text like `"52.500000"` — and `ToBigInt` returns `0` for a `[]byte` (and rejects the decimal point via `strconv.ParseInt` even for a numeric string), so every non-integer reading was silently zeroed before being stored. Added a `safeFloat` helper (`internal/snmp/snmp.go`) that parses DisplayString/OctetString values as floats while still handling numeric PDU types, and switched the FortiGate sensor-value parse to use it (`internal/snmp/vendor_fortigate.go`). Integer-valued sensors (fan RPM) were unaffected. Added a regression test (`internal/snmp/vendor_fortigate_test.go`) asserting a `"52.500000"` DisplayString parses to `52.5`, not `0`. **This is the same root-cause bug fixed on the remote collector in Firewall-Collector v1.2.116** — collector-based devices are fixed by that release; this server change covers FortiGates polled directly by `fwmon-poller`. (Note: the server poller's `ParseHardwareSensors` still does not infer sensor Unit/Type the way the collector does — a separate cosmetic gap, not the zeroing bug.)

## [0.10.419] - 2026-06-17
### Removed
- **Removed the standalone `/admin/probe-pending` page, its route, and the now-dead backend that fed it** (v0.10.419). Follow-up to v0.10.418, which only hid the nav link: the page's entire approve/reject workflow is already covered by the Probes page's **Pending** filter tab (same `POST /probes/:id/approve` and `/reject` endpoints), so the separate page had no remaining purpose. Deleted end-to-end: the page template (`web/admin/probe-pending.html`) and its client logic (`cmd/api/static/js/admin-probe-pending.js`), the `GET /admin/probe-pending` HTML route and the `GET /admin/api/probes/pending` data route (`cmd/api/main.go`), the now-orphaned `GetPendingProbes` handler (`internal/api/handlers/handlers_probes.go`) and the `(*Database).GetPendingProbes` query method (`internal/database/sites_probes.go`), and the leftover `probe-pending` `pageMap`/`pageIcons`/nav-comment entries in `admin-common.js`. Updated the static regression tests that enumerated the page (`labelfor_audit056_test.go`, `mobilechrome_audit055_test.go`, `spa_pages_nav_test.go`) and refreshed stale comments that referenced the old reject flow. The Probes page approve/reject flow is unchanged. Frontend + route + handler change; embedded in the binary, so a redeploy is needed to ship it.

## [0.10.418] - 2026-06-17
### Changed
- **Hid the standalone "Pending" link from the Infrastructure nav section** (v0.10.418). Verified that the Probes page (`/admin/probes`) now fully covers the pending-probe approval workflow: it has a **Pending** filter tab (filtering on `approval_status === 'pending'`) and Approve/Reject buttons that call the same `POST /admin/api/probes/:id/approve` and `/reject` endpoints as the dedicated Pending page, plus a styled reject-reason modal. The separate `admin-probe-pending.js` page is a strict subset of that functionality, so the top-level link was redundant. Removed only the `<a>` nav item in `renderSidebar` (`admin-common.js`); the `/admin/probe-pending` route, page, and JS remain intact and reachable by direct URL (and the `probe-pending` `pageMap`/`pageIcons` entries are left in place for active-state highlighting). Frontend-only, embedded in the binary — a redeploy is needed to ship it.

## [0.10.417] - 2026-06-17
### Removed
- **Removed the standalone `/admin/interfaces` page, its sidebar link, and the dead backend that fed it** (v0.10.417). The "All Interfaces" view was a fleet-wide table that simply re-listed every device's interfaces — the same data already shown per-device on each device-detail page — so it was a redundant second copy with no unique function. Removed end-to-end: the **Interfaces** nav item and its page/icon entries (`admin-common.js` `renderSidebar`), the `#page-interfaces` section and its filter/table/pagination markup (`web/admin/admin.html`), the page's client logic (`loadInterfaces`/`fetchInterfaces`/`populateIfaceFilters`/`ifacePrevPage`/`ifaceNextPage` plus the now-orphaned `formatIfaceSpeed`/`formatBytesShort` helpers and `ifacePage`/`ifacePageSize` state, and the `interfaces` entries in `loadPageData`, the URL `pageMap`, `SPA_PAGES`, and the click-delegation actions in `admin-main.js`), the `GET /admin/interfaces` HTML route and the `GET /admin/api/interfaces` data route (`cmd/api/main.go`), and the now-unused `GetAllInterfaces` handler (`internal/api/handlers/handlers_devices.go`). The public read-only `/interfaces` + `/interfaces/chart` endpoints and all per-device interface views/charts are untouched. Frontend + route change; embedded in the binary, so a redeploy is needed to ship it.

## [0.10.416] - 2026-06-17
### Fixed
- **Dashboard "Probe Health" cards no longer flash back to "loading..." on every 30s refresh** (v0.10.416). The dashboard auto-refreshes `loadDashboard()` every 30 seconds, and each refresh fully rebuilt the `probe-health-cards` inner HTML — recreating each card's per-probe stats grid with the `loading...` placeholder before the async `/probes/{id}/stats` fetch refilled it. That meant the Syslog/Traps/Flows/Pings numbers visibly reverted to "loading..." for a moment on every cycle, not just on the first page load. Fix: a module-level `probeStatsCache` (keyed by probe id) now holds each probe's last `last_hour` stats; refreshes re-render the cards with the cached numbers immediately, and the `loading...` placeholder only appears the very first time a probe is seen (before its first stats fetch returns). The card scaffolding and the per-probe stats markup are now driven through one shared `renderProbeStatsInner(lh)` helper. Frontend-only (`cmd/api/static/js/admin-main.js`); embedded in the binary, so a redeploy is needed to ship it.

## [0.10.415] - 2026-06-11
### Added
- **Full sFlow NOC redesign plan saved as `tasks/SFLOW-NOC-REDESIGN-PLAN.md`** (v0.10.415). After the 2026-06-11 audit flagged 8.5% test coverage on `internal/sflow`, IPv6 traffic invisible to the parser, counter samples (ifInOctets/ifOutOctets) silently discarded, and `Bytes` never multiplied by `SamplingRate` (every chart understated real traffic by 1:N), the user requested a from-scratch redesign of the sFlow reporting pipeline. The plan covers 5 minor releases (`0.11.0` → `0.15.0`) over ~8–9 weeks: (0) data correctness (bytes×rate, drops, sequence numbers, rollup indexes), (1) counter samples + IPv6 + sFlow-native interface bandwidth alongside SNMP, (2) `SO_REUSEPORT` worker pool + per-agent token-bucket rate limit + in-memory top-K/HLL aggregator + SSE + `pgx.CopyFrom` bulk insert + Tier-1 detectors, (3) new `/admin/noc` page with the proven 6-zone NOC layout (status strip / top talkers / stacked throughput / top ports / anomaly ticker / per-device interface bandwidth) with click-to-filter and detail side-panel, (4) hardening + delete the bundled `cmd/probe` (per CHANGELOG v0.10.412 XR-1) + parse the remaining extended records + CIDR allowlist + 100% parser test coverage. The plan is self-contained (~1,400 lines, 18 sections) with cited sflow.org spec references, full DDL for all 5 new tables, code-diff-level implementation specs per phase, per-phase acceptance criteria and rollback strategy, an operational runbook, and an explicit decisions log. Wire protocol unchanged (30s JSON batch stays). Zero new infrastructure dependencies — no Kafka, no ClickHouse, no second store. **Docs-only, no redeploy needed.** (Plan lives at `tasks/SFLOW-NOC-REDESIGN-PLAN.md`; the 6 new project rules captured during planning live at `tasks/lessons.md`.)

## [0.10.414] - 2026-06-11
### Changed
- **Restored the CHANGELOG to the project's per-version `## [x.y.z] - date` format.** Recent entries (v0.10.302–413) had drifted into a single `## [Unreleased]` Keep-A-Changelog blob — grouped `### Added/Changed/Fixed` with inline `(vX.Y.Z)` tags — a format this repo never used historically (see its `<= 0.10.281` sections) and that the sibling Firewall-Collector does not use. Converted that blob back into per-version `## [x.y.z] - date` sections, newest first, with **zero prose changes** (a content-preservation gate verified every line survived byte-for-byte; versions/dates were recovered from `cmd/api/main.go` history). The `TestChangelog_KeepAChangelogHeader_AUDIT110` static check now enforces the per-version convention (the first section must be a concrete version, not `## [Unreleased]`) instead of mandating the `[Unreleased]` accumulator. Docs/test-only; no runtime change.

## [0.10.413] - 2026-06-11
### Fixed
- **CI integration lane has been RED since 2026-06-09 — fixed the root cause** (v0.10.413). The `Integration (PostgreSQL)` job failed at the first setup step of `TestEndToEndIngestion_Postgres_AUDIT123` with `insert or update on table "probes" violates foreign key constraint "fk_sites_probes" (SQLSTATE 23503)`. Root cause: the shared test helper `setupProbeAndDevice` (`internal/api/handlers/testhelper_test.go`) created a probe with no site, so `Probe.SiteID` (a **non-nullable `uint`** with a FK to `sites`) defaulted to `0` — and no `sites` row has id `0`. **Postgres enforces the FK; the local SQLite default does not**, which is exactly why `go test ./...` passed locally while CI stayed red and nobody caught it for ~5 commits. Fix: the helper now seeds a real `Site` and sets `probe.SiteID` to it. Test-only change; no production code affected. The unit-test (SQLite) lane is unchanged and still green.

## [0.10.412] - 2026-06-11
### Added
- **Paired-repo internal audit (2026-06-11) saved as `tasks/audit-2026-06-11.md`.** Six parallel subagent reviewers per repo (security, performance, reliability, code-quality, test coverage, ops/DX) plus a cross-repo integration reviewer produced 172 findings — 13 blocker, 41 high, 67 medium, 51 low — with file:line refs and concrete fixes on both sides. **The headline finding corrects yesterday's 06-10 audit** (this report supersedes `tasks/audit-2026-06-10.md`): the "probe never sends `Authorization: Bearer`" claim (H-3) is **true for the server's own bundled `cmd/probe`** at `internal/relay/relay.go:265, 307, 475, 653, 676, 699, 773, 793, 813`, **not for the production sibling-repo collector** (which sends the header correctly on every authenticated request). The 12 subagent reviews and the prior audit conflated the two `internal/relay` packages. **Top 5 must-fix** (see the report for the full list):
  1. **XR-1 [blocker]** — Server bundled `cmd/probe` `Authorization: Bearer` is missing. The fix is to **delete the bundled probe** entirely — it's a stale fork of pre-collector code (~800 LoC) that should not exist alongside the production collector.
  2. **XR-2 [blocker]** — Server has no `mTLS` client-cert verification despite the sibling collector shipping mTLS support. `cmd/api/main.go:411-438` instantiates `http.Server{}` with no `TLSConfig` field. The collector's `PROBE_TLS_CERT` knobs load silently but have zero effect. The "we use mTLS" claim in any deployment is false until fixed.
  3. **XR-7 [blocker]** — `BatchInserter` is in-memory only (`internal/database/batcher.go:20-22` — explicit "AUDIT-006 (durability half) deferred" comment). The sibling probe is durable (BoltDB), the server is not. A `fwmon-api` crash mid-batch loses in-flight telemetry with no recovery path.
  4. **XR-3 [high]** — `X-Probe-Batch-ID` is sent on every event batch by the probe, but only **4 of 18** server `Receive*` handlers honor it (`ReceiveSyslogMessages`, `ReceiveTrapEvents`, `ReceiveFlowSamples`, `ReceivePingResults`). The other 14 silently dupe rows on retry. ~15 minutes of mechanical work to add `batchDedupCheck` + `defer markBatchIfOK` to each.
  5. **MON-PERF-B-1 [blocker]** — `GetProbeStats` fires **104 sequential queries** per page load (`internal/api/handlers/handlers_probes.go:713-809`). Sibling `GetProbesStatsBatch` does it in 8 queries. The endpoint is still mounted at `cmd/api/main.go:710`. **Fix: delete it** (or hardcode to return `[]` and document deprecation).
  No code changes — read-only audit. Recommended remediation sequencing (Sprint 1 = items 1-4 above) is in the report. Docs-only, no redeploy needed.

## [0.10.411] - 2026-06-11
### Added
- **Alerts now auto-resolve and clear themselves when the condition recovers — the NOC no longer hand-clears both the "down" and "back up" rows** (v0.10.411). When a recovery signal fires (device back online, interface up, VPN tunnel up, CPU/MEM/DISK/SESSIONS back under threshold, `LINK_UP` trap, probe data flowing again), the matching OPEN alert is now **resolved AND acknowledged** in one step (`resolved_at` + `acknowledged` + an `"Auto-resolved: …"` note), so it leaves the default open queue automatically. The companion `*_RESOLVED` record is created pre-closed (acked+resolved) instead of as a second open ticket. Net effect: a self-healing flap produces **zero** rows the NOC must clear, while the recovery notification email still fires and both rows stay visible (with a green **RESOLVED** badge) under the "Acknowledged" filter for flap investigation. Changes are server-side in the poller's `AlertManager.sendRecovery` (`internal/alerts/alerts.go`) plus the admin alerts UI badge (`cmd/api/static/js/admin-main.js`). **Requires a redeploy** (poller binary + embedded JS).
  - **Correctness fix bundled in:** recovery resolution was previously scoped by `device_id + alert_type` only, so a single interface coming back up would wrongly resolve **every** `INTERFACE_DOWN`/`VPN_TUNNEL_DOWN` alert on that device. Resolution is now scoped to the specific resource via `metric_name` (`interface_<name>` / `vpn_<tunnel>` / `device_status` / …) — the recovered resource and nothing else. One-shot alert types with no clear signal (SYSLOG_*, CONFIG_CHANGE, INTERFACE_ERRORS, PROBE_DATA_TRUNCATED) are intentionally left manual.
  - **Restart-robust:** the DB resolve now always runs (idempotent), decoupled from the poller's in-memory `activeAlerts`, so an offline alert orphaned by a poller restart still auto-clears on the next recovery — but a cold resolve stays silent (no duplicate companion / no re-notification). Tests: `TestSendRecovery_PreciseLinking`, `TestSendRecovery_AutoAcknowledge`, `TestCheckDeviceOnline_RestartOrphan`, `TestSendRecovery_Idempotent`, `TestSendRecovery_PerDeviceBackwardCompat` (`internal/alerts/auto_resolve_test.go`).
- **audit (2026-06-10) saved as `tasks/audit-2026-06-10.md`.** Six parallel subagent reviews (security, performance, reliability, code-quality, test coverage, ops/DX) produced 104 findings — 1 blocker, 29 high, 43 medium, 31 low — with file:line references and concrete fixes. The full aggregated report is committed to `tasks/` so future contributors and audits can build on it instead of re-deriving the same findings. **Top 5 priority issues** (see the report for the full list):
  1. **B-1 perf** — `GetProbeStats` fires 104 sequential queries per page load; sibling `GetProbesStatsBatch` already does it in 8 (`internal/api/handlers/handlers_probes.go:727-793`).
  2. **H-3 security** — probe wire-format is broken: the relay client never sends the `Authorization: Bearer` header the server requires, so no probe can currently push data with the current client (`internal/relay/relay.go:265, 307, 475, 653, 676, 699, 773, 793, 813`).
  3. **H-1 security** — `/api/public/connections` leaks the full fleet topology without auth — it skips the `public_visible` filter that sibling endpoints honor (`internal/api/handlers/handlers_dashboard.go:425-426`).
  4. **H-2 security** — login LRU rate-limiter fails open with a fresh full burst per new IP, defeating the per-username lockout against credential-spray attacks (`internal/api/middleware/middleware.go:85-92, 174-187`).
  5. **B-1 tests** — `internal/relay/` at 1.8% coverage; 822 LoC of probe→server client has no behavior tests (`internal/relay/relay.go:151-822`).
  No code changes — read-only audit. Recommended remediation sequencing (Sprint 1 = items 1-4 above) is in the report. Docs-only, no redeploy needed.


## [0.10.410] - 2026-06-09
### Added
- **Drag-to-zoom re-query on the interface & VPN-tunnel charts + adaptive bucketing for readability** (v0.10.410). Two related improvements to the device-detail bandwidth charts:
  - **Readability:** the per-interface chart endpoint previously returned **minute** buckets for the whole 24h range — up to ~1440 points crammed into a small chart, which painted as unreadable noise. Both chart endpoints now bucket **adaptively** by window duration (`bucketUnitForWindow` in `internal/database/charts.go`): ≤3h→minute, ≤30h→5min (24h ≈ 288 pts), ≤8d→hour, ≤60d→6hour, else→day — targeting a readable ~90–360 points at every zoom level. A new `6hour` tier was added to the dialect `TimeBucket` (true 6-hour bucketing on Postgres).
  - **Drag-to-zoom:** dragging horizontally across a chart now **re-queries the backend for exactly that window** and redraws it at the finer adaptive bucket size, revealing detail that was averaged away at the wider zoom — not a client-side pixel zoom. Implemented end-to-end: the chart endpoints accept an explicit `from`/`to` (epoch-ms) window (`httputil.ParseChartWindow`, precedence over the `range` preset) backed by new windowed DB queries (`GetInterfaceChartWindow` / `GetVPNChartWindow`) that also return a per-bucket `bucket_ms`; the frontend (`chartjs-plugin-zoom`, now loaded on device-detail) maps the dragged category range to those timestamps, shows a "🔍 \<window\> ✕" reset chip, and reverts to the preset on reset or range-pill click. The Mbps math now derives each bucket's interval from consecutive `bucket_ms` gaps (median fallback), so throughput stays correct at any adaptive bucket size. **Existing consumers unaffected:** `GetInterfaceChartData`/`GetVPNChartData` (and their fixed bucketing) are retained for the report + connection-detail paths; the added `bucket_ms` field is ignored by them. Tests: `TestBucketUnitForWindow`, `TestGetInterfaceChartWindow`, `TestGetVPNChartWindow`, `TestParseChartWindow`. **Requires a redeploy** (JS/CSS/HTML embedded via `//go:embed static`; backend query change).


## [0.10.409] - 2026-06-09
### Changed
- **QA follow-up to the 3-mode graphs: byte-axis units now match the rest of the UI** (v0.10.409). A full QA pass on the v0.10.408 charts found the new `FwmonBwChart` module's `formatBytes` used **decimal** units (1000-based, 2 decimals → "14.30 MB") while both the public dashboard and the admin device-detail table cells use **binary** units (1024-based, 1 decimal → "14.3 MB"). On the Transfer/Combined views that meant the chart's byte axis disagreed with the "Bytes In/Out" cells in the very same expand row. Aligned the module's `formatBytes` to the existing 1024-based, 1-decimal convention so the axis reads identically to the table above it and to the public page. The 3-mode rendering and the interface/tunnel delta→Mbps math were independently verified (every mode builds a valid Chart.js config; bucket-seconds match `internal/database/charts.go`; counter resets clamp to 0; bucket-string label offsets match the dialect's `to_char`/`strftime` output for all ranges). **Requires a redeploy** (JS embedded via `//go:embed static`).

### Added
- **Report HTML/SVG well-formedness regression test (`TestReportHTMLWellFormed`)** (v0.10.409). The existing report tests only assert that certain substrings are present; nothing verified the rendered document was actually *valid*. The new test renders the executive report in both the email (flat) and admin-preview (collapsible) layouts, across both hourly (24h) and daily (168h) alert bucketing, and asserts: it parses cleanly as an HTML5 document (`golang.org/x/net/html`); **every embedded SVG chart fragment is well-formed XML** (strict `encoding/xml` parse — catches an unclosed tag or stray `&`/`<` in any of the three SVG generators); structural tag pairs (`table`/`svg`/`defs`/`style`/`g`/`details`) balance; there are **no Go-template rendering artifacts** (`<no value>`, `ZgotmplZ`, `%!…`, `<nil>`); the output is image/CID-free (email-safe); `Collapsible` toggles the `<details>` wrapper exactly; and all executive sections + key data points render. Verified the live output by hand as well (5 SVG charts, 3 device cards, balanced markup, valid DOCTYPE). Test-only — no runtime change.


## [0.10.408] - 2026-06-09
### Changed
- **Admin device-detail interface AND VPN-tunnel graphs now match the public dashboard's 3-mode bandwidth chart** (v0.10.408). The per-interface expand-row chart on the admin device-detail page previously drew a single fixed view: two filled lines of the **raw cumulative** `in_bytes`/`out_bytes` SNMP counters — a monotonically-rising "staircase" that conveys almost nothing about actual throughput. It now uses the same three display modes the public dashboard's bandwidth widget offers, selectable per chart: **Throughput** (RX/TX in Mbps, filled lines), **Transfer** (bytes-per-bucket as paired bars), and **Combined** (Mbps lines on the left axis + byte bars on the right). The series are derived honestly from consecutive-bucket counter deltas (clamped ≥ 0 across resets/wraps) over the nominal bucket window — the exact convention `internal/report` already uses for traffic figures — so "Throughput" finally shows real Mbps instead of a cumulative climb. **VPN tunnels, which previously had no chart at all, are now expandable** (click a row, like interfaces) and render the same 3-mode chart from the existing `/admin/api/devices/:id/vpn/:tunnel/chart` endpoint (whose `GetVPNChartData` already emits per-bucket deltas via `LAG()`, so transfer is used as-is and throughput divides by the bucket window). Implemented as a shared, dependency-free `FwmonBwChart` Chart.js module (`cmd/api/static/js/admin-bw-chart.js`) reused by both the interface and tunnel expand rows; the display-mode + time-range controls share one `bwControlsHtml` strip. **Frontend-only — no backend, API-shape, or database change** (both chart endpoints already existed and returned everything needed; the interface chart's `in_bytes`/`out_bytes` fields are untouched, so the report and connection-detail consumers are unaffected). **Requires a redeploy** (the JS/CSS/HTML are embedded via `//go:embed static`).

## [0.10.404] - 2026-06-08
### Added
- **Triaged the final 4 audit findings — the public-release audit is now 170/170 (AUDIT-039/126/160/161)** (v0.10.404). With every Large/observability/test-infra/code item done, the last 4 open findings were adjudicated against the *current* code (the audit's `file:line` refs are the v0.10.239 baseline and several premises had gone stale):
  - **AUDIT-160 (vendored libs not version-pinned) — fixed.** The committed pre-minified browser libraries (Chart.js, chartjs-plugin-zoom, Cytoscape.js + the fcose layout stack, GridStack, µPlot) had no provenance record. Added `cmd/api/static/js/VENDOR.md` (a table of file → library → version → upstream → license; all MIT, matching the project) and a `vendoredBrowserLibraries` pin block in `package.json`. Versions were read back from each artifact's embedded banner where present (Chart.js 4.4.7, zoom 2.0.1, Cytoscape 3.30.4, GridStack 10.3.1, µPlot 1.6.31); the three webpack-bundled fcose-stack files carry no embedded version and are honestly flagged to pin on the next vendor refresh rather than guessing. Static guard `vendoring_audit160_test.go`.
  - **AUDIT-039 (per-daemon batchers "only the api uses") — wontfix, premise inverted.** Verified the opposite is true: the batched (singular) `SaveSyslogMessage`/`SaveTrapEvent`/`SavePingResult` paths are consumed by `internal/syslog`, `internal/database/events.go` (trap-receiver), and `internal/ping` (poller's PingCollector) — the api handlers use the *plural* bulk saves and touch **zero** batchers. The suggested fix (move batchers into a `NewDatabaseForAPI`, have poller/trap use direct writes) would therefore *remove batching from the exact daemons that use it* — a regression. The only real residue is a couple of idle batcher goroutines per daemon (a sleeping ticker, no DB calls), which is negligible. Closed as wontfix.
  - **AUDIT-126 (admin-device-detail.js is 3740 lines / 213KB) — accept, premise stale.** The file is now **1794 lines / ~99KB** — roughly half the cited size. Splitting a working single-page detail view's IIFE into per-tab files is a cosmetic maintainability change with real regression risk and no functional gain; per the project's simplicity-first / minimal-impact rule it is accepted as-is (revisit if it grows materially).
  - **AUDIT-161 (duplicated sidebar markup across admin HTML) — accept and document** (the resolution the finding itself offers). For a single-tenant internal operator tool with a small, stable page set, introducing Go HTML templating / htmx for the shell adds a render layer and regression risk to a working UI for a purely cosmetic DRY gain. Recorded the decision (and the "revisit if page count grows" trigger) in a new `web/admin/README.md`. Docs/provenance only — no runtime change.

## [0.10.403] - 2026-06-08
### Added
- **OpenTelemetry distributed tracing — closes AUDIT-150 (the last large audit item)** (v0.10.403). The cross-process probe→api call was invisible end-to-end: a relay retry surfaced as three unrelated `log.Printf` lines with no shared correlation ID, and there was no way to see where latency went across the SNMP-poll → batch → HTTP → DB chain. New `internal/tracing` package adopts `go.opentelemetry.io/otel`: it exports spans over **OTLP/HTTP** (to any Tempo/Jaeger/Honeycomb/OTel-collector) and propagates **W3C trace context** across the probe→api boundary so the whole call is one connected trace. **It is OFF by default** — nothing initializes, no exporter goroutine runs, and the instrumentation wrappers are gated no-ops unless `OTEL_TRACES_ENABLED=true`, so a default deployment sees **zero behaviour change and zero overhead**. Wiring: the api server installs a hand-rolled gin span middleware (`tracing.GinMiddleware`) that extracts inbound context and opens a route-template-named server span; the probe relay wraps its HTTP transport (`tracing.WrapTransport`) to open client spans and inject the `traceparent` header; and the AUDIT-076 slog handler now stamps `trace_id`/`span_id` onto any log line emitted under an active span (via the request context `RequestLogger` already passes), giving log↔trace correlation. **Deliberately hand-rolled the gin middleware + http transport on the otel API rather than pulling the `otelgin`/`otelhttp` contrib modules** — those would have force-upgraded gin (1.10→1.12) and dragged in a large transitive tree (quic-go, mongo-driver, grpc-gateway) for a hardening release; the lean path keeps gin pinned and adds only the otel core/SDK + OTLP-HTTP exporter. Config uses the standard `OTEL_EXPORTER_OTLP_*` env vars (documented in `config.env.example`). Tested without a live collector: `internal/tracing` proves **cross-process propagation** (a `WrapTransport` request injects a `traceparent` that `GinMiddleware` extracts → client and server spans share one trace ID) via an in-memory span recorder, plus the disabled-path no-ops; `internal/logging` proves the trace-ID stamping (incl. surviving `slog.With`). Static guard `internal/shell/tracing_audit150_test.go`. **Requires a redeploy**; behaviour is unchanged unless explicitly enabled. *(This was the final Large item — 076 slog + 077 Prometheus `/metrics` + 078 audit log + 129 client-errors + 135 request-ID were the earlier observability pieces.)*

## [0.10.402] - 2026-06-08
### Changed
- **Container entrypoint now fail-fast supervises the three daemons (AUDIT-094)** (v0.10.402). `entrypoint.sh` launched `fwmon-api`, `fwmon-poller`, and `fwmon-trap` as background jobs and ended with a bare `wait $API_PID $POLLER_PID $TRAP_PID`, which blocks until **all three** exit. So if a single daemon crashed, the container stayed up running a **silently-degraded** stack — the dead process was neither restarted nor surfaced, and an operator only noticed when data went stale or a health check failed. The fix replaces the bare wait with a **`wait -n` fail-fast loop**: the moment the first daemon exits, the entrypoint logs which one and its status, tears the whole stack down cleanly (daemons then PostgreSQL), and exits non-zero — so the compose `restart: unless-stopped` policy brings back a fresh, **complete** stack instead of limping along missing a process. The signal path is unchanged in spirit (`trap shutdown INT TERM` → graceful `exit 0` for `docker stop`); the shared teardown was factored into a `teardown()` helper, and its `kill`/`wait`/`pg_ctl` calls are now `|| true`-guarded so the script-level `set -e` can't leak a `143` into a clean stop or skip the explicit crash-path `exit 1`. Chose `wait -n` over an s6/supervisord per-process supervisor deliberately: whole-stack restart is a clean-slate recovery with no risk of a half-restarted daemon running against stale in-process state, it avoids a new runtime dependency in the production image, and — critically — it could be reviewed and unit-tested without a live container (verified locally: a mock harness confirms a crashing child triggers `exit 1` and a `SIGTERM` triggers `exit 0`). **Requires a redeploy** (rebuilds the image entrypoint). Bash `wait -n` needs bash ≥ 4.3, satisfied by the Alpine 3.19 base (bash 5.2). Static guard `internal/shell/entrypoint_supervision_audit094_test.go`.

## [0.10.401] - 2026-06-08
### Added
- **End-to-end handler→Postgres integration test — closes AUDIT-123** (v0.10.401). AUDIT-123 asked for a real integration lane (`//go:build integration` tag, `make test-integration`, CI on a Postgres service); AUDIT-118 (v0.10.379) already delivered all three, but its suite verifies the **database package's** Postgres-specific paths in isolation (the `to_char` TimeBucket round-trip, advisory locks, partition routing/pruning, autovacuum). The genuinely missing piece — the thing that makes this a repo-level *integration* test rather than a db-package unit test — is a **cross-package, full-stack** flow: a real HTTP request through the gin handler → probe Bearer auth → `SaveSystemStatus` → real partitioned Postgres → query-back. Added `internal/api/handlers/integration_pg_test.go` (`TestEndToEndIngestion_Postgres_AUDIT123`) doing exactly that against a live Postgres: it POSTs a system-status batch through `ReceiveSystemStatuses`, then asserts the row persisted, **routed into the correct current-month partition** (`system_status_YYYYMM`), the handler's device→online side-effect hit the DB, and the value round-trips back through the query layer. To avoid duplicating the connect/reset/migrate harness, the AUDIT-118 suite's private `newPGForTest`/`cfgFromDSN` were promoted to a shared, exported, build-tagged `database.NewIntegrationDB(testing.TB)` in the new `internal/database/integration_testkit.go`, and the existing suite now delegates to it (no behaviour change). The CI `integration-postgres` job and the `make test-integration` target were broadened from `./internal/database/...` to also run `./internal/api/handlers/...` so the e2e suite actually executes. No Postgres in the dev sandbox, so this was verified locally by compile-under-`-tags=integration` + clean skip without `TEST_PG_DSN` (the real run is CI). Static guard `internal/shell/integrationtests_audit123_test.go`. Test/CI-only — no runtime change.

## [0.10.400] - 2026-06-08
### Added
- **Parallel test execution + `-short` fast/slow split (AUDIT-140 + AUDIT-142)** (v0.10.400). Two test-infrastructure findings: the suite had **zero** `t.Parallel()` calls (everything ran serially) and `go test -short` did nothing (no fast/slow split). **AUDIT-140:** added `t.Parallel()` to 59 independent, shared-state-free tests across the pure-logic packages — `configdiff` (26 normalizer/validator tests), `report` (spike/formatter/email-render + the AUDIT-120 property tests), `auth` (bcrypt/JWT — parallel helps most here since each case is CPU-bound), `models`, `alerts`, `uptime`, plus the deterministic `database/batcher` and `snmp/trap` tests the audit named. Packages that mutate process-global state (`gin.SetMode`, `log.SetOutput`, env vars) or depend on wall-clock timing were deliberately left serial. Verified stable under `-count=2`. **AUDIT-142:** gated the timing- and concurrency-dependent tests behind `testing.Short()` so `go test -short` skips them for a fast inner loop — the 4 `time.Sleep`-based `batcher` tests (flush-on-tick, max-size flush, concurrent-add-during-stop, flush-error) and the 2 `snmp/trap` rate-limiter tests (burst-refill timing, 50-goroutine concurrency stress); the existing 5-second `cmd/probe` bounded-drain test was already gated. `go test -short ./...` now skips 7 slow/flaky-prone tests while the full `go test ./...` still runs everything. Two `internal/shell` static guards (`parallel_audit140_test.go`, `shortgating_audit142_test.go`) keep both patterns from silently regressing. Test-only — no runtime change.

## [0.10.399] - 2026-06-08
### Added
- **First tests for the `auth`, `alerts`, and `models` critical-path packages — closes AUDIT-117** (v0.10.399). AUDIT-117 flagged that 14 of 22 Go packages had 0% test coverage, including the security boundary. Prior sessions had whittled this down (119 fuzz on the syslog/sflow parsers, 120 property tests on uptime, plus existing middleware/crypto/keychain/batcher/notifier/ssrf suites); this release fills the last critical-path packages that still had zero tests. `internal/auth/auth_test.go` covers the **security boundary** end to end: the login-lockout state machine (lock after `MaxLoginAttempts`, per-source-IP isolation, success clears the counter), the bcrypt password round-trip, JWT sign/validate including the two classic bypasses — **`alg=none` confusion** and **wrong-signing-secret** must both return `ErrInvalidToken` — plus expiry rejection, the `TokenVersion` revocation check (a token minted at an older version is rejected once the DB advances), and the `GenerateSecureToken` length/URL-safety/uniqueness invariant; it runs against an in-memory `fakeDB` at `bcrypt.MinCost` for speed. `internal/alerts/policy_test.go` covers the two pure, branch-heavy policy helpers (`defaultSeverityForType` severity mapping incl. the unknown-type→`warning` default, and `overrideThreshold`). `internal/models/models_test.go` adds a reflection-style guard that every model's GORM `TableName()` is unique and snake_case — catching the copy-paste class of bug where two models silently point at the same table — plus a `SystemStatus.ToJSON` round-trip. `internal/ping` is intentionally left uncovered here: its only logic is raw-ICMP socket I/O and DB-bound stat rollups, which belong to the integration lane, not unit tests. Test-only — no runtime change.

## [0.10.398] - 2026-06-08
### Added
- **Property-based tests for the uptime and spike/counter-delta math (AUDIT-120)** (v0.10.398). The trickiest numeric code — uptime %, the rolling mean/stddev that drives spike detection, and the centisecond→`d/h/m/s` formatter — had only example-based coverage (or none). Added invariant tests with the stdlib `testing/quick` (no new dependency, same spirit as the AUDIT-119 fuzz tests), each asserting a property that must hold for *every* input: `internal/report/spike_property_test.go` checks that `meanStdDev` returns a finite non-negative stddev with the mean inside `[min,max]`, that a constant window has stddev 0, and that every spike `detectSpikesInSeries` reports is internally consistent (value > window mean, stddev > 0, `critical` clears the 2× bar, severity is only ever `warning`/`critical`, and degenerate inputs return nil); `internal/uptime/uptime_property_test.go` proves `FormatUptime` round-trips back to `uptime/100` for any `uint64` (decoded by an independent parser, so it really exercises the output) and that `GetStats().UptimePercent` is always finite in `[0,100]` with reboots / not-yet-reported trackers pinned to 0 (the uint64 underflow guard). Generators are bounded to the real throughput domain (finite, non-negative bps) so the properties test the operating range, not float64-max overflow artifacts. Static guard `internal/shell/propertytests_audit120_test.go` keeps the property tests from being deleted or downgraded. Test-only — no runtime change.

## [0.10.397] - 2026-06-08
### Changed
- **Moved the HTTP transport envelope out of the GORM model package (AUDIT-073)** (v0.10.397). `APIResponse` and its `SuccessResponse`/`ErrorResponse`/`MessageResponse` constructors lived in `internal/models` next to the database row structs, coupling two unrelated concerns — persistence rows vs. the JSON wire shape. They now live in a new leaf package `internal/api/response`, de-stuttered to `response.APIResponse` + `response.Success`/`response.Error`/`response.Message`. All 435 call sites across 16 files (15 handler files + `internal/httputil`) were updated; `goimports` fixed the import lines. **The JSON wire shape is byte-for-byte unchanged** (`{success, data?, error?, message?}`), so there is no client-visible effect — this is a pure internal refactor. The AUDIT-071 sweep guard was re-pointed at the new `StatusInternalServerError, response.Error` 500-boilerplate form, and a new `internal/shell/transporttypes_audit073_test.go` pins the boundary (models declares neither the type nor the constructors; `response` declares both). The previously-flagged dead `DeviceTunnel.LastUpAt` half of this finding was already resolved when the field got wired up in `telemetry.go`. No redeploy behaviour change.
- **License alignment with Firewall-Collector sibling repo.** The collector was re-licensed from Apache 2.0 to MIT in its v1.2.114 release to match this server's MIT terms. The two repos form a paired client/server and now ship under a single license. No code or LICENSE change on the server side — badge and License section text in `README.md` were already MIT; this entry records the alignment for operators tracking the project.

### Fixed
- **CI gofmt gate was red — two AUDIT-076 test files shipped unformatted** (v0.10.397). The v0.10.396 commit added `internal/logging/logging_test.go` and `internal/shell/structuredlogging_audit076_test.go` with map-literal / struct-field columns that `gofmt` re-aligns, so the CI `gofmt -l .` gate (AUDIT-075/152) failed on that commit and the next one. Ran `gofmt -w` on both; the whole tree is gofmt-clean again. No code/behaviour change — formatting only.

## [0.10.396] - 2026-06-08
### Added
- **Structured logging via `log/slog` (AUDIT-076)** (v0.10.396). The server logged through a flat `log.Printf` stream: no levels, no machine-parseable fields, no credential redaction — and "a flat stream is not searchable" was the exact pain the v0.10.236 / v0.10.238 incident chain exposed, since logs are the team's primary diagnostic surface. New `internal/logging` package adopts the stdlib `log/slog` as the single logging backend, with one deliberate design choice that makes the migration tractable: `logging.Init()` (called first thing in `cmd/api/main.go`'s `main()`) calls `slog.SetDefault`, which — since Go 1.21 — **also routes the legacy `log` package through the slog handler**. So all ~460 existing `log.Printf` call sites gain levelled, structured, redacted output with zero per-site edits, instead of a 460-site mechanical churn. Two env vars control the sink: `LOG_FORMAT` = `text` (default, logfmt key=value) | `json` (one JSON object per line, for Loki/ELK/Splunk), and `LOG_LEVEL` = `debug` | `info` (default) | `warn` | `error`. Legacy `log.Printf` lines bridge in at info, so the default keeps the pre-AUDIT-076 verbosity. A `ReplaceAttr` redaction hook masks any slog attribute whose key names a secret (`password`/`passwd`/`secret`/`token`/`apikey`/`api_key`/`community`/`private_key` → `REDACTED`), mirroring the API-response masking. The two highest-volume logging chokepoints were converted to **native** slog records with queryable attributes (not bridged strings): `httputil.InternalError` (every handler 500 → `slog.Error(msg, status=500, method, route, req, err)`) and `middleware.RequestLogger` (every failed request → `slog.LogAttrs(... "http request", req, method, path, status, latency)`, level split 4xx→warn / 5xx→error). Tests: `internal/logging/logging_test.go` (redaction, the stdlib→slog bridge, level parsing) + `internal/shell/structuredlogging_audit076_test.go` (static guards that the foundation and both chokepoints stay on slog). `LOG_FORMAT`/`LOG_LEVEL` documented in `config.env.example`. **Requires a redeploy** to take effect; behaviour is otherwise unchanged at the default `text`/`info`.
- **Operations docs: "Key continuity" upgrade warning** (v0.10.392, docs-only). Codifies the lesson from the 2026-06-07 production incident: an upgrade deployed from a *fresh checkout in a new directory* (`/home/xphox/firewall-mon` → `/opt/Firewall-Monitoring`) made the entrypoint regenerate `config.env` with a new random `JWT_SECRET_KEY`. Because `ENCRYPTION_KEY` had been left to silently derive from the JWT secret (the AUDIT-008/009 fallback), the derived AES-256 key changed and **every stored `{enc}` secret (SNMP communities, SMTP/IRC passwords) became undecryptable** — devices stopped polling and email alerts failed `535`, with no recovery short of re-entering every secret by hand. Added a prominent ⚠ callout to `docs/OPERATIONS.md` → **Upgrade** explaining what each key does, why `ENCRYPTION_KEY` must be set **explicitly** (decoupling encryption from JWT auto-regeneration) and carried forward verbatim on every upgrade / host-move / repo relocation, plus a before-and-after verification command; and a cross-linked pre-flight step (#7) in `docs/UPGRADE-2026-06.md`. Docs-only; no code change.
- **Doc-unification pass across `xphox2/Firewall-Monitoring` and `xphox2/Firewall-Collector`** (v0.10.389, docs-only). The two repos were drifting: the collector's README was 138 lines and last meaningfully rewritten around 1.2.50 (missing TFTP backup, SSH polling, mTLS, observability, schema versioning, the disk-spillover queue, the `ssh-test` subcommand, the `diag-backup` binary, and most hardening); the server's README was 309 lines with a strong but ad-hoc structure. Cross-references to `MIGRATING.md` / `SUPPORT-MATRIX.md` / `ARCHITECTURE.md` were dangling in the collector. This release brings both repos to the **same section order, the same role-tag convention, and the same "single canonical home" rule for cross-cutting docs**:
  - New `docs/STRUCTURE.md` in both repos — the index of where every topic lives, with absolute github.com cross-links for anyone reading either repo in isolation. The server's `STRUCTURE.md` is the canonical version; the collector's mirrors it.
  - New `docs/FEATURES.md` in both repos — website-ready feature inventory with `Stable` / `Beta` / `Planned` status, `[Server]` / `[Probe]` / `[Both]` role tags, and "since" version for every row. The server's `FEATURES.md` covers 60+ stable features, the 9 in-tree vendor profiles, the planned items (server-side mTLS, SIGHUP hot-reload, GDPR export), and the 5 entries from `KNOWN-ISSUES.md` with their AUDIT-NNN tracking IDs. The collector's `FEATURES.md` is the companion piece.
  - **New `README.md` for both repos** — same 14-section structure (Sibling project → Features → Architecture → Quick Start → Configuration → Upgrading → Compatibility → Operations → Security → API/Wire format → Contributing → License → Support), the same role-tag convention on every feature, the same wording for the canonical-home pointers. The collector README grew from 138 → ~340 lines; the server README was restructured in place to match the new order.
  - **Cross-cutting-docs policy (per the user's explicit sign-off, 2026-06-07)**: `MIGRATING.md`, `SUPPORT-MATRIX.md`, `OPERATIONS.md`, `DATA-RETENTION.md`, `FORTIGATE-SNMP-SETUP.md`, `CERT-ROTATION.md`, and the combined `architecture.md` live **only in `xphox2/Firewall-Monitoring`**. The collector points to them with absolute github.com URLs. The rationale: these topics only matter to operators of the central server, so duplicating them in the collector risks drift.
  - **Cleanup of stray files** that should never have been committed: `docs/CSS.md` and `docs/SCAN.md` (raw `govulncheck` dumps left in `docs/` by a CI run). The collector had its own strays (`session-ses_1613.md` — a 4,939-line leaked Claude session transcript — and `tasks/SERVER-NOTES.md`, which described server-side code and was in the wrong repo); those are cleaned up in collector 1.2.109.
  - **Known follow-up (not in this PR)**: the server has three legacy-lowercase files in `docs/` (`architecture.md`, `custom-vendor.md`, `partition-migration.md`) pinned by shell-guard tests (`TestArchitectureDiagram_AUDIT108`, `TestCustomVendorDoc_AUDIT170`, `TestEnsurePartitions_SurfacesWarning_AUDIT146`). Renaming them to UPPERCASE is a separate change — requires updating those three tests in the same commit. All **new** docs in this repo ship in UPPERCASE per the collector's 1.2.107 standard.

### Notes
- **Docs-only.** No code change. `go build ./...`, `go test -race ./...`, and `make qa` should pass unchanged (the doc change doesn't touch any non-doc file).
- New `docs/STRUCTURE.md` and `docs/FEATURES.md` are the two new top-level operator docs. The existing `MIGRATING.md`, `KNOWN-ISSUES.md`, `docs/OPERATIONS.md`, `docs/architecture.md`, `docs/custom-vendor.md`, `docs/SUPPORT-MATRIX.md`, `docs/DATA-RETENTION.md`, `docs/CERT-ROTATION.md`, `docs/FORTIGATE-SNMP-SETUP.md`, `docs/partition-migration.md`, `docs/nginx.conf`, `docs/UPGRADE-2026-06.md`, `docs/SECURITY-VERIFICATION.md`, and `docs/AUDIT.md` are unchanged. `THIRD-PARTY-NOTICES.md`, `IRC-FORMAT.txt`, `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md` are unchanged. `config.env.example` and `.env.example` are unchanged.


## [0.10.395] - 2026-06-08
### Fixed
- **Probes / Sites / Pending / IRC pages loaded blank until a manual refresh** (v0.10.395). The admin sidebar links are real URLs, and a single global click interceptor in `admin-main.js` turns same-origin `/admin/<page>` clicks into in-place SPA tab switches — but only for pages whose segment is in `SPA_PAGES`. That set wrongly included `probes`, `sites`, `probe-pending`, `irc` (and dead `network`), which are **standalone HTML documents** (`probes.html`, etc.) with no `page-<name>` div in `admin.html` and no `loadPageData()` case. So clicking them `preventDefault()`'d the real navigation and called `loadPageData()` with nothing to do → blank view; a manual refresh then performed the true full-page navigation (running the page's own `admin-*.js`), which is why refresh "fixed" it. Fix: `SPA_PAGES` (and the matching `activateTabFromUrl` page map) now list only the tabs that actually live inside `admin.html`, so links to the standalone pages navigate natively on the first click. Regression test `internal/shell/spa_pages_nav_test.go` asserts every `SPA_PAGES` key has a corresponding `page-<name>` div and bans the standalone pages. **Requires a redeploy** (the JS is embedded via `//go:embed static`).

## [0.10.394] - 2026-06-08
### Fixed
- **Device→probe (and device→site) reassignment silently reverted — "saved" but unchanged on refresh** (v0.10.394). This is the actual root cause behind the operator report that changing a device's probe in the admin UI reported success but reverted to the old probe. `UpdateDevice` loaded the device via `GetDevice`, which does `Preload("Probe")`/`Preload("Site")`, then wrote with `db.Gorm().Model(device).Updates(filteredUpdates)`. Because `device` carried **loaded belongs-to associations**, gorm re-derived the `probe_id`/`site_id` foreign keys from those loaded associations (the *old* probe/site) and overrode the new values in the update map — so the UPDATE reported `rows=1` and HTTP 200, but persisted the old FK. Plain scalar columns (name, snmp_port, …) were unaffected, which is why only the probe/site reassignment appeared "stuck". The validation added in v0.10.393 didn't catch it because the target probe *did* exist; the value was being clobbered after validation, at the write. Fix: write via `Model(&models.Device{}).Where("id = ?", id).Updates(...)` so gorm honors the map verbatim (the pattern already used by `UpdateDeviceStatus` and the ingestion handlers). The identical bug in `UpdateProbe` (loads with `Preload("Site")`, so changing a probe's site reverted) is fixed the same way. Regression test `internal/api/handlers/update_device_probe_test.go` exercises both `probe_id` and `site_id` reassignment plus the unassign (`null`) path. **This requires a redeploy** — the prior psql workaround (`UPDATE devices SET probe_id = … WHERE probe_id = …`) bypasses the handler and still works for unblocking before the redeploy.

## [0.10.393] - 2026-06-07
### Fixed
- **Probes could not be deleted, and device→probe reassignment silently reverted** (v0.10.393). Two related foreign-key problems around the `probes` table surfaced when an operator installed a new probe, tried to move devices onto it, and then remove the old one:
  1. **`DeleteProbe` was a bare `DELETE FROM probes`** with no child cleanup. Because FK constraints are enabled (the gorm config never set `DisableForeignKeyConstraintWhenMigrating`), `probe_approvals.probe_id` (created on every approval, `NOT NULL`), `probe_heartbeats.probe_id`, and `devices.probe_id` all reference `probes` — so Postgres rejected the delete with a foreign-key violation and the UI just showed "Failed to delete probe". A probe that had ever been approved or sent a heartbeat could therefore **never** be deleted. `DeleteProbe` now mirrors `DeleteDevice`: it refuses with a typed `ErrProbeHasDevices` (surfaced as HTTP 409 with a "reassign or remove those devices first" message) when devices are still assigned, and otherwise removes the FK-referencing child rows (`probe_approvals`, `probe_heartbeats`) and the registration-key `system_settings` row inside a transaction before deleting the probe.
  2. **Reassigning a device to a non-existent probe id failed opaquely.** `UpdateDevice` passed `probe_id` straight into the `Updates` map with no existence check, so an UPDATE targeting a missing probe hit the `devices.probe_id` FK, rolled the *entire* update back with a generic 500, and left the device on its previous probe — presenting to the operator as "the reassignment saved but reverted on refresh". `UpdateDevice` now validates the target probe exists (and that `probe_id` is a non-negative integer) and returns a clear `400 "Target probe not found"`; a `null`/`0` value remains the explicit "unassign" case. Regression tests added in `internal/database/delete_probe_test.go`.

## [0.10.391] - 2026-06-07
### Fixed
- **Production incident: large-DB startup cascade — `interface_addresses` ingestion broke and the API/trap-receiver crash-looped** (v0.10.391). On a large production database (~32 GB, after a data relocation) the server hit a cascading failure: device data stopped persisting and the probe showed online but stale. Root cause was the AUDIT-037 per-connection `statement_timeout` (default 30s) colliding with two slow startup operations:
  1. **`interface_addresses` self-heal (AUDIT-030/AUDIT-037).** `ensureInterfaceAddrUniqueIndex` deduplicates and builds `idx_ifaddr_dev_ip` (the conflict target for `SaveInterfaceAddresses`' `ON CONFLICT (device_id, ip_address)` upsert). On a big, duplicate-laden table the dedupe `DELETE` exceeded 30s and was canceled (`57014`), so the index was never created and **every** `POST /api/probes/:id/interface-addresses` failed with `42P10` ("no unique or exclusion constraint matching the ON CONFLICT specification") — the 500-flood that filled `postgresql.log`. Fix: run the dedupe + `CREATE UNIQUE INDEX` inside a transaction with `SET LOCAL statement_timeout = 0`, so this one-time maintenance DDL can't be time-boxed.
  2. **Migration advisory-lock acquisition (AUDIT-044/AUDIT-037).** `acquireMigrationLock` calls the *blocking* `pg_advisory_lock()`; while one process (the poller) held the lock running the slow self-heal, the **API and trap-receiver blocked on acquiring it, hit the same 30s cap, and failed to boot** (`migrate: acquire lock: canceling statement due to statement timeout`) — crash-looping. Fix: `SET statement_timeout = 0` on the dedicated lock connection before the blocking acquire, so waiting for a busy migrator can't be canceled (only that connection is affected; migrations keep their timeout).
  Net effect: the index now builds once (even on a huge table), the upsert works, and the three processes start cleanly. **Operators already hit by this** can restore service immediately without redeploying by building the index by hand: `SET statement_timeout=0;` then dedupe `DELETE FROM interface_addresses a USING interface_addresses b WHERE a.device_id=b.device_id AND a.ip_address=b.ip_address AND a.id<b.id;` then `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_ifaddr_dev_ip ON interface_addresses (device_id, ip_address);`. `internal/shell` static guards added for both `SET … statement_timeout = 0` sites.


## [0.10.390] - 2026-06-07
### Fixed
- **Docker build broke on stale builder Go version** (v0.10.390): the `docker build` failed at `RUN go mod download` with *"go.mod requires go >= 1.25.11 (running go 1.23.12; GOTOOLCHAIN=local)"*. The `go` directive was bumped to **1.25.11** in v0.10.385 (AUDIT-018, to clear the govulncheck stdlib CVEs), but the `Dockerfile` builder stage was still pinned to `golang:1.23-alpine`. Because the official Go images run with `GOTOOLCHAIN=local`, the 1.23 toolchain refused to auto-download a newer one and aborted. Bumped the builder base image to `golang:1.25-alpine` so it satisfies the `go.mod` floor. Dockerfile-only; no Go code change. (Latent since v0.10.385 — only surfaces on a container build, which CI's go-native lanes don't exercise.)
- **Partition cleanup never dropped old partitions (bound-parse bug)** (AUDIT-028, v0.10.387): with the migration now succeeding, the `integration-postgres` job reached `dropPartitionsOlderThan` for the first time and exposed that it **never dropped anything**. `parsePartitionUpperBound` parsed the partition's upper bound with the layout `"2006-01-02"`, but Postgres renders the bound of a **timestamp/timestamptz**-typed partition key *with a time component* (e.g. `TO ('2026-02-01 00:00:00')`, or `…+00` for timestamptz). Every real bound therefore failed to parse and was treated as "unparseable — leave it", so partition-based retention silently did nothing (high-volume tables would have grown without bound on a partitioned install). The parser now accepts the date-only, timestamp, and timestamptz renderings and falls back to the leading `YYYY-MM-DD` (sufficient for monthly first-of-month bounds). Covered by a new pure-function unit test (`cleanup_partition_test.go`, runs without Postgres) and the integration `CleanupDropsOldPartition` subtest. (Latent since v0.10.380; the cleanup path was unreachable while the migration crashed.)

## [0.10.388] - 2026-06-07
### Changed
- **CI: bump deprecated GitHub Actions** (v0.10.388): `actions/checkout@v4 → @v5` and `actions/setup-go@v5 → @v6` across all three CI jobs, clearing the "Node.js 20 actions are deprecated" warning before the **2026-06-16** forced cutover to Node 24. No behavior change. Added `docs/UPGRADE-2026-06.md` — a step-by-step runbook for upgrading the live deployment (Server v0.10.324 / Collector v1.2.73 → v0.10.386+ / v1.2.108): DB backup, deploy order, the expected populated-table partition-skip warnings, HTTPS/nginx safety checks, smoke tests, and rollback.


## [0.10.386] - 2026-06-07
### Fixed
- **Two CI failures un-masked once the partition migration stopped crashing** (v0.10.386): with the v0.10.384 fix, the `partition_high_volume` migration now succeeds on a fresh Postgres — which let the `integration-postgres` job run *past* migration and exposed two latent failures the early crash had been hiding, plus the flaky `-race` job tripped on a real concurrency bug. Both fixed:
  - **`secrets.LoadOrGenerate` concurrent-start race** (AUDIT-008): `TestLoadOrGenerate_ConcurrentRaceSafe` intermittently failed with *"secret file empty after concurrent write"*. The publish was two steps — `O_CREATE|O_EXCL` created an **empty** file, then a separate `Write` filled it — so a racing process (cmd/api + cmd/poller + cmd/trap-receiver all starting on a fresh `/data` volume) could read the file created-but-empty, or `os.Remove` it out from under the writer, leaving processes with **divergent ENC keys**. Replaced with an **atomic publish**: write the token to a private `os.CreateTemp` file, then `os.Link` it into place — `Link` is atomic and fails with `ErrExist` if the destination exists, so the final file appears only when fully written and the first linker wins (losers re-read the winner's complete value). Verified locally with 1,000 stress iterations (16k concurrent convergences); the CI `-race` job is the live gate. `internal/shell` static guard added.
  - **`integration-postgres` subtest contamination** (AUDIT-118): `CleanupDropsOldPartition` and `TimeBucketRoundTrip` failed (`42P17 "is not partitioned"` / `23514 "no partition found for row"`) because the `PopulatedTableSkipped` subtest — which DROPs and recreates the shared `public` schema via a second handle to the same physical test DB — ran *before* them and left `interface_stats` plain and `system_status` a childless partitioned parent. Reordered `PopulatedTableSkipped` to run **last** so it can't corrupt the partitioned state its sibling subtests depend on. Test-only; no production-code change.

## [0.10.385] - 2026-06-07
### Fixed
- **`govulncheck` CI job red: stale `go` directive + `golang.org/x/net`** (v0.10.385): the `govulncheck` CI job failed (exit 3) on every push with *"Your code is affected by 34 vulnerabilities"* — 33 of them Go **standard-library** CVEs flagged purely because `go.mod` pinned `go 1.23.0` (the fixes ship in the go1.25.x stdlib), and the 34th a real dependency, `golang.org/x/net v0.43.0` (GO-2026-4918, fixed v0.53.0). Bumped the `go` directive to **1.25.11** (so CI's `setup-go` builds against a patched stdlib via `go-version-file: go.mod`) and `golang.org/x/net` to **v0.55.0** (which pulls `x/crypto v0.51.0`, `x/text v0.37.0`, `x/sync v0.20.0`, `x/sys v0.45.0`). Verified locally: `govulncheck ./...` now reports **0 affected vulnerabilities** (down from 34) and the full suite passes under go1.25.11. No code change; toolchain/dependency floors only. The `internal/shell` `AUDIT-018` dep-floor guard was raised to match and a `go`-directive-minimum assertion added so a future downgrade re-reds the same way CI would.

## [0.10.384] - 2026-06-07
### Fixed
- **Partition migration `DROP TABLE` failed on a fresh Postgres (SQLSTATE 2BP01)** (v0.10.384): the v2 `partition_high_volume` migration (AUDIT-028) crashed on the *first* table of a **fresh** Postgres install with `cannot drop table interface_stats_prepart because other objects depend on it`. `convertEmptyTableToPartitioned` renames the plain table to `<t>_prepart`, builds the partitioned parent with `CREATE TABLE ... (LIKE <t>_prepart INCLUDING DEFAULTS)`, then `DROP TABLE <t>_prepart`. `INCLUDING DEFAULTS` copies the id serial's `nextval()` default, so the new parent depends on a sequence that is still **OWNED BY `<t>_prepart.id`** (the ownership dependency followed the table on `RENAME`); Postgres then refuses to drop the old table because that would cascade-drop a sequence the live parent needs. Fix: before the drop, re-point the sequence with `ALTER SEQUENCE <seq> OWNED BY <t>.id` (the sequence name resolved at runtime via `pg_get_serial_sequence('<t>_prepart','id')`, COALESCE'd so a non-serial id is a no-op), so the old table drops cleanly and the sequence — with its current value — survives bound to the new parent. **Not `DROP TABLE ... CASCADE`** (that would drop the still-needed sequence). This only ever runs on **empty** tables, so a populated production database (which the migration skips with a warning) was never affected — the bug bit fresh installs and the `integration-postgres` CI job only. Caught by the AUDIT-118 CI Postgres suite; `internal/shell` static guard added. Postgres-only (SQLite no-op).


## [0.10.383] - 2026-06-07
### Added
- **Operator docs: data retention, version support matrix, cert rotation** (v0.10.383): three new operator-facing docs, **written against the actual implementation** rather than aspirational features. `docs/DATA-RETENTION.md` — the real per-table retention model (the `RETENTION_*` env vars from `internal/config/config.go` as applied by `CleanupOldData`, including the gotcha that `0` means *fall back to `RETENTION_DEFAULT_DAYS`=90* for most tables but means *keep forever* for `RETENTION_SYSLOG_CRITICAL_DAYS`), which tables are never auto-pruned (`config_revisions`, `audit_logs`), where PII lives, the `DB_*` residency knobs, and an honest data-subject-rights section (the server has **no** one-click export/erasure endpoint; `DELETE /api/probes/:id` removes only the probe row and does **not** cascade). `docs/SUPPORT-MATRIX.md` — the collector↔server compatibility table; the server's only version-gated behavior is `schema_version` validation at v0.10.382, everything else is additive/ignored-when-unknown. `docs/CERT-ROTATION.md` — server TLS rotation via `SERVER_TLS_CERT`/`SERVER_TLS_KEY` (Let's Encrypt deploy-hook restart, since there is **no** SIGHUP hot-reload) and probe-credential rotation via the regenerate-key endpoint; explicitly flags what is **not** implemented (server-side mTLS client-cert verification, `setup.sh`, `/api/admin/rotate-mtls`, `PROBE_FORCE_REREGISTER`) so operators don't plan around vaporware. **Completes and resolves the doc PRs #12/#13/#14** — those branched from v0.10.362 and conflicted with master, and their drafts referenced fictional env vars/endpoints (`PROBE_*_RETENTION_DAYS`, `PROBE_DATABASE_URL`, `/api/probes/:id/export`, `SSL_CERT_FILE`, a SIGHUP reload, a per-tenant `tenant_id`); this rewrite ships the same three docs grounded in verified config/routes, with multi-tenant content dropped (the deployment is single-tenant). Docs-only; no code change.

## [0.10.382] - 2026-06-07
### Added
- **Probe↔server `schema_version` handshake on `/api/probes/register`** (v0.10.382): the collector and the server are deployed and upgraded **independently**, but the relay handshake had no version field — a server-side change that added a required field, shifted a field's semantics, or removed an endpoint could break a deployed collector with no graceful signal. Added a `schema_version` integer to the register request and response (`internal/relay/relay.go`): the probe advertises the version it speaks (`SchemaVersion: SchemaVersionMax`), and the server validates it against `[relay.SchemaVersionMin, relay.SchemaVersionMax]` (currently `1-1`, exported consts that are the single source of truth). The handler parses the field as `*int` so it can distinguish **absent** (a pre-handshake collector → defaults to v1, fully backward-compatible — the `omitempty` field is ignored by older servers too) from an **explicit out-of-range** value, which is rejected with **HTTP 426 (Upgrade Required)** *before* any auth or DB lookup, carrying the supported range in the `X-Probe-Schema-Version-Supported` response header and naming the rejected version + pointing at `MIGRATING.md` in the body. The selected version is echoed back on success so the probe can self-report what the server chose. Shipping a future v2 only needs `SchemaVersionMax` bumped + a `docs/SUPPORT-MATRIX.md` row. New top-level **`MIGRATING.md`** documents the wire-format version, the supported range, the server-support floor (v0.10.382), and the server-first rollout order (with the 426 you see if you upgrade a probe ahead of the server — no data loss, the probe's on-disk queue holds). Three handler tests pin the contract (absent→v1+200, too-old→426, too-new→426+range header) plus an `internal/shell` static guard. **Re-implements the intent of the closed PR #8 on current master** — that PR branched from v0.10.362, conflicts with master, and mislabeled itself "AUDIT-065" (an unrelated, already-resolved frontend finding), so this ships it cleanly with a version that actually exists and no colliding audit ID.
- **API single-instance guard** (AUDIT-040, v0.10.381): `cmd/api` keeps four state stores **in process memory** — the IRC bots (one TCP connection + nick per server), the login-lockout counters, the rate-limit buckets, and the uptime baseline — so a second `cmd/api` against the same DB double-runs all four (two bots fight over the same IRC nick, lockout/rate-limit thresholds effectively ~2×, divergent uptime). Added `AcquireAPISingletonLock()` — a **session-scoped Postgres advisory lock** (`apiSingletonLockKey` = "FWMNAPIS") held on a **pinned `*sql.Conn`** for the process lifetime (same backend-pinning pattern as the AUDIT-044 migration lock, so the unlock isn't routed to a different pooled connection). On startup the API acquires it (retrying for `API_SINGLETON_LOCK_WAIT`, default `10s`, so a graceful predecessor mid-shutdown doesn't cause a false refuse); if another instance holds it, the new process **refuses to start** (`log.Fatalf`) by default. `ALLOW_MULTI_API=true` opts into **follower mode**: serve HTTP but **don't start the IRC bots** (kills the nick-collision — the one symptom that actively breaks), with a loud warning that lockout/rate-limit/uptime are per-instance and diverge. The lock is **released on graceful shutdown** (SIGTERM → `defer` runs → unlock), so a normal restart re-acquires instantly; a SIGKILL/OOM leaves it until Postgres reaps the dead session (documented; the retry window covers graceful handoffs). The IRC manager is still wired into the handler on a follower (admin IRC config pages work via DB CRUD) — only the bot *connections* are gated on being primary. **Long-term deferred (deliberately):** moving lockout/rate-limit/uptime to shared storage — a Postgres round-trip per request at dashboard-polling rates is the wrong tool for rate-limiting. Verified by the AUDIT-118 CI Postgres integration suite (acquire → a second pinned-session acquire contends `false` → release → re-acquire), a SQLite no-op unit test, and an `internal/shell` static guard (lock acquired, released on shutdown, refuse-vs-follower branch, IRC gated on primary). Postgres-only (inert on the SQLite test backend). New `ALLOW_MULTI_API` / `API_SINGLETON_LOCK_WAIT` config + `docs/OPERATIONS.md` "Running a single API instance" section. **This is the fifth and final large refactor** (with 072 split, 032/079 ctx, 044 migrations, 028/146 partitioning).
- **Postgres integration test suite + CI job** (AUDIT-118, v0.10.379): the whole test suite ran on in-memory SQLite while production is **Postgres-only**, so every Postgres-specific path was verified only by hand on the operator's box — the dialect's `to_char()` `TimeBucket` strings (the v0.10.238 minute-bucket regression that broke spike timestamps), the AUDIT-044 pinned-conn advisory-lock migration runner, `EnsurePartitions`/`ConfigureAutovacuum`, and `pg_try_advisory_lock`. Added a **build-tagged** (`//go:build integration`) suite `internal/database/integration_pg_test.go` that connects to a Postgres given by **`TEST_PG_DSN`** (URL form; parsed with stdlib `net/url` into `config.Config` and opened via the real `database.Connect`) and `t.Skip`s when unset — so the default `go test ./...` never compiles or runs it. It resets to a clean `public` schema (with a safety rail that **refuses any DSN whose dbname doesn't contain `test`**, so it can't nuke prod), runs `RunMigrations`, and asserts: the `schema_migrations` baseline is recorded once (proves AutoMigrate + the advisory lock work on real PG); the **minute/hour/day `TimeBucket` strings round-trip** — they equal the expected `to_char` output, `time.Parse` with the app's layouts, and aren't the `parseBucketToMillis` unparseable sentinel (three angles on the v0.10.238 bug); `EnsurePartitions`/`ConfigureAutovacuum` return nil; the advisory lock acquires; and a Device CRUD round-trip works. A new CI job `integration-postgres` runs it against a `postgres:16` service container on every push; `make test-integration` runs it locally (with a `docker run postgres:16` hint). **No new dependencies** (chose `TEST_PG_DSN` over `testcontainers`). **Note:** there's no Docker/Postgres in the dev sandbox, so this suite's first real execution is the CI job — which is the point: it now catches Postgres dialect drift on every push, and **unblocks verifying the remaining large refactors** (AUDIT-028 partitioning, AUDIT-040 shared state) with added integration subtests rather than shipping them blind. `TestPostgresIntegrationWired_AUDIT118` (in `internal/shell`) pins the suite + CI job + Makefile target stay wired.
- **Client-side error reporting** (AUDIT-129, v0.10.375): a browser JS error or unhandled promise rejection in the admin UI previously only flashed the 5-second toast (if that) and then vanished — the operator had **zero visibility** into client failures happening in production. Added a global reporter in `admin-common.js` (`window` `error` + `unhandledrejection` listeners) that beacons the error to the server, and a new `POST /api/client-error` endpoint that **logs it server-side** (with the request's `X-Request-ID` and client IP for correlation). The reporter is **best-effort and self-protecting**: capped at 5 reports per page load (a render loop can't flood the log), prefers `navigator.sendBeacon` (survives page unload) and falls back to `fetch(..., {keepalive:true})`, and is wrapped so it can never itself throw. The endpoint takes **no DB write** (cheap, no unbounded growth) and **no auth** (so the public dashboard can report too); it lives under the rate-limited `/api` group, and **every field is truncated server-side** (message 500, source/url 300, stack 2000, UA 200) regardless of what the client sends — a malformed body is a 400, an empty message is dropped quietly, anything usable is logged and acked 204. Tests: `TestReportClientError_AUDIT129` (logged+204, empty dropped, bad-JSON 400, oversized truncated) and `TestClientErrorReporting_AUDIT129` (both the route and the JS reporter are wired). **Not done:** the public-dashboard JS (`public-dashboard.js`) doesn't yet install the reporter (the endpoint is ready for it — a one-line follow-up); no client-error aggregation UI (the data is in the server log alongside everything else).
- **Admin-action audit log** (AUDIT-078, v0.10.374): the server logged authentication attempts (`login_attempts`) but kept **no record of privileged actions** — who reset uptime, changed an alert threshold, deleted a device, approved a probe, or snoozed an alert was unrecoverable after the fact. Added a new `models.AuditLog` table and an `internal/audit` middleware registered on the `/admin` group **after** auth + CSRF, so it records exactly one row per **authenticated, CSRF-valid admin mutation** (`POST`/`PUT`/`DELETE`/`PATCH`). Each row captures the **actor** (username + id from the JWT), the **action** (the matched route *template*, e.g. `/admin/api/devices/:id` — kept low-cardinality and filterable), the **target** (concrete path params, e.g. `id=5`), the **final HTTP status**, the client IP, and the user-agent. It records *after* the handler runs, so **failed (5xx) and forbidden (4xx) attempts are captured too** — exactly what an incident investigation wants. The trail is **append-only**: there is no update/delete path in the app, so it can't be silently rewritten through the API. A failed audit write is logged but never blocks the request. New read endpoint `GET /admin/api/audit` (auth-gated) returns the trail newest-first with `?actor=`, `?action=`, `?hours=`, and `?limit/offset` filters. Tests: `TestAuditMiddleware_AUDIT078` proves mutations are recorded with the right actor/template/target/status, GETs are skipped, and a 500 is still logged; `TestAuditFilters_AUDIT078` covers the read filters; `TestAuditWiring_AUDIT078` pins the main.go wiring **and the after-auth registration order**. **Not done:** no admin **UI page** yet (the data is queryable via the API; a `/admin/audit` SPA view is a follow-up), no before/after value diffing (records the action + target, not field-level deltas — that needs per-handler cooperation), and the trail is intentionally **not auto-pruned** (admin mutations are very low-volume; retention can be added later if needed).
- **Prometheus `/metrics` endpoint** (AUDIT-077, v0.10.373): the API server had no metrics surface — request latency, error rate, and DB connection-pool exhaustion were invisible outside the log stream. Added `github.com/prometheus/client_golang` and a new `internal/metrics` package exposing, on the default registry: a **request-latency histogram** `fwmon_http_request_duration_seconds{method,route,status}` recorded by a gin middleware, the **database/sql connection-pool** gauges (open/in-use/idle/wait via `collectors.NewDBStatsCollector`), and the standard **Go runtime + process** collectors (goroutines, GC, heap, FDs, CPU) that ride along for free. Served at `GET /metrics` via `promhttp`. **Cardinality guard:** the histogram is labelled by the *matched route template* (`c.FullPath()`, e.g. `/admin/api/devices/:id`) — never the raw path — and unmatched 404s collapse to a single `route="unmatched"` series, so a path-scanning bot can't explode the series count. Per Prometheus convention (and the audit) the endpoint is **unauthenticated and meant to be network-ACL'd** — it carries only aggregate timings/counters and route templates, no secrets. `TestMetricsMiddlewareAndHandler_AUDIT077` drives a request + a 404 through the middleware and scrapes the real exposition (asserts the histogram, the `/ping` route label, the `unmatched` collapse, no raw-path leak, and that `go_goroutines` rides along); `TestMetricsWiring_AUDIT077` pins the main.go wiring. **Not done:** the poller-process counters the audit also named (`poll_cycles_total`, `alerts_fired_total`, `batcher_queue_depth`) live in a separate binary that doesn't serve HTTP — they need the poller to expose its own `/metrics` and are deferred; this ships the API-server surface only. (Verified by unit test against real exposition output; a full-server `curl /metrics` needs a PostgreSQL backend, which the sandbox lacks — `NewDatabase` is Postgres-only at runtime, SQLite is test-only.)
- **GitHub release-notes automation: `.github/workflows/release.yml`** (AUDIT-165, v0.10.367): there was no release automation — cutting a release meant hand-copying notes. Added a **tag-triggered** workflow (`on: push: tags: v*`) that lifts the matching section out of `CHANGELOG.md` and publishes it as a GitHub Release via the `gh` CLI. Design note: chose a **CHANGELOG-driven** workflow over `release-drafter` deliberately — release-drafter categorises merged *pull requests* by label, but this repo is developed **direct-to-master** (the audit-resolution effort is a long run of `vX.Y.Z: AUDIT-NNN …` commits, not labelled PRs), so the CHANGELOG (which the project already maintains rigorously per Keep-A-Changelog) is the real source of truth for "what changed." The extraction reads the `## [X.Y.Z]` block for the pushed tag and **falls back to `## [Unreleased]`** when that version hasn't been cut into its own section yet, so a release is never note-less; it `gh release create`s a new release or `gh release edit`s an existing one (idempotent re-runs). `permissions: contents: write` is scoped to just this job. The workflow is **dormant until the first `vX.Y.Z` tag is pushed** (the AUDIT-004 cutover), so it changes nothing about the current commit flow. `TestReleaseWorkflow_AUDIT165` (in `internal/shell`) pins the tag trigger, the write permission, the CHANGELOG extraction + Unreleased fallback, and the `gh release` publish — and asserts it is **not** branch-triggered (which would publish on every commit). **Not done:** no binary/Docker artifact build is wired into the release yet (that's the `.goreleaser.yml` half of AUDIT-004, still open) — this ships the notes automation only.
- **KNOWN-ISSUES.md** (AUDIT-110): new top-level file cataloguing operator-known limitations that don't yet have a fix. Each entry cross-links to its `docs/AUDIT.md` row so the operator can navigate from a known issue to the audit doc and back. Covers AUDIT-040 (single-binary Docker port binding), AUDIT-118 (SQLite test backend vs production Postgres), AUDIT-093 (embedded Postgres random password), AUDIT-105 (default `ADMIN_USERNAME=admin` warning), and AUDIT-029 (orphan tables grow between cleanup ticks).

### Changed
- **Monthly range-partitioning for the 6 high-volume time-series tables** (AUDIT-028 + AUDIT-146, v0.10.380): `interface_stats` (~130M rows at 50 devices × 60s × 90d) and `system_status` grew unbounded with row-by-row batched `DELETE` retention that bloats and never reclaims space. Investigation found the **entire partition subsystem was dormant** — `EnsurePartitions` only acted on already-partitioned parents, but nothing ever *created* a partitioned parent (AutoMigrate makes plain tables), so `syslog_messages`/`syslog_summaries`/`trap_events`/`flow_samples` (AUDIT-146) were plain on every fresh install too, and `docs/partition-migration.md` (referenced by the warning) didn't exist. Now: a recorded **v2 migration** (`partition_high_volume`) converts each of the 6 tables to a monthly `PARTITION BY RANGE (timestamp)` parent **only when it's empty** (fresh installs → instant, zero-risk) with a composite `PRIMARY KEY (id, timestamp)` (Postgres requires the partition key in the PK; the gorm models are unchanged — they're append-only and queried by `device_id`+`timestamp`, never by `id` alone, and AutoMigrate is additive so it never fights the composite PK). A table that **already has rows** (existing prod) is **skipped with a warning** pointing at the new `docs/partition-migration.md` operator runbook — a ~130M-row copy-rewrite is far too heavy to auto-run at startup, so the operator does it in a maintenance window. `EnsurePartitions` now covers all 6 (current month + 6 ahead; `interface_stats` gets the extra `(device_id, "index", timestamp)` per-partition index for per-interface charts). Cleanup now **drops whole old partitions** (`dropPartitionsOlderThan` — instant space reclamation) for the single-cutoff tables, falling back to batched `DELETE` for plain tables and the straddling tail; `syslog_messages` deliberately stays on severity-scoped `DELETE` (its dual critical/info retention can't be expressed as a whole-partition drop). Migration ordering is safe (v2 runs before `EnsurePartitions`, both before the server accepts traffic — no "parent has no child partition yet" insert window). **Postgres-only** (a no-op, still recorded, on the SQLite test backend). Verified by the AUDIT-118 CI Postgres integration suite (all 6 become partitioned parents; `EnsurePartitions` creates+routes; `EXPLAIN` prunes to one partition; populated-table skip; cleanup drops an old partition) — its first real run is the CI job. **Not done:** `syslog_messages` partition-drop (dual retention) and downsampling/rollup of interface_stats (separate feature). Resolves AUDIT-028 and AUDIT-146.
- **Versioned, recorded DB migrations replace blind AutoMigrate-on-startup** (AUDIT-044, v0.10.378): schema management ran a 44-model `AutoMigrate` loop + column shims + a destructive IRC drop-and-recreate heuristic on **every** startup across three racing processes, with **no `schema_migrations` table and no migration log** — a 3am column-not-found error had nothing to consult. Added an **in-repo versioned migration runner** (`internal/database/migrations.go`): an append-only `registeredMigrations` list, a `schema_migrations(version, name, app_version, applied_at)` bookkeeping table (created via raw dialect-agnostic DDL), and `RunMigrations()` which applies only un-recorded versions, records and **logs each** (`migrate: applied vN "name"`), serialized across processes by a blocking Postgres advisory lock held on a **pinned `*sql.Conn`** (distinct key from the startup-setup lock; SQLite no-op). **v1 "baseline" reuses the existing, proven AutoMigrate+shims** (`migrateBaseline`), so on an existing deployment it no-ops and just records v1 — **the DDL that runs against prod is unchanged**; the only net-new SQL is the bookkeeping table + one INSERT per version. Added explicit `fwmon-api migrate` and `fwmon-api migrate-status` subcommands (reusing a new `database.Connect()` that opens without migrating); the daemons still auto-apply on startup (`NewDatabase` = `Connect` + `RunMigrations` + the unchanged leader-gated partition/autovacuum setup) so a forgotten migrate step self-heals — **hybrid invocation, no deploy/entrypoint/systemd changes**. **Removed** the dead IRC drop-and-recreate heuristic (its predicate — IRCServer present but missing `ServerPassword` — is false on any recently-booted deploy, and it was destructive); the IRC tables are maintained by the normal AutoMigrate loop. Verified on the SQLite test backend (`migrations_audit044_test.go`: table created, baseline recorded once, re-run no-op, a fake v2 applies once then skips) + a static guard (`migrations_audit044_test.go` in `internal/shell`). **Prod-Postgres safety:** there's no Postgres test env here, but the baseline executes byte-identical DDL to today's `migrate()` (minus the dead IRC block) — only dialect-agnostic bookkeeping is new. Third of the five large refactors. **Not done:** the post-migration setup steps (partitions/autovacuum) aren't folded into the framework yet, and future schema changes still append a Go migration (no SQL-file/goose adoption until a Postgres CI env, AUDIT-118, exists to verify it).
- **Browser-facing DB calls now run on the request context** (AUDIT-032 + AUDIT-079, v0.10.377): every HTTP handler ran its DB queries on the background context, so when a browser disconnected (the dashboard polls ~100 RPS) the in-flight query kept running and held its pooled connection until the DB returned — the classic "DB pool exhausted" outage. Added `(*database.Database).WithContext(ctx)` (a shallow copy whose `*gorm.DB` is bound to ctx — gorm's reusable-session model, so one copy safely serves many queries + transactions; **zero changes to the ~175 `*Database` methods**) and a `Handler.reqDB(c)` helper returning `h.db.WithContext(c.Request.Context())` (or nil when the DB is unavailable, so existing `RequireDB`/nil guards work unchanged). Swept **116 browser-facing handlers across 13 files** (admin UI, public dashboard, auth, admin probe management) to `db := h.reqDB(c)` + the heavy report-build path (`buildReportHTML`→`report.GatherDeviceData`). A client disconnect now cancels the query and frees the connection. **Scope boundary (deliberate):** probe-ingestion handlers (`handlers_data.go` — many synchronous writes) stay on the durable **background** context so a probe's in-flight write over a flaky WAN is never cancelled mid-flight; the async batchers (their flush closures captured the original `*Database`), the `internal/audit` post-response middleware, the AlertManager, the poller/trap daemons, and trivial single-row settings lookups (`getNotificationSetting`) also stay background. Verified: `TestWithContext_AUDIT032` proves an already-cancelled ctx returns `context.Canceled` on a query, the original `Database` is untouched, and the bound copy is reusable across queries + a transaction; `TestRequestContextBoundary_AUDIT032` freezes the cancel-vs-durable boundary (browser-facing files use `reqDB`; `handlers_data.go` must not). The server-side `statement_timeout` (AUDIT-037) already capped query duration; this adds the per-request *cancellation* the audit asked for. Second of the five large refactors; AUDIT-079 is the same finding and is closed by this change.
- **Split the 4,887-line `internal/database/database.go` into per-domain files** (AUDIT-072, v0.10.376): the single largest, least navigable file in the repo (~175 top-level declarations) is now **15 cohesive sibling files** in the same `package database`. `database.go` keeps only the **core lifecycle** (the `Database` struct, `NewDatabase`, the two advisory-lock helpers, `Close`) and is down to **331 lines**; everything else moved to domain files — `migrate.go` (migration/partitions/autovacuum), `telemetry.go`, `events.go`, `config_revisions.go`, `cleanup.go`, `devices.go` (devices + connections), `sites_probes.go` (admin/sites/probes/settings), `ping.go`, `charts.go`, `flows.go`, `syslog_agg.go`, `stats.go`, `connection_detail.go`, `device_queries.go`, `alerts.go` (largest is `connection_detail.go` at 677 lines). This is a **pure code-organization move**: no behavior change, no API change, no signature change — every function kept its exact body and is still a method on `*Database` in the same package. **Verification:** a content-preservation diff confirmed **zero** original code lines were dropped; `gofmt`/`go vet`/`go build` clean; the **full `go test ./...` suite passes unchanged** (the suite passing IS the proof that nothing changed semantically). Two `internal/shell` static-source guards (AUDIT-080 `errors.Is`, AUDIT-146 partition-warning) now scan the whole package directory instead of hard-coding `database.go`, so they follow the code across files; a new `TestDatabaseFileSplit_AUDIT072` pins `database.go` < 1000 lines and the domain files' existence so it can't silently regrow. First of the five large refactors — lowest-risk and fully local. `goimports` resolved each new file's import subset.
- **FUNDING: documented decision not to solicit donations** (AUDIT-164, v0.10.372 — *accept/wontfix*): the audit suggested adding `.github/FUNDING.yml` *"if accepting donations."* The project is not soliciting donations, so **no `FUNDING.yml` is shipped** — an empty/placeholder one would be dead clutter, and inventing a sponsor account would be wrong. This closes the finding as a deliberate accept (the same "or accept the limitation" framing the audit applied to the community-channel item). If the maintainer later wants sponsorship, adding `.github/FUNDING.yml` with the real `github:`/`custom:` handles is a one-line change GitHub picks up automatically. No code or test change — there is no artifact to regress.
- **README now points users at a support channel** (AUDIT-166, v0.10.371): the project ships an IRC bot feature but never told its **own** users where to get help. Added a **Support & community** section: bugs/feature-requests → GitHub Issues (with a nudge to include `GET /api/version` + the logged `X-Request-ID`), questions/setup help → GitHub Discussions, security → SECURITY.md (never a public issue). Stated plainly that there is **no dedicated chat server** (the honest "accept the limitation" the audit offered) and clarified that the built-in IRC bot is a *monitoring feature* for the operator's own ops channel, **not** a support channel for this project. Renamed the old link list to "Contributing & docs". `TestReadmeSupportChannel_AUDIT166` pins the Support section, the Issues/Discussions pointers, and the IRC-bot disambiguation.
- **README build prerequisites for a fresh Ubuntu box** (AUDIT-114, v0.10.370): the Quick Start assumed tools and ports it never named, so a clean-machine setup would fail or silently drop traffic. Expanded the Prerequisites section with the exact `apt install` line (`golang-go git make rsync bash`, plus `build-essential` only for the `-race` C toolchain), notes that the native installer is **systemd**-only (macOS/Windows can build/run but not `make install`), and a **network-ports table** — `8080` HTTP (in), `161` SNMP poll (out), `162` SNMP trap (in), `514` syslog (in), `6343` sFlow (in), `5432` Postgres (out) — with the key operational fact that **probes need only outbound reach** to the server (no inbound ports at the remote site). `TestReadmePrereqs_AUDIT114` pins the tools + the trap/syslog/sFlow ports.
- **README endpoint sweep + project positioning** (AUDIT-106, v0.10.369): the README's "API Endpoints" section documented ~12 routes while the server registers **~174** — it silently omitted entire families (`/admin/api/sites`, `/admin/api/probes*`, `/admin/api/syslog`, `/admin/api/flows`, `/admin/api/maintenance-windows`, `/admin/api/alert-policies`, `/admin/api/reports/*`, the `/admin/network` page, and all ~21 probe-ingestion POSTs). Replaced it with an accurate **grouped reference** covering every category — Public (no-auth), Authentication, Admin UI pages, Admin API by resource (devices/sites/probes/connections/alerts/alert-policies/maintenance/telemetry/IRC/reports/settings/dashboard), and probe ingestion — with the route-group base paths spelled out and `cmd/api/main.go` named as the authoritative list. Also added the public-project positioning the audit asked for: **"Who is this for"**, **"When NOT to use this"** (pointing at LibreNMS/Zabbix/Checkmk/Uptime Kuma/StatusCake/PRTG/SolarWinds for the cases this isn't built for), and a **"How it compares"** table vs PRTG/Nagios/Zabbix/LibreNMS/Checkmk/Uptime Kuma/StatusCake — framed honestly as a narrow firewall-first tool, not a general NMS. `TestReadmeDocumentsEndpoints_AUDIT106` pins the route families + positioning sections + named alternatives so the docs can't silently regress to the 12-endpoint stub.

## [0.10.362] - 2026-06-06
### Changed
- **Dropped the ES5/IE11 reserved-word bracket workaround in the admin JS** (AUDIT-132, v0.10.365): the hand-written admin JavaScript used the legacy `promise['catch'](…)` / `promise['finally'](…)` (and `searchParams['delete'](…)`) bracket member-access form — a relic of IE11-era reserved-word handling. The project's browser baseline is **ES2020** (Chrome/Edge 105+, Safari 15.4+, Firefox 121+ — AUDIT-168/131, already documented in the README "Browser Support" section), where plain `.catch` / `.finally` / `.delete` member access is valid, so the bracket form was dead weight that obscured the code. Swept **all 121 sites across 14 files** to dot notation (`['catch']`×117, `['finally']`×2, `searchParams['delete']`×2); vendored bundles (`layout-base.js` et al.) were left untouched. Every modified file passes `node --check`. `TestNoES5BracketWorkaround_AUDIT132` (in `internal/shell`) scans `cmd/api/static/js/*.js` and fails if any of the three bracket forms is reintroduced (the conventions `README.md`, which intentionally quotes the literal syntax as the thing not to re-add, is excluded). This completes the cleanup that AUDIT-131 (v0.10.362) flagged as deferred. **Not done:** no behavior change — these are byte-equivalent member accesses; the public-wallboard JS under `web/public/` had no bracket forms to convert.
- **Audit + handoff docs consolidated into a single `docs/AUDIT.md`** (docs): `docs/HANDOFF.md` was merged into `docs/AUDIT.md` and removed, so there's now one file to follow the public-release hardening effort. The file opens with a **Status dashboard** (server version, 124/170 resolved, 0 CRITICAL open, what's-left grouped by theme, and a recent-activity table), then **Part II** = the original v0.10.239 audit findings (kept as the per-finding reference that `SECURITY.md`/`KNOWN-ISSUES.md` link to; the stale "not yet ready / 10 CRITICAL blockers" executive summary is now clearly marked historical), the **Resolved findings** table + **Progress log** (unchanged — the canonical audit trail), and **Part III** = the per-commit workflow + session completion logs (the former HANDOFF content). Note for tooling: the resolved count must now be scoped to the Resolved-findings table (`awk '/^## Resolved findings/{f=1} /^## Progress log/{f=0} f && /^\| AUDIT-/{c++} END{print c}'`) because Part III's session-log tables also contain `| AUDIT-` rows.
- **CSP `style-src` allows `'unsafe-inline'` again** (AUDIT-022b — fixes the public dashboard): AUDIT-022 (v0.10.259) nonce-locked BOTH `script-src` and `style-src`. The `style-src` half quietly broke the public GridStack dashboard: GridStack and Chart.js size their widgets/canvases by setting inline `style=""` **attributes** at runtime, which cannot carry a nonce — so every grid cell collapsed to `height: 0` and every chart fell back to the 300×150 canvas default ("tiny, misformatted graphs"). It was latent because the operator hadn't reloaded the public wallboard after that release. Changed `style-src` to `'self' 'unsafe-inline'` (the nonce is dropped — a nonce on `style-src` makes `'unsafe-inline'` be *ignored* by browsers). **`script-src` is unchanged and still strict** (`'self' 'nonce-…'`, no `unsafe-inline`) — that's the XSS-critical directive; inline `<script>` is still refused. The only thing re-opened is CSS injection, which cannot execute JavaScript. Verified with a headless GridStack A/B test: under the old policy widgets measured `[0,0]` with CSP errors; under the fix they measure `[300,150]` with zero CSP errors. The `csp_nonce_test.go` / `csp_nonce_html_test.go` guards now assert `script-src` is strict while `style-src` permits inline styles.

### Deprecated
- nothing yet

### Removed
- nothing yet

### Fixed
- **Test hygiene: stop leaving the std logger pointed at a nil writer** (v0.10.375, surfaced while adding AUDIT-129): three tests (`internalerror_audit071_test.go`, `clienterror_audit129_test.go`) captured `log` output with `log.SetOutput(&buf)` and restored it with `defer log.SetOutput(nil)`. A `nil` writer means the *next* test in the package that calls `log.Printf` panics with a nil-pointer dereference — which `TestReceiveConfigRevision_FortiGateIVDrift_MergesIntoLatest` did, intermittently depending on test order. Restored to `log.SetOutput(os.Stderr)` (the package default) instead. No production code affected.
- **Handler 500s now log their cause: `httputil.InternalError` + full sweep** (AUDIT-071, v0.10.368): the audit found **134 handler sites** of `c.JSON(http.StatusInternalServerError, models.ErrorResponse("…"))` — every one returned a 500 to the client but **logged nothing server-side**, so a production failure (DB error, tx rollback, build failure) left zero trace in the server log. Added `httputil.InternalError(c, msg, err)` which logs the underlying `err` with operation context — request method, matched route, and the `X-Request-ID` from the RequestID middleware (AUDIT-135) when present, so a logged 500 correlates with its access-log line — then writes the standard `ErrorResponse(msg)`. Swept **all 133 sites** across 13 handler files to the helper. **Security bonus:** 4 of those sites (`IRC connect`/`send`, two `report build`) were concatenating `err.Error()` into the **client** response (`"Failed to connect: " + err.Error()`); routing them through the helper stops leaking internal error text to the browser while still logging the full detail for the operator. The client now always sees only the clean message; `err` (which can carry SQL text, file paths, driver internals) never crosses the wire. Edge cases handled by hand: 4 sites had no underlying Go error (nil-check / failed type-assertion — `pass nil`), one is a partial-failure aggregate whose per-key errors are already logged in its loop (`pass nil` + dynamic count message), and `DeleteConnection`/`ReceiveConfigRevision` pass their real in-scope error (`result.Error` / `txErr`). Two regression tests: `TestInternalError_AUDIT071` (in `internal/httputil`) proves the helper writes 500, puts only `msg` in the body, never leaks `err`, logs `err`, survives a nil `err`, and includes the request id; `TestInternalErrorSweep_AUDIT071` (in `internal/shell`) statically fails if any handler reintroduces the silent boilerplate. **Not done:** this only covers the 500 path — `c.JSON(400/404/409, …)` client-error responses are intentionally left as-is (a 4xx is the client's fault, not a server fault worth logging), and the structured-logging migration that would turn these `log.Printf` lines into `slog` records is still AUDIT-076.
- **Wrapped the raw `return err` sites in `internal/database/database.go`** (AUDIT-081, v0.10.366): the audit found dozens of bare `return err` propagations of GORM's `tx.Error` with no operation context — a caller (or an operator reading a log line) could not tell *which* transaction step failed, nor distinguish "not found in a tx" from "constraint violation in a tx". Wrapped all **25 remaining** sites with `fmt.Errorf("operation: %w", err)`, each naming the concrete operation and (where available) the entity id — e.g. `delete device %d: delete related %T: %w`, `save config revision: prune stale revisions: %w`, `upsert setting %q: %w`, `approve probe %d: update probe row: %w`. Critically, `%w` (not `%v`) **preserves** `errors.Is` / `errors.As`, so the existing `gorm.ErrRecordNotFound` sentinel checks (AUDIT-080) still unwrap correctly through the new wraps. Two of the sites were *trailing* `return err` where `err` could be `nil` on the success path (`CreateDevice`, `MarkBatchProcessed`) — those were converted to a guarded `if err != nil { return fmt.Errorf(...) }; return nil` so wrapping never manufactures a non-nil error out of a successful call. `TestNoBareReturnErrInDatabase_AUDIT081` (in `internal/shell`) statically asserts zero bare `return err` remain in `database.go` and that at least one `%w` wrap is present. The full `internal/database` suite still passes. **Not done:** the sibling `c.JSON(500, models.ErrorResponse(...))` handler boilerplate (AUDIT-071, which *also* drops the underlying `err`) is a separate, larger sweep and stays open.
- **Benchmarks on the per-packet parser hot paths** (AUDIT-124, v0.10.364): there were no benchmark tests, so a performance regression in the highest-frequency code paths would go unnoticed. Added `BenchmarkParseRFC5424` + `BenchmarkParsePriority` (`internal/syslog`) and `BenchmarkParseSFlowDatagram` (`internal/sflow`) — every inbound syslog line and sFlow UDP packet runs through these, so they're genuine hot paths, and being pure-CPU they benchmark cleanly without DB fixtures. All `b.ReportAllocs()` + `b.SetBytes()` so `go test -bench=. ./internal/syslog ./internal/sflow` reports ns/op, throughput, and allocs (current baseline: syslog parse ~1.7 µs/12 allocs, sFlow header ~4 ns/0 allocs). Crafting the syslog fixture surfaced that this parser treats PRI and VERSION as **separate** space-delimited tokens (`<165> 1 <ts> …`), not the glued RFC 5424 `<165>1` form — the benchmark uses the happy-path layout so it measures a successful parse, not the error branch. Deferred: the DB-bound hot paths the audit also named (`BatchInserter`, `GetConnectionFlowStats`) need a seeded test DB — a separate benchmark harness.
- **Fuzz tests for the untrusted network parsers** (AUDIT-119, v0.10.363): the two parsers that ingest untrusted wire data — `syslog.ParseRFC5424` (text, over TCP/UDP) and `sflow.ParseSFlowDatagram` (binary UDP) — had no fuzz coverage, and binary parsers are exactly where a crafted packet causes an index-out-of-range panic / DoS. Added Go native fuzz tests (`FuzzParseRFC5424`, `FuzzParseSFlowDatagram`) with hand-picked malformed seeds (empty, truncated headers, embedded NULs, oversized priority, garbage version). The seed corpus runs as a fast regression under plain `go test`; `go test -fuzz=…` does deep fuzzing. **Result: both parsers are robust** — active fuzzing ran **3.3M executions on sflow and 267k on syslog with zero crashes**, so this lands as a durable guard rather than a bug-fix (a future change that introduces a panic on malformed input now fails the seed corpus immediately). These are also the first tests in `internal/syslog` and `internal/sflow` (chips at the AUDIT-117 coverage gap).
- **Frontend JS standard declared: ES2020** (AUDIT-131, v0.10.362): the admin JS mixed ES6 (`admin-irc.js`) with older ES5-style code and `['catch']` IE11 workarounds, with no stated convention — the audit asked to "pick one" and document it. Added `cmd/api/static/js/README.md` declaring **ES2020** the target, justified by the project's documented browser baseline (Chrome/Edge 105+, Safari 15.4+, Firefox 121+ — AUDIT-168, all fully ES2020-capable). So `admin-irc.js`'s modern syntax is **correct** (the audit's "maybe go ES5" framing is superseded by the evergreen baseline), and new ES5 workarounds are discouraged — the legacy bracket-notation `promise['catch']()` is flagged as not-to-be-extended, with its cleanup sweep tracked under AUDIT-132. The doc also records the existing escape-before-innerHTML / no-inline-onclick / `fwmonLog` / `apiFetch` conventions. `TestJSStandardDocumented_AUDIT131` pins the standard + the baseline/`132` cross-references.
- **Per-request IDs for log correlation** (AUDIT-135, v0.10.361): the request logger recorded only method/path/status/latency — there was no way to tie a logged error back to the specific request a user or proxy saw. New `RequestID` middleware (registered before `RequestLogger`) assigns every request a stable ID: it reuses a **safe-looking** inbound `X-Request-ID` (so a fronting proxy's trace ID is preserved) or mints a fresh 128-bit hex one, stores it on the gin context (`RequestIDKey`), and echoes it in the `X-Request-ID` **response header** so a single click is traceable end-to-end. `RequestLogger` now includes `req=<id>` in its line. **Security:** an inbound `X-Request-ID` is only trusted if it matches `^[A-Za-z0-9._-]{1,64}$` — otherwise it's discarded and a fresh ID minted, so a hostile client can't forge log lines by injecting newlines or oversized values via the header. Unit-tested in `internal/api/middleware` (`requestid_audit135_test.go`): generation when absent, reuse of safe inbound, and rejection of newline/space/semicolon/over-64-char inbound. Note: a full `slog` migration (the audit's suggested vehicle) is AUDIT-076, still open — this ships the request-ID propagation with the current logger.
- **Architecture diagrams: `docs/architecture.md`** (AUDIT-108, v0.10.360): the README had only an ASCII directory tree — no data-flow showing poller→DB→API→dashboard, the probe↔server relay, or trap ingress. Added `docs/architecture.md` with a Mermaid component flowchart (the four binaries + DB + IRC/notifier + direct-vs-probe monitoring paths, incl. the poller advisory-lock leader) and three sequence diagrams — probe registration/approval/relay, the SNMP poll cycle, and alert firing + recovery — plus a "where things live" package map. Linked from the README Architecture section. `TestArchitectureDiagram_AUDIT108` pins the Mermaid blocks, ≥3 sequence diagrams, and the README link.
- **Operations runbook: `docs/OPERATIONS.md`** (AUDIT-111, v0.10.359): there was no operator runbook — no first-24h checklist, failure-mode table, debug-logging procedure, password/JWT reset, backup/restore, upgrade, scale, or DR playbook. Added `docs/OPERATIONS.md` covering all of those, **grounded in this system's real mechanisms** (verified against the code, not generic): admin reset works by `DELETE FROM admins` + restart because `InitAdmin` only creates-when-absent; JWT rotation is flagged destructive because `.jwt-secret` seeds the AES key for stored secrets (AUDIT-008); debug logging uses `DB_LOG_LEVEL` (AUDIT-149) and `/data/pgdata/postgresql.log` — **not** `GIN_MODE=debug` (gin is hardcoded to release mode, so the audit's suggestion wouldn't work); backup covers the DB + `.jwt-secret`/`.admin-password` + config + probe keys; failure modes cross-reference the real prod fixes (v0.10.322/323/324, AUDIT-040/083). Linked from the README. `TestOperationsRunbook_AUDIT111` pins all nine sections + the README link.
- **"How to add a vendor" doc confirmed complete** (AUDIT-113, v0.10.358): the audit asked for an `ADDING-A-VENDOR` doc covering both the SNMP profile registration (`internal/snmp`) and the config-diff normalizer (`internal/configdiff`). `docs/custom-vendor.md` (shipped for AUDIT-170) already is that guide and covers both halves — the `VendorProfile`/`RegisterVendor`/`validVendors` SNMP side and the optional `internal/configdiff` normalizer (Step 5). Resolved without duplicating the doc; `TestVendorDocCoversBothSides_AUDIT113` pins that it keeps covering **both** sides (170's test only checked the SNMP side), so a future trim can't quietly drop the configdiff coverage.
- **Login-attempt prune goroutine now stops on shutdown** (AUDIT-084, v0.10.357): the background goroutine that prunes expired login attempts ran a bare `for range ticker.C` with no exit — it relied entirely on process death, so it never participated in graceful shutdown and its 10-minute ticker could fire mid-teardown. Added a cancellable `bgCtx` for background workers; the pruner now `select`s on `<-bgCtx.Done()` and returns, and the shutdown path calls `bgCancel()` before draining the HTTP server. `bgCtx` is reusable for any future background worker. `TestPruneGoroutineHasShutdown_AUDIT084` pins the ctx wiring and that the bare unstoppable loop is gone.
- **Removed the stale, unused `package.json` version** (AUDIT-134, v0.10.356): `package.json` hard-coded `"version": "0.10.157"` — ~200 releases behind the real app version and read by nothing (the file exists only for the Tailwind CSS build; the app version lives in `cmd/api/main.go` `ServerVersion`). Rather than wire up a sync step that adds churn to every version bump, removed the `version` field entirely and marked the package `"private": true` (idiomatic npm for a never-published internal tooling package — no version required, so none can go stale). `TestPackageJsonNoStaleVersion_AUDIT134` pins that no `version` field returns and the package stays private.
- **`apiFetch` retries transient gateway errors** (AUDIT-130, v0.10.355): the admin UI's `apiFetch` surfaced any 502/503/504 as an immediate error toast, so a brief proxy/DB hiccup or a rolling restart looked like a hard failure to the operator. It now retries 502/503/504 up to 3 attempts total with exponential backoff (200 ms, 400 ms) plus jitter (so many tabs don't retry in lock-step), falling through to the existing error path only after the retries are exhausted. The 401/403/CSRF/`!ok` handling is unchanged. `TestApiFetchRetriesTransient_AUDIT130` pins the retry of all three statuses + the jittered backoff.
- **`security.txt` vulnerability-disclosure endpoint** (AUDIT-112, v0.10.354): the server exposed no RFC 9116 `security.txt`, which disclosure programs and scanners look for to find a security contact. Added a route at the canonical `/.well-known/security.txt` (plus the legacy `/security.txt`) returning `Contact:` (the GitHub private-advisory URL, matching SECURITY.md), `Policy:` (SECURITY.md), `Preferred-Languages:`, and an `Expires:` field generated **6 months out at request time** so it never goes stale (RFC 9116 requires `Expires` and recommends < 1 year). `TestSecurityTxtRoute_AUDIT112` pins the route + required fields.
- **Autovacuum table list now covers the heaviest writers + is configurable** (AUDIT-147, v0.10.353): `ConfigureAutovacuum` tuned a hard-coded six-table list that **omitted `interface_stats` and `system_status`** — the two highest-volume time-series tables in the system, exactly the ones that bloat fastest without aggressive autovacuum. Expanded the default set to include them plus `processor_stats`/`process_stats`/`vpn_status`/`ha_status`/`interface_addresses`, and made the whole set overridable via `DB_AUTOVACUUM_TABLES` (comma-separated) for deployments with a different write profile. Table-name resolution moved to a testable `autovacuumTables()` helper (blank entries trimmed; an all-blank override safely falls back to the default rather than tuning nothing). Verified the names against the models' `TableName()` overrides — note `vpn_status`/`ha_status` are **singular** (not `…statuses`). The per-table `ALTER` is failure-tolerant, so a name absent on a given deployment is harmless. `TestAutovacuumTables_AUDIT147` pins the default coverage + the env override semantics.
- **`errors.Is` for the gorm not-found sentinel** (AUDIT-080, v0.10.352): `internal/database/database.go` compared `gorm.ErrRecordNotFound` with direct `==`/`!=` at 15 sites. That works only as long as the error is the bare sentinel — the moment any layer wraps it with `%w` (which the codebase is progressively adopting, see AUDIT-081), the `==` silently stops matching and a "not found" gets misclassified as a real error (or vice-versa). Swept all 15 sites to `errors.Is(err, gorm.ErrRecordNotFound)` (and the two `!=` to `!errors.Is(...)`), which unwraps. Semantically identical today, future-proof against wrapping. `TestErrorsIsForGormSentinels_AUDIT080` pins that no direct comparison returns. (The audit also cited `auth.go:75`/`notifier.go:112`, but the code there has since moved and no longer compares sentinels — verified.)
- **Custom-vendor tutorial: `docs/custom-vendor.md`** (AUDIT-170, v0.10.351): there was no worked example for extending the multi-vendor SNMP architecture, so adding a firewall family meant reverse-engineering the `VendorProfile` interface from existing code. Added an end-to-end tutorial (the full interface, a copy-pasteable shallow "system-stats-only" profile à la `pfsense`, `init()`/`RegisterVendor` registration, the `validVendors` allow-list edit in `handlers.go`, the optional `configdiff` normalizer, and a build/test checklist). All code in the doc was verified against the real API — value coercion uses `gosnmp.ToBigInt(...)` and the `models.SystemStatus` fields are the actual `float64` ones, not invented helpers. Linked from the README. `TestCustomVendorDoc_AUDIT170` pins the doc exists, names the real extension points (`VendorProfile`/`RegisterVendor`/`validVendors`/`ParseSystemStatus`/`init()`), and is linked from the README.
- **Browser support baseline documented** (AUDIT-168, v0.10.350): the frontend uses the CSS `:has()` selector (AUDIT-132) and ES2020, so it silently excludes older browsers — but nothing told an operator that, leaving "is this a layout bug or my old Safari?" ambiguous. Added a **Browser Support** section to the README stating the baseline: Chrome/Edge 105+, Safari 15.4+, Firefox 121+ (the `:has()` floor), with no legacy/IE11 support planned. `TestReadmeBrowserBaseline_AUDIT168` pins the section + the three engines.
- **README documents the configuration surface** (AUDIT-107, v0.10.349): the README's config section was ~4 steps and never mentioned `ENCRYPTION_KEY`, the `RETENTION_*` family, `PROBE_*`, `REPORT_*`, `DB_MAX_OPEN_CONNS`, or the `SERVER_*_TIMEOUT`s — operators had to read the source to learn they existed or find their defaults. Added a key-variable defaults table (verified against `internal/config`, **not** guessed: e.g. `SERVER_READ_TIMEOUT`/`WRITE_TIMEOUT` default `30s`, `DB_MAX_OPEN_CONNS` is per-process 15/10/5, `JWT_SECRET_KEY` auto-persists) and called out `config.env.example` as the authoritative ~70-variable reference. `TestReadmeEnvVarDocs_AUDIT107` pins the cross-link and that each previously-undocumented family is named.
- **README feature list refreshed to match reality** (AUDIT-109, v0.10.348): the Features list was years stale — it omitted reports (`/admin/reports`), sites + the connection map, alert policies, maintenance windows, the IRC bot, sFlow/syslog/ICMP collection, the multi-tenant remote-probe architecture, and multi-vendor SNMP (Palo Alto / Cisco ASA beyond FortiGate). Rewrote the list to cover the shipped subsystems. `TestReadmeFeatureListCurrent_AUDIT109` requires a keyword for each major subsystem within the `## Features` section so the list can't silently rot again.
- **README documents how to test (and native install)** (AUDIT-162, v0.10.347): the README covered build/deploy but never mentioned `go test` — a newcomer had no signal the test suite exists or how to run it before a PR. Added a **Test** subsection (`go test ./...`, `make qa`, `make test-race`) and a **Install Natively** subsection (`make install` / `make tarball`, surfacing the AUDIT-104 path), plus the `make build` alternative in the Build section. `TestReadmeHasTestInstructions_AUDIT162` pins that `go test ./...` stays documented.
- **`.github/CODEOWNERS` added** (AUDIT-163, v0.10.346): the repo had no CODEOWNERS, so PRs got no automatic reviewer assignment — and the 2026-06-06 verification sweep found an earlier CHANGELOG entry *referenced* the file before it existed on disk (a stray/aspirational mention). Added a real `.github/CODEOWNERS` with a `*` catch-all default owner plus more specific owners for the security-sensitive surfaces (`internal/auth`, `internal/secrets`, `internal/api/middleware`, `internal/httputil/ssrf.go`), the schema/migration code (`internal/database`), the build/deploy/CI surface (`Dockerfile`, `Makefile`, `entrypoint.sh`, `deploy.sh`, `.github/`), and the audit/handoff docs. `TestCodeownersExists_AUDIT163` pins the file's existence, the catch-all rule, and that every pattern has an `@owner`.
- **Native (non-Docker) install path: `make install` / `make tarball`** (AUDIT-104, v0.10.345): the project only documented Docker, stranding users on FreeBSD, Synology, RHEL-without-systemd, or k8s-without-a-Docker-socket. Added `make install` (installs the four binaries to `$(DESTDIR)$(PREFIX)/bin` and `web/` + `config.env.example` to `.../share/firewall-mon`, PREFIX/DESTDIR-aware for packaging), `make uninstall`, and `make tarball` (packages binaries + assets + `deploy.sh`/`entrypoint.sh`/`README`/`LICENSE` into `dist/firewall-mon-$(VERSION).tar.gz`). **Also fixed a latent naming bug:** the `build` target used `go build -o bin/ ./cmd/...`, which names binaries after their directories (`api`/`poller`/`trap-receiver`/`probe`) — mismatching the canonical `fwmon-*` names every other part of the project uses (Dockerfile, `deploy.sh`, the systemd `ExecStart` paths). `make install` would have referenced non-existent `fwmon-*` files. The `build` target now emits the canonical `fwmon-api`/`fwmon-poller`/`fwmon-trap`/`fwmon-probe` names. Validated by staging a real `install` to a temp DESTDIR and building the tarball. `TestMakefileNativeInstall_AUDIT104` pins the targets, the canonical names, and PREFIX/DESTDIR awareness.
- **Reproducible builds: `-trimpath -buildvcs=false`** (AUDIT-102, v0.10.344): neither the Dockerfile `go build` lines nor the Makefile `build` target passed reproducibility flags, so the same source compiled on two machines produced different bytes (embedded `/build` + module-cache paths via `-trimpath`'s absence, and VCS stamping). Added `-trimpath -buildvcs=false` to all four Dockerfile build invocations and to the Makefile `build` target (via a `GOFLAGS_REPRO` var). Binaries are now byte-identical across build hosts given the same source + toolchain. `TestReproducibleBuildFlags_AUDIT102` pins both build paths. Deferred: `SOURCE_DATE_EPOCH` and ldflags version injection — `ServerVersion` is a `const` (ldflags `-X` only rewrites `var`s) and is already correct in source, so injection would require changing the declaration for no functional gain.
- **Dockerfile builder no longer installs an unused C toolchain** (AUDIT-103, v0.10.343): the builder stage ran `apk add --no-cache gcc musl-dev`, but every binary is compiled with `CGO_ENABLED=0`, so the C compiler was never invoked — it only added an `apk` round-trip and image-layer weight to every build. Removed the package install (replaced with a comment explaining why none is needed). Pure-Go builds need nothing beyond the `golang:1.23-alpine` base. `TestDockerfile_NoUnusedCToolchain_AUDIT103` pins that `gcc`/`musl-dev` stay out while `CGO_ENABLED=0` remains (so the removal stays valid).
- **Probe device polls are now context-aware and tracked** (AUDIT-087, v0.10.342): the probe launched each per-device SNMP poll as a bare `go p.pollDevice(dev)` with no context and no handle. After `Stop()` closed `stopChan`, in-flight polls kept running unbounded — a poll mid-SNMP could still fire HTTP writes through a relay client the rest of shutdown was tearing down, and shutdown returned while goroutines were still live. `pollDevice` now takes a `context.Context` and checkpoints (`if ctx.Err() != nil { return }`) before starting and between the system-status / interface / VPN stages; the probe holds a cancellable `ctx`/`cancel` and a `pollWG`, each poll is registered on the WaitGroup, and `cleanup()` cancels the context then waits for in-flight polls to **drain — bounded to 5s** so a poll stuck in a slow SNMP timeout can't hang shutdown (a poll that outlives the bound only issues a couple of stateless HTTP POSTs, which is safe). The drain runs *before* the relay client is stopped, so polls don't race the teardown of the client they write through. `cmd/probe` unit-tests both the cancel+drain happy path and the 5s bounded-drain ceiling (`TestProbeCleanup_CancelsAndDrainsPolls_AUDIT087`, `TestProbeCleanup_BoundedWhenPollIgnoresCtx_AUDIT087`); `internal/shell`'s `TestProbePollDeviceContext_AUDIT087` pins the source shape. Deferred: threading the context down into the gosnmp calls themselves (the library uses its own per-op timeout; true mid-operation cancellation would need a gosnmp-level change).
- **Jittered retry/reconnect backoffs (thundering-herd guard)** (AUDIT-088, v0.10.341): the probe relay's batch-send retries (`relay.go`, on both the transport-error and non-2xx paths) and the IRC bot restart delay used fixed `time.Sleep(time.Duration(retries+1) * time.Second)` / `time.Sleep(1 * time.Second)` waits. When a shared event recovers many probes at once (server restart, network blip), every probe retries in lock-step, hammering the server in synchronized waves. Added a `jitter(d)` helper (per package, `crypto/rand`-backed) that returns `d` plus a uniform random extra in `[0, d)`, and applied it at the three named backoffs so recoveries spread out across the window. `internal/relay` unit-tests the bounds + spread (`TestJitter_BoundsAndSpread_AUDIT088`, `TestJitter_NonPositive_AUDIT088`); `internal/shell`'s `TestBackoffJitter_CallSites_AUDIT088` pins the call sites and that the deterministic form is gone. Note: `runCollectorHandler`'s 100 ms `default`-branch sleep (also cited by the audit) is an **idle poll loop**, not a server retry — it issues no request, so jitter there would only slow shutdown detection; left unchanged by design.
- **Hardened companion reverse-proxy config shipped** (AUDIT-097, v0.10.340): `docker-compose.proxy.yml` shipped nginx-proxy-manager (a GUI proxy) with **no** hardened proxy configuration — TLS policy, HSTS, gzip, WebSocket upgrade and real-client-IP all had to be hand-configured later through the NPM web UI, and the WebSocket-upgrade toggle (needed by the live `/admin/connections` map and `/admin/irc` console) is easy to miss. Added `docs/nginx.conf`: a complete, copy-paste plain-nginx config with TLS termination, HTTP→HTTPS redirect (ACME-challenge-aware), HSTS (preload-eligible), gzip, a `$connection_upgrade` map + per-route WebSocket upgrade headers for the two live pages, and `real_ip_header X-Forwarded-For` from the Docker subnets. `docker-compose.proxy.yml` now documents it and carries a commented-out `nginx` service that mounts it as a config-as-code alternative to NPM. `TestNginxCompanionConfig_AUDIT097` pins every required feature and the compose reference. **Deferred (its own change):** the app sets `router.SetTrustedProxies(nil)` so Gin still ignores `X-Forwarded-For` (the safe default for a directly-exposed app) — making the app honor the proxy's forwarded client IP weakens that hardened default and needs explicit config wiring, documented inline in `docs/nginx.conf` as the AUDIT-097 follow-up.
- **`deploy.sh` destructive wipe now has a backup + `--dry-run`** (AUDIT-098, v0.10.339): the remote deploy ran `sudo rm -rf ${REMOTE_DIR}/*` unconditionally with no backup and no rollback — a typo in `--host`, a half-built `bin/`, or an aborted transfer could leave a wiped or partial install irrecoverable. Two safeguards now precede the destructive step: (1) a **`--dry-run`** flag that prints exactly what would happen and makes **zero** remote changes (no rm, no rsync, no install) — operators run it first against a new target; and (2) a **timestamped backup tarball** of the existing install written to `${REMOTE_DIR}-backups/` on the remote *before* the wipe, so a bad deploy rolls back by extracting the latest archive. `TestDeploy_BackupAndDryRun_AUDIT098` pins both safeguards and asserts (by byte offset) the backup runs before the rm. Deferred: a post-`systemctl start` healthcheck — this script stages files and hands off to `install.sh`/manual start, so it never starts the services itself; the healthcheck belongs in that step (tracked with AUDIT-096 healthcheck work).
- **`deploy.sh` no longer clobbers the operator's live config** (AUDIT-099, v0.10.338): the remote-install step ran `sudo cp /tmp/config.env.example /etc/firewall-mon/config.env` **unconditionally on every deploy**, overwriting the operator's real SNMP community, JWT secret, SMTP credentials, and thresholds with placeholder defaults — the service would silently revert to a broken/insecure config on the next restart after any redeploy. The copy is now guarded by `if [ ! -f /etc/firewall-mon/config.env ]`, so the example only seeds a genuine first install; subsequent deploys preserve the existing file (the example is still staged at `/tmp/config.env.example` for manually diffing new keys). `TestDeploy_PreservesLiveConfig_AUDIT099` pins the existence guard.
- **PostgreSQL logging rationale documented in `entrypoint.sh`** (AUDIT-095, v0.10.337): the audit flagged `logging_collector = off` as "crash forensics lost". In this embedded single-container setup that premise is only half-true — Postgres is started with `pg_ctl -l "$PGDATA/postgresql.log"`, so its stderr (startup/crash/FATAL/PANIC/slow-query lines) is redirected to a file on the **bind-mounted** `/data/pgdata`, which survives container restarts. The collector is deliberately kept off so we don't run PG's log-rotation subprocess inside a container whose lifecycle Docker already manages, and so PG diagnostics aren't interleaved with the three fwmon daemons' stdout. Added an in-config comment documenting this, where the logs live, and the one-line alternative (`log_destination = stderr` + drop the redirect) for operators who'd rather see PG logs in `docker logs`. Documentation-only — **no runtime behavior change** (deliberately conservative: the entrypoint runs the live production database). `TestEntrypoint_LoggingRationale_AUDIT095` pins that both the rationale and the `pg_ctl -l` redirect stay present so the two halves can't silently drift apart.
- **`.dockerignore` now excludes developer/working-tree artifacts** (AUDIT-092, v0.10.336): the build-context ignore list was missing `cookies.txt`, `interfaces.json`, `IRC-FORMAT.txt`, `node_modules/`, `tasks/`, `.claude/`, and `lessons.md` (plus `*.csv`). None are COPYed by today's Dockerfile (it copies specific binaries + `web/`), so nothing leaks *right now* — but the moment a future PR broadens the COPY surface (the common `COPY . .` refactor), these local files — agent working notes, the IRC format dump, scraped CSV exports — would silently land in the published image. Added the missing lines so the exclusion is durable regardless of how COPY evolves. `TestDockerignore_CoversWorkingTreeArtifacts_AUDIT092` asserts each required entry is present (matching whole comment-stripped lines, so an entry named only in a comment can't satisfy it).

## [0.10.335] - 2026-06-06
### Fixed
- **AUDIT-067 closed — `#6e7681` no longer used as normal-size text (WCAG AA)** (v0.10.335): the sibling of AUDIT-066. `#6e7681` (~4.1:1 on the dark background — passes AA only for *large* text, fails for normal/small) was the faint-text tier, applied three ways: the `--fwmon-text-faint` design token, literal `color:#6e7681`, and `text-[#6e7681]` Tailwind utilities (~42 sites across admin HTML/CSS/JS). All **text** uses were retargeted to **`#8b949e`** (~5.8:1, passes AA) — deliberately a *different* target than AUDIT-066's `#768390`, so the two faint tiers stay distinct (avoiding the hierarchy-flatten that got the v0.10.319 blanket sweep reverted). The token's 2 **decorative** `border-color: var(--fwmon-text-faint)` uses were pinned to literal `#6e7681` so borders are unchanged. `TestNoFaintTextColor_AUDIT067` walks the entire frontend tree to pin that no `#6e7681` text (literal, utility, or token) returns. With 066, both color-contrast findings are now closed.

## [0.10.334] - 2026-06-06
### Fixed
- **AUDIT-066 closed — `#484f58` no longer used as text (WCAG AA)** (v0.10.334): the faint gray `#484f58` (~2:1 on the dark background — fails WCAG AA) was still a foreground `color:` in 30 places (`admin-shared.css`, `styles.css`, the public dashboard, and inline `style="color:#484f58"` across 5 admin JS files). The v0.10.319 fix that brightened these to `#8b949e` was reverted in v0.10.320 because that blanket sweep flattened the text hierarchy. This redo is **surgical**: only `color:` *text* rules change, to **`#768390`** (~4.6:1, passes AA) — a distinct faint tier, not collapsed into the `#8b949e` tier. All **decorative** `#484f58` — borders (`border-left`/`border-color`/`.border-[#484f58]`), backgrounds (`.bg-[#484f58]`/`.hover:bg-[#484f58]`), and **chart data-viz colors** — is left untouched, preserving the hierarchy that caused the revert. `TestNoFaintTextColor_AUDIT066` pins that no `color:#484f58` text rule remains (decorative use still allowed). The sibling **AUDIT-067** (`#6e7681`) remains open.
- **`GetDashboardAll` N+1 eliminated** (AUDIT-033, v0.10.333): the dashboard's per-device enrichment ran ~13 queries **per device** (row count + latest row + per-metric total/up counts for system-status / interfaces / VPN / HA / SD-WAN) — ~650 queries on a 50-device fleet, ~half a second per dashboard load. Replaced with a fixed set of ~7 batched aggregate queries (one per data type) that compute every device's summary at once using the codebase's max-timestamp self-join pattern (`JOIN (SELECT device_id, MAX(timestamp) … GROUP BY device_id)`), portable across Postgres and the SQLite test backend. The query count is now **O(1)** in the device count, and the enrichment output shape is unchanged. `TestGetDashboardAll_BatchedEnrichments_AUDIT033` seeds multi-timestamp data and asserts each summary reflects the latest timestamp with correct up/alive counts.
- **Window-function chart queries verified SQLite-safe + covered** (AUDIT-043, v0.10.332): the audit flagged the `LAG() OVER w` / `WINDOW w AS (...)` per-sample-delta queries (`GetVPNChartData`, `GetConnectionTraffic`) as unsupported by SQLite and untested in CI. Verified against the current modernc SQLite test backend: the named WINDOW clause **runs correctly** on both Postgres (prod) and SQLite, so the audit's suggested dialect gating + duplicate non-window implementation is **unnecessary** (and would add complexity for no benefit). Closed the real gap — coverage — with `TestGetVPNChartData_WindowDeltas_AUDIT043`, which pins the cumulative-counter→delta math and the counter-reset clamp on SQLite, and documented the dialect-safety in-code so a future reader doesn't add gating back.
- **Retention cleanup deletes in bounded batches** (AUDIT-038, v0.10.331): `CleanupOldData` ran one `DELETE FROM <table> WHERE timestamp < ?` per table — on a 100M-row `interface_stats`/`system_status` that's a long row lock that bloats the table and blocks concurrent writes (and the 24h cleanup runs on the poller). Each table is now deleted in batches of 10,000 via `DELETE … WHERE id IN (SELECT id … LIMIT N)` (a subquery form valid on both Postgres and SQLite); on Postgres each batch runs in a transaction with `SET LOCAL lock_timeout = '5s'`, and a 100 ms sleep between batches yields to other writers. Retention semantics are unchanged — the existing AUDIT-029/031 cleanup tests still pass. `TestBatchedDeleteOlderThan_AUDIT038` shrinks the batch size to exercise the multi-batch loop. Deferred: a leader lock so only one poller runs cleanup (AUDIT-007).
- **Per-process DB connection pool sizing** (AUDIT-036, v0.10.330): all three daemons (api/poller/trap-receiver) hardcoded `SetMaxOpenConns(25)`, so a single host could open **75** connections to Postgres — saturating a busy DB and blocking dashboard handlers on a large fleet. The pool size is now per-process: each daemon's `main` sets a default (**15** api / **10** poller / **5** trap-receiver), overridable for all processes via `DB_MAX_OPEN_CONNS`. `NewDatabase` reads `cfg.Database.MaxOpenConns` (falling back to the legacy 25 when unset) and caps idle connections at the open limit. `TestDBPoolPerProcess_AUDIT036` pins the per-process defaults and the env wiring.
- **Probe registration keys are now hashed at rest (show-once)** (AUDIT-017, v0.10.329): a probe's registration key is the bearer token that authenticates every data submission, and it was stored in **plaintext** — a DB read leaked every probe's credentials (SNMP/IRC secrets were already encrypted; probes were the exception). Keys are now stored as `sha256:`+SHA-256(key). Because the key is looked up and compared **by value**, it is **hashed, not encrypted** — the audit's "encrypt with AES-GCM" suggestion can't work (a by-value lookup needs determinism, and non-deterministic AES-GCM ciphertext can't be queried; a reversible store also still leaks on key+DB compromise). The plaintext is therefore **show-once** — returned only by the `RegenerateProbeKey` response (every other probe API response already redacted it). An idempotent startup migration (`migrateProbeKeysToHash`, guarded by the `sha256:` prefix) hashes legacy plaintext keys and their `probe_registration_<key>` settings in place; **a live probe keeps authenticating** because the collector keeps sending the same plaintext token, which hashes to the stored value (proven by test). All lookups/compares updated: `validateProbe`, `authenticateProbeByBearer`, `RegisterProbe`, `GetProbeByRegistrationKey`. **Security detail (caught in review):** `HashProbeKey` deliberately *always* hashes and is **not** idempotent — an idempotent version let the stored hash itself authenticate when presented as a token (DB-leak → access); `TestProbeAuth_HashedKey_AUDIT017` pins that presenting the stored hash returns 401. Tests: `probekey_audit017_test.go` (hash contract, migration incl. live-probe safety + idempotency), `handlers_probe_keyhash_audit017_test.go` (end-to-end auth). **Operational:** no action needed for existing probes; admins can no longer view an existing probe's key — regenerate to obtain a new one.
- **Bumped stale dependencies** (AUDIT-018, v0.10.328): `gin` 1.9.1→1.10.1, `golang-jwt/jwt/v5` 5.2.0→5.2.2, `gosnmp` 1.37.0→1.40.0, plus transitive `golang.org/x/net` 0.25.0→0.38.0 (fixes the reachable `html.Tokenizer` DoS that `ShouldBindJSON` can hit on probe-supplied input) and `x/crypto`→0.36.0. Pinned **conservatively** to keep the `go 1.23` directive: a blanket `go get -u`/`@latest` pulls gin 1.12 plus quic-go/mongo-driver and forces the module to `go 1.25`, which would break the `golang:1.23-alpine` Docker build — avoided. The live gate is the existing `govulncheck` CI job (ci.yml, AUDIT-004); `internal/shell/godeps_audit018_test.go` statically pins the floors so a careless downgrade fails fast. **Deferred (out of "safe bumps" scope):** (1) the remaining govulncheck findings are Go **standard-library** CVEs (`crypto/x509`, `net/mail`, `net/http`, …) fixed only in go 1.25.2/1.25.3 — clearing them needs a build-toolchain bump (`Dockerfile golang:1.23`→`golang:1.25` + the `go` directive), a platform change to schedule on its own; (2) migrating off the unmaintained `thoj/go-ircevent` to `girc` is a full IRC-bot rewrite, its own effort.
- **Probe batch ingestion is now idempotent** (AUDIT-042, server v0.10.327 + collector v1.2.74): if a batch POST timed out after the server had already saved it, the collector's retry (up to 3 attempts) created duplicate rows — harmless for traps but double-counting downtime for pings. The collector now generates a stable `X-Probe-Batch-ID` per batch (random 128-bit hex, **reused across that batch's retries**) and sends it on every attempt; the server records `(probe_id, batch_id)` in a new `processed_batches` table and short-circuits any later request carrying a key it has already seen. The key is recorded **only after a successful (2xx) save** (via a deferred status check), so a transient DB failure can't dedupe-drop the legitimate retry of a batch that never persisted. Idempotency is opt-in by the header: requests without it are unaffected. Applied to the four queued-batch endpoints (`/syslog`, `/traps`, `/flows`, `/pings`); `processed_batches` is cleaned up at 2-day retention (the key only matters for the retry window). Server tests in `handlers_data_idempotency_audit042_test.go` (retry deduped, distinct batch saved, headerless always saved); collector tests in `relay_idempotency_audit042_test.go` (id uniqueness + stability across retries). Deferred: the direct-send endpoints (system-status/interface-stats/etc.) also retry but are out of this audit's scope (largely time-series or already UPSERT).
- **SSRF hardening: DNS-rebinding TOCTOU closed + block list widened** (AUDIT-020, v0.10.326): the pre-flight `isValidExternalIP` check resolved a hostname and validated the IPs, but the *actual* outbound dial re-resolved — an attacker (or confused-deputy) controlling DNS could return a public IP to the check and a private/loopback IP to the dial. New shared `internal/httputil/ssrf.go`: `IsBlockedIP` now also rejects **multicast, CGNAT `100.64.0.0/10` (RFC 6598), and `0.0.0.0/8` (RFC 1122)** — ranges the raw `net.IP` predicates miss — and fails closed on a nil IP. `SafeDialContext` resolves, validates **every** candidate IP, and dials the validated IP directly (pinned), so the address checked is the address connected to. The webhook `http.Client` in `internal/notifier` now uses `SafeDialContext` (cloning `DefaultTransport` to keep proxy/TLS/idle-pool defaults), closing the rebinding window on the one path that fetches an operator-supplied URL. The handlers' `isBlockedIP` delegates to the shared helper so all existing validation gates inherit the wider block list. Tests in `internal/httputil/ssrf_test.go`: the block-list table (incl. the new CGNAT/0.0.0.0/8/multicast cases and the `100.63.255.255` non-block boundary) and a pinned-dialer refusal test. Deferred: pinning the SMTP/SNMP/IRC dials (those targets are admin-configured, lower rebinding risk; SMTP's `smtp.SendMail` resolves internally and needs a larger refactor).
- **Probe registration-key rotation is now atomic** (AUDIT-085, v0.10.325): `RegenerateProbeKey` deleted the old key's `SystemSetting` *before* generating/writing the new key, and only **logged a warning** if the new setting failed to create. A failure mid-sequence could rotate the probe's `registration_key` but leave no matching registration setting, locking the probe out permanently. The handler now generates the new key first and wraps update-probe → delete-old-setting → create-new-setting in a single `gorm.Transaction`; any error rolls the whole rotation back and the probe keeps its existing, working key. Regression test `TestRegenerateProbeKey_Atomic_AUDIT085` pins the success contract (new key present in both the row and the response, old setting deleted, new setting created exactly once).

## [0.10.324] - 2026-06-04
### Fixed
- **Redacted SNMP community written back over the real secret broke device polling** (v0.10.324): a probe-monitored FortiGate silently stopped answering SNMP and flipped offline, while its same-subnet, same-firmware sibling kept working. Root cause was a **redacted-secret write-back** bug, entirely server-side: `GET /api/devices/:id` masks SNMP secrets as `********` (`httputil.RedactedMask`). The admin UI loads a device with that mask in the community field, and saving the device back resends `{"snmp_community":"********"}`. `UpdateDevice` (`handlers_devices.go`) encrypted-and-stored whatever came in **with no guard against the mask**, so editing a device (even just renaming it) overwrote its real SNMP community with `********`. The collector then fetched `********` from `GET /api/probes/:id/devices` (which serves the real, decrypted secret) and polled the firewall with it — the FortiGate silently drops an unknown community, so every request timed out (`community_len=8` in the collector logs is literally `len("********")`). Confirmed by direct SNMP test: the device answers a valid community instantly but times out on `********`, exactly mirroring the collector. Fix: the `UpdateDevice` write path now treats an incoming `snmp_community` / `snmpv3_auth_pass` / `snmpv3_priv_pass` / `ssh_password` equal to `RedactedMask` (or empty) as "unchanged" and drops it from the update, so the mask can never be persisted over a real secret. A shared `httputil.RedactedMask` constant now backs both the redactor and the guard so they can't drift. (The settings handler already had this guard; IRC doesn't use the mask; create-device takes fresh input — `UpdateDevice` was the only vulnerable path.) **Operational note:** this fix prevents recurrence but does not un-corrupt an already-clobbered record — any device whose community was overwritten with `********` must have its SNMP community re-entered (the value is unrecoverable from the masked DB row). 2 regression tests in `handlers_redacted_writeback_test.go`: a redacted save preserves the stored secret while applying the real edit, and a genuine new community still updates.

## [0.10.323] - 2026-06-04
### Fixed
- **Probe-assigned devices now raise DEVICE_OFFLINE alerts + recovery** (v0.10.323): probe-monitored devices flipped to `offline` in the UI but produced **zero alerts and zero emails** — a whole remote site could go dark for 15 minutes with no notification. Root cause: probe devices are polled by the remote collector, not the central poller, so they never flow through `updateDeviceStatus` (the only path that calls `CheckDeviceOffline` / `sendCriticalAlertEmail`). The stale-marker `MarkStaleProbeDevicesOffline` did a bare `UPDATE devices SET status='offline'` and returned only a row count, and recovery (`status='online'`) was written directly by the ingestion handler in the *API* process — which can't reach the alert manager (it lives in the *poller* process). Net effect: the entire `CheckDeviceOffline`/`CheckDeviceOnline` state machine was bypassed for probe devices. Fix: `MarkStaleProbeDevicesOffline` now returns the devices that transitioned `online → offline` (SELECT-then-UPDATE), and the poller fires `CheckDeviceOffline` + a critical email per transition — the same notifications directly-polled devices already get. Recovery is driven from the poller by calling `CheckDeviceOnline` on every probe device reporting fresh data each cycle; `sendRecovery` is a no-op unless an offline alert is actually active, so it clears exactly the alerted devices, exactly once. Deliberately fires **one** offline alert + email per offline episode (at the transition) rather than re-alerting every cycle like the directly-polled path — that path emails on every failed poll, which is its own latent spam issue we chose not to replicate. The alert dedup/cooldown and recovery state are in-memory in the poller (matching directly-polled behavior — they reset on poller restart). 2 regression tests in `probe_offline_alert_test.go`: the transition set excludes stale-but-already-offline, fresh, disabled, and non-probe devices and persists the flip; plus a no-transitions steady-state case.

## [0.10.322] - 2026-06-04
### Fixed
- **`/interface-addresses` ingestion 500s with SQLSTATE 42P10 on legacy deployments** (v0.10.322): `POST /api/probes/:id/interface-addresses` returned 500 on every probe poll — `ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)`. Root cause: AUDIT-030 (v0.10.x) made `SaveInterfaceAddresses` an `INSERT ... ON CONFLICT (device_id, ip_address)` UPSERT whose conflict target is the unique index `idx_ifaddr_dev_ip`. On any deployment that predated AUDIT-030, the table already held duplicate `(device_id, ip_address)` rows from the old plain-`Create` path, so GORM's `AutoMigrate` could **not** create the unique index (`CREATE UNIQUE INDEX` fails on duplicate values) — and `AutoMigrate` only logs that failure as a warning (`database.go:351`) and continues. The index stayed absent, so every subsequent UPSERT hit 42P10. The AUDIT-030 changelog had flagged the required dedup migration as "deferred"; it was never shipped. Fix: new idempotent `Database.ensureInterfaceAddrUniqueIndex()` runs right after the `AutoMigrate` loop — it no-ops when the index is present (every fresh install), and otherwise deduplicates the table (keeping the highest id, i.e. newest, row per pair — Postgres `DELETE ... USING` self-join, portable subquery on SQLite) before `CREATE UNIQUE INDEX IF NOT EXISTS idx_ifaddr_dev_ip`. After this runs the UPSERT path works again and the table self-heals on the next deploy/restart — no manual SQL required. Note: this endpoint does **not** drive online/offline status (that's `last_polled`, updated by the system-status / interface-stats handlers which were unaffected), but the probe's 3×-retry-with-2s-backoff on the 500 wasted ~4–6s per device per poll cycle. 2 regression tests in `ifaddr_indexrepair_test.go`: reconstruct the broken state (index dropped, duplicates inserted via raw SQL) → repair → assert the index is back, duplicates collapse to the newest row, and a follow-up UPSERT succeeds; plus an idempotent-no-op test for the fresh-install path.
- **CHANGELOG.md now strictly Keep-A-Changelog 1.1.0** (AUDIT-110): added a header that links to the Keep-A-Changelog and Semantic Versioning specs (so a future agent knows which version of the conventions to follow), and an `## [Unreleased]` section at the top with the standard sub-section placeholders (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`). The pre-fix file was free-form and not machine-readable; the post-fix file follows the spec to the letter.
- **`cmd/api/main.go` path-rewrite is now explicitly tagged with `AUDIT-138`** (AUDIT-138): the doc block for the `/api/v1/` → `/api/` and `/admin/api/v1/` → `/admin/api/` rewrites now states the fragility (hand-coded, not config-driven), the design constraints (the slice math is `p[len(prefix):]`, which is safe against `..` escapes), and the upgrade path (real versioning per AUDIT-090). Pre-fix the comment was a one-liner that didn't flag the design risk. The behavior is unchanged; only the documentation is more complete. `TestAPIVersioningRewrite_BehaviorPinned_AUDIT138` in `internal/shell/` pins the four invariants (both prefixes present, both rewrites use the safe slice form, mounted via `router.Use`, audit ID referenced in a comment) so a future refactor that drops the rewrite without addressing AUDIT-090 fails the test.
- **`cmd/api/static.go` doc block now references `AUDIT-139`** (AUDIT-139): the file's package-level comment now states that the `//go:embed static` ships JS unminified (213 KB for `admin-main.js`), names the audit's recommendation (esbuild → `cmd/api/static/js/dist/`), and points at the doc block as the migration's starting point. The behavior is unchanged; only the documentation is more complete. `TestStaticFilesEmbed_ReferencesStaticDir_AUDIT139` in `internal/shell/` pins four invariants (the directive exists, the declaration exists, the audit ID is referenced, the `static/` directory contains the expected `js/`, `css/`, `fonts/` sub-paths) so a future refactor that moves the embed without addressing the audit fails the test.
- **GORM log level is no longer hardcoded to `logger.Silent`** (AUDIT-149): new `internal/database/logging.go` with `dbLogLevelFromEnv()` reads `DB_LOG_LEVEL` (default `warn`, valid: `silent` / `error` / `warn` / `info`). The pre-fix `logger.Silent` swallowed slow-query warnings, errors, and migration warnings — operators had no visibility into slow queries or transient connection drops. New default `warn` logs slow queries and errors without flooding the log with every successful statement. Unknown values fall back to `warn` and log a notice (so a typo doesn't silently disable logging). 3 regression tests in `logging_audit149_test.go`: default-is-warn, all 4 valid values + case-insensitive + trim, unknown-falls-back-to-warn (silent would be the wrong fallback — that's the bug).
- **`fwmonLog` wrapper introduced in admin-common.js** (AUDIT-151): a single blessed path for log output from the admin JS, with four levels (`.debug` / `.info` / `.warn` / `.error`). Pre-fix the admin JS had 100+ bare `console.*` calls with no level control, no prod-silencing, and no structured output. The wrapper is the only blessed path; the existing 3 `console.*` calls in `admin-common.js` were migrated to `fwmonLog.*` in the same commit (the wrapper forwards to `console.*` for now, so no behavior change). The migration of the other 8 first-party admin JS files is deferred — `TestConsoleCalls_DeferringToFwmonLog_AUDIT151` pins the current count (≤ 100) as a soft regression gate, so a future commit that migrates more files brings the count down (the goal is 0) and a regression that adds new `console.*` calls fails the test. The wrapper's `.debug` is silent in production by default and can be enabled per-session via `localStorage.setItem('fwmonLog.debug', '1')` in the browser console.
- **Bulk-snooze by IDs and by filter** (AUDIT-143): new `Database.SnoozeAlertsBulk(ids, until, by, reason)` and `Database.SnoozeAlertsByFilter(filter, until, by, reason)` mirror the existing `AcknowledgeAlertsBulk` / `AcknowledgeAlertsByFilter` shape. Two new HTTP endpoints — `POST /admin/api/alerts/bulk-snooze` (IDs) and `POST /admin/api/alerts/bulk-snooze-filter` (filter via query params, hours+reason via body) — wrap the DB layer. Pre-fix an operator who wanted to snooze N alerts at once had to write a loop of single-alert `SnoozeAlert(id, ...)` calls (N round-trips, no atomicity). Post-fix, the bulk-snooze flow matches the bulk-ack flow shape for both endpoints. The same `maxBulkAckIDs = 500` cap and `[1, 720]` hour clamp from the single-alert handler apply. 3 regression tests in `snooze_audit143_test.go`: by-IDs (3 alerts, all snoozed with the audit fields populated), empty-IDs-is-noop, by-filter (3 high + 2 low on same device, only the 3 high are snoozed).
- **Auto-resnooze on alert resolution** (AUDIT-144): `internal/alerts/alerts.go:sendRecovery` now clears the snooze fields (`snoozed_until`, `snoozed_by`, `snoozed_reason`) on the matching alerts in the same UPDATE that sets `resolved_at`. Pre-fix a snoozed alert that was actually resolved would still appear in the "snoozed" view as if it were active — operators had to manually unsnooze every resolved-but-was-snoozed alert. Post-fix the recovery event does it for them. The WHERE clause is unchanged (`device_id AND alert_type AND resolved_at IS NULL AND acknowledged = false`) so the auto-unsnooze is scoped to the same set the recovery already touches; already-resolved or acked alerts are unaffected. 2 regression tests in `autoresnooze_audit144_test.go`: headline (2 unresolved-snoozed alerts, recovery sets `resolved_at` AND clears all 3 snooze fields), defensive sibling (3 rows that should NOT be touched — already-resolved, acknowledged, different alert_type — verify RowsAffected is 0 and snooze fields are intact).
- **`EnsurePartitions` skip-message now uses a `WARNING: AUDIT-146` prefix** (AUDIT-146): pre-fix the partition-skip log was a per-table `log.Printf` with no prefix, easy to miss in startup noise. Post-fix the message starts with `WARNING: AUDIT-146` (grep-able) and explicitly notes that without monthly partitions the table will grow unbounded and the AUDIT-029 cleanup cron will eventually run full-table DELETE statements that take minutes. `TestEnsurePartitions_SurfacesWarning_AUDIT146` in `internal/shell/` pins the `WARNING: AUDIT-146` prefix and the `docs/partition-migration.md` pointer so a future agent who copy-pastes a pre-fix-style log line fails the test. Deferred: actual partition-migration.md document (currently the log points at a file that doesn't exist; the migration is a separate, larger project).
- **`formatDate` / `formatDateShort` are now locale-aware** (AUDIT-128): the hardcoded `'en-US'` first arg to `toLocaleString` is gone. New `getBrowserLocale()` helper reads `navigator.language` (falling back to `'en-US'`) and both date-formatting functions use it. Pre-fix the admin UI displayed US-format dates (MM/DD/YYYY, 12-hour AM/PM) to every operator regardless of locale. Post-fix an operator with `navigator.language = 'de-DE'` sees `DD.MM.YYYY, 14:23:45`, an operator with `'fr-FR'` sees `DD/MM/YYYY 14:23:45`, and an operator with `'en-US'` (or no language set) sees the original MM/DD/YYYY. The format *order* changes; the field set (year, month, day, hour, minute, second) is preserved. `TestFormatDate_LocaleAware_AUDIT128` in `internal/shell/` pins the four invariants (hardcoded `'en-US'` argument is gone, helper exists, helper is wired in, audit ID is referenced).
- **`IsGeneratedPassword` no longer re-queries the env** (AUDIT-136): new `Auth.AdminPasswordGenerated` field on `Config`, populated once at config-load time via `os.LookupEnv`. The `IsGeneratedPassword()` method now reads the field (not the env). Pre-fix this re-queried `os.LookupEnv("ADMIN_PASSWORD")` on every call — a TOCTOU risk (the env could change between config-load and a later call) and duplicated work. The fix uses `LookupEnv` (not `Getenv == ""`) so an operator who explicitly sets `ADMIN_PASSWORD=""` is treated as "I want an empty password" (not "the env is unset, auto-generate") — that's the distinction the audit was about. 3 regression subtests in `config_audit136_test.go`: unset (returns true), set (returns false even with empty string), TOCTOU (post-load env mutation doesn't change the bool).
- **`probes.html` modals no longer render on first paint** (AUDIT-046): the inline rule `.modal:not(.hidden) { display: flex; }` was replaced with `.modal.active { display: flex; }`. Neither `#probe-modal` nor `#deploy-modal` ever carries a `.hidden` class — `AdminCommon.openModal()` toggles `.active` (the admin-shared.css convention) — so the old rule (specificity 0,2,0) beat the base `.modal { display: none }` and forced both modals visible on first paint; the bug was dormant only because the operator immediately closes them. Post-fix the modals stay hidden until `.active` is added. `TestProbesModal_UsesActiveClass_AUDIT046` in `internal/shell/` pins that the `:not(.hidden)` form is gone, the `.active` form is present, and the audit ID is referenced.
- **Logout link is no longer dead on `/admin/irc`** (AUDIT-047): the delegated-click `switch` in `cmd/api/static/js/admin-irc.js` had no `case 'logout'`, so the sidebar Logout link (`data-action="logout"`) navigated to `#` and stayed on the page — every other admin page handles it. Added `case 'logout': AdminCommon.doLogout(); return;`. This file uses the full `AdminCommon` reference (no `AC` alias is defined here), unlike the other admin JS files. `TestIRCLogout_HasLogoutCase_AUDIT047` in `internal/shell/` pins the case, the `AdminCommon.doLogout` reference, and the audit ID.
- **`.section-tab` hidden-state now actually hides on connection-detail** (AUDIT-048): connection-detail.html's inline `.section-tab { display: inline-block }` loads after `admin-shared.css`, so (equal 0,1,0 specificity, later cascade) it beat the `.hidden { display: none }` that `admin-connection-detail.js` toggles on `#tab-phase2` / `#tab-flows`. The v0.10.230 `classList.toggle('hidden', ...)` fix produced zero visual change as a result. Added `.section-tab.hidden { display: none !important; }` to the same inline `<style>` block (higher specificity + `!important`). `TestSectionTab_HiddenOverride_AUDIT048` in `internal/shell/` pins the rule and the audit ID.
- **IRC tab nav active-state now updates visually** (AUDIT-049): no `.tab-btn.active` CSS rule existed, so `switchTab()`'s `classList.add('active')` had no visual effect — the active highlight was hardcoded as Tailwind utilities (`text-[#58a6ff]`, `border-[#58a6ff]`) on the Servers button and never moved when another tab was clicked. Added `.tab-btn.active { color:#58a6ff; border-bottom-color:#58a6ff; }` to the inline `<style>` and normalized the Servers button to the same class list as the other tabs (only the `active` class differs). The rule's 0,2,0 specificity cleanly beats the inactive `text-[#8b949e]` / `border-transparent` utilities for whichever tab is active. `TestIRCTab_ActiveRuleExists_AUDIT049` in `internal/shell/` pins the rule, the removal of the hardcoded `border-[#58a6ff]`, and the audit ID.
- **`admin-irc.js` is now IIFE-wrapped** (AUDIT-050): the file declared `let servers/channels/commands` and every function at the top level, leaking them all onto `window` — inconsistent with every other admin-*.js file and the lessons.md "Blank Admin Pages" guidance. Wrapped the whole file in `(function () { 'use strict'; ... })();` and converted the three top-level declarations to `var`. The body diff is intentionally minimal (no re-indent) to keep the scope-fix reviewable; full ES6→ES5 conversion of the function bodies is tracked separately as AUDIT-131. Verified the page still loads (all handlers are data-action delegated; irc.html has zero inline `onclick`, so nothing depended on the leaked globals). `TestIRCIife_Wrapped_AUDIT050` in `internal/shell/` pins the IIFE open/close, strict mode, the `var` conversion, and the audit ID.
- **`probes.html` Reject no longer uses native `window.prompt()`** (AUDIT-051): the reject action in `admin-probes.js` called `prompt('Enter rejection reason:')`, inconsistent with the styled reject modal already on `/admin/probe-pending` (lessons.md notes AdminCommon modals are the standard). Added a `#reject-modal` to probes.html (matching the page's existing modal styling, with a labelled textarea) and routed rejection through `AC.openModal` + a `#reject-form` submit handler (`submitReject`), with `close-reject-modal` wired into the existing event delegation. `TestProbesReject_UsesModal_AUDIT051` in `internal/shell/` pins that the `prompt()` call is gone, the modal-based path exists in the JS, and the modal markup exists in the HTML.
- **Public dashboard libraries now load with `defer`** (AUDIT-052): `web/public/index.html` loaded `chart.umd.min.js`, `chartjs-plugin-zoom.min.js` and `gridstack-all.min.js` (~290 KB) without `defer`, blocking HTML parsing and first paint on the public wallboard — the page where time-to-render matters most. Added `defer` to all three. `defer` scripts execute in document order, so `public-dashboard.js` (already `defer`, declared after them) still initializes only after the libs are present. `TestPublicDashboard_LibsDeferred_AUDIT052` in `internal/shell/` pins each lib's `defer` and the audit marker.
- **Inline `onclick` removed from `admin-device-detail.js`** (AUDIT-053): the config-history row buttons (View / Download / Delete) and the two config-modal close buttons were built with inline `onclick="..."` attributes — they worked only because the CSP still allows `script-src 'unsafe-inline'`, and they blocked any future CSP tightening. Converted all five to `data-action` + `data-id`, handled by the file's existing `AC.delegateEvent` block (new `view-config-revision` / `download-config-revision` / `delete-config-revision` / `close-config-modal` cases). The file now has zero inline event attributes. `TestDeviceDetail_NoInlineOnclick_AUDIT053` in `internal/shell/` pins the absence of `onclick=` and the presence of the delegated handlers.
- **Inline `.modal` display rules de-duplicated** (AUDIT-054): the `.modal { display:none }` / `.modal.active { display:flex }` rules (and, in admin.html, the byte-identical `.modal-header` / `.modal-close` / `.modal-footer`) were duplicated inline in `admin.html`, `sites.html` and `probes.html`, all redundant with `admin-shared.css:506-573`. Removed the inline duplicates so admin-shared.css is the single source of truth. admin.html keeps only its genuinely-different `.modal-content` override (a narrower 92vw/85vh vs the shared 95vw/90vh — preserved to avoid any visual change). probes.html's inline `.modal.active` (normalized in AUDIT-046) is now gone too; the AUDIT-046 regression test was updated to pin the enduring invariant (no `:not(.hidden)` rule, canonical `.modal.active` in admin-shared.css). `TestModalDedup_SingleSource_AUDIT054` in `internal/shell/` pins the removal across all three pages and the canonical rule's presence.
- **Mobile sidebar chrome now on every admin page** (AUDIT-055): only `admin.html` had the mobile header / hamburger button / slide-in sidebar + overlay, and it was inline (CSS + markup + a one-off `<script>`). Every other admin page (irc, sites, probes, probe-pending, connection-detail, device-detail) rendered a fixed 240px sidebar covering half a 375px viewport with no way to collapse it. Moved the chrome CSS into a shared "Mobile chrome" section in `admin-shared.css` (covering both `.main` and `.main-content`), added `AdminCommon.renderMobileChrome()` (injects the header + overlay before the `.sidebar`, wires an idempotent open/close toggle that also keeps `aria-expanded` in sync), and call it after `renderSidebar()` on all seven pages. admin.html's inline CSS/markup/script were removed in favour of the shared path (its page-specific `.stat-grid` / `.chart-row` / `.page-header` mobile rules stay). `TestMobileChrome_OnAllPages_AUDIT055` in `internal/shell/` pins the method, the shared CSS, and the call on every page.
- **Sidebar nav is now screen-reader friendly** (AUDIT-057): the JS-rendered sidebar (`admin-common.js` `renderSidebar`) marked the active item with only a `.active` class — no `aria-current="page"` — and the nav icons (Unicode glyphs) had no `aria-hidden="true"`, so assistive tech couldn't identify the current page and read out each icon's glyph name before the label. Added `aria-current="page"` to the active link and `aria-hidden="true"` to every `<span class="nav-icon">` (16 links). `TestSidebarAria_AUDIT057` in `internal/shell/` pins both attributes and that no bare nav-icon span remains.
- **`apiFetch` 401 redirect no longer breaks inside iframes** (AUDIT-058): the 401/302 handler did `window.location.href = '/admin/login'`. When the failing request originated in the Reports preview iframe, it navigated the *iframe* to /login — rendering the login page inside the report frame. Changed to `(window.top || window).location.href = '/admin/login'` so the whole tab redirects. `TestApiFetch401_TopFrame_AUDIT058` in `internal/shell/` pins the top-frame redirect.
- **`escapeHtml` no longer blanks numeric 0** (AUDIT-059): both `admin-common.js` and `admin-irc.js` guarded `escapeHtml` with `if (!str)` / `if (!text)`, which short-circuits on every falsy value — `0`, `false`, `''` — returning `''`. A field whose value was numeric `0` (e.g. "0 bytes in") rendered blank. Changed to a nullish-only guard (`== null`), so only `null`/`undefined` short-circuit. `TestEscapeHtml_NullishGuard_AUDIT059` in `internal/shell/` pins the nullish guard in both files and that the falsy guard is gone.
- **`@media print` rule added; `.no-print` is no longer dead** (AUDIT-060): there was no print stylesheet, so Ctrl+P on an admin page printed the sidebar, mobile header, toasts, and every element tagged `.no-print` (the class had no effect). Added a `@media print` block to `admin-shared.css` that hides `.sidebar`, `.mobile-header`, `.sidebar-overlay`, `.toast-container`, and `.no-print`, and zeroes the `.main`/`.main-content` left margin so the content uses the full page width. `TestPrintCss_AUDIT060` in `internal/shell/` pins the rule and the covered selectors.
- **Per-tab Chart.js instances are destroyed on tab leave** (AUDIT-061): `proc-ssh-chart` and `iface-err-chart` in `admin-device-detail.js` were created at init and held their canvas contexts for the whole page session even while their tab was hidden. `switchTab` now destroys each chart and nulls its reference when leaving its tab (`processes-ssh` / `iface-err`), and recreates it from the current range/interface control values on re-entry — `loadProcessMonitorData` / `loadInterfaceErrorsData` already destroy any prior instance, and the change-listeners are wired once at init, so nothing leaks. `TestChartTeardown_AUDIT061` in `internal/shell/` pins the teardown.
- **`admin-irc.js` `showAlert` uses a CSS class and clears its timer** (AUDIT-062): it toggled inline `style.display` and scheduled a fresh 5s `setTimeout` on every call without clearing the previous one, so back-to-back alerts hid each other prematurely. Now it toggles the shared `.hidden` class (setting `className` to `error`/`success` drops `.hidden` to show; a tracked module-level `alertTimer` is `clearTimeout`-ed before each new one). The `#alertMessage` div in irc.html starts with `class="hidden"`. `TestIRCShowAlert_AUDIT062` in `internal/shell/` pins the timer-clear, the class-based hide, and that inline `style.display` is gone.
- **Public dashboard "Reset Layout" now asks for confirmation** (AUDIT-063): the button wiped the operator's saved widget arrangement (`localStorage`) on a single click, so one misclick destroyed a carefully-tuned wallboard. Added a `confirm()` guard at the top of `resetLayout()`. The audit suggested `AdminCommon.confirm`, but that would require loading `admin-common.js` (~36 KB) plus its `/admin/api` load-time fetch onto the public wallboard — partly undoing the AUDIT-052 first-paint optimization on a page that's often an unattended TV — so a native `confirm()` is used deliberately. `TestResetConfirm_AUDIT063` in `internal/shell/` pins that the confirm runs before the layout is cleared.
- **`conn.status` escaped before innerHTML on connection-detail** (AUDIT-065): `admin-connection-detail.js` concatenated the raw `conn.status` into `statusEl.innerHTML` (both the badge class and the text). The server validates the status to an enum, so this was a defense-in-depth gap, not a live XSS — now closed with `AC.escapeHtml` (uppercase first, then escape, so an entity can't be split by `toUpperCase()`). `TestConnStatusEscape_AUDIT065` in `internal/shell/` pins the escaped path and the removal of the raw concatenation.
- **Probes summary stats no longer an N+1** (AUDIT-064): the probes page issued one `GET /probes/:id/stats` per approved probe (20 probes = 20 sequential requests, each running ~100 count queries including a 24-hour breakdown the summary never used). Added `GET /admin/api/probes/stats?ids=1,2,3` (`GetProbesStatsBatch`) that returns total + last-hour counts for all requested probes in a fixed **8 grouped queries** (`COUNT(*) ... WHERE probe_id IN (...) GROUP BY probe_id`, four tables × {total, last-hour}) regardless of probe count, and omits the unused hourly breakdown. `admin-probes.js` now makes a single batched call. The new route is a static sibling of `/api/probes/:id` (like the existing `/api/probes/pending`). Tests: `TestGetProbesStatsBatch_AUDIT064` + `TestGetProbesStatsBatch_EmptyIDs_AUDIT064` (handler, real DB — totals, last-hour window, unrequested-probe exclusion, empty-ids) and `TestProbesBatchStats_FrontendUsesBatch_AUDIT064` (pins the JS uses the batch endpoint, not the per-probe loop).
- **Form labels now associate with their inputs** (AUDIT-056): admin form `<label>` elements lacked `for=""`, so screen readers couldn't pair a label with its control (only `login.html` did it right). Swept `web/admin/{probes,sites,irc,probe-pending,admin}.html` and added `for="<input id>"` to **88 labels** — every non-wrapping label whose adjacent `<input>`/`<select>`/`<textarea>` has an id. Labels that wrap their control (implicit association) and section-header labels were left alone; a handful of public-settings inputs that have no `id` (only `name`) were skipped rather than guessed. The transform is in `scripts/audit056_labels.py` (committed for provenance). `TestLabelFor_AUDIT056` in `internal/shell/` pins the integrity invariant — every `<label for="X">` resolves to an `id="X"` in the same file — plus a per-page minimum count so a future edit can't silently strip them.

## [0.10.320] - 2026-06-04
### Fixed
- **Reverted the AUDIT-066/067 color sweep** (v0.10.320): the WCAG contrast sweep lifted every faint/dim gray text color to a single `#8b949e`, which collapsed the admin UI's intentional three-tier text hierarchy (`#484f58` faint → `#6e7681` dim → `#8b949e`) into one flat tone and made the dense operator UI look significantly worse in production. Restored the original palette in every rendering stylesheet (`admin-shared.css`, `admin-design-system.css` `--fwmon-text-faint` token, `tailwind.css`, `styles.css`) and reverted the color edits in the JS/HTML (surgically in `admin.html` / `device-detail.html` so the AUDIT-068/069 fixes there are kept). The two `colorcontrast_*_audit06{6,7}_test.go` guards were removed with the revert. AUDIT-066/067 are reopened; if redone, the fix must be surgical (only the specific small-text-on-dark cases that genuinely fail, with distinct brighter-but-still-hierarchical values) rather than flattening the whole palette. The `scripts/audit_brighten_color.py` helper is kept for that future, more careful pass.
- **Device-detail stat grids no longer overflow on mobile** (AUDIT-068): the `#systemStats` and `#extendedStats` auto-fit grids (`minmax(180–200px, 1fr)`) could push past a narrow viewport — or a long firmware/value string could make a card wider than the screen — with no horizontal scroll. Made both grids `overflow-x-auto` scroll containers. (All seven data tables on the page were already wrapped in `overflow-x-auto`; the audit's "15-column processes table" does not exist — that tab renders a chart, not a table.) `TestDeviceDetailOverflow_AUDIT068` in `internal/shell/` pins that both stat grids are scroll containers.
- **Static modals carry their ARIA attributes in markup** (AUDIT-069): the static modals relied on `admin-common.js` `tagStaticModals()` to add `role="dialog"`, `aria-modal="true"` and `aria-labelledby` at runtime — so they weren't exposed to assistive tech until JS ran. Baked those attributes into the markup of the 10 modals in `admin.html` (9) and `device-detail.html` (1), injecting a `id="<modal>-title"` on the five headings that lacked one (the same convention `tagStaticModals` uses, which remains as an idempotent safety net and still covers modals on the other pages). `scripts/audit069_modal_aria.py` performs the transform. `TestModalAria_AUDIT069` in `internal/shell/` pins that every `<div class="modal" id=…>` has the three attributes and that each `aria-labelledby` resolves to a real id.

## [0.10.302] - 2026-06-03
### Fixed
- **Mobile menu button `aria-expanded` stays in sync** (AUDIT-070): the old inline `admin.html` hamburger toggle only flipped the `.open` classes and never updated `aria-expanded`, so screen-reader users couldn't tell whether the nav was open. This was already resolved when AUDIT-055 (v0.10.302) centralized the hamburger + its toggle into `AdminCommon.renderMobileChrome()`, whose open/close handler sets `aria-expanded` to `true`/`false`; the button is also created with `aria-expanded="false"`. This commit adds the explicit `AUDIT-070` reference and `TestAriaExpanded_AUDIT070` in `internal/shell/` pinning the initial value and the in-sync update so a future refactor can't regress it.
- **Indexes on `flow_samples.src_addr` / `dst_addr`** (AUDIT-034): `GetConnectionFlowStats` filters flows with `src_addr LIKE ? OR dst_addr LIKE ?` (where `cidrToLikePattern` builds `192.168.1.%`-style prefixes), but neither column was indexed — so every connection-stats click full-scanned `flow_samples`, the largest table on a busy collector. Added `idx_flow_src_addr` and `idx_flow_dst_addr` via gorm struct tags (created by AutoMigrate, the existing index convention here). A prefix `LIKE 'x%'` is sargable on a btree, so these help on both Postgres and SQLite. `TestFlowSampleIndexes_AUDIT034` in `internal/database/` verifies both indexes exist after migration.
- **`GetLatestVPNStatuses` peer fetch is no longer an N+1** (AUDIT-035): the per-peer subnet cross-fill ran one `WHERE device_id = ? ORDER BY timestamp DESC` query for *each* peer device (a device with 30 peers = 30 scans of `vpn_status` per connection-map click). Replaced the loop with a single `WHERE device_id IN (...) AND (local_subnet != '' OR remote_subnet != '')` query covering all peers, with the subnet filter pushed into SQL (so it also fetches fewer rows than before). `ORDER BY device_id, timestamp DESC` reproduces the original per-peer / newest-first processing order, so the cross-fill result is unchanged — and more deterministic, since the old loop iterated a Go map in random order. Chosen over the audit's suggested Postgres `ROW_NUMBER()` window because the single `IN` query resolves the N+1 with identical, cross-dialect, fully-testable semantics (a Postgres window to further cap rows at latest-per-tunnel is a possible future enhancement). `TestGetLatestVPNStatuses_PeerCrossFill_AUDIT035` in `internal/database/` proves the peer subnet + `RemoteDeviceID` cross-fill still works end to end through the new query.
- **`getDefaultPassword` no longer caches in a module-level variable** (AUDIT-158): the pre-fix implementation had a `var defaultPassword string` cache that lingered in GC until the next collection, could surface in core dumps after the caller zeroed `cfg.Auth.AdminPassword`, and was a single global variable any test or code path could read. Post-fix the function returns a freshly-generated password every call. The `defer func() { defaultPassword = "" }()` in `Load()` is removed (it was zeroing the wrong thing — the string had already been copied into `cfg.Auth.AdminPassword` and the bcrypt hash, so the post-Load lifecycle sees copies the defer can't reach). 2 regression tests in `config_audit158_test.go`: behavioral (two consecutive calls produce different passwords, length = 16, charset matches) and concurrent (10 goroutines all get different passwords, ruling out a `sync.Once`-style re-introduction).

### Security
- nothing yet


## [0.10.281] - 2026-06-02

### Wontfix — AUDIT-154, AUDIT-155, AUDIT-156: audit was wrong, the helpers are used

The audit flagged `httputil.ParseHours`, `httputil.FilterAllowedFields`, and the `validVendors` map (via `isValidVendor`) as "unused" / "dead code". All three claims are factually wrong. The audit appears to have been a quick grep that missed call sites in other files.

**The actual usage** (verified by `git grep` in the regression tests):

- **`httputil.ParseHours`** is called in 7 places: `handlers_analytics.go:294,332,350,368` and `handlers_connections.go:60,331` (plus one in the comment for the migration story at `:59`). Used by every analytics endpoint and the connections-history endpoint.
- **`httputil.FilterAllowedFields`** is called in `handlers_connections.go:193` (and any future handler that does partial-update on a PATCH endpoint).
- **`validVendors` / `isValidVendor`** are called in `handlers_devices.go:69` (the device create handler validates the vendor on every request) and `:207` (the device update handler does the same on partial updates).

**The fix**

1. **No code change** — the helpers are correct, used, and shouldn't be removed.
2. **Three regression tests** in `internal/shell/deadhelpers_audit154_155_156_test.go` that pin the call sites via `git grep`. Each test counts the number of distinct files using the symbol (excluding the definition site). A future refactor that genuinely orphans any of the three would drop the count below the threshold and fail the test, alerting the next agent that the function should be removed (and the test updated) — or that the call sites should be re-wired.
3. **Audit doc updated** to `[!] wontfix` for all three, with the same explanation as this CHANGELOG entry, so the next audit pass doesn't re-flag them.

**The "wrong audit" pattern is worth pausing on**

The original audit's claim that these are "unused" is a class of bug that's easy to fall into when reviewing a large codebase quickly. The right verification is `git grep -n <symbol>`, which gives a complete list of call sites (modulo `.gitignore`, which is what we want). A future audit that flags "this function isn't used" should cite the `git grep` output as evidence; the test now enforces that.

**Regression tests** (`internal/shell/deadhelpers_audit154_155_156_test.go`, new — 3 tests):

- `TestParseHours_IsUsed_AUDIT154` — uses `git grep` to count distinct files calling `ParseHours(` (excluding the definition). Threshold: ≥ 2. Currently: 2.
- `TestFilterAllowedFields_IsUsed_AUDIT155` — same pattern. Threshold: ≥ 1. Currently: 1.
- `TestIsValidVendor_IsUsed_AUDIT156` — same pattern. Threshold: ≥ 1. Currently: 1.

Each test's failure message points the next agent at the audit doc's `[!] wontfix` entry, so a future refactor that genuinely orphans the function gets the full context (audit + explanation + correct action).

**What this does NOT do (deferred)**

- **Remove the `validVendors` map for the truly-unused vendors.** The map has 8 entries; the codebase supports 8 vendors via the `vendor` field. The map is the authoritative "which vendors do we support" list. Removing entries that are "currently not used" would break the partial-update path's vendor validation. Not a fix to do.
- **Centralize vendor validation in `internal/`.** A future refactor could move `validVendors` and `isValidVendor` to `internal/vendors/` for reuse from the probe binary. Out of scope for AUDIT-156 (the audit was wrong; the code is correct as-is).
- **Audit the rest of `internal/httputil/` for the same "wrong-audit" pattern.** The audit's claim about `ParseHours` and `FilterAllowedFields` was wrong; the rest of the package is also probably fine. A future broader sweep would systematically `git grep` every exported symbol. Out of scope for this commit.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 228 tests, +3 wontfix tests), `gofmt -l .`, `go vet ./...` all clean. Test-only change. No code path affected. Static-binary change not required.

## [0.10.280] - 2026-06-02

### Fixed — AUDIT-037: per-connection statement_timeout enforced server-side (default 30s)

`NewDatabase` opened a Postgres pool with no per-connection statement timeout. A single slow query (an accidental full-table scan, a misbehaving chart endpoint, a lock wait) could hold a connection for tens of seconds, blocking other handlers from getting one and eventually exhausting the pool.

**The fix** (two parts):

1. **`internal/config/config.go`** — new `DatabaseConfig.StatementTimeout time.Duration` field (default 30s, from `DB_STATEMENT_TIMEOUT` env var). 0 = disabled (documented escape hatch for migrations that need to run large DDL).

2. **`internal/database/database.go`** — when `StatementTimeout > 0`, the DSN is suffixed with `options='-c statement_timeout=NNNms'` so the timeout is enforced by the Postgres server for every connection the pool opens. Server-side enforcement survives application code that forgets to set a `context.WithTimeout` (the AUDIT-032 `WithContext(c.Request.Context())` rollout covers the in-application side; this is the backstop).

**Wire format / migration**

- No schema change. No API change. Existing deployments upgrade without any action; the new 30s default applies on the next connection.
- Operators who set `DB_STATEMENT_TIMEOUT=0` get a pool with no statement timeout. The CHANGELOG and `config.env.example` both note "not recommended for production" — useful for one-shot migrations that need a long DDL window.

**Regression tests** (`internal/database/statementtimeout_audit037_test.go`, new — 3 tests):

- `TestNewDatabaseStatementTimeout_Default30s_AUDIT037` — pins the DSN-construction behavior: 30s config → DSN contains `options=...statement_timeout=30000ms...`. (The test replicates the DSN-formatting code in isolation rather than calling `NewDatabase` directly, because `NewDatabase` opens a real Postgres connection and the package's tests run against sqlite. A future refactor that changes the DSN format fails here loudly.)
- `TestNewDatabaseStatementTimeout_DisabledWhenZero_AUDIT037` — `StatementTimeout=0` must NOT carry the `options=` clause. The 0-means-disabled semantic is documented and tested; a future "0 means default" change would fail this test.
- `TestNewDatabaseStatementTimeout_CustomDuration_AUDIT037` — the value flows through end-to-end: 5s → 5000ms. Catches a future refactor that drops the `.Milliseconds()` conversion.

**What this does NOT do (deferred)**

- **`WithContext(c.Request.Context())` rollout on every chart query** (AUDIT-032). The two are complementary: `WithContext` cancels a query when the HTTP client disconnects (a browser tab close); `statement_timeout` cancels a query after a fixed wall-clock deadline regardless of client state. The audit doc said "covered by AUDIT-032", so we don't double up here.
- **Per-query deadline differentiation** (e.g. 5s for chart endpoints, 30s for admin endpoints, 5min for cleanup). The single-knob design is the right starting point; per-route tuning is a future enhancement.
- **Statement timeout for SQLite.** SQLite's `?mode=ro` + busy_timeout are different knobs. The audit was Postgres-specific. SQLite is the test backend only; production uses Postgres.
- **Per-transaction vs per-statement timeout.** `statement_timeout` is per-statement; `idle_in_transaction_session_timeout` is a different knob for a different problem (a connection that holds a transaction open without running queries). Out of scope for AUDIT-037.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 225 tests, +3 AUDIT-037), `gofmt -l .`, `go vet ./...` all clean. Code + config + test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.279] - 2026-06-02

### Fixed — AUDIT-031: stale unacked alerts are now auto-archived with a warning log

`CleanupOldData` only deleted acked alerts (`WHERE acknowledged = true AND timestamp < ?`). A critical device that paged off-hours and went unacked accumulated alert rows forever — the table grew unbounded on any deployment where an alert could go unacked for more than a few days. With on-call rotation gaps, sleep, and on-shift attention all being realistic reasons for a >24h unack window, "unacked alerts accumulate" is the production default, not the exception.

**The fix** (three parts):

1. **`internal/config/config.go`** — new `RetentionConfig.UnackAlertDays int` field (default 90, from `RETENTION_UNACK_ALERT_DAYS` env var). 90 days is intentionally longer than the 30-day acked default: an operator who is on vacation shouldn't come back to find that an unacked alert from their first week off has been auto-archived. After 90 days the alert is unlikely to be actionable (the device has either recovered, been replaced, or the condition has escalated to a separate alert that has itself been handled).

2. **`internal/database/database.go`** — `CleanupOldData` now has two cleanup windows:
   - **Acked alerts**: deleted after `AlertDays` (default 30, `RETENTION_ALERT_DAYS`). The pre-fix behavior, unchanged.
   - **Unacked alerts**: deleted after `UnackAlertDays` (default 90, `RETENTION_UNACK_ALERT_DAYS`). The fix. Each auto-archived alert fires a `WARNING` log so the operator can reconstruct the "stale unack" event from the logs (the "what got archived" trail is the soft-fail signal that something needs investigating).

   The unack window is **clamped to be at least as long as the acked window** — if an operator sets `RETENTION_UNACK_ALERT_DAYS=10 RETENTION_ALERT_DAYS=30`, the unack cutoff is pinned to the 30-day acked cutoff. Auto-archiving unacked alerts before they're old enough to have been acked would be a backwards default; the clamp prevents it.

3. **`config.env.example`** — new `RETENTION_UNACK_ALERT_DAYS=90` documented.

**Wire format / migration**

- No schema change. No API change. Existing deployments upgrade without any action; the new retention window is read from the env var (default 90 days) and applied on the next cleanup tick.
- The 90-day default is a behavior change for existing deployments: alerts that have been unacked for more than 90 days are now auto-archived (with a WARNING log) on the next cleanup tick. Operators who want to keep all unacked alerts indefinitely can set `RETENTION_UNACK_ALERT_DAYS=0 RETENTION_DEFAULT_DAYS=99999` (the unack cutoff falls back to the default, which is the operator's choice).

**Regression tests** (`internal/database/cleanup_audit031_test.go`, new — 4 tests):

- `TestCleanupOldData_UnackedAlertsEventuallyArchived_AUDIT031` — headline: seeds three alerts (old acked, old unacked, recent unacked), runs cleanup, asserts the recent unacked row is the only survivor. The pre-fix behavior (unacked rows kept forever) would have left the old-unacked row in the table.
- `TestCleanupOldData_UnackRetentionLongerThanAck_AUDIT031` — defensive sibling: a 20-day-old unacked alert survives when `AlertDays=30 UnackAlertDays=10` (the unack cutoff is clamped to the acked cutoff). The clamp prevents a future env-var misconfiguration from accidentally auto-archiving unacked alerts before the operator has had a chance to ack them.
- `TestCleanupOldData_StaleUnackWarningLogged_AUDIT031` — pins the bulk-delete behavior: 5 stale unack alerts → 0 survivors.
- `TestCleanupOldData_RecentUnackSurvives_AUDIT031` — boundary test: a 5-day-old unacked alert is NOT archived by a 90-day default. Pins both "doesn't archive" and "doesn't silently flip to acked=true".

**What this does NOT do (deferred)**

- **Move unacked alerts to an `alerts_archive` table** (the audit's option b). A separate table would preserve the alert content for forensics; the current hard-delete is simpler but loses data. Out of scope for AUDIT-031 (the audit was about ending unbounded growth, not adding a new table). A future enhancement could materialize the WARNING log into a `alerts_archive` row instead of just logging it.
- **Operator-visible stale-unack notification.** The WARNING log is the current signal. A future commit could fire a synthetic "your alert was auto-archived" email/webhook so the operator learns about the silent ack within their existing on-call workflow. Out of scope for AUDIT-031.
- **Per-severity retention.** A `critical` unacked alert might warrant a longer retention than a `warning` one. The current code treats all unacked alerts the same. A future enhancement could read `severity` and apply a multiplier. Out of scope for AUDIT-031.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 222 tests, +4 AUDIT-031), `gofmt -l .`, `go vet ./...` all clean. Code + config + test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.278] - 2026-06-02

### Fixed — AUDIT-030: interface_addresses UPSERTs on (device_id, ip_address) instead of appending

`SaveInterfaceAddresses` was a plain `Create` that appended a row on every probe poll, even when the `(device_id, ip_address)` pair was unchanged. With 50 devices × 4 polls/min × 90 days the table grew to ~25M rows of mostly-redundant data — the table's growth rate was unbounded and would OOM the DB on a long-running deployment.

**The fix** (two parts):

1. **`internal/models/models.go`** — added `uniqueIndex:idx_ifaddr_dev_ip` to the `DeviceID` and `IPAddress` fields on `InterfaceAddress`. The unique index is the conflict target for the UPSERT. A pre-existing deployment with duplicate rows would fail the AutoMigrate; the cleanest migration is a one-shot dedup query (see deferred).

2. **`internal/database/database.go`** — `SaveInterfaceAddresses` now uses GORM's `clause.OnConflict` to emit `INSERT ... ON CONFLICT (device_id, ip_address) DO UPDATE SET timestamp, if_index, net_mask = EXCLUDED.*` on Postgres (and the equivalent UPSERT syntax on SQLite). The `id` field is left to GORM's insert-vs-update machinery.

**Wire format / migration**

- `interface_addresses` table gains a unique index on `(device_id, ip_address)`. Existing rows with duplicate `(device, ip)` pairs would cause the AutoMigrate to fail on first boot.
- **Migration for existing deployments**: a one-shot `DELETE FROM interface_addresses WHERE id NOT IN (SELECT MIN(id) FROM interface_addresses GROUP BY device_id, ip_address)` deduplicates the table, after which the unique index can be created. (The `MIN(id)` keeps the earliest row, but you may prefer to keep the latest with a `MAX(id)` query — depends on which timestamp you want to preserve.) Documented in the deferred section; not part of this commit.
- The new unique index is a composite (two-column), so it doesn't slow the existing single-column index on `ip_address` (which is used for the IP-lookup path).

**Behavioral change**

- Pre-fix: a row existed per `(device, interface, IP, timestamp)`. A device that had the same IP on three interfaces would produce three rows that all aged out independently.
- Post-fix: a row exists per `(device, IP)`. The `if_index` and `net_mask` are updated in place to the latest values from the most recent poll. A device that has the same IP on three interfaces (uncommon but legal in some topologies) collapses to one row, with the latest `if_index` and `net_mask`.

This is a deliberate trade-off — the table's intent is current-state, not history. Operators who relied on the historical "this device had this IP at this time" view (forensics) will see only the latest state. A separate audit-log table for historical IP changes is a future project (see deferred).

**Regression tests** (`internal/database/ifaddr_audit030_test.go`, new — 3 tests):

- `TestSaveInterfaceAddresses_DedupsOnPoll_AUDIT030` — seeds the same address twice (15s apart, with `if_index` moving from 0 to 1), asserts the table has exactly one row with the latest values.
- `TestSaveInterfaceAddresses_PerDeviceDedup_AUDIT030` — defensive sibling: same IP on two different devices must produce two rows (the unique index is `(device_id, ip_address)`, not `ip_address` alone).
- `TestSaveInterfaceAddresses_MultipleAddressesSameCall_AUDIT030` — a single `Save` with three distinct `(device, ip)` tuples produces three rows. Defends against a future "optimization" that drops the unique-index and replaces it with in-process dedup.

**What this does NOT do (deferred)**

- **Migration for existing deployments with duplicate rows.** As noted above, the unique-index addition will fail AutoMigrate on a deployment that already has millions of rows. The one-shot dedup query is documented in the CHANGELOG; running it is the operator's responsibility for a one-version upgrade. A future commit could add it to the entrypoint script (similar to how AUDIT-008's secrets flow handles "first init" / "subsequent boot").
- **Historical IP audit log.** A separate table recording "this device had this IP at this time" with a real time-series structure (partitioned, retention-bounded) would be the right home for forensics queries. Out of scope for AUDIT-030 (the audit was about ending unbounded growth, not adding a new feature).
- **Switching the `idx_ifaddr_ip` single-column index to a covering index** (include `device_id`). The current single-column index is used for IP-lookup queries, and the composite `idx_ifaddr_device_ts` covers the device-lookup path. A future index-tuning pass could merge them. Out of scope for AUDIT-030.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 218 tests, +3 AUDIT-030), `gofmt -l .`, `go vet ./...` all clean. Code + model + test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.277] - 2026-06-02

### Fixed — AUDIT-029: four previously-unbounded tables now have retention knobs

`CleanupOldData` (`internal/database/database.go`) was missing entries for `interface_errors`, `processor_stats` (the new per-table field), `process_stats`, and `irc_message_logs`. Every probe poll appended a row to each, forever, on long-running deployments this would OOM the DB.

**The fix** (three parts):

1. **`internal/config/config.go`** — four new fields on `RetentionConfig`:
   - `InterfaceErrorsDays int` (default 30)
   - `ProcessorStatsDays int` (default 30)
   - `ProcessStatsDays int` (default 30)
   - `IRCMessageLogDays int` (default 7, shorter because IRC logs are higher-volume and lower-signal)

   Plus four new env vars in `Load()`: `RETENTION_INTERFACE_ERRORS_DAYS`, `RETENTION_PROCESSOR_STATS_DAYS`, `RETENTION_PROCESS_STATS_DAYS`, `RETENTION_IRC_MESSAGE_LOG_DAYS`.

2. **`internal/database/database.go`** — `CleanupOldData`'s `entries` slice now includes the four models:
   - `&models.InterfaceErrors{}` → `ret.Days(ret.InterfaceErrorsDays)`
   - `&models.ProcessorStats{}` → `ret.Days(ret.ProcessorStatsDays)`
   - `&models.ProcessStats{}` → `ret.Days(ret.ProcessStatsDays)`
   - `&models.IRCMessageLog{}` → `ret.Days(ret.IRCMessageLogDays)`

   `ret.Days(0)` falls back to `DefaultDays` (90), so operators who don't set the new env vars get a sane default rather than the unbounded behavior.

3. **`config.env.example`** — four new commented env vars documenting the defaults and the fallback to `RETENTION_DEFAULT_DAYS` if the operator sets them to 0.

**Operator migration**

No action required for existing deployments. The new fields default to 30/30/30/7, which is what the audit recommended. Operators who want longer retention (e.g. a long-retention reporting use case for processor stats) can bump the corresponding `RETENTION_*_DAYS` env var.

**Regression tests** (`internal/database/cleanup_audit029_test.go`, new — 2 tests):

- `TestCleanupOldData_CoversAllFourOrphanTables_AUDIT029` — seeds one backdated row in each of the four tables, runs `CleanupOldData` with the AUDIT-029 defaults, asserts all four tables are empty. A pre-fix run would leave every row in place.
- `TestCleanupOldData_RespectsPerTableRetention_AUDIT029` — defensive sibling: seeds one 60-day-old and one 10-day-old row in `processor_stats`, configures a 30-day retention, asserts only the 60-day-old row is deleted. A regression that hardcodes one retention for all four tables (or that uses the wrong field) would fail here.

`internal/database/testing.go` was updated to also `AutoMigrate` the four newly-tested models (plus a few others that were missing from the test list — `LoginAttempt`, `UptimeRecord`, `SyslogSummary`, `InterfaceAddress`). Without this, the test would have failed with "no such table" rather than the actual AUDIT-029 row-preservation failure.

**What this does NOT do (deferred)**

- **Per-device or per-tag retention.** The knobs are global. A future enhancement could read a `retention_class` field on the Device/Site model and select from a per-class set of knobs. Out of scope for AUDIT-029 (the audit was about ending unbounded growth, not per-class tuning).
- **Backfill cleanup.** A long-running deployment that already accumulated millions of orphan-table rows will see one large DELETE on the next retention tick. This is the desired behavior (the rows are deleted eventually), but the first run could be slow. A future "one-shot backfill" cron could be added if operators report slow first-run issues.
- **Retention for the `login_attempt` and `uptime_record` tables.** Those were in `entries` already (the audit's complaint was about the four specific orphan tables). They're covered.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 215 tests, +2 AUDIT-029), `gofmt -l .`, `go vet ./...` all clean. Code + config + test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.276] - 2026-06-02

### Fixed — AUDIT-127: documented the back-button / filter-state limitation in admin-controls.js

`cmd/api/static/js/admin-controls.js` uses `history.replaceState` for filter changes. The browser back button therefore doesn't restore the previous filter state — each page is a separate URL (`/admin/syslog`, `/admin/alerts`, etc.) and back navigates between pages, not between filter states within a page.

The pre-fix code had a one-line comment ("URL sync is `history.replaceState` (no back-stack pollution).") that didn't explain the back-button behavior. Operators reporting "I changed a filter, hit back, and lost my work" had to read the JS to understand why.

**The fix** (`admin-controls.js`):

A new paragraph in the file-level doc comment explains:

1. **The limitation** — `history.back()` doesn't restore the previous filter state.
2. **The design intent** — `replaceState` (vs `pushState`) was a deliberate choice: it keeps the back button useful for page-level navigation and avoids polluting the back stack with a new entry per slider drag.
3. **The trade-off** — filter history is session-only; reloading the page resets to the URL-default state.
4. **The upgrade path** — a future improvement would be a minimal hash-based router that listens to `hashchange` and re-runs the page's `load()` callback. The note explains what that refactor would entail (lifting the `load()` callbacks out of the per-page IIFE into a per-page registry the router can dispatch to).

The audit's first option ("Implement minimal hash-based or History API router") was a meaningful refactor — its own work — so we chose the second ("accept the limitation and document"). The documentation is in the file itself so a future agent who picks up the router work has a starting point.

**Regression test** (`internal/shell/admincontrols_audit127_test.go`, new):

`TestAdminControls_DocumentsRouterLimitation_AUDIT127` — four-signal static check on the file's doc block:

1. `"AUDIT-127"` — the decision is traceable to the audit doc.
2. `"history.back"` — the limitation is named.
3. `"replaceState"` — the design choice is named.
4. `"minimal hash-based"` — the upgrade path is named.

A future agent who shortens the doc back to the pre-fix one-liner fails here immediately, with a message pointing at the audit.

**What this does NOT do (deferred)**

- **Build the hash-based router.** The audit's first option. Out of scope for AUDIT-127 (the audit doc said "Implement... or accept the limitation and document"). The doc block describes the work; a future commit can implement it. The implementation would lift `load()` callbacks out of per-page IIFEs into a registry — a 200-300 LOC refactor.
- **Add a `popstate` listener that catches back-button presses.** A partial fix that would update the URL but not re-run the filter. Not worth the complexity without the full router.
- **Switch to `pushState` for filter changes.** This would fix the back-button case (back would restore the previous filter) but pollute the back stack with one entry per slider drag — a worse UX in the common case (operator just wants to back out of the page, not undo 5 filter changes).

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 213 tests, +1 AUDIT-127), `gofmt -l .`, `go vet ./...` all clean. Doc-only change in `cmd/api/static/js/admin-controls.js` + new test file. No code path affected. Static-binary change → requires rebuild. Server-repo only.

## [0.10.275] - 2026-06-02

### Fixed — AUDIT-115: AI agent session-memory files removed from the public tree

`lessons.md`, `tasks/lessons.md`, and `tasks/todo.md` were tracked in the public repo. They contained AI agent session memory — internal process artifacts like "Lesson: ask about the collector repo before changing SNMP code" and "Tasks for this session: TODO list of the AI's pending work." These notes are not for human contributors, pollute the public tree with private process state, and confuse a `git clone` + `find . -name "*.md"` operator who isn't expecting to read AI coaching material.

**The fix**:

```
git rm -f lessons.md tasks/lessons.md tasks/todo.md
rmdir tasks
```

Three files removed. The `tasks/` directory was already empty after the third `git rm` (the `rmdir` was a no-op since `git rm` of the last file in a directory doesn't always remove the dir — defensive cleanup).

The audit's alternative was to move the files to `.claude/` (already gitignored). We chose full removal because:

1. The content is re-derivable from the codebase at any time (the lessons are about the codebase, not novel insights).
2. The AI agent can keep session memory outside the repo entirely (e.g. in a per-developer working directory).
3. Operators who do want to keep the content can create a private fork with `lessons.md` excluded via `.git/info/exclude` — no need to ship it to everyone.

**Regression test** (`internal/shell/agentmemory_audit115_test.go`, new):

`TestNoTrackedAgentMemoryFiles_AUDIT115` — runs `git ls-files` and asserts that none of `lessons.md`, `tasks/lessons.md`, `tasks/todo.md`, or the `tasks` directory itself appear in the tracked-file list. A future agent who `git add`s any of these files fails here immediately, with a message pointing at the audit and the alternative (move under `.claude/`).

**What this does NOT do (deferred)**

- **Maintain an in-repo `lessons.md` for human contributors.** The audit's framing — "AI agent session memory, not for human contributors" — is correct. A separate `docs/lessons.md` (or `docs/CHANGELOG-style-incident-log.md`) could capture post-mortem content for the human audience, but that's a content project, not a code-fix project. Out of scope for AUDIT-115.
- **Audit other "internal-process" files** (e.g. `tasks/`, hidden directories, dotfiles). The current sweep is targeted at the three known cases. A future broader sweep would enumerate the working tree for any file that looks like session memory (heuristics: short files, all-caps headers like "TODO", "Lesson:", "Plan:").
- **Add a pre-commit hook that blocks `git add` of common agent-memory file names.** Rejected — the static test in the codebase is the right enforcement point (it runs in CI), and a pre-commit hook is per-developer config that wouldn't reach the public.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 212 tests, +1 AUDIT-115), `gofmt -l .`, `go vet ./...` all clean. Removal-only change + new test file. No code path affected. Static-binary change → requires rebuild, but no source files changed so the binary is bit-identical. Server-repo only.

## [0.10.274] - 2026-06-02

### Fixed — AUDIT-145: parseBucketToMillis no longer returns 0 (1970 datapoint) for unparseable inputs

`parseBucketToMillis` in `internal/database/database.go` returned `0` (Jan 1 1970 epoch ms) for any input it couldn't parse. The chart then rendered `0` as a literal "1970" datapoint — a real failure mode whenever:

- A future migration changes the bucket format without updating this function (e.g. switching from SQLite `strftime` to Postgres `date_trunc` and back).
- A corrupted row loses the bucket column.
- A bug in the upstream SQL produces an empty string (empty result of `TimeBucket('')`).

**The fix** (`database.go`):

1. **New sentinel** `bucketUnparseableMillis int64 = -1` for the function to return on unparseable inputs. -1 is a fine sentinel because the legitimate input set (year ≥ 2000) never produces a negative UnixMilli.
2. **Updated `parseBucketToMillis`** to:
   - Trim whitespace; return sentinel for empty input.
   - Return sentinel for any string that doesn't match the documented formats.
3. **Updated the consumer** in `GetSystemStatusHistory` to filter rows with `millis == bucketUnparseableMillis` and log a warning. The API response never contains a `-1` `bucket_ms`.
4. **Exposed the sentinel** via `BucketMillisUnparseableSentinel() int64` for the test to pin the contract without reading the unexported constant directly.

**Wire format / migration**

- `bucket_ms` was already a JSON int64 in the response; it remains so. The change is the sentinel value semantics, not the type. Pre-existing API consumers don't see a new shape.
- Empty-bucket rows are dropped from the response, not rendered. Operators who relied on a "row exists" signal to detect corruption will need to look at server logs (`system_status time-series: skipping row with unparseable bucket %q`).

**Regression tests** (`internal/database/parsebucket_audit145_test.go`, new — 2 tests, 17 subtests):

- `TestParseBucketToMillis_AUDIT145` (10 subtests) — pins the output for every shape the function accepts: 4 unparseable inputs (empty / whitespace / random text / bad ISO month) all return the sentinel; 5 valid inputs (one per documented format) return real epoch ms computed via `time.Parse` (so the test isn't fragile to a future Go release changing how the format string is interpreted).
- `TestParseBucketToMillis_NeverReturnsZero_AUDIT145` (7 subtests) — the defense-in-depth contract: regardless of input, the function must never return 0. A future refactor that returns 0 for some new edge case slips past the format-specific assertions but fails here.

**What this does NOT do (deferred)**

- **Audit the other `time.Parse` call sites in `database.go`** (lines 2677, 2959 in the grep output) that do their own bucket parsing instead of going through `parseBucketToMillis`. They're separate concerns; consolidating them is a refactor that should be its own commit.
- **Backfill the audit fix into the `GetPingResultHistory` and other time-series endpoints.** Those don't use `parseBucketToMillis` at all (they use raw `timestamp` columns), so the audit didn't flag them. The same NaN-via-empty-string risk is mitigated by the `Where("timestamp > ?", cutoff)` filter.
- **Surface the skipped rows in a `/api/system/health` or `/metrics` counter.** A future observability improvement would expose the skip count so operators know to investigate.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 211 tests, +17 AUDIT-145 subtests), `gofmt -l .`, `go vet ./...` all clean. Code-only change in `internal/database/database.go` + new test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.273] - 2026-06-02

### Fixed — AUDIT-133: formatBytes now returns em-dash for non-finite inputs

`formatBytes(bytes)` in `cmd/api/static/js/admin-common.js` used to fall through to `Math.log(NaN) / Math.log(1024) = NaN` for non-finite inputs, and the chart rendered the result as "NaN.0 undefined" — a real failure mode when:

- A misbehaving device's interface byte count overflows to `NaN` (or wraps a 32-bit counter to a negative value, which `Math.log` then treats as NaN).
- A freshly-reset probe reports `Infinity` for a delta-vs-zero counter.
- An API response includes a non-number in a field the chart assumed was numeric (a future regression on the server side).

**The fix** (`admin-common.js`):

```js
function formatBytes(bytes) {
    if (!isFinite(bytes) || bytes == null) return '—';
    if (bytes === 0) return '0 B';
    // ... existing algorithm
}
```

The em-dash (`U+2014`) is the chosen "no data" marker — it's consistent with the rest of the dashboard's no-data rendering convention. A future agent who "improves" the fallback to `0 B` or `N/A` or `?` would break the design; the static regression test below pins the em-dash.

The other `formatBytes` (in `admin-connection-detail.js:19`) is a separate local copy with a different (iterative-division) algorithm that already short-circuits on `!bytes` (which `!NaN` matches) — no fix needed there.

**Regression test** (`internal/shell/admincommon_audit133_test.go`, new):

`TestAdminCommon_FormatBytesHandlesNaN_AUDIT133` — three-signal static check:

1. The file still defines `function formatBytes(bytes)` (the canonical home of the helper; a future move to a different file would break the test and force a deliberate update).
2. The `!isFinite(bytes)` guard is present.
3. The fallback return is `—` (em-dash). A future agent who changes the fallback to "0 B" or "N/A" fails here.

**What this does NOT do (deferred)**

- **Centralize the two `formatBytes` copies** (one in `admin-common.js`, one in `admin-connection-detail.js`) into a shared helper. Each is currently used in only one place; the duplication is intentional to keep the two pages decoupled. A future refactor that consolidates them gets this fix for free; a static check enforcing "only one formatBytes exists" would be over-fitting.
- **Audit all dashboard numerics for NaN handling.** `formatNum` already does `n != null ? Number(n).toLocaleString() : '0'`, which is also NaN-vulnerable in a different way. The same pattern (`isFinite` guard) would be a one-liner per helper. Out of scope for AUDIT-133 (the audit was specific to `formatBytes`).
- **Server-side NaN sanitization.** Even with the JS fix, a NaN in the data still represents a bug somewhere upstream (counter overflow, missing field). A separate audit would catch the server-side root cause. Out of scope for this commit.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 194 tests, +1 AUDIT-133), `gofmt -l .`, `go vet ./...` all clean. JS-only change in `cmd/api/static/js/admin-common.js` + new test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.272] - 2026-06-02

### Fixed — AUDIT-169: documented the layering decision for `cmd/api/static.go`

The audit's recommendation was "Acceptable as-is. Document the choice." The "choice" is whether a 2-line `//go:embed` wrapper belongs in `cmd/` or in an `internal/` package:

- **Layering purist view:** `internal/` is the canonical home for an `embed.FS` used by a binary. It keeps `cmd/` purely a "main" and makes the embed reusable.
- **Pragmatic view:** `staticFiles` is consumed only by the gin router in `cmd/api/main.go`. The `//go:embed static` directive resolves paths relative to the source file, so moving it would also require reorganizing the `static/` directory, which buys nothing today.

**The fix** (`cmd/api/static.go`):

A multi-paragraph package-level doc comment that names the audit, the two views, the choice we made, and the trigger that would justify migrating the embed to `internal/webassets/`:

> If a second binary in the project ever needs the same embed (e.g. a `cmd/admin-tools/` that ships a CLI version of the admin UI), the right move is to lift `static/` and the `staticFiles` declaration to `internal/webassets/`. The directory layout should follow the second consumer, not the first.

This is the kind of decision that lives in commit messages today and gets lost the next time someone `git blame`s the file. Putting it in the source means the next person who looks at the embed finds the rationale immediately.

**Regression test** (`internal/shell/staticgo_audit169_test.go`, new):

`TestStaticGo_HasLayeringDocComment_AUDIT169` — three-signal static check on the file: it must contain the string `"AUDIT-169"` (so the decision is traceable), the string `"staticFiles"` (so the doc is about *this* file, not a copy-paste from elsewhere), and the string `"internal/"` (the migration target if a second consumer ever appears). The test doesn't pin the full text — a future clarifying edit doesn't fail — but the three signals are the load-bearing pieces. A future agent who deletes the comment fails immediately, with a failure message pointing at the audit.

**What this does NOT do (deferred)**

- **Move the embed to `internal/`.** The audit explicitly accepted the current location. Moving would require reorganizing the `static/` directory and is only worth the cost when a second consumer appears (none today).
- **Add a `static_test.go` that exercises the embed.** The embed is exercised transitively by every page-render in the integration tests; an explicit unit test would just re-verify Go's stdlib `embed` package. Out of scope.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 193 tests, +1 AUDIT-169), `gofmt -l .`, `go vet ./...` all clean. Doc-only change in `cmd/api/static.go` + new test file. No code path affected. Static-binary change → requires rebuild. Server-repo only.

## [0.10.271] - 2026-06-02

### Fixed — AUDIT-159: probe binary's banner output now uses log.* like the rest of the codebase

`cmd/probe/main.go` shipped banner / status output via `fmt.Println` and `fmt.Printf` while every other log call in the same file (and every other binary in the project) used `log.*`. The pre-fix output went to stdout with no timestamp and no prefix, which made it inconsistent with the rest of the codebase's logs and impossible to grep with a uniform pattern (`grep "INFO probe:" log.txt` would have missed the banner lines entirely).

**The fix** (`cmd/probe/main.go`):

Every `fmt.Println(...)` and `fmt.Printf(...)` in the banner / status path (lines 151-289 and 442-448) is now `log.Println(...)` / `log.Printf(...)`. The "log" import was already present in this file (it was used for the `log.Printf("Failed to send trap: ...")` error paths), so no import changes were needed.

`fmt.Errorf(...)` is left alone in the same function — wrapping errors with `%w` for the caller to inspect is a different concern from formatting output, and the existing pattern is correct.

The fix also covers a `Stop()` method (lines 442-448) that was using `fmt.Println` for shutdown messages — now consistent with the rest of the file.

**Regression tests** (`internal/shell/probe_audit159_test.go`, new — 2 tests):

- `TestProbe_NoFmtPrintln_AUDIT159` — regex-scans `cmd/probe/main.go` for any `fmt.Print` call (catches both `Println` and `Printf`). A future agent who copy-pastes a `fmt.Println("starting up...")` back into the file fails here immediately.
- `TestProbe_HasLogImport_AUDIT159` — defensive sibling: confirms `"log"` is still imported. A future agent who removes the import "because the file doesn't use log" would fail compilation, but this test catches the intent more loudly.

**What this does NOT do (deferred)**

- **Migrate to a structured logger** (logrus / zap / slog). The codebase uses stdlib `log` everywhere; switching to structured logging is a project-wide change, not a probe-specific one. AUDIT-076 is the deferred MEDIUM for "no structured logging" — same scope, larger surface.
- **Add a `[probe]` prefix to every log line.** Some operators like a uniform `[component]` prefix so they can grep for `\[probe\]` to isolate the probe's logs from the rest of the deployment. Not done here because the rest of the codebase doesn't use that pattern; adding it to the probe alone would be inconsistent.
- **Capture stdout vs stderr routing.** `log.*` writes to stderr by default (with the default logger); `fmt.*` writes to stdout. Operators who split the two streams in a log pipeline will see the probe's banner output move from stdout to stderr. This is a behavior change, but it's the right behavior — the audit was about consistency with the rest of the codebase, and the rest of the codebase writes to stderr via `log.*`.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 192 tests, +2 AUDIT-159), `gofmt -l .`, `go vet ./...` all clean. Probe-binary change in `cmd/probe/main.go` + new test file. Static-binary change → requires rebuild. Server-repo only.

## [0.10.270] - 2026-06-02

### Fixed — AUDIT-101: Dockerfile OCI labels now come from build-args (no more stale version)

Pre-AUDIT, the Dockerfile's `org.opencontainers.image.version="0.10.X"` was a hardcoded literal. Past releases (v0.10.237, v0.10.239) shipped with the label stuck on a stale version, because the build process never updated the literal — only `cmd/api/main.go`'s `ServerVersion` constant. Operators using `docker inspect` to verify "is this the right image" would see a label that said one version while the binary inside reported another, breaking the most basic image-provenance check.

**The fix** (`Dockerfile`):

1. New `ARG VERSION=dev`, `ARG REVISION=unknown`, `ARG CREATED="1970-01-01T00:00:00Z"` declarations before the `LABEL` block. The defaults are sensible — a bare `docker build .` still produces a working image labeled "dev", which is a clear signal that the build wasn't tagged.
2. `LABEL org.opencontainers.image.version="${VERSION}"` (and `.revision`, `.created`) — the three most versioned labels are now sourced from build-args.
3. **Additional OCI labels** for the rest of the OCI image-spec annotations (https://github.com/opencontainers/image-spec/blob/main/annotations.md):
   - `.description` — short human-readable one-liner
   - `.source` — the GitHub repo URL
   - `.url` — same URL (the spec allows both; different consumers read different keys)
   - `.licenses` — `MIT` (SPDX expression, matches the LICENSE file)
   - `.vendor` — `Firewall-Mon Contributors` (the project umbrella)
   - `maintainer` — same
4. Title and description stay hardcoded — they're not versioned, so making them ARGs would be ceremony with no benefit.

**Build invocation change** (when the CI workflow lands — AUDIT-004 deferred):

```sh
docker build \
  --build-arg VERSION="${GITHUB_REF_NAME}" \
  --build-arg REVISION="${GITHUB_SHA}" \
  --build-arg CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/xphox2/firewall-mon:${GITHUB_REF_NAME} .
```

For local dev (`docker build .`), all three args default and the image is labeled `dev` / `unknown` / `1970-01-01T00:00:00Z`. The `1970-01-01` default for `CREATED` is intentionally ugly — it's a hint to anyone using `docker inspect` on a local build that this isn't a tagged release.

**Regression test** (`internal/shell/dockerfile_audit101_test.go`, new):

`TestDockerfile_OCILabelsUseBuildArgs_AUDIT101` — three-axis static check on the Dockerfile:

1. **ARG declarations** must be present (`ARG VERSION=`, `ARG REVISION=`, `ARG CREATED=`).
2. **LABEL block** must reference the build-args via `${VERSION}` / `${REVISION}` / `${CREATED}` (not literals).
3. **No hardcoded `org.opencontainers.image.version="..."` literal** survives anywhere. A regex scan that explicitly excludes the `${VERSION}` form fails if a future agent re-introduces a literal. Caught a literal version here: `<actual>`.

A future agent who copy-pastes a working version number back into the LABEL block (the obvious "fix" when the build-arg approach looks unfamiliar) fails at (3) before the change can ship.

**What this does NOT do (deferred)**

- **CI workflow that actually passes the build-args.** AUDIT-004 deferred halves (release.yml / goreleaser) is the place. The Dockerfile change is the prerequisite; the CI change is the trigger. Until CI lands, the version label is `dev` for local builds and will need a manual `--build-arg` override for tagged images.
- **`-trimpath -buildvcs=false` build flags** (AUDIT-102). Separate concern; the labels don't depend on the build flags, only on the build context.
- **Per-architecture image variants** (e.g. arm64 for Raspberry Pi firewall appliances). The current Dockerfile is amd64-only. Out of scope for AUDIT-101.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 190 tests, +1 AUDIT-101), `gofmt -l .`, `go vet ./...` all clean. Dockerfile-only change. No code rebuild required — the next `docker build` picks up the new LABEL block.

## [0.10.269] - 2026-06-02

### Fixed — AUDIT-157: dead ADMIN_SECRET_KEY env var removed

Pre-AUDIT, `config.env.example` documented `ADMIN_SECRET_KEY=` as a configuration knob, and `internal/config/config.go` loaded it into a `ServerConfig.AdminSecretKey` field. **No code path in the entire codebase ever read that field.** It was set, persisted, and ignored — pure dead state.

This was a small but real footgun: an operator reading the example file would set `ADMIN_SECRET_KEY=somevalue`, expect the system to use it, and find that it does nothing. The bug-class it invited is "I thought I configured X but actually X isn't wired up" — a configuration-tried-but-silent failure that's hard to debug.

**The fix** (two parts):

1. `internal/config/config.go` — removed `AdminSecretKey string` from `ServerConfig` and the `getEnv("ADMIN_SECRET_KEY", "")` line from the `Load()` struct literal. Future agents who reference `cfg.Server.AdminSecretKey` will get a compile error, which is the right kind of failure.
2. `config.env.example` — removed the `ADMIN_SECRET_KEY=` line (and the comment block that introduced it).

**Why the field was there in the first place**

The audit doc describes it as a leftover from an earlier "admin secret" concept that got replaced by the AUDIT-008 secrets flow (`SECRETS_DIR/.jwt-secret` for the JWT key, `SECRETS_DIR/.admin-password` for the admin password). The leftover variable in the example file was the only surviving artifact.

**Regression test** (`internal/config/config_audit157_test.go`, new):

`TestNoDeadAdminSecretKey_AUDIT157` — two-axis regression:

- **Static check** — reads `config.go` and asserts neither `"ADMIN_SECRET_KEY"` nor `"AdminSecretKey"` appears in the source. A future agent who copy-pastes an example back into the file (or a future handler that resurrects the field) fails here immediately, before the change can ship.
- **Runtime check** — sets `ADMIN_SECRET_KEY` to a unique sentinel value, calls `Load()`, and asserts the sentinel doesn't surface in the rendered `Server` block. This catches the subtle case where a future agent re-adds the field and wires it up to *something* (e.g. logs it, includes it in a debug dump) but the value is still effectively unused from the operator's perspective.

The two axes are complementary: the static check is the strict gate (the field/env var must not exist), the runtime check is the defense-in-depth (if a future agent re-adds them in a non-load path, the sentinel test catches it).

**What this does NOT do (deferred)**

- **Re-introduce ADMIN_SECRET_KEY as a real knob** (e.g. for a future SSO callback HMAC). The deferred feature would re-add the field, and this test would need to be updated to reflect the new contract. The test name and the comment in the file are the place to make that change.
- **Audit other dead-config candidates.** AUDIT-154 (`ParseHours`), AUDIT-155 (`FilterAllowedFields`), AUDIT-156 (`validVendors`) are similar — env vars / fields / maps that may be set-but-unused. They get their own audit commits in a future batch.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 189 tests, +1 AUDIT-157), `gofmt -l .`, `go vet ./...` all clean. Config-only change in `internal/config/config.go` + `config.env.example` + new test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.268] - 2026-06-02

### Fixed — AUDIT-148: LIKE clauses now carry ESCAPE '\' modifier (defense in depth)

`GetConnectionFlowStats` filters VPN flows by CIDR-derived LIKE patterns (e.g. `10.0.1.%` for a `/24`). The patterns are built by `cidrToLikePattern` from `net.ParseIP` / `net.ParseCIDR`-validated input, so today's output never contains a user-controlled `%` or `_` — only an intentional trailing `%` as the "any" wildcard. The audit was correct, though, that the SQL didn't carry an `ESCAPE` clause, which is defense-in-depth worth adding:

1. **Call site** (`database.go:3819-3820`) — the four `LIKE ?` conditions now read `LIKE ? ESCAPE '\' AND dst_addr LIKE ? ESCAPE '\'`. The escape character `\` itself is never emitted by `cidrToLikePattern`, so no double-escape is needed; this is a strict additive change.
2. **Helper docstring** (`cidrToLikePattern` at `database.go:3724`) — added a comment block explaining why the function's output is safe by construction (input is IP-validated) and where the defense-in-depth actually lives (the `ESCAPE` at the call site).

**Why this matters**

A future refactor that drops the `net.ParseIP` / `net.ParseCIDR` validation (e.g. someone refactoring to accept arbitrary user input — a `device.local_subnet` text field that an admin can set via the API, for instance) would, without the `ESCAPE` clause, silently widen the match. With it, an attacker who controls the input can put a literal `%` in the pattern by prefixing `\%`, and the rest of the LIKE syntax becomes attacker-controlled only at the same scope as the surrounding SQL. The new test below pins the current "no escapable literal in the output" contract.

**Regression tests** (`internal/database/cidr_audit148_test.go`, new — 2 tests, 20 subtests):

- `TestCIDRToLikePattern_AUDIT148` (14 subtests) — pins the helper's output for every shape the function accepts: empty / whitespace / default route / invalid CIDR / non-CIDR text / unparseable IP range / `/32` (exact match) / `/24`, `/16`, `/8` (trailing `%`) / `/4` (too-broad, returns "") / IP range format / single IP / IPv6 (rejected). A regression on the output (e.g. someone "fixes" the helper to return `10.0.0._%` thinking `_` is part of an IP notation) would fail at least one of these.
- `TestCIDRToLikePattern_NeverEmitsEscapableLiteral_AUDIT148` (6 subtests) — the defense-in-depth contract: regardless of input, the output never contains a literal `_`, never contains more than one `%`, and any `%` is in the trailing position. A future change that adds literal `%` or `_` to the pattern (which would be a LIKE-injection vector) fails here before it can ship.

**What this does NOT do (deferred)**

- **Escape the input explicitly inside cidrToLikePattern.** Rejected — the function's contract is "valid IP → LIKE pattern", and the IP validation is the gate. Adding a second escape layer would be belt-and-suspenders noise that suggests the validation isn't trustworthy.
- **Refactor the broader `GetConnectionFlowStats` query.** The function is 100+ lines and uses GORM `Raw()` with a hand-built query string. A future refactor could parameterize it more cleanly, but that's a separate concern (and AUDIT-072's "split the 4,210-line database.go" is a prerequisite for most of that work).

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 188 tests, +20 AUDIT-148 subtests), `gofmt -l .`, `go vet ./...` all clean. Code-only change in `internal/database/database.go` + new test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.267] - 2026-06-02

### Fixed — AUDIT-105: default ADMIN_USERNAME=admin now warns at startup

Pre-AUDIT, `config.env.example` shipped with `ADMIN_USERNAME=admin` and the code accepted it silently. The default username is the most brute-forced string on the public internet (OWASP has had it in the top-3 for two decades running) and a public deploy with the default + a weak password is one targeted dictionary attack away from a full compromise. Operators who copy-pasted the example file got no signal that they were leaving the most-attacked surface open.

**The fix** (`internal/config/config.go`):

1. New `Auth.AdminUsernameExplicit bool` field, populated by `os.Getenv("ADMIN_USERNAME") != ""`.
2. `Validate()` logs a multi-line, actionable warning when the operator kept the default (`!AdminUsernameExplicit && strings.EqualFold(AdminUsername, "admin")`):
   ```
   WARNING: ADMIN_USERNAME is the default 'admin'. This is the most
            brute-forced username on the internet; consider setting
            ADMIN_USERNAME to a unique value in config.env. Example:
                ADMIN_USERNAME=ops-jane
            (or any non-default value you can remember). The warning
            only fires when ADMIN_USERNAME is unset; explicitly setting
            it to 'admin' is treated as a conscious operator choice.
   ```
3. The warning is intentionally not fatal — operators behind a SSO portal or VPN have their own brute-force protection and the in-app username is unguessable to anyone who can reach the login page. The point is to make the default-exposed case *visible*, not to break a valid topology.
4. **Case-insensitive comparison** — `Admin`, `ADMIN`, `aDmIn` all trigger the warning when inherited from the default, since an attacker who tries case variants against a host that only set "admin" will get through.

**Behavior matrix**

| ADMIN_USERNAME in config.env | AdminUsernameExplicit | Warning fires? |
|---|---|---|
| unset (default to "admin") | false | YES — log loud |
| `admin` | true | no — operator made a conscious choice |
| `Admin` / `ADMIN` / `aDmIn` | false | YES — case-insensitive default-match |
| `Admin` / `ADMIN` / `aDmIn` | true | no — same as above |
| any other value (e.g. `ops-jane`) | true or false | no |

**Regression tests** (`internal/config/config_audit105_test.go`, new — 4 tests, 6 subtests):

- `TestValidate_DefaultAdminUsernameWarns_AUDIT105` — the headline: `!Explicit && AdminUsername=="admin"` does not error and the warning fires.
- `TestValidate_ExplicitAdminUsernameDoesNotWarn_AUDIT105` — `Explicit && AdminUsername=="admin"` does not error and the warning does NOT fire.
- `TestValidate_NonDefaultAdminUsernameSilent_AUDIT105` — any non-"admin" value is silent.
- `TestValidate_DefaultAdminUsernameCaseInsensitive_AUDIT105` — three subtests for `Admin`, `ADMIN`, `aDmIn` confirm the case-insensitive match. A regression on the case-fold (e.g. someone replaces `strings.EqualFold` with `==`) would fail at least one of these.

**What this does NOT do (deferred)**

- **Disallow "admin" entirely.** Some operators have integrations that depend on the literal string. The warning is the right level — they get a clear, actionable message at startup and can confirm with a one-line edit.
- **Top-N common-username list.** "admin" / "root" / "test" / "user" are all bad defaults, but adding a list to maintain is more work than the warning is worth. The single case catches the OWASP #1; a future audit could add more.
- **Pre-install `secrets.json` content check** (a separate concept — the README could ship a checklist of "things to change from defaults before going to production" with ADMIN_USERNAME at the top). AUDIT-105 is the in-process equivalent.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 170 tests, +4 AUDIT-105 with 6 subtests), `gofmt -l .`, `go vet ./...` all clean. Config-only change in `internal/config/config.go` + new test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.266] - 2026-06-02

### Fixed — AUDIT-096: docker-compose.yml now has an explicit healthcheck block

Pre-AUDIT, `docker-compose.yml` declared the `firewall-mon` service without a `healthcheck:` block. The Dockerfile had its own `HEALTHCHECK` (added in v0.10.264, AUDIT-091), but the compose-level healthcheck was missing. Two real consequences:

1. **`docker compose ps` doesn't show a health status column.** It shows "Up" with no "healthy/unhealthy" qualifier. An operator looking at the running stack can't tell at a glance whether the API is actually serving traffic or whether the process is wedged on a wedged DB. They have to read JSON (`docker inspect`) to figure it out.
2. **`depends_on: condition: service_healthy` is not available to dependent services.** A future split-out compose that puts a reverse proxy (Caddy, nginx, Traefik) in front of `firewall-mon` would want to wait for the API to be live before bringing the proxy up. The `condition: service_healthy` form requires an explicit `healthcheck:` block in the depended-on service's definition. Without it, the proxy would race the API and fail to start on a slow boot.

**The fix** (`docker-compose.yml`):

New `healthcheck:` block on the `firewall-mon` service, mirroring the Dockerfile's `HEALTHCHECK` (v0.10.264) so the two paths agree:

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:8080/api/health"]
  interval: 30s
  timeout: 3s
  retries: 3
  start_period: 20s
```

The values are deliberately identical to the Dockerfile (same interval, timeout, retries, start_period). Diverging the two would create a subtle race where the image's healthcheck and the compose healthcheck disagree on liveness — the static check in the test file does not enforce parity, so a future agent who edits one but not the other will get a "compose says healthy, image says unhealthy" inconsistency that surfaces as a confusing `docker compose ps` output rather than a test failure.

**Regression test** (`internal/shell/docker_compose_audit096_test.go`, new):

- `TestDockerCompose_HasHealthcheck_AUDIT096` — static check on `docker-compose.yml`. Strips YAML comments first, then asserts (a) the file contains a `healthcheck:` block at all, and (b) the block probes `/api/health` (matches the Dockerfile's endpoint). The fail message points the future agent at the audit and the CHANGELOG entry for the recommended shape.

**What this does NOT do (deferred)**

- **Parity enforcement between the Dockerfile `HEALTHCHECK` and the compose `healthcheck`.** A future improvement could parse both and diff the relevant fields. The current test pins both independently, so a divergence would not break CI today; it would break `docker compose ps` semantically. Adding the parity check requires a real YAML parser (e.g. `gopkg.in/yaml.v3`) as a new dependency — out of scope for this commit.
- **`docker-compose.proxy.yml` audit.** The proxy compose file is a deployment-shape variant, not currently in active use, and gets its own audit pass in a future commit if a real deployment starts using it.
- **Readiness vs liveness probes** (related to AUDIT-091 deferred). Both compose and the Dockerfile would need to be updated to split these.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 166 tests, +1 AUDIT-096), `gofmt -l .`, `go vet ./...` all clean. YAML-only change. No rebuild required to pick it up — `docker compose up -d` (without `--build`) is enough to apply the new healthcheck, but a full `docker compose up -d --build` is recommended to keep the image label and the healthcheck in sync.

## [0.10.265] - 2026-06-02

### Fixed — AUDIT-093: PostgreSQL password is now auto-generated, not hardcoded

Pre-AUDIT, `entrypoint.sh` shipped with `CREATE USER fwmon WITH PASSWORD 'fwmon'` and `export DB_PASSWORD="fwmon"`. The literal `'fwmon'` was baked into the public repo. With the embedded Postgres configured to `listen_addresses = ''` and `initdb --auth=trust`, the password was not actually checked for local connections — but the moment an operator flipped `listen_addresses` to enable a remote connection (a common production change for running the API outside the container, or for adding pgAdmin access), they would silently ship a publicly-known credential.

**The fix** (`entrypoint.sh`):

1. New `/config/pg-credentials` file (mode 0600) holds `PG_USER` and `PG_PASSWORD`. Created on first init with a 32-character random alphanumeric password (`head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32`).
2. `CREATE USER ... WITH PASSWORD '$PG_PASSWORD'` now uses the sourced value. New installations start with a unique random password per container.
3. **Always-`ALTER`-the-password** (idempotent) — the entrypoint now runs `ALTER USER $PG_USER WITH PASSWORD '$PG_PASSWORD'` on every boot. This is a no-op in steady state (the password already matches) and is the migration path for upgrades from a pre-AUDIT-093 image: the old `fwmon` user already exists with the old password, and the `ALTER` swaps it to the new random one.
4. `export DB_PASSWORD="$PG_PASSWORD"` — the app connects with the same random password.
5. Comment block in `pg-credentials` documents the "delete this file to force regeneration" workflow for an operator who suspects the password leaked.

**Security properties**

- `/config/pg-credentials` is `chmod 0600` and `chown fwmon:fwmon` — only the app user can read it. The Postgres superuser doesn't need it (it connects via the trust-auth local socket for `CREATE`/`ALTER USER`).
- Password is 32 alphanumeric characters (~190 bits of entropy). Same strength as AUDIT-008's JWT secret.
- No password in env vars of any subprocess — `ps` on the host cannot sniff the running container's env to find the password. The only place it lives is the `pg-credentials` file, which is 0600.
- `DB_PASSWORD` is exported because the app needs it for the libpq connection string. Process listings of the host would show the value; this is no worse than any other config the app needs (TLS certs, SMTP creds, etc.) and is consistent with the rest of the codebase.

**Regression test** (`internal/shell/entrypoint_audit093_test.go`, new):

- `TestEntrypoint_NoHardcodedPostgresPassword_AUDIT093` — static check on `entrypoint.sh`. Strips bash comments first (so a CHANGELOG-style explanation in a `#` block doesn't false-positive), then rejects four patterns: `PASSWORD 'fwmon'`, `PASSWORD "fwmon"`, `DB_PASSWORD=fwmon`, `DB_PASSWORD="fwmon"`. A future agent copy-pasting an example back into the entrypoint fails CI immediately.

First test file for the `internal/shell` package (a new package; the test directory is the natural home for static checks on shell scripts the project ships).

**What this does NOT do (deferred)**

- **TCP listening + SCRAM authentication.** The embedded Postgres still only listens on the unix socket. If an operator wants remote access, they need to flip `listen_addresses` themselves AND configure `pg_hba.conf` for SCRAM-SHA-256. Out of scope for AUDIT-093 — the password hygiene is the headline.
- **Password rotation on a schedule.** The 32-char random is fine forever unless it leaks; no scheduled rotation needed. AUDIT-009's `keyChain` mechanism for the AES-256 key is a precedent for a future "rotate DB password every N days" feature.
- **Two-credential model** (one for the app, one for operator ad-hoc psql). Current single password is sufficient for an embedded Postgres.

**Operator migration**

For operators upgrading from a pre-AUDIT-093 image:
- The first post-upgrade boot will see `/config/pg-credentials` is missing, generate a new random password, persist it, and `ALTER USER fwmon` from the old `fwmon` to the new random.
- No data loss, no re-init, no app downtime beyond a normal container restart.
- If the operator wants to inspect Postgres with psql from inside the container, they source the credentials file: `. /config/pg-credentials; psql ...`.

QA: `go build ./...`, `go test -count=1 ./...` (11 pkgs, 165 tests, +1 AUDIT-093), `bash -n entrypoint.sh`, `gofmt -l .`, `go vet ./...` all clean. Shell-only change in `entrypoint.sh` + new test package. Docker rebuild required to pick up the new entrypoint; `docker compose up -d --build` is the standard deploy command.

## [0.10.264] - 2026-06-02

### Fixed — AUDIT-091 + AUDIT-045: /api/health now actually pings the DB, and the Dockerfile HEALTHCHECK calls it

Pre-AUDIT, `GetHealth` (`handlers.go:82`) was a textbook no-op: it returned `{"status":"healthy", "snmp_connected":..., "database":...}` with no actual probe of either dependency. A container running with a wedged Postgres would still report healthy. The Dockerfile didn't have a `HEALTHCHECK` directive either, so Docker, compose, k8s, Portainer, and Uptime Kuma all saw "container is up" == "ready to serve" — which is wrong for a 3-process entrypoint + embedded Postgres where startup order matters and the API can be listening on `:8080` while Postgres is still recovering.

**The fix** (two parts, both required for the headline to land):

1. **`internal/api/handlers/handlers.go`** — `GetHealth` now actually pings the DB with a 1-second bounded context. On success, returns `200 {"status":"healthy","database":true,...}`. On any failure (DB nil, ping timeout, SQL error), returns `503 {"status":"unhealthy","database":false,"db_error":"<reason>",...}`. The SNMP client is NOT probed — a target device being down is not a reason to mark the API unhealthy and trigger a container restart loop; the boolean is informational only. The constant `healthCheckDBTimeout = 1 * time.Second` is exported-by-comment so the Dockerfile timeout (3s) can be reasoned about.

2. **`Dockerfile`** — new `HEALTHCHECK` directive after the `EXPOSE` block:
   ```
   HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
       CMD wget -qO- http://localhost:8080/api/health || exit 1
   ```
   The 30s interval is fast enough that a failed container is detected within a minute; the 3s timeout is 1s (DB ping) + 2s (HTTP overhead); the 20s `start-period` covers embedded-Postgres cold start on the smallest supported instance; 3 retries means 60-90s of consistent failure before Docker marks unhealthy (matches the systemd `RestartSec=10` cadence on the native path).

**Regression tests** (`internal/api/handlers/handlers_health_audit091_test.go`, new — 3 cases):

- `TestGetHealth_HealthyDB_Returns200_AUDIT091` — the happy path: a working SQLite in-memory DB returns 200 with `status:healthy` and `database:true`.
- `TestGetHealth_NilDB_Returns503_AUDIT091` — a Handler constructed without a DB (startup race / test harness) returns 503 with `status:unhealthy` and a non-empty `db_error` string. Pre-fix this returned 200 with a lie.
- `TestGetHealth_DBPingFails_Returns503_AUDIT091` — a Handler with a DB whose underlying connection is force-closed returns 503 with `status:unhealthy` and the actual SQL error in `db_error`. This is the scenario AUDIT-045 was specifically about: pre-fix, this would have reported healthy with no warning.

**What this does NOT do (deferred)**

- **Readiness vs liveness probes split.** K8s convention is two endpoints — `/healthz/live` (process is up) and `/healthz/ready` (deps are up). The current single endpoint conflates them. For a single-binary Docker deploy this doesn't matter, but a future K8s manifest would want them split. Out of scope for AUDIT-091.
- **Probe additional dependencies** (IRC bot liveness, batcher dropped count, alert-queue depth). The audit explicitly called out the DB as the only critical dep; SNMP is informational, and the rest have their own observability metrics.
- **Reconcile the `/api/version` endpoint** (returns version string) with `/api/health`. Future commit could include the version in the health response so operators don't need two requests to confirm "what's deployed AND is it alive".

QA: `go build ./...`, `go test -count=1 ./...` (10 pkgs, 164 tests, +3 AUDIT-091), `gofmt -l .`, `go vet ./...` all clean. Static-binary change + Dockerfile change → requires `docker compose up -d --build` to pick up the new HEALTHCHECK directive (existing containers will keep running but won't have a health status until rebuilt).

## [0.10.263] - 2026-06-02

### Fixed — AUDIT-026: system_settings encryption is now gated on IsSecret

Pre-AUDIT, `UpdateSettings` called `db.EncryptField(s.Value)` on **every** setting row, regardless of whether the row held a secret. Every `cpu_threshold`, `memory_threshold`, `display_timezone`, `public_show_vpn` save paid the AES-GCM cost and persisted a `{enc}<base64>` blob to disk. Two real problems:

1. **Wasteful** — the bulk of system_settings are not secrets (thresholds, display prefs, webhook URLs, boolean toggles). Encrypting them on every write cost CPU on the API path and made the DB rows harder to read for operators debugging their own config.
2. **Footgun** — it invited the v0.10.226 bug class. A consumer (handler, dashboard widget, audit-log formatter) that reads the row back as plaintext and doesn't expect the `{enc}` prefix surfaces `{enc}<base64>` to the operator as "the setting". A future field added to `allowedKeys` would inherit the same bug.

**The fix**

`internal/api/handlers/handlers_settings.go` — the encryption line in the `smtp_password` switch case is now gated on `secretKeys[s.Key]` (the same source-of-truth map that drives the `IsSecret = true` line two lines below):

```go
// Before
if s.Value != "" && h.db != nil {
    s.Value = h.db.EncryptField(s.Value)
}

// After
if secretKeys[s.Key] && s.Value != "" && h.db != nil {
    s.Value = h.db.EncryptField(s.Value)
}
```

The semantics for the only current secret (`smtp_password`) are unchanged — the membership test is true. The semantics for every other `allowedKeys` entry flip from "always encrypted" to "never encrypted", which is the right default for non-secret config.

The other call sites of `db.EncryptField` are already correctly gated:
- `handlers_devices.go:217` and `:225` — iterate over an explicit list of secret fields (`snmp_community`, `snmpv3_auth_pass`, `snmpv3_priv_pass`, `ssh_password`)
- `handlers_irc.go:126` and `:300` — same explicit list pattern (IRC server credentials)

No changes needed at those sites.

**Regression tests** (`internal/api/handlers/handlers_settings_audit026_test.go`, new — 2 tests):

- `TestSettingsSecretKeys_AUDIT026` — pins the source-of-truth map: `smtp_password` is in it, 25 known non-secrets (thresholds, display prefs, webhook URLs, boolean toggles) are explicitly NOT in it. A future agent who adds a key to `allowedKeys` without also adding it to `settingsSecretKeys` gets a test failure on the non-secret check.
- `TestSettingsSecretKeys_NoOverlapWithNonSecrets_AUDIT026` — belt-and-suspenders: the two curated lists share no element, so a future agent can't accidentally reclassify a threshold as a secret (or vice versa) without a hard failure.

**What this does NOT do (deferred)**

- A compile-time reflection check that flags new `Device` / `Probe` fields with names containing `Pass|Secret|Key|Community` but no `IsSecret` annotation. The audit doc suggested this as an alternative; the explicit map is simpler and easier to reason about for the current schema size.
- A migration that re-decrypts the historical `{enc}` blobs for the rows that were never secret. Such rows are not actually secret — they round-trip through `DecryptField` to the same value they had before encryption (since `DecryptField` is idempotent for ciphertext that fails the GCM auth, returning ""), so a re-decryption would silently zero out every threshold. **Do not** write a backfill migration without reading the CHANGELOG entry for v0.10.226 first.

QA: `go build ./...`, `go test -count=1 ./...` (10 pkgs, 161 tests, +2 AUDIT-026), `gofmt -l .`, `go vet ./...` all clean. Code-only change in `internal/api/handlers/handlers_settings.go` + new test file. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.262] - 2026-06-02

### Fixed — AUDIT-024: COOKIE_SECURE / SERVER_ENABLE_TLS mismatch is now caught at startup

Pre-AUDIT the example file (`config.env.example`) shipped with `COOKIE_SECURE=true` and `SERVER_ENABLE_TLS=false` as defaults. The runtime code path was actually smarter — `CookieSecure` falls back to `EnableTLS` when `COOKIE_SECURE` is unset — but the example was still wrong: a copy-paste of the example file would lock the operator into the exact mismatch that produces a silent-login-break.

The failure mode: with `COOKIE_SECURE=true` over plain HTTP, the browser drops the `Secure` cookie on every response. The operator clicks "Login", the form posts, the server returns a Set-Cookie with the `Secure` flag, the browser refuses to store it, the next request carries no session, the user lands back on the login page. The JavaScript console shows nothing. The server logs show a successful login. The operator files a bug saying "login button does nothing".

**The fix** (two parts):

1. **`config.env.example`** — the `COOKIE_SECURE=true` line is now commented out (`# COOKIE_SECURE=`) with a comment block explaining the inheritance rule and the failure mode. The default is to inherit from `SERVER_ENABLE_TLS`; operators who really want to override have to remove the `#` and consciously set a value.

2. **`internal/config/config.go`** — new field `Server.CookieSecureExplicit bool`, populated by checking `os.Getenv("COOKIE_SECURE") != ""`. `Validate()` now logs a multi-line, actionable warning when `CookieSecure && !EnableTLS && CookieSecureExplicit`:

   ```
   WARNING: COOKIE_SECURE=true is set explicitly, but SERVER_ENABLE_TLS=false.
            Browsers will silently drop the session cookie over plain HTTP, so
            login will appear to do nothing. Either set COOKIE_SECURE=false
            (recommended for plain-HTTP deployments), or enable TLS by setting
            SERVER_ENABLE_TLS=true and configuring SERVER_TLS_CERT / SERVER_TLS_KEY.
   ```

   The warning is intentionally not a `log.Fatal` — a reverse-proxy-in-front setup is a legitimate reason to run plain HTTP on the app and TLS at the edge. The point is to make the operator **consciously confirm** the mismatch, not to break a valid topology.

3. **Code-path detail** — the audit's third suggestion ("send HSTS with `max-age=0`") was rejected. `max-age=0` actively tells browsers to *un-learn* HSTS, which is wrong for a public release; a server that briefly served HTTPS shouldn't punish later HTTPS-only sessions.

**Regression tests** (`internal/config/config_audit024_test.go`, new — 4 cases):

- `TestValidate_CookieSecureMismatch_AUDIT024` — broken config (explicit `true` over plain HTTP) doesn't error; the warning fires.
- `TestValidate_CookieSecureInheritedFromTLS_AUDIT024` — consistent config (TLS on, Secure inherited) doesn't error; the warning does NOT fire.
- `TestValidate_CookieSecureExplicitlyFalseOverPlainHTTP_AUDIT024` — explicit `false` over plain HTTP is the correct plain-HTTP config; warning does NOT fire.
- `TestConfigExample_HasNoCookieSecureMismatch_AUDIT024` — static check on `config.env.example`: rejects `COOKIE_SECURE=true` when the file also contains `SERVER_ENABLE_TLS=false`. Comments are stripped first to avoid false-positives on a commented-out `#COOKIE_SECURE=true` line. The test will catch a future agent re-introducing the misleading example.

First test file for the `internal/config` package.

**What this does NOT do (deferred)**

- **Auto-correction** (silently flip `COOKIE_SECURE` to match `EnableTLS`). Rejected — a config that looks wrong but is intentional (e.g. `EnableTLS` flipped off for a brief debug session, with `COOKIE_SECURE` flipped off separately to match) shouldn't be silently mutated.
- **Strict-dynamic on the HSTS path** (related but out of scope for AUDIT-024; would touch the `SecureHeaders` middleware).

QA: `go build ./...`, `go test -count=1 ./...` (10 pkgs, 159 tests, +4 AUDIT-024), `gofmt -l .`, `go vet ./...` all clean. Config-only change, no static-binary rebuild needed unless `go build` is the deployment vector — Docker rebuild still recommended to keep the version label in sync.

## [0.10.261] - 2026-06-02

### Fixed — AUDIT-021: systemd units now run as non-root with full hardening

Pre-AUDIT, `deploy.sh` generated `fwmon-{api,poller,trap}.service` units that ran as `User=root` with no hardening directives. The Docker path already ran as the non-root `fwmon` user (the Dockerfile's `USER fwmon`), so the two deployment shapes were inconsistent — and the systemd shape was the worse one. Concretely:

- The API binary listens on a public-facing TCP port (8080) plus three UDP ports (162/514/6343). A future memory-corruption RCE in any of those listeners would give the attacker root on the host — not a hypothetical, this is a firewall-monitoring tool that talks to untrusted networks by design.
- The trap receiver binds `0.0.0.0:162` (SNMP TRAP). Even with the AUDIT-012 community check in place, a future bug in the SNMP parser would land the attacker in the root namespace.
- The poller talks to the DB and to remote firewalls; a process-compromise gets the entire DB and the cluster of managed devices' credentials.

This is exactly the threat model where systemd's sandbox directives pay for themselves.

**The fix** (`deploy.sh`):

1. **`create_service_user`** — new function that creates the `fwmon` system user with `--system --no-create-home --shell /usr/sbin/nologin --home-dir /var/lib/firewall-mon`. Idempotent: skips if the user already exists (preserves upgrades).
2. **`create_systemd_service`** — the unit template now runs as `User=fwmon Group=fwmon`, with the following hardening directives (each line carries a comment explaining the threat it addresses):
   - `NoNewPrivileges=yes`
   - `ProtectSystem=strict` + `ReadWritePaths=/var/lib/firewall-mon` (the only writable mount is the data dir)
   - `PrivateTmp=yes`
   - `ProtectHome=yes`
   - `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`
   - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (no AF_PACKET, no AF_NETLINK, no AF_KEY)
   - `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`
   - `MemoryDenyWriteExecute=yes` (defense-in-depth against JIT-shellcode)
   - `SystemCallArchitectures=native`, `SystemCallFilter=@system-service ~@privileged @resources`
   - `CapabilityBoundingSet=` and `AmbientCapabilities=` both empty — drop ALL Linux capabilities
3. **Ownership fix-up after install** — `chown -R fwmon:fwmon` on `${INSTALL_DIR}`, `${DATA_DIR}`, `${CONFIG_DIR}`. Config files go to `0640` (readable by fwmon only) — `JWT_SECRET_KEY` and `ENCRYPTION_KEY` should not be world-readable.
4. **Bash syntax validated** with `bash -n deploy.sh` (CI gate in the next commit will do the same).

**What this does NOT do (deferred)**

- **Socket activation** (`Type=notify` + `sd_notify`). The current `Type=simple` works but doesn't give systemd the crash signal. Low-priority hardening; the service is already covered by `Restart=always` with a 10s backoff.
- **DynamicUser=yes**. Would create a per-boot ephemeral user. We use a stable system user instead so the SQLite WAL survives reboots without ownership fixups.
- **systemd credential support** (`LoadCredential=`) for the JWT secret. Currently the secret is read from `/etc/firewall-mon/config.env` which is `0640 fwmon:fwmon`. The credentials framework is cleaner but requires switching to a credential-loading helper in `cmd/api/main.go` — out of scope.
- **Run a fresh `systemd-analyze syscall-filter`** against the binaries to discover any missing syscalls not in `@system-service`. Operators can run this after the first prod deploy and report any startup failures; the comment in `deploy.sh` points them at the right command.

**Operator migration**

After `deploy.sh install_local`:
- Three new files exist: `/etc/systemd/system/fwmon-{api,poller,trap}.service` (overwriting the old root-running ones).
- A new system user `fwmon` exists.
- `systemctl daemon-reload && systemctl restart fwmon-{api,poller,trap}` picks up the new units. The secrets file at `/var/lib/firewall-mon/.jwt-secret` (AUDIT-008) is preserved through the chown.

QA: `go build ./...`, `go test -count=1 ./...` (9 pkgs, 155 tests, unchanged for this commit — the change is shell-only), `bash -n deploy.sh`, `gofmt -l .`, `go vet ./...` all clean. Native-deploy only — Docker path was already non-root.

## [0.10.260] - 2026-06-02

### Fixed — AUDIT-019: IRC bot admin commands now have a real per-channel allow-list

Pre-AUDIT, `Bot.isAdmin(nick)` returned `true` only when the calling nick equaled the bot's own configured nick. Since the bot never `PRIVMSG`es itself, this meant **`AdminOnly: true` commands were effectively dead code in production** — no human IRC user could execute them, and no human IRC user ever had. Operators reading the source naturally assumed "admin only" meant "channel admins only"; in reality it meant "nobody".

Worse, the failure mode was silent: a typo in the admin config would result in a command that does nothing when invoked, with no error to the operator. The AdminOnly flag was functionally a guarantee of non-execution.

**The fix**

1. New `IRCChannel.AdminNicks` field (string, semicolon-separated list of nicks). Empty means "no admins" — fail-closed.
2. `Bot.isAdmin` now takes `(target, nick)` and consults the target channel's `AdminNicks` list. Case-insensitive match, whitespace-tolerant, empty-list deny.
3. Private messages to the bot (target == bot's own nick) are denied for admin commands. The bot has no global admin allow-list by design — operators who want PM-admin can extend this later if a real use case appears.
4. **The bot's own nick is NO LONGER auto-admin.** This is the only behavior change visible to existing deployments. Since no production code path was using the old "bot-self-as-admin" path, this is a safe removal.

**Wire format / migration**

- AutoMigrate adds the new `admin_nicks` column with `default:''`. Existing rows get an empty allow-list, which means existing channels' admin commands become disabled until an operator configures admins — this is the fail-closed default and matches the pre-fix behavior of "nobody can run admin commands".
- No data loss. The bot's previously-set nick on IRCServer is unchanged.

**Operator workflow**

In the admin UI, edit an IRC channel and set `Admin Nicks` to e.g. `alice;bob` (semicolon-separated). Admins can now execute `!reset`, `!config`, and any other `AdminOnly: true` commands in that channel. Other channels are unaffected — they remain admin-free until configured.

**Regression tests** (`internal/irc/bot_audit019_test.go`, new — 30 cases across 2 tests):

- `TestChannelNickAllowed_AUDIT019` (16 subtests): empty / whitespace / single / multi / case-insensitive / trailing-semicolon / leading-semicolon / double-semicolon / partial-match-rejection / whitespace-around-nicks. Covers the data-layer helper directly.
- `TestBot_IsAdmin_AUDIT019` (14 subtests): end-to-end through `Bot.isAdmin(target, nick)` with a stub `*models.IRCServer` containing three channels (`#ops` with admins, `#alerts` with no admins, `#mixed` with one admin). Covers the happy paths, the `#alerts` empty-list case, the bot-self-is-NOT-admin regression, PMs to the bot, unknown channels, and empty target.
- `TestBot_IsAdmin_NilServer_AUDIT019`: nil-Server guard so a partial init can't deref-panic.

First test file for the `internal/irc` package.

**What this does NOT do (deferred)**

- A separate `models.IRCAdmin` join table with a per-user audit trail. The audit doc offered this as an alternative; we went with the simpler field-on-channel for the same reason we use semicolon-separated nicks — most deployments have 1-2 admins per channel, and a join table is overkill until the feature needs RBAC granularity.
- Per-nick permission levels (read vs write vs destructive). Today's `AdminOnly: true` is a single bit. A real RBAC scheme would need a permissions model and a migration of every `IRCCommand` row. Out of scope for AUDIT-019.

QA: `go build ./...`, `go test -count=1 ./...` (9 pkgs, 155 tests, +30 AUDIT-019), `gofmt -l .`, `go vet ./...` all clean. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.259] - 2026-06-02

### Fixed — AUDIT-022: CSP nonce for inline scripts/styles (no more 'unsafe-inline')

Pre-AUDIT the admin/public UI shipped a CSP that allowed `'unsafe-inline'` for both `script-src` and `style-src`. With that flag, CSP provides *zero* XSS defense-in-depth — any HTML or JS injection point (query string reflected into a JS context, a future template bug, a third-party JS that builds a `<script>` string and assigns it via `innerHTML`, etc.) would execute freely. The flag was a stop-gap from the v0.10-era development, when the inline `<script>AdminCommon.renderSidebar()</script>` bootstrap call was the easiest way to get the sidebar wired. AUDIT-022 closed it by switching to a per-request nonce.

**What changed**

- `internal/api/middleware/middleware.go` — `SecureHeaders()` now:
  1. Generates a fresh 128-bit random nonce (`crypto/rand` → 16 bytes → base64 std encoding) on every request.
  2. Stores it on the gin context via `c.Set("csp-nonce", nonce)`.
  3. Emits the CSP header with `script-src 'self' 'nonce-<x>'` and `style-src 'self' 'nonce-<x>'` — `'unsafe-inline'` is gone.

- New `middleware.RenderHTML(c, code, name, data)` — drop-in replacement for `c.HTML`. It pulls the nonce from the context and wraps `data` in a `HTMLRenderData{Data, Nonce}` struct so the template can reference `{{ .Nonce }}`. All 22 `c.HTML(...)` calls in `cmd/api/main.go` are now `middleware.RenderHTML(...)`. Routes that bypassed this wrapper would render with `Nonce: ""` and the browser would block every inline block — the *loud* failure mode, not silent.

- New `middleware.GetCSPNonce(c)` — exported helper for any handler that builds HTML by hand (e.g. test fixtures, future email templates).

- `web/admin/*.html` and `web/public/index.html` — 16 inline blocks stamped with `nonce="{{ .Nonce }}"`:
  - admin.html: 2 style + 2 script (mobile menu, sidebar bootstrap)
  - connection-detail.html: 1 style + 1 script
  - device-detail.html: 1 style + 1 script
  - irc.html: 1 style + 1 script
  - probe-pending.html: 1 script (no inline style)
  - probes.html: 1 style + 1 script
  - sites.html: 1 style + 1 script
  - public/index.html: 1 style (no inline script — all external)
  - login.html: 0 (no inline blocks; skipped)

**Why nonce, not SHA-256 hash**

Both nonce and hash are valid CSP defense mechanisms. Nonce was chosen because:
- The 8 inline scripts include `AdminCommon.renderSidebar()` which calls functions that change with each version — managing a SHA-256 allow-list of every `AdminCommon.*` invocation would mean updating the allow-list on every admin release.
- Nonce requires zero maintenance; the cost is the 22-byte-per-response header growth and a 16-byte random source per request.
- 128 bits of entropy gives a collision bound of 2^64 requests — well past the 24-hour key-rotation budget of any realistic attack.

**Backward compatibility**

- The CSP change is fail-closed: any inline block that was *not* stamped with a matching nonce (e.g. a forgotten inline `<script>` in a future page) will be blocked by the browser, not silently allowed. This is the desired security posture — operators see the regression immediately rather than having it discover itself via incident response.
- All inline `style="..."` attributes (e.g. `<div style="display:flex;">`) are unaffected — attribute styling is not subject to CSP `style-src` (it's subject to `style-src-attr`, which we deliberately do not set).
- `script-src` still lists `'self'`, so external `<script src="/static/js/...">` references continue to work.

**Regression tests** (16 new test cases across 2 packages):

`internal/api/middleware/csp_nonce_test.go` (new, 9 tests):
- `TestSecureHeaders_CSPNoLongerAllowsUnsafeInline_AUDIT022` — headline: `'unsafe-inline'` is gone, nonces are in `script-src` and `style-src`, both are equal.
- `TestSecureHeaders_NonceIsFreshPerRequest` — 5 sequential requests produce 5 distinct nonces (collision resistance).
- `TestSecureHeaders_OtherHeadersPreserved_AUDIT022` — the AUDIT-025 headers (X-Content-Type-Options, Permissions-Policy, etc.) are intact.
- `TestSecureHeaders_CSPHasAllExpectedDirectives` — `default-src`, `connect-src`, `img-src`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, `frame-ancestors 'none'` all still present.
- `TestSecureHeaders_HSTSOnlyOnTLS` — pre-existing HSTS-over-TLS-only behavior is unchanged.
- `TestGetCSPNonce_ReturnsStoredValue` and `TestGetCSPNonce_MissingReturnsEmpty` — the helper works in both states.
- `TestRenderHTML_InjectsNonceIntoTemplateData` and `TestRenderHTML_NilDataStillExposesNonce` — the wrapper handles real data and `nil` data identically.
- `TestNewCSPNonce_FormatAndEntropy` and `TestNewCSPNonce_ConcurrentSafe` — 100 serial + 200 concurrent calls all return valid 16-byte nonces with no collisions.

`internal/api/handlers/csp_nonce_html_test.go` (new, 1 test × 9 subtests):
- `TestAllHTMLFiles_StampNonceOnEveryInlineScriptAndStyle_AUDIT022` — full integration: loads each HTML file from disk, parses it as a template, renders it through a real gin engine with `middleware.SecureHeaders` + `middleware.RenderHTML`, then verifies the response body's inline `<script>`/`<style>` tags each carry a `nonce="..."` attribute that *exactly matches* the nonce in the response's CSP header (after HTML-entity decoding, which is what the browser does on parse). This test would catch a missing nonce, a typo in `{{ .Nonce }}`, a route that uses `c.HTML` instead of `RenderHTML`, or any other class of mistake that would produce a blank admin page in production.

**What this does NOT do (deferred)**

- `'strict-dynamic'` — would let the browser trust nonces from trusted scripts at runtime, simplifying the JS bundle ordering. Not needed for this commit; would require switching all `<script defer>` to `<script>` (eager) which changes load order.
- `report-uri` / `report-to` — would let the browser POST a JSON violation report to `/api/csp-report`. Deferred: requires new endpoint, new handler, new model. AUDIT-110.
- SHA-256 hash fallback for static inline blocks that are *truly* unchanging across deploys (e.g. the bootstrap sidebar call). Not currently exercised — every inline block now uses a nonce.

QA: `go build ./...`, `go test -count=1 ./...` (8 pkgs, 125 tests, +9 AUDIT-022), `gofmt -l .`, `go vet ./...` all clean. Static-binary change → requires `docker compose up -d --build` or rebuild the binary. Server-repo only.

## [0.10.258] - 2026-06-02

### Fixed — AUDIT-009: encryption key rotation now possible (key chain)

Pre-AUDIT the encryption layer held exactly one key (`Database.encKey []byte`). The first time an operator rotated the JWT secret — deliberately, or by accident via env-var typo — every `{enc}<base64>` stored credential (SNMP, IRC, SMTP) became permanently unreadable. AUDIT-008 closed the *accidental* case by persisting the auto-generated secret; AUDIT-009 closes the *deliberate* case by allowing multiple decryption keys to coexist.

**New type** `keyChain` in `internal/database/crypto.go`:

```go
type keyChain struct {
    current []byte   // used for encrypt; tried FIRST on decrypt
    legacy  [][]byte // tried IN ORDER after current on decrypt
}
```

**Refactor**: `Database.encKey []byte` → `Database.encKeys keyChain`. All Encrypt* helpers use `d.encKeys.current` (encrypt is always with the current key, never a legacy one). All Decrypt* helpers use `d.encKeys` and call the new `decryptFieldWithChain` — current key tried first (the common case for newly-encrypted data), then each legacy key in order. First successful GCM auth wins; if every key fails, the AUDIT-027 fail-closed contract holds and the function returns `""`.

**Backward compatibility**:

- The wire format is unchanged (`{enc}<base64>` — no version prefix). Single-key deployments behave identically to v0.10.257 (chain has 1 entry, decrypt tries once).
- The single-key `decryptField(ciphertext, key)` function is retained as a thin shim over `decryptFieldWithChain` — every existing AUDIT-027 test exercises the chain through the single-key path with zero source changes.

**Operator workflow for rotation** (documented in `config.env.example` and in code comments):

1. Save the current `ENCRYPTION_KEY` value.
2. Set `ENCRYPTION_KEY` to the new value.
3. Set `ENCRYPTION_KEY_HISTORY` to the old value (comma-separated, newest historical first if multiple rotations stack).
4. Restart — new writes use the new key; old reads fall through the chain.
5. Optional: run `cmd/keyrotate` (planned, separate commit) or re-save each setting in the admin UI to re-encrypt under the new key, then drop the old entry from `ENCRYPTION_KEY_HISTORY`.

Without step 5, the rotation is incomplete in the strict sense (old key still required for old data) but **operationally safe** — no data loss, no auth failures, gradual cutover.

Regression tests (`internal/database/crypto_keychain_test.go`, new):

- `TestDecryptFieldWithChain_LegacyKeyRotated_AUDIT009` — the canonical case: encrypt with key A, then decrypt under `keyChain{current: B, legacy: [A]}` → succeeds.
- `TestDecryptFieldWithChain_CurrentKeyTriedFirst` — fast path stays fast.
- `TestDecryptFieldWithChain_AllKeysFailReturnsEmpty` — AUDIT-027 fail-closed contract holds across multi-key.
- `TestDecryptFieldWithChain_TriesAllLegacyKeysInOrder` — middle-of-chain key still reached.
- `TestDecryptFieldWithChain_NoKeysReturnsEmpty` — empty chain fails closed.
- `TestDecryptFieldWithChain_NonEncryptedPassThrough` — legacy plaintext rule preserved through chain.
- `TestKeyChain_All_OrdersCurrentFirst` / `TestKeyChain_All_SkipsEmpty` / `TestKeyChain_HasAny` — chain primitives.

All 9 pre-existing AUDIT-027 tests in `crypto_test.go` continue to pass via the single-key shim — exercised under both code paths.

**What this does NOT do (deferred — separate commit):**

- `cmd/keyrotate` one-shot re-encryption migration tool. Operators wanting to fully retire an old key today need to re-save each `{enc}` row through the admin UI. A bulk migration tool is queued.
- Per-row `keyVersion` column in `models.SystemSetting`. Not strictly needed under the try-each-key strategy — the AUDIT recommended it as one option, this commit takes the other.

QA: `go build ./...`, `go test -count=1 ./...` (8 pkgs, 116 tests, +9 keychain), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.257] - 2026-06-02

### Fixed — AUDIT-006 (shutdown half): batcher no longer loses items at Stop, has a Dropped counter

The pre-AUDIT batcher had a subtle shutdown race documented in `docs/AUDIT.md`:

> `Stop()` calls `Flush()` after `<-b.doneCh` returns, racing with concurrent `Add()` from handlers.

The trace: HTTP handler in flight → handler calls `b.Add()` → concurrent `b.Stop()` closes `stopCh` → goroutine sees `stopCh`, immediately closes `doneCh`, exits → `Stop()`'s `<-doneCh` unblocks → handler's `Add` runs (appends to buf) → `Stop()` calls `Flush()` (flushes) → `Stop()` returns. Then a SECOND handler calls `Add` AFTER Stop returned and the goroutine is gone — the items sit in `buf` until process exit and are lost.

Two changes close the race:

1. **`stopped atomic.Bool` set BEFORE close(stopCh).** `Add` checks the atomic on entry (fast path) AND under the lock (re-check to defeat the read-then-stop interleave). Items added after `Stop()` is called are rejected and counted on `Dropped`. The handler always returns quickly — no infinite waits.
2. **Final Flush runs inside the goroutine BEFORE close(doneCh).** `Stop()` blocks on `<-doneCh` and so returns only after the final flush has completed. The post-`<-doneCh` Flush in `Stop` is gone — that's what was racing with concurrent Add.

Plus three operational features:

- `Stop()` is now idempotent via `CompareAndSwap` — double-Stop never panics on close-of-closed-channel.
- New `Dropped() int64` method returns the count of items rejected after Stop. Wired into the future `/metrics` endpoint (AUDIT-077).
- The atomic-recheck-under-lock pattern is documented inline because it's a common subtle mistake (single fast-path check leaks items past Stop's "everything flushed" guarantee).

Regression tests (`internal/database/batcher_test.go`, new — replaces the no-tests-at-all state for this file):

- `TestBatcher_AddFlushesAtMaxSize` — buffer triggers immediate flush at maxSize.
- `TestBatcher_StopDrainsBuffer_AUDIT006` — 10 items added then Stop → all 10 reach flushFn before Stop returns.
- `TestBatcher_AddAfterStopRejected_AUDIT006` — 3 items added post-Stop → none reach flushFn, all counted in Dropped.
- `TestBatcher_StopIdempotent` — second + third Stop calls don't panic.
- `TestBatcher_ConcurrentAddDuringStop_AUDIT006` — 10 goroutines × 100 items × Stop mid-stride → conservation invariant: `len(flushed) + Dropped() == total`. Some items will land in flushed, some in dropped depending on interleave; none are silently lost.
- `TestBatcher_FlushOnTick` — items below maxSize get flushed by the ticker.
- `TestBatcher_FlushErrorLoggedNotPropagated` — flushFn returning error doesn't crash the batcher.
- `TestBatcher_DroppedReflectsExactCount` — 47 post-Stop adds → Dropped() == 47.

**What this does NOT do (deferred — AUDIT-006 durability half):**

- No write-ahead log to disk. SIGKILL / OOM still loses the unflushed in-memory buffer (up to `maxSize` × `flushInterval` worth of data). The fix requires designing an on-disk format with fsync and a recovery-on-startup path; that's a separate, larger commit. For now the shutdown-race window is closed (the realistic data-loss case under graceful shutdown / restart), and operators can avoid the SIGKILL case by not using SIGKILL.
- No `maxBytes` cap. Currently the buffer can grow without bound if flushFn is failing — by `maxSize` items per iteration. Less urgent than the shutdown race; tracked separately.

QA: `go build ./...`, `go test -count=1 ./...` (8 pkgs, 107 tests, +8 batcher), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.256] - 2026-06-02

### Fixed — AUDIT-007: cross-process poller leader lock

`cmd/poller/main.go`'s 3 cron tickers — `pollAllDevices` (every `SNMP.PollInterval`, default 60s), the 5-minute rollup of `RunFlowRollupCycle` + `RunSyslogAggregationCycle`, and the 24-hour `CleanupOldData` + `CleanupConfigRevisions` + `EnsurePartitions` + `ConfigureAutovacuum` + `PruneExpiredCooldowns` block — all ran without coordination across processes. Under a 2-poller deployment (the "I want HA" or "I have a rolling deploy in flight" case) both processes did all the work: 2× SNMP load on every device, 2× alerts (the cooldown map is per-process so dedup fails across processes), 2× daily report emails, 2× row-lock contention on the cleanup cron.

Mirroring the existing `tryAcquireStartupLock` pattern (`internal/database/database.go:170`), I added a per-tick Postgres advisory lock:

- **New methods**: `Database.TryAcquirePollerWorkLock() bool` and `Database.ReleasePollerWorkLock()`. Both use a stable int64 key (`0x504f4c4c45525357` — visible as "POLLERSW" in `pg_locks` if an operator inspects it). On SQLite (tests / single-process dev) the methods are no-ops returning true / no-op respectively.
- **New helper in cmd/poller**: `runUnderLeaderLock(taskName, fn)` wraps a tick handler: try the lock, log `"Skipping <task>: another poller holds the work lock"` if it fails, otherwise `defer ReleasePollerWorkLock()` and run `fn`. All three ticker branches now go through it.

Failure semantics:

- Lock acquired → work runs, lock released on return (defer covers panic).
- Lock contested → tick skipped; next tick retries. Net behaviour: exactly one of N pollers does each work cycle.
- Lock-probe SQL error → bias toward DOING the work (duplicate poll cycle is recoverable; missed one is not). Logged.
- Process crash between acquire and release → session-scoped lock auto-released at `SetConnMaxLifetime` (5 min) — one tick window of degraded service.

Regression tests (`internal/database/poller_lock_test.go`, new):

- `TestPollerWorkLock_SQLiteAlwaysAcquires` — on SQLite both Acquire calls return true (no actual lock); Release is a no-op and safe to double-call.
- `TestPollerWorkLock_ReleaseAfterAcquireDoesNotPanic` — exercises the documented `defer db.ReleasePollerWorkLock()` pattern.

Cross-process Postgres semantics are NOT directly unit-tested here because the test harness runs in SQLite (AUDIT-118's production/test parity gap). The functional contract is in the doc comments on `TryAcquirePollerWorkLock`; integration coverage will land with AUDIT-118's testcontainers-go harness.

Operator action: none. The single-poller deployment is unaffected (no other poller contends, every lock acquires). Two-poller deployments now self-resolve to one effective poller.

QA: `go build ./...`, `go test -count=1 ./...` (8 pkgs, 99 tests), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.255] - 2026-06-02

### Added — AUDIT-004 (partial): CI workflow + Makefile

`.github/workflows/ci.yml` runs on every push and pull request to `master`/`main`. Two jobs:

- **build-test**: verifies `go.mod`/`go.sum` are tidy, enforces `gofmt -l . | (! grep .)` (AUDIT-075 / AUDIT-152), runs `go vet`, builds all four binaries, runs `go test -race -count=1 -timeout=5m ./...` (AUDIT-121 — race detector finally lands in CI).
- **vuln-scan**: installs `govulncheck` and scans every dependency for known CVEs (AUDIT-018 — surfaces stale-dep risk to the maintainer instead of leaving it for operators).

`Makefile` mirrors the same gates locally so contributors can run `make qa` before pushing (CONTRIBUTING.md already prescribed `gofmt -l . | (! grep .)` etc.; this makes it one command). Other targets: `make test`, `make test-race`, `make build`, `make vet`, `make fmt`, `make tidy`, `make vuln`, `make clean`, `make docker`, `make version`.

`go.mod` collateral cleanup: `github.com/glebarez/sqlite` was marked `// indirect` but is actually imported by `internal/database/testing.go`; CI's `go mod tidy` check would have failed without this fix, so I ran tidy and committed. Also added `google/pprof` to `go.sum` (transitive of the race detector / testing pkg).

**What this does NOT cover from AUDIT-004**:

- `.github/workflows/release.yml` (tag-triggered release flow) — out of scope without a goreleaser config + a sense of where binaries should land (GitHub Releases? Docker registry?).
- `.goreleaser.yml` — needs a sign-off on the artefact layout.
- `.golangci.yml` enabling `staticcheck` / `errcheck` / `ineffassign` / `unused` / `gosec` — separate commit because each linter typically flags real issues that need triage / waivers.
- One-time `git tag -a v0.10.X` backfill — operator decision.
- `-trimpath -buildvcs=false -ldflags=-X main.ServerVersion=${VERSION}` build flags (AUDIT-102) — Dockerfile change, separate commit.

QA: `go build ./...`, `go test -race -count=1 ./...` (8 pkgs, race-clean), `go vet ./...`, `gofmt -l .` all clean locally. CI YAML validated by inspection (no `actions/setup-go` deprecation warnings, no `ubuntu-latest` removal-list packages). Server-repo only.

## [0.10.254] - 2026-06-02

### Added — AUDIT-002 (LICENSE doc reference) + AUDIT-003 + AUDIT-011: public-release governance documents

Six new top-level docs covering the open-source housekeeping the audit called out as deployment blockers. Pure documentation; no binary rebuild required.

- **`THIRD-PARTY-NOTICES.md`** (AUDIT-003) — inventories every vendored browser-side asset (Chart.js 4.4.7, chartjs-plugin-zoom 2.0.1, uPlot 1.6.31, Cytoscape.js 3.30.4, cytoscape-fcose 2.2.0, cose-base 2.2.0, layout-base 3.1.0, Gridstack.js 10.3.1, Tailwind CSS, Inter font, JetBrains Mono font) and every direct Go dependency from `go.mod` with version, license (MIT / BSD-2 / BSD-3 / Apache-2.0 / OFL-1.1), copyright line, source URL, and (where vendored) the file path. Includes the full text of every license that applies — required by the attribution clauses of MIT / BSD / OFL.
- **`SECURITY.md`** (AUDIT-011 part 1) — GitHub-recognized vulnerability disclosure policy with the standard "don't open public issues" preamble, response-time SLOs (5 business days to ack, 10 for assessment, 30 for HIGH/CRITICAL fix), 90-day default disclosure, supported-versions table, scope/out-of-scope sections, operator hardening guidance pointing at the audit doc, and a hall-of-fame stub.
- **`CONTRIBUTING.md`** (AUDIT-011 part 2) — dev environment requirements (Go 1.24, Postgres 14+ optional, Node 20 for Tailwind only), in-scope vs out-of-scope work, branch + PR workflow, the **mandatory QA gate** (`go build` / `go test -count=1` / `gofmt -l` / `go vet` — and optional `-race`), CHANGELOG / version-bump / AUDIT.md update steps, commit message style with a working example from v0.10.246, code-style rules (no new global state, no new browser libraries without `THIRD-PARTY-NOTICES.md` update), and a dedicated security-sensitive-contributions section pointing back at `SECURITY.md`.
- **`CODE_OF_CONDUCT.md`** (AUDIT-011 part 3) — Contributor Covenant v2.1 verbatim, with the contact-method placeholder pointed at `SECURITY.md`.
- **`README.md`** — replaced the bare `MIT` license line with proper links to `LICENSE`, `THIRD-PARTY-NOTICES.md`, plus a new "Contributing & community" section linking the four new docs and the audit doc.

This unblocks the AUDIT-011 deployment-blocker (no security disclosure path, no contributor on-ramp, no Code of Conduct) and the AUDIT-003 deployment-blocker (8 vendored libraries + 2 fonts carry attribution clauses that were not honoured).

Still open from the AUDIT-011 fix list (deferred — different scope):

- `.well-known/security.txt` route (AUDIT-112).
- `.github/ISSUE_TEMPLATE/*.yml` and `PULL_REQUEST_TEMPLATE.md` (AUDIT-163).
- `.github/CODEOWNERS` (AUDIT-163).
- `docs/OPERATIONS.md` runbook (AUDIT-111).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Docs-only change → no rebuild required. Server-repo only.

## [0.10.253] - 2026-06-02

### Fixed — AUDIT-005: trap-receiver and poller now have a real DB + matching ENC key

Two related fixes for the multi-process secret-derivation problem.

**AUDIT-005**: `cmd/trap-receiver/main.go:29` passed `nil` to `alerts.NewAlertManager`. `am.saveAlert` (`alerts.go:532-539`) is a no-op when `db==nil`, so every trap that arrived was logged to stdout and immediately dropped on the floor. The trap-batcher's buffer in the API process was never written to either (the trap-receiver has its own process, not shared memory).

Fix: trap-receiver now calls `database.NewDatabase(cfg)`, hands the result to the AlertManager, and `defer db.Close()`s on shutdown. `alertManager.RefreshThresholds(db.Gorm())` is called the same way `cmd/api` and `cmd/poller` do so threshold lookups don't hit the DB on every alert.

**AUDIT-008 (multi-process completion)**: `cmd/trap-receiver` and `cmd/poller` opened DBs without first loading the persisted JWT secret. Each derived a DIFFERENT AES key — same DB, three keys. SMTP password / SNMP creds / IRC secrets saved through the admin UI were decryptable from `cmd/api` but garbage from the other two processes. The v0.10.252 fix only ran in `cmd/api`.

Fix: hoisted the `secrets.LoadOrGenerate(cfg.Server.JWTSecretKey, secretsDir, ".jwt-secret")` call to the top of `main()` in both `cmd/trap-receiver` and `cmd/poller`. All three processes now derive identical ENC keys from `/data/.jwt-secret`.

**Concurrent first-start race fix**: the three processes start in parallel from `entrypoint.sh:106-115`. On a fresh `/data` volume all three see the secret file as missing and would race to write three different secrets, then race to read whichever won the filesystem write — leaving two processes with mismatched in-memory copies. `secrets.LoadOrGenerate` now uses `os.OpenFile(..., O_CREATE|O_EXCL|O_WRONLY, 0o600)` so exactly one process wins; the others receive `os.ErrExist`, re-read the file, and use the winner's value. Best-effort empty-file cleanup (`_ = os.Remove(path)`) before the create attempt closes the "old empty file blocks new generate" footgun the AUDIT-008 test caught.

Regression tests:

- `internal/secrets/secrets_test.go::TestLoadOrGenerate_ConcurrentRaceSafe` — 16 goroutines all calling `LoadOrGenerate("", tmpdir, ".jwt-secret")`. Asserts exactly one returns `Generated`, the other 15 return `FromFile`, and all 16 values are identical. Fails loud with "AUDIT-008 race regression" if any pair diverges.
- `internal/secrets/secrets_test.go::TestLoadOrGenerate_EmptyFileTreatedAsMissing` — existing-but-empty file regenerates cleanly (the empty-file cleanup path).

QA: `go build ./...`, `go test -count=1 ./...` (8 pkgs, 96 tests), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Operator action: same as v0.10.252 (re-enter encrypted creds after upgrade, since the new shared key replaces three previously-divergent random keys). Server-repo only.

## [0.10.252] - 2026-06-02

### Fixed — AUDIT-008: JWT secret and admin password now persist across restarts

`cmd/api/main.go` previously regenerated both the JWT signing secret and the auto-generated admin password on every restart if their env vars were unset. The downstream damage:

- **JWT secret**: a new in-memory secret on each start invalidates every existing login JWT. Worse, the AES-256 key for `{enc}<base64>` stored credentials (SNMP, IRC, SMTP) is derived from the same secret via SHA-256 (`internal/database/database.go:82` `deriveKey(cfg.Server.JWTSecretKey)`), so a regenerated key made **every encrypted credential in the DB permanently unreadable**.
- **Admin password**: `getDefaultPassword()` cached a fresh random per `config.Load()` call, but `db.InitAdmin` only sets the bcrypt hash on the FIRST run. Result: on restart the operator saw a brand-new "AUTO-GENERATED ADMIN PASSWORD" printed in the logs that did NOT match the existing DB hash — and got locked out with no recovery path.

The previous `os.WriteFile("/data/.admin-password", ...)` attempt at persistence was best-effort — if the write failed, the code silently continued with an in-memory-only password the operator could never recover.

**New package** `internal/secrets` (10 unit tests):

- `LoadOrGenerate(envValue, baseDir, filename) (value, source, err)` — env > file > generate+persist, with fatal-on-IO-error semantics.
- `PersistGeneratedPassword(pw, baseDir, filename) (written, err)` — write-once helper for the admin-password flow (existing files are NEVER overwritten so a manually-edited file is honoured).
- `LoadPassword(baseDir, filename) (pw, ok, err)` — read-only counterpart for the load-side.

**`cmd/api/main.go` wiring**:

- `SECRETS_DIR` env (default `/data`) chooses where secrets live. Override for non-Docker installs.
- JWT secret: `LoadOrGenerate("", "/data", ".jwt-secret")` runs at startup. First run generates + persists chmod 0600. Subsequent runs reload the same value.
- Admin password: if env empty, attempt to load `/data/.admin-password`. If present, override the config-generated default. If absent (true first run), persist the just-generated default with `PersistGeneratedPassword`. Any I/O failure is `log.Fatal` — no silent fallback.
- Stopped logging the masked password (`pw[:3] + "***" + pw[len(pw)-3:]`) — that was a separate finding (AUDIT-137: 6 chars of the auto-generated password leaked into container logs narrowed brute-force space). Now the log directs operators to the chmod-0600 file instead.

`config.env.example` updated to explain both env vars + `SECRETS_DIR`.

QA: `go build ./...`, `go test -count=1 ./...` (8 packages, 95 tests), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`.

**Operator action required** on upgrade:

- If `JWT_SECRET_KEY` was previously unset and the volume `/data` survives the upgrade: existing `{enc}` ciphertext was already broken by the regenerate-on-restart bug — the new `.jwt-secret` file generated on first run after upgrade will be a fresh key, so any existing `{enc}` values stored under previous random keys remain unreadable. Re-enter SMTP / SNMP credentials in the admin UI after upgrade.
- If `JWT_SECRET_KEY` IS set in env: nothing changes — env value still wins.
- For brand-new installs: `/data/.jwt-secret` and `/data/.admin-password` will be created chmod 0600 on first start. Treat them like SSH host keys: back them up, don't share them.

Server-repo only. Also collaterally closes AUDIT-137 (no longer logs masked password).

## [0.10.251] - 2026-06-02

### Fixed — AUDIT-083: per-IP rate limiter is now capped + has a Stop() hook

`internal/api/middleware/middleware.go`'s `ipRateLimiter` had two scaling defects:

1. **Map had no size cap.** An attacker spraying unique source IPs (trivial with X-Forwarded-For when behind an untrusted proxy, or an IPv6 /64 walk) could grow `limiters` to millions of entries and OOM the process. The 5-minute stale-prune loop took 5 minutes to react, far longer than any flood.
2. **Cleanup goroutine had no shutdown hook.** Started with `go rl.cleanup()` at construction, never stopped. Process exit terminated it (via OS), but tests that constructed-and-discarded limiters leaked one goroutine per test — and any future code that wants to recycle a limiter at runtime had no way to release the resource.

Both fixed:

- New `maxRateLimiterEntries = 50000` cap (≈ 7.5 MiB headroom). `getLimiter` evicts the LRU entry when at cap, before inserting the new one. The LRU is a `container/list` doubly-linked list — `MoveToFront` on access, `Back()` is the eviction target. Amortized O(1).
- New `Stop()` method closes `rl.quit`; the cleanup goroutine `select`s on `ticker.C` or `quit` and returns cleanly.
- Reworked stale-prune loop to walk the LRU from the back (oldest first) and stop on the first not-expired entry, instead of scanning the whole map — O(stale-count) instead of O(map-size).

Wire-through note: `RateLimiter`, `PublicRateLimiter`, and `LoginRateLimiter` still return raw `gin.HandlerFunc`s and do not expose Stop. The cap addresses the OOM half of the audit; surfacing Stop on the public API requires returning a struct that bundles handler + stop, which is a larger refactor not in scope here. Tracked as a follow-up.

Regression tests (`internal/api/middleware/ratelimit_test.go`, new):

- `TestIPRateLimiter_GetLimiter_NewIPCreatesLimiter` — basic happy path.
- `TestIPRateLimiter_GetLimiter_SameIPReusesLimiter` — repeated calls share state (rate limits accumulate).
- `TestIPRateLimiter_LRUEviction_AUDIT083` — fills cap, touches one IP to make it MRU, asserts the LRU (not the touched one) is evicted on overflow.
- `TestIPRateLimiter_LRUEviction_ManyOverflow` — 3 × cap inserts; map size never exceeds cap; last `cap` IPs survive.
- `TestIPRateLimiter_Cleanup_RemovesStale` — back-dates 3 entries, drives a cleanup pass inline, asserts the fresh entry survives and the 3 stale ones are gone.
- `TestIPRateLimiter_Stop_TerminatesGoroutine` — second `Stop()` panics on close-of-closed-channel (proves the first Stop actually closed it).
- `TestIPRateLimiter_Concurrent` — 100 goroutines × 100 calls under cap=50; final size ≤ cap; lru length == map length (no divergence under race).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.250] - 2026-06-02

### Fixed — AUDIT-012: trap receiver is no longer an open relay

`internal/snmp/trap.go:46` had this short-circuit:
```go
if t.config.SNMP.TrapCommunity != "" && packet.Community != t.config.SNMP.TrapCommunity {
    return
}
```
When `SNMP_TRAP_COMMUNITY` was empty (or unset), the whole check was skipped and **every** UDP packet on port 162 was accepted, parsed, and stored as a trap event with `SourceIP = packet.SourceIP`. An attacker spoofing source IPs could inject thousands of bogus alerts, mask real outages, or just OOM the trap-event table.

Three changes:

1. **Fail-closed config**: `TrapReceiver.Start` now refuses to listen when `SNMP_TRAP_COMMUNITY` is empty: `"SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string"`. Operators who want the listener disabled should not run the `trap-receiver` daemon at all.
2. **Constant-time community compare**: replaced `packet.Community != expected` with `subtle.ConstantTimeCompare`. Closes a byte-by-byte timing oracle that let a network attacker recover the prefix length of any guessed community.
3. **Per-source-IP token-bucket rate limit**: 10 traps/sec sustained, burst 50, applied BEFORE the community check so a flooding attacker can't burn CPU on the crypto / parser. The IP map is capped at 10,000 entries to prevent unbounded growth under unique-source-IP spraying — when the cap is hit, *new* IPs are rejected (logged as drops); existing buckets continue to refill and serve.

The defaults (10/s, burst 50, cap 10k) are tight enough that a spoofed flood needs ~6,000 unique source IPs/min to sustain even 1,000 trap rows/sec; loose enough that a chassis link-flap storm from a real device stays within budget.

`config.env.example:36` now documents the requirement with an AUDIT-012 reference.

Regression tests (`internal/snmp/trap_test.go`, new — first test file for the SNMP package, closes part of AUDIT-117):

- `TestTrapReceiver_Start_RequiresCommunity` — empty community → Start returns error mentioning `SNMP_TRAP_COMMUNITY`.
- `TestTrapReceiver_Allow_BurstThenRefill` — first `burst` calls succeed; the next fails; after a refill window, one more succeeds.
- `TestTrapReceiver_Allow_PerIPIsolated` — draining IP A's bucket does not affect IP B's bucket (spoofing-defense requirement).
- `TestTrapReceiver_Allow_MapCapped` — fills the map to `maxRateLimitedIPs`, asserts the (cap+1)th NEW IP is rejected while EXISTING tracked IPs still serve.
- `TestTrapReceiver_Allow_ConcurrencySafe` — 50 goroutines × 5 calls under a burst of 10 → exactly 10 succeed (locking is neither too loose nor too tight). Race-detector compatible; runs under `-race` in CI once AUDIT-121 / AUDIT-004 land.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Operator action required: confirm `SNMP_TRAP_COMMUNITY` is set if running the trap-receiver daemon. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.249] - 2026-06-02

### Fixed — AUDIT-013: `TestIRCServer` now SSRF-gated (and validates port)

`POST /admin/api/irc/test` accepted an arbitrary `server_host` from the request body and dialed it via `irc.NewTestBot(...).Connect()` with **no** SSRF allow-list — even though sibling `TestProbeConnection` (`handlers_probes.go:351`) and `TestEmail` (`handlers_settings.go:667`) have called `isValidExternalIP` since v0.10.140. An admin (or anyone who phished an admin session cookie) could turn the endpoint into an internal port-scanner against the monitor's LAN — loopback, RFC 1918, link-local, the AWS metadata endpoint at `169.254.169.254`, etc.

Changes (`internal/api/handlers/handlers_irc.go:437`):

- Reject ports `< 1` or `> 65535` with 400 (mirrors the validation in `TestProbeConnection`).
- Run the host through `isValidExternalIP` and 400 with "Invalid or disallowed server host" if it resolves to a blocked range.

Regression tests (`internal/api/handlers/handlers_irc_audit013_test.go`, new):

- `TestTestIRCServer_RejectsSSRFTargets_AUDIT013` — 13 sub-cases covering IPv4/IPv6 loopback, unspecified, link-local (incl. `169.254.169.254`), RFC 1918 / RFC 4193, `localhost` name, and an unresolvable `.invalid` host. All must return 400 and mention "disallowed" or "invalid" in the body.
- `TestTestIRCServer_RejectsInvalidPort` — 2 sub-cases (negative, > 65535) must return 400.
- `TestTestIRCServer_RejectsMissingHost` — `binding:"required"` catches the empty case.

Side-effect on the package: this is the first test file for the IRC handler family (previously 0% coverage on `handlers_irc.go` — closes part of AUDIT-117).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.248] - 2026-06-02

### Fixed — AUDIT-086: HTTP listener errors no longer skip graceful shutdown

The listener goroutine in `cmd/api/main.go:226` called `log.Fatal` if `ListenAndServe[TLS]` returned anything other than `http.ErrServerClosed`. `log.Fatal` calls `os.Exit(1)` immediately, which **skips every `defer`** registered earlier in `main`: `defer ircManager.Stop()`, `defer snmpClient.Close()`, and the deferred `cancel` for the JWT-prune ticker. Result: bind-conflict / cert-load failure → IRC bot left connected with a half-open SASL session, SNMP socket leaked, batchers not flushed.

The same pattern existed at the post-signal `server.Shutdown` call (`cmd/api/main.go:248`). A 10-second shutdown timeout, plus `log.Fatal` on overrun, also skipped the defers.

Both paths now use the same graceful-shutdown sequence:

- Listener goroutine writes the error onto a buffered `errCh` (no `log.Fatal`).
- Main goroutine `select`s on either the signal channel or `errCh`, logs which one fired, then runs `server.Shutdown`.
- `server.Shutdown` failure logs the error and returns normally so the deferred `ircManager.Stop` / `snmpClient.Close` / `cancel` all run before the process exits.

No automated test (would require integration-level harness: spawn a real `http.Server` and trigger a bind-conflict mid-flight); the change is small and obvious from inspection. Manually verified: rebuilt, started, sent SIGTERM — saw "Received signal terminated, shutting down server..." → "Server exited" with all defers logged.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.247] - 2026-06-02

### Fixed — AUDIT-015: CORS `*` rejected at startup when Allow-Credentials=true

The CORS middleware always sends `Access-Control-Allow-Credentials: true` (cookie-based admin session). Combining that with a wildcard `Access-Control-Allow-Origin: *` is forbidden by the CORS spec (browsers drop the response) AND is dangerous because the old code reflected the requesting origin verbatim when the configured list contained `*` — letting any third-party site issue authenticated cross-origin requests against the admin API once an operator was logged in.

Changes:

- Extracted origin parsing into `parseCORSAllowedOrigins(raw string) (map[string]bool, error)` for testability.
- The helper returns an error if any entry in `CORS_ALLOWED_ORIGINS` is `*` (after `strings.TrimSpace`).
- `CORS()` calls `log.Fatalf` on that error so the server refuses to start with an unsafe config.
- Removed the `origins["*"]` short-circuit from the per-request path (no longer reachable, but defense-in-depth).

Regression tests (`internal/api/middleware/cors_test.go`, new):

- `TestParseCORSAllowedOrigins_WildcardRejected` — 5 sub-cases (bare `*`, `*` mixed with a real origin, `*` with leading/surrounding whitespace, `*` in the middle of a list) all return an error mentioning both `*` and `credentials`.
- `TestParseCORSAllowedOrigins_ValidInputs` — 9 sub-cases for happy paths and edge cases (empty / whitespace-only / one origin / two origins / surrounding whitespace trimmed / empty entries skipped / trailing comma / port suffix / http vs https as distinct origins) returning the expected map.

`internal/api/middleware` now has its first test file (was 0% coverage — closes part of AUDIT-117).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Operator action required if they had `CORS_ALLOWED_ORIGINS=*`: replace with an explicit comma-separated allow-list. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.246] - 2026-06-02

### Fixed — AUDIT-016: probe registration key compared in constant time

`validateProbe` in `handlers_probes.go:606` compared the presented Bearer token to the stored registration key with a plain Go `!=`. Go string comparison short-circuits at the first mismatching byte, so a network attacker on the LAN can in principle reduce the key search space by measuring how long the server takes to reject a wrong token. We replaced the comparison with `subtle.ConstantTimeCompare`, which (a) returns `0` if the lengths differ and (b) compares all bytes of equal-length inputs without short-circuiting.

Changes:

- `internal/api/handlers/handlers_probes.go`: added `crypto/subtle` import; `validateProbe`'s post-PK-lookup token check now uses `subtle.ConstantTimeCompare([]byte(token), []byte(probe.RegistrationKey)) != 1` with an explanatory comment referencing AUDIT-016.

Scope note: `authenticateProbeByBearer` (the only other key-check site, used by `ProbeHeartbeat`) looks the probe up directly by `WHERE registration_key = ?` against an indexed column. The DB engine's hash-bucket compare for that lookup is constant-ish, but the underlying lookup is still a timing channel for "token exists" vs "token does not exist". A complete fix requires restructuring the heartbeat protocol to carry an explicit probe ID (so we can fetch by PK and then constant-time-compare). That is tracked under AUDIT-017 (probe key stored in plaintext) and will be addressed when the at-rest encryption / hashed-token refactor lands. The validateProbe path patched here is the higher-leverage one — it is invoked by **18 ingestion handlers** vs. heartbeat's single call site.

Regression tests (`handlers_probes_audit016_test.go`, new):

- `TestValidateProbe_ConstantTimeKeyCompare_AUDIT016` — 9 sub-cases asserting the behavioral contract: correct key accepted; same-length flipped-byte (last/first/middle) all rejected; shorter-by-one / longer-by-one rejected; uppercase-cased rejected; empty rejected; whitespace-padded rejected. Timing assertion is not feasible in CI but every variant a naive `==` could short-circuit on is covered.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.245] - 2026-06-02

### Fixed — AUDIT-027: `decryptField` no longer returns ciphertext on decryption failure

This is the **v0.10.226 bug class** patched at its other doorway. v0.10.226 stopped `UpdateSettings` from gating decrypt on a never-persisted `IsSecret` flag, so the *normal* read path stopped sending `"{enc}<base64>"` to remote servers as a credential. But the failure paths inside `decryptField` itself still leaked the ciphertext back to the caller: if the JWT key changed, the DB was tampered with, or the ciphertext was truncated, the function dutifully returned the raw `"{enc}<base64>"` string and any caller (SMTP, IRC, SNMP) then transmitted it verbatim to the remote server. Postfix logged it; Dovecot logged "Password mismatch"; the operator chased their tail for days.

**Behavior change** (`internal/database/crypto.go:57`):

| Condition | Before | After |
|-----------|--------|-------|
| No `{enc}` prefix (legacy plaintext) | return unchanged | return unchanged *(unchanged)* |
| `{enc}` prefix, no key configured | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, bad base64 | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, AES setup error | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, GCM setup error | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, ciphertext shorter than nonce | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, GCM auth failure | return ciphertext + WARNING log | return `""` + ERROR log |
| `{enc}` prefix, decrypt success | return plaintext | return plaintext *(unchanged)* |

A caller that previously logged "535 wrong password" and stayed up will now log "no password / empty credential" instead, which is loud and points the operator at the underlying DB / key issue. The ciphertext bytes never leave the process under any failure mode.

**Regression tests** (`internal/database/crypto_test.go` — new):

- `TestDecryptField_RoundTrip` — 7 inputs (empty / single char / words / 4 KiB / Unicode / control chars) round-trip cleanly. This is the startup-test the audit asked for.
- `TestDecryptField_LegacyPlaintextPassthrough` — 6 non-prefixed inputs pass through unchanged so the v0.10.226 idempotency contract still holds.
- `TestDecryptField_NoKeyReturnsEmpty` — both `nil` and `[]byte{}` keys with a real ciphertext yield `""` and never the `{enc}` prefix.
- `TestDecryptField_WrongKeyReturnsEmpty` — encrypt with key A, decrypt with key B → `""` (the AUDIT-027 primary case).
- `TestDecryptField_BadBase64ReturnsEmpty` — 4 malformed payloads (illegal bytes, padding errors, control chars, embedded whitespace).
- `TestDecryptField_TamperedCiphertextReturnsEmpty` — flip a byte in valid ciphertext → `""`.
- `TestDecryptField_ShortCiphertextReturnsEmpty` — `{enc}YWJj` (3 bytes < 12-byte nonce) → `""` (no panic).
- `TestEncryptField_AlreadyEncryptedIsIdempotent` — double-encrypt is a no-op.
- `TestEncryptField_EmptyOrNoKeyPassthrough` — empty plaintext and nil key both pass through.

Database package now has its first test file (was 0% coverage — closes part of AUDIT-117).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.244] - 2026-06-02

### Fixed — AUDIT-014: SMTP critical-alert subject is now sanitized at build time

`BuildCriticalAlertEmail` (`internal/report/email.go:94`) formatted the Subject directly from `device.Name`, `device.IPAddress`, and `alert.AlertType` with no CR/LF sanitization. The downstream `notifier.SendHTMLEmail` did sanitize the final header values (line 299 of `notifier.go`), so a header-injection escape was *already blocked* in production — but the audit's defense-in-depth recommendation is to also sanitize at the **construction** site so that any future caller (or any future `Send*Email` path that forgets the sanitize step) cannot fold attacker-controlled CRLF into mail headers.

Changes:

- New `notifier.SanitizeHeader(s string) string` exported helper (`internal/notifier/notifier.go:25`). Strips CR and LF bytes — the only characters that fold an SMTP/HTTP header into two.
- `notifier.go:283` replaces the inline closure with a reference to the exported helper, so there is exactly one definition of "what does sanitize do" across the project.
- `report/email.go:94` now calls `notifier.SanitizeHeader` on `alert.AlertType`, `device.Name`, and `device.IPAddress` before `fmt.Sprintf`.

Regression tests:

- `internal/notifier/notifier_test.go` — `TestSanitizeHeader_StripsCRLF` (11 table cases including a literal `Bcc: attacker@evil.com` payload) + `FuzzSanitizeHeader` (property: result never contains CR or LF, ~180k execs in 3s).
- `internal/report/email_test.go` — `TestBuildCriticalAlertEmail_SubjectSanitizesCRLF` builds a critical alert with CRLF-laden `Device.Name`, `Device.IPAddress`, `Alert.AlertType` and asserts the returned subject contains none of `\r`/`\n` while still preserving the visible substrings (`CPU_HIGH`, `router-1`, `10.0.0.1`).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Notifier package now has its first test file (previously 0% coverage — closes part of AUDIT-117).

Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.243] - 2026-06-02

### Added — `LICENSE` (MIT) + AUDIT-002 / AUDIT-010 / AUDIT-023 / AUDIT-025 / AUDIT-122

Five small audit items, batched because each is a one-or-two-line change with no functional risk:

- **AUDIT-002** — added top-level `LICENSE` with standard MIT text (`Copyright (c) 2026 Firewall-Mon Contributors`). README has claimed MIT since v0.10.140 but no license file shipped; without it, Berne Convention defaults the codebase to All Rights Reserved.
- **AUDIT-010** — `internal/config/config.go:247`: changed `PROBE_SERVER_URL` default from `https://stats.technicallabs.org` to `""`. The probe binary itself already required the env var (`cmd/probe/main.go:67` fails if empty), but the hardcoded third-party domain in the server config was a public-release smell. Server side does not actually consume `cfg.Probe.ServerURL` anywhere — this is defensive cleanup.
- **AUDIT-023** — `cmd/api/main.go:216`: added `ReadHeaderTimeout: 10 * time.Second` on the HTTP server. `ReadTimeout` was 30s but `ReadHeaderTimeout` was unset, so a slow-loris attacker holding partial headers could tie up a goroutine per connection up to the existing 30s body limit. 10s is conservative for the longest practical real header.
- **AUDIT-025** — `internal/api/middleware/middleware.go:253`: added `Permissions-Policy` header denying camera, microphone, geolocation, USB, payment, accelerometer, gyroscope, magnetometer, midi, sync-xhr. The admin panel has no use for any of these; sending the deny header tells the browser to block them even if a future UI bug accidentally calls one.
- **AUDIT-122** — `internal/api/handlers/handlers_config_revision_retention_test.go:282`: deleted the 60-line `_unused_legacy_top50_test` orphan that was left in place with a leading underscore when the old retention policy was removed.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change (the header/timeout are baked into the API binary) → requires `docker compose up -d --build`. Server-repo only.

## [0.10.242] - 2026-06-02

### Fixed — AUDIT-074 + AUDIT-075: project-wide gofmt sweep and line-ending normalization

`gofmt -l .` flagged 14 files as unformatted, and `internal/irc/bot.go` had CRLF line endings inconsistent with the rest of the tree. Both were captured by AUDIT-074 and AUDIT-075 in `docs/AUDIT.md` and are now resolved with a single `gofmt -w .` pass.

Files reformatted (whitespace-only — `git diff -w` returns empty):

- `internal/api/handlers/handlers_config_diff_test.go`
- `internal/api/handlers/handlers_data.go`
- `internal/api/handlers/handlers_devices.go`
- `internal/api/handlers/handlers_probes.go`
- `internal/configdiff/normalize.go`
- `internal/configdiff/validate.go`
- `internal/configdiff/vendor_cisco_asa.go`
- `internal/configdiff/vendor_fortigate.go`
- `internal/configdiff/vendor_generic.go`
- `internal/configdiff/vendor_paloalto.go`
- `internal/irc/bot.go` (also normalized CRLF → LF)
- `internal/ping/ping.go`
- `internal/snmp/snmp.go`
- `internal/snmp/vendor_firewalla.go`

After this commit, `gofmt -l .` returns empty. AUDIT-152 (CI gofmt enforcement) is the natural follow-up — once the CI workflow exists (AUDIT-004) it should fail on any new unformatted file.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...` all clean. Static-binary change → requires `docker compose up -d --build` to reach a deployment. Server-repo only.

## [0.10.241] - 2026-06-02

### Fixed — AUDIT-001: test files are now tracked in git

`*_test.go` was excluded by `.gitignore:9`, which silently dropped **two regression-net test files** (`internal/configdiff/normalize_test.go`, `internal/report/report_test.go`) from every public clone. Recent CHANGELOG entries (v0.10.236, 0.10.238, 0.10.239) all cited those tests as the regression net — but downstream clones got an empty net.

Removed the `*_test.go` line from `.gitignore` and added the two formerly-hidden files. After this commit, `git ls-files | grep _test.go` returns 11 tracked test files (was 9).

Per the audit doc workflow: AUDIT-001 marked Resolved in `docs/AUDIT.md`. No code changes, no rebuild required (tracked tests do not affect runtime binaries). Server-repo only.

## [0.10.240] - 2026-06-02

### Added — public-release audit document (`docs/AUDIT.md`)

Comprehensive pre-release audit covering security, stability, code quality, frontend, database/architecture, testing/CI, docs/operations, and feature recommendations. **170 findings** (11 CRITICAL deployment blockers, ~70 HIGH-priority, ~25 MEDIUM/LOW) and **89 feature recommendations** (top 10 for v0.11.0 called out separately).

Each finding has a stable ID in the form `AUDIT-NNN` for commit-message tracking and a "Resolved findings" table at the bottom of `docs/AUDIT.md` for progress tracking. Workflow: fix the issue, reference the ID in the commit message, add a row to the Resolved table, append to the Progress log.

**Top 3 fixes to land first** (each unblocks downstream work):

- **AUDIT-001** — remove `*_test.go` from `.gitignore` and `git add -f` the two regression-net test files: `internal/configdiff/normalize_test.go` (631 LOC) and `internal/report/report_test.go` (192 LOC). Public clones currently lose them silently. Recent CHANGELOG entries (v0.10.236, 0.10.238, 0.10.239) cite these as the regression net; the net doesn't exist for downstream users.
- **AUDIT-002** — add `LICENSE` (MIT text). README claims MIT but no license file ships, so the project is "All Rights Reserved" by default under Berne Convention.
- **AUDIT-010** — change `PROBE_SERVER_URL` default to `""` (currently hardcodes `https://stats.technicallabs.org`).

**Other critical findings called out:** no CI / no git tags (AUDIT-004), trap-receiver drops every trap silently (AUDIT-005), batcher not crash-durable (AUDIT-006), no poller leader lock (AUDIT-007), auto-generated JWT secret breaks AES decrypt on restart (AUDIT-008), crypto key rotation impossible (AUDIT-009), no SECURITY.md / no runbook (AUDIT-011).

**Notable high-priority frontend bugs confirmed reproducible:** `probes.html` modals render on first paint (AUDIT-046), Logout link dead on `/admin/irc` (AUDIT-047), `.section-tab` redefines display nullifying the v0.10.230 `.hidden` fix (AUDIT-048), IRC tab nav active state never updates (AUDIT-049), `admin-irc.js` not IIFE-wrapped (AUDIT-050), CSP allows `'unsafe-inline'` for script+style (AUDIT-022).

Docs-only change → no rebuild required. Server-repo only.

## [0.10.239] - 2026-05-30

### Improved — traffic spikes are now summarized by interface, not listed per event

A busy link can spike 30+ times in a window, and the report listed every one as its own card — a wall of events, not a summary. Spikes are now **aggregated per device+interface** into a single row showing: event **count** (e.g. `31×`), **peak throughput**, **worst severity** (critical/warning, with a `(N critical)` note when mixed), and the **time window** (`May 30 02:14 – 14:31`). Rows sort critical-first, then by event count.

The fleet **Bandwidth & Traffic** section leads with a headline — `37 spikes on 3 interfaces · 14 critical · 23 warning` — then the top 8 interface rows, with a `+ N more interfaces with spikes` overflow line. Each device's own card shows the same summary scoped to that device (top 6 interfaces, device name omitted).

Implementation: new `SpikeGroup` + `groupSpikes()` aggregation and `windowLabel()` (replacing the per-event `SpikeCard`) in `internal/report/model.go`; new `spikegroup` template row (replacing `spike`) in `template_report.go`. Tests: `TestGroupSpikes` covers aggregation, critical-first sort, window labels, and the cap/overflow; the render test now asserts the summarized spike section appears.

Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.238] - 2026-05-30

### Fixed — report spike timestamps all showed "Jan 1 00:00"

Traffic-spike cards in the executive report rendered every timestamp as `Jan 1 00:00` (the Go zero time). `parseBucketTime` (`internal/report/data.go`) only tried layouts **with seconds** (RFC3339, `2006-01-02 15:04:05`), but the dialect `TimeBucket` helpers emit buckets via `to_char`/`strftime` **without seconds** — minute = `2006-01-02 15:04`, hour = `2006-01-02 15:00`, day = `2006-01-02` (see `internal/database/dialect.go`). No layout matched, so every parse fell back to the zero time. Added the secondless minute/hour/day layouts (first in the try-list); kept the seconds/RFC3339 variants for raw timestamps.

`internal/report/report_test.go` now feeds `computeTraffic` the real Postgres minute-bucket format and asserts the parsed bucket time is non-zero, so this can't regress.

Spike values/severities and all other report data were already correct — this was display-only. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.237] - 2026-05-30

### Fixed — Reports page "Failed to load report: res.json is not a function"

The new admin Reports page (v0.10.236) failed on **View** and **Send Now** with `res.json is not a function`. `admin-reports.js` chained `.then(res => res.json())` onto `AdminCommon.apiFetch(...)`, but `apiFetch` **already parses the body and resolves to the JSON object** (it calls `res.json()` internally at `admin-common.js:179`) — so the second `.json()` ran against a plain object. Removed the redundant `.json()` step at both call sites (preview + send); the resolved value is now consumed directly as `{success, data}`.

Also bumped the `Dockerfile` `org.opencontainers.image.version` label (was stale at `0.10.235`) to match the release.

This is a static-JS fix embedded in the binary, so it requires a container rebuild to reach a deployment (`docker compose up -d --build`). Server-repo only.

## [0.10.236] - 2026-05-29

### Redesigned email/summary report — one self-contained executive report, viewable + exportable from the admin panel

The daily/weekly email report was a `multipart/related` message with go-chart PNGs embedded via `Content-ID`. Outlook and several clients list those inline images as **separate attachments** — the "mix of text and multiple individual files" complaint. The charts were basic and, worse, the bandwidth section was fundamentally broken (details below). There was also no way to see the report without waiting for the scheduled email.

This rewrite replaces it with a single, modern, **image-free** report rendered entirely from email-safe HTML/CSS, delivered three ways from one template: the scheduled email, a new **Reports** page in the admin panel, and browser print-to-PDF.

#### The bandwidth detection was mathematically wrong — now fixed
`interface_stats.in_bytes`/`out_bytes` store the **raw cumulative SNMP octet counter** (`ifHCInOctets`), not a per-interval delta. The old report fed that monotonically increasing counter straight into:
- **Spike detection** (`DetectTrafficSpikes`) — running rolling std-dev on an always-increasing series means the latest sample is permanently far above the rolling mean. It fired constantly and reported meaningless raw byte counts ("12345 bytes at 15:04").
- **Top interfaces** (`GetTopInterfacesByTraffic` `SUM(in_bytes)`) — summing a cumulative counter is not bytes-transferred.

Now traffic is derived from **consecutive counter deltas** (`computeTraffic` in `internal/report/data.go`), with negative deltas clamped for counter resets/32-bit wrap. This yields honest **bytes transferred** (telescoping delta sum), **peak/avg throughput** (bits/sec), a throughput **sparkline**, and spike detection that runs on the *throughput* series (`detectSpikesInSeries`) and reports rates ("842.0 Mbps at …"), not counter values.

#### What the new report contains
- **Fleet KPI cards** — devices, online/offline, alerts, critical, fleet uptime %.
- **Bandwidth & Traffic** — peak throughput + total transferred chips, fleet **Top Talkers** horizontal bars, and traffic **spike callouts** as styled cards.
- **Alert timeline** — pure HTML/CSS column histogram (ported off go-chart).
- **Per-device detail** — KPI mini-grid, uptime bar, throughput sparkline, interface bars, spikes. Collapsible (`<details>`) in the admin preview; always-open in email.

#### Admin panel — new Reports page
- Sidebar **System → Reports** (`/admin/reports`).
- **View** (renders the report into an isolated iframe via `document.write` — robust against the `frame-src`-less CSP), **Export PDF** (browser print of the iframe; print CSS expands all device blocks and hides UI chrome), **Download HTML** (self-contained single file), **Send Now** (emails the report immediately, reusing the Test-Email SMTP path + SSRF guard).
- New endpoints: `GET /admin/api/reports/preview?period=daily|weekly`, `POST /admin/api/reports/send`.

#### Email is now a single message with zero attachments
`Notifier.SendHTMLEmail` sends a plain `text/html` message (8bit) when there are no attachments, instead of an empty `multipart/related` wrapper — so compliant clients show one clean message. The `multipart/related` path is retained for critical-alert emails, which still embed one CPU/Memory image.

#### Internal refactor
- New: `internal/report/model.go` (pure-data `ReportModel` + `BuildReportModel`), `template_report.go` (single email-safe HTML template + `RenderReportHTML`), `format.go` (`autoScale` moved out of `charts.go` + `formatBytes`/`formatThroughput`), `internal/api/handlers/handlers_reports.go`.
- `internal/report/data.go` now gathers raw series instead of pre-rendered PNGs; `email.go` `BuildDailyReport`/`BuildWeeklyReport` return `(subject, html, err)`; `charts.go` trimmed to `RenderCPUMemChart` (go-chart now used only for critical-alert emails); old `dailyTemplate` removed.
- `Handler` gains a `notifier` + `version` (injected in `cmd/api/main.go`); `ServerVersion` → `0.10.236`.
- Tests: `internal/report/report_test.go` covers counter-delta math, formatters, throughput-series spike detection, and a render smoke test asserting no `cid:`/`<img>` in the output.

#### Verification
- `go build ./...`, `go vet`, and `go test ./...` all pass (new report tests green).
- Server-repo only — no collector changes.

## [0.10.235] - 2026-05-19

### Fixed — 23 redundant `class="hidden"` tokens on `.modal` / `.tab-content` elements (deferred from v0.10.233)
v0.10.233 flagged ~21 HTML elements where `class="hidden"` appeared alongside `class="modal"` or `class="tab-content"`, both of which already default to `display: none` in admin-shared.css. The v0.10.233 audit explicitly deferred the cleanup ("risk of accidentally dropping a needed class on a 21-element sweep outweighs the latent-trap value"). This entry does the sweep carefully — verified element-by-element, with one specificity trap caught.

#### Why it's a real bug, not just style smell
The same shape — class-based show/hide that "works today" because of specificity but breaks if anyone touches the rules — has bitten us in v0.10.230 (connection-detail tabs), v0.10.231 (IRC SASL fields), and v0.10.232 (login error banner). Each landed silent UI regressions on operators. The redundant `hidden` on these 23 elements is the same trap class on the HTML side — `.modal.active { display: flex }` (specificity 0,2,0) currently beats `.hidden { display: none }` (0,1,0), but if Tailwind ever ships `.hidden { display: none !important }` (a real possibility in future Tailwind versions and a frequent monkey-patch), every modal in this repo would silently fail to open.

#### Files touched
- `web/admin/admin.html` — alerts-bulk-ack-modal.
- `web/admin/sites.html` — site-modal (special case, see below).
- `web/admin/probes.html` — probe-modal, deploy-modal.
- `web/admin/connection-detail.html` — tab-content-src-tunnels, tab-content-dst-tunnels, tab-content-phase2, tab-content-flows.
- `web/admin/device-detail.html` — tab-vpn, tab-sensors, tab-processors, tab-alerts, tab-ping, tab-ha, tab-security, tab-sdwan, tab-licenses, tab-config, tab-processors-ssh, tab-iface-err (12 tabs).
- `web/admin/irc.html` — tab-channels, tab-commands, tab-send.

Total: 4 modals + 19 tab-content elements = 23 elements (audit said 21; was off by 2).

#### The `sites.html:42` specificity trap caught during the sweep
`site-modal` was the one element where `hidden` was NOT purely redundant. It had `class="modal hidden flex …"`. In the compiled tailwind.css, `.flex { display: flex }` is declared AFTER `.modal { display: none }` — same specificity (0,1,0), source-order tiebreak means `.flex` wins. So `hidden` was actually the only thing keeping the modal hidden on page load (also at specificity 0,1,0 but declared after `.flex`). Removing just `hidden` would have rendered the site Add/Edit modal visible-on-load.

Fix: removed BOTH `hidden` AND `flex` from `site-modal`. `.modal.active { display: flex }` (added by `openModal()`) already provides flex layout when the modal is opened; the bare `.modal` default of `display: none` keeps it hidden at rest. This is the correct shape — same as the other three modals that had `items-center justify-center` but no explicit `flex`.

#### Verification
- `.modal { display: none }` confirmed in `admin-shared.css:506` AND in compiled `tailwind.css` (which loads after admin-shared.css). `.modal.active { display: flex }` likewise.
- `.tab-content { display: none }` confirmed in `admin-shared.css:524` and `connection-detail.html:39` (inline). `.tab-content.active { display: block }` likewise.
- `openModal()` in `admin-common.js:644` adds `.active`. No other modal show-path exists in the codebase (grep confirmed).
- `switchTab()` adds `.active` to the matching tab-content. No other show-path exists.
- No JS in `cmd/api/static/js/` or `web/` reads `classList.contains('hidden')` against any of the 23 elements — the `hidden` class was dead-code for state checks too.
- No tests reference `modal hidden` or `tab-content hidden` HTML strings (grep confirmed).
- `go build ./...` clean, full test suite green.

#### What was NOT touched
The 24 unrelated `.hidden` classes on non-modal/non-tab-content elements (empty-state placeholders, hidden inputs, error banners that use `classList.toggle('hidden')` correctly per v0.10.232's fix). Those are load-bearing — they're the JS's primary mechanism for show/hide on plain divs. Only the 23 elements where `hidden` was actively shadowed by a stronger rule were cleaned up.

## [0.10.234] - 2026-05-18

### Fixed — backend zero-value Save footgun (deferred from v0.10.233 audit)
The v0.10.233 sweep noted three handler-level instances of the same bug class that v0.10.226 had finally diagnosed in `UpdateSettings`: a struct decoded directly from the request body, then handed to `db.Save`, will UPDATE every column — so any field absent from a partial PUT lands as a Go zero-value and silently wipes the existing column. This entry fixes the three remaining handlers:

#### 1. `UpsertDeviceAlertConfig` (`handlers_alert_policies.go:226`)
Previous flow: `var cfg models.DeviceAlertConfig; c.ShouldBindJSON(&cfg); db.UpsertDeviceAlertConfig(&cfg)`. PUT `{"cpu_threshold": 95}` on a device with full thresholds and a policy binding would, after the save, leave that device with:
- `memory_threshold = 0`, `disk_threshold = 0`, `session_threshold = 0`, `cooldown_minutes = 0`
- `alerts_enabled = false` (because Go bool zero is false — alerts were silently disabled by editing CPU)
- `policy_id = NULL` (the device fell back to the default policy)

Fix: load the existing row first, bind the JSON onto it, then save. `encoding/json` (which `c.ShouldBindJSON` wraps) only writes struct fields that ARE present in the body, so untouched columns keep their values. If the row doesn't exist yet, seed `&DeviceAlertConfig{DeviceID:id, AlertsEnabled:true}` so the "create on first edit" path keeps the model's intended default.

Defensive `cfg.DeviceID = id` after binding prevents a client from rewriting the foreign key via the request body.

#### 2. `UpsertSiteAlertConfig` (`handlers_alert_policies.go:328`)
Identical pattern, identical fix. `SiteAlertConfig` has no `AlertsEnabled` column (site configs always apply when present), so the create-if-absent path just seeds `&SiteAlertConfig{SiteID:id}`. The threshold/cooldown surface mirrors the device handler.

#### 3. `UpdateMaintenanceWindow` (`handlers_maintenance.go:73`)
The most visible of the three. Previous flow loaded `existing` only as an "does this ID exist?" check, then bound the request body into a FRESH `MaintenanceWindow` and called `Save`. Any field absent from the PUT body wiped the row: `recur_rule`, `recur_days`, `alert_types`, `notes`, `suppress_all`, `recurring`. A user editing just the end time of a weekly maintenance window would lose the entire recurrence schedule on save.

Fix: `Gorm().First(&window, id)` to load directly into `window`, bind JSON onto it, then save. Re-asserts `window.ID = id` after binding to prevent PK rewrite.

#### 4. Shared threshold validation (`validateAlertConfigThresholds`)
Both alert-config upserts gained range validation that was previously absent — CPU/memory/disk must be 0-100, session and cooldown must be non-negative. Previously the UI could (and during one debug session in v0.10.232 nearly did) persist 200% CPU or negative thresholds.

#### Tests
Six new tests in `handlers_partial_update_test.go` lock the fix in:
- `TestUpsertDeviceAlertConfig_partial_update_preserves_other_fields` — seeds a full config, PUTs `{"cpu_threshold": 95}`, asserts every other column survives. This test FAILS against the v0.10.233 code.
- `TestUpsertDeviceAlertConfig_rejects_invalid_threshold` — PUTs `cpu_threshold: 150`, expects 400.
- `TestUpsertDeviceAlertConfig_creates_when_absent` — verifies `AlertsEnabled` defaults to `true` on insert.
- `TestUpsertSiteAlertConfig_partial_update_preserves_other_fields` — same shape, site variant.
- `TestUpdateMaintenanceWindow_partial_update_preserves_other_fields` — seeds a recurring weekly window, PUTs only `end_time`, asserts `recur_rule`/`recur_days`/`alert_types`/`notes`/`suppress_all`/`recurring`/`device_id` all preserved.
- `TestUpdateMaintenanceWindow_rejects_end_before_start` — guards the existing validation.

### Why the bug kept reappearing
`db.Save(&struct)` is GORM's natural ergonomic API — it looks like "save this object." But its semantic is "UPDATE every column to the values currently in this object," which is fine when the object was loaded from the DB and then mutated, and catastrophic when the object came straight from JSON decoding (because absent fields are now Go zero-values masquerading as the user's intent). The canonical safe shape across this codebase is either (a) load-existing → bind onto it → save, used by these three handlers now, or (b) bind into a fresh struct → build an allow-listed `map[string]interface{}` → `db.Model(...).Updates(map)`, used by `handlers_devices.go`. Both patterns make the "field was not in the body" case observable.

## [0.10.233] - 2026-05-18

### Fixed — comprehensive bundle from 4-agent codebase sweep
Per the operator's "do a full pass of everything using sub agents — you keep finding all these random bugs and issues," I ran four parallel deep audits across the entire codebase looking for every variant of the bug classes fixed in v0.10.226–v0.10.232. Verified every HIGH finding against the source before patching (audits have been wrong twice — stale Tailwind in v0.10.230, "intentional" expandable-msg in v0.10.231 — so trust-but-verify is now mandatory). This entry is the consolidated bundle.

#### 1. Rich connection-detail side panel was unstyled (HIGH)
Clicking a connection on the network diagram (`/admin/connections`) renders a side panel with 5 sub-tabs (Overview / Tunnels / Phase 2 / Flows / Events) built by `diagram-panels.js:130-217`. The JS template uses CSS classes `rich-detail-panel`, `panel-header`, `panel-tabs`, `panel-tab`, `panel-tab-content`, `panel-flow-grid`, `panel-flow-card`, `tunnel-columns`, `tunnel-col` — **none of which were defined in any CSS file**. Result:
- The panel rendered as an unstyled block with no border, no padding, no tab strip.
- Critically, **`.panel-tab-content { display: none }` was missing**, so all 5 tab-contents rendered simultaneously, stacked vertically — clicking a tab added `.active` but never hid the other tabs. Same shape bug as v0.10.230's connection-detail orphan blocks, on a different surface.

Added the missing rules to `admin-shared.css`. The panel now has a proper card boundary, working tab strip with active-state underline, and only-the-active-pane visibility.

#### 2. IRC management page was unstyled (HIGH)
The whole `/admin/irc` server-card list (`admin-irc.js:75-103`) referenced `server-card`, `server-card-header`, `actions`, `server-info`, `channel-list`, `channel-tag`, `status-badge`, plus seven status-color classes (`status-connected`, `status-disconnected`, `status-connecting`, `status-error`, `status-joined`, `status-pending`, `status-left`) — zero CSS for any of them. Operators saw a wall of bare text with no card boundaries, action buttons crowded against each other, and connection-state text rendered in default-text color instead of colored pills. v0.10.231 fixed the IRC modals; this finally styles the page behind them.

Added all 14 missing rules. Status pills now use the same color palette as the existing `.badge.online`/`.badge.offline`/etc. for visual consistency.

#### 3. Probe / probe-pending card internals were unstyled (HIGH)
`admin-probe-pending.js:33-41` rendered pending-probe cards using `probe-header`, `probe-details`, `probe-actions` — undefined. The `.probe-card` outer was styled but the layout inside was raw block-flow, so headers and action buttons stacked unattractively. `admin-probes.js:105-111` used `actions` and `info-text` for the probe-list table's action button group and description text — also undefined. Added all five rules.

#### 4. Connection-detail tunnel-row expand chart had a 0-height container (HIGH)
When the user expands a tunnel row on `/admin/connections/:id`, `admin-connection-detail.js:199-206` injects `.tunnel-chart-wrap > .range-pills + .chart-container > canvas`. `.tunnel-chart-wrap` and `.chart-container` had no CSS, so the chart container had no `height` declared. Chart.js with `maintainAspectRatio: false` rendered to whatever height it found in the parent — which was 0 in a default table cell. Charts may have been silently rendering at zero height. Fixed by giving `.chart-container` a 220px fixed height and proper padding on the wrap.

#### 5. Interface-type / tunnel-type badge variants had no colors (HIGH-cosmetic)
JS emitted `<span class="badge vxlan">`, `<span class="badge tunnel">`, `<span class="badge lag">`, `<span class="badge ipsec">`, `<span class="badge l3ipvlan">`, etc. Only the base `.badge` rules existed, so all type pills rendered in the neutral grey of `.badge.unknown` — operators couldn't tell L2VLAN from VXLAN from Tunnel from LAG at a glance. Added color variants matching the existing palette: VXLAN/L3IPVLAN purple, Tunnel/IPSec/GRE/SSLVPN pink, LAG/Bond orange, L2VLAN/VLAN cyan, Ethernet/Physical blue.

#### 6. `Database.UpsertSetting` was the v0.10.226 bug verbatim (MEDIUM)
`internal/database/database.go:1478-1487` had the exact `FirstOrCreate` → copy 3 fields → `Save` shape that v0.10.226 spent four versions diagnosing in `UpdateSettings`. `IsSecret` and `Type` were never copied onto the existing row. The function has zero in-tree callers today, but it's exported on the public `*Database` API — anyone wiring a new caller (a future migration helper, an admin tool, a webhook receiver) inherits the bug. Fixed to mirror the canonical `UpdateSettings` pattern with all five fields copied.

#### 7. 17 latent `.hidden` + `style.display` traps in admin-device-detail.js (MEDIUM)
The empty-state placeholders for Interfaces, VPN, Sensors, Processors, Alerts, Ping, HA, Security, SD-WAN, Licenses, Config-History, Process Monitor, and Interface Errors tabs all toggled visibility via `empty.style.display = 'block'/'none'` against elements with `class="hidden"` in markup. Same trap as the connection-detail tabs (v0.10.230), IRC SASL fields (v0.10.231), login error banner (v0.10.232). Worked today only because inline `'block'` (specificity 1,0,0,0) beats `.hidden` (0,1,0). One `style.display = ''` refactor and every device-detail tab's empty state would silently break. Converted all 17 sites — plus the `#loading`/`#content`/`#error` initial-render toggles in `renderDevice` — to `classList.toggle('hidden')` so the markup's `hidden` class and the JS toggling agree on a single source of truth.

#### 8. Dead `error-msg` / `success-msg` banner markup deleted (LOW)
`probe-pending.html:31-32`, `probes.html:37-38`, and `sites.html:35-36` had `<div … id="error-msg">` / `id="success-msg"` div pairs that were never referenced by any JS — the corresponding admin-*.js files route errors and successes through the `AC.showError` / `AC.showSuccess` toast helpers. Six lines of dead markup deleted.

### Bugs found by audit but NOT fixed in this bundle
- **21 `.modal` / `.tab-content` elements with redundant `class="hidden"`** — same latent trap class as #7 but on the HTML side. Cosmetic only since `.modal.active` (specificity 0,2,0) currently beats `.hidden` (0,1,0). Deferred — risk of accidentally dropping a needed class on a 21-element sweep outweighs the latent-trap value. Worth a focused cleanup pass.
- **`UpsertDeviceAlertConfig` / `UpsertSiteAlertConfig` / `UpdateMaintenanceWindow` zero-value `Save` footgun** — three handlers call `db.Save(cfg)` with the bound request struct directly, so any field absent from the PUT body lands as Go zero-value (0 thresholds, `false` booleans, nil policy bindings). Real silent-data-loss class but the fix requires per-field merge logic that I'd want to scope tightly. Filed for a follow-up audit pass.
- **Slack/Discord/webhook URLs stored unencrypted** — design call, not a bug — they embed per-channel secrets in the path. Worth encrypting at rest like `smtp_password`. Out of scope here.

### Audits that came back CLEAN
- Pattern C (`onclick="..."` JS-string-literal escape bugs): one was fixed in v0.10.229 (`togglePublicIface`), zero remain.
- Pattern D (`innerHTML` writes with unescaped user-supplied data): all interpolations go through `esc()` / `escapeHtml()` / `window.escapeHtml()`. No XSS surface found.
- Pattern P1 (duplicate IDs across admin HTML): cleaned up by v0.10.230's connection-detail consolidation. Zero duplicate IDs remain anywhere under `web/admin/`.
- Pattern P2 (modals missing `.modal` class): zero remain after the v0.10.231 IRC + probe-pending fixes.
- Pattern P3 (orphan content blocks missing required class for switchTab): zero remain.

### Files
- Modified: `cmd/api/static/css/admin-shared.css` — added ~300 lines covering rich-detail-panel, IRC server cards, probe card internals, badge variants, tunnel-chart-wrap, scope-toggle.
- Modified: `internal/database/database.go` — `UpsertSetting` now copies `Type` + `IsSecret` onto the existing row before `Save`.
- Modified: `cmd/api/static/js/admin-device-detail.js` — 17+ `style.display` call sites switched to `classList.toggle('hidden')`.
- Modified: `web/admin/probe-pending.html`, `web/admin/probes.html`, `web/admin/sites.html` — deleted dead `error-msg` / `success-msg` banner markup.

## [0.10.232] - 2026-05-18

### Fixed — admin-login.js latent `.hidden` + `style.display` trap
Audit of `/admin/login` for the bug patterns from v0.10.230-231. Found one M1-level latent trap matching the same shape:

`admin-login.js:17/30/35` toggled the error banner with `errorDiv.style.display = 'block'/'none'`. The banner has `class="hidden"` in markup (`login.html:15`) and tailwind.css defines `.hidden { display: none }`. *It works today* only because inline `style.display = 'block'` (specificity 1,0,0,0) beats the `.hidden` class (0,1,0). But that's the exact footgun that hid the connection-detail Phase 2 / Traffic Analysis tabs (v0.10.230) and the IRC SASL fields (v0.10.231 M1) — any future refactor to `style.display = ''` (intending "clear the inline override and let the cascade decide") would silently break the error banner. Operators with bad credentials would see no feedback at all — the form would simply re-enable and stop pretending to log in.

**Fix:** switched to `errorDiv.classList.add('hidden')` / `.remove('hidden')` so the markup's `hidden` class and the JS toggling agree on a single source of truth.

#### Otherwise CLEAN
The login page is a single self-contained HTML file (`web/admin/login.html`, 37 lines) plus `admin-login.js` (43 lines). It loads only `tailwind.css`, no `admin-shared.css` or `admin-design-system.css`, so the cross-file specificity battles affecting the rest of the admin can't reach it. No modals (so no `.modal`-class-missing bug), no duplicate IDs, no orphan content blocks, no class-toggling-without-matching-CSS-rule, no `.stat-card` flex-row leak. The one finding was the latent trap above.

### Files
- Modified: `cmd/api/static/js/admin-login.js` — three call sites switched from `style.display` to `classList.add('hidden')`/`.remove('hidden')`.

## [0.10.231] - 2026-05-18

### Fixed — three more dead admin features uncovered by audit
After v0.10.230 fixed the connection-detail tab/duplicate-ID bugs, the operator asked me to sweep the rest of the admin area for the same patterns. The audit turned up three more **completely-broken features** plus one latent trap. Real bugs, not style smell.

#### 1. IRC modals never opened (Add/Edit Server, Add/Edit Channel, Add/Edit Command)
`web/admin/irc.html:120, 222, 290` declared `<div id="serverModal" class="… hidden …">` for the three IRC dialogs but **omitted the `modal` class**. `AdminCommon.openModal()` (`admin-common.js:610-644`) shows modals by adding `.active`, which the admin-shared `.modal.active { display: flex }` rule then matches. With no `.modal` class on the element, `.active` had no rule to trigger and `.hidden { display: none }` kept the dialog invisible. Clicking *Add Server*, *Edit Channel*, *Add Command* etc. fired the JS handler, the modal got its `active` class, and… nothing visibly happened. The entire IRC configuration UI was unreachable from the admin without backdoor edits (DB or env vars).

**Fix:** added `modal` to the class list of each dialog, removed the now-redundant `hidden` (the `.modal { display: none }` default in admin-shared.css already handles the initial state). The Tailwind utility classes that previously stood in for the modal layout — `fixed top-0 left-0 right-0 bottom-0 bg-black/60 z-[200]` — were kept; they continue to provide the overlay positioning while `.modal.active` toggles visibility.

#### 2. Probe-pending Reject dialog never opened
Same bug. `web/admin/probe-pending.html:40` had `<div class="hidden …" id="reject-modal">` with no `.modal` class. `admin-probe-pending.js:72` calls `AC.openModal('reject-modal')`. Same `.active`-without-`.modal` problem → dialog invisible. Operators clicking *Reject* on a pending probe got no feedback. (The Approve action on the same page worked because it didn't use a modal.)

**Fix:** identical to #1 — added `modal` class, removed `hidden`.

#### 3. Click-to-expand syslog/alert messages was a no-op
JS at `admin-main.js:3518-3520` toggles a `.expanded` class on `.expandable-msg` cells when clicked. The intent is clear: cells with long messages render truncated by default, click reveals the full text. But the cells were rendered with inline `style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"` (`admin-main.js:1106` for syslog, `:1736` for alerts). Inline styles have specificity 1,0,0,0 — *no class-based rule* can override them. There was also **no `.expandable-msg.expanded` rule defined anywhere** under `cmd/api/static/css/`, so even removing the inline style wouldn't have done anything. The feature had never worked in production.

Compounding the confusion: the v0.10.228 CHANGELOG explicitly absolved this case ("intentional click-to-expand truncation"). It was wrong — the click handler exists but the visual unwrapping doesn't.

**Fix:** dropped the inline `style=""` from both rendering call sites. The CSS class `.expandable-msg` (already declared in `admin.html:140` with `max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap`) carries the truncation now. Added `.expandable-msg.expanded { max-width: none; white-space: normal; overflow: visible; text-overflow: clip; word-break: break-word; overflow-wrap: anywhere; }` to actually unwrap the message on click. Clicking a truncated syslog or alert message now expands it inline; clicking again collapses it back.

#### 4. Latent trap fixed — IRC form SASL / status-interval pickers
`admin-irc.js:134` and `:331` set `style.display = 'block'/'none'` on `#saslFields` (the SASL credentials sub-form in the server dialog) and `#statusIntervalGroup` (the status-message interval input in the channel dialog). Both elements have `class="hidden"` in their markup. *Today this works*, because inline styles beat class selectors. But it's exactly the same trap that hid the connection-detail tabs for an unknown number of versions — the moment anyone refactored to use `style.display = ''` (intending "clear the inline override and let the cascade decide"), the fields would silently break and the operator would have no working SASL or status-interval configuration UI.

**Fix:** switched both to `classList.toggle('hidden', !cond)` so the markup's `hidden` class and the JS toggling agree on a single source of truth.

### Audit findings deliberately deferred
- **Redundant `hidden` on `.modal` dialogs that already work** (alerts-bulk-ack-modal on admin.html, site-modal on sites.html, probe-modal + deploy-modal on probes.html) — same pattern as #1/#2 but `.modal.active { display: flex }` already wins over `.hidden`, so they function correctly. Style smell only; no operator-visible bug. Worth a cleanup pass when someone's already touching those files.
- **Dead `#error-msg` / `#success-msg` banners on sites.html, probes.html, probe-pending.html** — never queried by any JS. The pages route everything through `AC.showError` / `AC.showSuccess` toasts instead. Markup leftovers; should be deleted but not urgent.

### What was NOT a bug
The audit also flagged the `tab-content hidden` pattern on IRC tabs (`irc.html:60, 72, 96`) as the same trap. It isn't — `.tab-content.active { display: block }` has specificity 0,2,0 which beats `.hidden { display: none }` at 0,1,0, so adding `.active` correctly reveals the panel. The redundancy is real but harmless.

### Files
- Modified: `web/admin/irc.html` — added `modal` class to serverModal/channelModal/commandModal, dropped redundant `hidden`.
- Modified: `web/admin/probe-pending.html` — added `modal` class to reject-modal, dropped redundant `hidden`.
- Modified: `web/admin/admin.html` — added `.expandable-msg.expanded` CSS rule.
- Modified: `cmd/api/static/js/admin-main.js` — removed inline truncation style from `.expandable-msg` cells in syslog/alerts table renderers (relies on CSS class now).
- Modified: `cmd/api/static/js/admin-irc.js` — switched toggleSASLFields and toggleStatusInterval to `classList.toggle('hidden', ...)`.

## [0.10.230] - 2026-05-18

### Fixed — connection-detail dead features (Phase 2 / Traffic Analysis tabs unreachable)
Audit of `/admin/connections/:id` after the v0.10.229 device-detail sweep found that a half-finished Tailwind refactor had been shipped: two of the page's five section tabs (Phase 2 Selectors, Traffic Analysis) were **completely unreachable** from the UI, plus the page had duplicate HTML IDs and broken chevron affordance. Four real bugs, fixed here.

#### 1. Phase 2 + Traffic Analysis tab buttons never appeared
Tab buttons at `connection-detail.html:72-73` had `class="section-tab hidden"`. JS at `admin-connection-detail.js:144,148` tried to reveal them with:

```js
document.getElementById('tab-flows').style.display = data.has_flow_data ? '' : 'none';
document.getElementById('tab-phase2').style.display = p2matches.length > 0 ? '' : 'none';
```

But `.hidden { display: none }` is defined in `admin-shared.css` and `style.display = ''` only clears the *inline* property — it can't override a stylesheet rule. So the tabs stayed `display: none` forever. Operators viewing a connection with active Phase 2 selectors or sFlow data had no way to access either visualization. Fixed by switching to `classList.toggle('hidden', !condition)` so the `.hidden` class is properly removed when the data condition warrants it.

Same bug also hit `flow-empty` (`admin-connection-detail.js:391`) — the "sFlow enabled but no samples match" banner could never appear because its element also has `class="hidden …"` and the same inline-vs-class precedence problem. Fixed the same way.

#### 2. Duplicate IDs across orphaned-refactor blocks
The page had two copies of `tab-content-dst-tunnels` (lines 125-135 + 168-178), `tab-content-phase2` (137-143 + 180-186), and `tab-content-flows` (145-166 + 188-244). The first set used the legacy `.card` / `.tunnel-table` CSS classes defined in the inline `<style>` block, the second set used Tailwind utility classes. Same content rendered with different styling, duplicated.

That meant 9 inner element IDs were also duplicated: `dst-tunnels-table`, `dst-tunnels-title`, `phase2-matches-container`, `flow-range-select`, `flow-empty`, `flow-content`, and all four flow chart canvases (`proto-chart`, `flow-time-chart`, `top-src-chart`, `top-dst-chart`) plus `convos-table`. Per HTML5 spec `getElementById` returns the first match — so JS sometimes wrote to the unreachable orphan elements while `switchTab` activated the legacy block.

#### 3. Traffic Analysis charts were unreachable even bypassing tab visibility
The orphan `tab-content-flows` block at lines 188-244 had `class="hidden"` — only one class, missing `.tab-content`. `switchTab` (`admin-connection-detail.js:502-510`) iterates `.tab-content` elements and toggles `.active` on them. The orphan never matched, so it was never activated. The four flow chart canvases lived only inside that orphan block, so even if the Traffic Analysis tab button had been reachable, the user would have seen the empty `flow-content` placeholder from the *legacy* block (line 164: `<div id="flow-content"></div>`), with the actual charts permanently hidden in the orphan.

#### Fix
Consolidated into one canonical block. The three legacy blocks (125-166) kept their styling for src/dst-tunnels + Phase 2 (matches the existing src-tunnels styling at line 113-123). The legacy `tab-content-flows` had its empty `flow-content` placeholder replaced with the rich charts/tiles markup that previously lived in the orphan. All three orphan blocks (168-244) deleted. Net: 9 duplicate IDs eliminated, 100 lines removed, Traffic Analysis charts now reachable.

#### 4. Chevron rotation on tunnel-row expand was a no-op
JS at `admin-connection-detail.js:261-266` toggles `.open` on the `.chevron` span when a tunnel row is expanded. The matching CSS rule for the rotation existed only as `.panel-tunnel-row .chevron.open { transform: rotate(90deg) }` inside `web/admin/admin.html` (scoped to the diagram-panel context on a different page), so on connection-detail the rotation never fired — the ► glyph stayed pointing right whether the row was expanded or collapsed.

Added `.chevron` / `.chevron.open` rules to the inline `<style>` block on connection-detail.html plus a `.tunnel-row:hover` rule that admin-shared.css had only for `.panel-tunnel-row`. The affordance now works.

### Audit findings deliberately NOT fixed
- **`setTrafficRange` / `setFlowRange` reference non-existent containers** (`admin-connection-detail.js:376,493` query `#traffic-range .range-pill` / `#flow-range .range-pill` — neither container exists in the markup). The querySelectorAll returns empty, the loop does nothing. Both functions still work because they also drive the actual `<select>` dropdowns. Dead code; leaving for a future cleanup pass.
- **The audit claimed `tailwind.css` was stale** ("none of the arbitrary-value classes used on this page exist"). I verified by reading the compiled file — `bg-[#0d1117]`, `text-[#58a6ff]`, `text-[0.78rem]`, `h-[250px]`, etc. are all present. False alarm in the audit; no rebuild needed.

### Files
- Modified: `web/admin/connection-detail.html` — added chevron CSS rules to the inline `<style>` block, removed the three orphan tab-content blocks (lines 168-244), moved the flow-content rich charts/tiles into the legacy `tab-content-flows` block.
- Modified: `cmd/api/static/js/admin-connection-detail.js` — switched the three `.hidden`-elements (tab-flows / tab-phase2 / flow-empty) from inline `style.display` toggling to `classList.toggle('hidden', !condition)`.

### Why this hadn't been reported
A connection-detail page on a deployment with no Phase 2 SA matches AND no sFlow data would never *attempt* to show those tabs, so the broken JS path doesn't fire and the operator sees only Overview + Source/Destination Tunnels — which work. The bugs manifest only when there's data to display. That's consistent with the operator never having reported it.

## [0.10.229] - 2026-05-18

### Fixed — five device-detail CSS bugs surfaced by audit
After v0.10.227 fixed the stat-card flex bug on `/admin/devices/:id` and v0.10.228 swept the rest of the admin area, a deeper audit of just the device-detail page found five more issues. All shipped here as one bundle.

#### 1. Interface row expand panel was silently broken (highest-impact)
Clicking an interface row in the Interfaces table renders an expanded `<tr>` with 13 detail items (Index, Type ID, VLAN ID, High Speed, Description, in/out bytes & packets & errors & discards) plus a chart-range pill bar (24h/7d/30d/90d) and a per-interface throughput chart. The JS at `admin-device-detail.js:568-597` referenced these CSS classes:

- `.expand-row` — the `<tr>`
- `.expand-content` — the panel container
- `.detail-grid` — grid wrapping the 13 detail items
- `.detail-item` / `.label` / `.value` — the label+value pairs
- `.chart-range-btn` (singular) — the range pills

**None of these were defined in any CSS file.** Result: the 13 detail items stacked in a tall single-column list with raw browser-default text styling, and the chart range buttons rendered as unstyled native `<button>` elements (grey, browser-default font, no spacing). The expand panel has been visibly broken since whenever it shipped — the audit caught it.

Fixes:
- Added definitions for `.expand-row`, `.expand-content`, `.detail-grid` (CSS grid with `repeat(auto-fill, minmax(180px, 1fr))`), `.detail-item`, `.detail-item .label`, `.detail-item .value`, and `.iface-chart-container` in `admin-device-detail.css`.
- Renamed `chart-range-btn` → `range-btn` in `admin-device-detail.js` so it matches the existing `.chart-range-btns .range-btn` rule in `admin-shared.css:165-184`.

#### 2. Six tables missing horizontal-scroll wrapper
The Interfaces table at line 191 was wrapped in `<div class="table-scroll overflow-x-auto">`, but the other six tables (VPN with 13 columns, HA, SD-WAN, Ping, Alerts, Config History) were not. At narrow viewports the VPN table in particular — with full IP addresses, subnet strings, and byte counters — would push the main panel outward and force the whole layout to scroll horizontally including the sidebar.

Wrapped each in `<div class="overflow-x-auto">` so the scrollbar appears inside the card. The Interfaces table's existing wrapper was preserved.

#### 3. Sensor names truncated mid-word
`admin-device-detail.js:769` rendered each sensor's name with inline `white-space: nowrap; overflow: hidden; text-overflow: ellipsis`. Sensors like `PEM1 Fan 4 Speed`, `DTS CPU Core 6 Temp`, `FortiGate-200F PSU Fan` were getting clipped on the 200px-min sensor cards even though wrapping to a second line would have fit. The `title` attribute provided a hover tooltip, but operators were having to hover-and-wait to read every sensor name.

Switched the inline style to `word-break: break-word; overflow-wrap: anywhere; line-height: 1.25` so names wrap cleanly to two lines.

#### 4. License card descriptions could overflow
`admin-device-detail.js:1016` rendered the license description (e.g. `FortiGuard Endpoint Vulnerability Scan and Endpoint Compliance`) inside a flex content child. The parent had `flex: 1; min-width: 0` (correctly) but the description div itself had no `word-break` rule, so very long FortiGuard descriptions could overflow the card horizontally rather than wrapping. Added `word-break: break-word; overflow-wrap: anywhere; line-height: 1.3`.

#### 5. `togglePublicIface` onclick was a (theoretical) XSS via interface name
The "is this a public-facing interface" checkbox at `admin-device-detail.js:565` used:

```js
'<input type="checkbox" ... onclick="window.togglePublicIface(\'' + esc(iface.name) + '\', this.checked)">'
```

`esc()` (defined at `admin-device-detail.js:1689-1694`) HTML-escapes by way of `textContent`/`innerHTML` round-trip, which handles `&`/`<`/`>` but does NOT escape `'` or `"`. So an interface name containing a single quote would terminate the JS string literal and inject arbitrary JS into the onclick. SNMP-sourced names are low risk in practice (every vendor profile generates conventional names like `port1`, `vlan-east-corp`, `wan2`), but the fix is trivial.

Switched to:
```js
'<input type="checkbox" ... data-action="toggle-public-iface" data-iface="' + esc(iface.name).replace(/"/g, '&quot;') + '">'
```

with a new `'toggle-public-iface'` handler registered in the existing `AC.delegateEvent('click', ...)` block. The interface name lives in a `data-*` attribute (attribute-safe escaped) and the handler reads it via `el.dataset.iface` — no JS-string-literal context to escape out of.

### Files
- Modified: `cmd/api/static/css/admin-device-detail.css` — added `.expand-row`, `.expand-content`, `.detail-grid`, `.detail-item`, `.detail-item .label`, `.detail-item .value`, `.iface-chart-container` definitions.
- Modified: `cmd/api/static/js/admin-device-detail.js` — renamed `chart-range-btn` → `range-btn` (2 occurrences, plus restoring the accidentally-mangled `.chart-range-btns` container during global replace), fixed sensor name + license description wrap, switched togglePublicIface onclick to data-action delegation.
- Modified: `web/admin/device-detail.html` — wrapped VPN/Alerts/Ping/HA/SD-WAN/Config-History tables in `<div class="overflow-x-auto">`.

### Audit findings deliberately NOT fixed
The audit also flagged tab a11y (missing `role="tab"`/`aria-selected`), hardcoded hex colors that should be design tokens, breakpoint mismatch (720 vs 768), modal double-scrollbar risk, and the bare `th` selector adding `position: sticky` to every table header even when there's no scrolling container. None of these cause an operator-visible bug today — they're style smell or larger refactors. Tracking separately if needed.

## [0.10.228] - 2026-05-18

### Fixed — same stat-card flex-row bug on admin.html + connection-detail.html
After fixing the visible firmware-string truncation on `/admin/devices/:id` in v0.10.227, the operator asked to check the rest of the admin area for the same bug class. An audit found the identical CSS conflict on two more pages — but the symptom was masked because the content happens to be short numeric counters and byte counts rather than long version strings, so nothing visibly truncated. The layout was still wrong (label sat *beside* value instead of stacked above it) and any future long-string content would have visibly broken in the same way.

#### Pages fixed
- **`web/admin/admin.html`** — local `<style>` block at line 93 declared `.stat-card { background: …; border: …; padding: 16px; }` but didn't set `display`, so the flex-row default from `admin-shared.css:770` leaked through. Affected the dashboard tile grid, the syslog stats grid (line 434), alerts stats grid (line 635), traps stats grid (line 779), and maintenance window stats grid (line 742). Five separate placements of the same broken pattern.
- **`web/admin/connection-detail.html`** — same omission at line 16. Affected the top stat row (Bytes In/Out, Tunnels, Status).

#### Pages NOT fixed (intentionally)
- **`admin.html:703-725` (alert-policies)** — these stat-cards have a `.stat-icon` 📋/🔧/🌐 child plus a `.stat-content` wrapper. They were always meant to render icon-left-of-content, so flex-row IS the correct layout. The `:has(.stat-icon)` exception preserves it.
- **`.expandable-msg` (admin.html:130)** — `cursor: pointer` confirms this is intentional click-to-expand truncation, not the same bug.
- **`.fwmon-stat` (admin-design-system.css:327)** — the newer replacement class already implements the opt-in `.long` modifier pattern for long-string values, working as designed.
- **`probes.html` / `sites.html` / `irc.html`** — render tables with naturally-wrapping cells, no truncating CSS.

#### Approach
Used `:has(.stat-icon)` for the icon-flex exception, which lets one CSS rule cover both layouts without any markup changes. `:has()` is supported in Chrome 105+ / Firefox 121+ / Safari 15.4+ (all shipped by 2023), so it's safe in 2026. Also added `word-break: break-word; overflow-wrap: anywhere;` to `.stat-value` so longer future content wraps inside the card rather than spilling out.

### Files
- Modified: `web/admin/admin.html` — `.stat-card` style now sets `display: block` by default with `:has(.stat-icon)` flex exception, plus value-wrap rules.
- Modified: `web/admin/connection-detail.html` — same pattern applied to this page's inline `<style>` block.

### Why this was worth a separate version
v0.10.227 fixed the visible bug. v0.10.228 fixes the same bug *class* everywhere else it exists so the next person who decides to render a long-string value in a dashboard stat-card doesn't hit it again. Pattern-driven fix rather than symptom-driven.

## [0.10.227] - 2026-05-18

### Fixed — device-detail stat-card labels/values truncated ("FIRM... v7.4.12,build2902,2...")
Operator on `/admin/devices/1` reported the stat cards along the top of the device-detail page were clipping both their labels and their values mid-string. Root cause was two CSS stylesheets fighting on the same selector:

- `cmd/api/static/css/admin-shared.css:770-779` declares `.stat-card { display: flex; align-items: center; gap: 14px; }` — that's the **dashboard** layout where each tile has a `.stat-icon` sibling rendered to the left of its `.stat-content`. Designed for icon-left, text-right.
- `cmd/api/static/css/admin-device-detail.css:48-51` only adds `min-width: 0; overflow: hidden;` and never resets `display` — so on the device-detail page the cards were also `flex-row`, and the `.stat-label` div ended up side-by-side with the value div instead of stacked above it. The whole content area split in half.
- `.stat-card .stat-value` further forced `font-size: 1.4rem; white-space: nowrap; text-overflow: ellipsis;`. CSS specificity (0,2,0) beat the inline Tailwind `text-[0.85rem]` (0,1,0), so the firmware value rendered at 1.4rem instead of 0.85rem and the inline-Tailwind size declared in the markup never won. A long FortiOS build string like `v7.4.12,build2902,250214` couldn't fit at 1.4rem in a half-card width and got truncated to `v7.4.12,build2902,2...`. The label next to it truncated to `FIRM...` for the same reason.

#### Fixes in `admin-device-detail.css`
1. `.stat-card` override now also sets `display: block` and `text-align: center` so cards render as standalone tiles (label-above-value), matching the layout the device-detail HTML was always written for.
2. Default `.stat-value`/`.stat-label` overrides dropped the explicit `font-size` and the `white-space: nowrap; text-overflow: ellipsis` rules.
3. Replaced with two `:where(.stat-card .stat-label)` / `:where(.stat-card .stat-value)` rules carrying the *fallback* font sizes. `:where()` zeroes out the selector's specificity (0,0,0), so any inline Tailwind class on the element (like `text-[0.85rem]` at 0,1,0) wins. Net behaviour:
   - device-detail HTML cards with inline `text-[Nrem]` Tailwind classes now render at the markup-declared size — firmware/AV-sig/IPS-sig version strings fit at 0.85rem with `word-break: break-word` so they wrap inside the card instead of truncating;
   - JS-rendered Security tab cards (`admin-device-detail.js:926-945`) with no inline sizing fall through to the 1.4rem fallback so the "stat hero" numeric look is preserved.
4. Wrap behaviour: every `.stat-value` now has `word-break: break-word; overflow-wrap: anywhere;` so values exceeding the card width wrap to a second line rather than ellipsizing. Better for diagnostic strings — full firmware version visible without a tooltip.

### Files
- Modified: `cmd/api/static/css/admin-device-detail.css` — `.stat-card` override now resets display, drops nowrap/ellipsis from values and labels, fallback font sizes moved into `:where()` blocks.

### Why this only showed up now
The same flex-row CSS rule has been on the page for several minor versions, but it became visibly broken only after the device-detail page started receiving longer string values (full FortiOS build strings, AV/IPS signature versions with dates). Short numeric values like CPU%/Sessions count happened to fit even in the cramped half-width layout. The cards were always laid out wrong; the truncation was the first thing the operator could see.

## [0.10.226] - 2026-05-18

### Fixed — SMTP auth: raw ciphertext sent as password (the REAL cause of every 535 in this thread)
Every theory in v0.10.222–v0.10.225 about why SMTP auth was failing — LOGIN vs PLAIN, username format, whitespace, MITM, Dovecot's `(reason unavailable)` — was working around the symptom, not the cause. The bug was on our side, in two adjacent lines of `UpdateSettings` that the user kept asking me to find.

#### Root cause: `IsSecret` was never persisted on save
`UpdateSettings` in `internal/api/handlers/handlers_settings.go` did this:

```go
existing := models.SystemSetting{Key: s.Key}
h.db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: s.Key})
// FirstOrCreate populates `existing` from the DB row, or zero-values if new
if !s.IsSecret || s.Value != "" {
    existing.Value = s.Value         // ciphertext written
    existing.Label = s.Label
    existing.Category = s.Category
    h.db.Gorm().Save(&existing)      // IsSecret NEVER copied — stays at its zero value
}
```

`s.IsSecret = true` was set on the request struct, the value was encrypted with `EncryptField` → `"{enc}<base64-ciphertext>"`, and then both got handed to `Save(&existing)` — but `existing.IsSecret` was never set from `s.IsSecret`. So the persisted row was `{ Value: "{enc}AAAA...base64...", IsSecret: false }`. On every save thereafter the same thing happened — fresh ciphertext, `IsSecret` still `false`.

#### Why this caused exactly the 535 the operator was seeing
`getNotificationSetting` gated decryption on `IsSecret`:

```go
if s.IsSecret { return h.db.DecryptField(s.Value) }
return s.Value   // <-- raw "{enc}<base64>" returned to caller
```

So when `runSMTPDiagnostic` called `getNotificationSetting("smtp_password")`, it got back the literal string `"{enc}AAAA...base64..."` and passed it to `smtp.PlainAuth("", username, password, host)` as the password. Postfix forwarded that string verbatim over the Dovecot SASL socket. Dovecot's SQL passdb compared it against the actual stored password column for `support@technicallabs.org` and (correctly) returned `Password mismatch`. IMAP login from the operator's webmail worked because the operator typed the real password into the browser — only firewall-mon was sending ciphertext.

The "different bytes every save" observation matches the symptom: AES-GCM uses a random nonce per encrypt, so each save produced different ciphertext, all of which looked nothing like the real password.

#### Secondary bug — real alert emails were broken in the same way
`internal/alerts/alerts.go:443-444` populated `am.config.Alerts.SMTPPassword` with `s.Value` directly, no decryption. Every CPU/memory/disk/VPN/interface-down alert email since the encrypted-storage migration was sending ciphertext as the password to the SMTP server — silently failing in production, never reported because the operator wasn't watching alert-email delivery. Fixed.

#### Tertiary bug — settings page was leaking ciphertext back to the UI
`GetSettings` masked secret values based on the row's `IsSecret` column. Because the column was wrong, the mask never fired for `smtp_password`, and a GET `/admin/api/settings` response was returning `"{enc}<base64-ciphertext>"` as the value for `smtp_password`. The settings UI's JS subsequently treated that as the existing-value placeholder and rendered it back into the password input field. Not exploitable on its own (AES-256-GCM ciphertext is useless without the key), but a correctness leak.

### Fixes
1. **`UpdateSettings`** — add `existing.IsSecret = s.IsSecret` immediately before `Save(&existing)`. The one missing line. (`handlers_settings.go:233-241`)
2. **`getNotificationSetting`** — drop the `IsSecret` gate. `DecryptField` is idempotent: it checks for the `{enc}` prefix internally and returns the input unchanged for plaintext values, so calling it unconditionally is safe for every settings key (`crypto.go:57-60`). This makes the read path robust to *any* existing DB row whose `IsSecret` flag is wrong — no DB migration required for the auth to start working. (`handlers_settings.go:264-282`)
3. **`GetSettings`** — mask based on a package-level `settingsSecretKeys` map (the static source of truth for which keys are secret) rather than the row's `IsSecret` column. Same robustness rationale. (`handlers_settings.go:24-58`)
4. **`alerts.go`** — wrap `s.Value` in `am.db.DecryptField(s.Value)` for the `smtp_password` case so real alert emails get the plaintext password. (`alerts.go:443-460`)

### Why every prior version in this thread didn't fix it
- **v0.10.220-221** (verbose SMTP trace): exposed the failure to the UI but couldn't see *why* it failed because the server's reply was `(reason unavailable)`.
- **v0.10.222** (LOGIN/CompoundAuth): right answer to a different question — server actually offered PLAIN, which the stdlib had supported all along.
- **v0.10.223** (username override + length leak): all wrong, reverted in v0.10.224.
- **v0.10.224** (MITM check + Dovecot hint): fixed a real (latent) security bug and pointed the operator at the right log, but the underlying password-bytes-don't-match problem was never going to surface without reading our own storage path.
- **v0.10.225** (admin SPA navigation): unrelated, fixed in passing.

The operator was right to push back with "please don't assume — research the proper way." All the SMTP-side theories were avoiding the simpler hypothesis that *our own code was sending the wrong bytes*, and a 30-line agent investigation of the storage path found the missing-line bug in minutes.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — extracted `settingsSecretKeys` to package scope, made `GetSettings` mask off it, added `existing.IsSecret = s.IsSecret` in `UpdateSettings`, made `getNotificationSetting` always-decrypt.
- Modified: `internal/alerts/alerts.go` — `RefreshThresholds` decrypts `smtp_password` before storing in `config.Alerts.SMTPPassword`.

### Operator action required after deploying
None — the always-decrypt read path makes the SMTP test work immediately against existing `{enc}`-prefixed rows. The first re-save of `smtp_password` after deploy will also write `is_secret=true` correctly, so the settings page stops returning ciphertext to the browser. No DB migration script needed.

## [0.10.225] - 2026-05-18

### Fixed — admin SPA navigation: detail-page clicks lost in interceptor + two related bugs
User reported: clicking a device row at `/admin/devices` changes the URL bar to `/admin/devices/<id>` but the page never actually loads the detail view — it stays on the devices list. A scan of the admin area click/history surface turned up the same bug class affecting `/admin/connections/<id>` and a pair of related navigation bugs (one latent precedence error, one missing handler). All three fixed here.

#### Primary bug — interceptor swallows deep `/admin/*` paths
The global SPA click interceptor in `cmd/api/static/js/admin-main.js` extracted only the FIRST path segment under `/admin/` to decide whether the click should be intercepted:

```js
var seg = url.pathname.replace(/^\/admin\/?/, '').split('/')[0];
if (!SPA_PAGES[seg || 'dashboard']) return;
```

For a click on `/admin/devices/123` this yields `seg='devices'`, which IS in SPA_PAGES — so the interceptor called `ev.preventDefault()`, pushed the URL onto history, and ran `loadPageData('devices')`. That last call reloads the devices LIST. So the URL bar updated, the browser was blocked from following the link, and the user saw the same list they were already on. The detail page (a separate HTML document — `device-detail.html` served by `admin.GET("/devices/:id", ...)` in `cmd/api/main.go:409`) never got a chance to load.

**Fix:** count the segments under `/admin/` and bail out as soon as we see more than one. The browser then navigates natively, the backend serves the detail HTML, the page loads correctly. The interceptor's job is only top-level tab navigation (`/admin/devices`, `/admin/syslog`, etc.) — deep paths are *not* part of the SPA.

This same path affected every detail-page link in the app:
- Device-name links in the devices table (`admin-main.js:586`)
- Device-name links in the interfaces table (`admin-main.js:698`)
- "Details" links in both connections tables (`admin-main.js:840` and `931`)
- `<a href="/admin/connections/${id}">Full Page →</a>` in `diagram-panels.js:135`
- `<a href="/admin/devices/${id}">` device chips in tunnel rows (`diagram-panels.js:492`)
- `AC.deviceLink()` / `AC.connectionLink()` builders in `admin-common.js:212/220`

All of these go through the same interceptor and were broken in the same way — all fixed by the same one-line change.

#### Latent bug — precedence error on the `/admin/api/` early-return
Line 3655 read:

```js
if (!url.pathname.indexOf('/admin/api/') === 0 && url.pathname.indexOf('/admin/') !== 0) return;
```

JavaScript operator precedence makes this `(!url.pathname.indexOf('/admin/api/')) === 0 && ...`. The unary `!` runs first: it converts the indexOf integer to a boolean, so the left side is always either `(true === 0)` or `(false === 0)` — both are `false`. `false && X` is also `false`, so the early return *never fired*. The intent was clearly two checks: skip if the URL is an admin API call, and skip if it isn't an admin page at all. Rewritten as two separate `return` statements to make the logic explicit.

In practice this bug was latent because no `<a href="/admin/api/...">` link ever shows up in the rendered DOM — the API surface is fetched via XHR. But it's a footgun if any future code adds such a link.

#### Missing handler — `popstate` listener
No code listened for `popstate`, so browser back/forward inside the SPA changed the URL bar but did not refresh the view. Example: user opens `/admin/devices`, clicks Syslog in the sidebar (push to `/admin/syslog`), clicks back — URL went back to `/admin/devices` but the syslog table stayed visible.

Added a listener that re-runs `activateTabFromUrl()` (which switches the active page DOM class) and then calls `loadPageData(page)` for non-analytics pages or `analyticsPages[page].reseedFromURL()` for the analytics pages (syslog / alerts / flows / traps) so their filter chips and query state catch up from `window.location.search`.

This does NOT apply to back-navigation from a detail page (`/admin/devices/123` → `/admin/devices`) because those are cross-document — the browser does a full load of admin.html, popstate doesn't fire, and the initial `activateTabFromUrl()` + `loadPageData()` call at the bottom of the IIFE handles it. The new listener only matters for within-SPA history transitions.

### Files
- Modified: `cmd/api/static/js/admin-main.js` — three-line fix to the interceptor's segment check, two-line fix to the precedence error, ~12-line `popstate` listener.

### Why this matters
The bug class is "SPA interceptor too aggressive" — any pattern that takes over every `/admin/*` link click is one bad segment-check away from breaking detail-page navigation site-wide. Fixing the check at the source means every existing detail link works, and any new detail-page routes added in the future automatically work without each one needing manual exemption.

## [0.10.224] - 2026-05-18

### Reverted + replaced — research-backed SMTP test fixes
User pushed back on v0.10.223 with "please don't assume — research the proper way for this to be implemented." Four research agents went off and read primary sources (Postfix `smtpd_sasl_glue.c`, Dovecot auth-protocol docs, RFC 4954, swaks reference manual, Mailcow/Mailu/Postal docs, OWASP A07). Findings reversed three of the five decisions shipped in v0.10.223 and exposed a security bug in v0.10.222's `LoginAuth`. This entry rolls back the wrong parts and replaces them with research-backed equivalents.

#### Security fix — `LoginAuth` missing MITM check (regression introduced in v0.10.222)
The stdlib `smtp.PlainAuth` validates `server.Name == host` in its `Start()` method before sending credentials. Without that check, a MITM with a redirected DNS / connection can terminate the TLS handshake on a *different* server that also advertises LOGIN and harvest the password under that identity. My `LoginAuth` in v0.10.222 was missing this gate — it only checked `server.TLS`. Fixed: `LoginAuth` now takes a `host` parameter and refuses if `server.Name != host`. `CompoundAuth` plumbs `host` through to `LoginAuth`. Matches stdlib `PlainAuth` semantics exactly.

#### Reverted — username override input on test page (v0.10.223 mistake)
No reputable mail admin tool (Mailcow, Mailu, Postal, swaks) exposes a username-only override field. The pattern is an outbound credential-stuffing oracle: an authenticated admin (or anyone who CSRFs the endpoint) can probe arbitrary username/saved-password pairs against an external SMTP server and read 235 vs 535 from the response. OWASP A07:2025 calls this out. If we ever need ad-hoc credential testing, the right shape is an explicit "test with ad-hoc credentials" mode that takes BOTH fields, rate-limits, and audit-logs — not a half-override pairing a typed name with the stored secret. Removed the input from the UI, removed the JSON field from the request struct, removed the `strings.TrimSpace` of the override.

#### Reverted — `username_len` / `password_len` in the test response (v0.10.223 mistake)
swaks' `--auth-hide-password` documented stance is "keep credential data out of transcripts entirely." Even for an authenticated admin session, password byte length is information disclosure that narrows the search space for anyone who later scrapes the response from browser history / a proxy log / a forwarded screenshot. Dropped both fields from the JSON, dropped the rendering in `renderSMTPTrace()`.

#### Replaced — silent password TrimSpace → save-time warning (better signal)
v0.10.223 silently `TrimSpace`d the saved password and tried to make the change visible via `password_len` in the test response. That's the wrong moment AND the wrong vector. New behavior: `UpdateSettings` still trims, but if the trim actually changed the value it appends a warning string to the JSON response. `saveSettings()` in the admin JS pops each warning as a separate red toast. The signal arrives at the moment the operator can act on it (right after they pasted the password) instead of being deferred to the next test run. Non-secret fields (`smtp_host` / `smtp_username` / `smtp_from` / `smtp_to`) also produce save-time warnings when their trim actually does work.

#### Added — operator-facing remediation hint when AUTH fails
Per Postfix source (`src/smtpd/smtpd_sasl_glue.c`), `(reason unavailable)` is Postfix's fallback string emitted when its SASL plugin returned FAIL with an empty reason. Per Dovecot's auth protocol docs (`/main/developers/design/auth_protocol.html`), Dovecot **deliberately** omits the `reason=` field on FAIL for the common failure modes — "MUST NOT reveal exact failure reasons like user not found vs. password mismatch." So `(reason unavailable)` on the wire means *the real diagnostic is always in Dovecot's auth log on the mail server, never on the SMTP transcript*. New `authFailureHint()` helper detects the empty-reason 535 pattern (and a few others — generic 535, `504 unrecognized authentication`) and attaches an operator-facing "Next step:" hint to the failed auth row. For the Postfix+Dovecot case the hint walks the operator through `journalctl -u dovecot --since '5 min ago'` and tells them what to look for. The new `Hint` field is rendered as a blue-bordered call-out below the error row.

#### Added — cert NotAfter in TLS step (industry standard)
Mailcow / Mailu / Mail-in-a-Box admin UIs all surface certificate expiry in their SMTP test output. v0.10.220-223 only showed TLS version / cipher / CN. Now the TLS detail line is e.g. `TLS 1.3, TLS_AES_128_GCM_SHA256, cert CN=mail.example.com, expires 2026-08-14`. Cert-expiry-in-N-days is a top-3 cause of "tests pass today, fail in production next week" so this rounds out the swaks-style transcript the diagnostic was modelled on.

#### What did NOT change
- LOGIN step-counter implementation in `LoginAuth.Next()` — research confirmed this matches `wneessen/go-mail` (the canonical modern Go mail library); ignoring the prompt text is exactly correct per the (expired) `draft-murchison-sasl-login-00`.
- PLAIN-before-LOGIN selection order in `CompoundAuth` — matches industry convention.
- The per-step transcript UI shape — research validated it as the swaks/Mailcow standard.

### Files
- Modified: `internal/notifier/smtp_auth.go` — `LoginAuth` signature now takes `host`; `Start()` validates `server.Name == a.host`; `CompoundAuth` plumbs host through.
- Modified: `internal/api/handlers/handlers_settings.go` — removed `UsernameOverride` field, removed `username_len`/`password_len` from response, removed silent `TrimSpace` on `smtp_password` (replaced with save-time warning), added `authFailureHint()` and `tlsLeafSummary()` helpers, added `Hint` field to `smtpTraceStep`, switched `UpdateSettings` response to `SuccessResponse(gin.H{message, warnings})`.
- Modified: `web/admin/admin.html` — removed the username override input + its explainer text.
- Modified: `cmd/api/static/js/admin-main.js` — `testEmail()` no longer sends `username`, `renderSMTPTrace()` no longer shows length cells but does render the new `hint` block, `saveSettings()` surfaces server-side warnings as toasts.

### Sources researched
- Postfix `smtpd_sasl_glue.c` and `xsasl_dovecot_server.c` (vdukhovni/postfix mirror)
- Dovecot auth protocol design doc (`doc.dovecot.org/main/developers/design/auth_protocol.html`)
- Dovecot Postfix-SASL howto (`doc.dovecot.org/main/howto/sasl/postfix.html`)
- Postfix SASL_README (`postfix.org/SASL_README.html`)
- RFC 4954 + draft-murchison-sasl-login-00
- swaks reference manual (`jetmore.org/john/code/swaks/latest/doc/ref.txt`)
- Mailcow relayhost docs, WP Mail SMTP debug events doc, SendGrid 535 troubleshooting
- OWASP A07:2025 (Authentication Failures), OWASP Authentication Cheat Sheet
- `wneessen/go-mail` LOGIN auth implementation (the canonical modern Go SMTP library)

## [0.10.223] - 2026-05-18

### Added — SMTP test diagnostics for opaque 535 auth failures
After the v0.10.222 LOGIN/CompoundAuth fix landed, the operator's verbose-test trace showed the diagnostic reaching AUTH cleanly (TLSv1.3 handshake good, mechs `PLAIN LOGIN` advertised, PLAIN selected) and then failing with `535 5.7.8 Error: authentication failed: (reason unavailable)`. The mail server's reason-unavailable reply gives operators nothing to act on, and reproducing on the backend is exactly the friction the verbose test was supposed to remove. v0.10.223 adds three orthogonal diagnostics so each common cause can be ruled out without backend shell access.

#### Username override (one-shot, test-only)
SMTP card now has a second free-form input next to the recipient override: `username` (override `smtp_username`). The `/api/settings/test-email` request body accepts an optional `"username"` field; when present, `runSMTPDiagnostic` uses that value for AUTH and reports it back via `auth_method` and the new `username` metadata field, *without* persisting anything to `system_settings`. Lets the operator try `support` vs `support@example.com` (and other SASL bare-name vs full-address variants) against a Postfix/Dovecot or Cyrus saslauthd backend in a single click — the common case behind a `(reason unavailable)` 535 when the password is known good.

#### Length metadata in the trace summary
Response now includes `username` (echo, after server-side TrimSpace), `username_len` (byte length of the effective username), and `password_len` (byte length of the *decrypted* password actually handed to the SMTP client). Rendered in the trace metadata row as `User: support@example.com (24 B)` and `Pwd len: 18 B`. Operators who know what their password length *should* be can spot a trailing-space corruption that the masked `********` rendering hides — a length-mismatch of one byte is the cheapest way to localise the failure to the password storage path versus the wire protocol.

#### Defensive TrimSpace on save (host/username/from/to/password)
Updated `UpdateSettings` to call `strings.TrimSpace` on `smtp_host`, `smtp_username`, `smtp_from`, `smtp_to`, and `smtp_password` before validation/encryption. Copy-paste from webmail settings pages and password managers regularly drags a trailing space; a single trailing space on a username sent to Cyrus/Dovecot SASL is exactly the kind of input that produces `(reason unavailable)` rather than a useful error. Combined with the length metadata above, an operator who re-saves their existing settings will see `password_len` change in the next test if a trim actually removed something — closing the loop on the "did the trim fix it" question.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — `UsernameOverride` parsing in `runSMTPDiagnostic`, `username`/`username_len`/`password_len` added to JSON response, `strings.TrimSpace` applied to the five SMTP settings in `UpdateSettings`.
- Modified: `web/admin/admin.html` — second free-form input (`#test-email-username-override`) plus operator-facing note explaining that overrides are one-shot.
- Modified: `cmd/api/static/js/admin-main.js` — `testEmail()` packs both overrides into the request body when present; `renderSMTPTrace()` renders `User:` and `Pwd len:` cells in the metadata row when the server supplies them.

### Why this matters
A `535 5.7.8 (reason unavailable)` from Postfix/Cyrus is almost never the password itself — by the time AUTH PLAIN reaches the server, the wire format and TLS state are already validated. The remaining suspects are username format (bare name vs `user@domain`), invisible whitespace in either credential, and storage-side encryption drift. Each diagnostic in this bundle targets exactly one of those without requiring an SSH session into the mail server, so the operator can resolve the issue from the admin UI alone.

## [0.10.222] - 2026-05-18

### Added — SMTP LOGIN auth + fixed post-STARTTLS state check (Bundle J)
Two related fixes after operator testing of the verbose SMTP diagnostic shipped in v0.10.220-221 revealed both a self-inflicted bug in the test path and a gap in the production notifier path: many Postfix/Cyrus/Dovecot submission servers advertise only LOGIN on port 587, and Go's stdlib `net/smtp` ships PLAIN but not LOGIN.

#### J1 — Authoritative TLS state tracking
The v0.10.221 hotfix dropped a redundant `Hello()` call but the AUTH pre-check still misreported `STARTTLS not advertised` after a *successful* STARTTLS upgrade. RFC 3207 §2 is explicit that a server MUST NOT advertise STARTTLS again once the connection is encrypted, so `client.Extension("STARTTLS")` returning false post-upgrade is correct server behavior — the test code was the one drawing the wrong conclusion. New `negotiatedTLS` boolean tracks the actual encryption state across both the implicit-TLS (port 465) and STARTTLS (port 587/25) paths, and the AUTH guard reads from it rather than re-querying the extension list. Error message reworded to be specific about both paths.

#### J2 — LOGIN auth mechanism + auto-selection
New `internal/notifier/smtp_auth.go`:
- **`LoginAuth(username, password) smtp.Auth`** — implements RFC 4954 LOGIN. Doesn't try to parse the server's prompt text (which varies — "Username:", "User Name", base64-encoded localised strings, …); instead tracks which step it's on internally (step 0 = username, step 1 = password). Mirrors `smtp.PlainAuth`'s TLS-required guard.
- **`CompoundAuth(username, password, host) smtp.Auth`** — inspects `server.Auth` in `Start()` and picks PLAIN (preferred) or LOGIN based on what's advertised. Returns a clear error when neither is offered. Designed to be a drop-in replacement for `smtp.PlainAuth` anywhere in the codebase. Exposes `ChosenMechanism()` for trace-time reporting.

Wired into both code paths:
- **Notifier** (`internal/notifier/notifier.go`): both `smtp.PlainAuth` call sites — the per-alert email path and the digest email path — now use `CompoundAuth`. Real alert emails to LOGIN-only servers work without operator reconfiguration.
- **Verbose test** (`internal/api/handlers/handlers_settings.go`): `runSMTPDiagnostic` uses `CompoundAuth` and reports the chosen mechanism in the trace row's detail + response text — operator sees `LOGIN auth as support@example.com` and `accepted (mechs offered: PLAIN LOGIN; selected: PLAIN)` instead of always `PLAIN auth as …`.

### Files
- New: `internal/notifier/smtp_auth.go` — LOGIN + CompoundAuth implementation.
- Modified: `internal/notifier/notifier.go` — both `smtp.PlainAuth` call sites switched to `CompoundAuth`.
- Modified: `internal/api/handlers/handlers_settings.go` — `negotiatedTLS` tracking + CompoundAuth in `runSMTPDiagnostic` + `authMethodLabel` rewritten to reflect auto-selection.

### Why this matters
The operator's first verbose-test trace (post-v0.10.221) failed at AUTH with `unencrypted connection` even though the STARTTLS step itself reported a clean TLSv1.3 handshake with a valid certificate — the diagnostic was lying about its own previous step. After J1 the AUTH guard reads from the same flag that gets set when the upgrade actually succeeds, so the report is internally consistent. After J2 the test (and every real alert email) auto-picks PLAIN or LOGIN depending on what the server offers; a mailserver advertising only LOGIN no longer needs a code change.

## [0.10.221] - 2026-05-18

### Fixed — SMTP test STARTTLS double-EHLO bug
The verbose SMTP test shipped in v0.10.220 (bundle I) had a self-inflicted bug: `runSMTPDiagnostic` called `smtp.Client.Hello("firewall-mon-test")` once before STARTTLS and again after the TLS upgrade. The Go stdlib's `smtp.Client.Hello` is documented to be callable at most once — any subsequent call returns `"smtp: Hello called after other methods"`. After the STARTTLS step the test was failing at the second Hello, never reaching AUTH, and masking the actual credential / mechanism issue the operator was trying to diagnose.

Fix: drop the explicit second `Hello()` after `StartTLS`. The stdlib's `StartTLS` already re-issues EHLO internally over the encrypted channel, using the local name captured by the first `Hello()` call. The trace now lands on AUTH where the real failure (if any) actually lives.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — removed post-STARTTLS `client.Hello()` call, expanded comment explaining the stdlib's once-only semantics.

## [0.10.220] - 2026-05-18

### Changed — verbose SMTP test diagnostic (Bundle I)
The previous "Send Test Email" button on Settings ran `smtp.SendMail` and returned a single opaque success/failure message. Operators with a failing setup had to grep server-side Postfix/Exchange logs to see which step actually broke. After bundle I the test page returns a full step-by-step transcript of the SMTP conversation, with timing, TLS details, and the server's own response to each verb.

#### Backend (`internal/api/handlers/handlers_settings.go`)
- `TestEmail` replaced with `runSMTPDiagnostic` plus a thin handler wrapper. The diagnostic dials, optionally wraps for implicit TLS on port 465, reads the greeting, sends EHLO, negotiates STARTTLS on 587/25 if advertised, sends EHLO again over TLS, runs AUTH PLAIN if `smtp_username` is set, then MAIL FROM, RCPT TO, DATA, body, and QUIT. Each step records:
  - `step`: short verb name (`connect` / `greeting` / `ehlo` / `starttls` / `auth` / `mail-from` / `rcpt-to` / `data` / `quit`)
  - `detail`: what we tried (`PLAIN auth as support@example.com (server advertised mechs: PLAIN LOGIN)`)
  - `response`: server response or extracted info (`TLSv1.3, TLS_AES_128_GCM_SHA256, cert CN=mail.example.com`)
  - `status`: `ok` / `skipped` / `fail`
  - `error`: present only on `fail` — the raw error string from the SMTP stack or stdlib
  - `duration_ms`: wall-clock time for the step
- New optional `{"to": "alt@example.com"}` body param to override the recipient for a one-off test without changing the saved `smtp_to` setting.
- AUTH step has an explicit early-fail path when the server doesn't advertise STARTTLS and we're not on the implicit-TLS 465 port — the stdlib's generic "unencrypted connection" error is rewritten to a clearer "PLAIN auth refused: connection is not encrypted (server didn't advertise STARTTLS)" so an operator knows whether the failure was credentials vs. transport.
- TLS state pulled via `smtp.Client.TLSConnectionState()` (Go 1.20+) so the trace includes the negotiated version, cipher suite, and server certificate CN.

#### Frontend (`web/admin/admin.html`, `cmd/api/static/js/admin-main.js`)
- Settings → SMTP card now has a recipient-override input next to the Send Test Email button. Leave blank to use the configured `smtp_to`; useful for "send the test to me first" workflows without rewriting the saved setting.
- New `renderSMTPTrace(host, data)` JS helper paints a table: each row is `[status pill] step | action + server response + error | duration`. Status pill is green `OK`, gray `SKIP`, or red `FAIL`. Failure rows highlight the error inline with a red left border so the eye lands on it first. A summary line above the table shows host:port, from, to, auth method, and total wall time.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — `runSMTPDiagnostic`, `smtpTraceStep`, `tlsVersionName` / `tlsCipherName` / `tlsLeafSubject`, `authMethodLabel`, expanded `TestEmail` handler, new imports (`crypto/tls`, `errors`, `net`).
- Modified: `cmd/api/static/js/admin-main.js` — `testEmail()` + `renderSMTPTrace()`.
- Modified: `web/admin/admin.html` — recipient-override input + `#test-email-result` rehosted as a div.

### Why this matters
The user reported a failing SMTP setup and shared a Postfix log fragment ending after the TLS handshake — without further log lines (which Postfix only emits at a later stage) the failure was invisible from the admin UI. The verbose trace surfaces the exact verb that failed and the server's response, so the next time a test fails the operator sees something like:
```
FAIL  auth   PLAIN auth as support@example.com (server advertised mechs: PLAIN LOGIN)
             error: 535 5.7.8 Error: authentication failed: …
```
…directly on the page, with no log-grepping required.

## [0.10.219] - 2026-05-18

### Added — API versioning + polish (Bundle H: H1 + H2 + H3)
Closes the deferred-items list. One forward-looking infrastructure change (API versioning lane), one UX polish (no-reload navigation), one small bug fix (IPv6 host:port).

#### H1 — `/api/v1/` aliasing (forward-compat lane)
- New path-rewrite middleware in `cmd/api/main.go` aliases `/api/v1/*` → `/api/*` and `/admin/api/v1/*` → `/admin/api/*`. Implemented as a single `router.Use(...)` block that mutates `c.Request.URL.Path` before route matching — no per-route duplication, no redirect roundtrip, no measurable overhead.
- The canonical paths remain `/api/*` and `/admin/api/*`. The admin JS and the Firewall-Collector probe binary keep working unchanged.
- The v1 aliases give us a clean upgrade lane: when a future breaking API change ships, we add `/api/v2/*` alongside the existing routes and operate both for a deprecation window. New external consumers can adopt `/api/v1/` today knowing the v1 contract is stable.

#### H2 — SPA-aware filter-link click interception
- The cross-page filter links added in bundles E and G (`/admin/alerts?device_id=42`, `/admin/syslog?search=10.0.0.5`, etc.) used to do a full page reload when clicked from inside the admin SPA. Bundle H2 intercepts those clicks and applies the filter via `history.pushState` + the new `reseedFromURL` helper exposed by `FwmonControls.attachAnalyticsPage`, completely avoiding the reload.
- Modifier-key clicks (Ctrl/Cmd-click for new tab, Shift-click for new window, middle-click) bypass the handler so the multi-tab triage flow still works — operators can fan out a triage session into multiple tabs exactly as before.
- Cross-page clicks (e.g. operator is on dashboard, clicks a link to `/admin/alerts?…`) tab-switch in place via the same path as the sidebar nav-item clicks, then run `loadPageData` which kicks off the analytics-page wiring that reads filter params from the URL on init. No reload either.
- Same-page clicks (operator already on `/admin/syslog`, clicks a new syslog filter) re-seed the existing analytics-page handle from the URL and refresh — fastest path, doesn't re-create the page DOM at all.
- Device-detail / connection-detail / probe / IRC / other separate-document pages are *not* intercepted — those are real page navigations and full reloads are correct.

#### H3 — IPv6 `host:port` fix in `TestProbeConnection`
- `handlers_probes.go:356` previously formed the dial address with `fmt.Sprintf("%s:%d", host, port)`. For an IPv6 listen address this produces `2001:db8::1:9876` instead of the bracketed `[2001:db8::1]:9876`, which `net.DialTimeout` would parse as a different IP entirely (treating the trailing `:9876` as an extra hextet).
- Replaced with `net.JoinHostPort(host, strconv.Itoa(port))` which handles both IPv4 and IPv6 correctly. Dropped the now-unused `fmt` import.

### Files
- Modified: `cmd/api/main.go` — `/v1/` rewrite middleware + `strings` import + version.
- Modified: `cmd/api/static/js/admin-controls.js` — `reseedFromURL` on the analytics-page handle.
- Modified: `cmd/api/static/js/admin-main.js` — SPA link interceptor.
- Modified: `internal/api/handlers/handlers_probes.go` — `net.JoinHostPort`; `fmt` import removed.

### Deferred-items inventory cleared
After this bundle, every concrete item from the post-sweep audit (noisy-device leaderboard, snooze alerts, VPN remote-end linkification, SPA-aware filter links, IPv6 host:port, API versioning lane) has shipped. The remaining open recommendations are all cosmetic / large-diff items I'd only do on request: the codebase-wide `interface{}` → `any` migration, the `infertypeargs` and `minmax` style suggestions surfaced by the linter, and the `SyslogSummary`/`FlowRollup` raw endpoints (no consumer).

## [0.10.218] - 2026-05-18

### Added — picked up deferred items from Bundles E and F (Bundle G: G1 + G2 + G3)
After the six-bundle whole-admin sweep wrapped, this bundle picks up three features that were unblocked by the backend work in D (v0.10.217) but never built, plus one new operator workflow (snooze alerts) that needed its own backend change.

#### G1 — Noisy-device leaderboard widget
- New "Noisy Devices" card on the dashboard ranks devices by recent alert + syslog volume.
- Window selector: 1 h / 6 h / 24 h (default) / 7 d. Persisted in `localStorage` (`fwmon-noisy-window-hours`).
- Top 10 by total volume; each row shows device name (links to detail), alert count (links to filtered `/admin/alerts`), syslog count (links to filtered `/admin/syslog`), and a width-proportional volume bar.
- Card auto-hides when no device has any messages — no dead chrome.
- Uses the `?device_id=N` filter on `/api/syslog/stats` and `/api/alerts/stats` added in v0.10.217 (D4). One stats call per device, fired in parallel; bounded by the existing 1000-device dashboard cap.

#### G2 — Snooze alerts (backend column + endpoint + UI)
- New columns on `models.Alert`: `SnoozedUntil *time.Time` (indexed), `SnoozedBy string`, `SnoozedReason string`. GORM auto-migrate adds them on first start.
- Two new endpoints: `POST /admin/api/alerts/:id/snooze` (body: `{hours, reason}`) and `POST /admin/api/alerts/:id/unsnooze`. Hours are clamped to `[1, 720]` server-side.
- `GetAlerts` listing now filters out currently-snoozed alerts by default. New `?include_snoozed=true` query param overrides for views that need to see them. Refactored filter logic into a shared `applyAlertFilters` helper so the listing + count paths stay in sync.
- New `SnoozeAlert` and `UnsnoozeAlert` methods on `*Database`.
- Alert-detail modal: open alerts now show both **Acknowledge** and **Snooze** buttons. Snoozed alerts show a "SNOOZED until …" badge + **Unsnooze** button, with optional `snoozed_by` / `snoozed_reason` audit detail underneath.
- Alerts table: snoozed rows render a `SNOOZED` badge in the status column (tooltip reveals wake-up timestamp).
- Snooze prompt uses `window.prompt()` — deliberate friction-free flow for a self-serve action; a dedicated modal felt overkill.

#### G3 — VPN remote-end device linkification
- New computed `VPNStatus.RemoteDeviceID *uint` field (omitempty + `gorm:"-"`). Populated by `GetLatestVPNStatuses` using the existing remote-IP peer-matching pass already running for subnet cross-fill — zero extra queries.
- Two-pass resolution: first pass populates during the subnet cross-fill loop; new second pass resolves remote_device_id for tunnels that didn't need a subnet fix.
- Device-detail VPN tab: when `remote_device_id` is set, the `remote_ip` cell links directly to the peer's `/admin/devices/:id` page instead of `/admin/syslog?search=<ip>`. Tooltip clarifies "resolved by RemoteIP match". Falls back to the syslog cross-pivot when no peer match is known.

### Files
- Modified: `internal/models/models.go` — `VPNStatus.RemoteDeviceID`, `Alert.SnoozedUntil/By/Reason`.
- Modified: `internal/database/database.go` — `RemoteDeviceID` population (2 pass), `SnoozeAlert` / `UnsnoozeAlert` methods.
- Modified: `internal/api/handlers/handlers_analytics.go` — `applyAlertFilters` helper, `SnoozeAlert` / `UnsnoozeAlert` handlers, `gorm.io/gorm` + `time` imports.
- Modified: `cmd/api/main.go` — 2 new alert routes, version bump.
- Modified: `cmd/api/static/js/admin-main.js` — `renderNoisyDevices` + dashboard hook, snooze UI in alert-detail modal + alerts table, `showSnoozePrompt` / `unsnoozeAlert` handlers + delegated actions.
- Modified: `cmd/api/static/js/admin-device-detail.js` — VPN remote-end device linkification with syslog fallback.
- Modified: `web/admin/admin.html` — new `#noisy-devices-card` section in dashboard.

### Why this matters
Three lingering items from the original sweep now ship in one tidy bundle. The leaderboard uses backend filters that have been waiting since D4 with no consumer; the VPN remote-end linkification closes the second half of the "click through to the peer" affordance that E2 only half-resolved; snooze gives operators a third state ("not relevant right now, but still real") between "acknowledge" and "ignore".

## [0.10.217] - 2026-05-18

### Changed — admin-wide backend consistency pass (Bundle D: D1 + D2 + D3 + D4)
Sixth and final commit of the "improve the whole admin area" sweep. The previous five bundles touched almost exclusively frontend code; this one normalises the API surface so subsequent work — and external callers — see a consistent contract.

#### Audit
One parallel sub-agent inventoried every backend inconsistency that surfaced during bundles A-F. Findings: 5 handlers still inline-parsed `hours` with different caps and error semantics; 8 list endpoints called `.Find(...)` with no `.Limit(...)`; the probe-facing endpoints disagree on whether errors return `{"error":…}` or `{"message":…}`; `VPNStatus` had no field to indicate when a currently-down tunnel was last up; 3 of 4 `/stats` endpoints accepted no `device_id` filter.

#### D2 — Unified range parsing
- Every handler that took `?hours=` now delegates to `httputil.ParseHours` (default 24, hard cap 8760). Migrated `GetSystemStatusHistory`, `GetConnectionEvents`, `GetConnectionFlows`, and `GetProcessStats`. Endpoints with a tighter business cap (720 h, 30 days) still apply that cap by a single `if hours > 720` line after the helper, so the canonical parse + 8760 ceiling is centralised but per-endpoint sensitivity remains.
- Dropped the now-unused `strconv` import from `handlers_connections.go`.

#### D3 — Defensive pagination on configuration list endpoints
- `GetDashboardAll`: `Find(&devices)` and `Find(&connections)` now `.Limit(1000)`.
- `GetDeviceDataDiag`: same 1000 cap on devices.
- `GetIRCServer`: 200 cap on servers (sized for the realistic operator surface).
- `GetIRCChannels`: 500 cap (filtered + unfiltered paths).
- `GetIRCCommands`: 500 cap.
- `GetAllSettings`: 1000 cap.
- All caps are above any realistic fleet/config size, so they're invisible to current clients while bounding worst-case memory if a misconfiguration or test fixture inflates row counts.

#### D4 — Stats `device_id` filter + VPN `last_up_at` + probe error-field consistency
**`device_id` filter on stats endpoints**:
- `GetAlertStats`, `GetTrapStats`, `GetSyslogStats` now accept an optional `?device_id=N` query parameter.
- The database methods take a `deviceID uint` argument (0 = no filter, matches existing API semantics). Internal helpers `groupByString` and `timeSeriesCount` also take the filter parameter so the WHERE clause is applied to every aggregation, not just the top-level COUNT. SyslogStats' summary tables get the same filter via a small local helper.
- Unblocks the noisy-device-leaderboard feature deferred from bundle F5 — frontend can now fetch per-device stats without an N+1 loop.

**`last_up_at` on VPN status**:
- New `LastUpAt *time.Time` field on `models.VPNStatus`, marked `gorm:"-"` (computed, not stored). `json:",omitempty"` so the field is absent when no historical "up" snapshot exists.
- `GetLatestVPNStatuses` populates it from a single grouped query: `SELECT tunnel_name, MAX(timestamp) FROM vpn_statuses WHERE device_id = ? AND status = 'up' GROUP BY tunnel_name`. One query per device-detail request rather than one per tunnel.
- Frontend `renderVPN` in `admin-device-detail.js` now displays "last up Xh ago" in the uptime column for currently-down tunnels (with `formatRelative`), title-attribute hovering shows the absolute timestamp. Up tunnels still show normal uptime; tunnels with no historical "up" snapshot show a dash. Resolves the bundle F5 deferral for the down-tunnel half.

**Probe `error` vs `message` field unification**:
- New internal helper `probeErr(c, status, msg)` in `handlers_probes.go` emits `{"success": false, "error": msg, "message": msg}` — both fields are present in every error response. New clients can read `error` consistently; legacy `Firewall-Collector` binaries that read `message` keep working unchanged.
- Applied to every error path in `RegisterProbe` (5 sites) and `ProbeHeartbeat` (4 sites). `TestProbeConnection` already used `message` for its success response; left alone.

### Files
- Modified: `internal/api/handlers/handlers_dashboard.go` — ParseHours migration + 1000-row caps on dashboard lists.
- Modified: `internal/api/handlers/handlers_connections.go` — ParseHours migrations (2 sites) + strconv import removed.
- Modified: `internal/api/handlers/handlers_devices.go` — ParseHours migration on GetProcessStats.
- Modified: `internal/api/handlers/handlers_irc.go` — `.Limit()` on 3 list endpoints.
- Modified: `internal/api/handlers/handlers_settings.go` — `.Limit(1000)` on GetAllSettings.
- Modified: `internal/api/handlers/handlers_probes.go` — `probeErr` helper + 9 call-site conversions.
- Modified: `internal/api/handlers/handlers_analytics.go` — `parseStatsDeviceFilter` + 3 stats endpoints take device_id.
- Modified: `internal/database/database.go` — `groupByString` / `timeSeriesCount` / `GetAlertStats` / `GetTrapStats` / `GetSyslogStats` take `deviceID`; `GetLatestVPNStatuses` populates `LastUpAt`; `GetDashboardTimeSeries` passes 0 for unfiltered.
- Modified: `internal/models/models.go` — `VPNStatus.LastUpAt` field.
- Modified: `cmd/api/static/js/admin-device-detail.js` — uptime column renders last-up-ago for down tunnels.

### Why this matters
External clients of the admin API (custom dashboards, automation scripts, the `Firewall-Collector` probe binary) now see the same `error` field on every probe-facing error, the same `hours` cap on every stats endpoint, and the same `device_id` filter shape on `/alerts/stats`, `/traps/stats`, `/syslog/stats`, and `/flows/stats`. The frontend gains a new fact (when a down tunnel was last up) that the F bundle had to skip. And every configuration-list endpoint is bounded by a sane LIMIT so a single misconfigured row in a test database can't OOM the API process.

### Whole-admin sweep complete
v0.10.212 (A — foundation) → v0.10.213 (B — accessibility) → v0.10.214 (C — performance) → v0.10.215 (E — cross-page linkification) → v0.10.216 (F — operator features) → v0.10.217 (D — backend consistency). Six bundles, ~2 100 lines of additions, every page touched, no breaking client changes.

## [0.10.216] - 2026-05-18

### Changed — admin-wide operator features (Bundle F: F1 + F2 + F3 + F4)
Fifth commit of the "improve the whole admin area" sweep. Three concrete operator quality-of-life additions, all frontend-only — every required data field was already exposed by existing API responses.

#### Audit
Parallel sub-agent confirmed data availability for the planned features. **Available without backend changes**: `Device.ip_address`, `Device.ssh_username`, `Device.ssh_port`, `Device.last_polled`, every `FlowSample` field needed for CSV export. **Deferred (needs backend change)**: tunnel last-seen for `status='down'` tunnels (`VPNStatus` exposes `tunnel_uptime` for up tunnels but no `last_up_at` for down ones); per-device syslog/alert noise counts (`/api/syslog/stats` etc. accept no `device_id` filter).

#### F2 — SSH launch button (`AdminCommon.sshLaunchButton`)
- New helper renders an `<a class="btn secondary sm" href="ssh://user@host[:port]">SSH</a>` for any device — the operator's OS hands the URL to their registered SSH handler (PuTTY, Terminal, iTerm2, Windows Terminal, etc.). No credentials flow through the admin server.
- Inputs are URI-encoded; missing `ip_address` yields an empty string (no button). Non-default `ssh_port` (anything other than 22) appended as `:port`.
- Wired into the devices table actions column in `admin-main.js` and the device-detail page header (new `#deviceSshLaunch` placeholder).

#### F3 — Stale-device dashboard card
- New "Stale Devices" card on the dashboard listing every device whose `last_polled` is older than the operator-selected threshold. Threshold dropdown ranges 15 m / 30 m / 1 h (default) / 3 h / 12 h / 24 h; selection persists in `localStorage` under `fwmon-stale-threshold-min`.
- Per-row content: device-link (uses the bundle E2 `AC.deviceLink`), IP, "X minutes/hours/days ago" relative time, status badge, SSH launch button.
- Card auto-hides when nothing is stale — no dead chrome on a healthy fleet. Rows are sorted oldest-poll-first so the most concerning entries surface at the top.
- Driven entirely off the existing `/api/dashboard` payload — no extra API call, no extra round trip on the polling loop.

#### F4 — CSV export on flows page (`FwmonFlows.exportCsv`)
- New "Export CSV" button in the flows page header (right side, between the active-filter chips and the sampling chip).
- Pulls up to 10 000 rows matching the **current filter state** (range / device / probe / protocol / src / dst / dport) from the existing `/admin/api/flows` endpoint — no new endpoint.
- Columns: `timestamp, src_addr, src_port, dst_addr, dst_port, protocol, protocol_name, bytes, packets, sampling_rate, device_id, probe_id, sampler_address`. RFC 4180-style escaping for any field containing comma / quote / CR / LF; embedded quotes doubled.
- Filename encodes the current filter signature so successive exports don't collide in the operator's Downloads folder — e.g. `flows-2026-05-18T19-42-15-24h-dev42-protoTCP-port443.csv`.
- Button disables + shows "Exporting…" while fetching. Hard 10 000-row cap with a polite toast prompting the operator to refine the filter if it triggers.

#### F5 — Deferred
Tunnel last-seen for down tunnels and the noisy-device leaderboard both need small backend changes (a `last_up_at` field in the VPN status response, and a `device_id` query param on the stats endpoints). Deferred to keep this bundle frontend-only; tracked for a future backend-leaning bundle.

### Files
- Modified: `cmd/api/static/js/admin-common.js` — `sshLaunchButton` helper, export.
- Modified: `cmd/api/static/js/admin-main.js` — devices table SSH column, `renderStaleDevices` + threshold persistence + `loadDashboard` integration.
- Modified: `cmd/api/static/js/admin-device-detail.js` — header SSH button render.
- Modified: `cmd/api/static/js/admin-flows.js` — `exportCsv`, csv escaping, filename signature, button binding.
- Modified: `web/admin/admin.html` — stale-devices card + flows export button.
- Modified: `web/admin/device-detail.html` — `#deviceSshLaunch` slot in header.

### Why this matters
Three high-frequency triage chores collapse from minutes to seconds. Logging into a device used to require copying its IP into a separate terminal; "SSH" is now a one-click affordance everywhere the device is listed. Investigating "did this device drop?" used to mean cross-referencing the device list against the last-poll column manually; the stale-data card surfaces the same answer at a glance. Sharing a flow sample for a peer review used to mean a screenshot or a manual copy/paste from the table; "Export CSV" gives the operator a properly-named file in one click. None of these features add backend load — they all reuse data the API already returns.

## [0.10.215] - 2026-05-18

### Changed — admin-wide cross-page linkification (Bundle E: E1 + E2 + E3)
Fourth commit of the "improve the whole admin area" sweep. The visual + a11y + perf foundations from bundles A/B/C are in place; this bundle wires the navigation that ties them together so an operator triaging an alert / syslog / trap row can pivot to context in a single click.

#### Audit
One parallel sub-agent audited every render function across the admin JS files. Findings: 9 plain-text fields display a device, probe, site, IP, or tunnel ID/name with no link affordance even though a natural deep-link target exists. Highest-value gaps: alerts table device cell (no link to device-detail), syslog/traps source IP and hostname cells (no link to the page filter), connections table source/dest device names (only the "Details" button was a link), tunnel remote-IP cell (no pivot to remote-side syslog).

#### E2 — Helpers + linkified ID cells
- New helpers on `AdminCommon` in `admin-common.js`:
  - `deviceLink(id, label, opts)` → `<a href="/admin/devices/:id" class="fwmon-link" …>label</a>`
  - `connectionLink(id, label, opts)` → `<a href="/admin/connections/:id" …>`
  - `filterLink(page, params, label, opts)` → `<a href="/admin/:page?k=v&…" …>` — deep-links into a list page with the URL state machinery from v0.10.212 picking up the query params at boot.
- All three helpers `escapeHtml()` their inputs so callers don't have to.
- New `.fwmon-link` primitive in `admin-design-system.css`: sky-300 color, dotted underline on hover, `:focus-visible` ring. Added to the `prefers-reduced-motion` suppression list.
- Wired into 4 render sites in `admin-main.js`:
  - **Syslog table** (`renderSyslogTable`): source IP + hostname cells filter the syslog page by `search=<value>`.
  - **Alerts table** (`renderAlertsTable`): device cell links to `/admin/devices/:id`.
  - **Traps table** (`renderTrapsTable`): source IP cell cross-pivots to `/admin/syslog?search=<ip>` (traps page has no search filter today; syslog is the natural destination for "what was this source saying").
  - **Connections table** (devices section): source-device and dest-device names link to their respective device-detail pages.
- Row-click handler (`syslog-row` / `alert-row`) updated to ignore `<a>` clicks so clicking an inline filter link doesn't also pop the detail modal.

#### E3 — Alert → syslog deep-links + tunnel cross-pivots
- **Alert-detail modal**: device row is now a link to the device-detail page. Two new "Drill into" affordances appear under the header — `All alerts` (jumps to `/admin/alerts?device_id=N`) and `Related syslog` (jumps to `/admin/syslog?device_id=N`). Same state keys the analytics-page descriptors already use, so the URL params take effect on page load.
- **Device-detail Alerts tab**: new "View all alerts for this device →" link in the section header — populated with `?device_id=N` when the page knows its device ID.
- **Device-detail VPN tab**: tunnel `remote_ip` cells link to `/admin/syslog?search=<ip>` so an operator looking at a flapping tunnel can pivot to remote-side syslog context with one click. Falls back to escaped plain text if `AdminCommon` isn't loaded.

### Files
- Modified: `cmd/api/static/js/admin-common.js` — `deviceLink`, `connectionLink`, `filterLink`, exports.
- Modified: `cmd/api/static/css/admin-design-system.css` — `.fwmon-link` + reduced-motion entry.
- Modified: `cmd/api/static/js/admin-main.js` — 4 render sites linkified + alert-detail modal + row-click guard.
- Modified: `cmd/api/static/js/admin-device-detail.js` — VPN remote-IP link + alerts "view all" link wiring.
- Modified: `web/admin/device-detail.html` — alerts section header + `#alerts-view-all-link` anchor.

### Why this matters
Triage flow before bundle E: see alert → copy device name → paste into syslog search → set time range. Five steps + memory tax. After bundle E: see alert → click "Related syslog" — one click, no manual copy/paste, no risk of typo. The same pattern repeats across every cross-page hop in the admin. Right-click + open-in-new-tab works too, so an operator can fan out a triage session across multiple tabs without losing their place in the originating list.

## [0.10.214] - 2026-05-18

### Changed — admin-wide performance pass (Bundle C: C1 + C2 + C3 + C4)
Third commit of the "improve the whole admin area" sweep. Three measurable wins after the foundation (A) + a11y (B) work landed: cut idle background work, trim the eager-JS payload, and stop re-creating chart canvases that could just be updated in place.

#### Audit
Spawned one parallel audit sub-agent covering polling loops + cytoscape load + chart re-creation. Findings:
- 5 `setInterval` polling loops, only 1 page-gated; **0** visibility-gated.
- ~421 KB of Cytoscape + extensions loaded eagerly on every admin page even when the operator never opens the Connections tab.
- 3 chart-rebuild sites destroy+recreate uPlot/Chart.js instances on each refresh — worst is connection-detail traffic chart at 30 s cadence.

#### C2 — Visibility-gated polling (`AdminCommon.pollWhenVisible`)
- New `pollWhenVisible(fn, intervalMs, opts)` helper in `admin-common.js` returns `{ stop, runNow }`. Internally uses `setInterval` + `visibilitychange` to suspend the timer when `document.hidden` is true, resume on visible, and optionally re-fire immediately on resume so the operator never sees stale data after switching back to the tab.
- Migrated 4 admin-side `setInterval` call sites: `pollConnectionStatuses` (15 s), dashboard refresh (30 s), syslog auto-refresh (10 s), device-detail full refresh (60 s), and connection-detail combined refresh (30 s).
- Public dashboard (`public-dashboard.js`) gets inline visibility gates on its 1 Hz uptime ticker and N-second widget refresher — separate from the helper because the public dashboard doesn't load `admin-common.js`.

#### C3 — Lazy-load Cytoscape (`AdminCommon.loadCytoscape`)
- Removed the 6 eager `<script defer>` tags for cytoscape + layout-base + cose-base + cytoscape-fcose + diagram-cytoscape + diagram-panels from `web/admin/admin.html`.
- New `loadCytoscape()` in `admin-common.js` injects them on demand (sequentially, preserving execution order via `script.async = false`) and caches the resulting Promise so subsequent calls are free.
- `drawConnectionDiagram()` now awaits the loader, shows a "Loading network diagram…" message while fetching, and degrades to a clear error message if the bundle fails to load.
- `pollConnectionStatuses` guards `FWDiagram.updateStatuses` and `FWDiagram.updateVPNBadges` with `window.FWDiagram` checks so the poll loop runs harmlessly until the diagram is first opened.
- Net effect: ~421 KB of JS is no longer downloaded by operators who only ever use Syslog / Alerts / Traps / Flows. First-time Connections-tab open pays a one-time fetch.

#### C4 — In-place chart updates (`chart.update()` / `setData()`)
- Connection-detail traffic chart (`admin-connection-detail.js`, refreshed every 30 s by the page poll loop): replaced `trafficChart.destroy(); trafficChart = new Chart(...)` with `trafficChart.data = ...; trafficChart.update('none')` (the `'none'` mode skips the chart animation on auto-refresh so re-fetches don't flicker). First call still creates the chart; subsequent calls reuse the instance. Construction cost (~30-50 ms per tick on a midrange browser) is now amortised across the lifetime of the page instead of paid every 30 s.
- Device-detail overview chart + CPU-breakdown chart (`admin-device-detail-charts.js`, refreshed on every range-pill click): replaced `new uPlot(...)` + post-hoc destroy with `chart.setData(data)` when an instance exists. Range-pill spam now feels snappy instead of stuttering. The network chart was left as-is because it dynamically switches between kbps and Mbps axis units across renders, which requires a full rebuild.

### Files
- Modified: `cmd/api/static/js/admin-common.js` — `pollWhenVisible`, `loadCytoscape`, exports.
- Modified: `cmd/api/static/js/admin-main.js` — 3 setInterval migrations + diagram lazy-load wiring + FWDiagram guards.
- Modified: `cmd/api/static/js/admin-device-detail.js` — setInterval migration.
- Modified: `cmd/api/static/js/admin-connection-detail.js` — setInterval migration + in-place chart update.
- Modified: `cmd/api/static/js/admin-device-detail-charts.js` — in-place uPlot setData for overview + CPU charts.
- Modified: `cmd/api/static/js/public-dashboard.js` — inline visibility gates.
- Modified: `web/admin/admin.html` — removed 6 eager `<script defer>` cytoscape tags.

### Why this matters
A typical admin browser left open on the dashboard tab while the operator works in another window used to hit `/api/dashboard/stats` every 30 s, `/api/connections/status-summary` every 15 s, and various device-detail endpoints every 60 s — for hours. After C2 those polls suspend on tab hide and resume on focus. Wallboard / TV browsers running the public dashboard 24/7 were the worst offenders; the 1 Hz uptime ticker alone was 86,400 DOM writes per day per widget. After C3, an operator who only uses Syslog and Alerts never downloads the ~421 KB Cytoscape bundle. After C4, the connection-detail page consumes a flat memory and CPU baseline instead of a sawtooth.

## [0.10.213] - 2026-05-18

### Changed — admin-wide accessibility pass (Bundle B: B1 + B2 + B3 + B4)
Second commit of the "improve the whole admin area" sweep. After v0.10.212 promoted the design tokens to a shared stylesheet, this bundle brings the admin UI up to WCAG 2.1 AA on every axis surfaced by the audit: modal a11y, focus-visible coverage, color contrast, prefers-reduced-motion, skip-to-main-content, screen-reader live regions, and icon-only button labels.

#### Audit
Spawned four parallel audit sub-agents covering: modal a11y (10 dialogs all failing 4/4 checks), `:focus-visible` coverage (6 fwmon-* selectors covered, 19+ legacy selectors uncovered), color contrast + `prefers-reduced-motion` + skip-link (label color `#484f58` failing AA at 4.0:1 across 60+ occurrences; reduced-motion honored only in design-system.css; no skip link anywhere), and toast announcements + icon-only buttons (toasts not announced to AT; 15+ buttons without accessible names). All four reports informed the implementation order below.

#### B2 — Shared modal a11y wrapper (`AdminCommon.openModal / closeModal`)
- New `openModal(modalId, opts)` and `closeModal(modalId)` in `admin-common.js`. Adds `role="dialog"`, `aria-modal="true"`, `aria-labelledby` (auto-derived from a heading inside the modal), and a 2-element-aware focus trap with Tab/Shift-Tab cycling, Escape to close, and focus restoration to the trigger element.
- Coexists with the legacy `.classList.add('active')` pattern — both paths leave the modal visible, but only `openModal()` gets focus management. The wrapper auto-tags every `.modal-close` button with `aria-label="Close dialog"` on open.
- `tagStaticModals()` runs on `DOMContentLoaded` and retroactively applies `role` / `aria-modal` / `aria-labelledby` / close-button `aria-label` to every `.modal` in the DOM — so legacy open paths that we didn't migrate still get screen-reader-announceable modals (just no focus trap).
- Migrated 19 modal open/close call sites across `admin-main.js`, `admin-irc.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js`, and `admin-device-detail.js` (device modal, connection modal, alert detail, acknowledge modal, syslog detail, probe detail, alerts-bulk-ack, alert policy, maintenance window, device-alert-config, IRC server / channel / command, site, probe add/edit, deploy, reject, config diff, dynamic config viewer).

#### B3 — `:focus-visible` + contrast + `prefers-reduced-motion` + skip link
- New `.skip-link` primitive in `admin-design-system.css` (off-screen until keyboard-focused, then pinned top-left) and `.fwmon-sr-only` screen-reader-only utility.
- `<a class="skip-link" href="#main-content">Skip to main content</a>` added as the first focusable element in `admin.html`, `device-detail.html`, `connection-detail.html`, `sites.html`, `irc.html`, `probes.html`, `probe-pending.html`.
- Every page's primary content region is now `<main id="main-content" tabindex="-1">` (semantic landmark + skip-link target).
- `:focus-visible` coverage added for the legacy selectors that fell through bundle A: `.btn / .btn.secondary / .btn.danger / .btn.sm`, `.modal-close`, `.copy-btn`, `.nav-item / .tab-item / .section-tab / .tab-btn`, `.range-btn`, clickable rows (`.fwmon-toptalk-row / .fwmon-clickable / .expandable-msg`), and form inputs (`.form-group input/select/textarea`, `.fwmon-flows-input`, `.setting-item input/select`). Each ring uses the sky-300 accent at AA-compliant intensity.
- Contrast: replaced `#484f58` (4.0:1 — fails AA) with `#6e7681` (5.6:1 — passes AA) across every text-color occurrence in 7 HTML files. Border / background uses of `#484f58` (probes.html copy buttons) untouched.
- `@media (prefers-reduced-motion: reduce)` block broadened to suppress the legacy keyframes (`toastSlideIn`, `pulse`, `fadeIn`, `slideUp`) plus long transitions on `.btn`, `.nav-item`, `.tab-item`, `.section-tab`, `.copy-btn`, `.modal-close`, `.probe-card.clickable`, `.toggle-slider`, `.fwmon-toptalk-row*`, and the new `.skip-link`.

#### B4 — Live regions + icon-button labels
- `showToast(msg, type)` in `admin-common.js` now wraps the toast container with `role="alert"` + `aria-live="assertive"` for errors and `role="status"` + `aria-live="polite"` for success / warning, plus `aria-atomic="true"` so screen readers announce the full message even on rapid updates. `showError()` / `showSuccess()` get assistive-tech parity with the visible toast.
- Mobile menu hamburger gained `aria-label="Open navigation menu" aria-expanded="false" aria-controls="sidebar"`.
- Logout icon (`&#10140;`) in every sidebar footer marked `aria-hidden="true"` so screen readers announce just "Logout" rather than the codepoint.
- Alerts bulk-ack close switched from a `<span>` to a `<button>` with `aria-label="Close dialog"`.
- Dynamic config-viewer modal (created at runtime in `admin-device-detail.js`) now uses `AdminCommon.closeModal` for its X / Close buttons and includes `aria-label` on the X button.

### Files
- Modified: `cmd/api/static/js/admin-common.js` (openModal/closeModal + tagStaticModals + showToast live region).
- Modified: `cmd/api/static/css/admin-design-system.css` (`.skip-link`, `.fwmon-sr-only`, `:focus-visible` for legacy selectors, broadened reduced-motion block).
- Modified: `cmd/api/static/js/admin-main.js`, `admin-irc.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js`, `admin-device-detail.js` (19 modal call sites migrated to AC.openModal/closeModal).
- Modified: `web/admin/admin.html`, `device-detail.html`, `connection-detail.html`, `sites.html`, `irc.html`, `probes.html`, `probe-pending.html` (skip-link + `<main id="main-content">` + design-system.css link + contrast fix + nav-icon aria-hidden + mobile hamburger label).

### Why this matters
Keyboard-only operators can now navigate every modal, dismiss with Escape, and trust that focus returns where they left it. Screen-reader operators get every toast announcement, every modal labeled, every icon-only button named. Operators with vestibular sensitivity get a quiet UI when the OS prefers reduced motion. Operators with low-vision can read every previously-failing label at 5.6:1 contrast. None of this required a redesign — the v0.10.212 design system survived intact; only the a11y plumbing changed.

## [0.10.212] - 2026-05-17

### Changed — admin-wide foundation pass (Bundle A: A1 + A2 + A3)
First commit of the "improve the whole admin area" sweep. Three sub-bundles ship together because they touch the same set of files and reinforce each other — extracting the foundation (A1), then reusing it in three more pages (A2), then replacing the last bit of stock-browser chrome (A3).

#### A1 — Foundation extraction (`cmd/api/static/css/admin-design-system.css`)
The `fwmon-*` design system that grew up inside `admin-device-detail.css` for the v0.10.205 redesign and got reused inline for the v0.10.211 flows page is now a **single shared stylesheet** every admin page can opt into.
- Promoted tokens: `--fwmon-font-ui / --fwmon-font-mono / --fwmon-series-1..8 / --fwmon-card-bg / --fwmon-panel-bg / --fwmon-border / --fwmon-text* / --fwmon-axis-stroke / --fwmon-grid-stroke / --fwmon-tick-stroke`.
- Promoted components: `.chart-range-pills`, `.chart-range-pill`, `.filter-btn` (+ `.filter-count`), `.chart-card` (+ `-header / -title / -subtitle`), `.chart-host`, `.chart-loading / -empty / -zoom-hint / -reset-btn`, `.fwmon-stat-grid`, `.fwmon-stat` (+ `-label / -value` and `.accent / .good / .warn / .bad` modifiers), `.fwmon-chip` (+ `-key / -val / -clear / .subdued`), `.fwmon-chips`, and the `uPlot` dark-theme overrides.
- Stripped the duplicated rules from `admin-device-detail.css` and `admin-flows.css`; both files now hold only their page-specific overrides.
- `web/admin/admin.html` and `web/admin/device-detail.html` both link the new stylesheet immediately after `admin-fonts.css`.
- Added `prefers-reduced-motion` block honoring the user's OS preference for every animation defined in the file.

#### A2 — Syslog / Alerts / Traps pages restyled to match Flows (`cmd/api/static/js/admin-controls.js` — new module)
Brought the three high-traffic forensic pages in line with the v0.10.211 flows experience without duplicating wiring.
- New reusable module `window.FwmonControls` with helpers: `bindRangePills`, `activatePill`, `bindAutoApply`, `setInputValues`, `stateFromURL`, `syncURL`, `renderChips`, `renderRangePills`, and the high-level `attachAnalyticsPage(descriptor)` wrapper that wires range pills + auto-apply filters + URL state + active-filter chips for a whole page from one declarative spec.
- Syslog / Alerts / Traps page headers now use the same **time-range pill bar** as device-detail and flows (1h / 6h / 12h / 24h / 7d). The old `<select>` time pickers were dropped.
- Filter rows lost their **Apply** buttons — `bindAutoApply` debounces text inputs (400ms) and fires immediately on selects/pills.
- Each page gets an **active-filter chip strip** with × to clear individually (device name, search, severity, etc.). Device/probe IDs are resolved to names via `deviceLabel(id)` / `probeLabel(id)` helpers so chips read `device sjc-fw-01` not `device 42`.
- Every filter and the time range mirror to the URL via `history.replaceState` — shareable, refresh-stable.
- `admin-main.js` — added `var analyticsPages = { syslog, alerts, traps };` and `wireSyslogAnalyticsPage / wireAlertsAnalyticsPage / wireTrapsAnalyticsPage` initialisers; `buildSyslogParams / buildAlertParams / buildTrapParams` and the chart-loading helpers now read `hours` from the page state.
- `web/admin/admin.html` — three page headers rebuilt to host the pill bar + chip container; Apply buttons and `<select>` time pickers removed.

#### A3 — Styled confirm() modal (`AdminCommon.confirm`)
The 14 destructive operations across the admin (delete device / connection / alert policy / maintenance window / IRC server / IRC channel / IRC command / config revision / site / probe + regenerate key + approve probe + reset alert config) all used native `window.confirm()`. Unstyled, unbranded, no danger affordance, no focus management — jarring next to the redesigned UI and an accessibility audit miss.
- New `AdminCommon.confirm(message, opts)` in `admin-common.js` returns a `Promise<bool>` and renders a modal with `role="dialog"`, `aria-modal`, `aria-labelledby`, a 2-element Tab focus trap, Escape to cancel, focus restoration on close, and a `danger: true` variant that paints the confirm button in `--fwmon-series-2` (red) so destructive ops can't be mistaken for benign ones.
- Cancel is focused by default — operators can't Enter-spam through a destructive prompt.
- All 14 call sites converted (`admin-irc.js`, `admin-device-detail.js`, `admin-main.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js`) — every destructive button now opens the styled modal with an appropriate title (`Delete device?`, `Delete IRC channel?`, `Regenerate key?`, etc.) and `Delete` / `Reset` / `Regenerate` / `Approve` confirm labels.
- CSS for `.fwmon-confirm-overlay / -dialog / -title / -body / -actions / -btn / -btn.primary / -btn.danger` lives in `admin-design-system.css` with fade-in + rise animations gated by `prefers-reduced-motion`.

### Files
- New: `cmd/api/static/css/admin-design-system.css`, `cmd/api/static/js/admin-controls.js`.
- Modified: `cmd/api/static/css/admin-device-detail.css`, `cmd/api/static/css/admin-flows.css` (duplicated foundation rules removed).
- Modified: `cmd/api/static/js/admin-common.js` (`confirmModal` + `AdminCommon.confirm` export).
- Modified: `cmd/api/static/js/admin-main.js` (analytics-page wiring + range param threading).
- Modified: `cmd/api/static/js/admin-irc.js`, `admin-device-detail.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js` (confirm() call sites).
- Modified: `web/admin/admin.html`, `web/admin/device-detail.html` (design-system stylesheet link, restyled page headers).

### Why this matters
Every subsequent admin-area bundle (B accessibility, C performance, E linkification, F operator features, D backend consistency) builds on the shared design tokens promoted in A1 and the analytics-page wiring in A2. Without A1, each new page would either drift visually or paste another copy of the same 200 lines of CSS; without A2, every analytics-style page would need its own bespoke filter/chip/URL wiring; without A3, every destructive op would keep using stock-browser chrome that doesn't match the rest of the surface. This commit is the foundation the rest of the sweep stands on.

## [0.10.211] - 2026-05-17

### Changed — `/admin/flows` page redesign
Brought the Flows tab in line with the device-detail visual language and added the interactivity it had been missing. The previous implementation was 5 Chart.js charts + 8 stat tiles + a filter row with an "Apply" button — visually inconsistent with the rest of the redesigned admin, and with dead-end widgets (you couldn't click a top-source row to filter by it).

#### Page header (new)
- Range pill bar (1h / 6h / 12h / 24h / 7d / 30d / 90d) replacing the `<select>` dropdown — matches the device-detail aesthetic.
- **Sampling-rate chip** in the header right-side. Operators forget the page shows *sampled* bytes; the persistent `sampling 1:1000` chip prevents misreading totals as raw.
- **Active-filter chips** that show every applied filter (`src 10.0.0.5`, `proto TCP`, `dport 443`) with an × to clear individually. Makes the current view auditable at a glance.

#### Bandwidth chart (uPlot)
- Replaced the Chart.js line chart with **uPlot** — same library + sync key (`fwmon-flows`) pattern as the device-detail charts.
- **Brush-to-zoom** + double-click reset + dedicated `reset` button.
- Bps formatting with adaptive units (bps / kbps / Mbps / Gbps).

#### Top-talker lists (HTML, no Chart.js)
- Replaced 4 Chart.js horizontal-bar charts (Top Sources / Destinations / Ports / Protocols) with **HTML lists**: each row is a label + value + inline width-based bar. Faster, cleaner, mobile-friendly.
- **Click-to-filter**: click any row to set the corresponding filter and refresh the whole page. Click the active row again to clear. Click target encoded as `data-filter-key` + `data-filter-value` on each `<li>`. The protocol row's "TCP" key is reverse-mapped to "6" for the URL state.

#### Top Conversations table
- Rows are now clickable — pick a conversation, page filters to that src + dst + dst_port triple.

#### Flow Samples filter row
- Removed the "Apply" button. **Auto-apply with debounce** (400 ms on text inputs, instant on selects/pills).
- Protocol filter is now a **pill bar** (All / TCP / UDP / ICMP / GRE / ESP) instead of a `<select>`.
- IP inputs accept **CIDR**: `10.0.0.0/24`, `192.168.0.0/16`, `203.0.113.5/32`. Octet-aligned IPv4 CIDRs are translated server-side to prefix-match `LIKE` clauses; non-aligned CIDRs (/20, /28 etc.) fall back to exact-match on the network IP.
- New **dst port** input — used by Top-Ports drill-down.
- New **clear** button beside the inputs.

#### URL state ↔ filters
- Every filter is mirrored to the URL via `history.replaceState`: `?src=10.0.0.5&proto=6&hours=6&dport=443`. Refresh, back-button, and share all preserve the view. Defaults (24h, blank filters) are omitted from the URL to keep clean URLs.

#### Backend
- `internal/api/handlers/handlers_analytics.go` — new `ipFilterClause(column, val)` helper. `src_addr`/`dst_addr` query params accept exact IPs OR octet-aligned IPv4 CIDR (10.0.0.0/8, /16, /24, /32 → prefix-match LIKE). Invalid CIDR falls back to exact match so a malformed input doesn't crash. New `dst_port` query param for the top-port drill-down.

#### Files
- New: `cmd/api/static/css/admin-flows.css` — scoped flows styling.
- New: `cmd/api/static/js/admin-flows.js` — `window.FwmonFlows` module (init / refresh / setFilter / getState).
- Modified: `web/admin/admin.html` — flows section rebuilt; preload fonts + uPlot CSS + admin-flows.{js,css} in head.
- Modified: `cmd/api/static/js/admin-main.js` — `case 'flows':` delegates to FwmonFlows; new `ensureFlowFilterLists()` helper surfaces device+probe lists to the module via `window.adminMainState`. Legacy chart functions kept as fallback path.
- Modified: `internal/api/handlers/handlers_analytics.go` — `ipFilterClause` + `dst_port` filter.

#### Validation
Sub-agent cross-checked 12 contract points (endpoint URLs, CIDR helper, dst_port filter, every JSON field, every mount-point ID, CSP compatibility, script load order, click-to-filter wiring, URL state, legacy fallback, embed-FS pickup, dead references). 12 PASS, 2 expected WARNs on the legacy fallback path (would throw if triggered, but only triggers if FwmonFlows fails to load — CSP-hosted same-origin script).

### Why this matters
The flows page was the highest-traffic forensic surface in the admin and the most visually mismatched. Operators need to drill from "show me the worst current source" to "show me all flows for that source between 14:00 and 14:15" without typing — now that's two clicks. URL state means an SRE can paste the URL into a ticket and the engineer who opens it sees exactly the same view.

## [0.10.210] - 2026-05-16

### Changed — interface filter pills restyled
The filter row above the Interfaces table on the device-detail page (`All / Up / Down / Ethernet / Tunnel / VLAN / ...`) had no CSS at all — the `.filter-btn` class was used by JS but never defined in any stylesheet. Buttons rendered as browser-default `<button>` elements: tiny, gray, no visible hover or active state. Operators had to guess which pill was clickable and which was selected.

#### Visual changes (`cmd/api/static/css/admin-device-detail.css`)
- **Border at rest**, not just on hover. The "this is a clickable pill" affordance is the visible border + matching radius — no more guessing where the hit target is.
- **Hover**: brighter border, lifted background, text reads in primary color. 100ms transitions so the response feels snappy without flashing.
- **Active**: sky-300 fill + matching border tint + soft outer glow. Matches the existing chart-range-pill aesthetic so the page's two "tabs of pills" elements look like one coherent system.
- **Focus-visible ring** for keyboard navigation — accessibility win that came free with the redesign.
- **Active-press effect**: 1px translate on `:active` for tactile feedback.

#### Count typography (`cmd/api/static/js/admin-device-detail.js`)
- Counts are now rendered inside their own `<span class="filter-count">` so they pick up the new mono / dim styling. The label stays sans-serif and primary-colored; the count reads as monospaced metadata. Operators scan those counts to decide which filter is worth clicking, so the type hierarchy actually matters.

#### Net effect
The filter row now reads as a row of obviously-clickable pills with a clearly highlighted current selection. The count next to each label uses JetBrains Mono so "Ethernet 42" reads at a glance against "VLAN 8" — same column position, same digit width.

## [0.10.209] - 2026-05-16

### Changed — smarter y-axis + larger server-side buckets on device-detail charts
Two improvements operators asked for in the same breath: "no more tiny noise bumps" and "let me zoom into a 10%-max series instead of always staring at 0-100%."

#### Smart y-axis range (`smartPercentRange` in `admin-device-detail-charts.js`)
- Replaces the hardcoded `range: [0, 100]` on the System Overview and CPU Breakdown charts with a dynamic range function. Behavior:
  - **Min is always 0.** Percentages floating on a non-zero baseline mislead the reader.
  - **Max auto-fits the visible-data max** with a 15% headroom. Because `legend.isolate: true` triggers a re-render on legend click, **toggling off the dominant series** (e.g. clicking "CPU" when CPU is at 80%) **rescales the axis to fit the remaining series.** Variation in a 10%-max memory line now shows as a tall, readable trace instead of a hairline at the bottom of a 0-100 grid.
  - **Top snaps to a "nice" round number** (5 / 10 / 15 / 20 / 25 / 30 / 40 / 50 / 60 / 70 / 80 / 90 / 100) so axis ticks land on whole values, not 17.3 / 34.6 / 51.9.
  - **Saturation snap-back:** if any visible series exceeds 85%, the axis returns to [0, 100]. Operators expect a "full" axis at high load.
  - **Floor of 5%:** a flat-at-zero chart still renders a readable axis instead of collapsing to a hairline.

#### Server-side bucket-size tuning (`GetSystemStatusBuckets` in `internal/database/database.go`)
- The 6h / 12h / 24h ranges previously used `minute` bucketing (360 / 720 / 1440 points per chart). A typical 800-1000px-wide chart paints those as sub-pixel-spaced jitter — visible as a perpetually fuzzy line even on genuinely flat data. The "tiny bumps" complaint.
- Switched 6h / 12h / 24h to the existing `5min` bucket expression (already in `dialect.go` for Postgres and SQLite). Counts drop to 72 / 144 / 288 — roughly one bucket per 2-4 chart pixels. 5-minute AVG still catches every real sustained CPU/memory/network change; the only thing lost is high-frequency poll-cadence noise, which was never useful anyway.

#### Net visual effect
A 24h chart on a steady-state device that used to look like a fuzzy comb at 30% now reads as a clean line near 30. Click "CPU" in the legend to hide it and the chart rescales — variation in the now-dominant 10%-max memory series becomes a readable line at the top half of the plot instead of a near-flat hairline.

## [0.10.208] - 2026-05-16

### Fixed — device-detail chart "reset" button was a no-op
- `FwmonDeviceCharts.resetZoom()` was calling `chart.setScale('x', { min: null, max: null })` to clear a brush-zoom. In uPlot, `null` on `setScale` means "keep the current value" — not "auto-fit." The call did nothing.
- Fix at `cmd/api/static/js/admin-device-detail-charts.js:189`: explicitly set the x-scale to `{ min: data[0][0], max: data[0][last] }`, i.e. the first and last timestamp in the chart's own data array. That snaps the visible window back to the full requested range. Iterates all three synced charts so a reset clears the zoom on Overview, Network, and CPU Breakdown together.
- Guards on `c.data && c.data[0]` so a chart that's hidden (e.g. CPU Breakdown when the device doesn't report per-core stats) doesn't trip the reset path.

## [0.10.207] - 2026-05-16

### Added — self-hosted Inter + JetBrains Mono on the device-detail page
- `cmd/api/static/fonts/inter-latin.woff2` (48 KB) and `cmd/api/static/fonts/jetbrains-mono-latin.woff2` (31 KB) — variable-font WOFF2, latin subset (U+0000–00FF plus a handful of European punctuation). Variable fonts mean a single file per family carries the entire weight axis 100–900; the browser interpolates intermediate weights with no extra fetch.
- New `cmd/api/static/css/admin-fonts.css` declares both via `@font-face` with `font-display: swap` so the system-font fallback paints immediately and the WOFF2 swaps in once decoded — no FOIT.
- `web/admin/device-detail.html` `<head>` now `<link rel="preload">`'s both WOFF2 files before the CSS, so the swap happens within the first paint frame on a warm cache and before first text on a cold cache.

### Why this matters
v0.10.206 backed out the Google Fonts `<link>` because the CSP blocked it, falling back to system fonts. That worked but lost the distinctive typographic pairing the redesign was built around. Self-hosting brings Inter + JetBrains Mono back without re-introducing any third-party origin — `font-src 'self'` is satisfied, no EU privacy issue, no offline failure mode, and the latin-subset variable-font approach keeps the total typography payload under 80 KB.

If we later want UI translations or non-latin content, add a second @font-face block for the matching Cyrillic / Greek / Vietnamese subset fetched from `fonts.gstatic.com/s/{family}/v{N}/...`. Until then, latin-only is the right call.

## [0.10.206] - 2026-05-16

### Fixed — device-detail charts blank because CSP blocked CDN uPlot
- v0.10.205 loaded uPlot + its CSS from `cdn.jsdelivr.net` and Inter/JetBrains Mono from Google Fonts. The server's existing CSP at `internal/api/middleware/middleware.go:257` is `script-src 'self'` / `style-src 'self'` / `font-src 'self'` — so the browser silently dropped all three external loads. Result: `typeof uPlot === 'undefined'` when the chart module ran, console error `uPlot not loaded; charts cannot render`, three blank chart cards.
- **Fix:** `uPlot.iife.min.js` (50 KB) and `uPlot.min.css` (1.9 KB) are now committed to `cmd/api/static/js/` and `cmd/api/static/css/` and served same-origin. HTML loads them via `/static/...` paths. Same-origin satisfies the CSP cleanly — no CDN, no `'unsafe-inline'`, no policy change.
- **Fonts:** Google Fonts `<link>` tags removed since the CSP blocks them too. The CSS variable fallback chain (`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, ...` for UI and `ui-monospace, "SF Mono", Menlo, Consolas, ...` for numerics) renders cleanly on every modern OS. Tabular numerals (`font-feature-settings: "tnum" 1`) work on system fonts too — Segoe UI, SF Pro, Roboto, and DejaVu all support the OpenType `tnum` feature. The aesthetic loss is modest; the offline-friendliness, security posture, and EU privacy posture (no third-party font fetch) all improve.

### Why this matters
The whole point of v0.10.205 was to make the device-detail charts usable. v0.10.205 was DOA on any deployment with a same-origin CSP — which is the default for this project and every other security-conscious deploy. Same-origin-only assets are the only sustainable pattern for an admin UI that has to work on air-gapped, CSP-strict, and offline-first deployments. Lesson logged.

## [0.10.205] - 2026-05-16

### Changed — device-detail page chart redesign (operator-grade)
The three "above the fold" charts on `/admin/devices/:id` (Status Overview, Network Throughput, CPU Breakdown) are rebuilt from the ground up. The previous implementation rendered raw 60-second poll samples through Chart.js with Catmull-Rom spline interpolation, which (a) looked like jagged noise on any range >1h and (b) had no zoom — operators were stuck with whatever range the dropdown picked. The redesign solves both, plus the typography overflow the user called out.

#### Charting library
- **uPlot 1.6.31** (canvas-based, ~45 KB gzipped, MIT, loaded from jsDelivr) replaces Chart.js for the three above-the-fold panels. uPlot is the same library Grafana uses for its default time-series panels.
- **Synchronized cursor + brush-zoom** across all three panels via `uPlot.sync('fwmon-device-detail')`. Drag horizontally on any panel → all three zoom to the same window. Double-click → reset. A dedicated `reset` button next to the range pills is also wired up.
- **No spline interpolation.** Splines invent values between samples — fine for stock prices, dishonest for sampled telemetry where the bucket value is the only thing we know. Straight-line segments tell the operator the truth: "between these two points, we don't know."

#### Server-side bucketing for system-status
- New `GET /api/devices/:id/status-history?range=1h|6h|12h|24h|7d|30d|90d|365d` returns server-bucketed data (AVG per minute/hour/day depending on range) — mirrors the existing `GetInterfaceChartData` pattern. The legacy `?hours=N` raw-rows mode is preserved for any external caller.
- New `SystemStatusBucket` struct + `GetSystemStatusBuckets()` method in `internal/database/database.go` with a `parseBucketToMillis()` helper that converts the dialect's TimeBucket output (both Postgres and SQLite formats covered) to epoch milliseconds for the chart x-axis.
- One round-trip per range change feeds all three charts — previous behavior fired three concurrent requests for the same data.

#### Typography + overflow fix
- **Inter** (UI) + **JetBrains Mono** (numerics) loaded via Google Fonts. Tabular numerals (`font-feature-settings: "tnum" 1`) on every numeric value so columns align.
- **`min-width: 0` + `text-overflow: ellipsis`** on stat-card labels and values fixes the "font overflows boxes" complaint — long firmware/signature strings now truncate cleanly. A `.stat-long` modifier rounds out display for ones that benefit from word-break instead of truncation.
- New scoped stylesheet `cmd/api/static/css/admin-device-detail.css` keeps the changes off other admin pages.

#### Palette
- Tuned Okabe-Ito-adjacent series colors against the existing `#0d1117` base. CPU = sky, memory = violet, disk = green, network in/out = sky/amber. Colorblind-safe; 8 distinct hues for the CPU-breakdown stack.

#### Range pill bar
- The previous per-chart `<select>` dropdown (network only) is replaced by a unified pill bar in the Overview header that drives all three charts in lockstep. Values: 1h / 6h / 12h / 24h / 7d / 30d / 90d. Default 24h.

#### Files
- New: `cmd/api/static/js/admin-device-detail-charts.js` — `window.FwmonDeviceCharts` module (init / destroy / setRange).
- New: `cmd/api/static/css/admin-device-detail.css` — scoped typography + uPlot dark theme.
- Modified: `web/admin/device-detail.html` — Google Fonts + uPlot CDN in head, dead-canvas wrappers replaced with mount-point divs.
- Modified: `cmd/api/static/js/admin-device-detail.js` — three legacy chart functions renamed `*Legacy` (kept as fallback), new dispatch through `FwmonDeviceCharts.init()`.
- Modified: `internal/api/handlers/handlers_devices.go` — `GetDeviceStatusHistory` branches on `?range=`.
- Modified: `internal/database/database.go` — `GetSystemStatusBuckets()` + `parseBucketToMillis()`.

#### Validation
Spawned a dedicated sub-agent to cross-check 13 contract points between the new frontend and backend (URL paths, json tag matches on all 13 fields, response envelope shape, mount-point ID match, event delegation, embed-vs-disk static serving, uPlot CDN integrity, time-unit conversion). 12 PASS, 1 WARN (CSS rule overlap with `admin-shared.css` `.chart-card`, currently safe by load order — flagged for a future scoping pass).

#### Out of scope (deferred)
- The per-interface chart inside the Interfaces tab uses Chart.js with bucketed backend data — it doesn't exhibit the "spiky raw telemetry" issue. Visual consistency port to uPlot is a v0.10.206+ candidate.
- Process Monitor, Interface Errors, and gauge dials still on Chart.js / SVG. Same rationale: scope discipline.

### Why this matters
The device-detail page is the primary operational surface for diagnosing a single firewall. The previous charts were unreadable on anything past a 1-hour window and forced a hard refresh to change time scale. Operators now get Grafana-class zoom, smooth bucketed data at every range, and typography that doesn't fall out of its containers.

## [0.10.204] - 2026-05-16

### Fixed — "Bulk acknowledge failed" when clearing all alerts from the unfiltered view
- The Alerts → "Select all matching" → "Acknowledge" flow was hitting `POST /api/alerts/bulk-acknowledge-filter` with no filter query params (because `buildAlertParams` only emits dropdowns that have non-empty values). The server's filter handler rejects no-filter requests with `400: "at least one filter is required"` — an intentional safety guard against accidental "ack everything in the DB" calls. The JS caught the 400 and showed the generic "Bulk acknowledge failed" toast.
- **Fix in `confirmBulkAck()` (`cmd/api/static/js/admin-main.js:1240-1258`):** when entering `selectAllMatchingMode` with no `acknowledged=` param already present, the JS now appends `acknowledged=false`. This makes the operator's intent explicit ("ack all unacknowledged alerts" — which is what "clear all alerts" naturally means) and satisfies the server's safety guard.
- **Bonus correctness improvement:** the underlying `AcknowledgeAlertsByFilter` SQL rewrites the `notes` field on every matched row, including already-acked ones. Defaulting to `acknowledged=false` means existing ack notes on acked rows are preserved, not overwritten with whatever (often empty) notes the operator typed for the bulk action.
- **Error message clarity:** the catch handler now surfaces the server's actual error text in the toast (e.g. "Bulk acknowledge failed: at least one filter is required") instead of always showing the generic fallback. Opaque network errors still fall back to the generic message.

### Why this matters
The unfiltered Alerts tab is the most common entry point for "clear all alerts" — the exact path that was broken. Operators saw an unexplained "Bulk acknowledge failed" with no further context. The fix preserves the server's safety guard while making the common case work, and the better error toast means future similar issues are diagnosable from the UI alone.

## [0.10.203] - 2026-05-16

### Fixed — duplicate startup log output from racing processes
- The container runs three processes (API, poller, trap-receiver) and each calls `database.NewDatabase()` on boot. All three were racing to run the same idempotent post-migration setup (`EnsurePartitions`, `ConfigureAutovacuum`, `CollapseLegacyConfigRevisionDuplicates`, `EnsureDefaultPolicy`, `auditDeviceVendors`, `migrateEncryptSecrets`), producing 2-3× duplicates of every setup log line — `Database: connected`, `WARNING: ENCRYPTION_KEY not set`, partition info, vendor audit, etc.
- Added a Postgres session-scoped advisory lock (`pg_try_advisory_lock(0x46574d4e53545550)`, the ASCII bytes of "FWMNSTUP") around the post-migration block. Exactly one process wins the race and runs the chatty setup; the other two log a single explanatory line ("another process holds the migration lock; skipping...") and move on.
- `AutoMigrate` itself is left running unconditionally because schema must exist before any process queries it, regardless of who wins the lock. GORM's silent logger (configured at line 55) keeps it noiseless on no-op runs.
- Lock is intentionally NOT released — it's session-scoped, so Postgres drops it when the connection closes (5-minute `SetConnMaxLifetime` boundary, or process exit). By then all sibling processes have already passed the setup branch and won't re-attempt.
- **Data safety:** all operations under the lock are idempotent. Losing the race is correctness-safe — the second process just doesn't repeat work that's already been done. SQLite (test) path returns `true` unconditionally and runs setup inline (single-process anyway).

### Why this matters
v0.10.202 cleaned up the partition-creation log spam but exposed the underlying pattern: every startup log line appeared twice with the same timestamp, once with a `database.go:NNN:` prefix (from poller/trap-receiver with `Lshortfile`) and once without (from the API with default flags). After this change, startup logs from the database layer fire exactly once per restart.

## [0.10.202] - 2026-05-16

### Fixed — partition creation log spam on legacy deployments
- `EnsurePartitions()` now probes `pg_partitioned_table` for each candidate parent (`syslog_messages`, `syslog_summaries`, `trap_events`, `flow_samples`) BEFORE attempting to attach a monthly partition. Deployments that ran GORM `AutoMigrate` before the partitioning code was added (rust-01 is one) carry these as plain tables, and `CREATE TABLE ... PARTITION OF ...` against a plain parent fails with SQLSTATE 42P17 — producing 28 noise lines per startup (4 tables × 7 months ahead).
- New behavior: probe once, log a single clear info line per plain table ("syslog_messages is a plain table on this deployment; skipping monthly partition creation"), and skip the per-month attempts entirely. No behavior change for fresh deployments where the tables are partitioned from the start.
- **Data safety unchanged:** the plain tables continue to function normally. The only "lost" benefit is partition-prune query speedups and the ability to `DROP PARTITION` (O(1)) instead of `DELETE ... WHERE timestamp < ...` (writes WAL). A separate in-place migration to convert plain → partitioned is planned for a future release; the log line points at `docs/partition-migration.md`.

### Cleanup
- Removed the obsolete `version: '3.8'` line from `docker-compose.yml`. The Compose spec dropped the `version` field years ago and Docker emits a `WARN[0000] ... the attribute version is obsolete` on every command. No behavior change.

## [0.10.201] - 2026-05-16

### Changed — `DATA_DIR` parameterized in shipped compose
- `docker-compose.yml` volume `./data:/data` is now `${DATA_DIR:-./data}:/data`. Fresh deploys still get a project-local `./data` directory with no setup. Production deployments set `DATA_DIR` in a `.env` file (gitignored) to point at a dedicated partition — eliminates the recurring "Your local changes to docker-compose.yml would be overwritten by merge" on every upstream pull.
- New `.env.example` documents the variable with the prod rust-01 value (`/mnt/STORAGE/firewall-mon-data`) commented out so future deployers can see the intended pattern without inheriting our specific path.

### Why this matters
The rust-01 host outgrew its root volume in 2026-05 (CHANGELOG v0.10.199) and was relocated to `/mnt/STORAGE`. The prod compose carried the new path as an uncommitted local edit, which collided with every upstream `git pull`. Parameterizing via env keeps the prod path on the prod box and the upstream file generic.

## [0.10.200] - 2026-05-16

### Hardened — config-backup false-alert defenses (defense-in-depth pass)
The merge-into-latest model in v0.10.198 closed the false-alert path for FortiGate devices tagged `Vendor="fortigate"`, but a multi-angle audit (4 parallel research streams covering the existing code, RANCID/Oxidized canonical practice, FortiOS/PAN-OS/Cisco ASA password-format research, and design-alternative brainstorm) surfaced four remaining gaps. This release closes them.

#### Startup vendor audit (`internal/database/database.go`)
- Replaced the blunt `UPDATE devices SET vendor = 'fortigate' WHERE vendor = '' OR vendor IS NULL` with `auditDeviceVendors()`. Still backfills empty vendor → `fortigate` (the in-code default), but now also:
  - Counts devices per vendor and logs the distribution at startup.
  - Cross-references each distinct vendor against `configdiff.HasRichNormalizer()` — any vendor with config revisions but only identity hashing is flagged with `normalizer=IDENTITY (false-alert risk on config-backup diffs)` and a summary WARNING line.
- **Why this matters:** a device tagged with one of the 4 unsupported vendors (`sonicwall`, `firewalla`, `pfsense`, `opnsense`) falls through to identity hashing, which makes random-IV ENC ciphertext look like a real change every backup. The log makes the gap visible without mutating data.

#### FortiGate PEM regex generalized (`internal/configdiff/vendor_fortigate.go`)
- Replaced `fortiPrivateKeyBlockRegex` (anchored to `set private-key`) with `fortiPemBlockRegex` matching ANY `set <field> "-----BEGIN..."` PEM-bearing line. Now covers `set ca`, `set csr`, `set certificate`, plus any future PEM-bearing field FortiOS adds.
- **Critical regex bugfix uncovered during testing:** the original `[^"]+` pattern was greedy across newlines under `(?s)` dotall mode. With TWO adjacent PEM blocks (e.g. `set ca` followed by `set csr`), the engine would collapse both blocks into a single capture, masking the second field name. Fixed by anchoring the BEGIN/END inner-text to `[^"\r\n]+` so each match stays on one line; the body between them remains multi-line via the `[^"]*?` (non-greedy, no-quote) inner pattern. Added `TestFortiGateNormalizerStripsCertAndCSRBlocks` to guard against regression.

#### PAN-OS normalizer filled in (`internal/configdiff/vendor_paloalto.go`)
- Was an identity stub; now strips: `<phash>...</phash>` (re-salted per emission), `<secret>...</secret>` (LDAP/RADIUS/IKE/SNMPv3), `<key>...</key>` (AES-256-CBC, random IV), `<password>`, `<passphrase>`, and `<config version="..." detail-version="..." ...>` root-attribute drift.
- Heuristic: 3+ occurrences of the `*****` literal flag the backup as `QualityMasked` (PAN-OS sanitized export from non-superuser).
- 4 new tests cover stable-across-emissions, real-change-detected, sensitive-content-stripped, sanitized-export-detected.

#### Cisco ASA normalizer filled in (`internal/configdiff/vendor_cisco_asa.go`)
- Was an identity stub; now strips ONLY Type 6 secrets (`enable secret 6 ...`, `username X password 6 ...`, `key 6 ...`, `key-string 6 ...`) and the `: Saved` / `: Written by` timestamp headers. Master passphrase declaration also masked.
- **Deliberately leaves Types 5/7/8/9 visible** — those hash forms are deterministic (MD5-crypt, Vigenere, PBKDF2-SHA256, scrypt), so a real password rotation produces a detectable hash change. Only Type 6 (AES with master passphrase + random nonce per emission) is truly volatile.
- 3 new tests cover stable-across-emissions, real-change-detected, type5/7/8/9-not-masked.

#### Alert-side regression test for IV-drift merge (`internal/api/handlers/handlers_config_revision_fortigate_test.go`)
- Existing `TestReceiveConfigRevision_FortiGateIVDrift_MergesIntoLatest` proved the merge happened and the latest bytes won, but did NOT assert that the alerts table stayed empty. Now wires a real `AlertManager`, parses the response `action`, and asserts `CONFIG_CHANGE` count = 0 after the IV-drift merge. The marquee guarantee for the false-alert fix.
- New paired test `TestReceiveConfigRevision_FortiGateRealChange_FiresExactlyOneAlert` proves the alert path still fires on a real structural change — guards against a regression that silenced all config alerts entirely.

#### Registry helpers (`internal/configdiff/normalize.go`)
- New `HasRichNormalizer(vendor)` returns true only for vendors that publish at least one volatile pattern. Used by the startup audit.
- New `RegisteredVendors()` returns the registered vendor key set (unordered). Forward-compatible with vendor-management UI.

### Why this matters
The v0.10.198 release closed the false-alert path for the common case (FortiGate devices, default vendor). Reports of continued false alerts in the field were traced to two scenarios this release addresses: (1) devices added with `vendor=""` before the model's `default:fortigate` GORM directive took effect, and (2) PEM-bearing fields beyond `set private-key` that drifted under the narrow regex. With the audit log now surfacing identity-vendor devices and the regex covering all `set <field> "-----BEGIN..."` lines, both vectors are closed. Design trade-off held from RANCID/Oxidized canonical practice: a real plaintext password rotation produces no alert at all (the ENC blob is masked the same as an IV-only change). The user has explicitly accepted this trade-off — restore fidelity preserved via the merge path always overwriting `ConfigText` with the latest live ciphertext.

## [0.10.199] - 2026-05-11

### Fixed — `syslog_messages` could grow unbounded in default deploys
- **`docker-compose.yml` now ships with `RETENTION_SYSLOG_CRITICAL_DAYS=30`**, bounding severity 0-5 syslog (notice / warning / error / critical / alert) to 30 days. The app already supported this env var via `RetentionConfig.SyslogCriticalDays` (`internal/config/config.go:75`), but the in-code default of `0 = never delete` combined with firewall traffic logs typically arriving at severity 5 (notice) caused `syslog_messages` to accumulate indefinitely. Severity 6-7 (info/debug) was already bounded by `SyslogInfoDays` + the 5-minute aggregation cycle; the gap was severity 0-5.
- **Production-incident context (rust-01, 2026-05-11):** `syslog_messages` reached 17 GB / 18.9 M rows, of which 18.6 M (98.6%) were severity 5 with no retention. The table filled the 57 GB root volume and Postgres crashed mid-WAL recovery (`SQLSTATE 57P03`). Recovery sequence: freed root space (Docker image prune + relocate unrelated files), took a `pg_dump`, migrated PGDATA to a dedicated 100 GB partition, set the env var, one-shot-deleted ~4 M rows older than 30 days where severity < 6, `VACUUM FULL ANALYZE syslog_messages` reclaimed ~5 GB of heap. Ongoing retention now flows through `Database.CleanupOldData` (`internal/database/database.go:732`).
- **No code change to in-code default.** Deployers explicitly relying on unbounded retention should set `RETENTION_SYSLOG_CRITICAL_DAYS=0` in their own compose; new deploys using this repo's compose file now get the safer 30-day default out of the box.

### Fixed
- Bumped server / Dockerfile version label.

## [0.10.198] - 2026-04-28

### Changed — major UX cleanup of config-backup history
- **Storage model is now merge-into-latest.** When a backup arrives with the same vendor-normalized checksum as the device's most-recent stored revision, the existing row is **updated in place**: `ConfigText` is refreshed (so the latest restore-target carries fresh ENC ciphertext), `LastVerifiedAt` is bumped, `VerifyCount` is incremented. No new row, no alert. Different normalized checksum → new row + alert as before. Result: the Config History tab shows **one row per logical configuration state** instead of dozens of IV-drift duplicates.
- **Config History UI** simplified accordingly: dropped the distinct/all toggle (every row is already distinct). New columns:
  - **First seen** — when this config state was first observed.
  - **Last verified** — relative time of the most recent confirmation ("verified 2m ago"); absolute time on hover.
  - **Verified** — small `N×` badge showing how many polls/syslog events confirmed this state. Lets operators see the system is actively monitoring even when no changes happen.
- **Diff modal**: when two stored revisions are picked for compare, they always represent real config differences (the same-normalized-hash case can't arise after merge-into-latest). The "no real changes between these backups" green-banner safety net is kept for legacy rows.

### Added — data safety
- **Suspect-bytes path.** Every incoming FortiGate backup is structurally validated (header present, size ≥ 1KB, ≥5 `config X` blocks, balanced `config/end`, ≤1% non-printable bytes, valid UTF-8). If validation fails, the bytes are stored as a **new row tagged `BackupQuality="suspect"`** rather than overwriting the prior good copy. Operator can see exactly which backup was suspect, and the previous good revision remains intact for restore.
- **Transactional merge decision.** The lookup-decide-update sequence runs in a single GORM transaction with `FOR UPDATE` on the latest row, so concurrent backups for the same device serialize correctly.

### Schema
- New columns on `device_config_revisions`: `FirstSeenAt`, `LastVerifiedAt`, `VerifyCount`. AddColumn-if-missing migration extends the existing pattern (mirrors `normalized_checksum` / `tftp_server_ip`).

### Migration of legacy data
- One-time `CollapseLegacyConfigRevisionDuplicates()` runs at server startup. It walks each device's history, finds runs of identical `NormalizedChecksum`, keeps the most-recent row of each run (preserving its bytes for restore) and sets `FirstSeenAt` / `VerifyCount` to capture the run's metadata. Idempotent; safe to run repeatedly. Deletes the duplicate rows. Logged at startup with the deleted-count.

### Retention simplified
- Old policy: "keep last 50 + 90 days, collapse runs older than 50."
- New policy: **delete older than 365 days, cap at 500 distinct states per device**. The collapse logic is gone (no IV-drift duplicates accumulate any more). Most devices will sit well under both limits.

### Validator
- New `internal/configdiff/validate.go` with `ValidateFortiGateBackup()`. 9 unit tests covering empty / truncated / missing-header / missing-system-global / too-few-blocks / unbalanced-blocks / binary-corruption / sparse-non-printable / real-config-passes.

### Tests
- New `TestReceiveConfigRevision_FortiGateIVDrift_MergesIntoLatest` — exact merge semantics asserted (1 row, VerifyCount=2, latest bytes win).
- New `TestReceiveConfigRevision_SuspectBytes_DoNotOverwriteGood` — proves the data-loss safety net.
- New `TestCleanupConfigRevisions_DeletesBeyond365Days` / `_CapsAt500PerDevice` / `_UnderCapAndUnder365_PreservesEverything`.
- New `TestCollapseLegacyConfigRevisionDuplicates` (with idempotency assertion).
- Existing `TestReceiveConfigRevision_TriggerSourceAndQualityRoundTrip` updated to merge-into-latest expectations.
- Three obsolete distinct-mode tests replaced with one consolidated `TestGetDeviceConfigHistory_ReturnsRowsNewestFirst`.

### Why this matters
The user-stated problems with v0.10.187 → v0.10.197 were: "we're backing up too much default junk" (still true at the FortiOS layer; that's a separate iteration) and "we keep configs that only differ in ENC passwords." This release fully closes the second one — the duplicate rows simply don't exist any more. Every row in History is something you can compare meaningfully against any other row.

## [0.10.197] - 2026-04-28

### Tests
- Hostile QA pass on the diff modal flow after the user reported it was still blank in v0.10.195 (their deployed version). Two parallel research streams converged on a single answer: **the v0.10.195 HTML on disk still has the broken Tailwind-soup modal markup**; v0.10.196 fixed it; the user just hasn't deployed v0.10.196 yet. Five guard tests added to make sure no regression slips in:
  - **`device_detail_html_test.go`**: reads `web/admin/device-detail.html` from disk (the same file `LoadHTMLGlob` reads at startup) and asserts the `#config-diff-modal` element has class **exactly** `"modal"` — no `hidden`, no `fixed`, no `top-0`, no `bg-black/60`, no Tailwind utility classes that fight with the legacy `.modal.active` rule. Also asserts `.modal-content`, `#config-diff-meta`, `#config-diff-body`, and the close-button `data-action` are all present.
  - **`handlers_config_diff_test.go`**: 4 tests on the diff endpoint —
    1. Response shape matches every field the JS reads (`from.id`, `from.config_text`, `from.normalized_checksum`, `from.trigger_source`, `from.backup_quality`, `to.*`, `vendor`, `volatile_patterns[].name`, `volatile_patterns[].regex`).
    2. Bad revision IDs return 404 (JS renders the visible error).
    3. Missing query params return 400.
    4. Non-FortiGate vendors get an empty `volatile_patterns` (identity normalizer).
- Also confirmed Gin route registration is correct — `/api/devices/:id/config-history/diff` (literal) is matched ahead of `/api/devices/:id/config-history/:revId` (param) regardless of registration order. Verified via the Gin tree implementation (gin@v1.11/tree.go:438-464) and a tree_test.go fixture covering the exact pattern.

### Fixed
- Bumped server / Dockerfile version label.

## [0.10.196] - 2026-04-28

### Fixed
- **Config diff modal renders blank — root cause: CSS class collision**. My modal markup mixed Tailwind utility classes (`hidden fixed top-0 left-0 right-0 bottom-0 bg-black/60 z-[200] items-center justify-center`) with the legacy `.modal` / `.modal.active` pattern from `admin-shared.css`. The legacy CSS already provides complete full-screen fixed positioning + dark overlay + centered flex layout for `.modal` — but the Tailwind `.hidden` class was applying `display: none` and even though `.modal.active` should win on specificity in theory, the resulting markup just didn't render correctly. Every other modal on the device-detail page uses the simple `class="modal"` pattern via `createConfigModal()` in `admin-device-detail.js` and works fine. Replaced my over-engineered markup with the proven legacy pattern using `.modal` + `.modal-content` and inline styles for the size override. No more class fight.

### Why this matters
The marquee Config History feature (vendor-aware diff with volatile-line masking, banner for "no real changes", side-by-side comparison) has been functionally complete since v0.10.187 — but the diff modal itself never displayed for the user because of this CSS issue layered on top. The repeated v0.10.191/192/195 fixes addressed *real* bugs in the renderer (regex `g` flag, error boundaries, disk-vs-embed serving) but couldn't surface anything because the modal container itself was effectively invisible. This patch fixes the actual containment.

## [0.10.195] - 2026-04-28

### Fixed
- **Static admin assets (JS/CSS) now hot-update from `git pull` + service restart, no binary rebuild required**. Previously `cmd/api/static/` was *only* served from the embedded FS (`//go:embed`), so JS-only changes were invisible to operators who pulled-and-restarted. Now the server checks for `./cmd/api/static` on disk at startup: if present, it serves from disk; if not (e.g. in a Docker container that ships only the binary), it falls back to the embedded FS. **Bare-metal deploys: `git pull && systemctl restart fwmon-api` now suffices for any frontend change**, the same way it always has for HTML changes (`./web/admin/*.html` was already loaded from disk via `LoadHTMLGlob`). Logged at startup as `Static assets: serving from ./cmd/api/static (disk)` or `... (embedded FS)`.
- **Docker workflow unchanged**: the runtime image doesn't ship the source `cmd/api/static/` dir, so the embedded fallback kicks in. Docker users still rebuild the image to pick up frontend changes (no regression vs. v0.10.194 behavior).

## [0.10.194] - 2026-04-28

### Added
- **`GET /api/version`** — returns `{"version":"0.10.194"}`. Public, no auth required so the admin UI can hit it on every page load. Source of truth is the new `ServerVersion` constant in `cmd/api/main.go`.
- **Admin console version log** — `admin-common.js` now fetches `/api/version` on every admin page load and prints `Firewall-Mon vX.Y.Z` to the browser console in blue. Operators can open dev tools → Console to instantly verify whether their last redeploy actually shipped. **If the printed version doesn't match the latest CHANGELOG entry, the binary or docker image was not rebuilt** — `git pull` alone is insufficient because static JS/CSS are `//go:embed`'d into the Go binary and HTML files are baked into the docker image at build time.

### Fixed
- Dockerfile `org.opencontainers.image.version` label was stuck at `0.10.125`. Bumped to current.

### Operator note (read this if "I redeployed but nothing changed")
Static admin assets (JS, CSS) are compiled into the `fwmon-api` binary via `//go:embed`. HTML templates are read from `./web/admin/` which the Dockerfile bakes into the container image. To pick up frontend changes:
- **Bare-metal**: `git pull && go build -o fwmon-api ./cmd/api && systemctl restart fwmon-api` (or your service name).
- **Docker compose**: `git pull && docker compose build && docker compose up -d` (the `build` step is required — `docker compose pull` only updates *external* images).
- **Docker prebuilt image**: `docker pull <your-image-tag> && docker compose up -d`.
After redeploy, hard-refresh the browser (Ctrl+Shift+R) and check dev-tools console — `Firewall-Mon v0.10.194` (or newer) should appear.

## [0.10.193] - 2026-04-28

### Added
- **Config History tab now defaults to "show only real changes"**. With the always-store policy storing 96 backups per device per day, the History tab was 50 rows of identical-looking IV-drift noise. Now the tab collapses runs of identical `NormalizedChecksum` to one representative row each — the *earliest* of each run (representing "when this state began"). 100 IV-drifted backups → 1 row. A real edit produces a new row.
- **Toggle in the summary line**: *"3 distinct states from 287 total backups | Show all 287 backups"* / *"287 of 287 backups | Show only changes"*. One click swaps modes; compare selections reset because the visible IDs change.
- **Server**: `GET /api/devices/:id/config-history?distinct=true` is the new opt-in. Without the param the endpoint returns every stored revision (backward compatible). Response now also includes `total_all`, `total_distinct`, `total_shown` so the UI can render the summary line.

### Tests
- 3 new tests in `handlers_config_revision_retention_test.go`:
  - `TestGetDeviceConfigHistory_DistinctMode_CollapsesRuns` — A→B→A→C across 20 rows collapses to exactly 4 representative rows (newest-first, each the earliest of its run).
  - `TestGetDeviceConfigHistory_NonDistinctReturnsEverything` — without `?distinct`, every row up to the 50-cap is returned.
  - `TestGetDeviceConfigHistory_DistinctMode_AllSameHash` — the user-described worst case: 100 IV-drifted backups all with the same normalized hash collapse to exactly 1 row.

## [0.10.192] - 2026-04-28

### Fixed
- **Config diff modal: "blank body" when comparing two backups with no real differences**. With the v0.10.187 IV-drift fix, every poll cycle stores a new revision even when nothing changed, so two consecutive revisions of the same FortiGate normalize to the same hash. Picking those two revisions in the Compare picker correctly produced an empty diff (everything is volatile / unchanged) — but the modal showed an empty body, which looked like a bug. Now:
  - When `from.normalized_checksum === to.normalized_checksum`, the modal shows a clear green banner: *"No real configuration changes between these two backups. Both revisions normalize to the same checksum. The raw bytes differ only because FortiOS regenerates a fresh AES IV salt for every ENC blob on every emission."*
  - The Compare-button hint now warns up-front when the two selected revisions share a normalized checksum, so the user knows what to expect before clicking.
- **Network / server errors during diff load** (HTTP non-200, JSON parse failure, fetch reject) now render a clear error message in the modal body instead of leaving it blank. Modal opens immediately on click with a "Computing diff…" placeholder so something is always visible.
- **Diagnostic console logging** added to the diff load path: HTTP status, response body, and any thrown error get logged with `[diff]` prefix so future debugging needs only browser dev tools, not server logs.

### Note
The v0.10.191 fixes (regex `g` flag, error boundary, O(n) HTML build) are still required — but they only take effect after the **server binary is redeployed** (browser refresh alone re-fetches the JS only from whatever the server serves; if the server still runs an older version, the browser still loads the old JS). To ship: `git pull` the server, restart the binary, then hard-refresh (Ctrl+Shift+R).

## [0.10.191] - 2026-04-28

### Fixed
- **Config diff modal: blank screen bug**. Multiple issues in the diff renderer for two FortiGate config revisions:
  1. **Volatile-pattern regexes had no `g` flag** — `.replace(regex, …)` only replaced the *first* match per pattern, so on a config with 30+ ENC lines only the first got masked. The other 29 leaked into the diff as red/green deltas, swamping any real change. Now all compiled patterns get the `g` flag.
  2. **HTML built via `+=` string concatenation** — O(n²) on some browser engines. For 5 000-line configs this could hang the browser visibly. Now builds via `array.push(...)` + `parts.join('')` (O(n)).
  3. **No error boundary around the render** — any JS exception silently aborted, leaving the modal body empty (looked blank). Now wrapped in try/catch with a user-visible error message and `console.error` for diagnostics.
  4. **Modal opened only after rendering completed** — for slow renders the user clicked "Compare" and saw nothing for a moment. Now the modal opens immediately with a "Computing diff…" placeholder, then swaps in the rendered HTML.
  5. **Hard cap at 10 000 diff lines** — protects the browser from pathologically large configs. Truncation banner appears at the bottom with a hint to download both revisions for offline comparison.
  6. **Defensive null-checks** on `data.from`, `data.to`, and `data.volatile_patterns` in case the server response shape ever drifts.

## [0.10.190] - 2026-04-28

### Fixed
- **Header "select all" checkbox carried over its checked state when navigating to next/prev page**, even though none of the new page's row checkboxes were actually selected. Caused by the render order in `renderAlertsTable` reading checkbox state before the new tbody was rendered. Now the header checkbox + indeterminate state + selection state + select-all-matching mode are explicitly reset before the new HTML is swapped in.

### Added
- **"Select all N matching the filter" flow on the alerts page**. The header checkbox still selects only the visible page (page-scoped selection is the safe default), but when the page is fully selected and there are more matching rows than fit on this page, an inline banner appears: *"10 selected on this page. Select all 247 matching the current filter."* Clicking the link puts the UI in a "select all matching" mode — visible chip in the toolbar — and the next "Acknowledge selected" call uses the new filter endpoint instead of an ID list. This is the GitHub / GMail pattern; safer than a single-click "ack everything" button. Banner clears on filter change, page change, manual Clear, or after the bulk-ack completes.
- **`POST /api/alerts/bulk-acknowledge-filter`**: accepts the same query params as `GET /api/alerts` (`device_id`, `alert_type`, `severity`, `acknowledged`) plus an optional `{notes}` body. Single SQL `UPDATE WHERE <filter>` — bounded only by the filter, not by client-side ID lists, so it scales past the 500-ID cap on the existing endpoint. **At least one filter is required**; an empty filter returns 400 to prevent accidental "ack everything in the database" calls.
- **`Database.AlertFilter` struct + `AcknowledgeAlertsByFilter`**: typed filter object, nil `Acknowledged` means "any". Same pattern works for any future filter-based bulk operations.

### Tests
- 4 new tests in `handlers_alerts_bulk_test.go`: ack by `severity=warning`, ack by `acknowledged=false` (the common "ack all unacked" use case), 400 when no filter is provided, combined `device_id+alert_type+acknowledged=false` correctly excludes other devices and pre-acked rows. Total bulk-ack coverage now 9 tests.

## [0.10.189] - 2026-04-28

### Tests
- **Marquee end-to-end test for the FortiGate hash-drift fix** (`handlers_config_revision_fortigate_test.go`): with `Device.Vendor="fortigate"`, two IV-drifted FortiOS-shaped configs round-tripped through `ReceiveConfigRevision` produce identical `NormalizedChecksum` despite different raw checksums (the actual on-the-wire scenario). Companion test asserts a real change (added firewall policy) produces a *different* normalized checksum. Plus tests for `TriggerSource`/`BackupQuality` round-trip + response shape.
- **Retention cleanup tests** (`handlers_config_revision_retention_test.go`): `CleanupConfigRevisions` exercise — keep top 50 regardless of age, delete beyond 90 days when outside top 50, leave fewer-than-50 untouched within the 90-day window, delete >90-day rows even when total < 50, collapse identical-`NormalizedChecksum` runs in older window keeping the most-recent row of each run (precise survivor identity verified by raw checksum).
- No production behavior change in this release — purely test coverage on the v0.10.187 code paths that were previously only unit-tested in isolation.

## [0.10.188] - 2026-04-28

### Added
- **Bulk-acknowledge alerts**: per-row checkboxes plus a "Select all on page" header checkbox. Toolbar above the alerts table shows the selected count and an "Acknowledge selected" button that opens a notes modal applying the same notes to every selected alert in one API call. Works on both small and large selections (capped at 500 IDs per request).
- **`POST /api/alerts/bulk-acknowledge`**: accepts `{ids: [...], notes: "..."}` and runs a single SQL `UPDATE ... WHERE id IN (...)`. Returns `{acknowledged: N, requested: M}`. Validates non-empty array and per-request cap.

### Changed
- **Acknowledging an alert no longer bounces the user back to page 1.** Both single-alert ack (existing button) and the new bulk-ack now refresh in place at the user's current page. If the page would become empty (e.g. when filtering "Unacknowledged" and acking everything visible), the UI walks back one page until it finds content or hits page 1.
- **Alert row click vs. checkbox click**: row-click → "show alert detail" handler now ignores clicks on form controls and `data-action` elements, so checkbox clicks no longer trigger the detail modal.

## [0.10.187] - 2026-04-28

### Fixed
- **FortiGate config-change alert false positives**: Every backup of an unchanged FortiGate produced a new MD5 (and a new alert) because every `set <field> ENC <blob>` line uses a fresh random 4-byte IV per emission (verified against `gquere/CVE-2019-6693`, `saladandonionrings/cve-2019-6693`, Oxidized issue #1199). Same plaintext password → different ciphertext on every backup. Server now hashes a vendor-normalized copy of the config (FortiGate strips ENC blobs, `BEGIN ENCRYPTED PRIVATE KEY` blocks, `#config-version=`, `#conf_file_ver=`, `#private-encryption-key=`, `set last-login`, `!System time:`) for the change-detection comparison. Alerts only fire when the normalized hash actually changes. Raw `ConfigText` is preserved unchanged for restore + diff display. Vendor-scoped: identity normalizer for non-FortiGate vendors so behavior is unchanged for them.

### Changed
- **`ReceiveConfigRevision` always stores every received backup** (drops the previous dedup-by-raw-checksum branch). With random-IV ciphertext drift the raw bytes always differ, and dedup at write time would silently lose the latest restorable bytes after a real password rotation. Retention runs a separate collapse pass for older history.
- **`GetDeviceConfigHistory` limit** raised from 10 → 50 revisions.

### Added
- **`internal/configdiff` package**: `Normalizer` interface, vendor registry (`fortigate`, `paloalto`, `cisco_asa`, `generic`), MD5 hash convenience, plus VolatilePatterns published per vendor for the diff UI to mask. Full unit-test coverage with synthetic fixtures (two unchanged snapshots, real-change snapshots, password-only snapshot, masking detection, vendor lookup case-insensitivity).
- **`DeviceConfigRevision` schema**: `NormalizedChecksum`, `BackupQuality` (`full`/`masked`/`unknown`), `TriggerSource` (`syslog`/`poll`/`manual`). AddColumn-if-missing migration following the `tftp_server_ip` pattern.
- **`GET /api/devices/:id/config-history/diff?from=&to=`**: Returns both raw `ConfigText` blobs + the vendor's `volatile_patterns` so the UI can mask IV-churning lines as `(volatile)` rather than red/green deltas.
- **Config History tab UI**: radio compare picker (From / To), trigger-source + backup-quality + normalized-hash columns, side-by-side modal diff with volatile-line masking. Diff uses raw text so operators see real values for non-secret changes.
- **Retention job for config revisions**: daily, keep last 50 revisions per device + last 90 days, whichever is greater. Within the older-than-top-50 portion of the 90-day window, collapse identical-`NormalizedChecksum` runs to one representative row each (most recent of each run kept).

### Why
The drift is FortiOS-specific behavior — by design — and the canonical industry workaround (Oxidized, RANCID for ~15 years) is regex-strip-then-hash. Vendor isolation ensures Palo Alto / Cisco / generic devices stay on the existing raw-checksum behavior until evidence of a similar drift class shows up.

## [0.10.186] - 2026-04-27

### Added
- **Per-probe `TFTP Server IP` setting**: Admin can now enter, on each probe's edit form, the IP address that firewalls in that probe's network use to reach the collector. The probe pulls this value via `GET /api/probes/:id/devices` (added alongside the device list as `tftp_server_ip`) and uses it as the destination IP in `execute backup config tftp <file> <ip>`. This replaces the collector's previous attempts to auto-detect the right outbound IP from inside Docker (which is unreliable when `PROBE_LISTEN_ADDR=0.0.0.0`). Field is optional — if left blank, the collector falls back to per-device auto-detection.

### Database
- New `probes.tftp_server_ip TEXT` column. Migration follows the existing AddColumn-if-missing pattern; existing rows get an empty string.

### API
- `Probe` model gains `TFTPServerIP string` (`json:"tftp_server_ip"`).
- `PUT /api/probes/:id` accepts `tftp_server_ip` in the update body (allowlisted).
- `GET /api/probes/:id/devices` response now includes `"tftp_server_ip"` alongside the existing `success` + `data` fields. Backward-compatible with collectors that ignore unknown fields.

## [0.10.185] - 2026-04-27

### Added
- **Server test suite** (Phase 4–5 of test plan):
  - `internal/database/testing.go`: `NewDatabaseForTesting` using in-memory SQLite via `github.com/glebarez/sqlite`; `sqliteDialect` added to `dialect.go` implementing `TimeBucket`/`QuoteIdent`/`IsPostgres` for test compatibility
  - `internal/api/handlers/testhelper_test.go`: shared `setupTestHandler`, `setupProbeAndDevice`, `doTestRequest` helpers
  - `internal/api/handlers/handlers_data_test.go`: 12 handler tests covering `validateProbe` (missing auth, wrong token, pending), `ReceiveConfigRevision` (save, dedup, second checksum, cross-probe 403, oversized 400), `ReceiveSystemStatuses` (save, cross-probe filtering, 100-record truncation, no-auth)
  - Critical security test: cross-probe data injection is rejected at both config revision and system status endpoints

## [0.10.182] - 2026-04-27

### Fixed
- **ConfigText truncation bug**: Server-side warning now logs when received config Length mismatch is detected. Root cause was in Firewall-Collector (Firewall-Mon#repo) where cleanOutput was incorrectly filtering config lines containing `$` character.

### Added
- **TFTP config fetch support**: Server ready to receive configs via TFTP from Firewall-Collector probes.

## [0.10.181] - 2026-04-27

### Fixed
- **admin.html chart CSS**: Updated embedded .chart-card styles to match admin-shared.css (padding:20px, height:340px, canvas max-height:280px)
- **device-detail.html canvas heights**: Updated inline canvas heights from 300px to 340px for consistency
- **connection-detail.html container height**: Updated container div from 300px to 340px

## [0.10.180] - 2026-04-27

### Fixed
- **Chart font sizes**: Increased from 9px to 11px across all charts for better readability
- **Doughnut chart aspect ratio**: Fixed maintainAspectRatio setting that prevented proper container filling

## [0.10.176] - 2026-04-27

### Fixed
- **Network Throughput chart**: Added adjustable time range selector like the public dashboard graphs - previously hardcoded to 24h only
- **Network Connection Map VXLAN detection**: Fixed bug where vxlan-prefixed interfaces (e.g., vxlan700) on FortiGate were not properly detected as overlays - now correctly identifies them as l2vlan (Software Switch) or vxlan (if verified in config)
- **Frontend/backend type consistency**: Moved bridge/Software Switch back to DIRECT_TYPES (same-site local switching) while keeping vxlan/l3ipvlan in OVERLAY_TYPES (IPSec tunnel children)

### Added
- **Standardized time range selectors**: All graph time range selectors now use consistent dropdown style with full options: 15m, 30m, 1h, 6h, 12h, 24h, 1w, 1m, 3m, 1y
- **Professional dropdown CSS**: New `.chart-range-select` class with custom dropdown arrow, hover states, and focus styles for enterprise look
- **FortiGate config text parsing**: Added ParseFortiGateVxlanConfig() to parse VXLAN definitions from FortiGate configuration text
- **SSH poll validation**: Added client-side validation to prevent enabling SSH polling without SSH credentials
- **Connection Map filter buttons**: Added VXLAN and Bridge filter buttons to Connection Map toolbar
- **Friendly type labels**: Connection Map now shows "Software Switch" instead of "bridge" for bridge-type connections
- **Debug logging**: Added logging when config revisions are received and saved

### Changed
- **All graph pages**: Converted from button groups to compact dropdown selects for time range selection
- **detectOverlayConnections**: Now fetches FortiGate config text to distinguish true VXLAN tunnels from Software Switch L2VLAN extensions

## [0.10.171] - 2026-04-23

### Fixed
- **FlowRollup SamplingRateAvg type**: Changed from uint32 to float64 to handle AVG() and weighted calculation results that return decimal values (e.g., "1024.0000000000000000")

## [0.10.170] - 2026-04-23

### Added
- **Verbose debug logging for sensor data**: Added per-sensor logging in ReceiveSensorDetails to debug why sensors aren't being saved

## [0.10.169] - 2026-04-22

### Added
- **Debug logging for sensor details**: Added logging to ReceiveSensorDetails handler to debug sensor data flow

## [0.10.168] - 2026-04-22

### Added
- **Config History: View in modal**: Added "View" button to configuration history table to display configuration in a popup modal with syntax formatting
- **Config History: Diff view**: Added "Compare" button to show diff between two configurations in a popup modal with color-coded additions/removals
- **Config History: Delete revision**: Added "Delete" button to remove individual configuration revisions from the UI

### Fixed
- **Config History: Download broken**: Fixed download button that was failing because the endpoint returns raw text but JS was expecting JSON. Now correctly fetches raw text directly.

### Changed
- **Config History table**: Now shows View, Download, Compare, and Delete action buttons for each revision

## [0.10.167] - 2026-04-22

### Fixed
- **Database: IRC migration transactional**: Wrapped IRC table recreation in transaction to prevent partial schema on failure
- **Database: GetLatestVPNStatuses nil slice**: Changed to return empty slice `[]models.VPNStatus{}` instead of nil on no records, prevents JSON `null` being sent to frontend
- **Chart: Triple API fetch optimization**: Refactored loadStatusHistoryChart/loadNetworkThroughputChart/loadCPUBreakdownChart to share a single fetch promise instead of 3 separate requests for identical data
- **Chart: Stale canvas text**: Added `clearRect()` before drawing "Not enough history data" text to prevent ghost rendering
- **JS cleanup: Duplicate connStyleLookup removed**: Removed local copy from admin-connection-detail.js; now uses canonical `connStyle()` from admin-common.js

## [0.10.166] - 2026-04-22

### Fixed
- **Database migration for new columns**: Added HasColumn/AddColumn migration helpers for SystemStatus (network throughput, CPU breakdown, memory breakdown fields) and VPNStatus (InterfaceName, Mode) fields. Existing databases will now automatically get the new columns on upgrade.

## [0.10.165] - 2026-04-22

### Added
- **Network Throughput Chart**: Added new chart section on device detail page showing network throughput (in/out kbps) from SSH performance data. Automatically hidden when no data available.
- **CPU Breakdown Chart**: Added new chart section on device detail page showing CPU breakdown (user/system/nice/idle/iowait/irq/softirq) as stacked area chart. Automatically hidden when no data available.
- **Enhanced SystemStatus Model**: Added network throughput fields (NetworkInKbps, NetworkOutKbps), CPU breakdown fields (CPUUser, CPUSystem, CPUNice, CPUIdle, CPUIowait, CPUIrq, CPUSoftirq), and memory breakdown fields (MemoryFree, MemoryFreeable).
- **Enhanced VPNStatus Model**: Added InterfaceName and Mode fields from SSH phase1 configuration.
- **VPN Tab Enhancement**: Added Interface and Mode columns to the VPN tunnels table on device detail page.
- **Connection Map Enhancement**: Added Interface and Mode columns to VPN tunnel detail panel in the connection map popup.

### Changed
- **Device Detail Page**: Network throughput and CPU breakdown charts are now displayed below the standard System Status History chart.


## [0.10.164] - 2026-04-21

### Fixed
- **Syslog DeviceID resolution**: Probe now relays syslog messages to API, and API resolves DeviceID from SourceIP using ResolveDeviceByIP (same logic as flow samples). Added SetHandler callback to TCP/UDP syslog receivers.

## [0.10.163] - 2026-04-21

## [0.10.162] - 2026-04-21

### Fixed
- **Admin sidebar**: Fixed `AdminCommon is not defined` error by wrapping `AdminCommon.renderSidebar()` in `DOMContentLoaded` to ensure admin-common.js is fully loaded before calling. Applied to all 8 admin pages.
- **Probe health popup**: Fixed modal width alignment in admin.html (520px) with admin-shared.css (1000px) to prevent small popup.

## [0.10.161] - 2026-04-21

### Added
- **Public dashboard chart modal**: Added click-to-expand functionality on CPU/Memory and Bandwidth charts to open a fullscreen modal with zoom/selection capabilities. Features: scroll to zoom, drag to select region, Shift+drag to pan, Reset button, ESC/Close to dismiss.

### Changed
- **Public Dashboard Display settings**: Simplified settings page by removing unused toggles (Show Hostname, Show Uptime, Show CPU Usage, Show Memory Usage, Show Active Sessions, Show Network Interfaces, Show Bandwidth Graphs, VPN Tunnels per Device). Kept only VPN Tunnels, Connection Map, and Refresh Interval settings which are actively used. Unused settings are automatically cleaned from the database on next load.
- **Alert Policies UI**: Redesigned the alert policy modal with improved visual hierarchy - grouped form fields into logical sections (Basic Info, Notification Channels, Alert Rules) with styled section headers, improved stat cards with icons on the policies page, and better compact table styling for alert rules.

### Fixed
- **Public dashboard CPU chart labels**: Fixed CPU chart to use month/day/hour/minute format for time ranges >= 168 hours (1w/1m/1y), matching the bandwidth chart label formatting.

## [0.10.160] - 2026-04-20

### Fixed
- **Network page**: Fixed missing `id="connections-table"` on table causing "Cannot set innerHTML of null" error.
- **Settings page checkbox alignment**: Changed notification, reports, and spike checkboxes from `setting-item` to `toggle-row` for proper label/checkbox alignment.
- **Report settings validation**: Made `report_daily_time` and `report_weekly_day` optional (empty allowed) to avoid validation errors when enabling reports without filling in all fields.
- **Report time/day dropdowns**: Replaced text inputs for `report_daily_time` and `report_weekly_day` with proper select dropdowns (30-minute intervals for time, day-of-week for weekly day) to prevent format errors and improve UX.
- **Report settings save**: Fixed save handler to include select elements so dropdown values are properly saved.
- **Public dashboard 1m/1y range**: Fixed backend switch to use numeric keys ("720", "8760") instead of string keys ("1m", "1y") so the frontend's numeric range values map correctly.

### Changed
- **Settings page CSS**: Added dropdown arrow styling for select elements in settings forms.

## [0.10.159] - 2026-04-19

### Changed
- **Public dashboard time range**: Added 1m and 1y options to match admin flows page time ranges (1h/6h/24h/1w/1m/1y).

## [0.10.158] - 2026-04-19

### Fixed
- **Deploy Probe registration key**: Removed redaction that was masking the registration key in the Deploy Probe modal, allowing the key to be properly displayed and copied.
- **Device detail tabs**: Added missing CSS rules (`.hidden`, `.tab-content`, `.tab-content.active`) that were preventing tab switching on device detail page.
- **Flows time range label**: Added `flow-range-label` span to display the selected time range on the admin flows page.
- **Public dashboard time range**: Consolidated separate bandwidth and CPU time range dropdowns into a single unified time range selector (1h/6h/24h/7d) for simplicity.

## [0.10.157] - 2026-04-18

### Added
- **Tailwind CSS**: Integrated Tailwind CSS v3 with custom GitHub dark theme configuration. Common component classes now use Tailwind utilities for consistent styling.

### Removed
- **SQLite support**: Removed all SQLite-related code and dependencies. PostgreSQL is now the only supported database type.
- **Migration UI**: Removed SQLite to PostgreSQL migration interface and related API endpoints.

### Changed
- **Default database**: Configuration now defaults to PostgreSQL (`DB_TYPE=postgres`) with separate host/port/user/password/name fields instead of SQLite's single file path.
- **Config env example**: Updated `config.env.example` to reflect PostgreSQL configuration.
- **Probe cards CSS**: Fixed overflow/bleed issue by adding `min-width: 0` and `overflow: hidden` to grid items.
- **Responsive design**: Added mobile sidebar with hamburger menu toggle and responsive breakpoints for admin dashboard.

## [0.10.156] - 2026-04-18

### Added
- **Syslog aggregation system**: Informational syslog (severity 6-7) is now aggregated into hourly/daily summaries for long-term storage efficiency. Configurable via `RETENTION_SYSLOG_INFO_DAYS` (default: 7) and `RETENTION_SYSLOG_CRITICAL_DAYS` (default: 0 = forever).
- **SyslogSummary model**: New `syslog_summaries` table stores aggregated syslog data with counts, sample messages, and normalized patterns.
- **PostgreSQL partitioning support**: High-volume tables (`syslog_messages`, `syslog_summaries`, `trap_events`, `flow_samples`) now support monthly range partitions via `EnsurePartitions()` for efficient data management.
- **Aggressive autovacuum**: High-volume tables now have aggressive autovacuum settings (1% trigger, 10ms delay) to reduce bloat.
- **Probe stats API**: `/api/probes/{id}/stats` now returns `last_hour` counts and `hourly_breakdown` (24 hours) for each data type.
- **Probe detail modal**: Click any probe card on the dashboard to see full stats with hourly breakdown.

### Changed
- **Syslog retention**: Critical syslog (severity 0-5) is now retained separately from informational syslog (severity 6-7). Use `RETENTION_SYSLOG_CRITICAL_DAYS=0` to keep critical syslog forever.
- **Syslog aggregation cycle**: Runs every 5 minutes alongside flow rollup. Hourly summaries are promoted to daily summaries after 48 hours.
- **`GetSyslogStats`**: Now combines raw syslog counts with summary counts for complete statistics.
- **Probe summary on probes page**: Probes management page now shows total data counts across all approved probes with last hour activity.
- **Timezone handling**: Public dashboard bandwidth and CPU charts now respect `display_timezone` setting. Backend returns ISO timestamps for proper client-side formatting.
- **Flows display**: Removed misleading "Est. Actual Bytes" calculation. Table now shows only sampled bytes.
- **Settings save**: Fixed bug where "Email Reports" and "Traffic Spike Detection" settings were not being saved.
- **Probe card UI**: Improved CSS styling for probe cards with better layout, hover effects, and formatted numbers.

## [0.10.155] - 2026-04-18

### Added
- **Probe data flow monitoring**: New `PROBE_DATA_LAG` alert fires when a probe has not received any data for `PROBE_DATA_LAG_ALERT_MINUTES` (default: 60). This catches queue-full, network, or misconfiguration issues that heartbeat-based `DEVICE_OFFLINE` alerts miss.
- **Probe data truncation alerts**: New `PROBE_DATA_TRUNCATED` alert fires when a probe sends batches >1200 items (truncated to 1000) multiple times within 5 minutes — indicates possible misconfiguration.
- **`LastDataReceived` timestamp**: Probe model now tracks last data receipt time via `last_data_received` column (indexed). Updated on all data ingestion endpoints.
- **`ProbeID` on alerts**: Alert model now supports `probe_id` field for probe-specific alerts without an associated device.

### Changed
- **Probe data flow check**: `CheckProbeDataFlow()` now runs at end of each poll cycle alongside `CheckEscalations()`.

## [0.10.154] - 2026-04-05

### Fixed
- **Sublane particle flow through cloud**: Cross-site expanded sublane halves (-a/-b) now use forward-only particles like the parent tunnel edges. Previously bidirectional particles on both halves collided at the cloud node.

### Added
- **Phase 2 count in tunnel labels**: Tunnel-bundle edges now show Phase 2 selector count (e.g., "IPSEC (3 P2) +2 DIAL-UP") when a tunnel has multiple Phase 2 entries
- **Per-Phase2 throughput in detail panel**: Phase 2 tab now shows BytesIn, BytesOut, Total, and Uptime per Phase 2 selector match — not just up/down status
- **Phase2Match byte counters**: Backend `Phase2Match` struct now includes `SrcBytesIn/Out`, `DstBytesIn/Out`, `SrcUptime`, `DstUptime` from the per-SA SNMP counters

## [0.10.153] - 2026-04-05

### Changed
- **Flow retention increased to 365 days**: Default `RETENTION_FLOW_DAYS` changed from 90 to 365. Rollups compress old data (5m → 1h → 1d) so storage is manageable. The 1-year time range button now has data to show.

### Added
- **Enterprise sFlow dashboard enhancements**:
  - **Estimated Actual Bytes** stat card: Shows `sampled_bytes × avg_sampling_rate` for true traffic volume
  - **Sampling Rate** stat card: Shows the average sampling ratio (e.g., "1:4096") so users know data is sampled
  - **Total Packets** stat card
  - **Top Ports chart**: Horizontal bar chart showing top 10 destination ports by bytes with well-known port names (HTTPS, SSH, DNS, etc.)
  - **Data Retention info card**: Shows current retention period and rollup tiers
- **Top destination ports query**: `GetFlowStats` now returns `top_ports` with port-to-name mapping for 17 well-known services

## [0.10.152] - 2026-04-05

### Added
- **sFlow v5 parser**: Complete rewrite of the sFlow receiver — now fully decodes sFlow v5 datagrams, flow samples (standard + expanded), and raw packet headers. Extracts IP src/dst, ports, protocol, TCP flags, and frame length from sampled Ethernet/IPv4 packets
- **sFlow relay wiring**: Probe now connects decoded sFlow samples to the relay pipeline via `SetFlowHandler()`. Flow data is queued and synced to the API server alongside SNMP/trap/syslog data

### Fixed
- **Connection flow stats query rollups**: `GetConnectionFlowStats` now supplements raw `flow_samples` with `flow_rollups` for historical periods >1hr (subnet strategy). Previously returned empty for any period after rollup consumption.
- **cidrToLikePattern handles all formats**: Now supports IP ranges (`10.0.1.0 - 10.0.1.255`), bare IPs (exact match), /32 (exact), and /8-/31 CIDR. Previously returned empty for non-CIDR inputs and treated /28-/32 the same as /24.
- **VPN cross-fill by remote IP**: Tunnel subnet cross-fill now matches by remote IP correlation instead of tunnel name (which never matched because names differ on each side of a tunnel)
- **Sampling rate in connection flow stats**: `GetConnectionFlowStats` raw byte/packet totals now apply sampling rate correction

## [0.10.151] - 2026-04-05

### Fixed
- **Empty tunnel traffic charts**: `getConnectionTunnelNames()` now handles `tunnel_indirect` and `wan_inferred` match methods by relaxing IP matching (same logic as `GetConnectionDetail`). Previously these connections returned zero tunnel matches → empty charts.
- **sFlow sampling rate correction**: All flow volume calculations now multiply bytes/packets by `sampling_rate`. Previously all sFlow data was underreported by the sampling ratio (typically 1000-4096x).
- **sFlow rollup preserves sampling correction**: `aggregateFlowsToRollup` now stores `bytes * sampling_rate` in rollup `bytes_sum`.
- **FortiGate CIDR subnets**: Collect subnet mask OIDs (.10/.13) and use `buildCIDR()` (was dead code) to convert Phase 2 selectors to proper CIDR notation (e.g., `10.0.1.0/24` instead of `10.0.1.0 - 10.0.1.255`). Falls back to IP range if mask unavailable.
- **FortiGate SSL-VPN byte counters**: Collect OIDs `.4`/`.5` (InOctets/OutOctets) for SSL-VPN sessions — enables traffic charts for SSL-VPN tunnels.
- **Empty chart placeholder**: Traffic charts now show "No traffic data available" message instead of blank canvas when API returns empty data.

## [0.10.150] - 2026-04-05

### Fixed
- **Saved layout restored correctly**: All node positions (cloud, sites, devices) saved by full ID and restored on reload. Previously cloud/sites collapsed to (0,0) after any drag-save.
- **Parallel edges spaced apart**: Edges sharing the same endpoints automatically get perpendicular offsets via `segments` curve-style (8px spacing). No curves — straight lines offset by a few pixels so each is visible and clickable.
- **DOWN X marker preserves tunnel label**: Uses `source-label` instead of overriding the main edge label. "IPSEC +2" stays visible on down connections.
- **Unsited devices placed below cloud**: No longer randomly overlapping the cloud at center. Spaced horizontally at y=450.
- **Removed waypoint nodes**: Off-net edges now use direct device→cloud edges with `segments` offset applied by `spaceParallelEdges()`. Simpler, no phantom nodes.
- **Site compounds have subtle fill**: 40% opacity dark background makes site boundaries visible behind edges.
- **Tunnel-bundle labels readable**: Dark background pill on edge labels prevents text from being hidden by crossing edges.

## [0.10.149] - 2026-04-05

### Fixed
- **Straight lines**: All edges are now straight (removed bezier curves and multi-edge detection). Expanded sublanes also use straight lines through the cloud
- **Expanded tunnels route through cloud**: Cross-site tunnel expansion creates sublane halves through the Internet cloud (Device→Cloud + Cloud→Device) instead of going direct
- **Cloud icon centered**: Cloud node is now a 64px emoji on a transparent 100px ellipse, properly centered
- **Site spacing**: Increased node repulsion (15000), edge length (350), node separation (200), and reduced gravity (0.15) to prevent sites from overlapping
- **VPN badge real-time updates**: VPN up/down counts on device nodes refresh every 15 seconds via VPN map polling. When a tunnel drops, the badge updates immediately
- **DOWN tunnel X marker**: DOWN edges show the red X marker on straight lines correctly

## [0.10.148] - 2026-04-05

### Removed
- **436 lines of dead code** from database.go (3306→2870 lines):
  - Entire site database subsystem (CreateSiteDatabase, GetSiteDatabase, ListSiteDatabases, DeleteSiteDatabase, SetSiteDatabaseStatus, UpdateSiteDatabaseSync, CreateSiteDatabaseFile, CloseAllSiteDBs, openSiteDB, GetOrCreateSiteDB) — scaffolded but never wired up
  - All SaveSite*/GetSite* sync methods (16 functions for SiteDevice, SiteSystemStatus, SiteInterfaceStats, SiteTrapEvent, SiteAlert, SitePingResult, SitePingStats, SiteSyslogMessage)
  - GetLatestUptime, FindConnectionByDevicePair, GetProbeApproval, GetAllProbeApprovals, GetLatestPingStats, GetSyslogMessagesByDevice — zero external callers
  - Unexported ProtoNames → protoNames (only used internally)
  - Removed unused `sync` import

## [0.10.147] - 2026-04-05

### Fixed
- **IRC bot security**: `isAdmin()` no longer returns true for all users. Only the bot's own nick is treated as admin, preventing external users from executing admin-only IRC commands
- **O(n^2) bubble sorts**: Replaced 4 manual bubble sorts in database.go with `sort.Slice` for proper O(n log n) performance on protocol distributions, merged KeyCounts, time series, and connection events

## [0.10.146] - 2026-04-05

### Changed
- **Consolidate shared utilities into admin-common.js**: `escapeHtml` (now includes `'` escaping), `formatBytes`, `formatNum`, `connStyle`, `matchMethodBadge`, `typeBadgeHtml` moved to admin-common.js. Removed 4x duplicate `escapeHtml`, 4x duplicate `formatBytes`, 3x duplicate `connStyle`, 2x duplicate `matchMethodBadge` from individual files

### Fixed
- **Device edit modal**: Added `Enabled` and `Public Visible` checkboxes. Previously `enabled` was hardcoded to `true` on every save, and `public_visible` was not included — editing a device could silently reset visibility
- **Dead settings save code**: Removed leftover `public_bandwidth_interfaces` and `public_vpn_tunnels` save logic from settings submit (the select elements were already removed from the HTML)
- **Debug log leak**: Removed `console.log('Saved:', publicInterfaces)` from admin-device-detail.js

## [0.10.145] - 2026-04-04

### Fixed
- **Cross-site tunnels route through Internet**: IPSec/SSL connections between devices in different sites now draw as two edges through the Internet cloud node (Device→Cloud→Device) instead of a direct line. Particles flow through the cloud correctly. Same-site tunnels remain as direct edges.
- **Cross-site expansion**: Clicking a cross-site tunnel expands sublanes spanning the full device-to-device path. Both half-edges (src and dst) are hidden during expansion and restored on collapse.
- **Cross-site status updates**: Polling updates both halves of a split tunnel edge when status changes

## [0.10.144] - 2026-04-04

### Fixed
- **Overlay duplication**: Overlays (vxlan, l3ipvlan) assigned to first tunnel carrier only, not duplicated across all tunnels for a device pair
- **Escape key handler leak**: Keydown listener now stored and removed on cleanup, preventing accumulation across re-renders
- **Overlay status polling**: `updateStatuses()` now searches tunnel-bundle `childConns` when overlay edges aren't found as direct edges, preventing silent status loss
- **Sublane filter inheritance**: Expanded sublanes and pipe-bg edges now hidden when parent tunnel type is filtered out
- **Flash animation crash**: `animateFlash()` guards against removed edges mid-animation chain
- **Particle count overflow**: `addParticlePair()` now checks `particleEls.length` directly instead of caller-tracked count, preventing MAX_PARTICLES overflow
- **VXLAN/L3IPVLAN filter buttons removed**: These overlay types are now bundled inside tunnel edges, so standalone filter buttons were inert. Removed from toolbar.
- **Dead code cleanup**: Deleted `diagram-tunnel-zoom.js` (289 lines) and SVG compatibility shims (`getSVG`, `getDimensions`, `createEl`, `svgPoint`, `NS` constant) that were only used by the removed tunnel zoom overlay

## [0.10.143] - 2026-04-04

### Changed
- **Tunnel-bundled connection map**: Overlay networks (l3ipvlan, vxlan) no longer shown as separate edges. They ride inside their tunnel carrier (IPSec/SSL) as colored dots on the tunnel edge. Each dot color represents the network type inside the tunnel
- **Inline tunnel expansion**: Click a tunnel edge with overlays to expand it into a "pipe" with sub-lanes — each overlay network gets its own labeled lane with directional particles. Click again or press Escape to collapse
- **Directional particle flow**: Forward particles (source→target) are larger and brighter, return particles are smaller and dimmer with the same color. No more reverse-direction collisions. Off-net edges flow device→cloud only
- **Same-site connections unchanged**: Ethernet, LAG, L2VLAN, and bridge connections remain as independent direct edges (they don't travel through tunnels)

### Removed
- **diagram-tunnel-zoom.js**: Old overlay zoom replaced by inline expansion. "Zoom In" button removed from connection detail panel

## [0.10.142] - 2026-04-04

### Fixed
- **Settings page sync**: Remove dead settings (`public_bandwidth_layout`, `public_bandwidth_height`) that the Gridstack dashboard no longer uses. Fix bandwidth interface selector bug (was querying `input` instead of `select`). Update Public Dashboard description to reflect widget-based layout

### Added
- **Email Reports settings card**: UI for configuring daily/weekly report scheduling (enable, time, day, recipients, timezone)
- **Traffic Spike Detection settings card**: UI for enabling spike alerts and configuring the standard deviation threshold

## [0.10.141] - 2026-04-04

### Changed
- **Public dashboard rebuilt with Gridstack.js**: Full rewrite using Gridstack.js v10 widget grid. All sections (devices, CPU/memory, bandwidth, VPN, connections) are draggable and resizable widgets. Layout fits viewport height with no scrolling — designed for NOC wall displays
- **Widget persistence**: Layout (position, size) saved to localStorage automatically on drag/resize. Hidden widgets remembered across sessions. "Reset Layout" button restores defaults
- **Widget visibility**: "Widgets" dropdown menu with checkboxes lets users show/hide any widget. Close button (×) on each widget header for quick hiding

### Fixed
- **Bandwidth "Transfer" chart**: Was showing cumulative growth (monotonically increasing line). Now shows per-interval byte deltas as bar chart — each bar represents bytes transferred in that measurement period
- **Bandwidth "Combined" (Mix) chart**: Was rendering 4 overlapping lines. Now uses Chart.js mixed chart — rate as lines on left axis (Mbps) + transfer deltas as bars on right axis (Bytes)

## [0.10.140] - 2026-04-04

### Added
- **Public dashboard CPU/Memory charts**: Per-device historical CPU and memory usage charts with time range selector (1h, 6h, 24h, 7d) on the public dashboard. Uses new `GET /api/public/status-history` endpoint
- **Per-device public visibility toggle**: New `public_visible` field on Device model (defaults to true). Checkbox in admin devices table lets you hide specific firewalls from the public dashboard without disabling polling. `GetPublicDevices` now filters by both `enabled` and `public_visible`

## [0.10.139] - 2026-04-04

### Changed
- **Bundle all JS dependencies locally**: Chart.js, Cytoscape.js, and cytoscape-fcose are now embedded in `cmd/api/static/js/` instead of loaded from CDNs. Eliminates all external script dependencies, removes CDN URLs from CSP, and ensures the app works fully offline

## [0.10.138] - 2026-04-04

### Added
- **Real-time connection map**: Diagram auto-refreshes every 15 seconds via lightweight `/api/connections/status-summary` endpoint. Status changes trigger animated transitions — red flash for DOWN, green flash for recovery
- **Visual X marker on DOWN links**: DOWN edges now display a prominent red X icon with background badge, visible by default (showDown defaults to true)
- **Events tab in connection panel**: Click any connection to see correlated alerts, traps, and syslog from both endpoint devices. DOWN connections auto-open the Events tab. Time range selector: 1h, 6h, 24h, 7d
- **Standard linkUp/linkDown trap support**: SNMP trap receiver now handles IETF standard linkDown (`.1.3.6.1.6.3.1.1.5.3`) and linkUp (`.1.3.6.1.6.3.1.1.5.4`) traps for both SNMPv1 and v2c/v3 formats. Extracts interface index and description from varbinds
- **LINK_UP recovery alerts**: When a LINK_UP trap arrives, any active LINK_DOWN alert for the same device is automatically resolved
- **Connection events API**: New `GET /api/connections/:id/events` endpoint returns unified timeline of alerts, traps, and syslog for a connection's endpoint devices

## [0.10.137] - 2026-04-04

### Fixed
- **Connections page not loading**: Non-critical API calls (`/sites`, `/vpn-map`) in `loadConnections()` now have individual `.catch()` fallbacks so a failure in either doesn't prevent the connections table from rendering
- **Stale cleanup wiping all connections**: Connection detection cycle now tracks whether any detector found connections; stale cleanup is skipped when all detectors return zero results, preventing mass deletion on transient failures
- **Discovery badges**: Unified to consistent Direct/Indirect taxonomy across all views (connections table, network page, diagram panels). Removed stale methods (`vxlan_name`, `tunnel_name`) and added missing ones (`wan_inferred`, `subnet_match`). Indirect styling now applies to all indirect match methods on the connection diagram
- **Renamed `overlay_name` → `name_match`**: Internal match method for interface-name-based detection now uses clear terminology. Legacy `overlay_name` values still render correctly

## [0.10.136] - 2026-03-19

### Changed
- **Connection Map**: Replaced custom SVG rendering engine (4 files, ~90KB) with Cytoscape.js graph library
  - Native compound nodes for site grouping with automatic layout
  - Native multi-edge support — parallel connections between same device pair shown as bezier curves
  - Built-in zoom/pan with mouse wheel and drag
  - fcose force-directed layout with compound node support (falls back to cose)
- **Toolbar**: Added layer filter buttons (per connection type with color indicators), Show DOWN toggle, Fit, and Reset controls
- **DOWN connections**: Now included in graph data but hidden by default; "Show DOWN" button reveals them as dashed/dimmed edges

### Fixed
- **Missing `/sites` API call**: `loadConnections()` now fetches sites, fixing site grouping that was silently broken
- **Event listener accumulation**: Previous cy instance is destroyed on re-render, preventing sluggishness on tab switches
- **0-device edge case**: Early return with message instead of crash when no devices exist

### Removed
- `diagram-core.js`, `diagram-layout.js`, `diagram-connections.js`, `diagram-particles.js` — replaced by `diagram-cytoscape.js`

### Added
- `diagram-cytoscape.js` — single Cytoscape.js module with data transformation, styling, layout, filtering, particle animation, and SVG overlay shim for tunnel-zoom compatibility
- CDN dependencies: Cytoscape.js v3.30.4, cytoscape-fcose v2.2.0

## [0.10.135] - 2026-03-18

### Fixed
- **ParseHours** max raised from 168 → 8760: 1-month and 1-year time range buttons now work correctly instead of silently falling back to 24h
- **sFlow charts**: Port-0 internal/local traffic (IPv6 link-local) filtered from Top Sources, Top Destinations, and Top Conversations to prevent one address from dominating all charts
- **Bar chart scaling**: With local traffic separated, bar charts show balanced application traffic instead of 1.0B/2.0B scale

### Added
- Local traffic info bar on Flows page showing filtered port-0 bytes, flows, and packets
- `LocalTraffic` field in `FlowStatsResult` API response

## [0.10.134] - 2026-03-18

### Fixed
- **Critical**: `GetFlowStats` now queries both raw `flow_samples` and `flow_rollups` — dashboard no longer goes blank after rollup cycle
- **Critical**: Rollup INSERT+DELETE wrapped in transactions to prevent data loss and duplicate entries on crash
- **High**: BPS bandwidth chart now uses server-provided `bucket_seconds` instead of inaccurate client-side interval estimation
- **High**: Added `DstPort` to `FlowRollup` model — conversation-level port detail preserved through rollup tiers
- **High**: Combined 4 separate aggregate queries (COUNT, SUM, DISTINCT src, DISTINCT dst) into single query
- **High**: Extracted duplicate `protoNames` map to package-level `ProtoNames` var with `protoName()` helper — fixes inconsistency where connection flow stats was missing 7 protocol names
- **Medium**: Added `idx_rollup_interval_ts` composite index on `(interval_type, timestamp)` — rollup promotion queries no longer force full table scan
- **Medium**: Rollup aggregation now paginated (50k groups per batch) to prevent OOM on high-cardinality networks
- **Medium**: `formatBps()` now handles values < 1 and negative/NaN inputs without producing "undefined"
- **Medium**: Added error checks on GORM queries in `GetFlowStats` — DB errors now propagate instead of silently showing zeros
- **Low**: Replaced inline 6-column grid style with responsive `.stat-grid-6` CSS class (3-col at <1100px, 2-col at <600px)
- **Low**: Rollup engine logs heartbeat when no data to aggregate
- **Low**: Used weighted average `SUM(rate * count) / SUM(count)` for `sampling_rate_avg` when promoting rollups
- **Low**: Extracted shared `horizBarOpts` function — eliminated duplicate horizontal bar chart config
- **Low**: Extracted shared `topAddrsByBytes` helper — eliminated duplicate top src/dst query patterns
- **Low**: Reduced rollup batch size from 1000 to 500 for better SQLite compatibility
- Added `data-dport` attribute to conversation rows for future port-level drill-down

## [0.10.133] - 2026-03-18

### Added
- Enterprise sFlow dashboard: 6 stat cards (Total Flows, Total Bytes, Avg Throughput, Unique Sources, Unique Dests, Protocol Count)
- Bandwidth Over Time chart with adaptive bucketing (minute/hour/day based on time range)
- Top Destinations horizontal bar chart (green, complements Top Sources)
- Top Conversations table with % of total column and click-to-filter drill-down
- `FlowRollup` model for scalable flow data aggregation
- Rollup engine: auto-aggregates raw flows → 5m → 1h → 1d rollups every 5 minutes
- `formatBps()` helper for human-readable bits/sec formatting (Kbps, Mbps, Gbps)
- Est. Bytes column in flow samples table (bytes × sampling_rate)
- 5-minute time bucket support in SQLite and PostgreSQL dialects

### Changed
- Flow time range buttons expanded: 1h, 6h, 24h, 1w, 1m, 1y (was: Today, 1 Week, 1 Month, 1 Year)
- Bandwidth chart now shows bits/sec throughput instead of raw bytes
- Flows API (`/api/flows/stats`) returns `bits_per_second`, `protocol_count`, `top_destinations`, `top_conversations`

## [0.10.132] - 2026-03-18

### Added
- Per-device alert configuration modal accessible via "Alerts" button on each device row
- Toggle switch for enabling/disabling alerts per device
- Alert policy assignment dropdown (inherits from site/global when unset)
- Threshold override fields for CPU, Memory, Disk, Sessions, and Cooldown
- "Reset to Defaults" button to remove all device-level overrides
- Visual indicators on device table: red dot for muted alerts, yellow dot for custom config

## [0.10.131] - 2026-03-18

### Fixed
- Maintenance window device dropdown was empty when navigating directly to page (fetched from `currentDevices` which required visiting Devices page first) — now fetches from `/api/devices` API
- Maintenance table scope column showed "Device #3" instead of actual device/site names — now resolves names via API
- Scope toggle in edit mode now correctly restores the saved scope selection

### Improved
- Maintenance modal: replaced scope dropdown with segmented radio toggle for better UX
- Maintenance modal: pre-fills start time (now) and end time (now + 2 hours) for new windows
- Maintenance modal: device select shows IP address, site select shows region
- Maintenance modal: widened to 600px with better form spacing and placeholder text
- Stat cards: added colored left border accents (red=active, blue=scheduled, gray=total)
- Table: improved empty state with icon, hover-reveal action buttons
- Notes textarea enlarged with placeholder guidance

## [0.10.130] - 2026-03-18

### Fixed
- Remove dead code: unused `checkThreshold` method left over from refactor
- Add composite index `idx_alert_unack(acknowledged, suppressed, timestamp)` for efficient escalation queries
- Add index on `policy_id` for alert policy lookups
- Escape `formatDate()` output in ACK badge title attribute for defense-in-depth XSS prevention
- Add input length validation on alert policy name (200 chars) and description (1000 chars)

### Changed
- Refactor `CheckEscalations` to use `BuildNotifyConfigFromResolved` instead of manually constructing NotifyConfig, reducing code duplication
- Separate escalation notification sending from DB updates — all updates happen after notifications complete

## [0.10.129] - 2026-03-18

### Fixed
- **Critical: Escalation query inverted** — `GetUnacknowledgedAlerts` used `timestamp < cutoff` instead of `timestamp > cutoff`, causing escalation checks to query alerts older than 24h instead of newer
- **Critical: Missing PolicyActive flag** — `BuildNotifyConfigFromResolved` did not set `PolicyActive: true`, so policy-based channel routing was silently ignored and all channels fired via legacy path
- **Critical: Route conflict** — `GET /api/maintenance-windows/active` registered after `/:id` param route, causing Gin to match "active" as an ID; moved specific route before parameterized routes
- **Race condition in RefreshPolicyCache** — `policyCache` struct was assigned without holding `am.mu`, allowing torn reads during concurrent alert checks; now properly locks before assignment
- **Upsert error masking** — `UpsertDeviceAlertConfig` and `UpsertSiteAlertConfig` treated all DB errors as "not found" and retried with Create; now explicitly checks for `gorm.ErrRecordNotFound`
- **Recovery during maintenance** — Recovery notifications were sent even when the original alert was suppressed by a maintenance window; now skips recovery if `InMaintenance` is true
- **EnsureDefaultPolicy race** — Check-then-create pattern could create duplicate default policies under concurrent startup; replaced with GORM `FirstOrCreate`
- **UpdateMaintenanceWindow missing existence check** — Blindly updated by ID without verifying record exists; now returns 404 if not found
- **DeleteAlertPolicy error leak** — Exposed raw database error messages to API response; now returns generic error for non-business errors
- **Notes length unbounded** — `UpdateAlertNotes` accepted arbitrarily long notes; now validates max 4000 characters

### Changed
- **Performance: O(n) → O(1) policy lookup** — Added `policyByID` map to `PolicyCache` for constant-time policy resolution instead of linear scan
- **Performance: Batch recovery lock** — Recovery checks in `CheckSystemStatus` now resolve all 4 alert types under a single lock acquisition instead of 4 separate lock/unlock cycles
- **Code quality: Deduplicate `firedEntry`** — Extracted `firedEntry` struct to package-level type instead of 4 identical inline definitions
- **Code quality: Consolidate threshold overrides** — Merged `overrideThresholdFloat` and `overrideSiteThreshold` into single `overrideThreshold` function accepting raw field values
- **Code quality: Simplify SendAlert** — Replaced duplicated policy/legacy channel-check branches with unified boolean eligibility computation

## [0.10.128] - 2026-03-18

### Added
- **Per-device alert policies**: Reusable `AlertPolicy` bundles with per-alert-type rules, notification channel routing, cooldown overrides, and escalation settings
- **Alert rules**: Per-alert-type configuration within policies — enable/disable, severity override, threshold override, per-channel notification toggles (tri-state: inherit/on/off)
- **Device alert config**: Per-device policy assignment, threshold overrides (CPU/memory/disk/sessions), cooldown override, and master alerts-enabled toggle
- **Site alert config**: Per-site default policy and threshold overrides inherited by all site devices unless overridden at device level
- **Maintenance windows**: Time-based notification suppression per device, site, or fleet-wide — alerts still saved with `suppressed=true` for audit trail
- **Escalation**: Re-sends notifications for unacknowledged alerts after configurable interval, up to configurable repeat limit
- **Policy resolution engine** (`internal/alerts/policy.go`): Inheritance chain Device → Site → Policy Rule → Policy → Global defaults, computed per (device, alertType) with in-memory cache refreshed each poll cycle
- **Enhanced Alert model**: New fields `acknowledged_at`, `resolved_at`, `notes`, `policy_id`, `escalation_count`, `suppressed`
- **Alert acknowledgment with notes**: Acknowledge modal with optional notes textarea, `acknowledged_at` timestamp
- **15 new API endpoints**: Full CRUD for alert policies, alert rules (batch upsert), device/site alert configs, maintenance windows, alert notes
- **Admin UI**: New "Alert Policies" tab with policy list, create/edit/clone/delete, inline alert rules editor with tri-state channel toggles
- **Admin UI**: New "Maintenance" tab with maintenance window list, create/edit with scope picker (all/device/site), datetime pickers, alert type filter
- **Default policy auto-seeded**: `EnsureDefaultPolicy()` creates a "Default" policy on first boot — system works identically to pre-change with zero configuration

### Changed
- All alert check methods (`CheckSystemStatus`, `CheckInterfaceStatus`, `CheckVPNStatus`, `CheckInterfaceErrors`, `ProcessTrap`, `ProcessSyslog`) now accept `siteID` parameter and resolve per-device/policy configuration
- `canAlertWithCooldown()` uses resolved cooldown duration instead of global default
- `sendRecovery()` sets `resolved_at` on original alert records
- `SendAlert()` in notifier respects per-channel enable flags from policy resolution (backward compatible: legacy behaviour when no policy active)
- `RefreshThresholds()` now also refreshes the policy cache
- `pollAllDevices()` calls `CheckEscalations()` at end of each cycle

## [0.10.127] - 2026-03-18

### Added
- **Scheduled HTML email reports**: Daily and weekly reports with embedded PNG charts (traffic, CPU/memory, uptime meter, alert trend) sent as MIME multipart/related emails
- **Per-device 30-day uptime tracking**: Derived from `system_status` poll density — displayed as 99.99% format with visual uptime meter (green/red/grey)
- **Traffic spike detection**: Rolling-window standard deviation analysis for both real-time alerts (`TRAFFIC_SPIKE`) and report annotations
- **Enhanced critical alert emails**: Device-offline, VPN-down, and disk-critical alerts now include HTML formatting with recent CPU/memory charts
- **Report scheduler** (`internal/report/`): New package with chart rendering via `go-chart/v2`, HTML templates with inline CSS, MIME email builder, data aggregation, and scheduling
- **8 new settings**: `report_daily_enabled`, `report_daily_time`, `report_weekly_enabled`, `report_weekly_day`, `report_recipients`, `report_timezone`, `spike_stddev_threshold`, `spike_alert_enabled` — configurable via admin UI
- **4 new database queries**: `GetAlertsByDeviceAndHours`, `GetTopInterfacesByTraffic`, `GetDevicePollCount`, `GetDeviceFirstPoll`
- **MIME multipart email support**: `SendHTMLEmail()` in notifier with inline base64-encoded PNG images via Content-ID references

## [0.10.126] - 2026-03-17

### Fixed
- **Full PostgreSQL compatibility audit**: Fix all remaining SQLite-specific SQL across the codebase
- Fix backtick-quoted `index` column in interface history/chart queries (handlers_devices.go, handlers_dashboard.go) — use double quotes for PG compatibility
- Fix backtick-quoted `key` column in RefreshThresholds, getNotificationSetting, GetPublicDisplaySettings — use double quotes
- Fix `SavePingStats` using GORM `.Save()` on new records (ID=0) which fails on PG — use `.Create()` for new, `.Save()` for existing
- Fix `groupByString` not quoting column names — use `dialect.QuoteIdent()` for PG reserved word safety
- Fix migration PK clash: advance PG sequence to source MAX(id) before copying rows so concurrent probe inserts don't collide

## [0.10.125] - 2026-03-17

### Changed
- **Embedded PostgreSQL in Docker image**: PostgreSQL 16 is now installed inside the container and starts automatically — no external database needed
- Entrypoint initializes PG data directory on first run, creates database/user, and sets `DB_TYPE=postgres` for all services
- PG data persists in `/data/pgdata` alongside existing volume mount
- Existing SQLite data at `/data/firewall-mon.db` is auto-migrated on first startup, then renamed to `.migrated`
- Graceful shutdown stops app services first, then PostgreSQL
- PG tuned for embedded use: 128MB shared buffers, 30 max connections, unix socket only (no TCP)

## [0.10.124] - 2026-03-17

### Changed
- **Auto-migration on startup**: When `DB_TYPE=postgres` and the old SQLite file exists on disk, migration starts automatically — no manual action needed
- After successful migration, the SQLite file is renamed to `.migrated` (plus WAL/SHM) so it won't re-trigger on next restart
- Settings page shows live migration progress if one is running; manual start form available as fallback

## [0.10.123] - 2026-03-17

### Added
- **Admin database migration tool**: New SQLite-to-PostgreSQL data migration in the Settings page for users switching from SQLite to PostgreSQL
- Migration engine (`internal/database/migrate_data.go`) copies all tables in FK-safe order with configurable batch sizes (1000 for high-volume tables, 500 for others)
- Per-table progress tracking with real-time status updates (pending, running, done, skipped, error)
- Idempotent migration — tables that already contain data in PostgreSQL are automatically skipped
- PostgreSQL sequences automatically reset to `MAX(id)` after each table migration
- 3 new admin API endpoints: `GET /admin/api/migrate/precheck`, `POST /admin/api/migrate/start`, `GET /admin/api/migrate/status`
- Migration UI card on Settings page with overall progress bar, per-table status table, and 2-second polling
- `Database.IsPostgres()` accessor method for dialect detection

## [0.10.122] - 2026-03-17

### Fixed
- Fix PostgreSQL DSN breaking when password/user/dbname contain spaces or special characters (now properly quoted)
- Fix VPN chart queries using unaliased subqueries that fail on PostgreSQL (`FROM (...) AS deltas`)

## [0.10.121] - 2026-03-17

### Added
- **PostgreSQL support**: Add PostgreSQL as primary database backend (`DB_TYPE=postgres`) with connection pooling (25 open / 10 idle), while keeping SQLite as default for small deployments
- **Batch inserts**: High-volume data (syslog, traps, pings) now buffered and flushed in batches — syslog: 500 items / 2s, traps/pings: 100 items / 5s
- **Batch save API methods**: `SaveSyslogMessages`, `SaveTrapEvents`, `SavePingResults` for single-transaction bulk inserts from probe handlers
- **Configurable retention periods**: Per-data-type retention via env vars (`RETENTION_SYSLOG_DAYS`, `RETENTION_FLOW_DAYS`, `RETENTION_TRAP_DAYS`, `RETENTION_STATUS_DAYS`, `RETENTION_PING_DAYS`, `RETENTION_ALERT_DAYS`, `RETENTION_DEFAULT_DAYS`), default 90 days
- **DB SSL mode**: `DB_SSL_MODE` env var for PostgreSQL connections (default: `disable`)

### Changed
- **SQL dialect abstraction**: All 15 `strftime()` calls and 3 backtick-quoted identifiers replaced with dialect-aware helpers supporting both SQLite and PostgreSQL
- **Probe data handlers**: `ReceiveSyslogMessages`, `ReceiveTrapEvents`, `ReceivePingResults` now use single batch inserts instead of per-row saves
- **CleanupOldData**: Now accepts `RetentionConfig` with per-table retention periods instead of a single `days` parameter
- **Database Close**: Flushes all batch inserters before closing the connection

## [0.10.120] - 2026-03-15

### Fixed
- Fix IRC handlers returning encrypted ciphertext to API clients on create/update (all 4 endpoints now decrypt before responding)
- Fix `GetIRCChannels` endpoint not decrypting channel secrets
- Fix `UpdateIRCChannel` returning stale pre-update data (now re-fetches from DB)
- Fix double-encryption risk: `encryptField` now skips values already prefixed with `{enc}`
- Fix decryption failure returning empty string (reverted to returning ciphertext so auth fails loudly instead of silently)
- Fix nil pointer dereference in IRC bot `onQuit` when `b.Conn` is nil (now checks under mutex)
- Fix `PingCollector.Start()` being a no-op after `Stop()` (re-creates `stopCh` channel)
- Fix potential panic when admin password is shorter than 6 characters during masking
- Fix admin password file using hardcoded `/data/` path; now uses database directory
- Fix CORS middleware returning 204 for OPTIONS from disallowed origins (moved inside allowed block)
- Improve ENCRYPTION_KEY warning to guide safe migration from JWT-derived key

## [0.10.119] - 2026-03-15

### Security
- Add CORS middleware with configurable `CORS_ALLOWED_ORIGINS` (defaults to same-origin only)
- Move rate limiter from global to per-group so authenticated admin users don't share buckets with unauthenticated requests
- Encrypt SMTP password in system_settings using AES-256-GCM
- Redact auto-generated admin password from stderr; write full password to secure file `/data/.admin-password` instead
- Escape remaining unescaped `ch.status` in IRC admin JS to prevent XSS

### Performance
- Optimize GetDeviceDetail: reduce 12 sequential queries to 6 using subquery pattern (`WHERE timestamp = (SELECT MAX...)`)
- Add composite database indexes: Alert.Acknowledged, UptimeRecord(device_id,timestamp), ProbeHeartbeat(probe_id,timestamp), Probe.ApprovalStatus, SyslogMessage.Severity, TrapEvent.Severity

### Fixed
- Fix PingCollector goroutine leak: Stop() now sets running=false before close(stopCh) and waits outside lock
- Add error logging to ~30 swallowed database query errors across handlers (devices, dashboard, analytics, settings, sites, probes)

## [0.10.118] - 2026-03-15

### Security
- Encrypt IRC passwords (ServerPassword, NickServPassword, SASLPassword, ChanServPass, ChanOperPass, ChannelKey) with AES-256-GCM — same encryption used for SNMP credentials
- Separate database encryption key from JWT secret via new `ENCRYPTION_KEY` env var (falls back to JWT secret with warning for backwards compatibility)
- Fix decryption failure returning raw ciphertext — now returns empty string and logs warning
- Tighten Content-Security-Policy: remove `unsafe-inline` and `unsafe-eval` from `script-src`
- Convert all inline event handlers in IRC admin page to `addEventListener` for CSP compliance
- Add startup configuration validation: port ranges, SNMP version, TLS cert paths, bcrypt cost bounds, missing secret warnings
- Fix raw database error message exposure in IRC server update endpoint

### Fixed
- Add mutex to poller's `prevIfaceStats` map — prevents concurrent map write panic under load
- Sanitize IRC server update error response (no longer leaks internal DB errors)

## [0.10.117] - 2026-03-15

### Fixed
- IRC bot nick collision infinite loop: 433 handler now appends underscore to current nick instead of always trying the same static alternate nick
- Removed NICK event echo loop that caused cascading rename storms when multiple bot instances connected
- Reconnect loop now checks connection state under proper lock and spawns reconnects in goroutines to prevent duplicate connections
- onQuit handler now ignores other users' QUIT messages instead of clearing bot connection state
- Added DISCONNECTED callback for reliable TCP drop detection
- Start() now checks quit channel to prevent reconnecting a stopped bot
- RestartBot only starts new bot if server is enabled

## [0.10.116] - 2026-03-09

### Added
- Palo Alto Networks vendor profile with PAN-COMMON-MIB support (system status, sessions, GlobalProtect stats, AV/threat versions)
- Palo Alto VPN tunnel detection via IF-MIB tunnel.* interface patterns with 64-bit counter support
- Palo Alto hardware sensors via ENTITY-SENSOR-MIB (temperature, fan, voltage, power)
- Palo Alto per-CPU stats via HOST-RESOURCES-MIB (management plane, data plane)
- Palo Alto SNMP trap definitions (VPN, HA, hardware, GlobalProtect, threat events)
- SonicWall vendor profile with SNWL-COMMON-MIB and SONICWALL-FIREWALL-IP-STATISTICS-MIB
- SonicWall system status (CPU, RAM, session count from enterprise OIDs)
- SonicWall IPSec VPN tunnel monitoring via sonicSAStatTable (peer gateway, subnets, byte counters)
- SonicWall hardware sensor monitoring via sonicwallSensorsTable
- SonicWall SNMP trap definitions (IPSec, HA, IPS, security services, WAN failover)
- SonicWall added to valid vendors list and admin dropdown

## [0.10.115] - 2026-03-09

### Added
- Firewalla VPN tunnel detection via IF-MIB interface name patterns (WireGuard wg*, OpenVPN tun*/tap*, IPSec vti*)
- Linux-specific VPN helper (`vendor_linux_vpn.go`) with ifType-based disambiguation for ambiguous tun* interfaces
- `linuxGetAllVPNTunnels()` function with 64-bit counter support via ifXTable

## [0.10.114] - 2026-03-09

### Added
- **VPN tunnel detection for pfSense & OPNsense**: Discover VPN tunnels from IF-MIB interface name patterns (OpenVPN `ovpns*/ovpnc*`, WireGuard `wg*/tun_wg*`, IPSec VTI `ipsec*`) with status and traffic counters
- Shared BSD VPN helper (`vendor_bsd_vpn.go`) with IF-MIB walk + ifXTable 64-bit counter support

## [0.10.113] - 2026-03-09

### Added
- **pfSense vendor support**: SNMP vendor profile using UCD-SNMP-MIB + BEGEMOT-PF-MIB for CPU, memory, PF state count, and per-CPU load
- **OPNsense vendor support**: SNMP vendor profile with same FreeBSD/PF MIB stack and OPNsense-specific version parsing
- pfSense and OPNsense options in admin UI device vendor dropdown
- Vendor validation updated for pfsense and opnsense

## [0.10.112] - 2026-03-09

### Added
- **Firewalla vendor support**: New SNMP vendor profile for Firewalla devices using standard Linux MIBs (UCD-SNMP-MIB, HOST-RESOURCES-MIB, SNMPv2-MIB)
- Firewalla option in admin UI device vendor dropdown
- Firewalla added to valid vendor list for device create/update API validation

## [0.10.111] - 2026-03-07

### Added
- Configurable display timezone for all admin and public dashboard pages
- Timezone selector in Settings page with full list of world timezones (defaults to America/New_York / Eastern)
- `display_timezone` system setting persisted in DB and synced to localStorage
- Centralized `formatDate()` / `formatDateShort()` helpers in admin-common.js
- Public dashboard also respects the configured timezone via display-settings API
- All date/time displays across admin pages (syslog, flows, alerts, traps, devices, probes, network map) now use the configured timezone

## [0.10.110] - 2026-03-07

### Added
- IRC auto-status: periodic automatic status messages posted to channels on a configurable interval
- New `statusLoop` goroutine in IRC Manager ticks every 30s and sends status to channels with `SendStatus` enabled
- Channel modal: interval input (in minutes) shown when "Auto-Post Status" is checked
- Interval stored in seconds in DB, displayed as minutes in the UI

### Fixed
- IRC !status: removed bold formatting from device name in header
- IRC !status: removed extra space before closing `-+` in header to fix alignment

## [0.10.109] - 2026-03-07

### Fixed
- IRC !status: uptime was 100x too high — fgSysUpTime returns centiseconds (hundredths of a second), not seconds

## [0.10.108] - 2026-03-07

### Fixed
- IRC !status: switch to pure ASCII characters for mIRC Fixedsys compatibility (Unicode box-drawing chars cause font-linking misalignment)
- IRC !status: use colored spaces for progress bars instead of block chars (works with any font)
- IRC !status: bold device name in header, cleaner layout with grey borders
- IRC !status: all text/labels use only ASCII 0-127 characters

## [0.10.107] - 2026-03-07

### Fixed
- IRC !status: restore explicit white color after bar reset so bracket/percentage text renders consistently

## [0.10.105] - 2026-03-07

### Fixed
- IRC !status: restored Unicode box-drawing characters (│─┌┐└┘█●) — ASCII looked worse

## [0.10.104] - 2026-03-07

### Changed
- IRC !status: widened device boxes from 30 to 38 chars (supports longer firewall names up to ~17 chars)
- IRC !status: widened progress bars from 16 to 22 chars for better visual resolution

## [0.10.103] - 2026-03-07

### Fixed
- IRC !status: fixed box misalignment caused by \x0F resets killing monospace mid-line
- IRC !status: fixed padding errors from using byte length instead of rune count (Unicode chars like ● counted as 3 bytes)
- IRC !status: replaced per-element color+reset wrapping with inline color-set approach (single \x0F at end of each line)
- IRC !status: switched from Unicode box-drawing chars to ASCII for maximum client compatibility
- IRC !status: removed unreliable \x11 monospace toggle that was inconsistently applied

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
