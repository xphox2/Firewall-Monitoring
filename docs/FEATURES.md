# Features

> Probe-side features: [xphox2/Firewall-Collector/docs/FEATURES.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/FEATURES.md).
> This file is the **server-side** feature inventory. Every row is verified
> against `internal/` source — if a row says "Stable" the corresponding
> code is in `main`, not in a draft branch. Probe-side rows that the server
> depends on (e.g. `schema_version`, mTLS) are cross-referenced for context.

**Status legend**

- **Stable** — shipping in the current `0.11.x` release, exercised in CI,
  covered by tests.
- **Beta** — shipping but the audit row says "not done" or there's a known
  follow-up. Safe to use, but read the linked caveat.
- **Planned** — the CHANGELOG or `KNOWN-ISSUES.md` mentions it as deferred. Do not depend on it in production.

**Role legend**

- **[Server]** — the central server does it (this repo).
- **[Probe]** — the [collector](https://github.com/xphox2/Firewall-Collector) does it.
- **[Both]** — both sides participate.

## Data ingest (direct poll, no probe)

| Feature | Status | Role | Since |
|---|---|---|---|
| SNMP polling (v1 / v2c / v3, MD5/SHA/SHA2, DES/AES/AES192/256) | Stable | [Server] | 0.1 |
| Per-device SNMP vendor OID profile (FortiGate, Palo Alto, SonicWall, pfSense, OPNsense, Firewalla) | Stable | [Server] | 0.1 |
| Vendor-neutral default: a device without a vendor is `generic` everywhere (column default, create API, device form, SNMP resolver, deny projection); one cached resolver (`handlers.deviceVendor`) and a CI guard against a `"fortigate"` default creeping back | Stable | [Server] | 0.11.290 (migration v71) |
| `unifi` and `meraki` vendors: accepted by the API, the device form and the event-rule vendor scope; standards-only SNMP profiles (clones of `generic`, built from vendor docs — untested on real hardware) | Experimental | [Server] | 0.11.291 |
| Config-change syslog attribution is gated per vendor (`configdiff.SyslogAuditParser`, FortiGate only): a non-FortiGate device's change is never credited to a `user=` found in unrelated syslog | Stable | [Server] | 0.11.291 |
| Trap type names are canonical (`HA_STATE_CHANGE`, never `ha-state-change`) at the trap receiver and the relay ingest, so Palo Alto / SonicWall HA and VPN traps match the alert types and the seeded trap rules | Stable | [Server] | 0.11.291 |
| Event-rule preview extracts each message with its own device's vendor (as the live engine does) when no vendor scope is set, instead of assuming FortiGate | Stable | [Server] | 0.11.292 |
| sFlow-only interface cards decode the sFlow v5 `ifStatus` bit field into oper / admin status (`up` / `down`; `0` stays `unknown`) | Stable | [Server] | 0.11.292 |
| Flows CSV export honours its 10 000-row cap (`GET /admin/api/flows` accepts `limit` up to 10000; other lists stay at 500) | Stable | [Server] | 0.11.292 |
| Vendor-neutral syslog normalizer (`internal/normalize`): every line maps to one typed Event (class / activity / action enums, rule identity key with VDOM-qualified tiers, ISO country codes); event rules can match the canonical `event.*` fields (`event.action eq deny` covers a FortiGate deny and a pf block) beside the unchanged vendor-native keys. Mappers: FortiGate, OPNsense, pfSense, generic (CEF / filterlog / key=value) | Stable | [Server] | 0.11.293 |
| UniFi (netfilter firewall log, SIEM CEF events 100/112/113/201/400-402/512/544/578/1005, dnsmasq) and Meraki (flows / firewall / vpn_firewall / urls / ids-alerts / security_event / events / airmarshal) syslog normalizers — built from vendor docs, **untested on real hardware** — plus the static per-vendor capability matrix (`internal/normalize/capability`: which `event.*` field each vendor can supply, via which transport, how completely; `Features` map for the UI / detectors) | Experimental | [Server] | 0.11.294 |
| SNMP trap receiver (UDP/162, V1 enterprise + V2c specific-trap, per-source-IP rate-limit, community filter) | Stable | [Server] | 0.1 |
| Syslog receiver — TCP + UDP, RFC 5424 + RFC 3164, source allow-list (parsed at the edge, relayed to the server) | Stable | [Probe] | 0.1 |
| sFlow v5 datagram parser (parsed at the edge, relayed to the server) | Stable | [Probe] | 0.1 |
| NetFlow v5/v9 + IPFIX ingest (`flow_source`-labelled rows, denied-flow events, post-NAT tuple, source filter, biflow, dual-export dedup) | Stable | [Server] + [Probe] | 0.11.20 / collector 1.3.0 (migration v29) |
| ICMP ping (raw `net/icmp`, no external `ping` binary; runs at the edge, relayed to the server) | Stable | [Probe] | 0.1 |
| **Probe** relay ingest (syslog / sFlow / trap / flow / ping / SNMP-poll results) | Stable | [Server] + [Probe] | 0.1 |
| Probe idempotency via `X-Probe-Batch-ID` | Stable | [Server] + [Probe] | 0.10.246 (AUDIT-042) |
| `schema_version` handshake (HTTP 426 on mismatch) | Stable | [Server] + [Probe] | 0.10.382 / 1.2.108 |

## Multi-tenant / multi-site

| Feature | Status | Role | Since |
|---|---|---|---|
| Sites | Stable | [Server] | 0.1 |
| Connections between sites (inter-site topology) | Stable | [Server] | 0.1 |
| Probes (per-probe registration key, hashed + constant-time compare) | Stable | [Server] | 0.10.246 (AUDIT-016/017) |
| Probe approval workflow (Pending → Approve / Reject) | Stable | [Server] | 0.1 |
| Probe regenerate-key endpoint | Stable | [Server] | 0.10.245 (AUDIT-085) |
| Per-probe key auth (probe-side hash + constant-time compare) | Stable | [Server] | 0.10.246 |

## Alerting

| Feature | Status | Role | Since |
|---|---|---|---|
| Threshold alerts (CPU / memory / disk / session count) | Stable | [Server] | 0.1 |
| `INTERFACE_DOWN_ALERT` | Stable | [Server] | 0.1 |
| Alert state machine (threshold + dedup + cooldown) | Stable | [Server] | 0.1 |
| Alert policies (per-device / per-site, DB-backed, bulk rules, clone) | Stable | [Server] | 0.1 |
| Maintenance windows (suppress alerts during planned work) | Stable | [Server] | 0.1 |
| `PROBE_DATA_LAG` alert (no data received for N minutes) | Stable | [Server] | 0.1 |
| `PROBE_DATA_TRUNCATED` alert (re-truncation within 5 min) | Stable | [Server] | 0.1 |
| Spike detection (per-interface, std-dev threshold) | Stable | [Server] | 0.10.239 |
| Auto-snooze + auto-archive of stale unacked alerts | Stable | [Server] | 0.10.144 (AUDIT-144), 0.10.31 (AUDIT-031) |

## Notifications

| Feature | Status | Role | Since |
|---|---|---|---|
| Email (SMTP, HTML, STARTTLS / LOGIN / PLAIN) | Stable | [Server] | 0.1 |
| Slack incoming webhook | Stable | [Server] | 0.1 |
| Discord webhook | Stable | [Server] | 0.1 |
| Generic webhook (SSRF-gated) | Stable | [Server] | 0.1 (AUDIT-020) |
| IRC bot (per-server, alerts + status commands) | Stable | [Server] | 0.1 |
| Per-channel command allow-list (AUDIT-019) | Stable | [Server] | 0.1 |
| **Probe** test-endpoint (test email / test webhook from the UI) | Stable | [Server] | 0.1 |

## Reports

| Feature | Status | Role | Since |
|---|---|---|---|
| Executive HTML report — image-free in-browser/PDF; scheduled email embeds inline `cid:` charts | Stable | [Server] | 0.1 |
| Daily / weekly scheduled report | Stable | [Server] | 0.1 |
| Traffic-spike detection in reports | Stable | [Server] | 0.10.239 |
| Uptime rollup in reports | Stable | [Server] | 0.1 |
| `REPORT_TIMEZONE` (IANA TZ) | Stable | [Server] | 0.1 |

## Dashboards

| Feature | Status | Role | Since |
|---|---|---|---|
| Public GridStack dashboard (drag-and-drop wallboard) | Stable | [Server] | 0.1 |
| Admin dashboard (auth-gated) | Stable | [Server] | 0.1 |
| Site / connection / device topology diagram (Cytoscape.js) | Stable | [Server] | 0.1 |
| Per-device detail page (status, interfaces, VPN, HA, SD-WAN, security, process top, config history with diff) | Stable | [Server] | 0.1 |
| Per-connection detail page (traffic / events / flows / detail) | Stable | [Server] | 0.1 |
| Chart zoom + pan (chartjs-plugin-zoom) | Stable | [Server] | 0.1 |

## Auth & security

| Feature | Status | Role | Since |
|---|---|---|---|
| JWT-based admin auth (HS256, `golang-jwt/jwt/v5`) | Stable | [Server] | 0.1 |
| bcrypt password hashing (configurable cost, default 12) | Stable | [Server] | 0.1 |
| Account lockout (5 attempts, 15 min) | Stable | [Server] | 0.1 |
| 2FA retry budget shared across the password stage (a correct password no longer resets the lockout bucket of a 2FA account; cleared only when the login completes) | Stable | [Server] | 0.11.289 |
| In-session re-authentication limiter (password change, 2FA setup/disable, secret reveal, device purge, passkey registration/deletion: 5 attempts per account, then 1/min, `429`; separate from the login lockout) | Stable | [Server] | 0.11.289 |
| Self-service account actions resolve the account by the session's user id; API-token principals refused (`403`) | Stable | [Server] | 0.11.289 |
| Rate limiting (per-IP LRU cap; separate buckets for login / public / probe) | Stable | [Server] | 0.1 (AUDIT-083) |
| CSRF protection (admin mutations) | Stable | [Server] | 0.1 |
| Secure HTTP headers (HSTS, CSP nonce, X-Frame-Options) | Stable | [Server] | 0.1 |
| In-process TLS termination (opt-in) | Stable | [Server] | 0.1 |
| Per-probe registration keys (hashed, constant-time compare) | Stable | [Server] | 0.10.246 (AUDIT-016/017) |
| Encrypted-at-rest stored secrets (AES-256-GCM, key derived from JWT secret, rotation chain) | Stable | [Server] | 0.10.258 (AUDIT-009) |
| Admin-action audit log (append-only, route-template labelled) | Stable | [Server] | 0.10.374 (AUDIT-078) |
| `httputil.InternalError` (logs underlying error, never leaks it) | Stable | [Server] | 0.10.368 (AUDIT-071) |
| SSRF block-list (private/loopback/CGNAT) for webhooks + test endpoints | Stable | [Server] | 0.1 (AUDIT-020) |
| Client-side JS error reporting (`POST /api/client-error`) | Stable | [Server] | 0.10.375 (AUDIT-129) |
| RFC 9116 `security.txt` at `/.well-known/security.txt` | Stable | [Server] | 0.10.354 (AUDIT-112) |
| Request-ID correlation (`X-Request-ID` propagation) | Stable | [Server] | 0.10.361 (AUDIT-135) |
| Server-side mTLS client-cert verification of probes | Planned | [Server] | tracked in [CERT-ROTATION.md](CERT-ROTATION.md) |
| SIGHUP hot-reload of TLS certs | Planned | [Server] | restart required today |
| Multi-tenant / `tenant_id` data partitioning | Planned (wontfix, single-tenant) | [Server] | CONTRIBUTING "What is out of scope" |
| One-click GDPR export / per-subject erasure endpoint | Planned | [Server] | tracked in [DATA-RETENTION.md](DATA-RETENTION.md) |

## Database & storage

| Feature | Status | Role | Since |
|---|---|---|---|
| PostgreSQL backend (production) | Stable | [Server] | 0.1 |
| SQLite backend (tests only — AUDIT-118) | Stable | [Server] | 0.1 |
| Embedded PostgreSQL in the Docker image (auto-generated password in `/config/pg-credentials`, chmod 600) | Stable | [Server] | 0.1 (AUDIT-093) |
| Versioned, recorded DB migrations (`schema_migrations` table, advisory-lock-gated runner, `migrate` / `migrate-status` subcommands) | Stable | [Server] | 0.10.378 (AUDIT-044) |
| Normalized event tables (`net_events` daily-partitioned with a retention-deep lookback, `sec_events` monthly, `net_event_rollups` per device / rule / action / direction / app category / ruleset per day, `fw_rules` catalog, `device_field_observed`); COPY writer, per-class retention (`config_change` kept forever by default), partition-drop-only `net_events` retention, hourly rollup with exact day close. Written by the syslog ingest since 0.11.296 | Stable | [Server] | 0.11.295 (migration v72) |
| Syslog ingest normalizes every row once (`NORMALIZE_ENABLED`, default on): the same parse feeds the rule engine, the deny projection (`denied_events`, now for every vendor's network-class deny) and the `net_events` / `sec_events` / `fw_rules` / `device_field_observed` writers; raw syslog is saved first and never depends on it; v6 probes skip the re-framing fallback | Stable | [Server] | 0.11.296 |
| Capability API (admin-only): `GET /admin/api/devices/:id/capabilities` — every normalized field's effective state (`native` / `partial` / `config_dependent` / `inactive` / `unsupported`) from the vendor profile ∩ what the device sent in the last 24 h, plus per-feature verdicts; `GET /admin/api/capabilities?feature=` — one verdict per active device for a feature | Stable | [Server] | 0.11.296 |
| One-time 30-day backfill of the normalized tables from stored syslog (`POST /admin/api/normalize/backfill`, `fwmon-api normalize-backfill`): keyset-paged per leaf, rate-limited (2 000 rows/s default), one transaction per batch (resumable, exactly-once beside the live ingest), cancel / resume, optional night window, disk-headroom precheck, rollup days re-closed afterwards | Stable | [Server] | 0.11.297 |
| The collector's syslog `format` hint is stored (`syslog_messages.format`, smallint, NULL unless the row came from a framing-contract probe — relay schema v6); the normalized-event backfill re-reads it and skips the re-framing join exactly as the live ingest did. Metadata-only migration under a short `lock_timeout` with retries | Stable | [Server] | 0.11.298 (migration v74) |
| Raw syslog / flow archive to S3-compatible storage — configuration and client: `ARCHIVE_*` keys (required when a stream is enabled, no service defaults, secret redacted everywhere, strict parsing), low-level aws-sdk-go-v2 client (checksums only when required, Content-MD5 on every upload, Object Lock headers, multipart with abort, HEAD + full read-back verify, pinned dials, no redirects, no delete). Used by the archive worker since 0.11.302; retention is unchanged | Beta | [Server] | 0.11.300 |
| Raw archive groundwork: manifest tables (`archive_chunks`, `archive_objects`, `archive_months`, `archive_id_marks`), the chunk planner (daily syslog cuts by `created_at` binary search of the primary key, hourly `flow_samples` / daily `flow_if_counters` cuts at recorded `max(id)` marks, export held until the cut has settled — `max(1 min, max(session, DB_STATEMENT_TIMEOUT) + 5 s)`, then every writing transaction older than that has finished (`pg_current_snapshot()`; read-only transactions never block; refused without a `statement_timeout`) — and a count + id-sum + id-hash check after it) and the deterministic gzip NDJSON exporter (rows in id order, fixed field order per schema version, SHA-256 of the content and of the object, message-day histograms; keyset pages of 5 000 rows under a 120 s statement timeout, optional rate). Driven by the archive worker since 0.11.302 (no delete gate yet); retention is unchanged. Ingest now always stamps `created_at` of syslog, flow and counter rows itself (a probe body could set it before) | Beta | [Server] | 0.11.301 (migration v75) |
| Raw archive worker (poller, own advisory lock; runs only for an enabled stream): takes the flow tables' `max(id)` marks every minute, every 10 minutes cuts the due chunks (flows first, one chunk per stream in turn), waits until each cut has settled, exports it to a staging directory (`ARCHIVE_STAGING_DIR`, free-space floor, paced by `ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC` / `ARCHIVE_FLOW_RATE_ROWS_PER_SEC`, syslog optionally confined to `ARCHIVE_WINDOW`), uploads each object (Content-MD5, Object Lock), reads every object back in full (stored-bytes SHA-256, decompressed SHA-256, row count, every line JSON with an id in range) and recounts the id range in the table; only a count of `match` writes the `chunk.json` manifest of each stream folder (an empty netflow hour gets `"objects": []`) and marks the chunk verified. Any other outcome fails the attempt, retried after 1 / 5 / 30 min then every 2 h with a fresh export that supersedes the old objects. Resumes after a crash at any step (same keys, database state machine). Syslog months before the stored `format` are schema v1. `fwmon_archive_*` metrics (lag, verified-through id, chunks by status, rows / objects / bytes, errors by stage, last success, unsettled reason). No delete gate, month seal or UI yet; retention is unchanged | Beta | [Server] | 0.11.302 |
| Monthly range-partitioning for the 6 high-volume tables (`interface_stats`, `system_status`, `syslog_messages`, `syslog_summaries`, `trap_events`, `flow_samples`) | Stable | [Server] | 0.10.380 (AUDIT-028 + AUDIT-146) |
| Autovacuum tuning for high-write tables | Stable | [Server] | 0.10.353 (AUDIT-147) |
| Per-table data retention (14 `RETENTION_*_DAYS` env vars) | Stable | [Server] | 0.1 |
| GORM log level (default `warn` — slow queries, errors, migration warnings) | Stable | [Server] | 0.10.353 (AUDIT-149) |
| API single-instance guard (Postgres advisory lock; `ALLOW_MULTI_API=true` opts into follower mode) | Stable | [Server] | 0.10.381 (AUDIT-040) |
| Poller cross-process leader lock (only one does cleanup/migration work) | Stable | [Server] | 0.1 (AUDIT-007) |
| Per-connection `statement_timeout` (Postgres) | Stable | [Server] | 0.10.261 (AUDIT-037) |
| Request-bound DB queries (browser-disconnect cancellation) | Stable | [Server] | 0.10.377 (AUDIT-032 + AUDIT-079) |

## Resiliency

| Feature | Status | Role | Since |
|---|---|---|---|
| Graceful shutdown on SIGINT/SIGTERM (drain in-flight requests, close DB) | Stable | [Server] | 0.1 |
| Async batcher with `Dropped` counter (bounded queue) | Stable | [Server] | 0.1 (AUDIT-006) |
| `apiFetch` (5xx retry + jittered backoff on the browser side) | Stable | [Server] | 0.10.355 (AUDIT-130) |
| `test/guardrails` static guard tests (one per resolved AUDIT-NNN) | Stable | [Server] | 0.1 |

## Observability

| Feature | Status | Role | Since |
|---|---|---|---|
| `GET /api/health` (Postgres ping, 1s timeout) | Stable | [Server] | 0.1 (AUDIT-091) |
| Docker `HEALTHCHECK` calls `/api/health` (30s interval, 3s timeout, 3 retries) | Stable | [Server] | 0.10.264 |
| Prometheus `/metrics` (request-latency histogram by matched route template, DB-pool gauges, Go runtime + process collectors) | Stable | [Server] | 0.10.373 (AUDIT-077) |
| API `/metrics` gated: loopback peers only (404 otherwise), or `Authorization: Bearer $METRICS_TOKEN` when set | Stable | [Server] | 0.11.288 |
| Cookie `Secure` flag and HSTS follow how the request arrived (in-process TLS, or a `TRUSTED_PROXIES` peer sending `X-Forwarded-Proto: https`) unless `COOKIE_SECURE` is set | Stable | [Server] | 0.11.288 |
| Poller + trap-receiver `/metrics` + `/healthz` + `/readyz` (`POLLER_METRICS_ADDR` `:9101`, `TRAP_METRICS_ADDR` `:9102`, `off` disables) | Stable | [Server] | 0.10.487 |
| Structured logging (slog) with request-ID correlation | Stable | [Server] | 0.1 |
| `fwmon_normalize_outcomes_total{kind}`, `fwmon_normalize_rows_total{table}`, `fwmon_normalize_write_errors_total{table}` on the API `/metrics` | Stable | [Server] | 0.11.296 |

## Vendor profiles

The server ships with a SNMP `VendorProfile` registry. The list is verified
in `internal/snmp/vendor_test.go`. Six vendors have a registered SNMP polling
profile, plus the standards-only `generic` profile (MIB-II / HOST-RESOURCES
only, no enterprise OIDs) that a device without a vendor is polled with;
`cisco_asa` is supported for config-diff only and has **no** SNMP profile
(see the `validVendors` list in `internal/api/handlers/handlers.go`).

| Vendor | SNMP profile | HA | SD-WAN | Security stats | License | VPN |
|---|---|---|---|---|---|---|
| **fortigate** | full | ✅ | ✅ | ✅ | ✅ | site-to-site + dialup + SSL |
| **paloalto** | full | ✅ | ✅ | ✅ | ✅ | site-to-site + SSL |
| **sonicwall** | full | ✅ | — | — | ✅ | site-to-site |
| **pfsense** | full | ✅ (CARP) | — | — | — | IPsec |
| **opnsense** | full | ✅ (CARP) | — | — | — | IPsec |
| **firewalla** | basic | — | — | — | — | — |
| **cisco_asa** | _config-diff only — no SNMP profile_ | — | — | — | — | — |
| **generic** (default) | _standards-only MIB-II profile — config-diff identity-hash only, no deny projection_ | — | — | — | — | — |

To add a vendor: see [custom-vendor.md](custom-vendor.md).

## Deployment

| Feature | Status | Role | Since |
|---|---|---|---|
| Multi-stage rootless Docker image (`alpine:3.19`, dedicated `fwmon` user, hardened) | Stable | [Server] | 0.1 |
| `docker-compose.yml` (single service, embedded Postgres, healthcheck) | Stable | [Server] | 0.1 |
| `docker-compose.proxy.yml` (NPM or hardened-nginx alternative) | Stable | [Server] | 0.1 (AUDIT-097) |
| Hardened systemd unit (`deploy.sh install` — `NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies`, etc.) | Stable | [Server] | 0.1 (AUDIT-021) |
| Native installer (`make install` to `/usr/local`, `make tarball` for the tarball) | Stable | [Server] | 0.1 (AUDIT-104) |
| Reproducible builds (`-trimpath -buildvcs=false`) | Stable | [Server] | 0.10.260 (AUDIT-102/103) |
| `deploy.sh` (build / install / deploy with `-h host -k key --dry-run` and remote backup) | Stable | [Server] | 0.1 (AUDIT-098/099) |
| CHANGELOG-driven GitHub release workflow (`.github/workflows/release.yml`) | Stable | [Server] | 0.10.367 (AUDIT-165) |

## Coverage stats

| Metric | Value | Source |
|---|---|---|
| Go source lines (server, non-test) | ~45,000 | `find . -name '*.go' ! -name '*_test.go' -exec wc -l {} +` |
| Go source lines (server, with tests) | ~67,000 | same with `*_test.go` |
| Internal packages | 23 | `internal/{alerts,api,audit,auth,config,configdiff,database,httputil,irc,logging,metrics,models,notifier,ping,relay,report,secrets,sflow,shell,snmp,syslog,tracing,uptime}` (`api` groups `handlers`/`middleware`/`response`) |
| Binaries built | 3 fwmon daemons | `cmd/{api,poller,trap-receiver}` (`cmd/configcheck` is a CLI; `cmd/probe` was removed) |
| Vendors with a registered SNMP `VendorProfile` | 6 | fortigate, paloalto, sonicwall, pfsense, opnsense, firewalla (cisco_asa is config-diff only) |
| Static guard tests in `test/guardrails` | 144 | `ls test/guardrails/*_test.go` |
| API endpoints | ~174 | `cmd/api/main.go` |

## Known limitations (catalogued in [KNOWN-ISSUES.md](../KNOWN-ISSUES.md))

| Limitation | Tracking | Workaround |
|---|---|---|
| Single-binary Docker image; only one port-binding host | AUDIT-040 | Run a single container, OR `ALLOW_MULTI_API=true` for followers |
| Embedded Postgres uses a randomly-generated password in `/config/pg-credentials` | AUDIT-093 | `docker exec firewall-mon cat /config/pg-credentials` |
| Default `ADMIN_USERNAME=admin` triggers a startup warning | AUDIT-105 | Set `ADMIN_USERNAME` to something non-default |
| Four tables (`interface_errors`, `processor_stats`, `process_stats`, `irc_message_logs`) can grow between cleanup ticks | AUDIT-029 | `RETENTION_*_DAYS` set to 30 (or shorter) |
| SQLite is tests-only | AUDIT-118 | Production is Postgres-only |
