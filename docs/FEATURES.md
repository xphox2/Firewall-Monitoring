# Features

> Probe-side features: [xphox2/Firewall-Collector/docs/FEATURES.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/FEATURES.md).
> This file is the **server-side** feature inventory. Every row is verified
> against `internal/` source — if a row says "Stable" the corresponding
> code is in `main`, not in a draft branch. Probe-side rows that the server
> depends on (e.g. `schema_version`, mTLS) are cross-referenced for context.

**Status legend**

- **Stable** — shipping in the current `0.10.x` release, exercised in CI,
  covered by tests.
- **Beta** — shipping but the audit row says "not done" or there's a known
  follow-up. Safe to use, but read the linked caveat.
- **Planned** — a public `AUDIT-NNN` row exists in [AUDIT.md](AUDIT.md) or
  the CHANGELOG mentions it as deferred. Do not depend on it in production.

**Role legend**

- **[Server]** — the central server does it (this repo).
- **[Probe]** — the [collector](https://github.com/xphox2/Firewall-Collector) does it.
- **[Both]** — both sides participate.

## Data ingest (direct poll, no probe)

| Feature | Status | Role | Since |
|---|---|---|---|
| SNMP polling (v1 / v2c / v3, MD5/SHA/SHA2, DES/AES/AES192/256) | Stable | [Server] | 0.1 |
| Per-device SNMP vendor OID profile (FortiGate, Palo Alto, SonicWall, pfSense, OPNsense, Firewalla) | Stable | [Server] | 0.1 |
| SNMP trap receiver (UDP/162, V1 enterprise + V2c specific-trap, per-source-IP rate-limit, community filter) | Stable | [Server] | 0.1 |
| Syslog receiver — TCP + UDP, RFC 5424 + RFC 3164, `SYSLOG_ALLOWED_SOURCES` allow-list | Stable | [Server] | 0.1 |
| sFlow v5 datagram parser | Stable | [Server] | 0.1 |
| NetFlow v5/v9 + IPFIX ingest (`flow_source`-labelled rows, denied-flow events, post-NAT tuple, source filter, biflow, dual-export dedup) | Stable | [Server] + [Probe] | 0.11.20 / collector 1.3.0 (migration v29) |
| ICMP ping (raw `net/icmp`, no external `ping` binary) | Stable | [Server] | 0.1 |
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
| Image-free executive HTML report (view in-browser, export PDF) | Stable | [Server] | 0.1 |
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
| `internal/shell` static guard tests (one per resolved AUDIT-NNN) | Stable | [Server] | 0.1 |

## Observability

| Feature | Status | Role | Since |
|---|---|---|---|
| `GET /api/health` (Postgres ping, 1s timeout) | Stable | [Server] | 0.1 (AUDIT-091) |
| Docker `HEALTHCHECK` calls `/api/health` (30s interval, 3s timeout, 3 retries) | Stable | [Server] | 0.10.264 |
| Prometheus `/metrics` (request-latency histogram by matched route template, DB-pool gauges, Go runtime + process collectors) | Stable | [Server] | 0.10.373 (AUDIT-077) |
| Poller + trap-receiver `/metrics` + `/healthz` + `/readyz` (`POLLER_METRICS_ADDR` `:9101`, `TRAP_METRICS_ADDR` `:9102`, `off` disables) | Stable | [Server] | 0.10.487 |
| Structured logging (slog) with request-ID correlation | Stable | [Server] | 0.1 |

## Vendor profiles

The server ships with a SNMP `VendorProfile` registry. The list is verified
in `internal/snmp/vendor_test.go`. Six vendors have a registered SNMP polling
profile; `cisco_asa` is supported for config-diff only and has **no** SNMP
profile (see [config-diff-roadmap.md](config-diff-roadmap.md) and the
`validVendors` list in `internal/api/handlers/handlers.go`).

| Vendor | SNMP profile | HA | SD-WAN | Security stats | License | VPN |
|---|---|---|---|---|---|---|
| **fortigate** (default) | full | ✅ | ✅ | ✅ | ✅ | site-to-site + dialup + SSL |
| **paloalto** | full | ✅ | ✅ | ✅ | ✅ | site-to-site + SSL |
| **sonicwall** | full | ✅ | — | — | ✅ | site-to-site |
| **pfsense** | full | ✅ (CARP) | — | — | — | IPsec |
| **opnsense** | full | ✅ (CARP) | — | — | — | IPsec |
| **firewalla** | basic | — | — | — | — | — |
| **cisco_asa** | _config-diff only — no SNMP profile_ | — | — | — | — | — |
| **generic** | _no SNMP profile — config-diff identity-hash only_ | — | — | — | — | — |

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
| Static guard tests in `internal/shell` | 98 | `ls internal/shell/*_test.go` |
| API endpoints | ~174 | `cmd/api/main.go` |
| Open audit findings | 0 of 170 (all resolved) | [AUDIT.md](AUDIT.md) Part I |

## Known limitations (catalogued in [KNOWN-ISSUES.md](../KNOWN-ISSUES.md))

| Limitation | Tracking | Workaround |
|---|---|---|
| Single-binary Docker image; only one port-binding host | AUDIT-040 | Run a single container, OR `ALLOW_MULTI_API=true` for followers |
| Embedded Postgres uses a randomly-generated password in `/config/pg-credentials` | AUDIT-093 | `docker exec firewall-mon cat /config/pg-credentials` |
| Default `ADMIN_USERNAME=admin` triggers a startup warning | AUDIT-105 | Set `ADMIN_USERNAME` to something non-default |
| Four tables (`interface_errors`, `processor_stats`, `process_stats`, `irc_message_logs`) can grow between cleanup ticks | AUDIT-029 | `RETENTION_*_DAYS` set to 30 (or shorter) |
| SQLite is tests-only | AUDIT-118 | Production is Postgres-only |
