# Firewall Monitor

> **A vendor-agnostic firewall monitoring system with SNMP polling, trap
> reception, alerting, config-change tracking, and uptime — run centrally
> or distributed via lightweight remote probes.**
>
> This repo builds the **central server** (3 Go binaries: `fwmon-api`,
> `fwmon-poller`, `fwmon-trap`) and ships the admin UI
> and the public GridStack dashboard. The **probe** half of the project
> is a sibling repo, [Firewall-Collector](https://github.com/xphox2/Firewall-Collector).

[![CI](https://github.com/xphox2/Firewall-Monitoring/actions/workflows/ci.yml/badge.svg)](https://github.com/xphox2/Firewall-Monitoring/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.11.235-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25.13+-00ADD8)](go.mod)
[![Status](https://img.shields.io/badge/status-alpha-orange)](#project-status)

> ⚠️ **Alpha.** This project is under active development and is published for early
> adopters and feedback. Expect rough edges and occasional breaking changes between
> versions. Pin a version, read [`MIGRATING.md`](MIGRATING.md) before upgrading, and
> please [file issues](https://github.com/xphox2/Firewall-Monitoring/issues) — feedback
> is exactly what this stage is for. See [Project status](#project-status) for details.

## Sibling project

This is **one of two** repositories. The other is
[Firewall-Collector](https://github.com/xphox2/Firewall-Collector) — the
lightweight probe that runs at a remote site, listens for syslog /
SNMP-trap / sFlow / ICMP, SSH- and TFTP-polls FortiGates, and relays
everything to this server. You need both: the other repo **deploys at
the edge**, this repo **runs at HQ**.

| | Server (this repo) | Probe (sibling) |
|---|---|---|
| Role | Store, alert, visualize, configure | Listen at the edge, relay to HQ |
| Binaries | `fwmon-api`, `fwmon-poller`, `fwmon-trap` | `firewall-collector`, `firewall-collector-diag-backup`, `firewall-collector-tftp-test` |
| Listens on | 8080/tcp (Web UI/API + probe relay), 162/udp (SNMP traps) | 162/udp, 514/tcp+udp, 6343/udp, 69/udp |
| Talks to | The device (SNMP/SSH/TFTP); the probe (HTTPS) | The server (HTTPS, mTLS) |
| Docs | this README + [docs/](docs/STRUCTURE.md) | [README](https://github.com/xphox2/Firewall-Collector/blob/master/README.md) + [docs/](https://github.com/xphox2/Firewall-Collector/blob/master/docs/STRUCTURE.md) |

## Who is this for

Self-hosted network/security teams and small-to-mid MSPs running a
**firewall fleet across multiple sites** — primarily FortiGate today, with
SNMP profiles for Palo Alto, Cisco ASA, SonicWall, pfSense, OPNsense and
Firewalla, plus config-diff normalization for FortiGate, Palo Alto and Cisco
ASA. It gives you one pane of glass (status, interfaces, VPN tunnels,
syslog, sFlow, alerts, reports) with **lightweight remote probes** that
relay SNMP/syslog/sFlow/ICMP from sites you can't poll directly — without
standing up a heavyweight NMS.

## When NOT to use this

- **General-purpose infrastructure monitoring** (servers, switches, apps,
  DBs) → LibreNMS, Zabbix, or Checkmk are built for that breadth.
- **Agentless website / synthetic / SSL-expiry checks** → Uptime Kuma or
  StatusCake are simpler and purpose-built.
- **A single firewall with no remote sites** → an SNMP exporter +
  Grafana, or the vendor's own GUI, is lighter than running this stack.
- **Vendor-supported enterprise NMS with SLAs and pro services** → PRTG
  or SolarWinds. This is OSS you self-host and operate yourself.

## How it compares

| | Firewall Monitor | PRTG | Nagios | Zabbix | LibreNMS | Checkmk | Uptime Kuma | StatusCake |
|---|---|---|---|---|---|---|---|---|
| Focus | **Firewall fleets** | General NMS | General NMS | General NMS | General NMS | General NMS | Uptime/synthetic | Uptime/synthetic |
| License | OSS (MIT) | Commercial | OSS + paid | OSS | OSS | OSS + paid | OSS | SaaS |
| Self-hosted | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✗ (SaaS) |
| Multi-site relay probes | ✅ built-in | sensors/remote probes | distributed pollers | proxies | distributed pollers | distributed | ✗ | n/a |
| Multi-vendor firewall SNMP profiles | ✅ (Forti/Palo/Cisco ASA/SonicWall/pfSense/OPNsense/Firewalla) | generic SNMP | generic SNMP | generic SNMP | generic SNMP | generic SNMP | ✗ | ✗ |
| Config-change tracking | ✅ (per-vendor normalized) | partial | plugins | partial | ✅ (Oxidized) | partial | ✗ | ✗ |
| Syslog + sFlow ingest | ✅ | add-on | plugins | add-on | partial | add-on | ✗ | ✗ |
| Footprint | Light (3 Go daemons) | Heavy | Medium | Medium | Medium | Medium | Light | n/a |

This project is intentionally **narrow and firewall-first**: it does a
few things (firewall health, VPN/connection mapping, config drift,
alerting) well, rather than being a general NMS. If you need breadth,
reach for one of the tools above; many teams run this *alongside* a
general NMS.

## Features

Every feature below is shipped in the current `0.11.x` release. **Role
tag** — `[Server]` runs on the central server (this repo), `[Probe]`
runs on the collector, `[Both]` requires both sides. **Status** —
Stable shipping, Beta shipping but with a known follow-up, Planned a
public AUDIT-NNN row exists.

### Data ingest

- **[Probe] SNMP device polling** (v1/v2c/v3, MD5/SHA/SHA2, DES/AES/AES192/256).
  Per-device `VendorProfile` registry. SNMP-pollable profiles: FortiGate,
  Palo Alto, Cisco ASA, SonicWall, pfSense, OPNsense, Firewalla (seven vendor
  profiles plus a generic fallback). Cisco ASA has both a full SNMP polling profile
  (CISCO-PROCESS-MIB CPU, CISCO-MEMORY-POOL-MIB memory, CISCO-FIREWALL-MIB
  connection count + failover HA, CDP neighbors) and per-vendor config-diff
  normalization. **The server never polls devices itself** (the direct poll loop
  was retired in v0.11.74) — collectors poll at the edge and relay;
  `fwmon-poller` is the server-side monitoring/alert engine that evaluates
  the relayed telemetry every `SNMP_POLL_INTERVAL` (default 60s).
- **[Server] SNMP trap receiver** (UDP/162). V1 enterprise + V2c
  specific-trap, per-source-IP rate limit, community filter (required,
  AUDIT-012).
- **[Both] Probe relay ingest** — syslog / sFlow / trap / flow / ping /
  SNMP-poll results from a remote [collector](https://github.com/xphox2/Firewall-Collector).
  Syslog (RFC 5424 + RFC 3164), sFlow v5 and ICMP are parsed **at the
  edge by the collector** and relayed here already-decoded — the server
  runs no raw syslog/sFlow/ICMP listener of its own.
- **[Both] `X-Probe-Batch-ID` idempotency key** (AUDIT-042) +
  **`schema_version` handshake** (0.10.382 / 1.2.108). Out-of-range
  versions get HTTP 426 with `X-Probe-Schema-Version-Supported`. No
  data loss on a 426. See [MIGRATING.md](MIGRATING.md).

### Multi-tenant / multi-site

- **[Server] Sites, Connections, Probes** — group devices into sites,
  visualize the physical → VLAN → tunnel → overlay network topology
  between them.
- **[Server] Probe approval workflow** — Pending → Approve / Reject.
  Per-probe registration keys (hashed, constant-time compare, AUDIT-016/017).
- **[Server] `POST /admin/api/probes/:id/regenerate-key`** (AUDIT-085).

### Alerting

- **[Server] Threshold alerts** (CPU / memory / disk / session count).
- **[Server] `INTERFACE_DOWN_ALERT`** (default `true`).
- **[Server] Alert state machine** (threshold + dedup + cooldown).
- **[Server] Alert policies** — per-device / per-site, DB-backed, bulk
  rules, clone.
- **[Server] Maintenance windows** — suppress alerts during planned work.
- **[Server] `PROBE_DATA_LAG_ALERT_MINUTES`** (default 60).
- **[Server] `PROBE_DATA_TRUNCATED`** alert (re-truncation within 5 min).
- **[Server] Traffic-spike detection** (per-interface std-dev threshold,
  0.10.239).
- **[Server] Auto-snooze + auto-archive of stale unacked alerts**
  (AUDIT-144 / AUDIT-031).

### Notifications

- **[Server] Email** (SMTP, HTML, STARTTLS / LOGIN / PLAIN).
- **[Server] Slack / Discord / generic webhook** (SSRF-gated, AUDIT-020).
- **[Server] IRC bot** (per-server, alerts + status commands; per-channel
  command allow-list, AUDIT-019).

### Reports

- **[Server] Executive HTML report** — image-free when viewed in-browser or
  exported to PDF; the scheduled email variant embeds the charts as inline
  (`cid:`) images.
- **[Server] Daily / weekly scheduled report** with
  `REPORT_TIMEZONE` (IANA TZ).
- **[Server] Traffic-spike + uptime rollup** in reports.

### Dashboards

- **[Server] Public GridStack dashboard** (drag-and-drop wallboard, no
  auth — safe to expose).
- **[Server] Admin dashboard** (auth-gated).
- **[Server] Site / connection / device topology diagram** (Cytoscape.js).
- **[Server] Per-device + per-connection detail pages** (status,
  interfaces, VPN, HA, SD-WAN, security, process top, config history
  with diff).
- **[Server] Chart zoom + pan** (chartjs-plugin-zoom).

### Auth & security

- **[Server] JWT-based admin auth** (HS256, `golang-jwt/jwt/v5`).
- **[Server] bcrypt** (configurable cost, default 12).
- **[Server] Account lockout** (5 attempts, 15 min).
- **[Server] Rate limiting** — per-IP LRU cap; separate buckets for
  login / public / probe (AUDIT-083).
- **[Server] CSRF protection** on admin mutations.
- **[Server] Secure HTTP headers** (HSTS, CSP nonce, X-Frame-Options).
- **[Server] Encrypted-at-rest stored secrets** (AES-256-GCM, key
  derived from JWT secret, rotation chain, AUDIT-009).
- **[Server] Admin-action audit log** (append-only, route-template
  labelled, AUDIT-078).
- **[Server] `httputil.InternalError`** — logs underlying error, never
  leaks it (AUDIT-071).
- **[Server] SSRF block-list** (private/loopback/CGNAT) for webhooks
  + test endpoints.
- **[Server] Client-side JS error reporting** (`POST /api/client-error`,
  AUDIT-129).
- **[Server] RFC 9116 `security.txt`** at `/.well-known/security.txt`
  (AUDIT-112).
- **[Server] Request-ID correlation** (`X-Request-ID` propagation,
  AUDIT-135).
- **[Planned] Server-side mTLS client-cert verification of probes** —
  tracked in [CERT-ROTATION.md](docs/CERT-ROTATION.md).
- **[Planned] SIGHUP hot-reload of TLS certs** — restart required
  today.
- **[Planned] One-click GDPR export / per-subject erasure endpoint** —
  tracked in [DATA-RETENTION.md](docs/DATA-RETENTION.md).

### Database & storage

- **[Server] PostgreSQL backend** (production).
- **[Server] SQLite** (tests only, AUDIT-118).
- **[Server] Embedded PostgreSQL in Docker** (auto-generated password
  in `/config/pg-credentials`, chmod 600, AUDIT-093).
- **[Server] Versioned, recorded DB migrations** (`schema_migrations`
  table, advisory-lock-gated runner, `migrate` / `migrate-status`
  subcommands, AUDIT-044).
- **[Server] Monthly range-partitioning** for the 6 high-volume
  tables (AUDIT-028 + AUDIT-146).
- **[Server] Autovacuum tuning** for high-write tables (AUDIT-147).
- **[Server] Per-table data retention** (14 `RETENTION_*_DAYS` env vars).
- **[Server] API single-instance guard** (Postgres advisory lock;
  `ALLOW_MULTI_API=true` opts into follower mode, AUDIT-040).
- **[Server] Poller cross-process leader lock** (only one does
  cleanup/migration work, AUDIT-007).
- **[Server] Per-connection `statement_timeout`** (Postgres, AUDIT-037).
- **[Server] Request-bound DB queries** (browser-disconnect
  cancellation, AUDIT-032 + AUDIT-079).

### Observability

- **[Server] `GET /api/health`** (Postgres ping, 1s timeout).
- **[Server] Docker `HEALTHCHECK`** (30s interval, 3s timeout, 3
  retries, AUDIT-091).
- **[Server] Prometheus `/metrics`** (request-latency histogram by
  matched route template, DB-pool gauges, Go runtime + process
  collectors, AUDIT-077).
- **[Server] Poller + trap-receiver `/metrics`, `/healthz`, `/readyz`**
  (v0.10.487; `POLLER_METRICS_ADDR` default `:9101`, `TRAP_METRICS_ADDR`
  default `:9102`; set to `off` to disable).
- **[Server] Structured logging** (slog) with request-ID correlation.

The full **website-ready** feature inventory (with status, role, and
"since" version for every row, plus the known-limitations table) lives
in [docs/FEATURES.md](docs/FEATURES.md).

## Architecture

```
firewall-mon/
├── cmd/
│   ├── api/           # Main API server (Gin web server) — auth, REST, admin UI
│   ├── poller/        # Monitoring/alert engine daemon (advisory-lock leader)
│   ├── configcheck/   # Config-backup validation CLI
│   └── trap-receiver/ # SNMP trap listener
├── internal/          # 23 packages — key ones below
│   ├── config/        # Configuration management (env vars)
│   ├── database/      # GORM persistence (SQLite/Postgres) + Store repo interface
│   ├── auth/          # JWT authentication & lockout
│   ├── snmp/          # SNMP client + multi-vendor OID profiles
│   ├── configdiff/    # Vendor-aware config normalization & semantic diff
│   ├── alerts/        # Alert threshold checking / AlertManager
│   ├── notifier/      # Email/Slack/Discord/webhook notifications
│   ├── report/        # Scheduled email/HTML executive reports
│   ├── irc/           # IRC bot manager
│   ├── uptime/        # Uptime calculation
│   ├── models/        # GORM data models
│   ├── relay/         # Probe↔server wire contract (DTOs + schema_version)
│   ├── secrets/       # JWT/encryption key load-or-generate
│   ├── audit/         # Append-only admin-action audit log
│   ├── metrics/       # Prometheus /metrics + observability server
│   ├── logging/       # slog setup + SafeGo panic recovery
│   ├── tracing/       # OpenTelemetry (OTLP) tracing
│   ├── httputil/      # Shared HTTP helpers (SSRF guard, error responses)
│   ├── shell/         # Static-source guard tests (cross-cutting invariants)
│   └── api/
│       ├── handlers/  # HTTP handlers (split per domain)
│       └── middleware/ # Security middleware
├── web/
│   ├── public/        # Public dashboard
│   └── admin/         # Admin panel
├── docs/              # Operator runbooks, AUDIT log, compatibility matrix
└── deploy.sh          # Deployment script
```

The full architecture with **Mermaid sequence diagrams** (probe
registration, poll cycle, alert firing/recovery) is in
[docs/architecture.md](docs/architecture.md).

## Quick Start

### Prerequisites

- **Go 1.25.13** (the version pinned in `go.mod`; uses `log/slog`-era
  stdlib; CI builds on the same toolchain).
- **Linux server** (tested on Ubuntu/Debian). The native installer uses
  **systemd**; macOS/Windows can build and run the binaries but the
  `make install` / `deploy.sh install` unit files are Linux-only.
- **PostgreSQL** (or use the embedded one in the Docker image).

On a fresh Ubuntu 24.04 box:

```bash
sudo apt update
sudo apt install -y golang-go git make rsync bash
# rsync is required by `deploy.sh deploy`; make drives the Makefile; git stamps the version.
sudo apt install -y build-essential   # gcc — only for `make test-race`; normal builds are CGO-free
```

**Network ports** the stack uses (open only what you enable):

| Port | Proto | Direction | Purpose |
|---|---|---|---|
| `8080` | TCP | inbound | HTTP UI + API (set by `SERVER_PORT`; put TLS or a reverse proxy in front for prod) |
| `162` | UDP | inbound | SNMP trap receiver (`SNMP_TRAP_LISTEN`, default `0.0.0.0:162`) |
| `514` | UDP/TCP | inbound | syslog receiver — **on the collector** (edge); the server ingests syslog only via the probe relay on `8080` |
| `6343` | UDP | inbound | sFlow receiver — **on the collector** (edge); the server ingests sFlow only via the probe relay on `8080` |
| `5432` | TCP | outbound | PostgreSQL (`DB_PORT`; prod backend) |

Probes relay back to the server over the same HTTP(S) port (`8080`),
so a remote site only needs **outbound** reach to the server — no
inbound ports at the site.

### Docker (recommended)

Prebuilt images are published to Docker Hub as
[`xphox/firewall-mon`](https://hub.docker.com/r/xphox/firewall-mon)
(tags: `latest`, `stable`, and one per version) on every green build of
`master`, so `docker compose up` pulls the image — no local build needed.

```bash
git clone https://github.com/xphox2/Firewall-Monitoring.git
cd Firewall-Monitoring
docker compose up -d
# wait ~30s for Postgres to come up
open http://localhost:8080
```

To build from source instead, use `docker compose up -d --build`.

The first boot auto-generates the admin password and writes it to
`./data/admin-password`. Tail `./data/firewall-mon.log` to see it.

### Build from source

```bash
./deploy.sh build          # build all binaries into ./bin
# or
make build                 # reproducible build of the three fwmon-* binaries
```

### Test

```bash
go test ./...              # the full test suite
make qa                    # full pre-commit gate: tidy + gofmt + vet + build + test
make test-race             # under the race detector (needs CGO)
make test-integration      # against a real Postgres (TEST_PG_DSN)
```

### Install natively (without Docker)

```bash
sudo make install          # installs to /usr/local (override PREFIX=/opt/firewall-mon)
make tarball               # package dist/firewall-mon-<version>.tar.gz
```

### Deploy to a remote server

```bash
./deploy.sh deploy -h your-server.com -u root -k ~/.ssh/id_rsa
```

### Install locally

```bash
sudo ./deploy.sh install
sudo ./deploy.sh start
```

## Configuration

Configuration is loaded from **environment variables** (or a
`CONFIG_FILE` pointing at an .env-style file). The authoritative
reference is [config.env.example](config.env.example) — it lists every
variable with inline comments and defaults. The probe-side env vars
live in the
[collector's ENV-VARS.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/ENV-VARS.md).

The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `SERVER_HOST` / `SERVER_PORT` | `0.0.0.0` / `8080` | HTTP listen address |
| `SERVER_ENABLE_TLS` | `false` | Terminate TLS in-process (cert/key via `SERVER_TLS_CERT`/`_KEY`) |
| `JWT_SECRET_KEY` | _(auto-generated + persisted)_ | Signs login JWTs **and** derives the AES-256 key for stored secrets |
| `ENCRYPTION_KEY` | _(derived from JWT secret)_ | Optional explicit key for encrypting device/probe secrets at rest |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / _(auto-generated + persisted)_ | Initial admin login — leave `ADMIN_PASSWORD` unset/empty to auto-generate and persist one (a non-default username is strongly recommended) |
| `SNMP_HOST` / `SNMP_PORT` / `SNMP_COMMUNITY` | `192.168.1.1` / `161` / `public` | Legacy global SNMP defaults (devices are polled by collectors, not the server) |
| `SNMP_POLL_INTERVAL` | `60s` | `fwmon-poller` monitoring-cycle cadence (staleness threshold = 3× this, min 5m) |
| `SNMP_TRAP_COMMUNITY` | _(empty — required)_ | Trap community check (AUDIT-012) |
| `CPU_THRESHOLD` / `MEMORY_THRESHOLD` / `DISK_THRESHOLD` / `SESSION_THRESHOLD` | `80` / `80` / `90` / `100000` | Alert thresholds |
| `EMAIL_ENABLED` + `SMTP_*` | `false` | Email alerting + scheduled reports |
| `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` | _(empty)_ | Chat alerting |
| `DB_TYPE` / `DB_HOST` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `postgres` (prod) | Database connection (SQLite is used for tests) |
| `RETENTION_*_DAYS` | varies | Per-table data retention (see [DATA-RETENTION.md](docs/DATA-RETENTION.md)) |
| `ALLOW_MULTI_API` | `false` | Opt out of the single-API-instance guard (AUDIT-040); follower mode serves HTTP only, no IRC bots. See [docs/OPERATIONS.md](docs/OPERATIONS.md). |
| `SERVER_READ_TIMEOUT` / `SERVER_WRITE_TIMEOUT` | `30s` / `30s` | HTTP server read/write timeouts |
| `DB_MAX_OPEN_CONNS` | per-process (15/10/5) | Connection-pool ceiling per daemon |

## Upgrading

The Docker image is `:latest` by default; for reproducibility pin to
the matching `:0.11.x` tag. The collector and the server can be
upgraded in either order — the `schema_version` handshake is symmetric
and both directions are backward-compatible. The
[operations runbook](docs/OPERATIONS.md#upgrade) is the
operator-facing step-by-step (backup, migrate, restart, verify).

```bash
# server (Docker)
docker compose pull && docker compose up -d
# server (native)
./deploy.sh deploy -h your-server.com -u root -k ~/.ssh/id_rsa
# probe
docker compose -f /path/to/probe/docker-compose.yml pull && up -d
```

## Compatibility

The collector and the server are deployed and upgraded independently.
The `schema_version` handshake (1.2.108 / 0.10.382) makes the upgrade
**order-independent** — both directions are backward-compatible. The
canonical compatibility table is [docs/SUPPORT-MATRIX.md](docs/SUPPORT-MATRIX.md);
the 1-pager version is the
[collector's COMPATIBILITY.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/COMPATIBILITY.md).

| Server | Accepts collectors | Notes |
|---|---|---|
| **0.10.386+** (current) | all 1.2.x | |
| 0.10.382 | 1.2.108+ | `schema_version` field is required starting here; absent field → 1 (back-compat) |
| 0.10.380 and earlier | all 1.2.x | Pre-handshake. The probe's `schema_version` field is ignored |

| Collector | Talks to server | Notes |
|---|---|---|
| **1.2.108+** (current) | 0.10.382+ (recommended), 0.10.380+ (works, field ignored) | Advertises `schema_version` on register |
| 1.2.78 – 1.2.107 | any 0.10.x | Pre-handshake; field omitted → server assumes v1 |
| < 1.2.78 | unsupported | Missing disk-spillover and several hardening fixes |

## Operations

The full operator runbook is in [docs/OPERATIONS.md](docs/OPERATIONS.md).
The first-24h checklist, failure modes table, backup/restore, JWT
rotation (flagged destructive), and the single-instance API guard
semantics are all there. The probe side is intentionally simpler
(see the [collector's README](https://github.com/xphox2/Firewall-Collector/blob/master/README.md#operations)).

## Security

- JWT tokens with secure cookies; account lockout after 5 failed
  attempts; CSRF protection on admin mutations.
- Rate limiting (per-IP LRU cap; 10 req/s baseline).
- Secure HTTP headers (HSTS, CSP nonce, X-Frame-Options).
- TLS support (in-process or via reverse proxy — `docs/nginx.conf` is
  a hardened plain-nginx config-as-code alternative to nginx-proxy-manager).
- Encrypted-at-rest stored secrets (AES-256-GCM, key derived from JWT
  secret, rotation chain).
- Admin-action audit log (append-only, route-template labelled).
- SSRF block-list (private/loopback/CGNAT) for webhooks and test
  endpoints.
- Client-side JS error reporting (`POST /api/client-error`).
- See [SECURITY.md](SECURITY.md) for the supported-versions table,
  vulnerability disclosure policy (90-day coordinated), and the hall
  of fame.

## API Endpoints

The server registers **~174 routes** across four groups. The
authoritative list is the route table in [`cmd/api/main.go`](cmd/api/main.go).
The grouped overview below covers every category.

### Public — no authentication (safe to expose on a wallboard)

- `GET /` — public GridStack dashboard
- `GET /api/health` — liveness/readiness check
- `GET /api/version` — build version (JSON)
- `GET /api/public/{dashboard,devices,interfaces,interfaces/chart,connections,vpn,status-history,display-settings}` — read-only status JSON
- `GET /security.txt`, `GET /.well-known/security.txt` — RFC 9116 contact; `GET /favicon.ico`

### Authentication

- `POST /api/auth/login` — obtain the JWT cookie
- `POST /admin/api/logout` — clear the session
- `GET /admin/api/csrf-token` — fetch the CSRF token for mutating requests

### Admin UI pages (HTML, auth-gated)

`GET /admin` and `/admin/{dashboard,devices,devices/:id,connections,connections/:id,sites,probes,syslog,flows,noc,traps,alerts,alert-policies,alerting,event-rules,threat-intel,ipsec,maintenance,reports,settings,profile,audit,irc}`

### Admin API (JSON, auth + CSRF) — base `/admin/api`

- **Devices:** `GET/POST /devices`, `GET/PUT/DELETE /devices/:id`, `POST /devices/test`, and per-device detail/history/charts under `/devices/:id/{detail,interfaces/:ifIndex/{history,chart},status-history,process-history,config-history[/:revId[/view]],config-history/diff,ha-status,sdwan-health,security-stats,interface-errors,vpn/:tunnel/chart,alert-config}`
- **Sites:** `GET/POST /sites`, `GET/PUT/DELETE /sites/:id`, `GET/PUT/DELETE /sites/:id/alert-config`
- **Probes:** `GET/POST /probes`, `GET/PUT/DELETE /probes/:id`, `GET /probes/pending`, `GET /probes/stats`, `GET /probes/:id/stats`, `POST /probes/:id/{approve,reject,regenerate-key}`, `POST /probes/test`
- **Connections:** `GET/POST /connections`, `GET/PUT/DELETE /connections/:id`, `GET /connections/:id/{detail,events,flows,traffic}`, `GET /connections/{status-summary,vpn-map}`
- **Alerts:** `GET /alerts`, `/alerts/:id`, `/alerts/stats`; `POST /alerts/:id/{acknowledge,snooze,unsnooze,notes}`; bulk `POST /alerts/bulk-{acknowledge,snooze}[-filter]`
- **Alert policies:** `GET/POST /alert-policies`, `GET/PUT/DELETE /alert-policies/:id`, `POST /alert-policies/:id/clone`, `PUT /alert-policies/:id/rules`
- **Maintenance windows:** `GET/POST /maintenance-windows`, `GET/PUT/DELETE /maintenance-windows/:id`, `GET /maintenance-windows/active`
- **Telemetry queries:** `GET /syslog`, `/syslog/:id`, `/syslog/stats`, `/flows`, `/flows/stats`, `/traps`, `/traps/stats`, `/interfaces`
- **IRC:** `GET/POST /irc/{servers,channels,commands}`, `PUT/DELETE /irc/{servers,channels,commands}/:id`, `POST /irc/servers/:id/{connect,disconnect}`, `POST /irc/{send,servers/test}`
- **Reports:** `GET /reports/preview`, `POST /reports/send`
- **Settings:** `GET/POST /settings`, `POST /settings/{password,test-email,test-webhook}`, `GET /display-settings`
- **Dashboard / uptime:** `GET /dashboard[/:id|/stats|/diag]`, `GET /uptime`, `POST /uptime/reset`

### Probe ingestion (probe → server, per-probe key auth) — base `/api/probes`

- `POST /register`, `POST /heartbeat`, `GET /:id/devices`
- `POST /:id/{system-status,interface-stats,interface-addresses,interface-errors,processor-stats,process-snapshot,hardware-sensors,sensor-details,vpn-status,ha-status,sdwan-health,security-stats,license-info,license-details,config-revision,syslog,traps,flows,pings}`

## Contributing & docs

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev environment, QA requirements, PR workflow.
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1.
- [docs/STRUCTURE.md](docs/STRUCTURE.md) — index of where every topic lives.
- [docs/architecture.md](docs/architecture.md) — combined architecture with Mermaid sequence diagrams.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — operator runbook.
- [docs/SUPPORT-MATRIX.md](docs/SUPPORT-MATRIX.md) — version compatibility table.
- [docs/DATA-RETENTION.md](docs/DATA-RETENTION.md) — per-table retention, PII inventory.
- [docs/CERT-ROTATION.md](docs/CERT-ROTATION.md) — TLS / probe-credential rotation.
- [docs/custom-vendor.md](docs/custom-vendor.md) — step-by-step tutorial for adding a new SNMP vendor profile.
- [docs/FORTIGATE-SNMP-SETUP.md](docs/FORTIGATE-SNMP-SETUP.md) — FortiGate device-side setup.
- [docs/FEATURES.md](docs/FEATURES.md) — website-ready feature inventory.
- [docs/AUDIT.md](docs/AUDIT.md) — public-release audit and progress log.
- [docs/OPERATIONS.md §Upgrade](docs/OPERATIONS.md#upgrade) — production upgrade runbook.
- [MIGRATING.md](MIGRATING.md) — probe↔server wire format (`schema_version`).
- [KNOWN-ISSUES.md](KNOWN-ISSUES.md) — current limitations with AUDIT-NNN cross-links.
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — vendored browser-side assets.

## Browser Support

The admin panel and public dashboard target **evergreen browsers**.
The baseline is set by the use of the CSS `:has()` selector and
ES2020 JavaScript:

| Browser | Minimum version |
|---|---|
| Chrome / Edge (Chromium) | 105+ |
| Safari (macOS / iOS) | 15.4+ |
| Firefox | 121+ |

## Project status

**Alpha.** The core feature set (SNMP polling, trap/syslog/sFlow ingestion,
alerting, config-change tracking, remote probes, reporting) is implemented and
runs in the maintainer's own environment, and the codebase has been through
several internal engineering and security audits (see [`docs/AUDIT.md`](docs/AUDIT.md)).
That said, it is early:

- **Breaking changes may land between minor versions.** Pin a version and read
  [`MIGRATING.md`](MIGRATING.md) and [`CHANGELOG.md`](CHANGELOG.md) before upgrading.
- **Not yet battle-tested across many environments.** It is FortiGate-first; other
  vendor profiles are less exercised.
- **Run it hardened.** See the [Security](#security) section and
  [`SECURITY.md`](SECURITY.md) — put TLS in front of it, don't expose the
  SNMP trap listener to the public internet, and change the generated admin
  password on first login.
- **No telemetry.** Firewall-Mon does not phone home — see [`PRIVACY.md`](PRIVACY.md).

Feedback, bug reports, and vendor-SNMP samples are very welcome — that is what
the alpha is for. See [Support](#support).

## License

MIT — see [LICENSE](LICENSE). Third-party components and their
licenses are inventoried in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Support

- **Bug reports & feature requests** → open a **GitHub Issue** on this
  repository. Include version (`GET /api/version`), platform, and the
  `X-Request-ID` of any 500.
- **Questions, setup help, "how do I…"** → use **GitHub Discussions** on
  this repository.
- **Security vulnerabilities** → do **not** open a public issue; follow
  [SECURITY.md](SECURITY.md).

There is no dedicated chat server (Discord/Matrix/IRC) for the project.
The built-in **IRC bot** is a *monitoring feature* — it posts alerts and
answers status queries in **your** ops channel. It is not a support channel for this project. (The project's own support channels are GitHub Issues and GitHub Discussions, listed above.)
