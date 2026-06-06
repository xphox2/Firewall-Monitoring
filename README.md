# Firewall Monitor

A comprehensive, vendor-agnostic firewall monitoring system with SNMP polling, trap reception, alerting, and uptime tracking. Currently supports FortiGate devices via Fortinet enterprise OIDs, with a generic architecture ready for any SNMP-capable firewall.

## Features

- **Public Dashboard**: Display firewall status without authentication (drag-and-drop GridStack wallboard)
- **Secure Admin Panel**: Protected by JWT authentication with rate limiting and account lockout
- **Multi-vendor SNMP**: FortiGate, Palo Alto, and Cisco ASA profiles today, with a generic profile for any SNMP-capable firewall (`VendorProfile` interface)
- **SNMP Polling**: Comprehensive monitoring with configurable intervals (default 60s to avoid firewall overload)
- **SNMP Trap Receiver**: Listen for SNMP traps and generate alerts
- **Remote Probe / Collector Architecture**: Deploy lightweight probes at remote sites that relay SNMP polls, SNMP traps, syslog, sFlow, and ICMP ping back to the central server (multi-tenant, per-probe registration keys)
- **Syslog / sFlow / ICMP collection**: TCP+UDP syslog receiver, sFlow flow sampling, and ping-based reachability — directly or via a probe
- **Sites & Connection Map**: Group devices into sites and visualize the physical → VLAN → tunnel → overlay network topology between them
- **Alerting System**: Email, Slack, Discord, and webhook notifications, with configurable **alert policies** and **maintenance windows** (suppress alerts during planned work)
- **Reports**: Image-free executive HTML reports (view in-browser, export PDF, download, or email on a schedule) at `/admin/reports`
- **IRC Bot**: Per-server IRC bots that post alerts and answer status queries from a channel
- **Uptime Tracking**: 99.99999% (five nines) uptime calculation
- **Secure**: CSRF protection, secure headers (HSTS/CSP), rate limiting, account lockout, encrypted-at-rest device/probe secrets

## Who is this for

Self-hosted network/security teams and small-to-mid MSPs running a **firewall
fleet across multiple sites** — primarily FortiGate today, with Palo Alto and
Cisco ASA profiles and a generic SNMP profile for anything else. It gives you
one pane of glass (status, interfaces, VPN tunnels, syslog, sFlow, alerts,
reports) with **lightweight remote probes** that relay SNMP/syslog/sFlow/ICMP
from sites you can't poll directly — without standing up a heavyweight NMS.

## When NOT to use this

- **General-purpose infrastructure monitoring** (servers, switches, apps, DBs) →
  LibreNMS, Zabbix, or Checkmk are built for that breadth.
- **Agentless website / synthetic / SSL-expiry checks** → Uptime Kuma or
  StatusCake are simpler and purpose-built.
- **A single firewall with no remote sites** → an SNMP exporter + Grafana, or
  the vendor's own GUI, is lighter than running this stack.
- **Vendor-supported enterprise NMS with SLAs and pro services** → PRTG or
  SolarWinds. This is OSS you self-host and operate yourself.

## How it compares

| | Firewall Monitor | PRTG | Nagios | Zabbix | LibreNMS | Checkmk | Uptime Kuma | StatusCake |
|---|---|---|---|---|---|---|---|---|
| Focus | **Firewall fleets** | General NMS | General NMS | General NMS | General NMS | General NMS | Uptime/synthetic | Uptime/synthetic |
| License | OSS (MIT) | Commercial | OSS + paid | OSS | OSS | OSS + paid | OSS | SaaS |
| Self-hosted | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✗ (SaaS) |
| Multi-site relay probes | ✅ built-in | sensors/remote probes | distributed pollers | proxies | distributed pollers | distributed | ✗ | n/a |
| Multi-vendor firewall SNMP profiles | ✅ (Forti/Palo/ASA/+generic) | generic SNMP | generic SNMP | generic SNMP | generic SNMP | generic SNMP | ✗ | ✗ |
| Config-change tracking | ✅ (per-vendor normalized) | partial | plugins | partial | ✅ (Oxidized) | partial | ✗ | ✗ |
| Syslog + sFlow ingest | ✅ | add-on | plugins | add-on | partial | add-on | ✗ | ✗ |
| Footprint | Light (4 Go binaries) | Heavy | Medium | Medium | Medium | Medium | Light | n/a |

This project is intentionally **narrow and firewall-first**: it does a few
things (firewall health, VPN/connection mapping, config drift, alerting) well,
rather than being a general NMS. If you need breadth, reach for one of the tools
above; many teams run this *alongside* a general NMS.

## Architecture

```
firewall-mon/
├── cmd/
│   ├── api/          # Main API server (Gin web server)
│   ├── poller/       # SNMP polling daemon
│   ├── probe/        # Remote site probe collector
│   └── trap-receiver/ # SNMP trap listener
├── internal/
│   ├── config/      # Configuration management
│   ├── auth/        # JWT authentication & security
│   ├── snmp/        # SNMP client & trap receiver (FortiGate OIDs)
│   ├── alerts/      # Alert threshold checking
│   ├── notifier/    # Email/webhook notifications
│   ├── uptime/      # Uptime calculation
│   ├── models/      # Data structures
│   ├── relay/       # Probe relay client
│   ├── ping/        # ICMP ping collector
│   ├── syslog/      # Syslog receiver
│   ├── sflow/       # sFlow receiver
│   └── api/
│       ├── handlers/ # HTTP handlers
│       └── middleware/ # Security middleware
├── web/
│   ├── public/      # Public dashboard
│   └── admin/       # Admin panel
└── deploy.sh        # Deployment script
```

See [docs/architecture.md](docs/architecture.md) for component **data-flow and sequence diagrams** (probe registration, poll cycle, alert firing).

## Quick Start

### Prerequisites

- **Go 1.21+** (uses `log/slog`-era stdlib; `go.mod` pins the exact minor).
- **Linux server** (tested on Ubuntu/Debian). The native installer uses
  **systemd**; macOS/Windows can build and run the binaries but the
  `make install` / `deploy.sh install` unit files are Linux-only.
- An **SNMP-enabled firewall** (or a remote **probe** at a site you can't poll
  directly).

On a fresh Ubuntu 24.04 box, install the toolchain and the tools the
build/deploy scripts shell out to:

```bash
sudo apt update
sudo apt install -y golang-go git make rsync bash
# 'rsync' is required by `deploy.sh deploy` (it rsyncs binaries to the remote).
# 'make' drives the Makefile targets; 'git' is needed for the version stamp.
# The race detector (`make test-race`) additionally needs a C toolchain:
sudo apt install -y build-essential   # gcc — only for -race; normal builds are CGO-free
```

**Firewall / network ports** the stack uses (open only what you enable):

| Port | Proto | Direction | Purpose |
|---|---|---|---|
| `8080` | TCP | inbound | HTTP UI + API (set by `SERVER_PORT`; put TLS or a reverse proxy in front for prod) |
| `161` | UDP | outbound | SNMP polling to devices (`SNMP_PORT`) |
| `162` | UDP | inbound | SNMP trap receiver (`SNMP_TRAP_LISTEN`, default `0.0.0.0:162`) |
| `514` | UDP/TCP | inbound | syslog collector (when syslog ingest is enabled) |
| `6343` | UDP | inbound | sFlow collector (when flow ingest is enabled) |
| `5432` | TCP | outbound | PostgreSQL (`DB_PORT`; prod backend) |

Probes relay back to the server over the same HTTP(S) port (`8080`), so a remote
site only needs **outbound** reach to the server — no inbound ports at the site.

### Build

```bash
./deploy.sh build          # build all binaries into ./bin via the deploy script
# or, with the Makefile:
make build                 # reproducible build of the four fwmon-* binaries
```

### Test

```bash
go test ./...              # run the full test suite
make qa                    # the full pre-commit gate: tidy + gofmt + vet + build + test
make test-race             # run the suite under the race detector (needs CGO)
```

### Install Natively (without Docker)

```bash
sudo make install          # installs to /usr/local (override PREFIX=/opt/firewall-mon)
make tarball               # package dist/firewall-mon-<version>.tar.gz
```

### Deploy to Remote Server

```bash
./deploy.sh deploy -h your-server.com -u root -k ~/.ssh/id_rsa
```

### Install Locally

```bash
sudo ./deploy.sh install
sudo ./deploy.sh start
```

### Configuration

1. Copy `config.env.example` to `/etc/firewall-mon/config.env`
2. Update `SNMP_HOST` and SNMP community
3. Set strong admin credentials
4. Configure alert thresholds

**[`config.env.example`](config.env.example) is the authoritative reference for every setting** — it lists all ~70 variables with inline comments and defaults. The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `SERVER_HOST` / `SERVER_PORT` | `0.0.0.0` / `8080` | HTTP listen address |
| `SERVER_ENABLE_TLS` | `false` | Terminate TLS in-process (cert/key via `SERVER_TLS_CERT`/`_KEY`) |
| `JWT_SECRET_KEY` | _(auto-generated + persisted)_ | Signs login JWTs **and** derives the AES-256 key for stored secrets — leave empty to auto-persist to `<SECRETS_DIR>/.jwt-secret` |
| `ENCRYPTION_KEY` | _(derived from JWT secret)_ | Optional explicit key for encrypting device/probe secrets at rest |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / _(set me)_ | Initial admin login (a non-default username is strongly recommended) |
| `SNMP_HOST` / `SNMP_PORT` / `SNMP_COMMUNITY` | `192.168.1.1` / `161` / `public` | Default directly-polled device |
| `SNMP_POLL_INTERVAL` | `60s` | Poll cadence (keep ≥ 60s to avoid overloading devices) |
| `CPU_THRESHOLD` / `MEMORY_THRESHOLD` / `DISK_THRESHOLD` / `SESSION_THRESHOLD` | `80` / `80` / `90` / `100000` | Alert thresholds |
| `EMAIL_ENABLED` + `SMTP_*` | `false` | Email alerting + scheduled reports |
| `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` | _(empty)_ | Chat alerting |
| `DB_TYPE` / `DB_HOST` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `postgres` (prod) | Database connection (SQLite is used for tests) |
| `DB_MAX_OPEN_CONNS` | per-process (15/10/5) | Connection-pool ceiling per daemon |
| `RETENTION_*_DAYS` | varies | Per-table data retention (e.g. `RETENTION_SYSLOG_CRITICAL_DAYS`) |
| `PROBE_*` | _(empty)_ | Remote-probe identity/listeners (see the probe section of `config.env.example`) |
| `REPORT_*` | _(empty)_ | Scheduled-report recipients/cadence |
| `SERVER_READ_TIMEOUT` / `SERVER_WRITE_TIMEOUT` | `30s` / `30s` | HTTP server timeouts |

## SNMP OIDs Monitored

### System Status (FortiGate enterprise OIDs)
- CPU Usage (`1.3.6.1.4.1.12356.101.4.1.3`)
- Memory Usage (`1.3.6.1.4.1.12356.101.4.1.4`)
- Disk Usage (`1.3.6.1.4.1.12356.101.4.1.6`)
- Session Count (`1.3.6.1.4.1.12356.101.4.1.8`)
- Uptime (`1.3.6.1.4.1.12356.101.4.1.20`)

### Interface Statistics (RFC IF-MIB)
- Status, Speed, In/Out Bytes, Packets, Errors

### Hardware Sensors (via `fgHwSensorTable`)
- Temperature, Voltage, Power, Fans

### Traps Supported (FortiGate enterprise traps)
- VPN Tunnel Up/Down
- HA Failover
- IPS Signatures & Anomalies
- Antivirus Events

## Security

- JWT tokens with secure cookies
- Account lockout after 5 failed attempts
- CSRF protection
- Rate limiting (10 req/sec)
- Secure HTTP headers (HSTS, CSP, X-Frame-Options)
- TLS support

## API Endpoints

The server registers ~170 routes across four groups. The authoritative list is
the route table in [`cmd/api/main.go`](cmd/api/main.go); the grouped overview
below covers every category. Path bases: `api` → `/api`, public → `/api/public`,
admin → `/admin`.

### Public — no authentication (safe to expose on a wallboard)
- `GET /` — public GridStack dashboard
- `GET /api/health` — liveness/readiness check
- `GET /api/version` — build version (JSON)
- `GET /api/public/{dashboard,devices,interfaces,interfaces/chart,connections,vpn,status-history,display-settings}` — read-only status JSON behind the public dashboard
- `GET /security.txt`, `GET /.well-known/security.txt` — RFC 9116 contact; `GET /favicon.ico`

### Authentication
- `POST /api/auth/login` — obtain the JWT cookie
- `POST /admin/api/logout` — clear the session
- `GET /admin/api/csrf-token` — fetch the CSRF token for mutating requests

### Admin UI pages (HTML, auth-gated)
`GET /admin` and `/admin/{dashboard,devices,devices/:id,connections,connections/:id,sites,probes,probe-pending,interfaces,syslog,flows,traps,network,maintenance,reports,settings,irc,alerts,alert-policies}`

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

## Monitoring Intervals

Recommended intervals to avoid overloading devices:
- System stats: 60 seconds
- Interface stats: 60-120 seconds
- Hardware sensors: 300 seconds
- Full system walk: 300 seconds

## Browser Support

The admin panel and public dashboard target **evergreen browsers**. The baseline is set by the use of the CSS `:has()` selector and ES2020 JavaScript:

| Browser | Minimum version |
|---|---|
| Chrome / Edge (Chromium) | 105+ |
| Safari (macOS / iOS) | 15.4+ |
| Firefox | 121+ |

Older browsers may render the dashboard with degraded layout. There is no IE11 / legacy support, and none is planned.

## License

MIT — see [LICENSE](LICENSE). Third-party components and their licenses are inventoried in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Support & community

- **Bug reports & feature requests** → open a **GitHub Issue** on this
  repository. Include version (`GET /api/version`), platform, and relevant log
  lines (every server-side 500 is logged with an `X-Request-ID`).
- **Questions, setup help, "how do I…"** → use **GitHub Discussions** on this
  repository.
- **Security vulnerabilities** → do **not** open a public issue; follow
  [SECURITY.md](SECURITY.md) (also published at `/.well-known/security.txt`).

There is no dedicated chat server (Discord/Matrix/IRC) for the project — GitHub
Issues/Discussions are the support channels. Note that the built-in **IRC bot**
is a *monitoring feature* (it posts alerts and answers status queries in **your**
ops channel); it is not a support channel for this project.

## Contributing & docs

- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy.
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev environment, QA requirements, PR workflow.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1.
- [docs/AUDIT.md](docs/AUDIT.md) — public-release audit and progress log.
- [docs/custom-vendor.md](docs/custom-vendor.md) — step-by-step tutorial for adding a new SNMP vendor profile.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — operator runbook: first-24h checklist, failure modes, backup/restore, upgrade, password/JWT reset, DR.
