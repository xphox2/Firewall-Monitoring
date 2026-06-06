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

## Quick Start

### Prerequisites

- Go 1.21+
- Linux server (tested on Ubuntu/Debian)
- SNMP-enabled firewall device

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

### Public
- `GET /` - Public dashboard
- `GET /api/public/dashboard` - System status JSON
- `GET /api/public/interfaces` - Interface stats JSON
- `GET /api/health` - Health check

### Admin (Protected)
- `GET /admin` - Admin dashboard
- `POST /api/auth/login` - Login
- `POST /admin/api/logout` - Logout
- `GET /admin/api/dashboard` - Full dashboard data
- `GET /admin/api/devices` - Device management
- `GET /admin/api/alerts` - Alert history
- `GET /admin/api/uptime` - Uptime stats
- `POST /admin/api/uptime/reset` - Reset uptime tracking

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

## Contributing & community

- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy.
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev environment, QA requirements, PR workflow.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1.
- [docs/AUDIT.md](docs/AUDIT.md) — public-release audit and progress log.
