# Firewall Monitor

A comprehensive firewall monitoring system with SNMP polling, trap reception, alerting, and uptime tracking.

## Features

- **Public Dashboard**: Display firewall status without authentication
- **Secure Admin Panel**: Protected by JWT authentication with rate limiting
- **SNMP Polling**: Comprehensive monitoring with configurable intervals (default 60s to avoid firewall overload)
- **SNMP Trap Receiver**: Listen for FortiGate traps and generate alerts
- **Alerting System**: Email, Slack, Discord, and webhook notifications
- **Uptime Tracking**: 99.99999% (five nines) uptime calculation
- **Secure**: CSRF protection, secure headers, rate limiting, account lockout

## Architecture

```
fortiGate-Mon/
├── cmd/
│   ├── api/          # Main API server (Gin web server)
│   ├── poller/       # SNMP polling daemon
│   └── trap-receiver/ # SNMP trap listener
├── internal/
│   ├── config/      # Configuration management
│   ├── auth/        # JWT authentication & security
│   ├── snmp/        # SNMP client & trap receiver
│   ├── alerts/      # Alert threshold checking
│   ├── notifier/    # Email/webhook notifications
│   ├── uptime/      # Uptime calculation
│   ├── models/      # Data structures
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
- FortiGate with SNMP enabled

### Build

```bash
./deploy.sh build
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

1. Copy `config.env.example` to `/etc/fortigate-mon/config.env`
2. Update the FortiGate host and SNMP community
3. Set strong admin credentials
4. Configure alert thresholds

## SNMP OIDs Monitored

### System Status
- CPU Usage (`1.3.6.1.4.1.12356.101.4.1.3`)
- Memory Usage (`1.3.6.1.4.1.12356.101.4.1.4`)
- Disk Usage (`1.3.6.1.4.1.12356.101.4.1.6`)
- Session Count (`1.3.6.1.4.1.12356.101.4.1.8`)
- Uptime (`1.3.6.1.4.1.12356.101.4.1.20`)

### Interface Statistics (RFC IF-MIB)
- Status, Speed, In/Out Bytes, Packets, Errors

### Hardware Sensors (via `fgHwSensorTable`)
- Temperature, Voltage, Power, Fans

### Traps Supported
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
- `POST /api/auth/logout` - Logout
- `GET /admin/api/dashboard` - Full dashboard data
- `GET /admin/api/alerts` - Alert history
- `GET /admin/api/uptime` - Uptime stats
- `POST /admin/api/uptime/reset` - Reset uptime tracking

## Monitoring Intervals

To avoid overloading the FortiGate:
- System stats: 60 seconds
- Interface stats: 60-120 seconds  
- Hardware sensors: 300 seconds
- Full system walk: 300 seconds

## License

MIT
