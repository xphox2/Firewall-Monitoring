# Data Retention & Data Flow Disclosure

This document describes what data the Firewall-Monitoring central server
collects from remote probes, how long it's stored, and what data-subject
rights (GDPR Art. 15-17, CCPA §1798.100-1798.130) operators can honor.

## Data flow (probe → server)

| Source | Type | Default retention | Configurable | Contains PII? |
|---|---|---|---|---|
| `SystemStatus` (every 60s) | CPU, mem, disk, sessions, uptime | 30 days | `PROBE_STATUS_RETENTION_DAYS` | No |
| `InterfaceStats` (every 60s) | Bytes/err/discards per iface | 30 days | `PROBE_STATS_RETENTION_DAYS` | No |
| `ProcessTop` (every 15 min, SSH) | Top-N processes by CPU/mem | 7 days | `PROBE_PROC_RETENTION_DAYS` | Process names may contain customer data |
| `HardwareSensors` (every 5 min) | Temp/fan/voltage | 30 days | `PROBE_SENSOR_RETENTION_DAYS` | No |
| `VPNStatus` (every 5 min) | Phase1/Phase2 tunnels | 90 days | `PROBE_VPN_RETENTION_DAYS` | No (tunnel IDs are opaque) |
| `LicenseDetails` (every 24h) | AV/IPS/Web-filter version, expiry | Forever (license expiry is the trigger) | — | No |
| `ConfigRevision` (per backup event) | Full firewall config text | **Forever** (each new revision is appended; old revisions are never deleted) | `PROBE_CONFIG_RETENTION_COUNT` (default: keep all) | **Yes** — FortiOS pre-7.2.1 configs may contain `set password <plaintext>` for LDAP/RADIUS bind passwords, IPSec PSKs, and admin recovery passwords. FortiOS 7.2.1+ with the "mask sensitive fields" backup option marks these as `*******` and the probe tags the revision as `backup_quality: "masked"`. |
| `TrapEvent` (per received trap) | Type, severity, source IP, varbinds | 90 days | `PROBE_TRAP_RETENTION_DAYS` | Source IP may identify customer location |
| `SyslogMessage` (per received line) | RFC 5424 parsed fields + raw | 30 days | `PROBE_SYSLOG_RETENTION_DAYS` | **Yes** — syslog lines commonly contain usernames, blocked URLs, and authentication events. |
| `FlowSample` (per sFlow sample) | 5-tuple, packet/byte counts | 7 days | `PROBE_FLOW_RETENTION_DAYS` | Source/dest IPs are PII in some jurisdictions |
| `PingResult` (every 60s) | Latency, packet loss | 7 days | `PROBE_PING_RETENTION_DAYS` | No |
| `Heartbeat` (every 60s) | Online/offline status | 7 days | `PROBE_HEARTBEAT_RETENTION_DAYS` | No |

## Data residency

- The server stores all data in the database configured by `PROBE_DATABASE_URL`
  (default: SQLite at `/var/lib/firewall-mon/firewall.db`).
- For multi-region deployments, deploy a server per region and use
  the regional `PROBE_SERVER_URL` (`https://stats-eu.example.com`,
  `https://stats-us.example.com`).
- Backups are written to `PROBE_BACKUP_PATH` (default: same directory as the DB).
  Encryption-at-rest is the operator's responsibility — set up filesystem-level
  encryption (LUKS, eCryptfs, AWS EBS encryption, etc.) on the host.

## Data subject rights

- **Right of access (GDPR Art. 15)**: a probe's data is tied to a single
  `probe_id` (UUID) and a single `tenant_id` (UUID). The admin can
  export a probe's data via the `/api/probes/:id/export` endpoint
  (returns tarball of all `*Revision` and `*Message` records).
- **Right of erasure (GDPR Art. 17)**: the admin can delete a probe via
  `/api/probes/:id` (DELETE), which cascades to all child tables.
  Hard-deletes are not reversible; soft-deletes (audit-trail-preserving)
  are a planned follow-up.
- **Right of portability (GDPR Art. 20)**: same as access; tarball export.
- **Right to rectification (GDPR Art. 16)**: not directly applicable to
  telemetry data; operators can edit device labels via the admin UI.

## What is NOT in the data flow

- The probe does NOT collect: packet captures, application-layer payload,
  decrypted traffic, DNS query names, certificate private keys,
  firewall admin sessions.
- The probe does NOT exfiltrate customer data to anywhere other than the
  configured `PROBE_SERVER_URL`.

## Breach notification

In the event of a confirmed data breach, the server admin should:
1. Rotate all probe tokens (the server can issue replacements; the probes
   will pick them up on the next reregister).
2. Notify affected tenants within 72 hours per GDPR Art. 33.
3. File a CVE and post to the project's security advisory page if the
   breach is in the server's own code.

## Third-party processors

The server does not call out to any third-party analytics, error tracking,
or telemetry service. The only outbound HTTP calls from the server are:
- Outbound alert delivery (email via SMTP, Slack/Discord webhooks) —
  configured by the operator.
- Outbound IP-info enrichment (optional, for the topology map) —
  disabled by default.

## Configuration reference

| Env var | Default | Purpose |
|---|---|---|
| `PROBE_STATUS_RETENTION_DAYS` | 30 | SystemStatus, InterfaceStats, HardwareSensors, LicenseDetails |
| `PROBE_VPN_RETENTION_DAYS` | 90 | VPNStatus |
| `PROBE_TRAP_RETENTION_DAYS` | 90 | TrapEvent |
| `PROBE_SYSLOG_RETENTION_DAYS` | 30 | SyslogMessage |
| `PROBE_FLOW_RETENTION_DAYS` | 7 | FlowSample |
| `PROBE_PING_RETENTION_DAYS` | 7 | PingResult |
| `PROBE_HEARTBEAT_RETENTION_DAYS` | 7 | Heartbeat |
| `PROBE_PROC_RETENTION_DAYS` | 7 | ProcessTop (SSH) |
| `PROBE_CONFIG_RETENTION_COUNT` | 0 (keep all) | ConfigRevision max rows per device; 0 = unlimited |
| `PROBE_CONFIG_DELETE_AFTER` | 0 (never) | Auto-delete ConfigRevision older than N days; 0 = disable |

Tuning the retention values is a balance between disk usage and forensic
value. Recommended starting points are the defaults above. For
high-volume deployments (1000+ devices), reduce `PROBE_FLOW_RETENTION_DAYS`
to 3 and `PROBE_SYSLOG_RETENTION_DAYS` to 14.
