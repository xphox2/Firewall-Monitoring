# Data Retention & Data Flow Disclosure

This document describes what data the Firewall-Monitoring central server
stores, how long it keeps it, and how an operator can honor data-subject
requests (GDPR Art. 15-17, CCPA §1798.100-1798.130).

> Every fact below is grounded in the code: retention knobs are the
> `RETENTION_*` env vars in `internal/config/config.go`, applied by
> `CleanupOldData` in `internal/database/cleanup.go`. The deployment is
> **single-tenant** — there is no `tenant_id` partitioning of data.

## How retention works

A background cleanup cycle deletes rows older than a per-table cutoff. The
cutoff is resolved by `RetentionConfig.Days(perType)`:

- A **positive** `RETENTION_<TABLE>_DAYS` value is used as-is.
- **`0` or unset** falls back to **`RETENTION_DEFAULT_DAYS`** (default **90**).
- **Status-table exception (v0.11.24):** the per-poll status tables
  `vpn_status`/`ha_status`/`security_stats`/`sdwan_health` fall back to
  **`RETENTION_STATUS_DAYS`** (the knob their chart siblings
  `system_status`/`interface_stats` use), not directly to the default.
- **One exception:** `RETENTION_SYSLOG_CRITICAL_DAYS` — here **`0` means keep
  forever** (severity 0-5 syslog is never auto-deleted unless you set a
  positive value). This is the historical cause of `syslog_messages` bloat;
  set it to e.g. `30` in production.

High-volume time-series tables are monthly range-partitioned (AUDIT-028/146),
so cleanup drops whole old partitions where it can (instant space reclaim) and
falls back to batched `DELETE` for the straddling tail. Since v0.11.24 this
partition-drop fast path also applies to `syslog_messages`: a monthly
partition whose entire range is older than **both** syslog windows (the max
of the critical and informational retention) is dropped wholesale; if any
severity class is kept forever (`RETENTION_SYSLOG_CRITICAL_DAYS=0`), syslog
partitions are never dropped and only the severity-scoped deletes run.

## Retention by table

| Data | Table | Knob | Default | Contains PII? |
|---|---|---|---|---|
| System status (CPU/mem/disk/sessions) | `system_status` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Interface counters | `interface_stats` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Interface addresses | `interface_addresses` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Hardware sensors (temp/fan/voltage) | `hardware_sensors` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| VPN tunnel status | `vpn_status` | `RETENTION_VPN_STATUS_DAYS` | 0 → `RETENTION_STATUS_DAYS` (0 → 90) | Tunnel names + remote gateway IPs may identify sites/partners |
| HA cluster status | `ha_status` | `RETENTION_HA_STATUS_DAYS` | 0 → `RETENTION_STATUS_DAYS` (0 → 90) | No |
| Security/UTM counters | `security_stats` | `RETENTION_SECURITY_STATS_DAYS` | 0 → `RETENTION_STATUS_DAYS` (0 → 90) | No |
| SD-WAN health | `sdwan_health` | `RETENTION_SDWAN_HEALTH_DAYS` | 0 → `RETENTION_STATUS_DAYS` (0 → 90) | No |
| License/support expiry snapshots | `license_info` | `RETENTION_LICENSE_INFO_DAYS` | 365 | No |
| Processor stats | `processor_stats` | `RETENTION_PROCESSOR_STATS_DAYS` | 30 | No |
| Process stats (SSH top-N) | `process_stats` | `RETENTION_PROCESS_STATS_DAYS` | 30 | Process names may reflect customer workloads |
| Interface errors/discards | `interface_errors` | `RETENTION_INTERFACE_ERRORS_DAYS` | 30 | No |
| Flow records — sFlow **and, since v0.11.20, NetFlow v5/v9 + IPFIX** (5-tuple, counts; incl. unsampled ASA NSEL denied-flow events; origin labeled by `flow_source`) | `flow_samples` | `RETENTION_FLOW_DAYS` | 365 | **Yes** — src/dst IPs are PII in some jurisdictions |
| Flow rollups (per-conversation 5m/1h/1d aggregates; since v0.11.26 also carry the allow/deny `firewall_event`) | `flow_rollups` | `RETENTION_FLOW_ROLLUP_DAYS` | 365 | **Yes** — src/dst IP conversation pairs are kept a full year by default |
| Flow detections (detection-engine findings; ages on `detected_at`) | `flow_detections` | `RETENTION_FLOW_DETECTION_DAYS` | 90 | **Yes** — flagged src/dst IPs + detection message |
| Flow interface counters | `flow_if_counters` | `RETENTION_FLOW_DAYS` | 365 | No |
| Flow agent sample-drop windows (ages on `window_start`) | `flow_agent_drops` | `RETENTION_AGENT_DROPS_DAYS` | 30 | No |
| SNMP traps | `trap_events` | `RETENTION_TRAP_DAYS` | 0 → 90 | Source IP may identify a site |
| Ping results | `ping_results` | `RETENTION_PING_DAYS` | 0 → 90 | No |
| Syslog (severity 6-7, info) | `syslog_messages` | `RETENTION_SYSLOG_INFO_DAYS` | 7 | **Yes** — usernames, URLs, auth events |
| Syslog (severity 0-5, critical) | `syslog_messages` | `RETENTION_SYSLOG_CRITICAL_DAYS` | **0 = forever** | **Yes** — set a positive value in prod |
| Syslog summaries | `syslog_summaries` | `RETENTION_SYSLOG_INFO_DAYS` | 7 | Aggregated, low PII |
| Acknowledged alerts | `alerts` | `RETENTION_ALERT_DAYS` | 0 → 90 | No |
| Unacknowledged alerts | `alerts` | `RETENTION_UNACK_ALERT_DAYS` | 90 | No |
| **Resolved** incidents (ages on `resolved_at`; open incidents are never auto-deleted) | `incidents` | `RETENTION_INCIDENT_DAYS` | 0 → 90 | No |
| IRC bot message log | `irc_message_logs` | `RETENTION_IRC_MESSAGE_LOG_DAYS` | 7 | Operator's own ops-channel chatter |
| Login attempts | `login_attempts` | `RETENTION_DEFAULT_DAYS` | 90 | Username + client IP |
| Batch idempotency keys | `processed_batches` | (fixed) | 2 | No |

### Tables that are NOT auto-pruned

- **`config_revisions`** — firewall config-backup history is kept **forever by
  design** (each new revision is appended; old revisions are never deleted).
  **PII/secrets:** FortiOS configs backed up *without* the "mask sensitive
  fields" option can contain `set password`/PSK material; the collector tags
  masked revisions `backup_quality: "masked"`. Treat this table as sensitive.
- **`audit_logs`** — the admin-action trail (AUDIT-078) is intentionally
  append-only and not auto-pruned (very low volume).
- **Open `incidents`** — an incident row is live state until the device
  recovers (or the device is deleted, which closes its open incidents); only
  **resolved** incidents age out per the table above.
- **`uptime_records`** — reboot/uptime history; low-volume (rows accrue per
  device state change, not per poll) and not auto-pruned.
- **`threat_intel`** — not touched by `CleanupOldData`, but the poller prunes
  feed-sourced rows whose TTL has expired (`PruneExpiredThreatIntel`,
  `THREAT_FEEDS_TTL_DAYS`); manually added entries with no expiry are kept
  forever. Contains third-party-reported bad IPs, not subject telemetry.
- **Bounded upsert tables** — `ping_stats` (one running aggregate row per
  device+target) and `probe_heartbeats` (one row per probe, overwritten on
  each heartbeat) never grow with time and need no pruning.
- **Inventory/configuration state** — `devices`, `sites`, `probes`,
  `device_connections`, `device_tunnels`, admin users/API tokens, alert
  policies/rules, maintenance windows, IRC server/channel config, and
  settings are durable records managed through the UI/API, not time-series;
  they are never auto-deleted.

## Data residency

- All data lives in the database configured by the `DB_*` env vars
  (`DB_TYPE`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`,
  `DB_SSL_MODE`). Production is **PostgreSQL**; the test backend is SQLite.
- For multi-region needs, run one server per region — there is no built-in
  geo-sharding.
- **Encryption at rest** is the operator's responsibility: enable
  filesystem/volume encryption (LUKS, AWS EBS encryption, etc.) on the DB host.

## Data-subject rights

> **Honest scope:** the server does **not** ship a one-click subject-export
> or per-subject erasure endpoint. The mechanisms below are what exists today.

- **Erasure (Art. 17):** `DELETE /api/probes/:id` removes the **probe row
  only** — it does **not** cascade to that probe's device/telemetry rows.
  Removing the associated time-series and config data is a manual operation
  against the database (delete by `device_id` / `probe_id`), or you wait for
  the retention windows above to age the data out.
- **Access / portability (Art. 15/20):** export the relevant rows directly
  from the database (e.g. `pg_dump --table=... ` or a scoped `COPY ... TO`).
- **Rectification (Art. 16):** not generally applicable to telemetry; device
  labels are editable via the admin UI.

## What the server does NOT collect

- No packet captures, no decrypted traffic, no application payloads, no DNS
  query names, no certificate private keys.
- It does not exfiltrate data to any third party — see below.

## Outbound connections / third-party processors

Every outbound destination is **opt-in**: nothing below is contacted unless
the operator sets the named configuration. The full list (verified against
`internal/notifier`, `internal/irc`, `internal/threatfeed`, and
`internal/tracing` — see also [PRIVACY.md](../PRIVACY.md)):

**Alert / report delivery** — payloads contain alert type, message, severity,
metric name, threshold, current value, and the device ID (device names and
IPs appear inside the message text); scheduled reports contain the report's
device/traffic summaries.

- **SMTP email** (`EMAIL_ENABLED` + `SMTP_*`) — alerts and scheduled reports
  to the operator's own mail relay.
- **Slack webhook** (`SLACK_WEBHOOK_URL`) — to the operator-configured Slack
  incoming-webhook URL (Slack, a third-party SaaS).
- **Discord webhook** (`DISCORD_WEBHOOK_URL`) — to the operator-configured
  Discord webhook URL (Discord, a third-party SaaS).
- **Microsoft Teams webhook** (`TEAMS_WEBHOOK_URL`, v0.11.7) — to the
  operator's Teams tenant incoming-webhook URL (Microsoft, a third-party
  SaaS).
- **PagerDuty Events API v2** (`PAGERDUTY_ROUTING_KEY`, v0.11.7) — alert
  trigger/resolve events to the **hardcoded** endpoint
  `https://events.pagerduty.com/v2/enqueue` (PagerDuty, a third-party SaaS).
- **Opsgenie Alerts API** (`OPSGENIE_API_KEY`, v0.11.7) — alert
  create/close calls to the **hardcoded** endpoint
  `https://api.opsgenie.com/v2/alerts` (Atlassian Opsgenie, a third-party
  SaaS).
- **Generic webhook** (`WEBHOOK_URL`, optional HMAC signing via
  `WEBHOOK_SECRET`) — JSON alert payloads to any operator-chosen URL.
- **IRC bot** (configured in the admin UI) — alert lines to the operator's
  own IRC server/ops channel.

Webhook deliveries go through an SSRF-guarded HTTP client, and the settings
pages' "Test" buttons dial the same destinations as live delivery.

**Monitoring of the operator's own devices** (not third parties): SNMP
polling and ICMP ping to the monitored firewalls. (SSH-based capture —
process top-N, config backup — is performed by the remote collector, a
separate binary on the operator's own network, which pushes the results in.)

**Opt-in external fetches / exports:**

- **Threat-intelligence feeds** (`THREAT_FEEDS_ENABLED`, default off,
  v0.10.514) — outbound HTTPS `GET`s to public blocklist URLs (blocklist.de,
  CINS, Spamhaus DROP, Emerging Threats, Tor exit list, plus any
  `THREAT_FEEDS_EXTRA_URLS`). Only the HTTP request itself leaves the server
  (no monitoring data is sent); IP lists are downloaded into `threat_intel`.
- **OpenTelemetry tracing** (`OTEL_TRACES_ENABLED`, default off) — request
  spans (routes, timings, trace IDs — no packet or syslog payloads) exported
  over OTLP/HTTP to the operator-configured `OTEL_EXPORTER_OTLP_ENDPOINT`.

There is **no** third-party analytics, error-tracking, or telemetry service in
the data path, and no automatic update checks or phone-home.

## Breach response

1. Rotate probe registration keys (`POST /api/probes/:id/regenerate-key`) — the
   probes re-register and pick up the replacement.
2. If a server credential or TLS key is involved, rotate it (see
   `docs/CERT-ROTATION.md`).
3. Notify affected parties per your obligations (GDPR Art. 33: 72 hours).
4. Review `audit_logs` and `login_attempts` for the compromise window.

## Tuning guidance

The defaults balance disk against forensic value. For high-volume deployments,
the biggest wins are: set `RETENTION_SYSLOG_CRITICAL_DAYS` to a finite value
(e.g. `30`), and lower `RETENTION_FLOW_DAYS` (e.g. `30`) — `flow_samples` and
`syslog_messages` dominate database size. Privacy-minded deployments should
also consider lowering `RETENTION_FLOW_ROLLUP_DAYS` (default 365): rollups
retain per-conversation src/dst IP pairs for a full year even after the raw
`flow_samples` rows have aged out.
