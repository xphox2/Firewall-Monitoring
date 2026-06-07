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
- **One exception:** `RETENTION_SYSLOG_CRITICAL_DAYS` — here **`0` means keep
  forever** (severity 0-5 syslog is never auto-deleted unless you set a
  positive value). This is the historical cause of `syslog_messages` bloat;
  set it to e.g. `30` in production.

High-volume time-series tables are monthly range-partitioned (AUDIT-028/146),
so cleanup drops whole old partitions where it can (instant space reclaim) and
falls back to batched `DELETE` for the straddling tail.

## Retention by table

| Data | Table | Knob | Default | Contains PII? |
|---|---|---|---|---|
| System status (CPU/mem/disk/sessions) | `system_status` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Interface counters | `interface_stats` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Interface addresses | `interface_addresses` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Hardware sensors (temp/fan/voltage) | `hardware_sensors` | `RETENTION_STATUS_DAYS` | 0 → 90 | No |
| Processor stats | `processor_stats` | `RETENTION_PROCESSOR_STATS_DAYS` | 30 | No |
| Process stats (SSH top-N) | `process_stats` | `RETENTION_PROCESS_STATS_DAYS` | 30 | Process names may reflect customer workloads |
| Interface errors/discards | `interface_errors` | `RETENTION_INTERFACE_ERRORS_DAYS` | 30 | No |
| sFlow samples (5-tuple, counts) | `flow_samples` | `RETENTION_FLOW_DAYS` | 365 | **Yes** — src/dst IPs are PII in some jurisdictions |
| SNMP traps | `trap_events` | `RETENTION_TRAP_DAYS` | 0 → 90 | Source IP may identify a site |
| Ping results | `ping_results` | `RETENTION_PING_DAYS` | 0 → 90 | No |
| Syslog (severity 6-7, info) | `syslog_messages` | `RETENTION_SYSLOG_INFO_DAYS` | 7 | **Yes** — usernames, URLs, auth events |
| Syslog (severity 0-5, critical) | `syslog_messages` | `RETENTION_SYSLOG_CRITICAL_DAYS` | **0 = forever** | **Yes** — set a positive value in prod |
| Syslog summaries | `syslog_summaries` | `RETENTION_SYSLOG_INFO_DAYS` | 7 | Aggregated, low PII |
| Acknowledged alerts | `alerts` | `RETENTION_ALERT_DAYS` | 0 → 90 | No |
| Unacknowledged alerts | `alerts` | `RETENTION_UNACK_ALERT_DAYS` | 90 | No |
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

The server makes outbound network calls **only** for:

- **Alert delivery** the operator configures: SMTP email, Slack/Discord
  webhooks, and the built-in IRC bot.
- **SNMP polling** of the monitored devices (the poller binary).

There is **no** third-party analytics, error-tracking, or telemetry service in
the data path.

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
`syslog_messages` dominate database size.
