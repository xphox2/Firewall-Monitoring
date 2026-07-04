# Architecture

How Firewall-Mon's processes, data stores, and external systems fit together
(AUDIT-108). For per-component code layout see the tree in the
[README](../README.md#architecture); for operations see
[OPERATIONS.md](OPERATIONS.md).

## Components & data flow

Three long-running server daemons (`fwmon-api`, `fwmon-poller`, `fwmon-trap`)
share one database; `configcheck` is a one-shot CLI, not a daemon. Firewalls are
monitored **directly** (the central poller polls them over SNMP) or **remotely**
(a probe at the site polls them and relays the data back).

```mermaid
flowchart TB
    subgraph firewalls["Firewalls (FortiGate / Palo Alto / Cisco ASA / generic)"]
        FW["SNMP agent · traps · syslog · sFlow · NetFlow/IPFIX"]
    end

    subgraph site["Remote site"]
        PROBE["firewall-collector<br/>(sibling repo)"]
    end

    subgraph server["Central server (single container)"]
        API["fwmon-api<br/>(Gin: admin + public + ingestion)"]
        POLLER["fwmon-poller<br/>(SNMP poll loop)"]
        TRAP["fwmon-trap<br/>(SNMP trap receiver)"]
        DB[("PostgreSQL 16")]
        IRC["IRC bot(s)"]
        NOTIF["notifier<br/>(email / Slack / Discord / webhook)"]
    end

    USERS["Operators (admin panel)"]
    WALL["Public wallboard"]

    FW -- "SNMP poll" --> POLLER
    FW -- "SNMP traps" --> TRAP
    FW -- "SNMP / syslog / sFlow / NetFlow / IPFIX / ICMP" --> PROBE
    PROBE -- "HTTPS relay (X-Probe-Batch-ID)" --> API

    POLLER --> DB
    TRAP --> DB
    API --> DB
    POLLER -- "threshold breach" --> NOTIF
    API --> IRC
    NOTIF -- "alerts" --> USERS
    API --> USERS
    API --> WALL

    POLLER -. "pg advisory lock<br/>(single leader)" .-> DB
```

**Notes**
- The three server daemons (`api`, `poller`, `trap`) are separate processes
  sharing the DB; in the Docker image they run side-by-side under one
  entrypoint with PostgreSQL embedded.
- The **poller** owns directly-polled devices and fires offline/threshold
  alerts; **probe** devices are polled at the edge and the poller drives their
  offline alerting from relayed freshness (v0.10.323).
- Only one poller does migration/cleanup work at a time, gated by a Postgres
  advisory lock (AUDIT-007).
- Secrets (SNMP/IRC/SMTP) are encrypted at rest with an AES-256 key derived
  from the persisted JWT secret (AUDIT-008); probe registration keys are hashed
  (AUDIT-017).

## Sequence: probe registration

```mermaid
sequenceDiagram
    participant P as firewall-collector
    participant A as fwmon-api
    participant D as PostgreSQL
    participant Op as Operator

    P->>A: POST /api/probes/register (name, site, registration key)
    A->>D: store probe (key hashed), status = pending
    A-->>P: 202 pending approval
    Op->>A: approve probe (admin panel)
    A->>D: status = approved
    loop every sync interval
        P->>A: relay batch (system-status / interfaces / syslog / traps / flows / pings)
        Note over P,A: X-Probe-Batch-ID makes retries idempotent (AUDIT-042)
        A->>D: upsert / insert (dedup by batch id)
        A-->>P: 2xx
    end
```

## Sequence: poll cycle (directly-polled device)

```mermaid
sequenceDiagram
    participant Po as fwmon-poller
    participant FW as Firewall (SNMP)
    participant D as PostgreSQL
    participant N as notifier

    loop every SNMP_POLL_INTERVAL (default 60s)
        Po->>FW: GET system OIDs (vendor profile)
        FW-->>Po: CPU / mem / disk / sessions / uptime
        Po->>FW: WALK interfaces / VPN / HA / sensors
        FW-->>Po: rows
        Po->>D: insert time-series + update last_polled
        alt threshold breached or device unreachable
            Po->>N: send alert (with cooldown/dedup)
            N-->>N: email / Slack / Discord / webhook
        end
    end
```

## Sequence: alert firing & recovery

```mermaid
sequenceDiagram
    participant Src as Poller / trap / syslog
    participant AM as AlertManager (in poller)
    participant N as notifier
    participant IRC as IRC bot

    Src->>AM: signal (offline / threshold / trap severity)
    AM->>AM: dedup + cooldown + maintenance-window check
    alt new alert
        AM->>N: critical alert (email + chat)
        AM->>IRC: post to channel
    end
    Note over AM: recovery clears only an active alert, once
    Src->>AM: device healthy again
    AM->>N: recovery notice (no-op if no active alert)
```

## Where things live (quick map)

| Concern | Package / path |
|---|---|
| HTTP handlers (admin / public / ingestion) | `internal/api/handlers/` |
| Security middleware (CSP, CSRF, rate limit, headers) | `internal/api/middleware/` |
| SNMP client + vendor profiles | `internal/snmp/` (`vendor_*.go`) |
| Database access + migrations | `internal/database/` |
| Alert thresholds + state machine | `internal/alerts/` |
| Notifications | `internal/notifier/` |
| Probe wire contract (DTOs + schema version) | `internal/relay/` |
| Config-backup change detection | `internal/configdiff/` |
| Persisted secrets (JWT / admin) | `internal/secrets/` |
| Frontend (admin SPA + wallboard) | `cmd/api/static/`, `web/` |
