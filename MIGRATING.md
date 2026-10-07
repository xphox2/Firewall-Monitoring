# Probe ↔ Server Wire-Format Compatibility

> **Audience:** operators upgrading either side of a probe/server pair —
> the `fwmon-api` server in this repo (`xphox2/Firewall-Monitoring`) and the
> `firewall-collector` probe binary (`xphox2/Firewall-Collector`).
>
> **Source of truth for the supported range:** the exported
> `relay.SchemaVersionMin` / `relay.SchemaVersionMax` consts in
> `internal/relay/relay.go`. This file is the human-readable mirror, and
> `docs/SUPPORT-MATRIX.md` holds the per-version compatibility table.
>
> **Source of truth for the telemetry wire shapes:** the server-side receiver
> types in `internal/models` (e.g. `models.FlowSample`, bound in
> `internal/api/handlers/handlers_data.go`) and the sender types in the
> Firewall-Collector repo's `internal/relay` package. `internal/relay` in
> *this* repo holds only the schema-version consts above and the v4
> command-channel DTOs — it is not the wire-shape reference.

## Why this doc exists

The collector probe and the central server communicate via a set of
hand-maintained JSON DTOs — the server-side receiver shapes live in
`internal/models` (bound in `internal/api/handlers/handlers_data.go`) and the
sender shapes in the Firewall-Collector repo's `internal/relay` package — over
the `/api/probes/...` REST endpoints. The
two binaries are deployed and upgraded **independently**, so a server-side
change that adds a required field, shifts a field's semantics, or removes an
endpoint could break a deployed collector with no graceful signal.

The first guard against that is the **`schema_version` field on the
`POST /api/probes/register` handshake**. This doc tells you which collector
versions can talk to which server versions, and what to do when a
**426 (Upgrade Required)** shows up in your probe logs.

## What the version number means

`schema_version` is the **probe↔server relay wire-format version**, exchanged
in the `POST /api/probes/register` request and response bodies. It is **not**
the semantic version of either binary; it is a small integer bumped in
lockstep with this file whenever the relay handshake changes shape. The
current maximum is **`6`**; v1 through v5 remain fully supported.

When a probe registers it sends its `schema_version`. The server validates it
against `[relay.SchemaVersionMin, relay.SchemaVersionMax]` (currently `1`-`6`)
and, since server v0.11.75, **persists the selected version on the probe row**
(`probes.schema_version`) — version-gated downstream features key off the
stored value. Three outcomes:

| Probe sends | Server response | What happens next |
|---|---|---|
| `schema_version` absent | 200 OK, treated as v1 | The probe registers as before (pre-handshake collectors). |
| `schema_version: 1`–`6` | 200 OK, selected version echoed + persisted | The probe registers normally. |
| anything outside `1-6` | **426 Upgrade Required**, header `X-Probe-Schema-Version-Supported: 1-6` | The probe refuses to register. The body names the rejected version and points here. |

Version history:

- **v1** — the original relay format (pre-handshake collectors default here).
- **v2** — sFlow interface counter samples (`/api/probes/:id/flow-counters`).
- **v3** — `disk_usage` + `load_average` telemetry endpoints.
- **v4** — the **server→collector command channel**: the heartbeat response
  carries `pending_commands` and the collector reports outcomes to
  `POST /api/probes/:id/command-result`. This is the FIRST schema version
  where data flows **down** the relay beyond device sync — command payloads
  are encrypted at rest on the server and may later carry credentials, so the
  relay **must** run over HTTPS. The server only attaches `pending_commands`
  for probes whose **registered** `schema_version` is ≥ 4; a v3 collector
  never sees the field, and a v4 collector against a v3 server gates its
  result sends the same way.
- **v5** — **L2 topology snapshots** for the port-to-port connection map:
  ARP + MAC-table (FDB) rows to `POST /api/probes/:id/topology-entries` and
  LLDP/CDP neighbor rows to `POST /api/probes/:id/topology-neighbors`. These
  are STATE snapshots — the server REPLACES a device's rows per
  (device, entry_type/protocol) scope on every batch — so the collector never
  spools them (a replayed old snapshot would revert newer state) and gates
  both sends on a negotiated ≥ 5.
- **v6** — the **syslog framing contract** (server 0.11.296, collector
  1.3.50): no new endpoint or payload. A v6 collector guarantees the `format`
  hint on every syslog row and correct RFC 3164 / RFC 5424 / Meraki header
  columns, so the server normalizes its rows without the re-framing fallback
  it still applies to v5 rows. Deploy the server first; a 1.3.50 collector
  against an older server renegotiates down to v5. `SchemaVersionMin` stays
  at 1 — dropping the fallback is a later transition release. The skip is
  per row, gated on the row carrying the `format` hint: a collector upgraded
  straight from < 1.3.48 to 1.3.50 replays a spool its old parser framed
  positionally (no hint), and those rows are still re-framed under the v6
  registration.

The consts in `internal/relay/relay.go` are the single source of truth —
shipping a future version only requires bumping `SchemaVersionMax` there and
adding a row to `docs/SUPPORT-MATRIX.md`.

## Server support

`schema_version` validation on `/api/probes/register` landed in server
**v0.10.382**. Older servers don't read the field at all: a probe that sends
`schema_version` against a pre-v0.10.382 server is accepted (the unknown JSON
field is ignored by Go's `encoding/json`), so advertising it is always
backward-safe.

## Upgrade rollout order

The happy-path rolling upgrade is **server first, then probe**:

1. **Stage the new server.** Build the new `fwmon-api`, run it through
   staging, deploy to prod. Existing probes are unaffected — the new server
   treats an absent `schema_version` as v1.
2. **Watch the logs.** Confirm the new server is happy with the current
   probes (no 426s; register + heartbeat + ingestion all working).
3. **Roll the probes.** Update the collector on the remote sites. Each probe
   registers with the new server, gets its selected `schema_version` echoed
   back, and proceeds.

If you do the **wrong** order (a probe whose `schema_version` is newer than
the server supports) you will see exactly one class of error: the probe gets a
426, logs `Probe schema_version N not supported (server supports 1-6)`, and
its register fails. Roll the server forward (or the probe back) and the probe
registers. There is **no data loss** — the probe keeps unsent data in its
on-disk queue until the server can accept it again.

## Database migration pre-flight: server 0.11.298 (migration v74)

v74 adds `syslog_messages.format` (`smallint`, nullable, no default, no
index). On PostgreSQL 11+ that is a catalog change only — no table rewrite on
a plain heap or a partitioned parent — but it needs a brief ACCESS EXCLUSIVE
lock on `syslog_messages` (and on every leaf when partitioned). While the
ALTER waits for that lock, every syslog insert waits behind it, so each
attempt is capped at 2 s (`lock_timeout` and `statement_timeout`) and retried
every 5 s, 30 times (about 3.5 minutes) before the migration fails.

Readers the queued lock does **not** cancel will hold it off:
an anti-wraparound autovacuum, a `pg_dump`, a `psql` session left idle in a
transaction, a long report query. Before deploying:

```sql
-- sessions touching syslog_messages (or a leaf), oldest transaction first
SELECT pid, state, now() - xact_start AS xact_age, left(query, 80) AS query
FROM pg_stat_activity
WHERE xact_start IS NOT NULL AND pid <> pg_backend_pid()
ORDER BY xact_start;

-- vacuums in progress (an anti-wraparound one reads as "to prevent wraparound"
-- in pg_stat_activity.query and is not cancelled by a lock waiter)
SELECT p.pid, p.relid::regclass, p.phase, a.query
FROM pg_stat_progress_vacuum p JOIN pg_stat_activity a USING (pid);
```

Wait for, or end (`SELECT pg_terminate_backend(<pid>)`), anything old that
holds `syslog_messages` before you restart. Restart the API and the poller
together (they share the migration lock; the poller's normalized-event
backfill, while one runs, issues reads of up to 120 s each).

If the processes crash-loop with `migrate v74 add syslog_messages.format
(attempt 30/30): ... SQLSTATE 55P03` (or `57014`), a blocker outlasted the
retries: find it with the queries above, wait for it or terminate it, and
the next restart applies v74 in milliseconds. An interrupted attempt leaves
nothing behind: the ALTER is one transaction, and until it commits the table
is unchanged.

## Database migration: server 0.11.314 (migration v80)

v80 drops three unused indexes from every `net_events` leaf —
`idx_<leaf>_rule_key_ts`, `idx_<leaf>_src_ip_ts`, `idx_<leaf>_dst_ip_ts` — and
returns their space at once (no table rewrite, no VACUUM needed). Each
`DROP INDEX` is its own transaction and needs a brief ACCESS EXCLUSIVE lock on
its leaf; while it waits, inserts into that leaf (today's) wait behind it, so
each attempt is capped at 2 s (`lock_timeout` and `statement_timeout`) and an
index whose lock was not granted is retried every 5 s, 12 rounds (about
1.5 minutes). The same pre-flight as v74 applies: a long reader of a leaf
(`pg_dump`, an idle-in-transaction session, a running normalized-event
backfill read of up to 120 s) only delays that leaf's drops.

An index still held after the last round is **not** an error: the startup
continues and logs `WARNING: migrate v80 drop unused net_events indexes: N of M
not dropped ... : <names>`. A daily leaf's leftovers go with the leaf when
retention drops it (`RETENTION_NET_EVENT_DAYS`); to reclaim the space sooner,
drop the logged names by hand when the database is quiet:

```sql
SET lock_timeout = '2s';
DROP INDEX IF EXISTS idx_net_events_default_rule_key_ts;  -- one per logged name
```

**Rolling back** to 0.11.313 or earlier rebuilds the three indexes on every
leaf at the next startup (its partition pass creates them `IF NOT EXISTS`):
about 0.9 GB per retained day, and each build holds a SHARE lock on its leaf
(inserts into today's leaf wait for that build). Check free disk space first.

## Header / field reference

For operators debugging a `curl` or a probe that won't register:

- Request body field: `schema_version` (integer, optional).
- Response body field on success: `schema_version` (integer, the version the
  server selected for this probe).
- Response header on 426: `X-Probe-Schema-Version-Supported: <min>-<max>`.
- Response body on 426:
  `{"success": false, "error": "Probe schema_version N not supported (server supports <min>-<max>); see MIGRATING.md", "message": "..."}`.

## Related

- `internal/relay/relay.go` — source of truth for the consts.
- `internal/api/handlers/handlers_probes.go` — the `RegisterProbe` handler
  that does the validation.
- `docs/SUPPORT-MATRIX.md` — the per-version collector ↔ server table.
