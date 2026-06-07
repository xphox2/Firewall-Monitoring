# Probe ↔ Server Wire-Format Compatibility

> **Audience:** operators upgrading either side of a probe/server pair —
> the `fwmon-api` server in this repo (`xphox2/Firewall-Monitoring`) and the
> `firewall-collector` probe binary (`xphox2/Firewall-Collector`).
>
> **Source of truth for the supported range:** the exported
> `relay.SchemaVersionMin` / `relay.SchemaVersionMax` consts in
> `internal/relay/relay.go`. This file is the human-readable mirror, and
> `docs/SUPPORT-MATRIX.md` holds the per-version compatibility table.

## Why this doc exists

The collector probe and the central server communicate via a set of
hand-maintained JSON DTOs (defined in `internal/relay/relay.go` and
`internal/models/models.go`) over the `/api/probes/...` REST endpoints. The
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
lockstep with this file whenever the relay handshake changes shape. Today it
is **`1`**.

When a probe registers it sends its `schema_version`. The server validates it
against `[relay.SchemaVersionMin, relay.SchemaVersionMax]` (currently `1`-`1`).
Three outcomes:

| Probe sends | Server response | What happens next |
|---|---|---|
| `schema_version` absent | 200 OK, treated as v1 | The probe registers as before (pre-handshake collectors). |
| `schema_version: 1` | 200 OK, `schema_version: 1` echoed | The probe registers normally. |
| anything outside `1-1` | **426 Upgrade Required**, header `X-Probe-Schema-Version-Supported: 1-1` | The probe refuses to register. The body names the rejected version and points here. |

The supported range is **deliberately narrow** today (v1 only). The consts in
`internal/relay/relay.go` are the single source of truth — shipping a future
v2 only requires bumping `SchemaVersionMax` there and adding a row to
`docs/SUPPORT-MATRIX.md`.

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
426, logs `Probe schema_version N not supported (server supports 1-1)`, and
its register fails. Roll the server forward (or the probe back) and the probe
registers. There is **no data loss** — the probe keeps unsent data in its
on-disk queue until the server can accept it again.

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
