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
current maximum is **`5`**; v1 through v4 remain fully supported.

When a probe registers it sends its `schema_version`. The server validates it
against `[relay.SchemaVersionMin, relay.SchemaVersionMax]` (currently `1`-`5`)
and, since server v0.11.75, **persists the selected version on the probe row**
(`probes.schema_version`) — version-gated downstream features key off the
stored value. Three outcomes:

| Probe sends | Server response | What happens next |
|---|---|---|
| `schema_version` absent | 200 OK, treated as v1 | The probe registers as before (pre-handshake collectors). |
| `schema_version: 1`–`5` | 200 OK, selected version echoed + persisted | The probe registers normally. |
| anything outside `1-5` | **426 Upgrade Required**, header `X-Probe-Schema-Version-Supported: 1-5` | The probe refuses to register. The body names the rejected version and points here. |

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
426, logs `Probe schema_version N not supported (server supports 1-5)`, and
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
