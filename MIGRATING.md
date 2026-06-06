# Probe ↔ Server Wire-Format Compatibility

> **Audience:** operators upgrading either side of a probe/server pair
> (the `fwmon-api` server in this repo and the `Firewall-Collector`
> probe binary in `E:\Golang\OpenCode\Firewall-Collector`).
>
> **Source of truth for the supported range:** the exported
> `relay.SchemaVersionMin` / `relay.SchemaVersionMax` consts in
> `internal/relay/relay.go` — this file is the human-readable mirror.

## Why this doc exists

The collector probe and the central server communicate via 15+ hand-maintained
JSON DTOs (defined in `internal/relay/relay.go` and `internal/models/models.go`)
over 20+ REST endpoints (under `/api/probes/:id/...` on the server). Before
AUDIT-065 there was no version field, no `Accept`-style content-type, and no
per-DTO compatibility matrix — a server-side change that added a required
field, shifted a field's semantics (e.g. `BackupQuality`), or removed an
endpoint could brick every deployed collector with no graceful fallback.
**The fix is the `schema_version` field on the `/api/probes/register`
handshake.** This doc is the operator-facing half of that fix: it tells
you which collector versions can talk to which server versions, and what
to do when a 426 (Upgrade Required) shows up in your probe logs.

## What the version number means

`schema_version` is the **probe↔server wire-format version**, exchanged
in the `POST /api/probes/register` request and response bodies. It is
**not** the semantic version of either binary; it is a small integer
bumped in lockstep with this file whenever the relay handshake changes
shape. Today it is **`1`**.

When a probe registers it sends its `schema_version`. The server
validates it against the supported range
`[relay.SchemaVersionMin, relay.SchemaVersionMax]` (currently
`1`-`1`). Three outcomes:

| Probe sends              | Server response                    | What happens next                                       |
|--------------------------|------------------------------------|---------------------------------------------------------|
| `schema_version` absent  | 200 OK, treats it as v1            | The probe registers as before. (Pre-AUDIT-065 probes.)  |
| `schema_version: 1`      | 200 OK                             | The probe registers normally.                          |
| `schema_version: 2` (or anything else out of range) | **426 Upgrade Required**, header `X-Probe-Schema-Version-Supported: 1-1` | The probe refuses to register. The operator sees the supported range in the response body. |

The supported range is **deliberately narrow** today (v1 only) — the
consts in `internal/relay/relay.go` are the single source of truth, and
shipping a future v2 only requires bumping `SchemaVersionMax` there and
adding a row to the matrix below.

## Supported matrix (collector ↔ server)

> **Reading the table:** rows = `Firewall-Collector` versions,
> columns = `Firewall-Monitoring` (this repo) server versions, cells =
> "OK" (the pair works as-is) or the minimum server version needed.
>
> When in doubt, **upgrade the server first**, then the collector. A
> probe running v2 against a server that only supports v1 gets a 426
> and shuts its relay loop down with a clear error; a server running
> v2-aware code against a v1 probe is harmless (the v1 probe never
> sends `schema_version`, the server defaults it to 1).

| Collector version | Server version required | Notes                                                                                       |
|-------------------|-------------------------|---------------------------------------------------------------------------------------------|
| v1.2.x            | v0.10.18X+ (current)    | The pre-AUDIT-065 collector shipped without `schema_version`; this server defaults to v1.   |
| v1.3.x            | v0.11.0+ (TBD)          | Will require server changes for the TFTP source-IP allowlist + size cap (per the audit).   |
| v2.x (future)     | TBD                     | Not yet cut. When the first v2 collector ships, the `SchemaVersionMax` const in `internal/relay/relay.go` will move to `2` and the v1/v2 range will be widened. |

## Upgrade rollout order

The "happy path" rolling upgrade is **server first, then probe**:

1. **Stage the new server.** Build the new `fwmon-api`, run it through
   staging, deploy to prod. Existing probes are unaffected — the
   server's new code still treats absent `schema_version` as v1.
2. **Watch the logs.** Confirm the new server is happy with the current
   probes (no 426s, register + heartbeat + ingestion all working).
3. **Roll the probes.** Update `Firewall-Collector` on the remote
   sites. Each probe will register with the new server, get its
   selected `schema_version` echoed back, and start the new wire
   format.

If you do the **wrong** order (probe first, then server) you will see
exactly one class of error: the new probe gets a 426 from the old
server, logs `Probe schema_version N not supported (server supports
1-1)`, and its relay loop dies. Roll the server back to the
AUDIT-065-aware build and the probe will register. There is **no data
loss** — the probe keeps its unsent data in its on-disk queue until
the server can accept it again.

## Header / field reference

For operators debugging a `curl` or a probe that won't register:

* Request body field: `schema_version` (integer, optional).
* Response body field on success: `schema_version` (integer, the
  version the server has selected for this probe).
* Response header on 426: `X-Probe-Schema-Version-Supported: <min>-<max>`.
* Response body on 426: `{"success": false, "error": "Probe schema_version N not supported (server supports <min>-<max); see MIGRATING.md", "message": "..."}`.

## Related

* **AUDIT-065** (this doc's parent audit): server-side DTO
  `schema_version` field + version negotiation.
* **AUDIT-046** (sibling audit in the `Firewall-Collector` repo):
  collector-side implementation of `schema_version` on outbound.
* **`internal/relay/relay.go`** — source of truth for the consts.
* **`internal/api/handlers/handlers_probes.go`** — the
  `RegisterProbe` handler that does the validation.
