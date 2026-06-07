# Compatibility Matrix — Collector × Server Versions

This document tracks wire-format compatibility between the **collector**
(`xphox2/Firewall-Collector`, the `firewall-collector` probe binary) and the
**central server** (`xphox2/Firewall-Monitoring`, the `fwmon-api` binary). Use
it when planning upgrades, since the two are deployed and upgraded
**independently**.

> The mechanics of the registration handshake version live in `MIGRATING.md`;
> this file is the per-version table. The deployment is **single-tenant** —
> there is no per-tenant authorization or cross-tenant compatibility concern.

## TL;DR

- The current server major line (`0.10.x`) is **wire-compatible with all
  shipped `1.2.x` collectors.** A pre-handshake collector that doesn't send
  `schema_version` is treated as v1 and accepted.
- Two collector-introduced fields the server already honors: `backup_quality`
  on a config revision, and the `X-Probe-Batch-ID` idempotency header on
  batched ingestion (server-side dedup, AUDIT-042).
- The **`schema_version` registration handshake** is validated by the server
  starting at **v0.10.382** (the only version-gated behavior so far).

## Matrix (collector → minimum server)

| Collector | Min server | Notes |
|---|---|---|
| ≤ 1.2.71 | 0.9.x (any) | Pre-`backup_quality`. Bearer-token relay. No `schema_version`; the server defaults it to v1. |
| 1.2.72+ | (any current 0.10.x) | Sends `backup_quality` on `ConfigRevision`. Older servers ignore the field (Go `encoding/json`); v0.10.x honors it. Wire-compatible. |
| 1.2.74+ | (any current 0.10.x) | Sends the `X-Probe-Batch-ID` header for server-side dedup. Older servers ignore the header (a retry just creates a duplicate; data integrity is preserved). Wire-compatible. |
| (future) sends `schema_version` | **0.10.382+** | A server ≥ 0.10.382 validates `schema_version` against `relay.SchemaVersionMin..Max` (currently `1-1`) and returns **HTTP 426** with `X-Probe-Schema-Version-Supported` for anything out of range. Sending the field against an older server is harmless (ignored). |

> The collector-side version notes above describe behavior owned by the
> `Firewall-Collector` repo; this server's only **version-gated** behavior is
> the `schema_version` validation at 0.10.382. Everything else is
> additive/ignored-when-unknown and therefore wire-compatible across versions.

## Server features that would require a collector change

None today — the `0.10.x` server accepts all `1.2.x` collectors unchanged. Any
future server change that *requires* collector cooperation (a new required
field, a removed endpoint, a `schema_version` bump) will:

1. Move `relay.SchemaVersionMax` in `internal/relay/relay.go`, and
2. Get a row here and in `MIGRATING.md`.

## Upgrade procedure (canonical)

1. **Server first, then collector.** The server is wire-compatible with all
   `1.2.x` collectors, so a server upgrade is safe at any time. The reverse is
   not guaranteed once a future collector starts advertising a higher
   `schema_version` than an old server supports.
2. **Roll collectors in waves.** Use the admin UI to confirm each probe is
   sending data after its upgrade; if a probe goes silent for more than two
   heartbeat intervals, roll it back.
3. **Verify versions.** `GET /api/version` reports the running server version;
   the collector reports its own via its `--version` flag. The server's
   Prometheus surface is at `GET /metrics` (`fwmon_http_request_duration_seconds`
   and the DB-pool/runtime collectors — API-server metrics only).

## Wire-format reference

- `internal/relay/relay.go` — the relay DTO definitions + the
  `SchemaVersionMin`/`SchemaVersionMax` consts (source of truth).
- `internal/models/models.go` — the server's persisted model definitions.
- `MIGRATING.md` — the `schema_version` handshake mechanics and rollout order.

## Reporting an incompatibility

File an issue on the
[collector repo](https://github.com/xphox2/Firewall-Collector/issues) with:

- The collector version (`firewall-collector --version`) and server version
  (`GET /api/version`).
- The relevant log lines from both sides (include the server's `X-Request-ID`).
- The failure mode (collector silent? server 4xx? a specific field rejected?).
