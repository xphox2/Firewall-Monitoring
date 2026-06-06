# Compatibility Matrix — Collector × Server Versions

This document tracks the wire-format compatibility between the
**collector** (`xphox2/Firewall-Collector`) and the **central server**
(`xphox2/Firewall-Monitoring`) across versions. Use this when planning
upgrades, especially in environments where the collector and the server
are upgraded independently.

## TL;DR

| Collector | Minimum server | Maximum server | Notes |
|---|---|---|---|
| 1.0.0 — 1.1.x | (any 0.9.x) | (any 0.9.x) | Pre-`schema_version`. Wire-compatible with all 0.9.x servers. |
| 1.2.0 — 1.2.71 | 0.9.x (any) | 0.10.358 | Bearer-token auth. No `schema_version` field. |
| 1.2.72 | 0.10.358 | (latest 0.10.x) | **Adds `backup_quality` field on `ConfigRevision`**. Server from this version onward accepts the field; older servers ignore it (Go's `encoding/json` default). Wire-compatible. |
| 1.2.73 | 0.10.358 | (latest 0.10.x) | TFTP-ephemeral-TID race fix. No wire-format change. |
| 1.2.74 | 0.10.358 | (latest 0.10.x) | **Adds `X-Probe-Batch-ID` header on batched POSTs** for server-side dedup. Server from this version onward honors it; older servers ignore the header (collector's retry just creates duplicates, but data integrity is preserved). Wire-compatible. |
| 1.2.75 | 0.10.358 | (latest 0.10.x) | Audit summary commit. No wire-format change. |
| 1.2.76 — 1.2.78 | 0.10.358 | (latest 0.10.x) | Shutdown / panic-recovery / pin image tag commits. No wire-format change. |
| 1.2.79 | 0.10.358 | (latest 0.10.x) | **Adds `mTLS` support**. Requires the server to also support mTLS (`PROBE_TLS_CERT` / `PROBE_TLS_KEY` env vars on the server). Without mTLS, falls back to one-sided TLS. Wire-compatible. |
| 1.2.80 | 0.10.358 | (latest 0.10.x) | **Hard requirement**: `PROBE_SNMP_TRAP_COMMUNITY` must be set when `PROBE_SNMP_TRAP_ENABLED=true` (collector refuses to start otherwise). No wire-format change. |
| 1.2.81 — 1.2.88 | 0.10.358 | (latest 0.10.x) | Various bug fixes (panic recovery, shutdown idempotency, dead code removal, crypto upgrade, Go toolchain pin). No wire-format change. |
| 1.2.89+ | 0.10.363 | (latest 0.10.x) | **Adds `schema_version` field** in the registration handshake. Server refuses to register collectors with `schema_version > 1` (returns HTTP 426 with `X-Probe-Schema-Version-Supported` header). Wire-compatible with 0.10.358+ for unversioned collectors. |
| 1.3.0+ | 0.10.363 | (latest 0.10.x) | **Adds per-tenant authorization** (AUDIT-067). Server returns 403 on cross-tenant access. The collector's bearer token is scoped to a single tenant at registration; rotating the token does NOT change the tenant. Wire-compatible. |
| 1.4.0+ (planned) | 0.11.0+ | (latest 0.11.x) | **Adds TFTP source-IP allowlist + 2MB size cap** on `ConfigRevision` writes. The server is unchanged, but the probe refuses TFTP WRQ from source IPs not in the per-device allowlist. Wire-compatible on the server side. |

## What about server-side changes the collector must follow?

The reverse is also true: server features that require a corresponding
collector change. The current major version (`0.10.x`) is wire-compatible
with all `1.2.x` collectors, so the answer today is "no". Future
`0.11.0` server features that require collector cooperation will be
listed here.

## Upgrade procedure (canonical)

1. **Server first, then collector.** The server is wire-compatible
   with all 1.2.x collectors, so a server upgrade is safe at any time.
   The reverse is NOT always true — a collector upgrade may introduce
   new `schema_version` or new fields that the running server doesn't
   know about.
2. **Stage the server upgrade** with `PROBE_REGISTER_REQUIRE_SCHEMA_VERSION=false`
   if you need a brief overlap period where both old and new collectors
   are present (rare; usually not needed).
3. **Roll collectors** in waves. Use the operator UI to verify each probe
   is sending data after the upgrade. If a probe is silent for >2 heartbeat
   intervals, roll it back.
4. **Verify** the `/api/metrics` `firewall_collector_heartbeat_success_total`
   is monotonically increasing on every probe post-upgrade.

## Wire format reference

For the precise list of DTOs, fields, and headers, see:
- `internal/relay/relay.go` (the collector's DTO definitions).
- `internal/models/models.go` (the server's DTO definitions, mirrored from collector).
- `MIGRATING.md` (per-version wire-format changes).

## Reporting an incompatibility

If a collector + server pair does not match the matrix above, file an
issue on the [collector repo](https://github.com/xphox2/Firewall-Collector/issues)
with:
- The collector version (`firewall-collector --version`).
- The server version (`/api/version` on the server).
- A copy of the relevant log lines from both sides.
- A description of the failure (collector silent? server returning 4xx?
  specific DTO field rejected?).
