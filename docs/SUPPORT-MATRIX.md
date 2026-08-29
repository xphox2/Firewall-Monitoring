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
| 1.3.0+ (NetFlow/IPFIX) | (any current 0.11.x; **0.11.20+ for labeling**) | Sends `flow_source` + the Tranche 3 flow fields (`flow_start`/`flow_end`, `firewall_event`, `flow_end_reason`, post-NAT tuple, `icmp_type_code`, `tos`, VLANs, `app_name`) on flow rows — all additive `omitempty`, **no `schema_version` change**. Servers < 0.11.20 ignore the fields (Go `encoding/json`): NetFlow data ingests with correct byte math but is labeled sFlow and the source filter is unavailable. Server 0.11.20+ (migration v29) stores and filters them. Wire-compatible both directions. |
| 1.3.10+ (disk/load, **schema v3**) | **0.11.73+** (migration v38) | Sends `disk_usage` + `load_average` to two new endpoints. The collector gates these on the negotiated `schema_version ≥ 3`, so against a server < 0.11.73 (which advertises max v2) it simply doesn't send them — no 404 churn. `SchemaVersionMax` is now `3`. Deploy the 0.11.73 server first; the collector follows at any time. |
| 1.3.14+ (command channel, **schema v4**) | **0.11.75+** (migration v39) | The first **server→collector** feature: the heartbeat response carries `pending_commands` and the collector reports outcomes to `POST /api/probes/:id/command-result`, idempotent by `command_id`. Double-gated: the server persists the negotiated `schema_version` on the probe row at register and only attaches `pending_commands` for probes registered at ≥ 4; the collector no-ops its result sends below a negotiated v4. A v3 collector against a 0.11.75 server (or a v4 collector against an older server) simply has no command channel — everything else works. Command payloads are encrypted at rest server-side and may later carry credentials — the relay **must** be HTTPS. PR-1 ships only the `noop` command type. Deploy the server first; the collector follows at any time. |
| 1.3.15+ (L2 topology, **schema v5**) | **0.11.94+** (migration v45) | Sends L2 topology STATE snapshots for the port-to-port connection map: ARP + MAC-table (FDB) rows to `POST /api/probes/:id/topology-entries` and LLDP/CDP neighbor rows to `POST /api/probes/:id/topology-neighbors`, every 5th SNMP cycle. The server REPLACES a device's rows per (device, entry_type/protocol) scope on each batch; the collector gates both sends on a negotiated `schema_version ≥ 5` and never spools them (a replayed old snapshot would revert newer state). Against a server < 0.11.94 nothing is sent — no 404 churn. Deploy the server first; until the collector upgrades, the map shows no local links (subnet-guess links were removed in 0.11.94). |

> The collector-side version notes above describe behavior owned by the
> `Firewall-Collector` repo; this server's only **version-gated** behavior is
> the `schema_version` validation at 0.10.382. Everything else is
> additive/ignored-when-unknown and therefore wire-compatible across versions.

## Server features that would require a collector change

The **schema v4 command channel** (server 0.11.75) is the first: receiving
and executing heartbeat-delivered commands requires collector 1.3.14+. It is
opt-in by negotiation — an older collector keeps working with no command
channel. Any server change that *requires* collector cooperation (a new
required field, a removed endpoint, a `schema_version` bump) will:

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

## Flow-export vendor matrix (NetFlow v5/v9 · IPFIX · sFlow)

What each firewall vendor can export and what to watch for. Full sourced
detail in `docs/flow-protocol-research-2026-07-03.md` §5. **Configure ONE
flow protocol per device** — dual-exporting the same interfaces double-counts
every byte (the collector's `PROBE_FLOW_DEDUP` policy defends against this,
default `prefer-netflow`, and the Flows page warns when it sees mixed
sources for one device).

| Vendor | Protocols | Sampling | Operator notes |
|---|---|---|---|
| FortiGate (kernel) | NetFlow v9 + sFlow v5 | Session-based, unsampled < 7.6; 7.6+ `netflow-sample-rate` (exported counters are sampled-scale — the collector re-multiplies) | **Prefer NetFlow: sFlow disables NPU offload.** Lower `template-tx-timeout` (default 1800 s) to shrink the post-restart template wait. The only mainstream dual-export vendor. |
| FortiGate NP7 CGN | NetFlow v9 or IPFIX | Unsampled | `config log npu-server`; distinct observation domains per NP7 vs CPU. |
| Palo Alto PAN-OS | NetFlow v9 only | Never sampled | App-ID/User-ID come as PAN-specific fields; template refresh 30 min. |
| Cisco ASA/FTD | NSEL (v9 transport) | Never sampled | Bytes only (no packet counters exist); denied/create records carry zero counters — expected. |
| SonicWall | NetFlow v5/v9, IPFIX, IPFIX-with-extensions (EntID 8741) | Unsampled | Plain modes fully supported; AppFlow extension fields are skipped safely (mapping is a planned fast-follow). |
| Firewalla | **No flow export** | — | Flows are internal to the Firewalla app/MSP API only. |
| pfSense | Plus 24.03+: pflow v5 + IPFIX; CE: softflowd v5/v9/IPFIX | Unsampled | Use IPFIX mode on CE — softflowd's v9 has known timestamp bugs. |
| OPNsense | NetFlow v5/v9 | Unsampled | v5 = IPv4 only. |
| MikroTik | v1/v5/v9/IPFIX | ROS 7+ | ROS 6.49.x has a byte-order bug in the exported sampling rate (fixed 7.10) — use a per-exporter rate override, never trust auto-detection. Fasttrack/HW-offloaded traffic is invisible to traffic-flow. |
| Juniper SRX | J-Flow v9/IPFIX | Sampled | Rate arrives via options templates. |
| Sophos XG/XGS | NetFlow v5 only | Unsampled | IPv4 only (vendor limit). |
| WatchGuard | v5 + v9 (12.3+) | Optional | v9 needed for IPv6 + post-NAT fields (12.7.1+). |
| Ubiquiti EdgeOS / UniFi | v5/v9/IPFIX (UniFi Network 8.5.6+ selectable) | Configurable | Not available on UniFi Express / UXG-Lite. |
| VyOS | v5/v9/IPFIX + sFlow | Both | Second dual-export vendor; VyOS recommends sFlow at high pps. |

## Wire-format reference

- `internal/relay/relay.go` — the `SchemaVersionMin`/`SchemaVersionMax`
  handshake consts (source of truth) + the v4 command-channel DTOs
  (`PendingCommand` / `CommandResultRequest`) the server consumes. NOT the
  telemetry wire-shape reference.
- `internal/models` (server receiver, e.g. `models.FlowSample` bound in
  `internal/api/handlers/handlers_data.go`) + the Firewall-Collector repo's
  `internal/relay` package (sender) — the authoritative telemetry wire shapes.
- `internal/models/models.go` — the server's persisted model definitions.
- `MIGRATING.md` — the `schema_version` handshake mechanics and rollout order.

## Reporting an incompatibility

File an issue on the
[collector repo](https://github.com/xphox2/Firewall-Collector/issues) with:

- The collector version (`firewall-collector --version`) and server version
  (`GET /api/version`).
- The relevant log lines from both sides (include the server's `X-Request-ID`).
- The failure mode (collector silent? server 4xx? a specific field rejected?).
