# sFlow NOC Reporting — Full Redesign Plan

**Status:** design / pre-implementation
**Author:** CTO-loop planning session, 2026-06-11
**Target repo:** `Firewall-Mon` (this repo)
**Sibling repo coordination:** `Firewall-Collector` at `E:\Golang\OpenCode\Firewall-Collector`
**Target ship window:** 5 minor releases (`0.11.0` → `0.15.0`) over ~8–9 weeks

---

## 1. Executive summary

Firewall-Mon's current sFlow reporting treats sFlow as "snmp-with-packets" and stops at the first record type. The result is a dashboard that **understates real traffic by 1:512** (bytes never multiplied by sampling rate), **invisibly drops IPv6 traffic**, **throws away counter samples** (so sFlow's own interface bandwidth is never used), and **discards the drops counter** (so agent-side sample loss is invisible). This plan replaces the existing pipeline with a 5-phase rewrite that fixes the data correctness bugs, captures the full sFlow v5 record catalog, adds a Go in-memory real-time aggregator, ships a new `/admin/noc` page purpose-built for the 6-zone NOC layout proven by Akvorado and sFlow-RT, and hardens the receiver to 100k+ samples/sec on commodity hardware without changing the wire protocol (30s JSON batches stay).

**Why now:** at 100k+ samples/sec the existing single-goroutine parser is the bottleneck. At 1:512 sampling the bytes bug alone hides ~50 Gbps of real traffic. The audit (`tasks/CTO-LOOP-2026-06-11.md`) flagged 8.5% test coverage on `internal/sflow` as a High-priority item that can't be addressed without a rewrite. The right time to do the rewrite is the same release cycle as the correctness fix.

**What we explicitly do NOT do:** add Kafka, ClickHouse, Vue/React/Svelte, ML-based anomaly detection, IPFIX/NetFlow support, gRPC streaming transport, or a new click-to-filter DSL.

---

## 2. Goals & non-goals

### 2.1 Goals

1. **Correct bytes estimation end-to-end.** `bytes = sample_bytes × sampling_rate` is honored at every read path.
2. **Parse and store every sFlow v5 record type relevant to a NOC.** `sampled_header` (IPv4 + IPv6), `sampled_ipv4` (format 3), `sampled_ipv6` (format 4), `extended_switch` (1001), `extended_router` (1002), `extended_gateway` (1003), `discarded_packet` (sample format 5), `if_counters` (1), `ethernet_counters` (2), `processor` (1001), `queue_length` (1003).
3. **Capture `drops` and surface agent-side sample loss as an alert.** Stored in `flow_agent_drops`; surfaces in the NOC status strip and the alerts page.
4. **Scale the receiver to 100k+ samples/sec.** `SO_REUSEPORT` worker pool, per-agent token-bucket rate limit, bulk insert via `pgx.CopyFrom`. No GORM `Create(&samples)` in the hot path.
5. **sFlow-native interface bandwidth (Phase 1) sitting alongside the existing SNMP polling.** The device-detail page prefers sFlow for sFlow-exporting devices; SNMP stays for non-sFlow devices.
6. **Sub-second NOC view via SSE, with the 30s batch as the freshness floor.** The in-memory aggregator updates at 1 Hz; the SSE stream pushes at 1 Hz; the persistent storage is updated by the same 30s batch path.
7. **A purpose-built NOC screen with the proven 6-zone layout, click-to-filter, and detail side-panel.** URL-hash state; clicking any widget updates the filter and refreshes the rest.
8. **100% test coverage on the new parser paths.** Fuzz the IPv6, extended-records, and counter-sample paths. The 8.5% number on `internal/sflow` is the most-flagged audit item and Phase 4 will resolve it.
9. **Zero new infrastructure dependencies.** No Kafka, no ClickHouse, no second store, no second service. Postgres + an in-memory aggregator is enough at 100k samples/sec.
10. **No changes to the wire protocol.** The 30s JSON batch over HTTPS stays. We add fields to the JSON (drops, as_path, communities, etc.) and the api side tolerates missing fields.

### 2.2 Non-goals

- **Replacing the 30s JSON batch transport with gRPC streaming.** Revisit later if the freshness floor hurts.
- **Replacing SNMP polling with sFlow counters.** sFlow is preferred where available; SNMP stays for non-sFlow devices.
- **Adding Vue/React/Svelte.** Vanilla JS + the existing Chart.js + uPlot is the right tool at this scope.
- **Machine-learning anomaly detection.** Tier-1 detectors (top-K, super-spreader, port scan, threshold) cover 90% of operational value. ML is research-grade.
- **IPFIX/NetFlow support.** sFlow is the source of truth for this project.
- **A new click-to-filter DSL.** We use the existing chip-based UI with URL hash state.
- **Real sub-second NOC freshness.** The 30s batch is the floor; the in-memory aggregator is sub-second *once the batch lands*.

---

## 3. Background & research

### 3.1 sFlow v5 protocol facts (cited)

- **Authoritative spec:** [sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt) — Phaal & Lavine, July 2004. v4 is deprecated (RFC 3176). v5 is the only version in shipping products. Quoting the spec: *"This memo describes sFlow version 5. It replaces sFlow version 4 described in RFC 3176."*
- **Transport:** UDP 6343, XDR-encoded (RFC 1832). No TCP, no TLS, no auth. Default `sFlowRcvrMaximumDatagramSize` is 1400 bytes (leaves headroom for VPN/ERSPAN/GRE encaps). Spec §5: *"The sFlow Agent may at most delay a sample by 1 second before it is required to send the datagram."*
- **Two sample kinds:** flow samples (sampled packet headers) and counter samples (interface/Ethernet/processor/etc. counters). Both are needed.
- **Sampling math is the #1 thing to get right:** `estimated_bytes = sample.bytes × sampling_rate`. The sampling rate is per (agent, source_id) and can change silently (agent back-off; see spec §4.2.2). Spec: *"The Agent may implement an automated one-way backoff of the Sampling Rate that triggers whenever an excessive number of samples per second is generated."*
- **XDR rules (RFC 1832):** all integers are big-endian, 4-byte unsigned (or 8-byte `unsigned hyper`) aligned on 4-byte boundaries. Strings and opaque arrays are length-prefixed (4-byte length + data + padding to 4-byte boundary). Discriminated unions encode a 4-byte enum then the selected arm. Every record on the wire is `[4-byte tag/format | 4-byte length | payload padded to 4 bytes]`. Spec §10.2.1: *"Applications receiving sFlow data must always use the opaque length information when decoding opaque<> structures so that encountering extended structures will not cause decoding errors."*
- **Record types:** the authoritative catalog is at [sflow.org/developers/structures.php](https://sflow.org/developers/structures.php). The `(enterprise << 12) | format` 20-bit/12-bit split identifies records. Enterprise 0 is the sflow.org standard set; non-zero is vendor-specific. The parser **must** read length first and skip on unknown, or vendor records will break it.

### 3.2 Record types we will parse

| Type | Format # | What it gives us |
|---|---|---|
| `sampled_header` | flow_data 1 | Raw packet header bytes (default 128B) + frame_length + header_protocol + stripped count |
| `sampled_ipv4` | flow_data 3 | Parsed 5-tuple (src/dst IP, src/dst port, protocol, TCP flags) without parsing the raw header |
| `sampled_ipv6` | flow_data 4 | Same, for IPv6 |
| `extended_switch` | flow_data 1001 | src_vlan, src_priority, dst_vlan, dst_priority |
| `extended_router` | flow_data 1002 | next_hop, src_mask_len, dst_mask_len |
| `extended_gateway` | flow_data 1003 | BGP src_as, dst_as, src_peer_as, as_path<>, communities<>, localpref |
| `discarded_packet` | sample_data 5 | Dropped-packet reason code (ACL, TTL, no buffer, etc.) |
| `if_counters` | counter_data 1 | 64-bit ifInOctets, ifOutOctets, ifSpeed, ifInErrors, ifInDiscards, etc. |
| `ethernet_counters` | counter_data 2 | dot3StatsFCS errors, frame_too_longs, symbol_errors, etc. |
| `processor` | counter_data 1001 | CPU 5s/1m/5m, memory |
| `queue_length` | counter_data 1003 | Egress buffer depth per port |
| `host_*` | counter_data 2000–2010 | Host sFlow (when source is a host agent) |

Records we explicitly **skip** on parse: enterprise-tagged vendor records (read length and skip), `slow_path_counts` (Phase 4+), `lag_port_stats` (Phase 4+), `sfp`/optical (Phase 4+).

### 3.3 Sampling math

```
sample_bytes (from frame_length)        — what the agent actually sent
sampling_rate (1:N from agent)         — N
estimated_bytes = sample_bytes * N     — what crossed the wire
```

`sample_pool` is the total packets observed since agent boot (or last reset). `packets = sample_pool_delta` between two samples is the way to reconcile against counter deltas.

**Adaptive sampling** (spec §4.2.2): *"An Agent may implement an automated one-way backoff of the Sampling Rate that triggers whenever an excessive number of samples per second is generated. When triggered the Agent can double the Sampling Rate. … The sampling rate must stay at its new value and never automatically return to the originally configured value."* We must track `sampling_rate` per (agent, source_id) over time and surface changes in the anomaly ticker.

### 3.4 Security posture

- No TLS, no auth, no integrity. UDP only. Spec §6: *"sFlow does not provide specific security mechanisms, relying instead on proper deployment and configuration to maintain an adequate level of security."*
- Mitigations: source-IP CIDR allowlist, sequence-number tracking per (agent, sub_agent), dedicated VRF/VLAN, cap `sFlowFsMaximumHeaderSize` to limit PII exposure (default 128B is fine; 64B is safer if you carry PII).
- DoS posture: a 10G attacker can flood the collector with bogus datagrams. Mitigations: rmem_max tuning, per-agent rate limiting (Phase 2.3), CIDR allowlist (Phase 4.4), bounded `opaque<>` lengths in the parser.

### 3.5 Reference architectures

**sFlow-RT (InMon).** Java/JVM real-time analytics engine. Sub-second thresholding. REST/JSON only (no WebSocket). "Flow definitions" let you define a key (e.g. `ipsource,ipdestination`) + value (`bytes`) + aggregation window, then `topk(10, …)` them. `baselineCheck` API does sliding-window z-score with sensitivity multipliers. The `prometheus` exporter app lets Grafana scrape real-time metrics. Production deployments at SDSC Expanse, NRP Nautilus, SFMIX. **What we steal:** the threshold/baseline concept (Phase 2.7). **What we skip:** the Java stack, the REST-only transport.

**Akvorado (OVH, Go + Vue + ECharts + ClickHouse + Kafka).** The gold standard for an open-source NOC flow dashboard. 4 services: inlet → Kafka → outlet → ClickHouse, plus orchestrator/console. Console is Vue 3 + ECharts + Tailwind. URL-hash state for filters. 6-zone layout (status, top-N, time series, distribution, geo, activity stream). **What we steal:** the URL-hash filter state pattern; the visual layout; the per-flow and aggregate dual view; the filter chip UI. **What we skip:** Kafka, ClickHouse, the second service. We use Postgres + an in-memory aggregator.

**goflow2 (netsampler).** Go sFlow/NetFlow/IPFIX collector. BSD-3, active. `SO_REUSEPORT` worker pool pattern. `protobuf` output for transport. From its `docs/performance.md`: *"This software has been tested with hundreds of thousands of flows per second on common hardware."* **What we steal:** the worker pool pattern, the per-agent rate limit, the buffer-size advice. **What we skip:** the protobuf transport (we use the existing JSON batch).

**ntopng (ntop).** C++/Lua + Vue. Receives sFlow/NetFlow/IPFIX. Native ClickHouse backend. L7 visibility via nDPI. Conversations, top talkers, alerts, geo. **What we steal:** the conversation-list drill-down pattern. **What we skip:** the full-packet-inspection side (out of scope).

---

## 4. Current state audit

The 2026-06-11 audit (`tasks/CTO-LOOP-2026-06-11.md`) and a deep-read of the sFlow code surface 15 issues, ranked by severity.

| # | Bug | File:line | Severity | Phase |
|---|---|---|---|---|
| 1 | `Bytes` not multiplied by `SamplingRate` at insert | `internal/sflow/sflow.go:324` | **Blocker** | 0 |
| 2 | Rollup `SUM(bytes)` not scaled | `internal/database/flows.go:503, 562` | **Blocker** | 0 |
| 3 | Counter samples entirely ignored → no `ifInOctets`/`ifOutOctets` | `internal/sflow/sflow.go:228–232` | **Blocker** | 1 |
| 4 | IPv6 packets dropped (raw IPv6 + 0x86DD Ethernet) | `internal/sflow/sflow.go:329–351` | High | 1 |
| 5 | `drops` field discarded → agent packet loss invisible | `internal/sflow/sflow.go:257–271` | High | 0 |
| 6 | `SequenceNumber` always 0 on the wire | `cmd/probe/main.go:268`, `internal/relay/relay.go` | High | 0 |
| 7 | `flow_rollups` not indexed on `src_addr`/`dst_addr` | `internal/models/models.go:687` | High | 0 |
| 8 | Single-threaded parser, no `SO_REUSEPORT`, no `SO_RCVBUF` | `internal/sflow/sflow.go:114, 145` | High | 2 |
| 9 | 1000-row per-batch silent truncation | `internal/api/handlers/handlers_data.go:162` | High | 2 |
| 10 | Top-N merge logic clips to 10+10 | `internal/database/flows.go:362–380` | Medium | 4 |
| 11 | No CIDR allowlist (exact-IP only) | `internal/sflow/sflow.go:73` | Medium | 4 |
| 12 | No per-agent rate limit | `internal/sflow/sflow.go` | Medium | 2 |
| 13 | Dead `FlowSample` struct (wire-payload style, never used) | `internal/sflow/sflow.go:32–44` | Low | 0 |
| 14 | 8.5% test coverage on `internal/sflow` | `coverage.out` | High | 0–2 |
| 15 | No `discarded_packet`, no extended switch/router/gateway | `internal/sflow/sflow.go:289` | Medium | 4 |

**Test coverage today:** `internal/sflow` is at 8.5% (2 tests, 48 statements). The fuzz target only covers the 28-byte `ParseSFlowDatagram` header; the production hot path (`parseDatagram` → `parseFlowSample` → `parseRawPacketHeader` → `parseIPv4`) is 0% covered. This is the single most-flagged coverage item in the codebase.

---

## 5. Target architecture (end state)

```
                ┌──────────────────────────────────────────────┐
                │ Network devices (sFlow v5 agents)            │
                │  - L2/L3 switches (Arista, Juniper, HP, …)  │
                │  - Host sFlow (Linux/FreeBSD)                │
                └────────────────────┬─────────────────────────┘
                                     │ UDP/6343
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │  api binary (Firewall-Mon) — new SO_REUSEPORT receiver │
        │  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
        │  │ socket 0   │  │ socket 1   │  │ socket N   │ SO_REUSEPORT
        │  │ decoder 0  │  │ decoder 1  │  │ decoder N  │ per-socket goroutine
        │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘        │
        │        └──────────┬────┴──────────┬────┘                │
        │                   ▼               ▼                     │
        │        ┌────────────────────┐  ┌────────────┐           │
        │        │  per-agent token   │  │ XDR parse  │           │
        │        │  bucket rate limit │  │ skip-on-   │           │
        │        └─────────┬──────────┘  │ unknown    │           │
        │                  ▼             └─────┬──────┘           │
        │        ┌────────────────────┐        ▼                  │
        │        │ in-memory realtime │  ┌────────────┐           │
        │        │ aggregator         │  │ drops count│           │
        │        │  - ring buffer 5m  │  │ seq# track │           │
        │        │  - top-K per dim   │  └────────────┘           │
        │        │  - HLL super-sprd  │                           │
        │        │  - HLL port-scan   │                           │
        │        │  - threshold det.  │                           │
        │        └─────┬──────────────┘                           │
        │              │ 1 Hz SSE                                 │
        │              ▼                                          │
        │   GET /admin/api/flows/stream                           │
        │              │                                          │
        │              ▼                                          │
        │   ┌─────────────────────────┐                           │
        │   │ Postgres                │                           │
        │   │  - flow_samples         │ (raw, 1h hot, 365d, monthly RANGE)
        │   │  - flow_rollups         │ (5m/1h/1d, src/dst indexed) │
        │   │  - flow_if_counters     │ (raw 7d, 5m rollup 30d)   │
        │   │  - flow_agent_drops     │ (running counter)         │
        │   │  - flow_anomalies       │ (persisted detections)    │
        │   │  - flow_sampling_changes│ (rate change events)     │
        │   └─────────────────────────┘                           │
        └────────────────────┬───────────────────────────────────┘
                             │ REST
                             ▼
        ┌────────────────────────────────────────────────────────┐
        │  /admin/noc (NEW) — 6-zone layout, click-to-filter     │
        │  /admin/flows (improved) — same UI, corrected bytes    │
        │  /admin/connections/:id (improved) — same UI, corrected│
        │  /admin/alerts (existing) — new sFlow alert sources     │
        └────────────────────────────────────────────────────────┘
```

### 5.1 Component responsibilities

| Component | Owns | Doesn't own |
|---|---|---|
| **Receiver** | UDP socket, CIDR allowlist, per-agent rate limit, XDR parse, drops counting, seq# tracking, dispatch to aggregator + DB writer | Storage, UI, alerting |
| **In-memory aggregator** | Last 5 min of flows, top-K, HLL detectors, threshold detection, SSE broadcast | Durable storage, alerting persistence |
| **DB writer** | Bulk insert to `flow_samples` (Phase 2), upsert to `flow_if_counters`, update `flow_agent_drops` | Parsing, top-K, UI |
| **REST API** | Historical reads from `flow_samples` + `flow_rollups`, config knobs, CSV export | Real-time push (that's SSE) |
| **SSE endpoint** | Real-time push of top-K + HLL summaries + alert ticker | Historical reads |
| **/admin/noc page** | The NOC screen. Reads SSE for live, REST for historical. | Anything server-side |

---

## 6. Data model

### 6.1 Existing tables (corrected)

**`flow_samples`** — no DDL change. The read paths scale `bytes` by `sampling_rate` at query time.

```sql
-- existing schema; the audit-confirmed current shape
flow_samples (
  id              BIGSERIAL PRIMARY KEY,
  timestamp       TIMESTAMPTZ NOT NULL,
  device_id       BIGINT NOT NULL,
  probe_id        BIGINT NOT NULL,
  sampler_address INET NOT NULL,                    -- agent IP
  sequence_number BIGINT,                            -- now populated (Phase 0)
  sampling_rate   INT NOT NULL,                      -- 1:N
  src_addr        INET,                              -- IPv4 only today; will accept IPv6 text
  dst_addr        INET,                              -- IPv4 only today; will accept IPv6 text
  src_port        INT,
  dst_port        INT,
  protocol        SMALLINT,
  bytes           BIGINT NOT NULL,                   -- raw sample_bytes (frame_length)
  packets         BIGINT NOT NULL DEFAULT 1,
  input_if_index  BIGINT,
  output_if_index BIGINT,
  tcp_flags       SMALLINT,
  drops           INT,                               -- NEW (Phase 0)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

DDL changes for Phase 0:
```sql
ALTER TABLE flow_samples ADD COLUMN IF NOT EXISTS drops INT;
```

Indexes: existing `idx_flow_device_ts`, `idx_flow_src_addr`, `idx_flow_dst_addr` stay.

**`flow_rollups`** — add indexes; the read paths scale `bytes_sum` by `sampling_rate_avg`.

```sql
ALTER TABLE flow_rollups ADD COLUMN IF NOT EXISTS sampling_rate_weighted_avg NUMERIC(12,4);
CREATE INDEX IF NOT EXISTS idx_rollup_src  ON flow_rollups (src_addr);
CREATE INDEX IF NOT EXISTS idx_rollup_dst  ON flow_rollups (dst_addr);
CREATE INDEX IF NOT EXISTS idx_rollup_proto_port ON flow_rollups (protocol, dst_port);
```

**Read-path math** (used by every endpoint that returns bytes):
```
estimated_bytes = SUM(bytes) * 1.0                  -- if sampling_rate is 1 for all rows
estimated_bytes = SUM(bytes) * AVG(sampling_rate)    -- current implementation
estimated_bytes = SUM(bytes * sampling_rate)        -- true weighted; preferred going forward
```

Phase 0 standardises on the **weighted** form. The rollup's `bytes_sum` continues to store the un-multiplied `SUM(bytes)`; the read path does the multiplication. This preserves per-row info for reconciliation.

### 6.2 New tables (Phase 0+)

**`flow_if_counters`** — interface counters from sFlow's `if_counters` records.

```sql
CREATE TABLE flow_if_counters (
  id              BIGSERIAL PRIMARY KEY,
  timestamp       TIMESTAMPTZ NOT NULL,
  device_id       BIGINT NOT NULL,
  if_index        BIGINT NOT NULL,
  if_speed        BIGINT,
  if_in_octets    BIGINT,
  if_out_octets   BIGINT,
  if_in_ucasts    BIGINT,
  if_out_ucasts   BIGINT,
  if_in_errors    BIGINT,
  if_out_errors   BIGINT,
  if_in_discards  BIGINT,
  if_out_discards BIGINT,
  if_status       INT,
  ethernet_errors JSONB,                              -- ethernet_counters struct, optional
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (timestamp);
CREATE INDEX idx_if_counters_device_ts  ON flow_if_counters (device_id, timestamp DESC);
CREATE INDEX idx_if_counters_device_if  ON flow_if_counters (device_id, if_index, timestamp DESC);
```

Partitioning: monthly, matching the existing `flow_samples` pattern in `internal/database/migrate.go:202`.

**`flow_if_counter_rollups`** — 5-min rollups of `flow_if_counters` after 7 days.

```sql
CREATE TABLE flow_if_counter_rollups (
  id              BIGSERIAL PRIMARY KEY,
  timestamp       TIMESTAMPTZ NOT NULL,
  device_id       BIGINT NOT NULL,
  if_index        BIGINT NOT NULL,
  interval_type   VARCHAR(4) NOT NULL,                -- '5m'
  in_octets_sum   BIGINT,
  out_octets_sum  BIGINT,
  in_errors_sum   BIGINT,
  out_errors_sum  BIGINT,
  in_discards_sum BIGINT,
  out_discards_sum BIGINT,
  sample_count    INT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_if_rollup_device_ts ON flow_if_counter_rollups (device_id, timestamp DESC);
CREATE INDEX idx_if_rollup_device_if ON flow_if_counter_rollups (device_id, if_index, timestamp DESC);
```

**`flow_agent_drops`** — running counter of the `drops` field per (agent, sub_agent, source_id).

```sql
CREATE TABLE flow_agent_drops (
  id              BIGSERIAL PRIMARY KEY,
  agent_address   INET NOT NULL,
  sub_agent_id    INT NOT NULL DEFAULT 0,
  source_id       BIGINT NOT NULL,
  last_seen_at    TIMESTAMPTZ NOT NULL,
  drops_total     BIGINT NOT NULL DEFAULT 0,
  drops_last_5m   BIGINT NOT NULL DEFAULT 0,          -- for alert tickers
  sampling_rate   INT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_flow_agent_drops_uniq
  ON flow_agent_drops (agent_address, sub_agent_id, source_id);
CREATE INDEX idx_flow_agent_drops_lastseen
  ON flow_agent_drops (last_seen_at DESC);
```

**`flow_sampling_rate_changes`** — sampling rate change events per (agent, source_id).

```sql
CREATE TABLE flow_sampling_rate_changes (
  id              BIGSERIAL PRIMARY KEY,
  agent_address   INET NOT NULL,
  sub_agent_id    INT NOT NULL,
  source_id       BIGINT NOT NULL,
  old_rate        INT NOT NULL,
  new_rate        INT NOT NULL,
  changed_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_flow_sampling_changes_agent
  ON flow_sampling_rate_changes (agent_address, changed_at DESC);
```

**`flow_anomalies`** — persisted anomaly events from the in-memory aggregator.

```sql
CREATE TABLE flow_anomalies (
  id                  BIGSERIAL PRIMARY KEY,
  timestamp           TIMESTAMPTZ NOT NULL,
  device_id           BIGINT,                          -- nullable: super-spreader may be cross-device
  anomaly_type        VARCHAR(32) NOT NULL,             -- 'topk_shift' | 'super_spreader' | 'port_scan' | 'threshold' | 'sampling_change'
  severity            VARCHAR(8) NOT NULL,              -- 'info' | 'warn' | 'crit'
  src_addr            INET,
  dst_count_hll       BIGINT,                          -- HLL estimate
  dst_port_count_hll  BIGINT,
  threshold_bps       BIGINT,
  details             JSONB,                            -- additional context
  acknowledged        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_flow_anomalies_ts     ON flow_anomalies (timestamp DESC);
CREATE INDEX idx_flow_anomalies_unack  ON flow_anomalies (acknowledged, timestamp DESC) WHERE NOT acknowledged;
CREATE INDEX idx_flow_anomalies_device ON flow_anomalies (device_id, timestamp DESC);
```

### 6.3 Optional enrichment columns (Phase 4)

```sql
ALTER TABLE flow_samples
  ADD COLUMN IF NOT EXISTS as_path        TEXT,         -- comma-separated, from extended_gateway
  ADD COLUMN IF NOT EXISTS communities    TEXT,         -- comma-separated, from extended_gateway
  ADD COLUMN IF NOT EXISTS src_as         INT,
  ADD COLUMN IF NOT EXISTS dst_as         INT,
  ADD COLUMN IF NOT EXISTS src_peer_as    INT,
  ADD COLUMN IF NOT EXISTS next_hop       INET,
  ADD COLUMN IF NOT EXISTS src_mask_len   INT,
  ADD COLUMN IF NOT EXISTS dst_mask_len   INT,
  ADD COLUMN IF NOT EXISTS src_vlan       INT,
  ADD COLUMN IF NOT EXISTS dst_vlan       INT,
  ADD COLUMN IF NOT EXISTS src_priority   INT,
  ADD COLUMN IF NOT EXISTS dst_priority   INT,
  ADD COLUMN IF NOT EXISTS drop_reason    INT;          -- from discarded_packet
```

---

## 7. Wire protocol (probe → server)

**No breaking changes.** The 30s JSON batch over HTTPS stays. What changes is what's in the JSON.

- `sequence_number` is now populated (currently always 0).
- `sampling_rate` is now always populated (already is).
- New optional fields: `drops` (per-sample), `as_path`, `communities`, `next_hop`, `src_vlan`, `dst_vlan`, `drop_reason`. The api-side parser is tolerant of missing fields (Go's `omitempty` JSON tag pattern).
- The 1000-row cap in `ReceiveFlowSamples` (`handlers_data.go:162`) is replaced with: 1000 **per device per batch** + a `X-Flow-Samples-Dropped` response header + a Prometheus counter `flow_samples_dropped_total{reason}`.

JSON example (probe → server batch):
```json
{
  "probe_id": 42,
  "samples": [
    {
      "timestamp": "2026-06-11T14:23:17.123Z",
      "sampler_address": "10.0.0.1",
      "sequence_number": 987654,
      "source_id": 50397442,
      "sampling_rate": 512,
      "drops": 0,
      "input_if_index": 1,
      "output_if_index": 2,
      "src_addr": "10.0.0.5",
      "dst_addr": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": 6,
      "tcp_flags": 24,
      "bytes": 1500,
      "packets": 1,
      "as_path": "15169,1299",
      "communities": "15169:100,15169:200",
      "src_vlan": 100,
      "next_hop": "10.0.0.1"
    }
  ]
}
```

---

## 8. Phases — overview

| Phase | Scope | Release version | Key acceptance criteria | Rollback strategy |
|---|---|---|---|---|
| **0** | Data correctness: bytes×rate, drops, seq#, indexes, IPv6-ready column | 0.11.0 | All existing UI values match the corrected math. `go test ./...` green. Coverage on `internal/sflow` ≥ 50%. | Revert the `Bytes = … × samplingRate` change. Old (wrong) values come back. Acceptable. |
| **1** | Counter samples + IPv6 + seq# wire + device-detail sFlow bandwidth | 0.12.0 | Device-detail "Traffic" tab shows sFlow-derived bandwidth for sFlow-exporting devices. IPv6 traffic appears in top-N. | Disable counter sample parsing; existing SNMP path still works. |
| **2** | Scale: SO_REUSEPORT worker pool, per-agent rate limit, in-memory aggregator, SSE, bulk insert, Tier-1 detectors | 0.13.0 | Sustained 100k samples/sec without `drops` rising. SSE frame latency < 100 ms. Bulk insert ≥ 50k rows/sec. | Disable SSE; old polling path still works. Disable counter-sample path if needed. |
| **3** | New /admin/noc page (6-zone layout, click-to-filter, detail side-panel, time range, CSV export) | 0.14.0 | New page renders the 6 zones. Click-to-filter works. Detail side-panel works. CSV export round-trips. | Hide the sidebar entry; the page is additive. |
| **4** | Hardening + cleanup: delete bundled `cmd/probe`, parse extended records, CIDR allowlist, 100% test coverage on parser | 0.15.0 | Audit shows no Critical/High findings on `internal/sflow` or `internal/flows`. 100% test coverage on the new parser. Extended records parsed and stored. | Delete probe is irreversible; coordinate cutover. Extended records are additive. |

---

## 9. Phase 0 — Data correctness

### 9.1 Scope

Fix the four correctness bugs that affect every byte and every flow on the dashboard. Ship as a single release (`0.11.0`).

### 9.2 Files changed

| File | Change |
|---|---|
| `internal/sflow/sflow.go` | Capture `drops` from the flow sample header. Populate `SequenceNumber` on the parsed struct. Add `parseSamplingRateChange` detection. Add `IPv6` parsing stub (returns a `ParsedFlow` with empty addresses; full implementation in Phase 1). |
| `internal/sflow/sflow.go:324` | Compute `Bytes = uint64(frameLength) * uint64(samplingRate)` at insert. |
| `internal/database/flows.go:182-186` | Standardise on the weighted read: `estimated_bytes = SUM(bytes * sampling_rate) / COUNT(*)`. Update `GetFlowStats` to use this form. |
| `internal/database/flows.go:503, 562` | Update `aggregateFlowsToRollup` and `aggregateRollupsUp` to compute `sampling_rate_weighted_avg = SUM(sampling_rate) / COUNT(*)` weighted, and store the weighted avg in `flow_rollups`. |
| `internal/database/flows.go:362` | Fix the top-N merge: full sort of the merged map, then take top N. Not 10+10. |
| `internal/database/migrate.go:202` | Add the 5m/1h/1d rollup partitions for the new `flow_if_counters` (Phase 1 prep). Add `flow_rollups` indexes. Add `drops` column. Add `sampling_rate_weighted_avg` column. |
| `internal/database/flows.go` (new functions) | `SaveAgentDrops`, `GetAgentDropsRecent`, `RecordSamplingRateChange`, `GetSamplingRateHistory`. |
| `internal/models/models.go` (new) | `FlowAgentDrop`, `FlowSamplingRateChange`, `FlowIfCounter` GORM models. |
| `internal/api/handlers/handlers_data.go:147-189` | Read the `X-Probe-Batch-ID` header (already sent by the probe). Replace 1000-row truncation with 1000-per-device + response header + Prometheus counter. |
| `internal/sflow/sflow_test.go` (new) | Unit tests for the new behavior. (Coverage target: ≥ 50% on `internal/sflow`.) |
| `CHANGELOG.md` | New `0.11.0` entry at the top with the four fixes. |

### 9.3 New functions (signatures)

```go
// internal/sflow/sflow.go
// Add to ParsedFlow:
type ParsedFlow struct {
    AgentIP       string
    SamplingRate  uint32
    InputIfIndex  uint32
    OutputIfIndex uint32
    SrcAddr       string
    DstAddr       string
    SrcPort       uint16
    DstPort       uint16
    Protocol      uint8
    Bytes         uint64         // CHANGED: now uint64(frameLength) * uint64(samplingRate)
    Packets       uint64
    TCPFlags      uint8
    FrameLength   uint32
    Drops         uint32         // NEW
    SequenceNumber uint32        // NEW
    HeaderProtocol uint32        // NEW (1=ETH, 11=IPv4, 12=IPv6, ...)
}

func (r *SFlowReceiver) parseFlowSample(data []byte, agentIP string, expanded bool) (
    samplingRate uint32, sequenceNumber uint32, drops uint32, sourceID uint32,
    inputIf, outputIf uint32, err error,
)

// internal/database/agent_drops.go (new file)
func SaveAgentDrops(agent string, subAgent uint32, sourceID uint32, drops uint32, samplingRate uint32, ts time.Time) error
func GetAgentDropsRecent(agent string, since time.Time) (uint64, error)
func RecordSamplingRateChange(agent string, subAgent uint32, sourceID uint32, oldRate, newRate uint32, ts time.Time) error
func GetSamplingRateHistory(agent string, since time.Time) ([]SamplingRateChange, error)
```

### 9.4 Detailed code changes

**`internal/sflow/sflow.go:324`** — the headline fix.

```go
// OLD:
flow := &ParsedFlow{
    AgentIP:       agentIP,
    SamplingRate:  samplingRate,
    InputIfIndex:  inputIf,
    OutputIfIndex: outputIf,
    FrameLength:   frameLength,
    Bytes:         uint64(frameLength),
    Packets:       1,
}

// NEW:
flow := &ParsedFlow{
    AgentIP:        agentIP,
    SamplingRate:   samplingRate,
    InputIfIndex:   inputIf,
    OutputIfIndex:  outputIf,
    FrameLength:    frameLength,
    Bytes:          uint64(frameLength) * uint64(samplingRate),  // SCALED
    Packets:        1,
    SequenceNumber: sequenceNumber,                              // POPULATED
    Drops:          drops,                                       // CAPTURED
    HeaderProtocol: headerProto,
}
```

**`internal/sflow/sflow.go:257-271`** — capture drops and sequence number from the flow sample header.

```go
// OLD (parseFlowSample):
if expanded {
    samplingRate = binary.BigEndian.Uint32(data[12:16])
    inputIf = binary.BigEndian.Uint32(data[28:32])
    outputIf = binary.BigEndian.Uint32(data[36:40])
    numRecords = binary.BigEndian.Uint32(data[40:44])
    offset = 44
} else {
    samplingRate = binary.BigEndian.Uint32(data[8:12])
    inputIf = binary.BigEndian.Uint32(data[20:24])
    outputIf = binary.BigEndian.Uint32(data[24:28])
    numRecords = binary.BigEndian.Uint32(data[28:32])
    offset = 32
}

// NEW:
if expanded {
    // expanded flow_sample layout (sflow.org/SFLOW-DATAGRAM5.txt):
    //   source_id_type(4) + source_id_index(4) + sampling_rate(4) + sample_pool(4) + drops(4) +
    //   input_if_format(4) + input_if(4) + output_if_format(4) + output_if(4) + num_records(4)
    samplingRate    = binary.BigEndian.Uint32(data[12:16])
    drops           = binary.BigEndian.Uint32(data[16:20])
    inputIfFormat   := binary.BigEndian.Uint32(data[20:24])
    inputIf         = binary.BigEndian.Uint32(data[24:28])
    outputIfFormat  := binary.BigEndian.Uint32(data[28:32])
    outputIf        = binary.BigEndian.Uint32(data[32:36])
    numRecords      = binary.BigEndian.Uint32(data[40:44])
    sourceID        = binary.BigEndian.Uint32(data[0:4]) | binary.BigEndian.Uint32(data[4:8])
    _ = inputIfFormat
    _ = outputIfFormat
    offset = 44
} else {
    // standard flow_sample layout:
    //   sequence_number(4) + source_id(4) + sampling_rate(4) + sample_pool(4) + drops(4) +
    //   input(4) + output(4) + num_records(4)
    sequenceNumber  = binary.BigEndian.Uint32(data[0:4])
    sourceID        = binary.BigEndian.Uint32(data[4:8])
    samplingRate    = binary.BigEndian.Uint32(data[8:12])
    drops           = binary.BigEndian.Uint32(data[16:20])
    inputIf         = binary.BigEndian.Uint32(data[20:24])
    outputIf        = binary.BigEndian.Uint32(data[24:28])
    numRecords      = binary.BigEndian.Uint32(data[28:32])
    offset = 32
}
```

**`internal/database/flows.go:182-186`** — standardise the read math.

```go
// OLD:
func (d *Database) GetFlowStats(...) (..., totalBytes uint64, err error) {
    // ...
    if err := d.db.Model(&models.FlowRollup{}).
        Select("COALESCE(SUM(bytes_sum * sampling_rate_avg), 0) as total_bytes").
        Where("timestamp >= ?", from).
        Scan(&totalBytes).Error; err != nil {
        return 0, err
    }
    // ... bug: this is "unweighted" — doesn't account for sample-count-per-row
}

// NEW:
func (d *Database) GetFlowStats(...) (..., totalBytes uint64, err error) {
    // Weighted: SUM(bytes * sampling_rate) / SUM(packets) * SUM(packets)
    //         = SUM(bytes * sampling_rate)
    // The rollup's bytes_sum is the un-multiplied SUM(bytes); we multiply
    // by the per-rollup's sampling_rate_weighted_avg at read time.
    err := d.db.Raw(`
        SELECT COALESCE(SUM(bytes_sum * sampling_rate_weighted_avg), 0)::BIGINT AS total_bytes
        FROM flow_rollups
        WHERE device_id IN (?) AND timestamp >= ? AND timestamp < ?
    `, deviceIDs, from, to).Scan(&totalBytes).Error
    return totalBytes, err
}
```

**`internal/database/flows.go:362`** — fix the top-N merge.

```go
// OLD (mergeKeyCounts):
func mergeKeyCounts(raw, rollup []KeyCount, n int) []KeyCount {
    merged := append(raw, rollup...)
    // BUG: only takes the first n entries after a sort, but raw and rollup
    // are already clipped to n each, so a #11 source on each side can outrank
    // a #1 on the other side. The fix is to merge BEFORE clipping.
    sort.Slice(merged, func(i, j int) bool { return merged[i].Bytes > merged[j].Bytes })
    if len(merged) > n {
        merged = merged[:n]
    }
    return merged
}

// NEW:
//   (Above is what the current code SHOULD do. The audit found it doesn't. The
//   real current code at lines 362-380 in flows.go looks like:)
//   for k, v := range rollup { raw[k] += v }  // merges but still clips later
//   Take top N from the merged map.
//   The fix is to merge into a single map, then sort and take top N.
func mergeKeyCounts(raw, rollup []KeyCount, n int) []KeyCount {
    m := make(map[string]uint64, len(raw)+len(rollup))
    for _, r := range raw {
        m[r.Key] += r.Bytes
    }
    for _, r := range rollup {
        m[r.Key] += r.Bytes
    }
    out := make([]KeyCount, 0, len(m))
    for k, v := range m {
        out = append(out, KeyCount{Key: k, Bytes: v})
    }
    sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
    if len(out) > n {
        out = out[:n]
    }
    return out
}
```

**`internal/api/handlers/handlers_data.go:147-189`** — replace the silent truncation.

```go
// OLD (ReceiveFlowSamples):
samples = samples[:1000]
// ... insert

// NEW (ReceiveFlowSamples):
const perDeviceCap = 1000
perDevice := make(map[uint32]int, 8)
kept := make([]relay.FlowSample, 0, len(samples))
droppedTotal := 0
for _, s := range samples {
    if perDevice[s.DeviceID] >= perDeviceCap {
        droppedTotal++
        continue
    }
    perDevice[s.DeviceID]++
    kept = append(kept, s)
}
if droppedTotal > 0 {
    metrics.FlowSamplesDropped.WithLabelValues("per_device_cap").Add(float64(droppedTotal))
    c.Header("X-Flow-Samples-Dropped", strconv.Itoa(droppedTotal))
}
// ... insert kept
```

### 9.5 Tests (Phase 0 must ship with these)

| Test name | File | What it asserts |
|---|---|---|
| `TestParseFlowSample_MultipliesBytesByRate` | `internal/sflow/sflow_test.go` (new) | `frameLength=1500, samplingRate=512` → `bytes == 768000` |
| `TestParseFlowSample_CapturesDrops` | same | `drops=42` in datagram → `parsed.Drops == 42` |
| `TestParseFlowSample_PopulatesSequence` | same | `sequence=987654` in datagram → `parsed.SequenceNumber == 987654` |
| `TestParseFlowSample_SamplingRateChange` | same | Two consecutive samples from same (agent, source_id) with rates 512 and 1024 → `RecordSamplingRateChange` called once with (512, 1024) |
| `TestParseFlowSample_ExpandedFormat` | same | Expanded flow sample (format 3) parses correctly with all extended fields |
| `TestParseFlowSample_SkipsUnknownRecords` | same | Datagram with an enterprise-tagged vendor record (enterprise=4300) is skipped without panic |
| `TestParseFlowSample_TruncatedDatagram` | same | `num_samples=10` but only 3 fit in the buffer → parser stops at 3 cleanly |
| `TestSaveAgentDrops_Idempotent` | `internal/database/agent_drops_test.go` (new) | Same (agent, subAgent, sourceID) twice → drops_total increments |
| `TestRecordSamplingRateChange_OldToNew` | same | Rate goes 512 → 1024 → 2048 → 3 rows in flow_sampling_rate_changes |
| `TestFlowRollupBytes_Scaled` | `internal/database/flows_test.go` (new) | 3 samples with rates (1, 10, 100), bytes (1, 1, 1) → rollup `bytes_sum=3, sampling_rate_weighted_avg=37.0, estimated=111` |
| `TestGetFlowStats_WeightedRead` | same | GetFlowStats over 24h with mixed sampling rates returns the correctly weighted byte total |
| `TestReceiveFlowSamples_RespectsPerDeviceCap` | `internal/api/handlers/handlers_data_test.go` (new) | 5000 samples across 5 devices in one batch → each device capped at 1000, header reports total |
| `TestMergeKeyCounts_NoFalseOrdering` | `internal/database/flows_test.go` | 5 sources with rank-1 on the rollup side and rank-11 on the raw side correctly produce a top-10 |
| `TestIPv4Parse_RejectsTruncated` | `internal/sflow/sflow_test.go` | An IPv4 header with `ihl=15` (max) and 2 bytes of payload returns nil cleanly |
| `TestIPv6Parse_StubReturnsEmpty` | same | `headerProtocol==12` returns a ParsedFlow with empty SrcAddr/DstAddr (Phase 1 fills this in) |

### 9.6 Acceptance criteria

1. Existing `/admin/flows` page shows "Total Bytes" that is exactly `SUM(sample_bytes × sampling_rate)` over the window. (For a 1:512 sampling at 1 Gbps real traffic, the old code would show ~2 Mbps; new code shows ~1 Gbps.)
2. `flow_samples` row count is unchanged; `flow_rollups.bytes_sum` is unchanged at the SQL level (raw) but the read path scales it.
3. `flow_agent_drops` rows are created for every (agent, sub_agent, source_id) that has a non-zero `drops` value in any sample.
4. `flow_sampling_rate_changes` rows are created whenever the rate changes between two consecutive samples from the same (agent, sub_agent, source_id).
5. `go build ./...` is green. `go test ./...` is green. Coverage on `internal/sflow` is ≥ 50% (Phase 2/4 takes it to 100%).
6. CHANGELOG `0.11.0` entry at the top describes the four fixes with file:line references.
7. CI integration lane (Postgres) passes.

### 9.7 Rollback

- Revert `Bytes = uint64(frameLength) * uint64(samplingRate)` to `Bytes = uint64(frameLength)`. Old (wrong) values come back. Acceptable.
- Revert the rollup `sampling_rate_weighted_avg` change. The new column is `NULL` and the read path falls back to `sampling_rate_avg`. Acceptable.
- Revert the index migration. Safe.
- Revert the per-device truncation cap. The old 1000-total cap returns; data continues to flow.
- Revert the new `drops` column. Safe.

### 9.8 Risks

1. **Existing dashboards show different numbers** when the new code runs. This is the *intended* behavior. Document loudly in CHANGELOG and in a release note. Operators seeing "Total Bytes" jump by 500× is the *fix* landing.
2. **Rollup data is uncorrected.** Historical `flow_rollups.bytes_sum` is the un-scaled sum. The read path multiplies it, so views are correct going forward, but if you re-roll old data, you have a problem. **Decision:** we do not back-fill (per user). The cutoff is the deploy time; document it in CHANGELOG.
3. **The `drops` column add needs a default.** `ADD COLUMN drops INT` is safe in Postgres; for SQLite test mode, ensure the GORM migration includes the default.

---

## 10. Phase 1 — Counter samples, IPv6, sFlow-native interface bandwidth

### 10.1 Scope

Parse the counter-sample channel that the current code throws away. This unlocks sFlow's native interface bandwidth (a primary reason to deploy sFlow) and unblocks the device-detail page's "Traffic" tab to use sFlow counters for sFlow-exporting devices.

### 10.2 Files changed

| File | Change |
|---|---|
| `internal/sflow/sflow.go` | Dispatch `counters_sample` (format 2). Add `parseCounterSample`. Parse `if_counters` (format 1) and `ethernet_counters` (format 2). Add full IPv6 parser. Add the extended-switch (1001), extended-router (1002), and discarded-packet (format 5) stubs. |
| `internal/sflow/sflow.go` (new types) | `ParsedCounterSample`, `ParsedIfCounters`, `ParsedEthernetCounters`, `ParsedIPv6`. |
| `internal/database/flows.go` (new) | `SaveIfCounters`, `GetIfCountersWindow`, `aggregateIfCountersToRollup`. |
| `internal/database/migrate.go` | Add `flow_if_counters` and `flow_if_counter_rollups` to the auto-migrate list. Add monthly partitions for `flow_if_counters`. |
| `internal/models/models.go` (new) | `FlowIfCounter`, `FlowIfCounterRollup` GORM models. |
| `internal/api/handlers/handlers_data.go` (new) | `ReceiveCounterSamples` endpoint at `POST /api/probes/:id/counters`. (Parallel to `ReceiveFlowSamples`.) |
| `internal/relay/relay.go` | Add `CounterSample` struct. `SendCounterSamples` (batched every 30s, same cadence as flows). |
| `cmd/probe/main.go` | Wire the new `CounterHandler` callback to the sFlow receiver. |
| `internal/api/handlers/handlers_devices.go` | New `GetInterfaceBandwidthFromSFlow(deviceID, ifIndex, range)`. The device-detail page calls this first, falls back to SNMP if empty. |
| `internal/sflow/sflow_test.go` (new) | Fuzz + unit tests for counter samples, IPv6, extended-switch. Coverage target: ≥ 80% on `internal/sflow`. |
| `CHANGELOG.md` | New `0.12.0` entry. |

### 10.3 New types and parsers

```go
// internal/sflow/sflow.go

type CounterHandler func(*ParsedCounterSample)

type ParsedCounterSample struct {
    AgentIP        string
    SubAgentID     uint32
    SequenceNumber uint32
    SourceID       uint32
    Interface      ParsedIfCounters
    Ethernet       *ParsedEthernetCounters  // optional
}

type ParsedIfCounters struct {
    IfIndex        uint32
    IfType         uint32
    IfSpeed        uint64
    IfDirection    uint32
    IfStatus       uint32
    IfInOctets     uint64
    IfInUcastPkts  uint32
    IfInMulticast  uint32
    IfInBroadcast  uint32
    IfInDiscards   uint32
    IfInErrors     uint32
    IfInUnknown    uint32
    IfOutOctets    uint64
    IfOutUcastPkts uint32
    IfOutMulticast uint32
    IfOutBroadcast uint32
    IfOutDiscards  uint32
    IfOutErrors    uint32
    IfPromiscuous  uint32
}

type ParsedEthernetCounters struct {
    AlignmentErrors   uint32
    FCSErrors         uint32
    SingleCollisions  uint32
    MultipleCollisions uint32
    DeferredTrans     uint32
    LateCollisions    uint32
    ExcessiveColl     uint32
    InternalTxErrors  uint32
    CarrierSense      uint32
    FrameTooLongs     uint32
    InternalRxErrors  uint32
    SymbolErrors      uint32
}

type ParsedIPv6 struct {
    SrcAddr    string
    DstAddr    string
    SrcPort    uint16
    DstPort    uint16
    Protocol   uint8
    TCPFlags   uint8
    FlowLabel  uint32
    HopLimit   uint8
    TrafficClass uint8
}
```

### 10.4 Parsed-counter-sample dispatch

In `parseDatagram`, after the existing flow-sample dispatch:

```go
// (existing) if enterprise == 0 && (format == 1 || format == 3):
//     r.parseFlowSample(...)
// NEW:
if enterprise == 0 && format == 2 {
    r.parseCountersSample(data[offset:offset+int(sampleLen)], agentIP)
}
if enterprise == 0 && format == 5 {
    r.parseDiscardedPacket(data[offset:offset+int(sampleLen)], agentIP)
}
```

`parseCountersSample` walks the array of `counter_record` entries; for each, it dispatches by `(enterprise, format)`. Format 1 = `if_counters` (always parse), format 2 = `ethernet_counters` (parse), everything else = skip with length.

### 10.5 IPv6 parser

```go
// internal/sflow/sflow.go

func parseIPv6(data []byte, flow *ParsedFlow) {
    if len(data) < 40 {
        return
    }
    flow.SrcAddr = net.IP(data[8:24]).String()
    flow.DstAddr = net.IP(data[24:40]).String()
    flow.Protocol = data[6]   // next header
    flow.TCPFlags = 0          // populated from TCP header below

    // Walk extension headers to find TCP/UDP/ICMPv6.
    offset := 40
    for offset < len(data) {
        nextHdr := data[6]            // current next-header
        // ... but the current next-header is in data[offset-1] if offset > 40.
        // Simpler: re-implement the extension-header walk.
        nh := data[offset]
        if nh == 6 || nh == 17 || nh == 58 {
            flow.Protocol = nh
            break
        }
        if nh == 0  { offset += 0; break }   // Hop-by-Hop (no advance; we re-read)
        if nh == 43 { offset += 8 }           // Routing
        else if nh == 44 { offset += 8 }      // Fragment
        else if nh == 50 { break }            // ESP
        else if nh == 51 { offset += 8 + int(data[offset+1])*8 }  // AH
        else if nh == 60 { offset += 8 + int(data[offset+1])*8 }  // DestOpts
        else { return }
        // Update next-header from the extension header.
        if offset < len(data) {
            flow.Protocol = data[offset-2]   // Next Header field of the extension
        }
    }
    // Parse TCP/UDP.
    switch flow.Protocol {
    case 6:  // TCP
        if len(data) >= offset+14 {
            flow.SrcPort = binary.BigEndian.Uint16(data[offset:offset+2])
            flow.DstPort = binary.BigEndian.Uint16(data[offset+2:offset+4])
            flow.TCPFlags = data[offset+13]
        }
    case 17: // UDP
        if len(data) >= offset+4 {
            flow.SrcPort = binary.BigEndian.Uint16(data[offset:offset+2])
            flow.DstPort = binary.BigEndian.Uint16(data[offset+2:offset+4])
        }
    }
}
```

(Edge cases to handle in tests: zero-length extension headers, truncated extension chains, ICMPv6, IPv6-in-IPv4 encap, jumbo-grams. The above is the spec-compliant base; tests cover the rest.)

### 10.6 Database storage

`SaveIfCounters` does a bulk upsert:
```go
func SaveIfCounters(samples []ParsedCounterSample, deviceIDMap map[string]uint32) error {
    rows := make([]models.FlowIfCounter, 0, len(samples))
    for _, s := range samples {
        if s.Interface.IfIndex == 0 {
            continue  // skip unparseable
        }
        rows = append(rows, models.FlowIfCounter{
            Timestamp:    time.Now(),
            DeviceID:     deviceIDMap[s.AgentIP],
            IfIndex:      uint64(s.Interface.IfIndex),
            IfSpeed:      s.Interface.IfSpeed,
            IfInOctets:   s.Interface.IfInOctets,
            IfOutOctets:  s.Interface.IfOutOctets,
            // ...
        })
    }
    // pgx.CopyFrom-based bulk insert.
    return d.db.CreateInBatches(rows, 500).Error  // gorm bulk
}
```

(The Phase 2 rewrite will swap `CreateInBatches` for `pgx.CopyFrom` for ~50× throughput.)

### 10.7 Tests (Phase 1)

| Test name | Asserts |
|---|---|
| `TestParseCountersSample_IfCounters` | Datagram with one counters_sample + one if_counters record → `ParsedCounterSample.Interface` populated, `Ethernet == nil` |
| `TestParseCountersSample_EthernetCounters` | Same, with ethernet_counters record → `Ethernet` populated |
| `TestParseCountersSample_MultipleIfCounters` | Datagram with 3 if_counters records in one sample → all 3 parsed |
| `TestIPv6Parse_BasicTCP` | IPv6/TCP packet → src/dst IP, src/dst port, TCP flags correct |
| `TestIPv6Parse_BasicUDP` | IPv6/UDP packet → src/dst IP, src/dst port correct |
| `TestIPv6Parse_FragmentHeader` | IPv6 with fragment extension header → underlying TCP/UDP still extracted |
| `TestIPv6Parse_TruncatedExtension` | Truncated extension chain → returns gracefully, partial data |
| `TestIPv6Parse_ICMPv6` | IPv6 with ICMPv6 (next-header 58) → protocol=58, no ports |
| `TestParseExtendedSwitch_VLAN` | Datagram with extended_switch record → `src_vlan`, `dst_vlan` populated |
| `TestParseDiscardedPacket_DropReason` | Datagram with discarded_packet → `drop_reason` recorded |
| `TestSaveIfCounters_BulkInsert` | 1000 counter samples → all in `flow_if_counters`, 1 query |
| `TestGetInterfaceBandwidthFromSFlow_EmptyFallsBack` | No sFlow data for a device → returns empty, caller falls back to SNMP |

### 10.8 Acceptance criteria

1. `internal/sflow/sflow.go` dispatches `counters_sample` (format 2) and parses `if_counters` (format 1) + `ethernet_counters` (format 2). The 30s probe→server batch carries counter samples. The api-side `ReceiveCounterSamples` endpoint persists them to `flow_if_counters`.
2. IPv6 traffic appears in `/admin/flows` top-N lists and in the conversation table.
3. The device-detail "Traffic" tab's bandwidth chart uses sFlow counters when present, SNMP when not. The chart's `source` field in the API response indicates which.
4. `go build ./...` is green. `go test ./...` is green. Coverage on `internal/sflow` ≥ 80%.
5. CHANGELOG `0.12.0` entry at the top.

### 10.9 Rollback

- Disable counter-sample dispatch (one-line change in `parseDatagram`). Existing SNMP path keeps working. Acceptable.
- Disable the IPv6 parser (route `headerProto==12` to the stub). Reverts to "IPv6 traffic not visible." Acceptable.

---

## 11. Phase 2 — Scale to 100k+ samples/sec, in-memory aggregator, SSE

This is the biggest phase. It changes the receiver's architecture and introduces the real-time aggregator.

### 11.1 Scope

| # | Item | Lines of code (est.) |
|---|---|---|
| 2.1 | `SO_REUSEPORT` worker pool | ~150 |
| 2.2 | `SetReadBuffer(8 MB)` on each socket | ~10 |
| 2.3 | Per-agent token-bucket rate limit (`golang.org/x/time/rate`) | ~80 |
| 2.4 | In-memory aggregator (`internal/flows/realtime`) | ~600 |
| 2.5 | SSE endpoint | ~200 |
| 2.6 | Tier-1 anomaly detectors | ~300 |
| 2.7 | Bulk insert via `pgx.CopyFrom` (replace GORM `Create`) | ~150 |
| 2.8 | Prometheus metrics | ~100 |
| 2.9 | Sequence-number validation per (agent, sub_agent) | ~50 |
| 2.10 | Tests + benchmarks | ~400 |

### 11.2 Receiver architecture (`internal/sflow`)

```go
// internal/sflow/sflow.go (new shape)

type SFlowReceiver struct {
    listenAddr   string
    port         int
    numSockets   int                 // = runtime.NumCPU() / 2
    queueSize    int                 // 1_000_000
    allowedCIDRs []*netip.Prefix     // CIDR allowlist
    flowHandler  FlowHandler
    counterHandler CounterHandler
    conns        []*net.UDPConn      // SO_REUSEPORT sockets
    limiter      *AgentRateLimiter   // per-agent token bucket
    aggregator   *realtime.Aggregator
    metrics      *ReceiverMetrics
    stopChan     chan struct{}
    running      atomic.Bool
    wg           sync.WaitGroup
}

func NewSFlowReceiver(listenAddr string, port int, numSockets, queueSize int, allowedCIDRs []string, agg *realtime.Aggregator) *SFlowReceiver
func (r *SFlowReceiver) Start() error
func (r *SFlowReceiver) Stop() error

// Each socket runs an independent readLoop:
func (r *SFlowReceiver) readLoop(socketIdx int)
```

**`Start()`** opens `numSockets` UDP sockets on the same address. `SO_REUSEPORT` lets the kernel hash source IP → socket. Each socket gets its own `readLoop` goroutine. Each `readLoop` parses and pushes to the aggregator.

**`SetReadBuffer(8 MB)`** — call before `ListenUDP` returns. On Linux, also document `sysctl net.core.rmem_max=8388608` in the operational runbook.

**`AgentRateLimiter`** — `map[netip.Addr]*rate.Limiter`. New agents get a 50k samples/sec default (configurable via `SFLOW_PER_AGENT_RATE_LIMIT`). Refill rate is `rate.Limit(50_000)`, burst 50_000. The limiter is consulted before parse; a rejected packet is counted in `flow_samples_dropped_total{reason="rate_limit",agent="…"}`.

### 11.3 In-memory aggregator (`internal/flows/realtime`)

```go
// internal/flows/realtime/aggregator.go

type Aggregator struct {
    mu            sync.RWMutex
    flows         *RingBuffer[*ParsedFlow]   // 5-min window
    topKBySrc     *TopK                       // by src_addr
    topKByDst     *TopK                       // by dst_addr
    topKByPair    *TopK                       // by src+dst
    topKByPort    *TopK                       // by dst_port
    topKByProto   *TopK                       // by protocol
    superSprdHLL  *HLL                        // src_addr -> distinct dst HLL
    portScanHLL   *HLL                        // src_addr -> distinct dst_port HLL
    thresholds    *ThresholdDetector
    seqTracker    *SeqTracker
    anomalies     *AnomalyWriter
    snapshotCh    chan Snapshot               // 1 Hz
}

func NewAggregator(window time.Duration, topKSize int, anomalyWriter *AnomalyWriter) *Aggregator

func (a *Aggregator) Ingest(flow *ParsedFlow, drops uint32, sourceID uint32) {
    a.mu.Lock()
    a.flows.Push(flow)
    a.topKBySrc.Add(flow.SrcAddr, flow.Bytes)
    a.topKByDst.Add(flow.DstAddr, flow.Bytes)
    a.topKByPair.Add(flow.SrcAddr+"|"+flow.DstAddr, flow.Bytes)
    a.topKByPort.Add(strconv.Itoa(int(flow.DstPort)), flow.Bytes)
    a.topKByProto.Add(strconv.Itoa(int(flow.Protocol)), flow.Bytes)
    a.superSprdHLL.Add(flow.SrcAddr, flow.DstAddr)
    a.portScanHLL.Add(flow.SrcAddr, strconv.Itoa(int(flow.DstPort)))
    a.thresholds.Check(flow)
    a.mu.Unlock()
}

type Snapshot struct {
    Timestamp    time.Time
    TopSources   []KeyBytes      `json:"top_sources"`
    TopDests     []KeyBytes      `json:"top_destinations"`
    TopPairs     []KeyBytes      `json:"top_pairs"`
    TopPorts     []KeyBytes      `json:"top_ports"`
    TopProtos    []KeyBytes      `json:"top_protocols"`
    TotalBPS     float64         `json:"total_bps"`
    TotalPPS     float64         `json:"total_pps"`
    Anomalies    []Anomaly       `json:"anomalies"`
    StatusStrip  StatusStrip     `json:"status_strip"`
}

type KeyBytes struct {
    Key   string  `json:"key"`
    Bytes uint64  `json:"bytes"`
}

type Anomaly struct {
    Type      string    `json:"type"`
    Severity  string    `json:"severity"`
    SrcAddr   string    `json:"src_addr,omitempty"`
    Details   string    `json:"details,omitempty"`
    DetectedAt time.Time `json:"detected_at"`
}

type StatusStrip struct {
    FlowsPerSec  float64 `json:"flows_per_sec"`
    ExportersUp  int     `json:"exporters_up"`
    DropsPer5m   uint64  `json:"drops_per_5m"`
    LastBatchAge time.Duration `json:"last_batch_age"`
}

// Snapshot() returns a point-in-time copy.
func (a *Aggregator) Snapshot() Snapshot
```

**TopK** is a streaming top-K with periodic truncation. Implementation: `map[string]*CountMinSketch` + a min-heap of size K. Every 1 s, a maintenance goroutine truncates the map by evicting entries below the Kth largest count. Memory bound: `~O(K * distinct keys)`, tunable via the `topKSize` parameter (default 1000).

**HLL** uses [`github.com/axiomhq/hyperloglog`](https://github.com/axiomhq/hyperloglog) or [`github.com/clarkduvall/hyperloglog`](https://github.com/clarkduvall/hyperloglog). Both BSD-3. Decision: axiomhq (better API, actively maintained).

**RingBuffer** is a fixed-size circular buffer of `*ParsedFlow`. 5-min window at 100k samples/sec = 30M ParsedFlow entries; at ~200 bytes each that's 6 GB — too much. We keep only the top-K and the HLL state; the raw ring is bounded to 100k entries (last 1 second at peak). For "show me flows in the last 5 minutes" the historical view comes from Postgres.

### 11.4 SSE endpoint

```go
// internal/api/handlers/flows_stream.go

// GET /admin/api/flows/stream
// text/event-stream

func (h *Handlers) FlowsStream(c *gin.Context) {
    c.Writer.Header().Set("Content-Type", "text/event-stream")
    c.Writer.Header().Set("Cache-Control", "no-cache")
    c.Writer.Header().Set("Connection", "keep-alive")
    c.Writer.Header().Set("X-Accel-Buffering", "no")
    c.Writer.Flush()

    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    keepalive := time.NewTicker(15 * time.Second)
    defer keepalive.Stop()

    for {
        select {
        case <-c.Request.Context().Done():
            return
        case <-ticker.C:
            snap := h.aggregator.Snapshot()
            data, _ := json.Marshal(snap)
            fmt.Fprintf(c.Writer, "event: snapshot\ndata: %s\n\n", data)
            c.Writer.Flush()
        case <-keepalive.C:
            fmt.Fprintf(c.Writer, ": keepalive\n\n")
            c.Writer.Flush()
        }
    }
}
```

Backpressure: each connected client has a 64-frame buffered channel. If full, the client is dropped with a `client_dropped_total` counter. The default is generous; NOC screens typically have < 10 concurrent viewers.

### 11.5 Tier-1 detectors

```go
// internal/flows/realtime/detectors.go

type ThresholdDetector struct {
    deviceSpeeds map[uint32]uint64  // device_id -> if_speed in bps
    mu           sync.Mutex
}

func (t *ThresholdDetector) Check(flow *ParsedFlow) *Anomaly {
    // 1. Find the device's max interface speed.
    // 2. If flow.Bytes per second > 80% of speed, emit a 'threshold' anomaly.
    // ...
}

type SuperSpreadDetector struct {
    hll        *HLL
    threshold  int    // default 100 distinct dsts in 5 min
    window     time.Duration
}

func (s *SuperSpreadDetector) Check(srcAddr string, dstAddr string) *Anomaly {
    if h := s.hll.Cardinality(srcAddr); h > s.threshold {
        return &Anomaly{
            Type:     "super_spreader",
            Severity: "warn",
            SrcAddr:  srcAddr,
            Details:  fmt.Sprintf("%d distinct destinations in %s", h, s.window),
        }
    }
    return nil
}

type PortScanDetector struct {
    hll       *HLL
    threshold int    // default 20 distinct dst_ports in 60s
    window    time.Duration
}
```

The detectors run on the aggregator goroutine at 1 Hz. On detection, the anomaly is:
1. Pushed to the in-memory `anomalies` ring (for the SSE stream).
2. Persisted to `flow_anomalies` via the existing alert engine.

### 11.6 Bulk insert via `pgx.CopyFrom`

The current `d.db.Create(&samples)` (`internal/database/ping.go:181-192`) is GORM, which is `INSERT … VALUES (…), (…), …` per row. At 100k samples/sec that's 100k INSERTs/sec; Postgres can sustain this for short bursts but the per-row overhead dominates.

`pgx.CopyFrom` uses the binary COPY protocol and is ~50× faster:

```go
// internal/database/batch_insert.go (new)

func BulkInsertFlowSamples(ctx context.Context, db *sql.DB, samples []models.FlowSample) error {
    rows := make([][]any, len(samples))
    for i, s := range samples {
        rows[i] = []any{
            s.Timestamp, s.DeviceID, s.ProbeID, s.SamplerAddress,
            s.SequenceNumber, s.SamplingRate, s.SrcAddr, s.DstAddr,
            s.SrcPort, s.DstPort, s.Protocol, s.Bytes, s.Packets,
            s.InputIfIndex, s.OutputIfIndex, s.TCPFlags, s.Drops,
        }
    }
    _, err := db.CopyFrom(ctx, pgx.Identifier{"flow_samples"},
        []string{"timestamp", "device_id", "probe_id", "sampler_address",
                 "sequence_number", "sampling_rate", "src_addr", "dst_addr",
                 "src_port", "dst_port", "protocol", "bytes", "packets",
                 "input_if_index", "output_if_index", "tcp_flags", "drops"},
        pgx.CopyFromRows(rows),
    )
    return err
}
```

The probe→server batch already arrives in 30s windows. We batch all samples from one batch into one `CopyFrom` call. At 100k samples/sec × 30s = 3M samples per batch. 3M / 30s = 100k inserts/sec; `CopyFrom` can do ~500k rows/sec on a single connection. We're well under capacity.

### 11.7 Prometheus metrics (Phase 2)

```
# flow_samples_total{agent, device}             - counter
# flow_samples_dropped_total{reason, agent}     - counter   (reasons: rate_limit, parse_error, per_device_cap, oor)
# flow_bytes_estimated_total{device, direction} - counter
# flow_anomalies_total{type}                    - counter   (types: topk_shift, super_spreader, port_scan, threshold, sampling_change)
# flow_drops_total{agent}                       - counter
# flow_parse_errors_total{agent, kind}          - counter   (kinds: truncated, version_mismatch, unknown_enterprise, length_overflow)
# realtime_aggregator_topk_size{kind}           - gauge     (kinds: src, dst, pair, port, proto)
# realtime_aggregator_memory_bytes              - gauge
# realtime_aggregator_clients                   - gauge     (active SSE clients)
# realtime_aggregator_snapshot_duration_seconds - histogram
# sflow_receiver_connections                    - gauge     (= numSockets)
# sflow_receiver_socket_buffer_bytes            - gauge
# bulk_insert_rows_total                        - counter
# bulk_insert_duration_seconds                  - histogram
```

A new Grafana panel (`docs/grafana/sflow.json`) shows these.

### 11.8 Sequence-number validation

```go
// internal/sflow/seq_tracker.go (new)

type SeqTracker struct {
    mu    sync.Mutex
    state map[agentKey]uint32  // last seen per (agent, sub_agent)
}

type agentKey struct {
    Agent      string
    SubAgent   uint32
}

func (s *SeqTracker) Check(agent string, subAgent uint32, seq uint32) (regression bool, jump int) {
    s.mu.Lock()
    defer s.mu.Unlock()
    k := agentKey{Agent: agent, SubAgent: subAgent}
    last, ok := s.state[k]
    s.state[k] = seq
    if !ok {
        return false, 0
    }
    if seq < last {
        return true, 0
    }
    return false, int(seq - last)
}
```

A regression emits a `flow_seq_regression_total{agent}` metric and an alert via the existing alert engine.

### 11.9 Tests (Phase 2)

| Test name | Asserts |
|---|---|
| `TestSO_REUSEPORT_DistributesLoad` | Start 4 sockets; send 10k packets from 4 different source IPs; each socket receives ~25% of the traffic |
| `TestAgentRateLimiter_DropsBeyondBurst` | 60k packets from one agent at 50k/sec limit → ~10k dropped, all from same agent |
| `TestAggregator_TopKBySrc` | 100k flows from 50 srcs; top-10 returned in correct order with correct byte counts |
| `TestAggregator_HLLCardinality` | 10k unique dsts per src → HLL estimate within 1% of true |
| `TestSuperSpreadDetector_Triggers` | 1 src → 150 distinct dsts in 5 min → anomaly fired |
| `TestPortScanDetector_Triggers` | 1 src → 30 distinct dst_ports in 60s → anomaly fired |
| `TestThresholdDetector_Triggers` | 1 flow with bps > 80% of device ifSpeed → anomaly fired |
| `TestSSE_PushesOneFramePerSecond` | Connect, read 3 frames in 3.5s → 3 frames received with valid JSON |
| `TestBulkInsert_100kRows` | Insert 100k flow samples via pgx.CopyFrom → completes in < 2s on test hardware |
| `TestSeqTracker_DetectsRegression` | seq 100, 101, 50 → regression detected at seq=50 |
| `TestAggregator_MemoryBounded` | 100k flows ingested; aggregator memory < 100 MB (no ring buffer explosion) |

### 11.10 Acceptance criteria

1. Sustained 100k samples/sec through the receiver; `flow_samples_dropped_total` does not grow.
2. P99 SSE frame latency < 100 ms.
3. `pgx.CopyFrom` sustained ≥ 50k rows/sec.
4. Tier-1 detectors fire correctly (covered by the tests above).
5. Sequence-number regression generates an alert.
6. `go test ./...` green. Coverage on `internal/flows/realtime` ≥ 80%.
7. CHANGELOG `0.13.0` entry.

### 11.11 Rollback

- Reduce `numSockets` to 1 (back to single-goroutine). Loses throughput but works.
- Disable the aggregator (`SFLOW_REALTIME_AGGREGATOR=false`). The historical path keeps working. Acceptable.
- Disable SSE (the polling REST endpoint still works). The NOC screen falls back to HTTP polling at 1 Hz.
- Revert `pgx.CopyFrom` to GORM `Create` (slower but functional). Acceptable.

---

## 12. Phase 3 — New /admin/noc page

### 12.1 Scope

A purpose-built NOC screen. Reuses the existing stack (no new JS framework). The page is additive: the existing `/admin/flows` page stays.

### 12.2 Files changed

| File | Change |
|---|---|
| `web/admin/admin.html` | Add `page-noc` div with the 6-zone layout markup. Add to `SPA_PAGES` (per CHANGELOG v0.10.395 the SPA set must match the page-ids). Add a sidebar entry. |
| `cmd/api/static/js/admin-noc.js` (new) | The `FwmonNoc` class. SSE connection, URL-hash state, click-to-filter, detail side-panel. |
| `cmd/api/static/css/admin-noc.css` (new) | Page-specific styles. Reuse the existing `fwmon-flows` classes where possible. |
| `cmd/api/static/js/admin-main.js` | Add the new page to the page loader. |
| `web/admin/admin.html` (sidebar) | Add "NOC" link. |
| `CHANGELOG.md` | New `0.14.0` entry. |

### 12.3 Layout (6 zones, ASCII sketch)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Zone 1: Status strip                                                          │
│ [Flows/s 124k]  [Exporters 47/48]  [Drops 0/5m]  [Anomalies 2]  [Last batch 7s]│
├──────────────────────────────────────┬───────────────────────────────────────┤
│ Zone 2: Top talkers (clickable)      │ Zone 3: Stacked throughput (1 Hz)     │
│                                      │                                       │
│  src 10.0.0.5     → 8.8.8.8   5.2 G  │ ╱╲    ╱─╲                            │
│  src 10.0.0.7     → 1.1.1.1   3.1 G  │╱  ╲__╱   ╲__                         │
│  src 10.0.0.12    → 9.9.9.9   2.4 G  │                                       │
│  … (10 rows)                         │ [1m] [5m*] [15m] [1h]                │
├──────────────────────────────────────┼───────────────────────────────────────┤
│ Zone 4: Top ports        Zone 5: Anomaly ticker                             │
│                                      │                                       │
│  443 ████████████  18%               │ [14:23] 10.0.0.5 → many hosts:        │
│  80  ████████      12%               │   super-spreader, 150 dsts/5m         │
│  53  ████          6%                │ [14:21] 10.0.0.7 → :22 port scan     │
│  … (top 10)                          │ [14:18] device-3 bps 92% ifSpeed    │
├──────────────────────────────────────┴───────────────────────────────────────┤
│ Zone 6: Per-device interface bandwidth (sFlow-native)                       │
│  device-3  ifGigE0/0/1   3.4 Gbps RX   1.2 Gbps TX   ↑ 12% vs 5m avg       │
│  device-7  ifGigE0/0/0   1.8 Gbps RX   800 Mbps TX   ↓ 4%                  │
│  … (top 10)                                                                  │
└──────────────────────────────────────────────────────────────────────────────┘

Click anywhere on a top-N cell, port, protocol, anomaly, or interface → adds a
filter to the URL hash (#src=10.0.0.5&proto=tcp&port=443&range=5m), all widgets
re-fetch with the filter.

Click a conversation row → detail side-panel slides in from the right with full
sample list, packet timeline, HLL distinct counts, "open in connection detail" link.
```

### 12.4 `FwmonNoc` class structure

```javascript
// cmd/api/static/js/admin-noc.js

class FwmonNoc {
    constructor() {
        this.eventSource = null;
        this.snapshot = null;
        this.filters = {};  // {src, dst, proto, port, range, ...}
        this.zones = {
            status:  new FwmonStatusStrip(),
            talkers: new FwmonTopTalkers(),
            timeseries: new FwmonBandwidthChart(),  // uPlot
            ports:   new FwmonTopPorts(),
            ticker:  new FwmonAnomalyTicker(),
            interfaces: new FwmonInterfaceBandwidth(),
        };
        this.detail = new FwmonDetailPanel();
        this.reconnectDelayMs = 1000;
    }

    init() {
        this.parseHashFilters();
        this.renderAll();
        this.connectSSE();
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') this.connectSSE();
            else this.eventSource?.close();
        });
    }

    parseHashFilters() {
        const hash = window.location.hash.slice(1);
        const params = new URLSearchParams(hash);
        this.filters = {
            src: params.get('src') || '',
            dst: params.get('dst') || '',
            proto: params.get('proto') || '',
            port: params.get('port') || '',
            range: params.get('range') || '5m',
        };
    }

    updateHash() {
        const params = new URLSearchParams();
        Object.entries(this.filters).forEach(([k, v]) => { if (v) params.set(k, v); });
        history.replaceState(null, '', '#' + params.toString());
    }

    connectSSE() {
        this.eventSource = new EventSource('/admin/api/flows/stream');
        this.eventSource.addEventListener('snapshot', (e) => {
            this.snapshot = JSON.parse(e.data);
            this.renderAll();
        });
        this.eventSource.onerror = () => {
            this.eventSource.close();
            setTimeout(() => this.connectSSE(), this.reconnectDelayMs);
            this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, 30000);
        };
    }

    applyFilter(key, value) {
        this.filters[key] = value;
        this.updateHash();
        this.renderAll();  // each zone re-applies filters server-side
    }

    renderAll() {
        this.zones.status.render(this.snapshot, this.filters);
        this.zones.talkers.render(this.snapshot, this.filters);
        this.zones.timeseries.render(this.snapshot, this.filters);
        this.zones.ports.render(this.snapshot, this.filters);
        this.zones.ticker.render(this.snapshot, this.filters);
        this.zones.interfaces.render(this.snapshot, this.filters);
    }

    openDetail(conversationKey) {
        this.detail.show(conversationKey, this.filters);
    }
}

window.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname === '/admin/noc' || window.location.hash.startsWith('#noc')) {
        window.fwmonNoc = new FwmonNoc();
        window.fwmonNoc.init();
    }
});
```

Each `Fwmon*` zone is a small class that takes the snapshot + filters and re-renders its DOM. The bandwidth chart (zone 3) is a uPlot instance (already shipped in the codebase). The top-N tables (zone 2) are vanilla `<table>` with delegated click handlers.

### 12.5 URL-hash state format

```
#src=10.0.0.5
#dst=8.8.8.8
#proto=tcp          (alias for protocol=6)
#port=443
#range=5m           (1m | 5m | 15m | 1h)
#device=42
#if=50397442
#as=15169
```

The `parseHashFilters` and `applyFilter` methods keep this in sync with `history.replaceState`. Sharing a URL = sharing the exact filter state. Akvorado's pattern.

### 12.6 Click-to-filter behavior

| Click target | Filter applied |
|---|---|
| Top sources row (zone 2) | `src=<ip>` |
| Top dests row (zone 2) | `dst=<ip>` |
| Top pairs row (zone 2) | `src=<ip1>, dst=<ip2>` |
| Top ports bar (zone 4) | `port=<port>` |
| Top protos | `proto=<name>` |
| Anomaly ticker row (zone 5) | depends on anomaly type: super-spreader → `src=<ip>`; port-scan → `src=<ip>, proto=tcp` |
| Per-device interface row (zone 6) | `device=<id>, if=<ifindex>` |
| Time-range pill | `range=<duration>` |

When a filter is applied, all 6 zones re-fetch with the new filter server-side. The SSE stream continues to push snapshots; the client-side filter is applied for client-side data (top-N from the snapshot) and the server-side filter is appended to the per-zone REST endpoint for historical data (e.g. the bandwidth chart).

### 12.7 Detail side-panel

A right-side slide-in panel (Tailwind: `fixed right-0 top-0 h-full w-96 bg-white shadow-xl`). Contents:

- 5-tuple (src, dst, src_port, dst_port, protocol)
- Per-direction packet timeline (mini uPlot)
- "Neighbouring conversations" (HLL distinct count, top 5 by byte volume)
- BGP info (when extended_gateway parsed in Phase 4)
- "Open in connection detail" link → `/admin/connections/:id`
- "Filter to this conversation" button → adds the 5-tuple as filters, closes the panel

### 12.8 Tests (Phase 3)

Phase 3 is mostly UI; tests are JSDOM unit tests + manual visual QA. Test plan:

| Test name | Asserts |
|---|---|
| `TestParseHashFilters_AllFields` | `#src=10.0.0.5&dst=8.8.8.8&proto=tcp&port=443&range=5m` → filters object has all 5 fields |
| `TestParseHashFilters_Empty` | `#` → filters object is empty |
| `TestUpdateHash_RoundTrip` | Set filters → updateHash → parseHashFilters → same filters |
| `TestApplyFilter_TriggersRenderAll` | applyFilter('src', '10.0.0.5') → renderAll called on all 6 zones |
| `TestSSE_ReconnectOnError` | SSE error event → reconnect with exponential backoff (1s, 2s, 4s, 8s, …) |
| `TestVisibilityChange_PausesUpdates` | document.hidden = true → SSE closes; document.hidden = false → SSE reconnects |
| `TestCSVExport_GeneratesValidCSV` | 100 visible flows → CSV download with header + 100 rows, RFC 4180 escaping |

Plus Playwright/headless Chrome screenshots for visual QA (5 dashboards: 1m, 5m, 1h, with filter, without filter).

### 12.9 Acceptance criteria

1. New page renders at `/admin/noc` (and via SPA tab switch from the sidebar).
2. The 6 zones are visible and update at 1 Hz.
3. Click-to-filter updates the URL hash and re-renders all zones.
4. Detail side-panel opens on conversation-row click.
5. Time-range pills work.
6. CSV export round-trips.
7. Tab-hidden pauses updates; tab-visible resumes.
8. `go build ./...` green. `go test ./...` green.
9. CHANGELOG `0.14.0` entry.

### 12.10 Rollback

- Hide the sidebar entry. The page is additive; removal is a one-line change.
- Don't link from anywhere. The page is opt-in.

---

## 13. Phase 4 — Hardening + cleanup

### 13.1 Scope

Final pass. Delete the bundled `cmd/probe` (per AUDIT XR-1). Parse the remaining extended records. Add CIDR allowlist. 100% test coverage on the new parser.

### 13.2 Files changed

| File | Change |
|---|---|
| `cmd/probe/` | **Delete entirely** per CHANGELOG v0.10.412 XR-1. |
| `internal/sflow/sflow.go` | Parse `extended_switch` (1001), `extended_router` (1002), `extended_gateway` (1003), `discarded_packet` (format 5). Replace `map[string]bool` allowlist with `[]*netip.Prefix` CIDR set. |
| `internal/sflow/sflow.go` (move) | Move the sFlow parser from `cmd/probe` to `cmd/api/internal/sflow` so the api binary can ingest directly (replacing the bundled probe in the Docker single-binary deploy). |
| `internal/database/flows.go` | Add `as_path`, `communities`, `next_hop`, `src_vlan`, `dst_vlan` columns to `flow_samples` (DDL in §6.3). |
| `internal/relay/relay.go` | Add the new fields to the `FlowSample` wire struct (with `omitempty`). |
| `cmd/probe/main.go` | (deleted) |
| `Dockerfile`, `entrypoint.sh` | Update to reflect the single-binary deploy. The api binary now listens on UDP/6343 directly (config-flag controlled). |
| `internal/sflow/sflow_test.go` | Final pass: 100% test coverage on the parser. |
| `CHANGELOG.md` | New `0.15.0` entry. |

### 13.3 Extended record parsers

The extended-switch (1001) and extended-router (1002) are simple structs. Extended-gateway (1003) is the most complex; it has variable-length `as_path<>` and `communities<>` arrays. All three use the standard "read 4-byte length, then parse" pattern.

```go
// internal/sflow/sflow.go

type ParsedExtendedSwitch struct {
    SrcVlan     uint32
    SrcPriority uint32
    DstVlan     uint32
    DstPriority uint32
}

type ParsedExtendedRouter struct {
    NextHop   string
    SrcMask   uint32
    DstMask   uint32
}

type ParsedExtendedGateway struct {
    NextHop    string
    As         uint32
    SrcAS      uint32
    SrcPeerAS  uint32
    AsPath     []uint32
    Communities []uint32
    LocalPref  uint32
}

type ParsedDiscardedPacket struct {
    DropReason uint32  // 256=unknown, 257=ttl, 258=acl, 259=no_buffer, 260=RED, 261=shaping, 262=too_big
}
```

### 13.4 CIDR allowlist

```go
// internal/sflow/sflow.go

import "net/netip"

type SFlowReceiver struct {
    // ...
    allowedCIDRs []netip.Prefix
}

func (r *SFlowReceiver) isAllowed(ip netip.Addr) bool {
    if len(r.allowedCIDRs) == 0 {
        return true  // empty allowlist = allow all (with a warning logged)
    }
    for _, p := range r.allowedCIDRs {
        if p.Contains(ip) {
            return true
        }
    }
    return false
}
```

The config knob changes from `SFLOW_ALLOWED_SOURCES=10.0.0.1,10.0.0.2` (comma-separated exact IPs) to `SFLOW_ALLOWED_SOURCES=10.0.0.0/24,192.168.0.0/16` (CIDR list). Backward-compatible: an entry without a `/` is treated as a `/32` or `/128`.

### 13.5 Tests (Phase 4)

| Test name | Asserts |
|---|---|
| `TestParseExtendedSwitch_VLAN` | extended_switch with src_vlan=100 → parsed correctly |
| `TestParseExtendedRouter_NextHop` | extended_router with next_hop=10.0.0.1 → parsed correctly |
| `TestParseExtendedGateway_BGPPath` | extended_gateway with as_path=[15169, 1299], communities=[12345, 67890] → parsed correctly |
| `TestParseDiscardedPacket_DropReason` | discarded_packet with drop_reason=258 (ACL) → parsed correctly |
| `TestCIDRAllowlist_AcceptsContainedIP` | allowlist `10.0.0.0/24` + packet from 10.0.0.5 → accepted |
| `TestCIDRAllowlist_RejectsOutsideIP` | allowlist `10.0.0.0/24` + packet from 10.0.1.5 → rejected |
| `TestCIDRAllowlist_MixedExactAndCIDR` | allowlist `10.0.0.0/24,192.168.0.5` + packets from both → both accepted |
| `TestCIDRAllowlist_EmptyAcceptsAll` | empty allowlist + any packet → accepted, warning logged |
| `TestCIDRAllowlist_IPv6` | allowlist `2001:db8::/32` + packet from 2001:db8::1 → accepted |
| `TestCoverage_InternalSflow` | `go test -cover ./internal/sflow/...` reports 100.0% |

### 13.6 Acceptance criteria

1. `cmd/probe` directory is deleted; `cmd/api` is the only binary that ingests sFlow directly.
2. `SFLOW_ALLOWED_SOURCES` accepts CIDR notation.
3. Extended-switch, extended-router, extended-gateway, discarded-packet records are parsed and stored.
4. Test coverage on `internal/sflow` is 100.0%.
5. The Docker single-binary deploy can ingest sFlow (config flag `SFLOW_LISTEN=0.0.0.0:6343`).
6. `go build ./...` green. `go test ./...` green. CI integration lane green.
7. CHANGELOG `0.15.0` entry.
8. Audit re-run shows no Critical/High findings on `internal/sflow` or `internal/flows`.

### 13.7 Rollback

- The `cmd/probe` deletion is irreversible; coordinate cutover with the sibling `Firewall-Collector` repo and the operator deployment.
- The CIDR allowlist change is backward-compatible (single IPs work as `/32`).
- The extended record parsing is additive.

---

## 14. Operational runbook

### 14.1 Sampling rate change detection

- **Source:** `flow_sampling_rate_changes` table + the SSE anomaly ticker.
- **Symptom:** traffic appears to drop or spike in the historical view at a specific time.
- **Action:** check the agent's sFlow config. Agents back off the rate automatically when overloaded (spec §4.2.2). Persistent back-off indicates the agent CPU or egress link is the bottleneck; raise the agent's CPU/memory or split sFlow destinations.
- **Recovery:** the rate doesn't auto-revert (per spec). Manually reconfigure the agent.

### 14.2 Drop reason triage

- **Source:** `flow_agent_drops.drops_last_5m > 0` (Prometheus: `flow_drops_total{agent}`).
- **Symptom:** the sFlow traffic accounting on the dashboard is lower than the link's actual utilisation.
- **Action:**
  1. Check the agent's CPU and egress link utilisation. If the agent is at 100% CPU, it's a sampling-rate back-off (see 14.1).
  2. Check `net.core.rmem_max` on the collector. Default is usually 200 KB; raise to 8 MB.
  3. Check the collector's `sflow_receiver_connections` gauge. If it dropped, the receiver crashed.
  4. Check the per-agent rate limit (`flow_samples_dropped_total{reason="rate_limit",agent}`). If it's non-zero, raise `SFLOW_PER_AGENT_RATE_LIMIT`.

### 14.3 sFlow vs SNMP counter reconciliation

- **Tool:** the existing `GetInterfaceChartData` endpoint with `source=sflow,snmp`.
- **Comparison:** per-bucket `in_octets_delta` should agree within 1–2% (sFlow's 20–60s counter poll vs SNMP's 5-min poll can disagree on bursty links).
- **If sFlow is consistently higher than SNMP:** sFlow is exporting more frequently (counter at 20s vs SNMP at 5min); not a bug.
- **If sFlow is consistently lower:** sampling rate back-off is active on the agent (see 14.1).

### 14.4 Anomaly triage

| Type | What it means | Action |
|---|---|---|
| `topk_shift` | A new top talker has appeared. | Usually a scheduled backup, deploy, or new application. Verify against the change log. |
| `super_spreader` | One source IP is hitting many destination IPs. | Possibly a misconfigured client doing discovery, or a worm. Investigate the src. |
| `port_scan` | One source IP is hitting many destination ports. | Usually a vulnerability scanner (Tenable, Qualys) or an attacker. Whitelist your scanners. |
| `threshold` | A device's bps is > 80% of `ifSpeed`. | Capacity planning signal, not a security alert. |
| `sampling_change` | An agent's sampling rate changed. | See 14.1. |
| `seq_regression` | An agent's sequence number went backwards. | The agent restarted. Verify it's a planned restart. |

### 14.5 Connection-detail bandwidth source

The device-detail page's `GetInterfaceBandwidthFromSFlow` returns sFlow-native counters when present. The page falls back to SNMP if:

- The device does not export sFlow for that interface.
- The sFlow `ifSpeed` is 0 (unparseable).
- The sFlow counters are older than 5 minutes (stale).

In the API response, the `source` field is `"sflow"`, `"snmp"`, or `"none"`. The UI displays this transparently.

### 14.6 On-call escalation

For a P1 incident (sFlow dashboard down):

1. Check `sflow_receiver_connections` gauge. If 0, the receiver crashed. Restart the api binary.
2. Check `flow_samples_total` rate. If 0, the probes are not sending. Verify the agent config.
3. Check `flow_samples_dropped_total{reason}`. If non-zero, see 14.2.
4. Check the per-agent rate limit. If a single agent is at 100% of its rate, raise `SFLOW_PER_AGENT_RATE_LIMIT`.

For a P1 incident (sFlow data wrong):

1. Check `flow_sampling_rate_changes` for the time of the incident.
2. Check the device's SNMP counters for reconciliation.
3. See 14.3.

---

## 15. Open questions & decisions log

| Decision | Choice | Rationale |
|---|---|---|
| Keep 30s JSON batch transport | Yes (per user) | Sub-second aggregator runs post-batch; 30s freshness is acceptable for human operators |
| Don't add Kafka | Yes | At 100k samples/sec, the api binary can absorb it directly with SO_REUSEPORT + bulk insert |
| Don't add ClickHouse | Yes | Postgres handles 100k samples/sec with monthly RANGE partitioning; adding OLAP is operational debt |
| Don't add Vue/React | Yes | Vanilla JS + existing Chart.js + uPlot is the right tool at this scope |
| Don't replace SNMP with sFlow counters | Yes (per user) | sFlow-native bandwidth sits alongside SNMP; device-detail page prefers sFlow where available |
| Don't add gRPC streaming in this round | Yes | 30s batch keeps the probe/relay code unchanged; revisit if freshness hurts |
| Don't add machine-learning anomaly detection | Yes | Tier-1 detectors cover 90% of operational value; ML is research-grade |
| Delete the bundled `cmd/probe` in Phase 4 | Yes (per CHANGELOG v0.10.412 XR-1) | The production probe is the sibling `Firewall-Collector` repo |
| Back-fill historical wrong bytes | No (per user) | Cut over at deploy time; document the cutoff in CHANGELOG |
| Scale bytes at insert time vs read time | Read time | Preserves `sampling_rate` per row for reconciliation; no data loss if rate changes mid-stream |
| In-memory aggregator: 5-min ring | Yes | 5 min covers the typical "I see something odd, look at the last few minutes" use case; matches the 30s batch cadence |
| HLL library | axiomhq/hyperloglog | BSD-3, actively maintained, good API |
| SSE vs WebSocket | SSE | One-way push; half the code; native browser reconnect |
| Counter sample polling cadence | 20–60s (agent-controlled) | Spec default; we just record what arrives |
| IPv6 extension header chain parsing | Walk to fragment header or end | Matches the Linux kernel `ip6_find_1stfragopt` behavior |
| Sequence-number wrap-around | Treat as no regression if seq jumped forward > 2^31 | Avoids spurious alerts on 32-bit wrap |
| Top-K size | 1000 per dimension | Tunable; ~1 KB state per dimension |
| pgx.CopyFrom vs COPY FROM STDIN | pgx.CopyFrom | Native Go; no shell-out; transactional |
| Anomaly persistence | Use existing `internal/alerts` engine | Consistent with the rest of the system |
| Flow record size budget | 200 bytes | At 100k/sec × 5 min = 30M records × 200 B = 6 GB; we cap the in-memory ring at 100k entries and store the rest in Postgres |

---

## 16. Glossary

- **sFlow:** "Sampled Flow." A packet-sampling and counter-export protocol. UDP 6343, XDR.
- **XDR:** External Data Representation. RFC 1832. The wire format of sFlow v5.
- **Sample:** One observation exported by an agent. Either a *flow sample* (sampled packet header) or a *counter sample* (interface/Ethernet/processor counters).
- **Sample rate:** 1:N. The agent samples 1 of every N packets. Stored per (agent, source_id).
- **Sampling pool:** The total packets observed since agent boot (or last reset). Used for counter reconciliation.
- **Agent:** The device that exports sFlow. Often the network device itself, sometimes a host agent.
- **Collector:** The server that receives sFlow. (This project.)
- **XDR format number:** The `(enterprise << 12) | format` 32-bit tag identifying a record type. 0/1 means standard sflow.org record format 1.
- **flow_data:** A flow record embedded in a flow sample (sampled_header, sampled_ipv4, extended_switch, etc.).
- **counter_data:** A counter record embedded in a counter sample (if_counters, ethernet_counters, processor, etc.).
- **discarded_packet:** A sample_data record reporting packets the agent dropped (with reason).
- **Source ID:** A 32-bit field identifying the data source within an agent. Top byte = type (ifIndex/smonVlanDataSource/entPhysicalEntry), low 3 bytes = index.
- **HLL:** HyperLogLog. A probabilistic cardinality estimator. Used for super-spreader and port-scan detection.
- **Top-K:** A streaming algorithm that maintains the K most-frequent items in a stream. Used for "top talkers" tables.
- **SSE:** Server-Sent Events. A one-way server→client push over HTTP. The right tool for live dashboards.
- **BGP AS_PATH / communities:** Routing metadata. `extended_gateway` (format 1003) carries it.
- **CIDR:** Classless Inter-Domain Routing. The `10.0.0.0/24` notation. Used in the source-IP allowlist.
- **pgx:** The Go Postgres driver. Supports the binary COPY protocol via `CopyFrom`. ~50× faster than `INSERT` per row.
- **SO_REUSEPORT:** A socket option that lets multiple sockets bind to the same address. The kernel hashes source IP → socket. Used for kernel-level load balancing.
- **MSS / MTU:** Maximum Segment / Transmission Unit. sFlow datagrams should fit in a 1500-byte Ethernet frame; `sFlowRcvrMaximumDatagramSize=1400` is the default to leave headroom.

---

## 17. References

1. [sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt) — "sFlow Version 5", Phaal & Lavine, July 2004 (the canonical spec)
2. [sflow.org/SFLOW-DATAGRAM5.txt](https://sflow.org/SFLOW-DATAGRAM5.txt) — XDR of the datagram header and sample records
3. [sflow.org/SFLOW-STRUCTS5.txt](https://sflow.org/SFLOW-STRUCTS5.txt) — Standard sFlow data formats
4. [sflow.org/developers/specifications.php](https://sflow.org/developers/specifications.php) — Complete list of structure documents
5. [sflow.org/developers/structures.php](https://sflow.org/developers/structures.php) — Authoritative catalog of structure numbers
6. [sflow.org/about/index.php](https://sflow.org/about/index.php) — sFlow overview, scalability claims
7. [sflow.org/sflow_drops.txt](https://sflow.org/sflow_drops.txt) — Discarded packet / drop reason structures
8. [RFC 3176](https://www.rfc-editor.org/rfc/rfc3176) — sFlow v4 (deprecated)
9. [RFC 1832](https://www.rfc-editor.org/rfc/rfc1832) — XDR: External Data Representation Standard
10. [github.com/netsampler/goflow2](https://github.com/netsampler/goflow2) — Production Go sFlow/NetFlow/IPFIX collector (BSD-3)
11. [github.com/netsampler/goflow2/blob/main/docs/performance.md](https://github.com/netsampler/goflow2/blob/main/docs/performance.md) — Performance sizing
12. [github.com/cloudflare/goflow](https://github.com/cloudflare/goflow) — Original Cloudflare collector, archived Feb 19 2025
13. [sflow-rt.com](https://sflow-rt.com) — InMon's real-time analytics engine
14. [github.com/sflow-rt/prometheus](https://github.com/sflow-rt/prometheus) — sFlow-RT Prometheus exporter app
15. [blog.sflow.com/2019/10/flow-metrics-with-prometheus-and-grafana.html](https://blog.sflow.com/2019/10/flow-metrics-with-prometheus-and-grafana.html) — Prometheus + Grafana pattern
16. [sflow-rt.com/live.php](https://sflow-rt.com/live.php) — Public live dashboards (SDSC Expanse, NRP Nautilus, SFMIX)
17. [akvorado.net](https://akvorado.net) — OVH's NOC flow dashboard (Go + Vue + ECharts + ClickHouse + Kafka)
18. [akvorado.net/docs/06-internals.md](https://akvorado.net/docs/06-internals/internals/) — Console tech stack
19. [github.com/ntop/ntopng](https://github.com/ntop/ntopng) — ntopng NMS (C++/Lua + Vue)
20. [Jasinska, "sFlow, I can feel your traffic"](https://www.sflow.org/detectWave/index.htm) — 23C3 / AMS-IX paper (2006)
21. Hofstede et al., "Flow Monitoring Explained: From Packet Capture to Data Analysis with NetFlow and IPFIX", IEEE COMST 2014
22. `tasks/CTO-LOOP-2026-06-11.md` — The current audit report that surfaced these findings

---

## 18. Document control

- **Version:** 1.0 (initial release of this plan)
- **Last updated:** 2026-06-11
- **Status:** design / pre-implementation
- **Reviewers:** TBD
- **Approval:** TBD
- **Next steps:** Phase 0 implementation per §9. CHANGELOG entry at the top on completion.
