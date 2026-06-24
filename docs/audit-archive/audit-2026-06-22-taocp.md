# Firewall-Mon — Algorithms & Data Structures Audit (2026-06-22)

**Reviewer:** CTO-level audit, Knuth TAOCP Volumes 1–4B
**Scope:** `E:\Golang\OpenCode\Firewall-Mon` (server repo only)
**Method:** Static read + targeted grep over `internal/**`, `cmd/**`, `tasks/SFLOW-NOC-REDESIGN-PLAN.md`, `tasks/lessons.md`
**Out of scope:** `Firewall-Collector` (sibling repo, separate audit)

---

## Summary

- **Overall grade: B-** — Algorithmic foundations are sound; no Critical correctness bugs in the *data structures themselves*. Two **Critical** correctness bugs exist in the *sFlow data flow* and are documented (in `tasks/SFLOW-NOC-REDESIGN-PLAN.md`) but **not yet fixed**. Project-specific invariants `sampling_rate × bytes` and `drops` field both currently FAIL.
- **Top 3 wins**
  1. Security-sensitive RNG: every use of `rand` is `crypto/rand` with the **rejection-sampling** pattern (`rand.Int(reader, big.NewInt(n))`), not the modulo-bias trap (Lesson 3.5). Lesson 3.1/3.2 PASS.
  2. Constant-time compares: probe key hash, CSP nonce, and SNMP community string all use `subtle.ConstantTimeCompare` / `hmac.Equal`. Timing-attack surface is small.
  3. Multi-linked LRU (Lesson 2.25): `internal/api/middleware/middleware.go:42-100` implements a textbook-correct LRU as `map[string]*entry` + `container/list`, with a `maxEntries` cap (Lesson 6.4 load-factor). The pattern is the right one — no sharded in-memory map, no `sync.Map`, no eviction bug.
- **Top 3 concerns**
  1. **Project invariant broken end-to-end**: `internal/sflow/sflow.go:324` stores `Bytes = uint64(frameLength)` — *not* multiplied by `sampling_rate`. `internal/database/flows.go:188-192`, `226`, `326-377`, `559-562` also compute SUMs without the multiplier. The plan to fix it (Phase 0, `tasks/SFLOW-NOC-REDESIGN-PLAN.md` §9) is written but not shipped. Every chart, every top-N, every throughput value on the production dashboard is wrong by 1:N.
  2. **`drops` field is invisible.** Three places mention "drops" in comments only (`internal/sflow/sflow.go:258, 265`). `models.FlowSample` has no `Drops` field. `relay.FlowSample` (the wire format the collector sends) has no `Drops` field. `SaveAgentDrops` / `RecordSamplingRateChange` do not exist. Agent-side sample loss is undetectable by operators.
  3. **Hot path is not at design target.** `SaveFlowSamples` uses GORM `db.Create(&samples)` (`internal/database/ping.go:189`), not `pgx.CopyFrom`. `sflow.go:142` is one goroutine on one socket with no `SO_REUSEPORT`, no `SetReadBuffer(8 MB)`, no per-agent token bucket, no `sync.Pool` for `ParsedFlow`. At the lessons.md 100k samples/sec target, the receiver will be the bottleneck, but the design is documented in the plan and not yet implemented.

---

## Findings

### [SEVERITY: critical] sFlow `Bytes` is not multiplied by `sampling_rate` at insert

- **Lesson violated:** Knuth project invariant `tasks/lessons.md:41-51` ("non-negotiable"). Adjacent: Vol 2 §3.1, Lesson 4.1 (integer-arithmetic contract).
- **File:** `internal/sflow/sflow.go:318-326`
- **Snippet:**
  ```go
  flow := &ParsedFlow{
      AgentIP:       agentIP,
      SamplingRate:  samplingRate,
      InputIfIndex:  inputIf,
      OutputIfIndex: outputIf,
      FrameLength:   frameLength,
      Bytes:         uint64(frameLength),  // BUG: should be uint64(frameLength) * uint64(samplingRate)
      Packets:       1,
  }
  ```
- **Why it's a problem:** Every byte reported by the agent (frame length) is *one in N* sampled packets. Without multiplication by `SamplingRate`, the system reports ~1/Nth of the real traffic. At 1:512 sampling, the dashboard under-reports by ~512×. The bug is also latent in the database schema: `flow_samples.bytes` stores the unscaled value, so fixing it after the fact requires back-fill or a read-time multiplier (the plan §6.1 adopts the read-time approach — store raw, multiply at read).
- **Suggested fix:** Per `tasks/SFLOW-NOC-REDESIGN-PLAN.md` §9.4 lines 506-531, change to `Bytes: uint64(frameLength) * uint64(samplingRate)`. Also add a contract comment: "Bytes is the unscaled frame_length; EstimatedBytes (computed at read time) is frame_length × sampling_rate." Pick a convention and stick to it across `flow_samples`, `flow_rollups`, `flow_if_counters`, and every SUM/AVG on the read path.
- **Effort:** S (one-line code change + the read-path multiplier change in `flows.go`).

### [SEVERITY: critical] Read paths use `SUM(bytes)` without the sampling-rate multiplier

- **Lesson violated:** Project invariant; also Lessons 5.1 ("don't reinvent math, use the library"), 4.1 (declare integer-arithmetic contracts).
- **File:** `internal/database/flows.go:188-192, 226, 326-377, 559-562`
- **Snippet (lines 188-192):**
  ```go
  // Multiply bytes/packets by sampling_rate to estimate actual traffic volume
  if err := newRawBase().Select("COUNT(*) as total_flows, COALESCE(SUM(bytes),0) as total_bytes, " +
      "COUNT(DISTINCT src_addr) as unique_sources, COUNT(DISTINCT dst_addr) as unique_dests").
      Scan(&rawAgg).Error; err != nil {
      return nil, fmt.Errorf("flow stats raw aggregates: %w", err)
  }
  ```
  Comment promises multiplication; code does not do it. The `EstimatedBytes` field (line 233) does multiply — but only on the *total* field, not on TopSources / TopDestinations / TopConversations / TopPorts / local_traffic / BytesOverTime.
- **Why it's a problem:** Even after the insert path is fixed, the rollup path (line 561: `SUM(bytes) as bytes_sum`) is unscaled, and `mergeKeyCounts` (line 431), `topAddrsByBytes` (line 64-77), and `aggregateFlowsToRollup` (line 559-562) all aggregate `bytes` directly. Per-conversation, per-port, and per-protocol top-N lists are all wrong by 1:N unless every read path multiplies by sampling_rate.
- **Suggested fix:** Three options, ordered by elegance:
  1. **Best — weighted read math** (per plan §6.1, §9.4 lines 596-610): standardise on `SUM(bytes * sampling_rate) / SUM(packets) * SUM(packets)` which collapses to `SUM(bytes * sampling_rate)`. Update every SUM/aggregation in `flows.go` to include the multiplier. This makes EstimatedBytes trivially correct.
  2. **Good — store scaled bytes**: change `flow_samples.bytes` to the scaled value at insert (matches `Bytes: uint64(frameLength) * samplingRate` from finding #1). Then SUMs are correct without further change. Loses per-row sampling_rate info — can back-fill, but breaks reconciliation.
  3. **Acceptable — read-time multiplier**: keep unscaled bytes, but apply a single precomputed `sampling_rate_weighted_avg` column on `flow_rollups` and use `SUM(bytes_sum * sampling_rate_weighted_avg)` on read. Plan §6.1 documents this as the chosen path.
- **Effort:** M (cross-cutting change in `flows.go`, `aggregateFlowsToRollup`, `aggregateRollupsUp`, plus migration for the new `flow_rollups.sampling_rate_weighted_avg` column).

### [SEVERITY: critical] `drops` field is read and discarded end-to-end

- **Lesson violated:** Project invariant `tasks/lessons.md:53-61`. Adjacent: Lesson 3.10 (capture the signal, don't reinvent).
- **Files:**
  - `internal/sflow/sflow.go:258` (comment only, no read): `// Expanded flow sample: source_id_type(4) + source_id_index(4) + sampling_rate(4) + sample_pool(4) + drops(4) + input_if_format(4) + input_if(4) + output_if_format(4) + output_if(4) + num_records(4)`
  - `internal/sflow/sflow.go:265` (comment only, no read): `// Standard flow sample: source_id(4) + sampling_rate(4) + sample_pool(4) + drops(4) + input(4) + output(4) + num_records(4)`
  - `internal/sflow/sflow.go:316-326` (`ParsedFlow` struct has no `Drops` field)
  - `internal/relay/relay.go:68-95` (wire DTO has no `Drops` field)
  - `internal/models/models.go:673-700` (GORM `FlowSample` has no `Drops` column)
  - `internal/database/flows.go` — no `SaveAgentDrops`, no `RecordSamplingRateChange`, no `flow_agent_drops` table
- **Why it's a problem:** sFlow v5 spec §3.1.1 puts `drops` in every flow sample as the running counter of samples the agent had to drop because it couldn't keep up. It is the single best signal of agent-side congestion (vs. network-side loss). Discarding it means an operator cannot tell whether "we are missing flows" is the network, the agent, or the collector — and the redesign plan §2.1 / §4 #5 / §6.2 marks this as Blocker / Phase 0 / new table `flow_agent_drops`. Nothing is wired.
- **Suggested fix:** Per plan §9.2, §9.3: add `Drops uint32` to `ParsedFlow`, capture from data[16:20] in `parseFlowSample` (sFlow v5 §3.1.1, already-commented offset), add `Drops int` to `models.FlowSample` and `relay.FlowSample` (the latter with `omitempty` to keep wire compatibility — lessons.md line 80-83). Add `SaveAgentDrops` / `GetAgentDropsRecent` / `RecordSamplingRateChange` to the database layer. Add the `flow_agent_drops` and `flow_sampling_rate_changes` tables (plan §6.2). Surface `drops_last_5m` in the NOC strip — no implementation exists yet because there is no NOC page.
- **Effort:** L (cross-cutting: sflow parser + relay DTO + models + 2 new tables + migration + alert hook).

### [SEVERITY: critical] Bulk insert uses GORM `Create` instead of `pgx.CopyFrom`

- **Lesson violated:** Project invariant `tasks/lessons.md:85-97`. Adjacent: Lesson 5.1 (use the library), Lesson 1.3 (don't micro-optimise — but a 50× regression on the hot path isn't micro).
- **File:** `internal/database/ping.go:185-190`
- **Snippet:**
  ```go
  func (d *Database) SaveFlowSamples(samples []models.FlowSample) error {
      if len(samples) == 0 {
          return nil
      }
      return d.db.Create(&samples).Error
  }
  ```
  Called from `internal/api/handlers/handlers_data.go:221` once per 30s batch.
- **Why it's a problem:** GORM's `Create` does per-row INSERT (or at best a multi-row INSERT that is still N× the parameter count). `pgx.CopyFrom` does a single PostgreSQL COPY stream — typically 5–10× faster on the same payload, and crucially it does not hold a transaction lock for the duration of the round-trip. `go.mod` already pulls `github.com/jackc/pgx/v5 v5.6.0` transitively (gorm/driver/postgres uses it), so the dependency is in the closure. There is no `import "github.com/jackc/pgx/v5"` anywhere in the source tree (`grep -r "jackc/pgx"` returns zero non-test hits). The codebase has the dependency on disk but no code uses it directly.
- **Suggested fix:** Per plan §2.1 line 28, §4 #8, §9.2: replace `SaveFlowSamples` with a `pgx.CopyFrom`-based bulk insert. Keep the function signature (`SaveFlowSamples([]models.FlowSample) error`) so callers don't change. The new implementation pulls the underlying `*pgx.Conn` from the GORM connection pool (`db.ConnPool` after type-assertion to `*sql.DB`), calls `conn.CopyFrom(ctx, tableName, columnNames, pgx.CopyFromRows(rows))`. Existing `gorm.io/driver/postgres` exposes the underlying `*pgx.ConnPool`, so the wiring is straightforward. If the connection pool does not expose pgx directly (it does in v5), fall back to a direct `pgxpool.Pool`.
- **Effort:** M (one function; tests already exist for `SaveFlowSamples` round-trip).

### [SEVERITY: high] sFlow UDP receiver is single-goroutine, no `SO_REUSEPORT`, no `SetReadBuffer(8 MB)`

- **Lesson violated:** Project invariant `tasks/lessons.md:85-97`. Adjacent: Vol 1 Lesson 1.9 (cache locality, hardware realities), Vol 1 Lesson 2.2 (sequential allocation beats linked for hot paths).
- **File:** `internal/sflow/sflow.go:114-171`
- **Snippet (lines 142-152):**
  ```go
  func (r *SFlowReceiver) readLoop() {
      defer r.wg.Done()

      buf := make([]byte, 65536)
      for r.running.Load() {
          select {
          case <-r.stopChan:
              return
          default:
              r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
              n, addr, err := r.conn.ReadFromUDP(buf)
  ```
- **Why it's a problem:** At the design target of 100k samples/sec (lessons.md line 85), a single 64 KB receive buffer with default `net.core.rmem_max` (typically 212 KiB on Linux) will be overrun within microseconds. `SetReadBuffer(8 MB)` per lessons.md line 92 is required to keep the kernel queue from dropping packets. `SO_REUSEPORT` (also lessons.md line 91) allows multiple kernel-hashed listeners to share the port and parallelize parse — Go's idiomatic `net.ListenConfig` with `Control: func(...) { ... setsockopt(SO_REUSEPORT) }` is the pattern. The current implementation has neither.
- **Suggested fix:** Per plan §2.1 line 28 / §4 #8 / §10: spawn N listener goroutines (N = GOMAXPROCS typically) sharing the port via `SO_REUSEPORT`. Each goroutine gets its own `*net.UDPConn` after listen, then `conn.SetReadBuffer(8 * 1024 * 1024)` is called immediately after `net.ListenUDP`. Use `sync.Pool` of `[]byte` (8 MB cap, or 1 MB buckets) to avoid the per-packet allocation. The plan covers this in §4 and §10; the implementation lives in Phase 2.
- **Effort:** L (full receiver rewrite; needs load-test to verify 100k samples/sec target).

### [SEVERITY: high] No per-agent token-bucket rate limit on sFlow UDP path

- **Lesson violated:** Project invariant `tasks/lessons.md:85-97` line 94 ("Per-agent token-bucket rate limit before parse"). Adjacent: Lesson 6.4 (load-factor / cap), Lesson 3.14 (bounded random processes need termination guarantees).
- **File:** `internal/sflow/sflow.go:162-167`
- **Snippet:**
  ```go
  if n > 0 {
      if len(r.allowedIPs) > 0 && !r.allowedIPs[addr.IP.String()] {
          continue
      }
      r.parseDatagram(buf[:n])
  }
  ```
  The `allowedIPs` map is an exact-match CIDR (also lessons.md flagged in plan §4 #11 as needing CIDR not just exact-IP). There is no rate limit per agent IP. A misbehaving agent (or an attacker spoofing source IPs from within the allowed CIDR) can flood the parse path.
- **Why it's a problem:** `internal/snmp/trap.go:82-107` has a textbook token-bucket per-IP rate limiter with a `maxRateLimitedIPs = 10000` cap (the SNMP trap path was hardened in AUDIT-012). The sFlow path has nothing comparable. The lessons.md and the plan both call this out as required.
- **Suggested fix:** Add a per-agent-IP token bucket using the same `sync.Mutex`-protected `map[string]*ipBucket` pattern from `internal/snmp/trap.go:82-107`, with `maxRateLimitedIPs = 256` (sFlow agents are typically <50 per network). Rate ~ 1000 datagrams/sec/agent is generous for a 10G agent at 1:512 sampling.
- **Effort:** S (the pattern is already in `snmp/trap.go`; copy + parameterise).

### [SEVERITY: medium] `sort.Slice` for top-N where ties could be silent for pagination

- **Lesson violated:** Lesson 5.2 (stability matters). Adjacent: Lesson 5.1 (use `sort.SliceStable` when ties exist).
- **Files:**
  - `internal/database/flows.go:315` — `sort.Slice(protocols, func(i, j int) bool { return protocols[i].Count > protocols[j].Count })` followed by `if len(protocols) > 10 { protocols = protocols[:10] }`
  - `internal/database/flows.go:431` — `sort.Slice(merged, func(i, j int) bool { return merged[i].Count > merged[j].Count })` inside `mergeKeyCounts`
  - `internal/database/devices.go:262` — `sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.After(events[j].Timestamp) })` followed by `if len(events) > 100 { events = events[:100] }`
  - `internal/report/model.go:245` — `sort.Slice(fleetTalkers, func(a, b int) bool { return fleetTalkers[a].t.TotalBytes > fleetTalkers[b].t.TotalBytes })` followed by `if len(fleetTalkers) > 8 { fleetTalkers = fleetTalkers[:8] }`
- **Why it's a problem:** When two entries tie on the sort key, `sort.Slice` does not preserve their input order. For a top-N *without* pagination, this is fine — only N items are shown, and the operator can't tell which tied entry is which. The bug becomes visible when:
  1. An offset/limit pagination is added later to any of these endpoints (today's pagination is by `timestamp DESC` which is naturally stable — but if a sort-then-paginate path is added for top-N, the non-determinism leaks).
  2. Two different requests return different tied items, breaking visual diffs.
  The plan also explicitly notes (lines 624-635) that `mergeKeyCounts` has a separate bug where it merges 10+10 instead of full sort + clip — this is a *different* bug (not just stability) but the fix is in the same vicinity.
- **Suggested fix:** Convert these to `sort.SliceStable` (Go stdlib) with a tie-breaker on a natural secondary key (e.g., `Key` ascending for `mergeKeyCounts`). One-word change; low risk. While here, fix `mergeKeyCounts` per plan §9.4 lines 614-652 — the current code is `append(raw, rollup...)` then `sort.Slice`, which actually does merge correctly **for the total-byte case** (line 431 is OK), but does NOT for the `KeyCount` slice — `mergeKeyCounts` builds a map first (line 419-425) then re-sorts; that's correct for unmerged clip-to-10 but loses the tie-breaker.
- **Effort:** S (5–10 file edits, one-liners).

### [SEVERITY: medium] Top-N merge logic in `mergeKeyCounts` clips to 10+10 instead of merging-then-clipping

- **Lesson violated:** Lesson 5.1 (use the right library sort), Lesson 7A.7 (don't enumerate when you can compute).
- **File:** `internal/database/flows.go:418-436`
- **Snippet:**
  ```go
  func mergeKeyCounts(a, b []KeyCount, limit int) []KeyCount {
      m := make(map[string]int64, len(a)+len(b))
      for _, kc := range a {
          m[kc.Key] += kc.Count
      }
      for _, kc := range b {
          m[kc.Key] += kc.Count
      }
      merged := make([]KeyCount, 0, len(m))
      for k, c := range m {
          merged = append(merged, KeyCount{Key: k, Count: c})
      }
      // Sort descending by count
      sort.Slice(merged, func(i, j int) bool { return merged[i].Count > merged[j].Count })
      if len(merged) > limit {
          merged = merged[:limit]
      }
      return merged
  }
  ```
  The plan §4 #10 and §9.4 (lines 614-652) describe this as "Top-N merge logic clips to 10+10". Reading the code carefully, the current implementation actually does merge-then-clip (it builds the union map, then sorts, then clips to limit) — so the bug described in the plan is **partially fixed**. But there are two smaller issues:
  1. The `KeyCount` struct's JSON tag is `count`, not `bytes` (line 51) — but for top-talkers we sort by *bytes*, and the field is `Count` here, suggesting callers are conflating the two. Inconsistency: `FlowConversation` (line 657) has both `Bytes` and `Packets` — distinct fields. `KeyCount` has only `Count`. The semantics are ambiguous.
  2. The merge `for _, kc := range a { m[kc.Key] += kc.Count }` — if `a[i].Key == a[j].Key` (impossible because `a` came from a prior GROUP BY, but not impossible if `mergeKeyCounts` is ever called with two `[]KeyCount` from the same source), the merge over-counts. Defensive code would `if v, ok := m[kc.Key]; ok { m[kc.Key] = v + kc.Count } else { m[kc.Key] = kc.Count }`. The current code happens to work because `+=` on a zero-valued map entry is the same as `=` for an absent key.
- **Why it's a problem:** Mild. The plan said it was a bug; the current code is closer to correct than the plan claimed. Worth a comment explaining the merge-then-clip is intentional. The struct-name confusion (`Count` vs `Bytes`) is a real documentation issue.
- **Suggested fix:** Add a doc comment to `mergeKeyCounts`: "Merges the union of two KeyCount slices by key, then clips to limit. Used for top-N where the same logical key may appear in both halves (raw samples and rollups)." Rename `KeyCount.Count` → `KeyCount.Bytes` when the count represents bytes (separate `KeyCount.Count` for actual counts). The struct is reused across 8 callers in `flows.go`, so the rename needs care. Plan §6.1 / §9.4 line 459-460 says this is part of the Phase 0 cleanup.
- **Effort:** S.

### [SEVERITY: medium] `naiveFloatSum` in `meanStdDev` (Lesson 4.26)

- **Lesson violated:** Lesson 4.26 (Kahan summation for hot paths).
- **File:** `internal/report/spike.go:375-392`
- **Snippet:**
  ```go
  func meanStdDev(values []float64) (float64, float64) {
      if len(values) == 0 {
          return 0, 0
      }
      sum := 0.0
      for _, v := range values {
          sum += v
      }
      mean := sum / float64(len(values))

      sumSq := 0.0
      for _, v := range values {
          d := v - mean
          sumSq += d * d
      }
      stddev := math.Sqrt(sumSq / float64(len(values)))
      return mean, stddev
  }
  ```
- **Why it's a problem:** Naive sum of N floats has error O(N·ε). For the rolling 10-sample buffer the function is called with, the error is bounded (~10 × 2⁻⁵² ≈ 2e-15 of the largest value) — entirely negligible. But `meanStdDev` is *also* called from `detectSpikesInSeries` (line 50) on a sliding window of the full series, where N can be 100–1000+. For 1000 samples summed naively, the relative error is ~1e-13, still negligible. **Real risk**: the `sumSq` is over `(v - mean)`, and catastrophic cancellation is possible if mean is large and v varies by small amounts — but `detectSpikesInSeries` works in bps (typically 1e2–1e10), so v-mean is not small relative to mean.
- **Suggested fix:** None required today. Add a doc comment that meanStdDev assumes the standard Welford recurrence would be more numerically stable for series with mean ≫ variance, and tag a TODO if anyone hits a precision regression. The function is on a cold path (5-minute report rollup), so even a 10× cost from a compensated summation would be invisible.
- **Effort:** S (add the doc comment; do not change code).

### [SEVERITY: medium] `Relayer.FlowSample` struct in `internal/sflow/sflow.go:32-44` is dead code (plan §4 #13)

- **Lesson violated:** Lesson 2.23 ("Information structures are a taxonomy, not a toolkit — fit the new structure into the standard one before inventing a new one").
- **File:** `internal/sflow/sflow.go:32-44`
- **Snippet:**
  ```go
  type FlowSample struct {
      ID             uint64          `json:"id"`
      Timestamp      time.Time       `json:"timestamp"`
      ProbeID        uint32          `json:"probe_id"`
      DeviceID       uint32          `json:"device_id"`
      SequenceNumber uint32          `json:"sequence_number"`
      SourceID       uint32          `json:"source_id"`
      SamplingRate   uint32          `json:"sampling_rate"`
      SamplePool     uint32          `json:"sample_pool"`
      InputIfIndex   uint32          `json:"input_if_index"`
      OutputIfIndex  uint32          `json:"output_if_index"`
      FlowData       json.RawMessage `json:"flow_data"`
  }
  ```
- **Why it's a problem:** The codebase has *three* `FlowSample` types: this one, `internal/relay/relay.go:68-95` (wire format), and `internal/models/models.go:673-700` (database). The plan §4 #13 calls the sflow-package one out as "Dead FlowSample struct (wire-payload style, never used)". `grep` confirms zero non-test callers. It is dead code that future contributors will mistake for the canonical type.
- **Suggested fix:** Delete the type, or rename to `WireFlowSample` to disambiguate. Plan §9.2 line 463 references a refactor of `handlers_data.go` but does not explicitly call this out — should be added.
- **Effort:** S.

### [SEVERITY: medium] Counter samples entirely discarded — `ifInOctets` / `ifOutOctets` never used

- **Lesson violated:** Lesson 7A.7 (don't enumerate / discard when you can compute — we are discarding sFlow's native bandwidth signal).
- **File:** `internal/sflow/sflow.go:228-232`
- **Snippet:**
  ```go
  if enterprise == 0 && (format == 1 || format == 3) {
      // Flow sample (1) or expanded flow sample (3)
      r.parseFlowSample(data[offset:offset+int(sampleLen)], agentIP, format == 3)
  }
  // Skip counter samples and other types
  offset += int(sampleLen)
  ```
- **Why it's a problem:** sFlow's other primary record type, counter_sample (format 2), is ignored. The `if_counters` (format 1) inside carries `ifInOctets`, `ifOutOctets`, `ifSpeed`, `ifInErrors`, `ifInDiscards`. This is the sFlow-native interface bandwidth signal. The current code throws it away and relies entirely on SNMP polling (30s cadence, 60s polling interval) for interface bandwidth. Plan §4 #3 / §10 fixes this in Phase 1.
- **Suggested fix:** Per plan §10.4 lines 819-832, add: `if enterprise == 0 && format == 2 { r.parseCountersSample(...) }`. The `parseCountersSample` walks the array of `counter_record` entries and dispatches to `parseIfCounters`, `parseEthernetCounters`. New GORM model `models.FlowIfCounter` with monthly RANGE partition. Wire DTO `relay.CounterSample` matches the `models.CounterSample` already defined in `internal/sflow/sflow.go:46-61`.
- **Effort:** L (cross-cutting: parser + model + table + endpoint).

### [SEVERITY: low] IPv6 extension-header walk is correctly bounded but `flow.Protocol` may stay as `HOPOPT` (0) on truncation

- **Lesson violated:** Lesson 1.7 (off-by-one / loop termination). The code is correct; this is a documentation note.
- **File:** `internal/sflow/sflow.go:412-443`
- **Snippet:**
  ```go
  func parseIPv6(data []byte, flow *ParsedFlow) {
      if len(data) < 40 {
          return
      }

      flow.SrcAddr = net.IP(data[8:24]).String()
      flow.DstAddr = net.IP(data[24:40]).String()

      nextHeader := data[6]
      offset := 40
      for i := 0; i < 8 && isIPv6ExtHeader(nextHeader); i++ {
          if offset+2 > len(data) {
              break // can't read this ext header — keep nextHeader as best effort
          }
          ...
      }

      flow.Protocol = nextHeader
      if offset <= len(data) {
          parseTransport(data[offset:], flow)
      }
  }
  ```
- **Why it's a problem (potential):** The walk is hard-capped at 8 hops (RFC 8200 §4 recommends chain length limits). On truncated input, `nextHeader` may remain as the last-ext-header value (e.g., HOPOPT = 0), and `flow.Protocol = 0` is then stored. The downstream `parseTransport` is gated on `offset <= len(data)` so it correctly skips the port extraction. `flows.go:279-292` filters `protocol <> 0` out of the protocol breakdown — so the operator doesn't see noise, but the row *is* in `flow_samples` with protocol=0.
- **Why it's a non-issue today:** The downstream filter at `flows.go:289` (`Where("protocol <> 0")`) handles this exactly as the comment at lines 281-284 describes. The doc comment on `parseIPv6` (lines 408-411) explicitly says "Sampled headers are truncated, so every read is bounds-checked and the walk is capped." This is good code.
- **Suggested fix:** None. Worth a test that exercises truncated IPv6 headers, per plan §9.5 (`TestIPv6Parse_StubReturnsEmpty` and a fuzz target).
- **Effort:** S (test only).

### [SEVERITY: low] `ParsedFlow` allocation on every packet — no `sync.Pool`

- **Lesson violated:** Lesson 2.13 (free-list-in-array for high-churn objects), Lesson 1.9 (cache locality).
- **File:** `internal/sflow/sflow.go:302-326`
- **Snippet:**
  ```go
  flow := &ParsedFlow{
      AgentIP:       agentIP,
      ...
  }
  ```
- **Why it's a problem:** At 100k samples/sec, `ParsedFlow` allocation rate = 100k/s × sizeof(ParsedFlow). Looking at the struct (`internal/sflow/sflow.go:16-30`), it's 4 strings (16B header × 4 = 64B) + 10 small integers (~40B) + 1 time.Time (~24B) ≈ 128B/struct. Allocation rate ≈ 12.5 MB/s. Go's escape analysis will heap-allocate because `parseRawPacketHeader` returns the pointer and the caller (`parseFlowSample`) hands it to `flowHandler` which forwards to the batcher. **Heap churn at 12.5 MB/s is fine on a modern allocator**, but `sync.Pool` would eliminate the GC pressure entirely. Plan §1 line 13 calls out the bottleneck.
- **Suggested fix:** Per plan §10 / §4 #8: wrap `&ParsedFlow{...}` in a `sync.Pool.Get()` / `Put()` round trip. The pool reset (zero out the strings and pointers) must happen *after* the consumer is done, which is harder than it looks — the batcher holds the slice and consumes it asynchronously. Pattern: `pool.New = func() interface{} { return &ParsedFlow{} }`; consumer `batcher.Add(flow)` and the batcher's flush function calls `pool.Put(flow)` after `Create(&samples)` returns. Safe as long as the slice doesn't escape past flush.
- **Effort:** M.

### [SEVERITY: low] `cmd/probe` is a stale fork and not the production probe (plan §4 #14, lessons.md #63-69)

- **Lesson violated:** Lesson 2.23 (taxonomy — `cmd/probe` and the sibling `Firewall-Collector` repo are the same conceptual object).
- **File:** `cmd/probe/` (entire directory)
- **Why it's a problem:** `cmd/probe` is the legacy in-repo probe; the production probe is the sibling `Firewall-Collector` repo. `cmd/probe` does not send the `Authorization: Bearer` header the server requires (`internal/api/handlers/handlers_probes.go:784-788` expects a hashed probe key). Operators who try to use it will be silently 401'd.
- **Suggested fix:** Per lessons.md #65, delete `cmd/probe/` in the Phase 4 cleanup. Until then, add a `README.md` at `cmd/probe/README.md` with: "DEPRECATED: use the Firewall-Collector repo instead. This binary is preserved for reference only and does not authenticate against current server versions."
- **Effort:** S (delete) or XS (README).

### [SEVERITY: low] `RollupRow.SamplingRateAvg` uses unweighted AVG — not weighted by row count

- **Lesson violated:** Lesson 4.1 (declare integer-arithmetic contract; for floats, declare how aggregation behaves).
- **File:** `internal/database/flows.go:559-562, 615-624`
- **Snippet (raw → 5m rollup):**
  ```go
  "AVG(sampling_rate) as sampling_rate_avg").
  ```
  Snippet (5m → 1h rollup, already weighted):
  ```go
  "CASE WHEN SUM(flow_count) > 0 THEN SUM(sampling_rate_avg * flow_count) / SUM(flow_count) ELSE 0 END as sampling_rate_avg").
  ```
- **Why it's a problem:** Raw → 5m rollup uses `AVG(sampling_rate)` — unweighted. The next step (`aggregateRollupsUp`) tries to weight by `flow_count` (the number of samples in the bucket), but that weighting is only meaningful *if* the original AVG was weighted too. The math is inconsistent. If three rollups have `sampling_rate_avg = 100` but their `flow_count` is `1, 10, 100`, the unweighted-then-weighted math gives wrong results. Plan §9.4 line 619 already shows the desired weighted form for the 5m→1h step, but does not change the 1st-step formula.
- **Suggested fix:** Use the same weighted form at the raw→5m step. Plan §6.1 line 254 documents the desired output: `sampling_rate_weighted_avg NUMERIC(12,4)`. Compute as `SUM(sampling_rate) / COUNT(*)` only as a fallback when no row-count weighting is available — at the raw-to-5m step every row IS one sample, so `AVG(sampling_rate)` is the correct weighted average. The math is right; the issue is only the column name: rename to `sampling_rate_weighted_avg` to match plan §6.1 and prevent future confusion.
- **Effort:** S.

### [SEVERITY: low] `getDefaultPassword()` regenerates on every call (config-load only)

- **Lesson violated:** Lesson 2.10 (allocation rate vs. programmer discipline).
- **File:** `internal/config/config.go:576-592`
- **Snippet:**
  ```go
  func getDefaultPassword() string {
      return generateRandomPassword(16)
  }
  ```
  Called from line 317: `AdminPassword: getEnv("ADMIN_PASSWORD", getDefaultPassword()),` — exactly once at config-load.
- **Why it's a problem:** Today: not a problem. The audit test `internal/config/config_audit158_test.go:50-58` explicitly verifies the function returns a *fresh* value each call (so the password doesn't linger in GC). This is correct per the AUDIT-158 fix (the function was previously cached at module level). **No change needed**; this is a guard rail, not a bug.
- **Suggested fix:** None.
- **Effort:** N/A.

### [SEVERITY: low] `errors.Is` / `%w` discipline is excellent (AUDIT-080, AUDIT-081)

- **Lesson satisfied:** Lesson 1.20 ("proofs are necessary, not sufficient"), Lesson 4.20 (property-based testing of arithmetic, here: error-wrapping).
- **Evidence:** `internal/shell/errorsis_audit080_test.go:48-53` actively scans the `database` package for direct `==` / `!=` against `gorm.ErrRecordNotFound`. `internal/shell/returnerrwrap_audit081_test.go:37-44` actively scans for `return err` vs `fmt.Errorf("...: %w", err)`. Both tests enforce the policy. The grep `errors\.Is` shows 42 hits across `internal/database/*` and friends. Excellent.
- **Effort:** N/A — this is a **win**.

### [SEVERITY: low] Constant-time compares for auth/secret materials (PASS)

- **Lesson satisfied:** Lesson 3.3 (randomness = unpredictability; timing leaks), Lesson 4.29 (don't roll your own crypto primitives).
- **Evidence:**
  - `internal/api/handlers/handlers_probes.go:788` — `subtle.ConstantTimeCompare([]byte(database.HashProbeKey(token)), []byte(probe.RegistrationKey)) != 1`
  - `internal/api/middleware/middleware.go:294` — `hmac.Equal([]byte(csrfToken), []byte(expected))`
  - `internal/api/middleware/middleware.go:326, 563` — `rand.Read(b[:])` for CSP nonce generation
  - `internal/snmp/trap.go:145` — `subtle.ConstantTimeCompare([]byte(packet.Community), expectedCommunity) != 1`
- **Effort:** N/A — this is a **win**.

### [SEVERITY: low] Move-to-front self-organising list pattern in `ipRateLimiter` (PASS)

- **Lesson satisfied:** Lesson 6.2 (MTF beats LRU on linear scans; here the rate-limiter cache itself acts as the linear scan, and MTF is exactly the right heuristic).
- **Evidence:** `internal/api/middleware/middleware.go:42-100` — textbook LRU with map + doubly-linked list, `maxEntries=50000` cap (Lesson 6.4), `MoveToFront` on every access, `Back()`-eviction on overflow. Multi-linked structure (Lesson 2.25): one `rateLimiterEntry` node participates in both the `limiters` map and the `lru` list. The `entry.elem` field is the back-reference. Done correctly.
- **Caveat:** A singly-linked list with the "move-to-front by copying to head" trick could achieve the same thing at half the pointer-chasing cost, but the doubly-linked version is correct and the constant factor is irrelevant at 50k entries. Don't change.
- **Effort:** N/A — this is a **win**.

### [SEVERITY: low] `crypto/rand` everywhere for security-sensitive randomness (PASS)

- **Lesson satisfied:** Lesson 3.1 (named RNG), 3.2 (no `Math.random()` for security), 3.5 (no `rand() % n` modulo bias).
- **Evidence:** Every `math/big.Int`-based random selection uses `rand.Int(rand.Reader, big.NewInt(int64(n)))` — i.e. rejection sampling. No `rand.Int63() % n` patterns.
  - `internal/irc/bot.go:30` — `crand.Int(crand.Reader, big.NewInt(int64(d)))` for jitter
  - `internal/config/config.go:584` — `rand.Int(rand.Reader, big.NewInt(int64(len(charset))))` for password generation
  - `internal/auth/auth.go:208` — `rand.Read(b)` for token bytes
  - `internal/database/crypto.go:95` — `io.ReadFull(rand.Reader, nonce)` for crypto nonce
  - `internal/api/middleware/middleware.go:326, 563` — `rand.Read(b[:])` for CSP nonces
  - `internal/api/handlers/handlers_probes.go:120, 581` — `rand.Read(keyBytes)` for probe keys
- **Caveat:** `math/rand` is used in test files only (`internal/report/spike_property_test.go`) for `testing/quick` value generation. This is correct (test data, not security).
- **Effort:** N/A — this is a **win**.

### [SEVERITY: low] `errors.Is` for `gorm.ErrRecordNotFound` (PASS)

- Already covered by AUDIT-080. Win.

### [SEVERITY: low] `ipv6_test.go` and `bench_audit124_test.go` exist (PARTIAL)

- **Lesson satisfied:** Lesson 1.1 ("an algorithm must be seen to be believed"), Lesson 2.20 (proofs ≠ tests).
- **Evidence:** `internal/sflow/` has 3 test files: `ipv6_test.go`, `fuzz_audit119_test.go`, `bench_audit124_test.go`. The plan §1 line 15 quotes 8.5% coverage; Phase 4 targets 100%. The fuzz target at `internal/sflow/fuzz_audit119_test.go` covers the 28-byte header parse path but not the production hot path (`parseDatagram → parseFlowSample → parseRawPacketHeader → parseIPv4`).
- **Effort:** L (Phase 4 of plan, deferred).

### [SEVERITY: low] `BatchInserter` shutdown race — `stopped` atomic + recheck under mutex (PASS)

- **Lesson satisfied:** Lesson 2.27 (linked-list pointer aliasing — here applied to the "is the buffer still being appended to" flag, the same dual-check pattern is correct).
- **Evidence:** `internal/database/batcher.go:76-101` does the fast-path atomic check, takes the mutex, re-checks under the lock, then appends. The final Flush in the goroutine happens *before* `doneCh` is closed, so `Stop()` cannot return until every accepted item has been handed to `flushFn`. The `internal/database/batcher_test.go:92-155` test pins this behaviour. AUDIT-006 fix. Excellent.
- **Effort:** N/A — this is a **win**.

### [SEVERITY: informational] No bubble sort, no custom quicksort, no hand-rolled disk sort

- **Lesson satisfied:** Lessons 5.1, 5.3, 5.4, 5.8, 5.10. The codebase uses `sort.Slice` / `sort.SliceStable` / `sort.Strings` exclusively. No hand-rolled O(n²) sorts. No disk-sort paths.
- **Effort:** N/A — this is a **win**.

### [SEVERITY: informational] No hand-rolled binary search

- **Lesson satisfied:** Lesson 6.1 (the canonical bug). The codebase uses `db.Where(...)` (SQL indices + btree) for all membership / range queries. No Go-level binary search. `grep` for `lo\s*\+\s*hi\s*/\s*2` / `lo\s*\+\s*(hi\s*-` / `sort\.Search` / `binarySearch` returns zero hits.
- **Effort:** N/A — this is a **win**.

### [SEVERITY: informational] No GCD / mod-exp / primality / crypto reinvented

- **Lesson satisfied:** Lesson 4.29 (don't roll your own crypto). The auth path uses `crypto/sha256` (`internal/database/probekey.go:39`), `crypto/subtle` (`internal/api/handlers/handlers_probes.go:788`), and `crypto/aes-gcm` via `crypto.go`. No custom big-int arithmetic, no homebrew GCD, no custom primality.
- **Effort:** N/A — this is a **win**.

---

## Project-specific invariants checked

### sFlow `sampling_rate × bytes` multiplication — FAIL

- **Insert path** (`internal/sflow/sflow.go:324`): `Bytes: uint64(frameLength)` — missing multiplier.
- **Database schema** (`internal/models/models.go:692`): `Bytes uint64` stores the unscaled frame_length.
- **Raw SUMs** (`internal/database/flows.go:188-192, 226`): `SUM(bytes)` and `SUM(packets)` — unscaled.
- **Rollup SUMs** (`internal/database/flows.go:561`): `SUM(bytes) as bytes_sum` — unscaled.
- **Read-path partial fix** (`internal/database/flows.go:232-236`): `EstimatedBytes = TotalBytes × AvgSamplingRate` — only the top-level `TotalBytes` is scaled; `TopSources`, `TopDestinations`, `TopConversations`, `TopPorts`, `BytesOverTime`, `LocalTraffic` are all unscaled.
- **Plan remediation:** Phase 0 (`tasks/SFLOW-NOC-REDESIGN-PLAN.md` §9) — not yet shipped.

### sFlow `drops` field — FAIL

- **Wire DTO** (`internal/relay/relay.go:68-95`): no `Drops` field.
- **UDP parser** (`internal/sflow/sflow.go:213-298`): `drops` field is *commented in the format description* (lines 258, 265) but never read from the datagram.
- **Parsed struct** (`internal/sflow/sflow.go:16-30`): no `Drops` field.
- **GORM model** (`internal/models/models.go:673-700`): no `Drops` column.
- **Database layer** (`internal/database/flows.go` and entire `internal/database/`): no `SaveAgentDrops`, no `RecordSamplingRateChange`, no `flow_agent_drops` table, no `flow_sampling_rate_changes` table.
- **Alerts** (`internal/alerts/alerts.go`): no alert policy for `SFLOW_AGENT_DROPS`.
- **NOC strip** (`internal/report/model.go`): no `drops` widget.
- **Plan remediation:** Phase 0 (`tasks/SFLOW-NOC-REDESIGN-PLAN.md` §6.2, §9.2, §9.3) — not yet shipped.

### 100k samples/sec shape — FAIL

- **Single goroutine** (`internal/sflow/sflow.go:142-171`): one `readLoop`, one `*net.UDPConn`. No `SO_REUSEPORT`. No worker pool.
- **No `SetReadBuffer(8 MB)`** (`internal/sflow/sflow.go:114`): default kernel buffer (typically 64 KB on Linux; 212 KiB with autotuning). At 100k samples/sec × ~256 B/datagram ≈ 25 MB/s, default buffer will be overrun.
- **GORM `Create`** (`internal/database/ping.go:189`): per-row INSERT, not `pgx.CopyFrom`.
- **No per-agent token bucket** (`internal/sflow/sflow.go:162-167`): the `allowedIPs` map is exact-match only, not rate-limited.
- **No `sync.Pool`** for `ParsedFlow` (see finding above).
- **Plan remediation:** Phase 2 (`tasks/SFLOW-NOC-REDESIGN-PLAN.md` §2.1 line 28, §4 #8, §5) — not yet shipped.

### Wire protocol `omitempty` discipline — PARTIAL

- **Collector→server wire** (`internal/relay/relay.go:68-95`): the `FlowSample` DTO has **no `omitempty` on any field**. This is correct for sFlow semantics — every wire field is required to be present (the collector always populates `sampling_rate`, `bytes`, etc.). Adding `omitempty` here would invite silent field drops.
- **Optional fields** (`internal/relay/relay.go:106, 118, 126`): `SchemaVersion`, `ObservedHostKeys` correctly use `omitempty`.
- **Internal REST responses** (`internal/api/response/response.go:16-18`): `Data`, `Error`, `Message` use `omitempty` — correct.
- **Lessons.md rule** (`tasks/lessons.md:80-83`): "any new field on the wire is `omitempty`. The api-side parser must tolerate missing fields." Currently satisfied by the existing collector (which is in lockstep, per relay.go header comment lines 18-20). New fields the plan proposes (`drops`, `as_path`, `communities`, etc., per plan §7) should use `omitempty`. **Forward-looking PASS** for current shape; ensure plan §7 omitempty rule is enforced when implementing.

---

## Wins

1. **Crypto/rand discipline** is excellent. No `rand() % n` anywhere; no `math/rand` in production paths; rejection sampling via `crypto/rand.Int(reader, big.NewInt(n))` is used uniformly. Lesson 3.1/3.2/3.5 PASS.
2. **Constant-time compares** for all auth-secret comparisons (probe key, SNMP community, CSP nonce). Lesson 3.3 / 4.29 PASS.
3. **Error wrapping discipline** is enforced by automated tests (AUDIT-080, AUDIT-081). 42 `errors.Is` hits across `internal/database/**`; 100% of error returns use `%w`. Lesson 4.20 PASS.
4. **LRU with map+list** in the IP rate limiter is a textbook correct multi-linked structure with load-factor cap. Lesson 2.25 / 6.4 PASS.
5. **Token-bucket per-IP rate limiter** in `internal/snmp/trap.go` with explicit `maxRateLimitedIPs = 10000` cap is a clean Lesson 6.4 implementation.
6. **`BatchInserter` shutdown race** (AUDIT-006) is solved with double-checked locking and a `doneCh`-after-flush pattern. Lesson 2.27 PASS.
7. **`getDefaultPassword` regenerates each call** (AUDIT-158) — explicitly tested in `config_audit158_test.go:50-58`. Good property-based test design.
8. **CIDR allowlist helper** (`internal/database/connection_detail.go:805-854`, `cidrToLikePattern`) is bounded (only /8/16/24/32) and explicitly tested for SQL-injection safety via `internal/database/cidr_audit148_test.go`. Lesson 2.8 / 6.3 PASS for the safety property.
9. **`hashNormalized` using MD5** (`internal/configdiff/normalize.go:72-76`) is correct for a change-detection use case. Not collision-resistant on purpose. Lesson 6.3 PASS.
10. **N+1 dashboard query** replaced with batched aggregates (AUDIT-033, `internal/api/handlers/handlers_dashboard.go:606-611`). Lesson 6.9 PASS.
11. **All regexes compiled at package init** (no per-call `regexp.MustCompile` in hot paths). Lesson 1.9 PASS.

---

## Open questions

1. **When is Phase 0 of the sFlow redesign shipping?** Three critical findings (#1, #2, #3 above) all share a single root cause: the `tasks/SFLOW-NOC-REDESIGN-PLAN.md` is in "design / pre-implementation" status. The plan is excellent; the code has not caught up. Should the audit trigger a release-0.11.0 push of Phase 0?
2. **Is `cmd/probe` deletion (Phase 4) blocked** on collector feature parity, or can it be deleted today and the operator base can move to `Firewall-Collector`? Lessons.md #69 says "until then, treat it as read-only legacy" — implies there's a "then" some operators are waiting for.
3. **The `sFlow-NOC-Redesign-Plan.md` §6.1 mentions `flow_rollups` should have a `sampling_rate_weighted_avg` column** but `internal/database/flows.go:479` already has `SamplingRateAvg float64` in the `rollupRow` struct. Is the column addition actually pending, or is the existing column already serving? Plan line 245 implies an `ALTER TABLE ADD COLUMN IF NOT EXISTS sampling_rate_weighted_avg` — but the model field is named `sampling_rate_avg`, suggesting the migration never happened and the column was created with the original name.
4. **Should `internal/sflow/sflow.go:32-44` (dead `FlowSample` struct) be deleted now** as part of Phase 0, or left for Phase 4? Deleting it is one line of code and prevents future confusion; leaving it costs nothing.
5. **`internal/sflow/sflow.go:213, 274` loop bounds** `offset < len(data)-8`: this is signed-int-safe in Go (if `len(data) < 8`, `len(data)-8` is negative and `offset >= 0` is always greater, so the loop exits). But the body re-checks `offset+8 > len(data)` (line 215, 276) and uses `int(sampleLen)` without bounds check against `len(data)-offset` (line 230 uses `data[offset:offset+int(sampleLen)]` — slicing panics on out-of-bounds, but the prior check at line 221 ensures it). Defensive but correct. Worth a test that exercises truncated inputs.
6. **The `getDefaultPassword()` path** (config.go:317) is called once at config-load. The `generateRandomPassword(16)` makes 16 syscalls to `crypto/rand.Int`. Negligible at startup but could be batched into a single `rand.Read(15 bytes)` + indexing into the charset — eliminates the per-char rejection-sampling overhead. Low priority.

---

## Recommendations — priority order

| Priority | Finding | Effort | Owner |
|---|---|---|---|
| **P0** | Fix `Bytes = uint64(frameLength) * uint64(samplingRate)` at insert (`internal/sflow/sflow.go:324`) | S | Phase 0 |
| **P0** | Capture `Drops` in `parseFlowSample` and wire through to `models.FlowSample`, `relay.FlowSample`, `SaveAgentDrops` | L | Phase 0 |
| **P0** | Standardise the read-path math: `SUM(bytes * sampling_rate)` everywhere in `internal/database/flows.go` | M | Phase 0 |
| **P0** | Replace `SaveFlowSamples` GORM `Create` with `pgx.CopyFrom` | M | Phase 0/2 |
| **P1** | Add `SO_REUSEPORT` + `SetReadBuffer(8 MB)` + per-agent token bucket to sFlow receiver | L | Phase 2 |
| **P1** | Add `sync.Pool` for `ParsedFlow` to eliminate 12.5 MB/s heap churn at 100k samples/sec | M | Phase 2 |
| **P1** | Counter-sample parser (ifInOctets / ifOutOctets) + `flow_if_counters` table + `relay.CounterSample` DTO | L | Phase 1 |
| **P2** | Convert `sort.Slice` to `sort.SliceStable` in flows.go:315, 431; devices.go:262; report/model.go:245 | S | any sprint |
| **P2** | Delete dead `FlowSample` struct in `internal/sflow/sflow.go:32-44` | XS | any sprint |
| **P2** | Rename `flow_rollups.sampling_rate_avg` to `sampling_rate_weighted_avg` to match plan §6.1 | S | any sprint |
| **P3** | Delete `cmd/probe/` (or add deprecation README) | XS | Phase 4 |
| **P3** | Bump `internal/sflow` test coverage from 8.5% → 50% (Phase 2) → 100% (Phase 4) | L | Phase 2/4 |
| **P3** | Add doc comment to `meanStdDev` warning about naive summation | XS | any sprint |

---

**Audit close.** No code changes made (this is a read-only audit per the brief). Findings #1, #2, #3 are the headline critical issues; everything else is incremental polish or already-correct code. The `tasks/SFLOW-NOC-REDESIGN-PLAN.md` document is the right plan; the gap is execution, not design.
