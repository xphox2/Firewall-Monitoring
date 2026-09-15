# Admin console performance (plan: ~/.claude/plans/we-really-need-to-dreamy-plum.md)

Benchmarked prod 2026-09-07 after "the /admin page takes minutes to load". The dashboard was not the
problem. `/metrics` shows **no request has ever exceeded 10s** since process start; the real costs are
background I/O and two pages nobody had measured.

## Phase 1 — the unbounded scans (PR #253, v0.11.244)
- [x] `GetAllLatestInterfaces`: unbounded MAX GROUP BY -> correlated subquery from `devices`.
      423,092 buffers / ~1,700ms -> 60 buffers / 0.836ms. Same 146 rows on prod.
- [x] Rejected the `since` bound and recorded why: 3 of 4 callers need a wider window and
      `detectOverlayConnections` has no freshness gate at all.
- [x] Correlated subquery not LATERAL — LATERAL is a syntax error on SQLite (poller test lane).
- [x] `GetLatestInterfaceAddresses`: rewrite REVERTED after measuring. That table is UPSERT-bounded
      (67 rows / 2.5 months) so the GROUP BY wins there, 0.857ms vs 1.282ms. Rationale in the code.
- [x] Deleted 3 redundant `SELECT 1 ... LIMIT 1` work probes (flows x2, syslog x1); the
      `oldestEligibleTimestamp` that follows answers the same question at 1.9ms.
      The flow_rollups one was reading **1,971,092 buffers / 23,234ms every 5 min to return nothing**.
- [x] KEPT the `promoteSyslogSummaries` probe, no ORDER BY: `syslog_summaries` has no
      (interval_type, timestamp) composite, so ordering adds a Sort node.
- [x] `connection_detail` sFlow probes: ORDER BY device_id -> 0.303ms (was a seq scan, request path).
- [x] Per-cycle window cap on `walkAggregationWindows`.
- [x] Tests incl. a CI Postgres-lane test proving the rewrite on a PARTITIONED parent (prod is not
      partitioned; every fresh install is).
- [x] QA: gofmt, build, full test, staticcheck, go mod tidy; adversarial diff review; corrections
      committed; CI; merge.
- [ ] Deploy rust-01 and verify `interface_stats` I/O collapses.
      **Before-rate measured: 13.9 GB/min, 12 seq_scan/min.**

## Phase 2 — batch the dashboard (PR #255, v0.11.245) — MERGED, NOT YET DEPLOYED
User confirmed 2026-09-07: "it's the dashboard that is slow", so this is the targeted phase.
- [x] `computeDashboardSummary` moved onto `dashboardHealthHub`, published from the SAME compute pass
      as health. Served from the snapshot with the `computing`/`age_seconds` contract; never touches
      the DB. Before: ttlCache 15s TTL vs a 30s client poll = **every poll missed**. Measured on the
      deployed v0.11.244 (already PG-tuned): **322-448ms per poll, 1.31s cold**.
- [x] `h.dashHub == nil` guard (NewHandler only builds the hub when db != nil).
- [x] `noisyDevices` per-device rewrite: 15,704ms -> **594ms** warm post-tuning. Re-measured after the
      PG tuning to confirm the rewrite was still worth it — tuning alone got the old form to 3,617ms,
      so yes, 6x.
- [x] `partial` flag + `partial_blocks`, stamped ONCE after both computes.
      **Adversarial review caught the flag was blind to its own motivating case** — `noisyDevices`
      swallowed its errors, so the killed-scan incident would still publish `partial:false`. Fixed,
      with a test that drops the syslog table to stand in for the timeout.
- [x] Refresh default 30 -> 60; `admin.html` placeholder AND the "Blank uses N seconds" hint.
- [x] KEPT the 5-minute idle gate — the refresher is not primary-gated, so removing it reintroduces
      the M11 multi-instance duplication; primary-gating instead leaves followers on `computing`.
- [x] Deleted `dashCache`/`cache.go`/`cache_test.go`; `golang.org/x/sync` moved to indirect.
- [x] Vitals rail branches on the sentinel (it would otherwise label a pending snapshot NOMINAL on
      every admin page) AND on `partial`. Dashboard modules surface `partial_blocks` too — review
      found only the rail did, and the leaderboard lives on the dashboard.
- [ ] **Deploy to rust-01 and verify.** Image is BUILT (`firewall-mon:latest`); the container
      recreate is blocked by the permission classifier and needs the user to say "deploy".
      Verify: `/admin/api/dashboard/summary` should drop from ~400ms to single-digit ms.

## Phase 3 — the Flows page (plan: ~/.claude/plans/we-really-need-to-dreamy-plum.md)

Audited on prod 2026-09-13. The page is **wrong**, not just slow, and two 30s walls stop the long
windows from returning at all. Plan went through two adversarial Fable reviews; both found blocking
errors in my drafts. Third draft is the one being built.

### The walls (measure through the APP, never psql — server statement_timeout is 0)
- `statement_timeout` 30s via DSN (`database.go:155`, default `config.go:419`) — cancels one query.
- `WriteTimeout` 30s (`main.go:567`, default `config.go:372`) — the WHOLE response must fit in 30s.
  `GetFlowStats` fires ~24 sequential queries, so this is the binding constraint.

### Confirmed defects
- [x] Top Conversations / Top Ports raw-only (`flows.go:566`, `:587-588`) — true #1 is NFS at 6,799 MB,
      displayed #1 is 427 MB and the real one is absent.
- [x] TotalPackets raw-only (`:354`) — 24h shows 2.7% of truth, 90d shows 0.05%.
- [x] Sampling chip raw-only (`:359`) — always 1:1; max rollup rate is 1024, 15.3% of 90d bytes sampled.
- [x] Probe filter disables rollups entirely (`:236`) — shows 1.7% of the window, silently.
- [x] 30d/90d fall back to raw-only after a cancelled query; only `log.Printf` (`:338`).
- [x] Unique counts use `max()` of two tiers (`:343-348`) with no approximation marker.
- [x] Detection modal "Sampled flows" 404s — `admin-flows.js:705` hits an unregistered path.
- [x] Chart labels wrong twice: UTC parsed as local (`:1199`) AND `display_timezone` ignored (`:796`).
      Same parse bug in admin-main.js:912, admin-connection-detail.js:681, diagram-panels.js:407,
      admin-dashboard-modules.js:91.
- [x] 6h bandwidth view inflated 5x and spiky — minute buckets applied to a 5m tier (`:600-602`).
- [x] Every chart ends in a false cliff (in-progress bucket plotted as complete).
- [x] CIDR filter rounds masks UP to the octet boundary; /25 returns the whole /24, /6 returns nothing.
- [x] Flow Samples tab + CSV export are raw-only but labelled with the window.
- [x] ProtocolCount capped at 10 by `Limit(10)` (`:424`, `:457`).

### Corrections to my own drafts (do not re-propose)
- `SET LOCAL work_mem` is a NO-OP — GetFlowStats runs no transaction.
- Narrowing the raw base to now-1h is a **correctness regression** — raw is bounded by DELETION, not
  time, and spool replay is an explicitly designed path (`flows.go:812-815`).
- `GetDeviceIDsByProbe` applies ActiveDevices scope — inconsistent with the site filter. Use the
  inline subquery instead.
- Bytes-weighted mean sampling = 1:125, a rate that never existed. Report a range.
- Top-N merge is NOT "provably exact" — at N=10 the port bound (1,094 MB) exceeds the true #10
  (562 MB). **N must be >= 50** (bound 55 MB).
- Phase C premise was false: on prod only `denied_events` is partitioned. flow_samples,
  syslog_messages, flow_rollups, interface_stats, system_status are all flat heaps.
- 90d packets truth is 6,914,320,386 (window), not 11.68B (whole table).

### Build order
**v0.11.247 MERGED (PR #258) and DEPLOYED to rust-01 2026-09-15 00:06 UTC, healthy.**
Verified live: the 404 sample path is gone from the deployed JS, `parseUtcBucket` is
present, the degraded banner is present, no errors since restart. The Flows page
itself still needs a logged-in load to confirm the tiles.

Two adversarial review rounds on that PR, both of which found real blockers:
- Round 1: the `inet` cast aborted on prod's 2,377 empty-address rows; and the
  default 24h view would have shipped permanently degraded (14 panels, ~25s
  sequential, 18s budget). Fixed with `NULLIF` and 4-way concurrency.
- Round 2: the protocols tile came back EMPTY on any degraded window (it was the
  only panel without a raw-only publish); and my `session()` comment asserted a
  GORM statement-corruption that does not exist — the real cause was SQLite
  `:memory:` handing each connection its own database.

Measured after the concurrency change, replayed against prod: **24h completes in
9.5s**. 7d/30d/90d still degrade completely (9 of 14 panels cancelled at 7d, 13 of
14 at 90d) — honest now, but not fixed. That is what Phase B is for.
- [x] **Phase 0** — deadlines per query, short-circuit after first failure, convert the 7 error-
      discarding `Scan()`s, run independent aggregates concurrently. Nothing else is visible without it.
- [x] **Phase A** — the 14 correctness items above.
- [x] **Phase B1** — MERGED (PR #259) and DEPLOYED as v0.11.248 on rust-01 2026-09-15 01:39 UTC.
      Migration v66 applied, all three tables created, backfill running (2 daily buckets/cycle).
      **Verified exact on production**: the first days written match the source byte-for-byte and
      packet-for-packet.
      **Five adversarial review rounds, every one found a real defect.** The worst: the daily tier
      summed only the 1d rollup tier then deleted the hourly rows for that day — and the promotion
      boundary is never day-aligned, so on prod one day held 767 MB in one tier and 42 GB in the
      other. That would have kept 1.8% of the day, forever, for every new boundary day.
      Rounds 3-5 each found holes in the CHANGE-DETECTION bookkeeping, every fix opening the next.
      Round 5 confirmed the right answer was to DELETE the mechanism: the walk over changed buckets
      now always completes, which removed the cursor, the epoch ceiling and three silent-staleness
      bugs together (239 net lines). 15 tests, every one mutation-verified.

      **BACKFILL COMPLETE 2026-09-15, verified on prod.** 157 daily buckets (2026-03-02..08-16) +
      695 hourly (08-17..now) = **634,952 rows total** (389k cube + 245k top-N + 1.8k bucket)
      against 118M in flow_rollups. Zero errors in 24h. Steady state is exactly 2 hourly buckets
      per 5-min cycle, matching the measured prediction.

      **The payoff, measured:** a 90-day aggregate returns **113 ms** from the summary versus
      **31,595 ms** from flow_rollups — and that 31.6s is OVER the 30s statement_timeout, which is
      precisely why the 90-day view was broken. Both return **identical** figures (342,031,562 flows
      / 3,949,471,419,102 bytes / 7,079,816,102 packets), which also proves the two summary tiers
      are disjoint: an overlap would have made the summary total larger. Three tables cover the WHOLE six-month history in
      **under 1M rows against 118M**, and reproduce bytes/packets/flows **exactly** (verified by
      query on prod before writing code). Writer recomputes rather than merges, so late spool
      replay is absorbed and the same code path IS the backfill. Measured ~0.5s per bucket; ~885
      buckets catch up in under twenty 5-minute cycles.
- [ ] **Phase B2** — switch the read path onto the summary. Deliberately separate: the backfill
      has to run first so the output can be diffed against the live path on real data, which beats
      any fixture. A draft read path is parked in the scratchpad.
      Contract settled: cube answers any combination of the low-cardinality dimensions; a filter on
      src/dst/port/asn is NOT summary-compatible and keeps the live path; a dimension filter means
      the top-N panels must report degraded rather than show unfiltered talkers beside filtered
      totals.
- [ ] **Phase C** — fold the long tail at 5m->1h (88.6% of rows carry 1.08% of bytes) vs partitioning.
      NOTE the corrected premise: on prod only `denied_events` is partitioned (8 children).
      flow_samples, syslog_messages, flow_rollups, interface_stats and system_status are all flat
      heaps — confirmed again by the v0.11.247 startup warnings. `migrate.go` describes a FRESH
      install, not this box.

## Phase 3 remainder — other slow pages — NOT STARTED
- [ ] Syslog page hourly chart: 7,421ms with a 103MB disk sort -> 1.96ms from `syslog_ingest_hourly`
      (already populated; no device_id, so filtered views fall back).
- [ ] Probes page: 4 unbounded per-probe counts, syslog one = 4,238ms. `estimateRowCount` is
      per-TABLE so it is not a drop-in.
- [ ] Static assets are `no-store` with no ETag: 34 files, 501KB brotli, re-fetched every load.
- [ ] `/admin/api/dashboard/noisy` should serve from the snapshot it already contains.
- [ ] `vpn_status`: 228k seq scans / 54.3B tuples, needs a timestamp-leading index.

## Operator step — DONE 2026-09-07 23:43 UTC
- [x] PostgreSQL tuning applied via `ALTER SYSTEM` (not a postgresql.conf edit: the entrypoint's
      tuning block only runs when PGDATA is empty, and the host path is root-inaccessible).
      Live: shared_buffers **8GB**, effective_cache_size **20GB**, maintenance_work_mem **1GB**,
      effective_io_concurrency **2**, work_mem **16MB**, random_page_cost 4 (disk is rotational).
      Backup at `postgresql.conf.bak-20260907-perf`. The old VACUUM step was moot —
      relallvisible/relpages on syslog_messages is 99.99%.
- [ ] **work_mem is 16MB, not the planned 32MB.** `/dev/shm` is the Docker default 64MB and
      `dynamic_shared_memory_type = posix`, so parallel hash joins allocate work_mem-sized segments
      there; 32MB x 3 participants would fail. Needs `shm_size: 1g` on the compose service, which
      must go through a PR — editing the tracked docker-compose.yml in place on rust-01 caused the
      drift that blocked `git pull` in v0.11.179.

### Combined effect of v0.11.244 + the tuning, measured on prod
`interface_stats` disk reads: **13.9 GB/min -> 1.575 (code fix) -> 0.053 GB/min (tuned)** = 262x,
with a **98.6% buffer cache hit ratio** and 0 seq scans/min. Query-level, warm: noisy-devices
15,704ms -> 3,617ms (tuning) -> 594ms (rewrite); dashboard summary 24h COUNT 649ms -> 327ms; syslog
hourly chart 7,421ms -> 5,825ms and STILL spills 103MB (needs the meter, not more work_mem).

### Counter-example worth remembering
`cleanup.go`'s `SELECT id ... WHERE timestamp < ? LIMIT 10000` looks like the same probe
anti-pattern but is CORRECT as written: **15.2ms / 446 buffers**. Adding `ORDER BY timestamp` makes
it **4,594ms / 422,877 buffers** — 300x worse. The LIMIT trap is about a probe expecting ZERO
matches; a batch query expecting MANY wants the opposite plan. Never blanket-apply.

---

# Device retire / restore / purge (plan: ~/.claude/plans/when-i-removed-a-snappy-tower.md)

## PR A — retire/restore + exclusions + orphan recovery + site guard + UI
- [x] Backend: Device.RetiredAt + migration v60; RetireDevice/RestoreDevice; DELETE repointed; UpdateDevice 409; CreateDevice 409 retired_device_id; IsUniqueViolation
- [x] Backend: ActiveDevices scope + GetActiveDevices; GetDevicesByProbe/GetDeviceIDsByProbe/MarkStale/bumpDevicesOnline/heartbeat host-key filters; poller + dashboards + reports + IRC
- [x] Backend: retire acks/resolves open alerts (CheckEscalations quiet); probe delete/decommission counts ignore retired; DeleteProbe nulls retired probe_id
- [x] Backend: migration v61 materialize_orphaned_devices (device_id > 0, name/IP parse, setval on PG)
- [x] Backend: DeleteSite guard ErrSiteHasMembers → 409
- [x] Tests: retired_scope, retire acks alerts, update 409, create 409, migration v62, site guard, probe lifecycle
- [x] UI: Devices tabs Active/Retired/All, RETIRED badge, Retire/Restore actions, same-name restore prompt, alerts marker, device-detail banner + 404 copy
- [x] Docs: CHANGELOG (new top entry), README endpoint, DATA-RETENTION, OPERATIONS; ServerVersion bump
- [x] QA: (PR #247 merged, deployed 2026-09-07 00:27 UTC, device 4 recovered) gofmt, staticcheck, build, test -count=1; adversarial diff review; PR; CI; merge; deploy rust-01; verify device 4 retired + alert link

## v0.11.240 follow-up
- [x] migration v62 close_alerts_for_retired_devices — PR #248 merged, deployed 2026-09-07 00:47 UTC, verified

## v0.11.241 — names unique among ACTIVE devices (plan approved 2026-09-07)
- [x] Backend: Name tag index-only; migration v63 partial unique index; testing.go partial index; RestoreDevice single statement; CreateDevice reuse_name wrapper + retired_count; tests; docs; changelog 0.11.241
- [x] UI: AC.choose / AC.promptText / AC.deviceOptionLabel; add-device 3-way chooser; rename-on-restore; retired date inline; pickers labelled; shell guardrail updated
- [x] QA gates; adversarial diff review; PR #249; CI; merged; deployed rust-01 2026-09-07 01:34 UTC; index shape + v0.11.241 verified

## v0.11.242 — device UUID + IPSec identity from UUID (plan approved 2026-09-07)
- [x] Backend: Device.UUID + BeforeCreate; UpdateDevice Omit(uuid); migration v64 backfill; tests; docs; changelog 0.11.242
- [x] UI: wizard defaultIdentity fwm-<uuid>; help text + placeholders; UUID on detail page + edit modal; shell guardrail
- [x] QA gates; adversarial diff review; PR #250; CI; merged; deployed rust-01 2026-09-07 02:26 UTC; 6/6 uuids populated, v0.11.242

## v0.11.243 — permanent purge job (plan approved 2026-09-07)
- [x] Backend: DevicePurgeJob + v65; devicePurgeTables + reflection coverage; batchedDeleteWhere (ORDER BY, per-table batch, timeouts, retries, partitions); worker (CAS claim, advisory lock, stale requeue, shutdown flip); handlers + 5 admin routes + reauthCaller; docs; changelog 0.11.243
- [x] UI: purge-device action, #purge-device-modal (estimate/name/password/2FA), PURGING badge + cancel, polling, detail banner
- [x] QA gates; 2 review rounds; scratch-PG16 verification; PR #251; CI; merged; deployed rust-01 2026-09-07 04:55 UTC; v65 + worker verified, v0.11.243
