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

## Phase 2 — batch the dashboard (the original ask) — NOT STARTED
- [ ] Move `computeDashboardSummary` onto `dashboardHealthHub`; serve from the snapshot with the
      `computing`/`age_seconds` contract. Today its ttlCache TTL is 15s against a 30s client poll, so
      **every poll misses** and pays 545ms, from the vitals rail on EVERY admin page.
- [ ] `h.dashHub == nil` guard on `GetDashboardSummary`.
- [ ] Rewrite `noisyDevices` (15,704ms -> 1,876ms). Skip zero counts; do NOT add ActiveDevices.
- [ ] Publish a `partial` flag — a statement killed by the 30s timeout currently publishes a
      confident zero.
- [ ] Refresh default 30 -> 60; update `admin.html` placeholder.
- [ ] KEEP the 5-minute idle gate (the refresher is not primary-gated; removing it reintroduces the
      M11 multi-instance duplication).
- [ ] Delete `dashCache`/`cache.go`/`cache_test.go` + `go mod tidy` (drops golang.org/x/sync).
- [ ] Vitals rail must branch on the sentinel — today it paints 0/0/0 and labels it NOMINAL.

## Phase 3 — the pages an operator actually waits on — NOT STARTED
- [ ] **Flows page: 9.5s at 24h, 42.1s at 7d for ONE of ~8 queries.** Best candidate for the
      original complaint. Needs its own design pass (the COUNT DISTINCT is already "approximate").
- [ ] Syslog page hourly chart: 7,421ms with a 103MB disk sort -> 1.96ms from `syslog_ingest_hourly`
      (already populated; no device_id, so filtered views fall back).
- [ ] Probes page: 4 unbounded per-probe counts, syslog one = 4,238ms. `estimateRowCount` is
      per-TABLE so it is not a drop-in.
- [ ] Static assets are `no-store` with no ETag: 34 files, 501KB brotli, re-fetched every load.
- [ ] `/admin/api/dashboard/noisy` should serve from the snapshot it already contains.
- [ ] `vpn_status`: 228k seq scans / 54.3B tuples, needs a timestamp-leading index.

## Operator step (user approved 2026-09-07, not yet done)
- [ ] postgresql.conf: shared_buffers 8GB, effective_cache_size 20GB, work_mem 32MB,
      maintenance_work_mem 1GB, effective_io_concurrency 2. One container restart.
      **The old VACUUM step is moot** — relallvisible/relpages on syslog_messages is 99.99%.

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
