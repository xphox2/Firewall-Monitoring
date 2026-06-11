# Firewall-Mon Reliability Review (2026-06-11)

Read-only re-audit of `E:\Golang\OpenCode\Firewall-Mon` focused on stability and reliability, following up the 2026-06-10 audit (`tasks/CTO-LOOP-2026-06-10.md`) and the two recent fixes it requested (AUDIT-094 entrypoint fail-fast + v0.10.391 statement-timeout on the lock-conn / dedupe tx).

Build status verified by reading source: `gin.Default()` includes `gin.Recovery()`, so the HTTP path is panic-safe. Long-lived background goroutines (poller, report scheduler, IRC bot, login-attempt pruner, trap callback, batcher ticker, retention sweep on the poller) have **no `recover()` anywhere** — a single nil deref in the alert evaluator or an out-of-bounds in the connection-detail diff path will crash the whole process.

## Prior findings re-validation

| # | Finding | Status |
|---|---|---|
| **B-1** | Probe goroutine deadlock / lockout cascade (`-race` needed) | **Still unresolved.** The prior `cmd/poller/main.go:170-188` semaphore + per-device goroutine is unchanged. With -race + CGO off the regression is still latent; the relay client (H-3) is broken anyway, so no probe data reaches this path. **Action: re-open. Build the `-race` test harness that was deferred.** |
| **H-1 perf** | `GetProbeStats` 104 queries (`handlers_probes.go:727-793`) | **Unchanged.** No fix merged. |
| **H-1 sec** | `/api/public/connections` topology leak (`handlers_dashboard.go:425-426`) | **Unchanged.** |
| **H-2 sec** | Login LRU fail-open burst (`middleware.go:85-92, 174-187`) | **Unchanged.** `AuthManager.ValidateCredentials` still keyed on `username+IP`. |
| **H-3 sec** | Probe wire-format `Authorization: Bearer` missing on relay | **Unchanged.** `internal/relay/relay.go` sets zero `Authorization` headers on `r.httpClient.Post`/`Get` calls (lines 265, 307, 475, 624, 653, 676, 699, 773, 793, 813). The server requires it (`handlers_probes.go:670-688`). The fleet is silently broken unless the server-side check was bypassed. |
| **AUDIT-094** | entrypoint fail-fast | **Verified correct** (see below). |
| **v0.10.391** | `SET LOCAL statement_timeout = 0` on lock conn / dedupe tx | **Verified correct** (see below). |
| 1-7 R perf | N+1, missing composite indexes, etc. | **Unchanged.** Sprint-2 backlog. |
| API shutdown | defer chain + 10s grace | **Verified correct** (see below). |
| DB pool | 15/10/5 per process | **Verified correct.** |

### AUDIT-094 entrypoint verification (`entrypoint.sh`)

Confirmed correct as-shipped:

- `set -e` is on (line 2).
- The 3 daemons are backgrounded with `&` and their PIDs captured (lines 177-186).
- `trap shutdown INT TERM` (line 212) is the signal path: calls `teardown` → kills the three PIDs → waits → stops PG → `exit 0`. `kill … 2>/dev/null || true` and `wait … 2>/dev/null || true` (line 200-201) prevent `set -e` from leaking 143 into a clean `docker stop` exit.
- **Critical** the fail-fast loop on lines 229-236 is now:
  - `set +e` so the API's non-zero status doesn't abort the script before teardown.
  - `wait "$API_PID"` blocks on the **API only** (line 230), not `wait -n`. This is the regression-fix: `wait -n` (the v0.10.402 first cut) tore down the whole stack on ANY daemon exit, which crash-looped the container when the trap-receiver correctly bailed out for missing `SNMP_TRAP_COMMUNITY` (AUDIT-012).
  - On API exit, `teardown` runs and `exit 1` so Docker's `restart: unless-stopped` brings up a fresh complete stack.
  - The non-essential daemons (poller, trap) dying no longer tears down the API. A "traps disabled" degradation stays visible in the UI instead of looping every few seconds.

Edge case worth flagging in a future CTO loop, not a fix-now: if the **poller** dies and never comes back, the API's data goes stale silently — there is no `MAILTO`-style alert on poller death. The `AUDIT-040` advisory-lock check is the only thing that prevents the operator from seeing this in a UI that's been "online" for 3 days.

### v0.10.391 statement-timeout verification

- **Migration lock connection** (`internal/database/migrations.go:120-138`): `sqlDB.Conn(ctx)` pins a backend, `SET statement_timeout = 0` lifts the AUDIT-037 DSN-injected 30s cap before `pg_advisory_lock($1)`, returns a release func that calls `pg_advisory_unlock($1)` on the same pinned conn. ✅ Correct.
- **Interface-address dedupe tx** (`internal/database/migrate.go:582-599`): inside the `d.db.Transaction(...)`, `tx.Exec("SET LOCAL statement_timeout = 0")` lifts the cap, then the DELETE-`USING` dedupe and `CREATE UNIQUE INDEX IF NOT EXISTS idx_ifaddr_dev_ip` run. ✅ Correct.
- **Gaps (new findings — see REL-04 and REL-05 below):** the same `SET LOCAL statement_timeout = 0` discipline is **not** applied to:
  - `convertEmptyTableToPartitioned` (the v2 partition migration; `migrate.go:404-447`).
  - `EnsurePartitions` (the monthly partition creation loop; `migrate.go:208-341`).
  - `ConfigureAutovacuum` (the per-table `ALTER TABLE … SET (autovacuum_…)`; `migrate.go:495-528`).
  - `dropPartitionsOlderThan` (the cleanup-time `DROP TABLE partition_…`; `cleanup.go:101-141`).
  These are all DDL/maintenance paths that can run on large tables; on a busy production DB the 30s default will kill the startup-time partition creation or cleanup-time DROP, leaving the process running with stale partitions forever.

### API shutdown sequence verification (`cmd/api/main.go`)

- `signal.Notify(quit, SIGINT, SIGTERM)` (line 441-442) + `errCh` from the listener goroutine (line 427-439) — both paths lead to the same shutdown block (line 444-462). ✅
- `bgCancel()` (line 453) cancels the login-attempt pruner before the HTTP drain. ✅
- `server.Shutdown(ctx)` (line 458) with a 10s timeout. ✅
- `defer releaseSingleton()` (line 237), `defer db.Close()` (line 186), `defer snmpClient.Close()` (line 331), `defer ircManager.Stop()` (line 407) all run on return. ✅
- The pre-fix `log.Fatal` mid-handler is gone (AUDIT-086); the listener now sends to `errCh` instead. ✅
- **Gap:** the `batcher.Stop()` (which waits for the final flush) is in `db.Close()` (`database.go:412-414`), but the listener-error path doesn't `bgCancel` the login pruner before `ircManager.Stop()` — `ircManager.Stop` only closes the quit chan; the goroutines it spawned are joined by `m.wg.Wait()` (bot.go:111) but nothing in cmd/api enforces a deadline on that wait. A wedged IRC bot would block the process for the full 10s drain. Minor — see REL-11.
- **Gap:** `server.Shutdown(ctx)` returns when in-flight requests are drained OR 10s elapses. There's no `defer ctx cancel()` ordering with the `defer cancel()` for the inner 10s (line 455-456) that's already there. ✅ Actually fine.

## New findings

### [blocker] REL-01 — Background goroutines have no `recover()`; panic in alert/IRC/report path kills the process
**File:** `cmd/api/main.go:294-308`, `cmd/poller/main.go:182-186, 1480-1486`, `cmd/trap-receiver/main.go:84-91`, `internal/irc/bot.go:128, 191, 998`, `internal/report/report.go:34-37`, `internal/database/batcher.go:48-65`
**Category:** panic
**Failure mode:** `go func()` is used in 9 long-lived sites and **none** of them `defer recover()`. The HTTP path is safe (gin.Default includes gin.Recovery), but:
- `cmd/api/main.go:297-308` — login-attempt pruner; a nil deref in `authManager.PruneExpiredAttempts` kills the API.
- `cmd/poller/main.go:182-186` — per-device SNMP poll goroutine. One bad `client.GetInterfaceStats` return shape that triggers a downstream nil map access (rolling-stats internal map, for example) tears down the whole poller.
- `cmd/trap-receiver/main.go:84-91` — `trapReceiver.Start(...)` callback (line 84) is invoked synchronously from the gosnmp library's goroutine for **every incoming trap** (per `internal/snmp/trap.go:134`). Any panic in `alertManager.ProcessTrap` or in the pre-format log path crashes the trap-receiver.
- `internal/irc/bot.go:191-194` — `reconnectLoop`'s `go func(b *Bot) { b.Start() }` per bot. `b.Start()` calls `conn.Connect(addr)` (line 371) which on a misbehaving TLS peer can panic; the bot's outer goroutine is unprotected.
- `internal/report/report.go:35-37` — `runDaily` and `runWeekly` goroutines. `report.BuildDailyReport` and `report.BuildWeeklyReport` walk every device and build the entire HTML body in memory; a malformed `interface_stats` row that bypasses the chart-render nil-checks crashes the poller.
- `internal/database/batcher.go:48-65` — the per-batcher ticker goroutine runs `b.Flush()` which calls `flushFn(items)`. `flushFn` for syslog/trap/ping is `d.db.Create(&items).Error`; an item with a non-nullable column set to nil (e.g. timestamp, severity) panics inside GORM. The ticker goroutine is unprotected → process exit.
**Impact:** Any one of the above panics takes down the daemon. Because entrypoint.sh now treats only the API as essential, a poller panic puts the WHOLE data-collection path offline silently — no alerts, no chart data, no email reports. A trap-receiver panic stops alert ingestion from the SNMP trap path. A report-scheduler panic halts daily/weekly emails but is the least bad case.
**Fix:** Wrap every long-lived `go func()` in a small helper:
```go
func safeGo(name string, fn func()) {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                slog.Error("goroutine panic", "name", name, "panic", r, "stack", debug.Stack())
            }
        }()
        fn()
    }()
}
```
Replace every `go func() { … }()` in the files above with `safeGo("poller-tick", func(){ … })`. Add a Prometheus counter `fwmon_goroutine_panics_total{name=…}` so the operator sees the silent recovery.
**Effort:** S (mechanical replacement; ~12 sites)

### [blocker] REL-02 — Server-side idempotency gap: 14 of 18 probe `Receive*` endpoints have no `X-Probe-Batch-ID` dedup
**File:** `internal/api/handlers/handlers_data.go:52-100 (template), 308-995 (other handlers)`
**Category:** retry / data-integrity
**Failure mode:** `batchDedupCheck` and `markBatchIfOK` (lines 26-50) are only invoked in `ReceiveSyslogMessages`, `ReceiveTrapEvents`, `ReceiveFlowSamples`, and `ReceivePingResults` (lines 52, 104, 147, 191). The other 14 `Receive*` handlers — `ReceiveSystemStatuses`, `ReceiveInterfaceStats`, `ReceiveVPNStatuses`, `ReceiveHAStatuses`, `ReceiveSecurityStats`, `ReceiveSDWANHealth`, `ReceiveLicenseInfo`, `ReceiveConfigRevision`, `ReceiveProcessSnapshot`, `ReceiveInterfaceErrors`, `ReceiveSensorDetails`, `ReceiveLicenseDetails`, `ReceiveInterfaceAddresses`, `ReceiveProcessorStats`, `ReceiveHardwareSensors` — do **not** call the dedup helpers. The relay's `sendBatch` (relay.go:465-499) retries on non-2xx up to 3 times with jitter, AND the `processed_batches` cleanup is 2 days (cleanup.go:227) — a probe that retries on a server-side hiccup will double-write 14/18 of its data streams. The prior audit flagged the **collector** side (AUDIT-070 in the Firewall-Collector repo); the **server** side was identified as a finding (Audit #70 mentioned the table exists on both ends), but the dedup is implemented in only 4 of 18 server endpoints.
**Impact:** Silent data duplication in 14/18 ingest paths. For `interface_stats` (UPSERT-merged by `(device_id, ifIndex, timestamp)` — safe), `vpn_status` (UPSERT by device+tunnel), and most others, the **id columns differ**, so GORM `Create` will INSERT new rows on retry → doubled rows, doubled chart data, doubled alert state. The duplicates are NOT cleaned up by the 2-day `processed_batches` retention because the `processed_batches` row is never written.
**Fix:** Add `batchID, dup := h.batchDedupCheck(c, probe.ID); if dup { return }; defer h.markBatchIfOK(c, probe.ID, batchID)` to the top of every other `Receive*` handler. Boilerplate — a single edit per handler. Add a regression test in `handlers_data_idempotency_audit042_test.go` that exercises one of the 14 unprotected endpoints with a duplicated `X-Probe-Batch-ID`.
**Effort:** S

### [blocker] REL-03 — Relay's `sendBatch` consumes the queue then sends; the queue copy is dropped on retry, but the in-memory queues are not — and there's no disk spillover on the server side at all
**File:** `internal/relay/relay.go:430-499`, `cmd/probe/main.go` (no disk spillover)
**Category:** durability / data-loss
**Failure mode:** On the probe side, `syncData()` (line 430) **drains** the in-memory queues (`r.trapQueue = nil`, etc.) before the HTTP POST. If the POST fails 3× (the retry loop) and then returns, the events are **gone from the queue but never made it to the server**. The probe's `r.trapQueue`, `r.pingQueue`, `r.syslogQueue`, `r.flowQueue` are pure in-memory `[]*T` slices — no WAL, no disk buffer, no on-disk queue. A probe restart or process crash in the retry window loses every undelivered event.

The audit-pinned `internal/database/batcher.go:23-143` and its on-disk-WAL follow-up (the comment at line 22 says "AUDIT-006 (durability half — WAL-on-disk + fsync) is deferred: that requires a disk format design and operational changes for the operator, and is a separate commit") is the probe side. **The relay on the collector side is what the comment refers to**, and 9 months later that follow-up still hasn't landed.

The server side (the Firewall-Mon ingest path) buffers via the `BatchInserter[SyslogMessage]` / `BatchInserter[TrapEvent]` / `BatchInserter[PingResult]` (database.go:188-196) — those have the AUDIT-006 Stop-then-Flush guarantee but **also no on-disk WAL**; a Postgres-fails-just-as-batcher-flushes loses the batch. The 2-second flush interval on syslog and 5-second on trap/ping is the worst-case loss window.
**Impact:** On a 3-retry POST that exhausts attempts, the probe drops ~10K events (the queue cap, line 49) per process cycle. A probe restart loses whatever's in queue. A Postgres restart in the flush window loses a batch.
**Fix:** (1) Probe: spill queue to a rolling JSON-lines file in `os.TempDir()` / configurable path on overflow, replay on next `Start()`. Format: one JSON object per line, one file per type, rotate on size. (2) Server: convert `BatchInserter` to a `fsync`-then-append WAL before accepting the item into the in-memory buffer (item is "durable" only after fsync returns). (3) Probe `sendBatch`: on final retry failure, re-append the items to the queue (NOT just drop), so a flush is retried on the next tick. See probe's AUDIT-006 deferral in `batcher.go:20-22`.
**Effort:** L (the WAL format design + replay + crash-recovery test is a multi-day change)

### [high] REL-04 — Maintenance DDL in `migrate.go` and `cleanup.go` runs under the 30s default `statement_timeout`; large-table DDL will fail at 57014
**File:** `internal/database/migrate.go:404-447 (convertEmptyTableToPartitioned)`, `migrate.go:208-341 (EnsurePartitions)`, `migrate.go:495-528 (ConfigureAutovacuum)`, `internal/database/cleanup.go:101-141 (dropPartitionsOlderThan)`
**Category:** timeout
**Failure mode:** v0.10.391 (file `migrations.go:135` and `migrate.go:584`) lifts `statement_timeout = 0` on **two** maintenance paths: the migration-lock connection and the interface-address dedupe transaction. But the same discipline is missing on five other DDL/maintenance paths. Each of these:
- `convertEmptyTableToPartitioned` (migrate.go:404): runs inside `d.db.Transaction(func(tx) { ... })` and does `ALTER TABLE … RENAME`, `CREATE TABLE … PARTITION BY RANGE`, `ALTER TABLE … ADD PRIMARY KEY`, sequence reassignment, `DROP TABLE`. On a 100M-row table the `CREATE TABLE … (LIKE … INCLUDING DEFAULTS)` copies every column default; on a 1B-row table it can take minutes. The comment at line 348-353 explicitly says "Converting a populated ~100M-row table is a copy-rewrite far too heavy to run at startup" — so the function is gated to empty tables — **but the `LIKE` of an empty table with many columns and many indexes is still measurable**, and the sequence reassignment's `pg_get_serial_sequence` call holds a brief lock. On a busy DB the 30s default will 57014 here too.
- `EnsurePartitions` (migrate.go:251-338): the inner per-partition loop runs `CREATE TABLE … PARTITION OF …` + 2-3 `CREATE INDEX` per month × 7 months × 6 tables = ~150 DDL statements. On a DB with heavy concurrent traffic each `CREATE TABLE PARTITION OF` takes an `AccessExclusive` lock on the parent; if the pool is contended the 30s default can trip.
- `ConfigureAutovacuum` (migrate.go:511-525): 13 tables × `ALTER TABLE … SET (autovacuum_…)`. Each is fast individually, but on a partitioned parent with many children the autovacuum settings need to be re-set on children; Postgres does this transparently, but a slow disk means cumulative time > 30s.
- `dropPartitionsOlderThan` (cleanup.go:101-141): on the poller's daily cleanup cycle, drops the partitions whose upper bound is ≤ cutoff. Each `DROP TABLE` is normally instant, but on a system running `VACUUM` or holding an `AccessShare` lock, can stall. Runs at 30s default; not in a transaction (DDL auto-commits in Postgres, so no rollback is possible anyway).
**Impact:** The first AUDIT-037 application (default 30s) was specifically to prevent runaway queries from killing the server. The fix correctly applies to OLTP paths. But on a busy production DB the maintenance DDL hits the same cap and the relevant v0.10.391 fix didn't extend to it. A 57014 here leaves the partition scheme partially-created (e.g. some months exist, some don't) and `EnsurePartitions` logs a warning and moves on — so the table silently degrades.
**Fix:** At the top of each of the five functions, when `d.dialect.IsPostgres()`, pin a connection and lift the timeout:
```go
if d.dialect.IsPostgres() {
    sqlDB, _ := d.db.DB()
    conn, _ := sqlDB.Conn(context.Background())
    defer conn.Close()
    conn.ExecContext(context.Background(), "SET statement_timeout = 0")
    d.db = d.db.WithContext(… using the conn …) // or run the DDL through the conn directly
}
```
For the `convertEmptyTableToPartitioned` case the same `SET LOCAL` pattern as `ensureInterfaceAddrUniqueIndex` works inside the transaction. For the partition-creation loop, lift the timeout on a single dedicated connection for the loop duration.
**Effort:** S for the partition loop and the autovacuum block (lift + restore). M for the conversion tx (need a test on a real DB; the in-line "SET LOCAL" pattern is already proven at migrate.go:584).

### [high] REL-05 — Poller's `Stop()` does not wait for in-flight per-device SNMP goroutines; mid-poll devices see write to a closed DB
**File:** `cmd/poller/main.go:170-188 (pollAllDevices per-device goroutines)`, `cmd/poller/main.go:1423-1431 (Stop)`
**Category:** shutdown / use-after-close
**Failure mode:** `pollAllDevices` launches 5 concurrent `go p.pollDevice(device)` (gated by `sem`). The `Start()` loop's `<-p.stopChan` returns immediately when `Stop()` closes the channel — but the 5 per-device goroutines and any in-flight `db.SaveSystemStatus` / `db.SaveInterfaceStats` / `db.SaveVPNStatuses` / `db.SaveAlert` continue running. `Stop()` then returns, `main()` reaches its end, and `defer db.Close()` (main.go:1472) runs. A late `db.SaveInterfaceStats(interfaces)` from a still-running `pollDevice` will hit a `sql: database is closed` error and log it, but the alert-cooldown map `am.lastAlert` has already been written under `am.mu` for any alert that fired during the cycle — those cooldown entries are lost. Worse, a panic-recovered later in shutdown (REL-01) could resurrect the goroutine after `db.Close` if not properly sequenced.

The report scheduler has the same problem: `reportScheduler.Stop()` (report.go:41-47) closes `stopChan` but doesn't wait for the `runDaily` / `runWeekly` goroutines; the next mid-day `generateAndSendReport(24)` keeps running, hits the closed DB, and logs an error. Both report goroutines are NOT joined.
**Impact:** Stale data on shutdown. A `sendCriticalAlertEmail` that was about to fire when the process received SIGTERM completes its report build (heavy — `report.GatherRecentHistory` runs `p.db` calls for 2h of history per device) but then SMTP-times-out because `db.Close` already ran. The error shows up in the logs as a flood of `sql: database is closed` after every clean restart.
**Fix:**
- `Poller.Stop()` (line 1423) should `defer wg.Wait()` for a `sync.WaitGroup` added around the per-device goroutine launch (similar to `Probe.pollWG` in `cmd/probe/main.go:138-141`). Use a `context.Context` derived from the same `stopChan` and pass it into `pollDevice`; `Stop()` cancels the ctx. `pollDevice` should check `ctx.Done()` between sections and abort.
- `ReportScheduler.Stop()` (report.go:41) should use a `sync.WaitGroup` for `runDaily` and `runWeekly`, with a 10s timeout on the wait (or context-bounded) so it can't deadlock shutdown.
- Both daemons' main `Stop()` should also wait on the report scheduler and the rolling-stats cleanup, in the same 10s shutdown budget.
**Effort:** S for the poller; S for the report scheduler; M for tests that exercise shutdown-while-mid-poll (need a fake DB that delays to force the race).

### [high] REL-06 — IRC `Manager.sendAutoStatus` writes `m.lastStatus` under `m.mu.RLock()` — concurrent map write + race
**File:** `internal/irc/bot.go:216-271`
**Category:** race
**Failure mode:** `sendAutoStatus` takes `m.mu.RLock()` at line 221 and **writes** `m.lastStatus[ch.ID] = time.Now()` at line 268 while still holding the read lock. `Go map` writes under a `sync.RWMutex` in read mode is a data race: a concurrent `sendAutoStatus` on the same manager (one per server goroutine in the statusLoop ticker, but also called from the per-command `handleCommand("status")` path which goes through `b.handleCommand` → `b.manager.statusFn()` which is the same `m.statusFn` closure that read-locks `m.lastStatus`) will trigger a Go runtime fatal on a hash-table bucket split: `fatal error: concurrent map writes`. The statusLoop runs on a single goroutine, but `onPrivmsg` (line 424) for `!status` runs on a goroutine spawned by go-ircevent inside the bot's `conn.Loop()` (line 380), so two writer paths exist.

Additionally, `m.lastStatus` is declared without a corresponding struct mutex. The `m.mu` is the manager-wide lock, but it's not the right granularity (also protects `m.bots` which the reconnect loop iterates).
**Impact:** Go runtime fatal on a busy IRC channel that receives a `!status` command at the moment the 30s auto-status tick fires. Process exit. The whole IRC bot path is offline until the API restarts.
**Fix:** Use `m.mu.Lock()` for the write side, not `RLock`. Or move `lastStatus` to a `sync.Map` (cleaner, avoids the multi-locksite error). Or convert to a per-channel struct guarded by a dedicated mutex.

Better: use `time.AfterFunc`-style or store `lastStatus` keyed by `channelName` (instead of `ch.ID`) and protect with `m.mu` properly. A pattern like:
```go
m.mu.Lock()
if time.Since(m.lastStatus[ch.ID]) < interval {
    m.mu.Unlock(); continue
}
m.lastStatus[ch.ID] = time.Now()
m.mu.Unlock()
status, err := m.statusFn()  // outside the lock
```
**Effort:** S (5 lines)

### [high] REL-07 — `Handler.h.mu` is uneven; `h.alertManager`, `h.notifier`, `h.version` are set under the lock but read without it
**File:** `internal/api/handlers/handlers.go:24-101, 73-99`
**Category:** race
**Failure mode:** Audit finding "L-5" (CTO-LOOP-2026-06-10.md) called out partial coverage: `h.mu` only protects 4 of 8 fields. On close re-read, the actually-racy fields are zero in practice (SetAlertManager, SetNotifier, SetVersion are called once in `main()` after `NewHandler` and before `setupRoutes`, and the HTTP server hasn't started accepting connections yet). But:
- `GetIRCManager` (line 70) reads `h.ircManager` under `h.mu.RLock()`. If a future `RestartBot` handler wants to call `SetIRCManager` (e.g. on config save to wire a new manager), the writer-vs-reader race is real.
- `GetHealth` (line 112) reads `h.snmpClient`, `h.db` under `h.mu.RLock()`. Same story for `h.db` if any future code path mutates it.
- The bigger issue is *consistency*: a reader of `h.alertManager` (e.g. `handlers_data.go:71`) does `h.alertManager != nil && originalLen > 1200` without a lock. If a follow-up call site ever calls `SetAlertManager` while traffic is live (e.g. a config-driven runtime re-wire), the alert-manager pointer read is torn on architectures with weak memory ordering.
**Impact:** Today: theoretical. The reason it's high and not medium: the codebase is moving toward runtime reconfig (AUDIT-040 follower-mode already implies the manager might be swapped), and a torn read in the alert path means alerts fire on a half-initialized manager. Fix now while the call sites are small.
**Fix:** Either (a) make `Set*` use a `sync/atomic.Value` for each field (writer publishes, reader loads), or (b) read all fields under `h.mu.RLock()` everywhere they're dereferenced. Simpler: change `Handler` to hold the per-field `atomic.Pointer[T]` and use `.Load()` in reads.
**Effort:** S (mechanical: each field is one read site, ~6 total)

### [high] REL-08 — IRC `Manager.reconnectLoop` launches a `b.Start()` goroutine under `m.mu.RLock()`; `b.Start()` does blocking I/O (`conn.Connect`)
**File:** `internal/irc/bot.go:175-200`
**Category:** goroutine-leak / lock-hold
**Failure mode:** `reconnectLoop` holds `m.mu.RLock()` across the entire `for _, bot := range m.bots` loop, including the inner `go func(b *Bot) { b.Start() }(bot)`. `b.Start()` (line 284) calls `conn.Connect(addr)` (line 371) which is a blocking TCP+TLS dial. **The launched goroutine runs in parallel; the read lock is released as soon as the loop body returns.** That's actually fine in this case — Go doesn't hold the mutex across a goroutine launch. But:

- The actual issue: `reconnectLoop` reads `m.bots` under `m.mu.RLock()`. If a new `b.Start()` is in flight when the next tick fires (30s later) AND a `RestartBot` (line 975) is concurrently swapping the bot in `m.bots` under `m.mu.Lock()`, the new tick reads the OLD map under RLock. RestartBot does `m.mu.Lock()` then `m.bots[serverID] = newBot` then `m.mu.Unlock()` (lines 992-994) — so the writer takes the full lock. The reader holds RLock. **A `sync.RWMutex` is fair per the docs** but Go's runtime isn't strictly fair; under heavy read traffic the writer can starve. With only one writer (RestartBot from HTTP) and one reader (reconnectLoop from the ticker) this is essentially impossible in practice, but it IS a write-starvation shape that's worth knowing.

- The bigger issue: **`go func(b *Bot) { defer m.wg.Done(); b.Start() }(bot)`** captures `bot` by closure, but `bot` is a `*Bot` whose `Server` field is a pointer. If `RestartBot` (line 975) closes the bot via `bot.Stop()` and creates a new one, the still-running goroutine references the **OLD** bot. That's actually correct behavior, but the goroutine could end up with two `b.Start()` calls racing for the same `*Bot`: one launched by reconnectLoop, one launched by the start inside `RestartBot`. Both check `b.Conn != nil` under `b.mu.Lock()` (line 286) and bail if a connection exists — so the lock saves it — but it's fragile and the comment at line 285 doesn't explain the interaction.
**Impact:** A `!reconnect` IRC command + the 30s tick can race and either double-connect (with the OS rejecting the second dial on the same nick) or, worse, double-update the DB row via `b.db.Model(b.Server).Updates(...)` from two `onConnected` callbacks. Currently no observed crash because the inner `b.mu` is consistent.
**Fix:** Document the lock order (manager.mu → bot.mu, always) and add a "single-flight Start" guard at the top of `b.Start()` — replace the current `b.Conn != nil` check with `CompareAndSwap` on a `started atomic.Bool`. Consider moving the `b.Start()` invocation out from under the manager lock entirely (snapshot the bot list, then iterate, just like the probe's `syncLoop` does).
**Effort:** S

### [high] REL-09 — `Poller.runUnderLeaderLock` defers release but the cleanup cycle can take hours; on crash the lock auto-releases only on `SetConnMaxLifetime` (5 min) — but a *long* cleanup can exceed 5 min and free the lock while still working
**File:** `cmd/poller/main.go:91-116`, `internal/database/database.go:320-322`
**Category:** other (lock lifecycle)
**Failure mode:** The poller holds the `pollerWorkLockKey` (database.go:304) for the duration of `CleanupOldData` + `CleanupConfigRevisions` + `EnsurePartitions` + `ConfigureAutovacuum` + `PruneExpiredCooldowns`. The cleanup cycle runs every 24h. On a large DB the cycle can take 5+ minutes. The lock is **session-scoped** (held on a pooled connection); `SetConnMaxLifetime(5*time.Minute)` (database.go:148) means the connection that holds the lock will be killed and replaced at the 5-min mark, which silently drops the lock — while `CleanupOldData` is **still running** on a different connection. The next poller process's `runUnderLeaderLock` would then enter the cleanup section simultaneously.

This is a real shape but the impact is small in practice (two pollers running cleanup in parallel just means `batchedDeleteOlderThan`'s `id IN (SELECT id … LIMIT N)` subselects contend briefly; both transactions serialize on the per-batch `SET LOCAL lock_timeout = '5s'` and `time.Sleep(100ms)` between batches — but the worst case is a thundering herd on `pg_locks` for the time the second poller's connection lives).

The bigger issue: the lock auto-release comment (database.go:319-321) implies the fallback is "5 minutes" — but the comment was written before AUDIT-147 added `ConfigureAutovacuum` to the cleanup cycle, which can take 30+ seconds on its own. Total cycle is now: `dropPartitionsOlderThan` (N×DROP, fast) + `batchedDeleteOlderThan` (N tables × loop × 100ms + per-batch tx time) + `CleanupConfigRevisions` + `EnsurePartitions` (already idempotent, fast on no-op) + `ConfigureAutovacuum` (N ALTER) + `PruneExpiredCooldowns` (in-memory). On a 10-device fleet with 30-day retention: ~30s. On a 200-device fleet with 90-day retention: 5+ min.
**Impact:** A 2-poller deployment (which is the AUDIT-007 explicitly-targeted case) can race the cleanup if the cycle is slow. Not a blocker because the cleanup is idempotent and batched, but the leader-lock is supposed to prevent the race.
**Fix:** Use a `pg_try_advisory_lock_timeout` (no such function in Postgres) or a `pg_try_lock` with a `lock_timeout` that's larger than the longest expected cleanup. Practically: switch to a `pg_try_advisory_xact_lock` (transaction-scoped) inside an explicit transaction whose `BEGIN` sets `lock_timeout` to a known value. Or: hold a unique lease on a `system_settings` row (a row-level exclusive lock that the pool can't drop) for the entire cycle. Or: serialize by using the `pg_try_advisory_lock` with an explicit `pg_advisory_unlock_all()` in a finally block (so a connection rotation doesn't drop the lock — only the explicit unlock does). The current `SetConnMaxLifetime(5*time.Minute)` should be raised to `1*time.Hour` for the connection that holds the lock, OR the lock should be re-acquired by every batch.
**Effort:** M (requires understanding the Postgres advisory-lock semantics; the fix is a small change but the regression test requires a real Postgres with 2 connection-pool processes simulating the race)

### [high] REL-10 — Notifier `postJSON` retries zero times on a 5xx; one transient webhook outage drops the alert
**File:** `internal/notifier/notifier.go:219-241`
**Category:** retry / circuit
**Failure mode:** `postJSON` (used by `sendSlack`, `sendDiscord`, `sendWebhook`) makes one `n.client.Do(req)` call and returns the error on non-2xx. There is **no retry, no circuit breaker, no exponential backoff**. A single Slack/Discord/webhook receiver hiccup (their 5xx is not uncommon during regional incidents) drops the alert permanently. The relay's `sendBatch` retries 3 times with jitter (relay.go:474-498) — but the notifier path doesn't follow the same pattern.

SMTP via `smtp.SendMail` (line 180, 385) is similarly single-attempt. There's no circuit breaker: a 30-second `i/o timeout` to a misconfigured SMTP relay blocks every alert email that fires in the same window, sequentially.
**Impact:** A 5-minute Slack outage during a multi-device CPU spike = no alert visible to the operator. The DB row is written, so it's visible in the admin UI, but Slack/Discord/PagerDuty are missed.
**Fix:** Wrap `postJSON` in a 3-retry loop with jitter (the relay's pattern at relay.go:474-498 is a clean template). For SMTP, use a bounded `context.WithTimeout` so a stuck connection doesn't block the notifier queue (which is currently synchronous in the alert path — `CheckSystemStatus` calls `SendAlert` while holding the alert-cooldown lock isn't held, but it IS on the hot poll path).
**Effort:** S (port relay.go's retry block). Add a per-destination circuit breaker (`sony/gobreaker` or hand-rolled `sync.Map` of breakers) for M.

### [medium] REL-11 — IRC `Manager.Stop` does not bound the `wg.Wait()`; a wedged bot blocks API shutdown for the full 10s drain (then SIGKILL)
**File:** `internal/irc/bot.go:104-112`, `cmd/api/main.go:455-462`
**Category:** shutdown
**Failure mode:** `Manager.Stop()` (bot.go:104) closes `m.quit` then calls `m.wg.Wait()` with no timeout. If a bot's `conn.Loop()` is wedged on a TCP read that never returns (e.g. a NAT'd IRC server in a half-closed state), the `Quit()` call (line 392) may send the QUIT message but the underlying socket won't close until the read returns. The 10s `server.Shutdown` grace in `cmd/api/main.go:455-462` is the only ceiling — after that, `main()` returns and the process exits. The `wg.Wait()` is interrupted by the process exit, so it's "fine" in the strict sense, but the **defer chain in `main()`** that calls `ircManager.Stop()` runs AFTER `server.Shutdown` returns (line 462, the `defer` was registered at line 407, which runs on main's return, after `server.Shutdown` finishes). So `ircManager.Stop()` actually has the full 10s of `server.Shutdown` drain PLUS the time until `main` returns. In practice, the wedged bot blocks for 10s on the IRC path then SIGKILLs via the entrypoint's `kill $API_PID`.
**Impact:** Slow restarts. A wedged bot adds 10s to every clean `docker stop`. Not data-loss.
**Fix:** Bounded `wg.Wait`:
```go
done := make(chan struct{})
go func() { m.wg.Wait(); close(done) }()
select {
case <-done:
case <-time.After(8 * time.Second):
    log.Printf("IRC: manager.Stop timeout (8s); some bots may not have closed cleanly")
}
```
Plus `b.Conn.Quit()` followed by `b.Conn.Connection.Close()` (force-close the underlying socket) so a stuck read returns.
**Effort:** S

### [medium] REL-12 — Audit log has no retention sweep; `audit_logs` grows unbounded
**File:** `internal/database/cleanup.go:188-242 (entries)`, `internal/config/config.go:109-141 (RetentionConfig)`
**Category:** other
**Failure mode:** `CleanupOldData` iterates a fixed list of 12 tables (cleanup.go:202-228). The `audit_logs` table is **not in the list**. The `RetentionConfig` struct (config.go:109) has 15 fields covering status/flow/trap/ping/alert/syslog/etc but **no `AuditLogDays` field**. Every admin mutation logs a row (audit.go:38-80) — for a busy admin doing bulk-snooze on hundreds of alerts that's hundreds of rows per click. After a year of operation the table is the largest in the DB by row count. The `GetAuditLogs` query (`events.go:81-99`) has no time filter at the DB layer (it accepts a `since` param, but it's optional). The admin UI's "Audit Log" page (`admin.GET("/api/audit"`) will paginate but the underlying SELECT is unbounded.
**Impact:** Slow `GetAuditLogs` over time, slow admin UI, growing backup size, growing Postgres bloat. Audit-log is the canonical "low-signal, high-volume" table — exactly the kind that needs an explicit retention sweep.
**Fix:** Add `AuditLogDays int` to `RetentionConfig` (default 365), add an entry to the `entries` slice:
```go
{&models.AuditLog{}, "audit_logs", ret.Days(ret.AuditLogDays)},
```
Add a test in `cleanup_audit029_test.go` (or a new file) that verifies the audit row count drops after the cutoff. The retention should be longer than the other tables (365 days default) because audit logs are the compliance trail.
**Effort:** S

### [medium] REL-13 — `Poller.pollAllDevices` is a single un-cancellable function; SIGTERM mid-poll completes the full device loop (could be minutes) before the start loop notices
**File:** `cmd/poller/main.go:48-122, 145-263`
**Category:** shutdown
**Failure mode:** `Start()`'s main loop (line 77-121) checks `<-p.stopChan` only between `ticker.C` and `rollupTicker.C` and `cleanupTicker.C` events. **Inside the case body** it calls `p.runUnderLeaderLock(…)` which is synchronous and calls `p.pollAllDevices()`. `pollAllDevices` (line 145) launches 5 concurrent per-device goroutines and `wg.Wait()`s for all of them. There's no cancellation point inside `pollAllDevices`. If a pollDevice call hangs on a stuck `snmpClient` connection (5-second Timeout set at line 277, but `client.GetInterfaceStats` is one call — the actual poll function does GetSystemStatus, GetInterfaceStats, GetInterfaceAddresses, GetAllVPNTunnels, GetHardwareSensors, GetProcessorStats sequentially; a single stuck vendor-specific walk can take 30+s, multiplied by 6 walk-types is 3 minutes per device; with 5 concurrent = bounded 15 minutes worst case), the poller's `Stop()` returns but the main loop is still inside `wg.Wait()`.

There's also no panic recovery (REL-01), so a panic in a vendor walk code path (e.g. `snmp/vendor_fortigate.go` for a malformed OID) takes the whole poller down mid-loop.
**Impact:** Shutdown can take 5+ minutes for a large fleet, which means Docker's `docker stop --time=30` SIGKILLs the process mid-poll, possibly leaving a half-written row in the DB. The OS-level reaper is benign (Postgres rolls back the uncommitted tx if the connection is reset), but a partial-batch write (e.g. `SaveSystemStatus` succeeded, `SaveInterfaceStats` panic'd, `SaveVPNStatuses` not run) leaves the device in a half-updated state until the next poll.
**Fix:** Make `pollAllDevices` cancellable: take a `ctx context.Context`, pass it to `pollDevice`, check `ctx.Err()` between sub-sections, return early on cancellation. `Stop()` cancels the ctx. The `wg.Wait()` should also be bounded:
```go
done := make(chan struct{})
go func() { wg.Wait(); close(done) }()
select {
case <-done:
case <-time.After(8 * time.Second):
    log.Printf("poller: Stop timeout; %d device(s) still in flight", remaining)
    return nil
}
```
The current 8s budget aligns with the entrypoint's `kill $API_PID $POLLER_PID $TRAP_PID 2>/dev/null || true` not having an explicit `kill -9` timeout (the entrypoint is correct — Docker's `--time=30` is the outer bound).
**Effort:** M (touch pollDevice to take a ctx; refactor the goroutine-launching section; add a test that exercises shutdown-while-mid-poll)

### [medium] REL-14 — `Manager.RunCollectorHandler` is a busy-loop that wakes every 100ms; with 4 handlers (default collector setup) that's 40 wakeups/sec for the lifetime of the process
**File:** `internal/relay/relay.go:382-401`
**Category:** goroutine-leak (CPU shape)
**Failure mode:** The relay's `StartCollector(handlers ...)` (line 382) launches one goroutine per handler. `runCollectorHandler` (line 392) is a `for { select { default: time.Sleep(100ms) } }` busy-loop that does **nothing** — it's a placeholder that the probe is expected to call with custom handlers, but the only shipped caller is the probe itself (which doesn't use it; the probe's actual collection runs on its own goroutines, see `cmd/probe/main.go:299, 300, 467`). So the relay's `StartCollector` is dead code that consumes 4×10 wakeups/sec per collector goroutine.
**Impact:** Trivial CPU (40 wakeups/sec ≈ 0% CPU on any modern hardware), but it IS a goroutine-leak shape that confuses `pprof`. A `-race` run on the probe will see 4 goroutines per `StartCollector` call parked in the relay's busy-loop with no clear owner.
**Fix:** Either delete `StartCollector` and `runCollectorHandler` entirely (the probe's actual collection is in `cmd/probe/main.go`, not via the relay's interface), or make `runCollectorHandler` actually invoke the handler's `HandleTrap`/`HandlePingResult`/etc. by reading from the relay's queues.
**Effort:** S for delete; M for proper implementation.

### [medium] REL-15 — `Poller.sendCriticalAlertEmail` runs `report.GatherRecentHistory` under the poller's poll context with no timeout
**File:** `cmd/poller/main.go:1392-1421`, `internal/report/data.go:210+`
**Category:** timeout
**Failure mode:** When a device is marked offline, `sendCriticalAlertEmail` is called synchronously. It builds a full HTML email with charts (the audit's intent is "operator sees a context-rich email"). `report.GatherRecentHistory` queries the last 2 hours of `system_status` for the device. If the device has been offline for a long time, that query returns 0 rows and is fast. If the device has dense data (e.g. 5-min polls × 24 entries/hr × 2hr = 48 rows — tiny). But the email build (`report.BuildCriticalAlertEmail`) embeds chart PNGs (built in-memory by `internal/report/svg_charts.go`); for a device with 50 interfaces × 24 hours of history the SVG rendering is non-trivial — typically 100-500ms.

The path is **synchronous on the poll cycle**: `pollDevice` calls `updateDeviceStatus` which calls `sendCriticalAlertEmail` (line 1384). The poll semaphore (`sem := make(chan struct{}, 5)`) blocks other devices while this is happening. A slow chart build for device A blocks the poll of device B by ~500ms.

Worse, there's no context with timeout on the `p.db` calls. If Postgres is slow (high load, autovacuum running on a big table), the email query can hang indefinitely — and the `smtp.SendMail` in `SendHTMLEmail` has NO client timeout (uses `net.Dial` to SMTP host, then smtp protocol). A misconfigured SMTP host that blackholes the connection stalls the poll for 60+ seconds (default TCP keepalive).
**Impact:** A single stuck email can stall 5 concurrent device polls. The entrypoint's outer `docker stop --time=30` will SIGKILL the poller mid-SMTP-handshake, which is benign but means the next restart re-starts at the previous tick (no rollback needed for SMTP — no partial commit).
**Fix:** Wrap `sendCriticalAlertEmail` in a goroutine that returns immediately:
```go
go p.sendCriticalAlertEmail(dev, "DEVICE_OFFLINE", msg)
```
Same for the report-scheduler's `generateAndSendReport`. The cooldown map (`am.lastAlert`) already prevents duplicate fires. The trade-off: an email that fires when the poller is shutting down might be lost — but the operator can re-fire from the admin UI, and the SendAlert path is at-least-once via the DB row.

For SMTP timeout, use a `context.WithTimeout(ctx, 30*time.Second)` and pass it to `smtp.SendMail` (the standard library doesn't take a context, so use a `net.Dialer{Dial: (&net.Dialer{Timeout: 30 * time.Second}).Dial, KeepAlive: 30 * time.Second}` via `smtp.NewClient`-style customization, or wrap the SMTP send in a goroutine that returns on context cancel).
**Effort:** S for the goroutine launch; M for the SMTP timeout (need to switch to a context-aware SMTP client).

### [medium] REL-16 — IRC `bot.Conn.Privmsg` is called without checking backpressure; a stuck IRC server makes every auto-status send block forever
**File:** `internal/irc/bot.go:264, 444, 505, 933`, `internal/irc/bot.go:929 (`conn.Connected() == false` race)
**Category:** timeout
**Failure mode:** `conn.Privmsg(ch.ChannelName, line)` is a synchronous call into the go-ircevent library. The library queues outgoing messages in a `chan` of size N and writes them to the socket. If the socket is stuck (TCP zero-window, half-closed by the server), the channel fills and `Privmsg` blocks. In `sendAutoStatus` (line 264) the loop does multiple `Privmsg` per channel — one bad send blocks all subsequent auto-statuses for ALL channels of ALL bots for 5 minutes (the default go-ircevent keepalive). The `statusLoop` ticker fires every 30s; if one send takes 5 minutes the ticker just keeps queueing `sendAutoStatus` calls on the manager's statusLoop goroutine (single goroutine, so they serialize), and the in-memory Privmsg queue in go-ircevent grows unbounded.

Also, `b.SendMessage` (line 924-935) checks `conn.Connected() == false` then sends — but `Connected()` is itself a call into the library, and there's a TOCTOU race: the connection can drop between the `Connected()` check and the `Privmsg` call. The library handles this internally by buffering; the call returns immediately. The real failure is when the buffer is full.
**Impact:** Slow IRC server = every auto-status stalled behind it; manager status goroutine backed up; eventually the bufferedPrivmsg channel fills and the go-ircevent library logs a warning and drops the message. No crash, but the operator's IRC channel goes silent.
**Fix:** Send auto-status via a goroutine, not synchronously, so the ticker is never blocked. Add a write timeout: `conn.SetWriteDeadline(time.Now().Add(5 * time.Second))` before `Privmsg`. Limit the `formatStatusResponse` output to a sane number of lines (currently 6 lines × N devices — a 100-device fleet = 600 lines; 100-character-per-line IRC messages = 60K characters = 600 100-byte PRIVMSGs to a single channel, which is also rate-limit risk per the H-4 audit finding).
**Effort:** S

### [medium] REL-17 — `Poller.prevIfaceStats` map has unbounded growth keyed by `deviceID_ifName`
**File:** `cmd/poller/main.go:380-385`, `internal/relay/relay.go` (similar in collector)
**Category:** other
**Failure mode:** `prevIfaceStats map[string]*models.InterfaceStats` is keyed by `"%d_%s"` of `deviceID_ifName`. The poller NEVER evicts entries. When a device is deleted (admin DELETE /api/devices/:id), the corresponding entries in `prevIfaceStats` persist. After a year of operation with 100 devices added then removed, the map has 100×10 = 1000 stale entries holding `*models.InterfaceStats` pointers. The `*models.InterfaceStats` is captured by value (line 383 `iface := interfaces[i]`) and stored by pointer — so the GC keeps the underlying data alive.

The map is guarded by `p.ifaceStatsMu sync.RWMutex` (line 32). Reads happen in the error-check path (line 340-344), writes after each successful poll (line 379-385).
**Impact:** Slow leak — 10s of MB over a year per stale device. Not a blocker; doesn't OOM. The M-7 audit finding called this out; the fix is to add an eviction on `admin.DELETE /api/devices/:id` and/or a periodic sweep.
**Fix:** Add a `evictIfaceStats(deviceID uint)` method called from `cmd/api/main.go`'s `handler.DeleteDevice` (or from the poller's "device list" pass at the top of each `pollAllDevices`, where stale keys can be detected and removed). Bounded LRU is overkill for a 10×N entry map; a one-line `delete(p.prevIfaceStats, fmt.Sprintf("%d_%s", id, name))` for each deleted device suffices.
**Effort:** S

### [medium] REL-18 — `manager.wg` is `Add(1)`'d at 3 sites outside the manager mutex; concurrent `RestartBot` and reconnectLoop can race
**File:** `internal/irc/bot.go:127, 190, 997`
**Category:** race (theoretical)
**Failure mode:** `m.wg.Add(1)` is called inside `loadAndStartBots` (line 127, under `m.mu.Lock()`), `reconnectLoop` (line 190, under `m.mu.RLock()`), and `RestartBot` (line 997, under NO lock). Go's `sync.WaitGroup` says concurrent `Add` is safe as long as it happens-before the corresponding `Wait`, but the call pattern here can have `Add` racing with `Wait` on `Stop`. In particular:
- `m.quit` is closed in `Stop()` (line 105), then `m.wg.Wait()` (line 111). 
- If a reconnectLoop tick is in flight and calls `m.wg.Add(1)` AFTER `Stop`'s `close(m.quit)`, the new goroutine's `defer m.wg.Done()` never fires (it has the same `m.quit` and will exit at the next select check), so `m.wg.Wait()` blocks until the orphan goroutine's `Done` lands.
- If the goroutine is launched between `close(m.quit)` and the per-bot check (which inspects `m.quit`), it can run for up to 30s (the ticker period) before noticing.

This is benign — the process is shutting down — but it DOES mean `ircManager.Stop()` in `cmd/api/main.go`'s defer chain can block for 30s.
**Impact:** Slow shutdown. See REL-11.
**Fix:** Either move all `m.wg.Add` calls under `m.mu.Lock()`, or replace the WaitGroup with an atomic counter that `Stop` records before calling the real wait:
```go
type Manager struct {
    wg sync.WaitGroup
    stopped atomic.Bool
}
func (m *Manager) AddWork() {
    if m.stopped.Load() { return }
    m.wg.Add(1)
}
```
**Effort:** S

### [low] REL-19 — `Poller.snapshotConfig` race: `am.config.Alerts` is read by `am.alertManager` without locking from the report-scheduler path
**File:** `cmd/poller/main.go:1396-1420`, `internal/alerts/alerts.go:65`
**Category:** race (theoretical)
**Failure mode:** `p.alertManager.CheckSystemStatus` (poller.go:316) takes `am.mu.Lock()` and reads `am.config.Alerts` for `notifier.SnapshotConfig(&am.config.Alerts)`. The same `am.config.Alerts` is also read by `ReportScheduler.generateAndSendReport` (report.go:135-140) under `rs.mu.RLock()` (a different mutex). If a future "live reconfig" code path mutates `cfg.Alerts` (e.g. a `SetAlertsConfig` admin handler), there's a torn-read window.
**Impact:** Today: zero — `cfg.Alerts` is set once at startup and never mutated. Worth flagging for the same reason as REL-07.
**Fix:** Same as REL-07: pass `cfg.Alerts` through an atomic pointer or copy under lock.
**Effort:** S

### [low] REL-20 — `convertEmptyTableToPartitioned` runs inside `d.db.Transaction` but the `tx` is a GORM `*gorm.DB` that pins a single connection — yet there's no `defer cancel()` on the transaction
**File:** `internal/database/migrate.go:404-447`
**Category:** tx / context
**Failure mode:** The transaction is implicit (GORM's `d.db.Transaction(func(tx *gorm.DB) error {...})`). If the function returns an error, GORM rolls back; on nil return, it commits. There's no explicit `tx.Rollback()` call needed (GORM handles it). The connection is returned to the pool on commit/rollback. So this is fine in the strict sense.

But: the underlying `*sql.Tx` doesn't have a context. If the API server receives a SIGTERM mid-`convertEmptyTableToPartitioned` (which only happens during the v2 migration, which is a startup-time operation), the in-flight SQL doesn't get cancelled. The transaction runs to completion (or to the 30s statement_timeout) before the process can exit. For an empty table this is milliseconds; for a table with a few thousand partitions of historical data (a `LIKE` of a wide schema can be slow) it can be longer.
**Impact:** Slow startup shutdown on a busy DB. Not a real risk because the v2 migration is bounded to empty tables.
**Fix:** Use `d.db.Transaction` with a `context.Context` that's tied to the startup process: `ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute); defer cancel(); d.db.WithContext(ctx).Transaction(...)`. The 5-min cap is generous but bounds the worst case.
**Effort:** S

### [low] REL-21 — `sendAutoStatus` uses `formatStatusResponse` which is a pure function, but it reads `m.statusFn()` and calls `m.statusFn()` is a per-device DB-querying function (see main.go:336-373) — this serializes under the manager's RLock
**File:** `internal/irc/bot.go:254, 260`
**Category:** context / DB-load
**Failure mode:** `m.statusFn()` is a closure defined in `cmd/api/main.go:336-373` that does `db.Gorm().Find(&devices)` and then per-device queries. Holding `m.mu.RLock()` (line 221) for the duration of this query means:
- The reconnect loop (also `m.mu.RLock()` at line 184) is blocked while statusFn runs.
- `Stop()` (line 105) needs `m.mu.RLock()` to call `bot.Stop()` on each bot; if statusFn is slow, `Stop` blocks.
- `RestartBot` (line 975) needs `m.mu.Lock()`; same blocking.

The statusFn does 4-6 DB queries per device (lines 336-365 in main.go:336-373 — Find(&devices), then per-device `Where("device_id = ?")` on SystemStatus + 2 VPNStatus queries + Alert count). For a 50-device fleet that's 1 + 50×4 = 201 queries on a fresh connection. With the 30s statement_timeout, that's 201 × ~50ms = 10s of DB time. The IRC statusLoop fires every 30s — so every 30s the IRC manager holds the RLock for 10s. The reconnect loop and Stop are blocked for 33% of the time.
**Impact:** The reconnectLoop's 30s tick can miss if statusFn runs long. An IRC server that's slow to connect gets reconnected on the next tick, not the current one. Stop blocks for up to 10s.
**Fix:** Snapshot the status data outside the lock: call `statusFn()` first, then take `m.mu.RLock()` to iterate bots and send the cached result. Or call `statusFn()` per-bot outside the lock:
```go
status, err := m.statusFn()
m.mu.RLock()
defer m.mu.RUnlock()
for _, bot := range m.bots { ... use status ... }
```
**Effort:** S

### [low] REL-22 — `irc.goircev` is imported and uses `irc.Connection` (capital C) but `conn.Loop()` is called with no panic recovery
**File:** `internal/irc/bot.go:380`
**Category:** panic (extension of REL-01)
**Failure mode:** `go conn.Loop()` (line 380) is the IRC read loop. The go-ircevent library has been stable but any panic in its callbacks (registered at lines 324-366 in `b.Start`) propagates up to the goroutine, which has no recover. A panicking `onPrivmsg` (e.g. via a nil-deref in `b.manager.commands[cmdStr]` lookup if the map is concurrently modified) takes the whole API down.
**Fix:** Wrap `b.Start()` in a recover in the goroutine that launches it (line 191, 998). Same for line 380.
**Effort:** S

## What looks solid

- **AUDIT-094 entrypoint fix is correct** — fail-fast on API only, non-essential daemons can idle. The `set +e` around the `wait "$API_PID"` and the `|| true` on kill are the right safety belts.
- **v0.10.391 statement-timeout fix is correct** on the two paths it covers. Just needs to be extended to the five other DDL paths (REL-04).
- **API shutdown sequence** (`cmd/api/main.go:444-462`): signal + listener-error paths unified, `bgCancel` before drain, 10s grace, `defer` chain honored. Pre-AUDIT-086's `log.Fatal` issue is gone.
- **Migrations are idempotent and gated by `tryAcquireStartupLock`** (`database.go:227`): exactly one process runs the chatty post-migration steps; the others skip with one log line.
- **Migration lock and API singleton lock use pinned connections with `SET statement_timeout = 0`** (`migrations.go:135`, `database.go:381-408`): the right pattern for "long-running exclusive work on the pool".
- **`BatchInserter.Stop` ordering** (`batcher.go:129-135`): the `stopped` atomic is set BEFORE `close(stopCh)`, and `doneCh` is closed only after the final flush. No data loss on shutdown.
- **`WithContext` on every browser-facing DB call** (`handlers.go:57-62` + `WithContext_audit032_test.go`): a client disconnect cancels the in-flight query and frees the pool slot. Daemons (poller/trap) deliberately use the durable `h.db` to survive WAN flapping.
- **Probe authentication crypto** is correct: `subtle.ConstantTimeCompare` against the stored `sha256:`-hashed key.
- **Audit logging middleware** (`audit.go:38-80`): records on `c.Next()` completion, captures the final HTTP status, is non-blocking (logs but never fails the request).
- **CORS + CSP nonce + HSTS** middleware chain is tight; no wildcard origin allowed with credentials.
- **`gin.Default()` includes `gin.Recovery()`**: HTTP path is panic-safe.
- **DB pool sizing** is per-process and tunable (15 API / 10 poller / 5 trap, with `DB_MAX_OPEN_CONNS` override).
- **Auto-detect VPN connection** code is dense but appears correct; the indirect-match (Phase 2) and WAN-IP-inference (Phase 3) are well-commented and don't race on the maps.
- **ConnMaxLifetime = 5 min** on the pool prevents stale-connection accumulation; `ConnMaxIdleTime = 1 min` keeps the idle pool warm.
- **Time-sensitive test names** (`AUDIT-016`, `AUDIT-017`, `AUDIT-032`, etc.) are greppable and well-documented; the comment discipline in this repo is exemplary.
- **CGO-free Windows build works**; the repo builds on the dev box without CGO, which avoids the `-race` skip that the prior audit noted as a blocker for confirming REL-1.

## Summary

- **3 new blockers** (REL-01 missing panic recovery everywhere, REL-02 dedup gap on 14/18 ingest endpoints, REL-03 in-memory queue + no WAL on probe and on server batcher).
- **6 new highs** (REL-04 statement-timeout gap on 5 DDL/maintenance paths, REL-05 poller stop doesn't wait, REL-06 IRC lastStatus race, REL-07 Handler.h.mu partial coverage, REL-08 IRC reconnect under RLock with blocking I/O, REL-09 cleanup-cycle exceeds ConnMaxLifetime, REL-10 notifier has no retry/circuit).
- **7 new mediums** (REL-11..REL-17).
- **4 new lows** (REL-18..REL-21).
- **0 false positives from the prior audit** — every finding I re-validated is still open. The 2 fixes the prior audit requested (entrypoint fail-fast + statement-timeout on lock/dedupe) are correctly implemented.

**Total new findings: 21.**

The biggest wins, in order of impact-vs-effort, are REL-01 (panic recovery helper, S effort), REL-02 (dedup boilerplate to 14 handlers, S), REL-04 (timeout lift to 5 paths, S), and REL-06 (1-line race fix, S). Together those 4 fixes are roughly half a day of work and close 4 blockers/highs; the rest can land in a follow-up sprint.
