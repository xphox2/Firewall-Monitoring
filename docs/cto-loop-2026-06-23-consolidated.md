# CTO-Loop Audit — 2026-06-23 (Consolidated, Dual-Repo)

**Scope:** Both repositories of the firewall-monitoring product.
- **Server** — `Firewall-Mon` (Go module `firewall-mon`, ~v0.10.476): API, poller, trap-receiver, embedded web UI, central store + alerting brain.
- **Collector** — `Firewall-Collector` (Go module `firewall-collector`, ~v1.2.131): stateless remote edge probe.

Consolidated multi-agent-consensus report. A collector-scoped copy lives at `Firewall-Collector/docs/cto-loop-2026-06-23-consolidated.md`. The master feature inventory + roadmap lives at `Firewall-Mon/docs/FEATURE-ROADMAP.md`.

---

## Executive Summary

**49 confirmed findings** across both repos. The data plane and ingestion breadth are strong; concentrated risk clusters in three areas:

1. **Trust at the ingestion boundary** — server syslog ingestion is the only `Receive*` path skipping the per-probe device allow-list (cross-site alert/attribution injection); the collector's TFTP server never wires its built-in source-IP allowlist/rate-limit (forged config backups from any host on the management LAN).
2. **Process stability / availability** — a concurrent-map race that fatally crashes `cmd/api`; a TLS-syslog listener error swallowed by variable shadowing that nil-derefs; an alert-notification storm on every poller restart; a trap rate-limiter that permanently locks out new IPs after a spoof flood.
3. **Key-continuity / durability** — the `./config` mount isn't parametrized like `DATA_DIR`, so deploy-from-new-dir silently rotates the AES key and bricks every `{enc}` secret; the collector drops all primary SNMP telemetry (no spillover queue, no metric) during a server outage.

### Counts by final severity

| Severity | Count |
|---|---|
| High | 9 |
| Medium | 13 |
| Low | 16 |
| Info | 11 |
| **Total** | **49** |

> Counts use post-consensus `finalSeverity`. Several items initially rated higher were downgraded after confirming low real-world exploitability (admin-only, hashed value, Go-default-already-safe, dead code).

---

## Confirmed Findings by Severity

### HIGH

#### H1. Syslog ingestion trusts collector-supplied `device_id` with no probe-ownership check
- **server** · `internal/api/handlers/handlers_data.go:53-122` (esp. 95-105)
- The ONLY ingestion handler that doesn't enforce `allowedDevices := h.probeDeviceIDs(probe.ID)` (siblings: `flows.go:216`, traps `:150`, pings `:252`). Fills `DeviceID` from a GLOBAL `ResolveDevicesByIPs` lookup; a body-supplied `DeviceID` passes straight through.
- **Impact:** Any approved/compromised probe POSTs syslog attributed to ANY device → alert injection (`Severity<=2` → real SYSLOG_CRITICAL against another tenant's device), forged config-change attribution (`attributeConfigChange` queries `WHERE device_id=?`), cross-site dashboard pollution.
- **Fix:** Compute `allowedDevices` once; drop/zero any finalized `DeviceID` not in the set; scope `ResolveDevicesByIPs` to `probe.ID`. Add a regression test.

#### H2. TFTP config-upload accepts arbitrary content from ANY source IP — AUDIT-050 controls never wired
- **collector** · `cmd/collector/main.go:879-918`; unused at `internal/tftp/tftp.go:107,128`
- `startTFTPServer` binds `0.0.0.0:69` and only calls `SetWriteHandler`; `SetAllowedSourceIPs`/`SetMinWRQInterval` are never called, so `isSourceAllowed` returns true (nil allowlist) and rate-limit is a no-op. Attacker bytes become an authoritative `relay.ConfigRevision` forwarded via `SendConfigRevision`.
- **Impact:** Any host on the management LAN injects a forged config-revision for any `device_id` → poisons config-change detection / masks real changes.
- **Fix:** After `NewServer`, call `SetAllowedSourceIPs(deviceIPs)` from `c.devices[].IPAddress` + `SetMinWRQInterval(30-60s)`; refresh on device-list refresh (`main.go:312`).

#### H3. JWT token-version revocation check fails OPEN on a transient DB error
- **server** · `internal/auth/auth.go:190-198` · *finalSeverity: medium*
- Gated `if err == nil && claims.TokenVersion != currentVersion {...}`. On a `GetAdminTokenVersion` error (pool exhaustion / the 30s statement-timeout cascade) the comparison is skipped and the token accepted. Logout/password-change rely on the version bump. `fakeDB` never errors → untested branch.
- **Impact:** A revoked JWT honored during any DB-error window — exactly when locking out an attacker.
- **Fix:** Fail closed; if brief availability is wanted, make it an explicit bounded/logged grace TTL. Add a `fakeDB` error-injection test.

#### H4. IRC command lookup reads `Manager.commands` under the wrong mutex — fatal concurrent map race
- **server** · `internal/irc/bot.go:439-441` (read) vs `164-172` (write)
- `onPrivmsg()` reads `b.manager.commands[...]` under `b.mu` (per-Bot), but the map is replaced under `m.mu` in `loadCommands()`. Different mutexes ⇒ no mutual exclusion. `onPrivmsg` runs on the IRC read loop; `ReloadCommands` from 5 Gin sites (`handlers_irc.go:79,153,393,428,448`).
- **Impact:** Saving an IRC command while a channel delivers `!command` triggers Go's unrecoverable `fatal error: concurrent map read and map write` — aborts the whole `cmd/api`. (The 2026-06-22 design-patterns audit wrongly cited this as the *correct* locking example.)
- **Fix:** Add `Manager.lookupCommand(name)` under `m.mu.RLock()`; call from `onPrivmsg`. Add a `-race` test.

#### H5. TLS syslog listener error swallowed by variable shadowing — Start() returns success then acceptLoop nil-derefs
- **server** · `internal/syslog/syslog.go:71-88` (bug at 73 + 81)
- L73 `cert, err := tls.LoadX509KeyPair(...)` shadows the outer `err`; L81 `s.listener, err = tls.Listen(...)` writes the shadow; L86 checks the always-nil outer. staticcheck SA4006 at L81.
- **Impact:** On TLS-path listen failure (port bound/permission), Start() returns nil + logs "started", then `acceptLoop` nil-derefs `s.listener.Accept()` in an unrecovered goroutine → process crash with a "started successfully" log.
- **Fix:** `cert, certErr := ...` so L81 writes the outer `err`. Regression test against an already-bound TLS port.

#### H6. Syslog retention DELETEs bypass the AUDIT-038 batched-delete helper
- **server** · `internal/database/cleanup.go:248,260,277,284`
- Four single unbounded `DELETE`s on `syslog_messages`/`syslog_summaries` (the table that dominates DB size) instead of `batchedDeleteOlderThan` (10k batches, `lock_timeout='5s'`, inter-batch sleep).
- **Impact:** Daily cleanup issues one DELETE touching millions of rows in the straddling partition → long lock window, blocks ingestion, large WAL burst, can be killed by `statement_timeout` and re-attempted every tick (crash-loop shape).
- **Fix:** Add `batchedDeleteOlderThanWhere(model, cutoff, "severity < 6")` and route the syslog deletes through it.

#### H7. AlertManager re-fires a notification storm on every poller restart
- **server** · `internal/alerts/alerts.go:22-23,40-41,344-349,558-568`
- `lastAlert`/`activeAlerts` are empty in-memory maps; the fire path gates SOLELY on `canAlertWithCooldown` (true when key absent) and `dispatchFired` unconditionally `saveAlert`+`SendAlert` with no OPEN-alert dedup. The recovery path IS idempotent (`:494`); the fire path isn't.
- **Impact:** Any poller restart re-fires a fresh alert + email/Slack/Discord/IRC for every breaching condition; under the statement-timeout crash-loop it's a per-cycle storm.
- **Fix:** Before notify, check for an existing OPEN alert of `(device_id, alert_type, metric_name)` and suppress; or rehydrate maps from open alerts on startup. Mirror `:494`.

#### H8. ENCRYPTION_KEY-deriving JWT secret lives only on the hardcoded `./config` mount (not parametrized like DATA_DIR)
- **server** · `docker-compose.yml:26-27`, `entrypoint.sh:137-164`, `internal/database/database.go:164-168`
- AES key derives from `JWT_SECRET_KEY` (ENCRYPTION_KEY unset by default), persisted only to `/config/config.env` (hardcoded `./config:/config`, gitignored). `DATA_DIR` is relocatable; config is not → deploy-from-new-dir regenerates the key while the relocated DB holds ciphertext under the OLD key.
- **Impact:** Every `{enc}` credential becomes permanently undecryptable (SNMP/IRC/SMTP); `decryptField` logs ERROR + returns empty → fails silently at deploy, surfaces later as broken polling. The DATA_DIR/config asymmetry makes this the DEFAULT trap.
- **Fix:** Parametrize `- ${CONFIG_DIR:-./config}:/config` and document it; better, persist the key under `/data`. Add a fail-fast guard (see M8).

#### H9. Collector drops all primary SNMP telemetry on server outage (no spillover queue)
- **collector** · `internal/relay/relay.go:893-938`; callers `cmd/collector/main.go:1301,1317,1328,1336` · *finalSeverity: medium*
- 10 core metric senders go through `doDirectSend` (no queue; callers only log on failure). The device circuit breaker keys on POLL failures, not SEND failures, so polling continues and every sample is discarded; `doDirectSend` also burns ~7s backoff per metric per device.
- **Impact:** A server outage loses ALL primary health metrics for the full outage with no recovery, while lower-value event streams ARE preserved — inverts data-value priority.
- **Fix:** Route the metric `Send*` through the SpilloverQueue (or a bounded metric queue); drop `doDirectSend` retries to 1.

### MEDIUM

#### M1. `aggregateRollupsUp` loads the entire GROUP BY result into memory with no pagination
- **server** · `internal/database/flows.go:614-624` — high-cardinality 5-tuple GROUP BY with no `Limit`, unlike sibling `aggregateFlowsToRollup` (`pageSize=50000`). Backlog → millions of groups in one slice held in one long transaction. **Fix:** mirror the page loop / keyset cursor; insert+delete per page in its own txn.

#### M2. Syslog/flow aggregation OFFSET pagination is dead and silently drops un-summarized groups
- **server** · `internal/database/syslog_agg.go:79-118` (same shape `flows.go:555-589`) — each page deletes ALL matching raw rows so page-2 finds nothing; if distinct groups > `pageSize`, groups beyond page 1 are deleted without being summarized (silent count loss). **Fix:** scope the delete to the page's rows, or aggregate in one pass after removing the group cap. Test seeding >`pageSize` groups.

#### M3. `probeDeviceIDs` decrypts every device's secrets + Site-preload JOIN on every ingestion request
- **server** · `handlers_probes.go:804-814` + `sites_probes.go:390-397` — all 18 ingestion handlers call it; it does `Preload("Site")` + 4 AES-GCM decrypts/device then reads only `d.ID`. **Fix:** `GetDeviceIDsByProbe` with `Pluck("id", &ids)`; optionally memoize per-probe with a short TTL.

#### M4. `updatePingStats` does a serial read-modify-write DB round-trip per ping result
- **server** · `handlers_data.go:268-315` — ≤2N sequential commits over up to 1000 results, repeatedly SELECTing the same `(device,target)` row. **Fix:** group by `(deviceID,targetIP)`, fold in one pass, one UPSERT per target (`ON CONFLICT DO UPDATE`).

#### M5. `ReceiveSystemStatuses` inserts each row with an individual Create in a loop
- **server** · `handlers_data.go:437-452` · *finalSeverity: low* — per-row bare `Create`, up to 100 INSERTs/request. **Fix:** build `filtered`, add `SaveSystemStatuses` (one `Create(&slice)`).

#### M6. TCP syslog framing is O(n²) in messages-per-read (buffer rewind per line)
- **collector** · `internal/syslog/syslog.go:110-124` — rewrites the remaining tail to the front per extracted line. **Fix:** forward scan with an advancing offset, or `bufio.Scanner` with a 64KB token buffer.

#### M7. sFlow/event spillover `Push` does a synchronous BoltDB fsync under the queue mutex per overflow item
- **collector** · `internal/relay/queue/queue.go:188-201,207-242` (BoltDB no NoSync at `:76`) — at `MaxMem`, each evict fsyncs under `q.mu`; the single sFlow `readLoop` pushes inline, stalling flow-receive. **Fix:** decouple receive from persistence (RAM channel drained by a writer); batch overflow writes / NoSync; raise flow-queue MaxMem.

#### M8. Startup does NOT fail fast when `{enc}` ciphertext exists but no key resolves
- **server** · `internal/config/config.go:452-454`, `internal/database/crypto.go:134` — Validate only WARNs; `decryptField` returns empty; process comes up "healthy" with blank secrets. Pairs with H8. **Fix:** at startup, if any `{enc}` column can't round-trip a canary, `log.Fatalf` with guidance; or surface unhealthy on decrypt-error count.

#### M9. Trap-receiver rate-limiter map is capped but never pruned
- **server** · `internal/snmp/trap.go:55,82-107` (cap 88-90) — a spoof flood fills `rlBuckets` to 10000; stale buckets persist forever and every new device IP is rejected at L89 until restart (durable denial-of-trap). **Fix:** LRU-evict the oldest `.last` at cap, or periodic idle-bucket sweep.

#### M10. Collector never injects W3C trace context or a request ID — probe→server traces can never connect
- **cross-repo** · collector `internal/relay/relay.go:580-590` (no otel in go.mod) · *finalSeverity: low* — server propagates W3C context but the collector injects none, so the server always starts a fresh root span. **Fix:** collector RoundTripper injecting `traceparent`+`X-Request-ID`, or correct the tracing-package doc and log `X-Probe-Batch-ID` on ingestion.

#### M11. Poller and trap-receiver binaries expose no `/metrics`, `/healthz`, or `/readyz`
- **server** · `cmd/poller/`, `cmd/trap-receiver/` · *finalSeverity: low* — observability lives only in the API binary; the poller (AlertManager + polling + batching) is a black box to Prometheus/orchestrators, less observable than the remote collector. **Fix:** factor the collector's `observability.Server` into both daemons; wire `poll_cycles_total`/`alerts_fired_total`/batcher depth/trap rate.

#### M12. Collector metric-send failures have no Prometheus counter
- **collector** · `internal/observability/metrics.go:297-300` · *finalSeverity: low* — queue drops are visible but `doDirectSend` failures aren't. **Fix:** add `firewall_collector_metric_send_failed_total{kind=...}`.

#### M13. alpine:3.19 runtime base image is past end-of-life in both repos
- **cross-repo** · `Firewall-Mon/Dockerfile:29`, collector `Dockerfile:14` — EOL ~Nov 2025, no backports; server bundles `postgresql16*` + openssl. **Fix:** bump to alpine 3.21/3.22, verify `postgresql16*` resolves, add Renovate/Dependabot.

### LOW

- **L1. SSH `HostKeyCallback` returns nil + password auth leaks FortiGate creds to a first-connection MITM (alert-only by design)** — collector `internal/ssh/ssh.go:72-75,97-100` (isNew:false, AUDIT-071). Prefer key-based auth; consider local TOFU.
- **L2. SNMP getters use `vendor ...string` variadic to fake an optional param** — collector `internal/snmp/snmp.go:252,461,541,564,653,686,713,740`; mirrored in server `cmd/poller/main.go:29`. Change to plain `vendor string`.
- **L3. Build version stale hardcoded `const` (1.2.129) vs CHANGELOG 1.2.131, no ldflags** — collector `cmd/collector/main.go:55`. Bump in release flow or use `-ldflags -X main.version`.
- **L4. Connection-detail interface resolution: N+1 + per-call full-config reparse** — server `internal/database/connection_detail.go:196-210,244-252,662-694`. Batch `if_index IN (...)`, group chart windows, memoize parsed config.
- **L5. Device status UPDATE per device instead of `WHERE id IN (...)`** — server `handlers_data.go:456-461,508-513,553-558`. Shared `markDevicesOnline(ids)`.
- **L6. `doDirectSend` closes response body without draining — defeats keep-alive pool on every per-cycle send** — collector `internal/relay/relay.go:916` (callers 941-979) · *finalSeverity: medium*. `io.Copy(io.Discard, resp.Body)` before Close on all paths.
- **L7. Snapshot/detail senders return on 2xx without draining** — collector `relay.go:1578,1598,1621,1644,1667`. Drain via a shared helper.
- **L8. Ping opens a fresh raw ICMP socket per device per cycle; every socket parses all replies** — collector `internal/ping/ping.go:182,228-241,105`. One shared long-lived socket + demux by `(id,seq)`.
- **L9. SNMP trap receiver logs the configured expected community in cleartext on mismatch** — collector `internal/snmp/trap.go:96`. **(See L9b — this same line is independently confirmed at HIGH as a trap-secret disclosure: the configured community is written to logs/aggregation enabling trap forgery; the CHANGELOG "no longer logs the trap community" claim only covered the parse path; the leak is pinned by `trap_test.go:48-52`.)** Log only `Dropped: community mismatch from %s`; update the test to assert the secret is ABSENT; optionally per-IP rate-limit.
- **L10. Relay HTTPS client TLS sets no `MinVersion` — diverges from server (TLS 1.2 pinned)** — collector `internal/relay/relay.go:523-571` · *finalSeverity: info*. Not active on Go 1.25 (default already TLS 1.2). Add `MinVersion = tls.VersionTLS12`.
- **L11. `DeleteSite` hard-deletes devices but leaves `DeviceConnection` rows orphaned** — server `internal/database/sites_probes.go:139-149` · *finalSeverity: medium*. Bypasses `DeleteDevice`'s connection cleanup; orphans return with nil endpoints forever; child-site `parent_site_id` left dangling. Delete connections for the site's device IDs in-txn; decide child handling; add a `data_preservation_test`.
- **L12. Dead exported structs `sflow.FlowSample` + `sflow.CounterSample`** — server `internal/sflow/sflow.go:32-44,46-61`. Delete both.
- **L13. `GetProbe` returns the probe without redacting the hashed `registration_key`** — server `handlers_probes.go:45-64` · *finalSeverity: info*. Admin-only, non-reversible hash. Call `httputil.RedactProbe(&probe)`.
- **L14. Dead method `AlertManager.canAlert`** — server `internal/alerts/alerts.go:336`. Delete.
- **L15. Dead function `report.autoScale`** — server `internal/report/format.go:11` (base-1000 vs base-1024 inconsistency). Delete.
- **L16. Duplicated `getEnv` helper** — collector `cmd/collector/main.go:48` + `internal/config/config.go:103` (isNew:false). Export `config.GetEnv`, delete the local copy.

### INFO

- **I1. Orphaned sFlow agent-drops slice (write-only column + dead DB methods + unused table/model/alert-type)** — server `internal/database/agent_drops.go:15,30`, `models.go:36,781`, `migrate.go:817-829` · *finalSeverity: low*. `SaveAgentDrops`/`GetAgentDropsRecent`/`flow_agent_drops`/`AlertTypeSFlowAgentDrops` have zero non-test callers; `flow_samples.drops` is write-only. CONTRADICTS the 2026-06-22 C-3 finding ("read-and-discarded, no DB table") — now HALF-built. Finish (aggregate in `ReceiveFlowSamples` → `SaveAgentDrops` + reader/alert) OR remove the whole slice.
- **I2. Per-device 50MB config-revision guard is dead code behind the global 5MB body limit** — server `handlers_data.go:695-729` vs `cmd/api/main.go:474`. Real FortiGate backups >5MB get a generic 413, not "Config too large". Route-scope a larger limit or delete the constant; confirm real backup sizes.
- **I3. Dead local type `bucketResult`** — server `handlers_dashboard.go:219-223`. Delete.
- **I4. 13 unused vendor SNMP OID constants (HA/storage/fan/app-version)** — server `vendor_fortigate.go:64-67`, `vendor_paloalto.go:25-33`, `vendor_firewalla.go:33-48`. Prefer to KEEP as documented MIB references (`// reserved: not yet polled` or `//nolint:U1000`); don't silently delete.
- **I5. `trap.go` `ifAdminStatus` switch case is an empty HasPrefix body (SA4017)** — server `internal/snmp/trap.go:266-268`. Delete the case or capture into `formatLinkMessage` or `//nolint`.
- **I6. `config.Load()` returns `(*Config, error)` that can never be non-nil; validation lives in the caller** — collector `internal/config/config.go:54-101`. `parseInt`/`parseBool` silently swallow bad input (`PROBE_POLL_INTERVAL=6O` → 60s default). Drop the error or move validation into `Load` (match `queue.Open`).
- **I7. Server's doc-DTO `relay.FlowSample` advertises phantom sFlow fields** — server `internal/relay/relay.go:68-102` vs `models.go:727-763`; collector `relay.go:169-194`. `SamplePool/SampleAlgorithm/EngineID/EngineType/SrcAS/DstAS/SrcMask/DstMask/TOS` absent both ends. Prune to match reality, or wire end-to-end.
- **I8. `cmd/probe` already removed — memory note + prior-audit P3 stale** (isNew:false). `cmd/` now = api/configcheck/poller/trap-receiver. Update memory; close P3 / open-question #3; optionally `rm probe.exe`.
- **I9. Unused `internal/syslog` UDP receiver does synchronous per-packet DB INSERT (latent footgun)** — server `internal/syslog/syslog.go:461-506`. No daemon starts it (prod path is the POST batch handler). Delete, or before re-enablement route through a bounded channel + `syslogBatch` BatchInserter + large `SO_RCVBUF`.
- **I10. Collector has no THIRD-PARTY-NOTICES file** — collector repo root. Bundles `prometheus/client_golang` (Apache-2.0, requires NOTICE). Generate via `go-licenses report`.
- **I11. Hygiene cluster (CVE / version-skew / base-image) — none symbol-reachable today, all fail downstream SBOM/Trivy/Grype:**
  - **pgx v5.6.0 carries 2 unpatched CVEs** (GO-2026-4771/4772, CVE-2026-33815/33816; fixed v5.9.0). govulncheck exits 0 (import-tier `pgproto3.Backend`, this is a pgx *client*). `go get .../pgx/v5@v5.9.0 && go mod tidy`. (`go.mod:10`)
  - **govulncheck CI gate only fails on symbol-reachable vulns** — 2 import + 18 module-tier CVEs ride green. Add Trivy/Grype image scan + `govulncheck -scan module`. (`.github/workflows/ci.yml:119-142`, collector `docker.yml:53-56`)
  - **x/crypto skew:** server `v0.51.0` (~14 SSH CVEs + x/image via go-chart) vs collector `v0.52.0`. Bump server to `v0.52.0+`, `x/image v0.41.0+`. (`go.mod:18`)
  - **Container bases unpinned floating tags** (`golang:1.25-alpine`, `alpine:3.19`) — undermines the AUDIT-102 reproducibility claim. Pin by `@sha256` via Renovate. (both Dockerfiles)
  - **NPM admin GUI `:81` published on 0.0.0.0, no bind-restriction/default-cred note** + obsolete `version:` key. Bind `127.0.0.1:81:81`, warn to change the default login. (`docker-compose.proxy.yml:9,16-19`)
- **I-test. Test-coverage gaps (finalSeverity low):**
  - **FortiGate SNMP parse methods 6/7 untested** — `ParseSystemStatus/Interfaces/VPNStatus/VPNDialupStatus/GRETunnels`; only `ParseHardwareSensors` covered. This is the core FortiGate ingestion path and the exact `ToBigInt`-on-typed-value class that shipped the sensor-temp-0.0 bug. Add table-driven `[]gosnmp.SnmpPDU` fixtures. (`internal/snmp/vendor_fortigate.go:106,180,299,409`)
  - **SNMP trap PDU decode (`parseTrap`/`parseLinkTrap`) untested** — only rate-limiter/community gating is. The v1-vs-v2c branch + linkUp/linkDown classification are untested. Add synthetic `*gosnmp.SnmpPacket` tests. (`internal/snmp/trap.go:166,205`)

---

## Considered and Dismissed (refuted / unverified)

Do NOT treat as real findings:
- `GetAlertsByDeviceAndHours` unbounded result set (no LIMIT) — rejected.
- notifier multipart `writer.Close()` error ignored — rejected.
- 429 asymmetry (collector silently drops SNMP-metric batches on 429) — rejected.
- SNMP/SSH parsers lack fuzz harnesses (asymmetric with sflow/syslog) — rejected.
- Collector `SpilloverQueue` FIFO inversion / preferential loss of oldest data — rejected.

---

## Cross-Repo Wire-Contract Notes

HTTP/JSON relay; the collector's `internal/relay/relay.go` is the complete vocabulary and only client; the server's is now DOC-ONLY (real receiver = `handlers_data.go` → `internal/models`). 21 POST data endpoints + register/heartbeat/devices(GET) resolve; the `schema_version` handshake is correct both ends (Min=Max=1). Residual contract risks (beyond I1/I7):

- **Approval-revocation invisible to heartbeat:** `ProbeHeartbeat` authenticates by Bearer only, never checks `ApprovalStatus` (returns 200 for a revoked probe); only data endpoints (`validateProbe`) 403. A revoked-then-idle probe heart-beats "online" indefinitely.
- **Direct-send has no idempotency key:** `sendBatch` sends `X-Probe-Batch-ID`; `doDirectSend` (9 SNMP metric types) sends none → a timed-out-but-saved retry double-inserts system/interface/VPN rows. AUDIT-042 covers only traps/pings/syslog/flows.
- **sFlow `Bytes` is sampling-rate-scaled at source** and `SamplingRate` is also on the wire with no contract note — a future read-path multiplying by `SamplingRate` would double-scale. Add a one-line comment.
- **schema_version pinned to one value** ⇒ additive changes (`drops,omitempty`) aren't gated. Any future breaking field MUST bump `SchemaVersionMax` in lockstep both repos.

---

## Feature Inventory & Industry Roadmap

Maintained in **`Firewall-Mon/docs/FEATURE-ROADMAP.md`**. Headlines:
- **Strengths to defend:** config-change *attribution* without TACACS+, vendor-aware semantic config-diff + risk severity, OTel tracing across the probe→server boundary, encrypted-at-rest secrets with rotation chain, append-only route-labelled audit log, schema-version handshake + idempotent batch relay — several beat the entire peer set.
- **P0 credibility blockers:** multi-user + RBAC, scoped API tokens, TOTP 2FA, NetFlow v5/v9 + IPFIX. A single-admin / no-token / no-2FA / sFlow-only tool is rejected at security review regardless of data-plane quality.
- **Highest-ROI item:** the P0 access-control epic (RBAC → tokens → 2FA) — mostly assembly of stacks already present (JWT, bcrypt, hashed-key compare, audit log).
