# Engineering Audit — 2026-08-27 (Firewall-Mon + Firewall-Collector)

**Date:** 2026-08-27  
**Method:** Deep adversarial multi-agent audit. 22 finder lenses (Knuth/`taocp` and GoF/`design-patterns` applied on the algorithmic and abstraction-heavy areas) swept 100% of both repos' source; a dedup + do-not-re-flag screen produced candidates; every candidate faced **three independent refuter lenses** (reproduce-from-source, exploitability/materiality, mitigation-or-intent) and survived only on **≥2 confirmations** (refute-by-default). A completeness-critic loop ran until dry, and the highest-severity findings were re-derived by an independent accuracy pass before publication.

**Confirmed findings in this report: 148** — 6 high · 47 medium · 85 low · 10 info.

| Severity | Count |
|---|---|
| HIGH | 6 |
| MEDIUM | 47 |
| LOW | 85 |
| INFO | 10 |

| Defect class | Count |
|---|---|
| `correctness` | 43 |
| `input-hardening` | 17 |
| `docs-drift` | 17 |
| `contract-drift` | 15 |
| `security` | 13 |
| `data-integrity` | 10 |
| `concurrency` | 8 |
| `performance` | 7 |
| `maintainability` | 6 |
| `toolchain-ci` | 4 |
| `test-gap` | 3 |
| `frontend-state` | 3 |
| `frontend-xss` | 1 |
| `resource-leak` | 1 |

**Scope:** full server (`Firewall-Mon`) plus cross-repo contract findings. The collector-only findings and the cross-repo subset are additionally tracked in the `Firewall-Collector` copy of this report.

## Disposition roll-up (2026-08-29)

Final outcome of all 148 findings, recorded during the batched remediation program. Per-finding dispositions appear inline as a blockquote directly under each finding heading below (with the resolving version and PR, or the reason for a non-fix).

| Disposition | Count |
|---|---|
| ✅ Resolved | 147 |
| ⛔ Refuted | 1 |
| ⚠️ Unresolved | 0 |
| **Total** | **148** |

All 148 findings are now dispositioned. The single refuted finding is AUDIT-198 (dead/unreachable dashboard code); the remaining 147 are resolved. The final batches to land were Batch 6 (AUDIT-176, the last HIGH — serverhealth test coverage, server v0.11.232) and Batch 9 (the collector ingest-attribution/hardening set: AUDIT-186, 187, 216, 237, 263, 282, 283, 284, 305, 306, 307, 317, collector v1.3.43/v1.3.44). See each inline blockquote for the resolving version and PR.

## Highest-severity summary

- **AUDIT-171 (HIGH)** — Native systemd deploy flattens web/ so LoadHTMLGlob panics — fwmon-api crash-loops; HTML has no embedded fallback despite the comment claiming single- (`cmd/api/main.go:610`)
- **AUDIT-173 (HIGH)** — Explicitly-empty ADMIN_PASSWORD= (the shipped config default) creates an admin with bcrypt("") and permanently locks the operator out (`internal/config/config.go:524`)
- **AUDIT-174 (HIGH)** — EnsurePartitions builds duplicate per-partition indexes for columns already covered by parent-level partitioned indexes (v54 syslog sev_ts, v57 trap t (`internal/database/migrate.go:499`)
- **AUDIT-175 (HIGH)** — sendBatchesSequential silently drops the drained-but-unsent tail on a transient failure — defeats the AUDIT-058 outage-durability guarantee (`internal/relay/relay.go:1971`)
- **AUDIT-176 (HIGH)** — Zero test coverage for the incident-derived serverhealth invariants — DataDirLocator crash-loop fallback (serverhealth/probe.go:74) and dataOK nil-vs- (`internal/serverhealth/probe.go:61`)
- **AUDIT-177 (HIGH)** — FortiGate SD-WAN column OIDs omit the table-entry level (.2.1) — every PDU is swallowed by the Name branch, all SD-WAN metrics silently zero/garbage (`internal/snmp/vendor_fortigate.go:122`)

## Confirmed findings

### HIGH (6)

#### AUDIT-171 · HIGH · Native systemd deploy flattens web/ so LoadHTMLGlob panics — fwmon-api crash-loops; HTML has no embedded fallback despite the comment claiming single-binary support

> **✅ RESOLVED (v0.11.211 · PR #219)** — deploy.sh now copies web/ with its prefix so LoadHTMLGlob resolves — native systemd install no longer crash-loops at first boot.

**Firewall-Mon** — `cmd/api/main.go:610` · class: `correctness` · related: `deploy.sh`, `Dockerfile`

**Defect.** router.LoadHTMLGlob("./web/**/*.html") panics on zero matches; deploy.sh copies web/* CONTENTS into /opt/firewall-mon (no web/ prefix) while WorkingDirectory=INSTALL_DIR. Static assets have an embedded fallback; HTML templates do not. Only Docker survives (COPY web ./web).

**Failure scenario.** The repo's own deploy.sh native install starts fwmon-api with cwd=/opt/firewall-mon → ./web/**/*.html matches nothing → LoadHTMLGlob panics → Restart=always crash-loops forever. The documented native install path is dead on arrival. Fix: copy web/ with prefix or embed templates.

**Fix direction.** copy web/ with prefix or embed templates.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-173 · HIGH · Explicitly-empty ADMIN_PASSWORD= (the shipped config default) creates an admin with bcrypt("") and permanently locks the operator out

> **✅ RESOLVED (v0.11.211 · PR #219)** — a set-but-empty admin-password value is treated as unset (Validate() hard-fails empty), so the operator is no longer permanently locked out.

**Firewall-Mon** — `internal/config/config.go:524` · class: `input-hardening` · related: `config.env.example`, `deploy.sh`, `cmd/api/main.go`, `internal/database/sites_probes.go`

**Defect.** config.go:524 `AdminPassword: getEnv("ADMIN_PASSWORD", getDefaultPassword())` — getEnv (config.go:781) uses os.LookupEnv, so a shipped `ADMIN_PASSWORD=` yields "" not the generated default. IsGeneratedPassword() (line 537) correctly returns false → the secrets/generation block is skipped (cmd/api/main.go:263) → HashPassword("") with no empty guard (auth.go:301) → InitAdmin skips on every later boot (sites_probes.go:121). Login binding rejects empty password (handlers_auth.go:39 `binding:"required"`), so the account is unusable and no later ADMIN_PASSWORD can replace it — permanent lockout, resurrecting AUDIT-008.

**Failure scenario.** A fresh install with the documented placeholder creates a bcrypt("") admin, no password persisted; login impossible (binding rejects empty), later setting ADMIN_PASSWORD doesn't help (InitAdmin skips existing) → permanent lockout requiring DB surgery; resurrects AUDIT-008. Fix: treat empty as unset or fail Validate().

**Fix direction.** treat empty as unset or fail Validate().

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-174 · HIGH · EnsurePartitions builds duplicate per-partition indexes for columns already covered by parent-level partitioned indexes (v54 syslog sev_ts, v57 trap timestamp)

> **✅ RESOLVED (v0.11.214 · PR #222)** — partitionIndexPlan now excludes column-sets already covered by parent partitioned indexes (catalog-driven), so fresh installs build no duplicate per-partition btrees — latent for current heap-table prod; guards the next conversion.

**Firewall-Mon** — `internal/database/migrate.go:499` · class: `performance` · related: `internal/database/partition_index_lc19_test.go`, `internal/models/models.go`

**Defect.** EnsurePartitions creates idx_<partition>_<suffix> on each leaf while v54/v57 create parent partitioned indexes that PG auto-cascades to every new leaf; IF NOT EXISTS matches by name only, so a second physically identical btree is built on the same column set. partitionIndexPlan has no exclusion for parent-covered columns.

**Failure scenario.** Every new monthly partition of syslog_messages (volume-dominant, ~4.5-5.6M rows/day) carries two identical (severity,timestamp) btrees — double index write amplification + disk forever, undetected by tests.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-175 · HIGH · sendBatchesSequential silently drops the drained-but-unsent tail on a transient failure — defeats the AUDIT-058 outage-durability guarantee

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — sendBatchesSequential now requeues the failed chunk AND all not-yet-attempted chunks then stops the drain, so a server outage no longer shreds the disk spool.

**Firewall-Collector** — `internal/relay/relay.go:1971` · class: `data-integrity`

**Defect.** relay.go:1968-1971: on a transient chunk failure sendBatchesSequential calls requeue(chunk) then a bare `return` at 1971 — chunks[i+1:], already removed by the destructive Drain (queue.go:338/355/372), are never requeued; the comment 'leave the rest for next sync' is false. drainChunk = MaxBatchSize*10 (relay.go:1829) so up to ~9 of 10 chunks (~9,000 items at the 1000 default) are destroyed per failure. drainAndSend does not stop on failure (breaks only when len<drainChunk, 2035), so a full drain loops and repeats the loss. drainMetricQueue by contrast correctly requeues raw[idx:].

**Failure scenario.** Server down while the flow queue holds >MaxBatchSize items (trivial at a busy site): syncData drains 10,000, chunk 1 fails transiently → 1,000 requeued and ~9,000 destroyed; the drain loop repeats while len==drainChunk → a multi-day disk-spool backlog (AUDIT-058) is ~90% shredded within minutes, only per-chunk log lines. Fix: requeue the failed chunk AND all not-yet-attempted chunks, then stop the drain.

**Fix direction.** requeue the failed chunk AND all not-yet-attempted chunks, then stop the drain.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-176 · HIGH · Zero test coverage for the incident-derived serverhealth invariants — DataDirLocator crash-loop fallback (serverhealth/probe.go:74) and dataOK nil-vs-zero strictness (cmd/poller/serverhealth.go:137)

> **✅ RESOLVED (server v0.11.232 · PR #240)** — added regression tests for the serverhealth crash-loop data-dir fallback and the dataOK nil-vs-zero strictness (both incident-derived), plus a minimal injectable-lookup refactor for testability.

**Firewall-Mon** — `internal/serverhealth/probe.go:61` · class: `test-gap` · related: `cmd/poller/serverhealth.go`, `internal/alerts/serverdisk_test.go`

**Defect.** internal/serverhealth/ holds one file (probe.go, 118 lines) and zero _test.go. Two load-bearing, untested invariants: (1) the DataDirLocator crash-loop fallback at probe.go:74-82 (`if cached != "" { return cached, true, err }`) — the cache that kept disk telemetry alive across the 2026-07-26 PG crash-loop; (2) the dataOK nil-vs-zero *float64 strictness at cmd/poller/serverhealth.go:137-140 (`m.DataDiskPercent=&pct` only under `if dataOK`), which distinguishes 'unmeasured' from '0% used'. cmd/poller has 20 test files, none exercising collectServerVolumes/recordServerMetrics/DataDirLocator.

**Failure scenario.** A refactor dropping the cache fallback or flattening the *float64 fields passes CI and reproduces the 2026-07-26 blind spot: next PG crash-loop on a filling volume goes unalerted or renders 0% used.

*Verification: 3/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-177 · HIGH · FortiGate SD-WAN column OIDs omit the table-entry level (.2.1) — every PDU is swallowed by the Name branch, all SD-WAN metrics silently zero/garbage

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — the fgVWLHealthCheckLinkTable column OIDs now include the table-entry level, so SD-WAN health metrics are no longer all silently zero/garbage.

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:122` · class: `correctness`

**Defect.** fgOIDSDWANHealth* = ...101.4.9.{2,4,5,7,8,14} but fgVWLHealthCheckLinkTable columns live at ...4.9.2.1.{...}; fgOIDSDWANHealthName equals the TABLE node so HasPrefix(name, Name+".") matches every column, funneling all PDUs into the Name branch. State/Latency/PktSend/Recv/IfName branches match nothing. No test covers ParseSDWANHealth.

**Failure scenario.** On a FortiGate with SD-WAN health checks, each row has Name overwritten by the last string column, State '', Latency/loss 0 — a dead link reports loss 0% with empty state, no operator signal, no alert. Fix the OIDs to ...4.9.2.1.*.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

### MEDIUM (47)

#### AUDIT-172 · MEDIUM · F17 z-score DISK baseline is polluted by SSH-perf writer zero-disk rows during SNMP-cache-stale windows — the baseline loop lacks the zero/Source filter the evaluation path applies

> **✅ RESOLVED (v0.11.217 · PR #225)** — the F17 zscore disk baseline no longer ingests SSH zero-disk rows and is built from the newest samples.

**Firewall-Mon** — `internal/alerts/baseline_f17.go:62` · class: `correctness` · related: `internal/alerts/alerts.go`, `internal/models/models.go`, `internal/database/charts.go`

**Defect.** baseline_f17.go:62-67 appends hist[i].DiskUsage/SessionCount unconditionally — no zero-check and no Source check, though models.SystemStatus.Source exists (models.go:152). The EVALUATION path DOES filter: alerts.go:274 `sessionsMeasured := status.SessionCount>0 || status.Source==SNMP` and :278 gates disk on `status.DiskUsage>0`. So the baseline mean/std is computed over rows the evaluator would exclude. Scope corrected by accuracy pass: (a) the SESSIONS half is NOT a defect — the SSH-perf row carries a real parsed SessionCount (collector main.go:1655); (b) disk zeros occur only when the SNMP vitals cache is stale (>3× poll interval, throughput.go:145), so this pollutes the DISK baseline during SNMP-outage windows rather than steady-state. zscoreFireAt does use max(floor, mean+k*sd) (baseline_f17.go:109), so an inflated disk baseline can push the effective DISK_HIGH threshold above 100% for that window.

**Failure scenario.** During a multi-hour SNMP outage on a dual-writer FortiGate, ~half the 24h disk history is SSH-perf zero-disk rows; the polluted mean+3σ can exceed 100%, so a z-score DISK_HIGH rule cannot fire for the duration of the window even as the volume fills. Fix: filter the baseline sample the same way the evaluator does (drop DiskUsage==0 / non-SNMP-sourced rows before accumulating).

**Fix direction.** filter the baseline sample the same way the evaluator does (drop DiskUsage==0 / non-SNMP-sourced rows before accumulating).

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-178 · MEDIUM · Collector CI installs staticcheck and govulncheck @latest (unpinned) — server pins both for exactly this failure mode

> **✅ RESOLVED (collector v1.3.35 · PR #99)** — pinned the staticcheck/govulncheck CI tool versions (they were @latest) and added an automatic release-tag workflow.

**Firewall-Collector** — `.github/workflows/docker.yml:61` · class: `toolchain-ci`

**Defect.** docker.yml installs staticcheck@latest and govulncheck@latest; server pins staticcheck@v0.7.0 and govulncheck@v1.6.0 with a comment explaining unpinned tools fail CI out from under unrelated PRs. The collector workflow also has no permissions: block.

**Failure scenario.** A new staticcheck release fires on existing collector code → test job red on an unrelated PR/hotfix → build (needs:test) never runs → image publishing blocked by an upstream release with zero code change; two runs of one commit can disagree, so 'CI was green' isn't reproducible.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-179 · MEDIUM · MIGRATING.md states the current schema_version maximum is 4 (range 1-4) while code and the doc's own table say 5

> **✅ RESOLVED (v0.11.231 · PR #239)** — corrected the stale schema-version max in MIGRATING.md / SUPPORT-MATRIX.md to match relay.SchemaVersionMax = 5.

**Firewall-Mon** — `MIGRATING.md:32` · class: `docs-drift` · related: `internal/relay/relay.go`, `docs/SUPPORT-MATRIX.md`

**Defect.** MIGRATING.md:32/35 say max 4 / range 1-4, but relay.SchemaVersionMax=5 (both repos) and the same doc's outcome table says 1-5; SUPPORT-MATRIX.md says '0.10.x' and 'currently 1-1'.

**Failure scenario.** An operator planning a mixed-version rollout reads 'max 4', concludes a v5 1.3.15+ collector is rejected 426, and delays the upgrade or builds monitoring on the wrong supported-version range.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-180 · MEDIUM · Collector version facts stale across four docs: README badge 1.3.4, SECURITY.md supports only 1.2.x, FEATURES.md says current is 1.2.x, DEPLOY.md instructs pulling :1.2 images

> **✅ RESOLVED (collector v1.3.42 · PR #106)** — corrected stale version strings across the collector docs (README badge tracks the version const).

**Firewall-Collector** — `README.md:13` · class: `docs-drift` · related: `SECURITY.md`, `docs/FEATURES.md`, `DEPLOY.md`, `cmd/collector/main.go`

**Defect.** Badge 1.3.4 vs version 1.3.33; SECURITY.md table lists only 1.2.x (33 1.3.x releases absent) and tells reporters to inspect :1.2.x; FEATURES.md 'current 1.2.x'; DEPLOY.md pulls :1.2 while README default is :1.3.

**Failure scenario.** A user following DEPLOY.md runs :1.2 (frozen: no NetFlow/IPFIX, no disk/load, no command channel, no L2 topology at schema v2) then reports 'missing flows'; a researcher reads SECURITY.md and treats 1.3.x as unsupported/out-of-scope.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-181 · MEDIUM · README states Cisco ASA has no SNMP polling profile, but a full registered profile exists in both repos

> **✅ RESOLVED (v0.11.231 · PR #239 ; collector v1.3.42 · PR #106)** — documented that Cisco ASA has a full SNMP profile (server README) and added it to the collector vendor doc surfaces.

**cross-repo** — `README.md:94` · class: `docs-drift`

**Defect.** Firewall-Mon/README.md:92-95 and :46 say Cisco ASA is 'config-diff only (no SNMP polling profile)'. False: internal/snmp/vendor_cisco_asa.go registers a full VendorProfile via init() with SystemOIDs (CPU/mem/session), ParseSystemStatus/ProcessorStats/HAStatus (CISCO-FIREWALL-MIB failover), CDP neighbor discovery — identical in both repos. vendor.go keys by Name() so GetVendorProfile("cisco_asa") returns it; vendor_robustness_test.go enumerates cisco_asa. Collector README also omits ASA from its SNMP-pollable list.

**Failure scenario.** An operator with a Cisco ASA fleet reads the README, concludes ASA cannot be SNMP-health-monitored, and never adds ASA for polling — a fully-built, tested SNMP profile (CPU/mem/sessions/failover/CDP) sits unused because the doc contradicts shipped, reachable code.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-182 · MEDIUM · Server docs, compose, and Dockerfile advertise [Server] syslog/sFlow/ICMP listeners and an 8089 probe server that no server binary runs

> **✅ RESOLVED (v0.11.228 · PR #236)** — corrected docs that advertised nonexistent server-side syslog/sFlow/ICMP listeners.

**Firewall-Mon** — `README.md:102` · class: `docs-drift` · related: `docker-compose.yml`, `Dockerfile`, `docs/FEATURES.md`, `KNOWN-ISSUES.md`

**Defect.** README (102-105, port table 514/6343/8089), docker-compose (publishes 514/6343/8089), Dockerfile EXPOSE, docs/FEATURES.md, KNOWN-ISSUES.md all advertise server-side syslog/sFlow/ICMP + probe server, but go list -deps ./cmd/... shows internal/syslog, internal/sflow, internal/ping have zero importers and cfg.Probe (EnableProbeServer, SyslogAllowedSources) has zero consumers. Only the trap receiver (162) exists server-side.

**Failure scenario.** An operator without a collector follows README/compose, points firewall syslog+sFlow at the server → Docker publishes 514/6343 into a container where nothing binds them → every datagram silently dropped, no rows, no error; SYSLOG_ALLOWED_SOURCES changes nothing; the firewall is told to open 8089 for a nonexistent service.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-183 · MEDIUM · Transient DB error at singleton-lock acquisition installs a nil release func, panicking main at graceful shutdown

> **✅ RESOLVED (v0.11.211 · PR #219)** — the API-singleton advisory-lock error path returns a no-op cleanup func, so graceful shutdown no longer panics after a transient startup DB error.

**Firewall-Mon** — `cmd/api/main.go:205` · class: `correctness` · related: `internal/database/database.go`

**Defect.** In the lockErr branch (200-206): `isPrimary, releaseSingleton = true, release` where release is NIL on every error return of AcquireAPISingletonLock (database.go:539-551 all return nil,false,err). releaseSingleton is then registered with `defer releaseSingleton()` (238).

**Failure scenario.** NewDatabase succeeds, then a transient DB condition (pool exhaustion, reset, statement_timeout) makes AcquireAPISingletonLock return (nil,false,err). main takes the lockErr branch as intended ('proceed as primary'), setting releaseSingleton=nil, and serves. On the first SIGTERM/SIGINT (every redeploy) or listener error, `defer releaseSingleton()` invokes a nil func → panic + non-zero exit instead of the clean 'Server exited' path. Fix: keep the no-op func, or make AcquireAPISingletonLock return func(){} on error paths.

**Fix direction.** keep the no-op func, or make AcquireAPISingletonLock return func(){} on error paths.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-184 · MEDIUM · Stored XSS: solidBadge/typeBadgeHtml interpolate connection_type unescaped, and the server accepts arbitrary connection_type strings

> **✅ RESOLVED (v0.11.216 · PR #224)** — stored XSS via connection_type badges closed at both the render and ingest ends.

**Firewall-Mon** — `cmd/api/static/js/admin-common.js:175` · class: `frontend-xss` · related: `cmd/api/static/js/diagram-panels.js`, `internal/api/handlers/handlers_connections.go`, `cmd/api/static/js/admin-connection-detail.js`

**Defect.** solidBadge concatenates label unescaped; typeBadgeHtml feeds raw conn.connection_type; sink diagram-panels.js:163-171 sets panel.innerHTML with the unescaped typeBadge. UpdateDeviceConnection allowlists connection_type and validates only the status enum — no validation on connection_type, so any operator-role can PUT an HTML payload. The connections table escapes the same field.

**Failure scenario.** An operator-role user PUTs connection_type with an <img onerror> payload; any admin later clicking that connection on the map executes it via the rich-panel innerHTML → session-riding to admin-only endpoints (user mgmt, secret reveal, settings).

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-185 · MEDIUM · loadPublicInterfaces returns no promise (init chain broken) and togglePublicIface saves the whole map — an early toggle wipes other devices' public-interface selections

> **✅ RESOLVED (v0.11.224 · PR #232)** — the device-detail public-interface toggle no longer wipes other devices' selections, and the interface table waits for its curation to load.

**Firewall-Mon** — `cmd/api/static/js/admin-device-detail.js:63` · class: `data-integrity` · related: `cmd/api/static/js/public-dashboard.js`

**Defect.** loadPublicInterfaces fetches but never returns the promise, yet the init chain sequences on it (.then(loadPublicInterfaces).then(loadDevice)) so loadDevice runs with publicInterfaces={}; togglePublicIface persists the ENTIRE map as public_interfaces from whatever loaded so far; the catch leaves it empty on failure.

**Failure scenario.** On a slow link, ticking one interface's Public box before /display-settings lands POSTs {thisDevice:[port1]} as the complete setting → silently erases every other device's public-dashboard selections; checkboxes also render unchecked until the next 60s refresh.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-186 · MEDIUM · sFlow samples attributed by in-band agent_address, not bound to the UDP source — intra-fleet cross-device flow/counter forgery

> **✅ RESOLVED (collector v1.3.44 · PR #108)** — sFlow attribution now binds to the UDP source (asymmetric: reject a known-unique source-vs-claim mismatch; HA/CARP shared cluster IPs accepted via device-set ambiguity tracking; unresolvable source warns+accepts), behind PROBE_STRICT_SOURCE_BINDING.

**Firewall-Collector** — `cmd/collector/main.go:557` · class: `data-integrity` · related: `internal/sflow/sflow.go`

**Defect.** sFlow device attribution uses SamplerAddress, which for sFlow is the agent_address parsed from the datagram BODY (sflow.go:357/471), while the only spoofing guard checks the UDP source IP (sflow.go:253). The resolver keys on the in-band value: `sample.DeviceID = c.resolveDeviceByIP(sample.SamplerAddress)`. The allowlist binds only the UDP source, never agent_address, so a datagram from any allowed source may carry any agent_address. (NetFlow is NOT affected — it uses the UDP source as SamplerAddress.)

**Failure scenario.** Collector monitors A and B (both allowlisted). Attacker compromises A (or spoofs A's UDP source) and emits sFlow v5 whose in-band agent_address=B's IP with fabricated flow/counter samples. isSourceAllowed(A) passes; resolveDeviceByIP attributes them to B → forged telemetry drives false threat detections and bogus bandwidth graphs on B, and can game flowdedup.Key(B, B_ip) to suppress B's genuine flows. Same root cause as the TFTP finding: allowlist restricts sender, not claimed identity.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-187 · MEDIUM · TFTP WRQ handler trusts the filename-embedded device ID with no client-address binding — any allowlisted fleet device can forge config revisions for any other device

> **✅ RESOLVED (collector v1.3.44 · PR #108)** — TFTP config uploads bind to a collector-initiated pending-trigger registry (count-valued, 5-min window) rather than the filename alone, so an unsolicited cross-device upload is rejected while a NAT'd/hub upload of a triggered device is accepted.

**Firewall-Collector** — `cmd/collector/main.go:1283` · class: `security` · related: `internal/tftp/tftp.go`

**Defect.** parseUploadFilename derives DeviceID purely from the fgt_<id>_<trigger>_config filename; clientAddr is available (findDeviceByID/resolveDeviceByIP exist) but never cross-checked. The AUDIT-050 allowlist is a flat fleet-wide IP set; checksum is computed over the attacker's own bytes; server ReceiveConfigRevision gates only on probe-assignment.

**Failure scenario.** A compromised/NAT-sharing fleet device passes the allowlist and uploads fgt_<victimID>_manual_config with fabricated text → an authoritative ConfigRevision for the victim: false CONFIG_CHANGE, poisoned diff history, or (if checksum matches) silent overwrite of the victim's backup ciphertext. Fix: bind clientAddr→device (warn/strict) or derive device from source IP.

**Fix direction.** bind clientAddr→device (warn/strict) or derive device from source IP.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-188 · MEDIUM · Retention cleanup runs synchronously inside the poller's single select loop, so a large backlog clear parks the loop for its whole (potentially multi-hour) duration and the 5-minute server-disk DISK_HIGH check cannot fire — the exact silent-outage shape the 2026-07-26 postmortem added it to prevent

> **✅ RESOLVED (v0.11.214 · PR #222)** — retention cleanup runs async under its own lock so a multi-hour pass no longer blinds the server-disk health check.

**Firewall-Mon** — `cmd/poller/main.go:301` · class: `correctness` · related: `cmd/poller/serverhealth.go`, `internal/database/cleanup.go`

**Defect.** Confirmed by reading cmd/poller/main.go:300-304: the poller is one `for { select {...} }` goroutine; `case <-cleanupTimer.C: p.runRetentionCleanup()` executes inline and returns only when the whole cleanup finishes. checkServerHealth (the server's-own-volume disk-full detector added after the outage, serverhealth.go:84) is invoked ONLY from `case <-serverHealthTicker.C:` (main.go:304) plus once at startup (main.go:211) — grep confirmed no other caller. Go tickers coalesce, so serverHealthTicker.C is not serviced until the select loop returns. batchedDeleteOlderThanOn sleeps 100ms between every 10k-row batch and CleanupOldData sweeps ~20 tables plus per-severity syslog DELETEs; on prod syslog_messages is NOT partitioned so the whole backlog goes through batched DELETE. The authors deliberately moved threat-feed sync OFF this loop for exactly this blocking class (main.go:293 `startThreatFeedSyncAsync // M9: async, off the select loop`) but left the far longer cleanup synchronous.

**Failure scenario.** Poller restarts and 5 min later runRetentionCleanup begins clearing an over-retention syslog backlog on the non-partitioned prod heap (tens of millions of rows; thousands of 10k-row batches × 100ms sleep alone = many minutes, plus per-batch DELETE cost = tens of minutes to hours). Throughout that window the select loop is parked, serverHealthTicker.C is never serviced, and checkServerHealth never runs — no CheckServerVolumes, no DISK_HIGH on PGDATA. Large DELETEs transiently INCREASE on-disk WAL+dead-tuple usage before autovacuum reclaims (and reclaimed space returns to table freespace, not the OS), so the volume can cross full during cleanup and Postgres crash-loops on 'No space left on device' with no alert. Fix: run runRetentionCleanup off the select loop the way startThreatFeedSyncAsync/M9 does.

**Fix direction.** run runRetentionCleanup off the select loop the way startThreatFeedSyncAsync/M9 does.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-189 · MEDIUM · TELEMETRY_STALE falsely self-recovers on a FortiGate whose SNMP is dead >24h but SSH keeps vitals fresh, permanently suppressing a partial-collection outage

> **✅ RESOLVED (v0.11.217 · PR #225)** — the TELEMETRY_STALE recovery gate no longer false-recovers on unrelated fresh signal while SNMP is still dead.

**Firewall-Mon** — `cmd/poller/telemetrystale.go:128` · class: `correctness` · related: `cmd/poller/main.go`, `internal/database/telemetry.go`, `internal/alerts/alerts.go`

**Defect.** The recovery gate treats ANY one fresh signal as 'telemetry flowing again', but the two signals have independent writers on a FortiGate (system_status written by BOTH the SNMP writer AND the SSH perf writer per header 20-23; interface_stats written ONLY by SNMP). When staleParts is empty (telemetrystale.go:128-131): `if in.freshStatus[id] || (!in.latestIface[id].IsZero() && in.now.Sub(in.latestIface[id]) < in.staleAfter) { p.alertManager.CheckTelemetryRecovered(dev) }`. The iface fire condition (line 117) requires the device to still be a key in latestIface, but main.go:1178-1186 only sets latestIface for rows within the 24h lookback, so 24h after SNMP dies the last interface_stats row drops out and latestIface[id] becomes unset -> no iface stalePart. SSH keeps freshStatus[id] true, so line 109 `if !in.freshStatus[id]` skips the vitals stalePart too. staleParts is now empty and the gate passes on freshStatus. CheckTelemetryRecovered (alerts.go:2033) sees active=true and calls sendRecovery. The comment's stated invariant ('rows merely aged out ... its open alert remains the signal') only holds when BOTH signals aged out; the mixed dual-writer case violates it.

**Failure scenario.** FortiGate, probe-assigned, telemetry_stale_minutes 60. SNMP polling breaks (host-restriction/ACL/credential) while the SSH perf writer keeps system_status fresh. interface_stats stops at T0. At ~T0+60m TELEMETRY_STALE correctly fires and stays open. At exactly T0+24h the last interface_stats row ages out, latestIface[deviceID] unsets, staleParts empties, and the gate passes on freshStatus (SSH vitals). The operator receives a misleading 'Polled telemetry recovered' notification and the alert closes while SNMP is STILL dead. On subsequent cycles CheckTelemetryRecovered short-circuits (!active && swept), so the ongoing partial-collection outage is now permanently and silently suppressed — defeating the exact silent-failure gap this feature exists to close.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-190 · MEDIUM · Seeded SECRETS_DIR=/data collides with the native unit's ProtectSystem=strict sandbox — all three daemons log.Fatalf at the JWT-secret step on first native boot

> **✅ RESOLVED (v0.11.211 · PR #219)** — config.env.example seeds the native secrets directory so seeded secrets work under the systemd sandbox.

**Firewall-Mon** — `config.env.example:28` · class: `toolchain-ci` · related: `deploy.sh`, `cmd/api/main.go`, `internal/secrets/secrets.go`

**Defect.** config.env.example ships SECRETS_DIR=/data (Docker path); deploy.sh unit sets ProtectSystem=strict with ReadWritePaths=/var/lib/firewall-mon only. LoadOrGenerate's MkdirAll("/data",0700) fails on the read-only fs → log.Fatalf in all three daemons. deploy.sh's own AUDIT-021 comment names /var/lib/firewall-mon/.jwt-secret.

**Failure scenario.** First boot of a native systemd install seeded from the example config fatals at startup MkdirAll("/data") and crash-loops under Restart=always. Fix: seed SECRETS_DIR=/var/lib/firewall-mon.

**Fix direction.** seed SECRETS_DIR=/var/lib/firewall-mon.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-191 · MEDIUM · State rule's explicit min_up_seconds:0 is silently clobbered to the 3600 default, defeating a configured daily flap cap

> **✅ RESOLVED (v0.11.217 · PR #225)** — an explicit min_up_seconds: 0 on a state rule is now honored (pointer-typed field).

**Firewall-Mon** — `internal/alerts/staterules.go:99` · class: `correctness` · related: `internal/alerts/rules.go`, `internal/alerts/policy.go`

**Defect.** buildStateCandidateLocked forces any non-positive min_up via a bare `<= 0` test (staterules.go:99-101): `if dp.MinUpSeconds <= 0 { dp.MinUpSeconds = defaultStateMinUpSeconds /*3600*/ }`. Because `MinUpSeconds int` carries `json:"min_up_seconds,omitempty"` (rules.go:164), an OMITTED field and an EXPLICIT 0 both deserialize to 0 and `<= 0` treats them identically. The validator explicitly accepts 0 (staterules.go:276 `if dp.MinUpSeconds < 0`), and decideStateFire has dedicated 0 handling — the up->=Xs fast-path (step 4) is guarded `if c.dampen.MinUpSeconds > 0 && lr.ResolvedAt != nil && ...` (staterules.go:198), so 0 means 'disable the fast-path, respect the daily cap strictly.' The authors knew the omitempty/0 ambiguity and added a RefireMode sentinel to preserve an explicit DailyCap 0 (staterules.go:107) but gave MinUpSeconds no such guard.

**Failure scenario.** Operator saves a source=state INTERFACE_DOWN rule with dampen_json {refire_mode:episode, daily_cap:2, min_up_seconds:0} — intent: page at most twice/day regardless of up-run length. Validation accepts it, but buildStateCandidateLocked rewrites 0->3600. Every outage following a >=1h up-run then hits decideStateFire step (4) and returns stateFire unconditionally, bypassing capReached. A link that recovers >1h then drops 5x/day pages 5 times instead of 2 — the explicitly configured cap is silently unenforceable, contradicting the 'dampening must be configurable, never hardcoded' invariant.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-192 · MEDIUM · Unauthenticated /api/health leaks raw DB driver error (internal host/user/db/IP) to callers

> **✅ RESOLVED (v0.11.215 · PR #223)** — the unauthenticated /api/health endpoint no longer discloses internal database topology to anonymous callers.

**Firewall-Mon** — `internal/api/handlers/handlers.go:250` · class: `security` · related: `cmd/api/main.go`

**Defect.** GetHealth registered with no auth (main.go:657-658); on DB failure health["db_error"]=err.Error() returned verbatim in a 503 body.

**Failure scenario.** During a Postgres outage an anonymous caller gets the raw pgx/GORM error embedding host=rust-01 user=fwmon database=fwmon and the internal IP — infra topology disclosure exactly when degraded. Health should expose only a boolean.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-193 · MEDIUM · GetAlerts/GetSyslogMessages/GetDeviceConfigHistory ignore the COUNT query error — pager total silently 0 alongside a populated page

> **✅ RESOLVED (v0.11.219 · PR #227)** — paginated alert/syslog/config-history listings no longer show 0 results alongside visible rows when the count query fails.

**Firewall-Mon** — `internal/api/handlers/handlers_analytics.go:134` · class: `correctness` · related: `internal/api/handlers/handlers_devices.go`

**Defect.** applyAlertFilters(...).Count(&total) discards .Error, unlike the Find above it; same at GetSyslogMessages:460 and handlers_devices.go:968.

**Failure scenario.** A transient count failure (statement_timeout on partitioned syslog, or 22P02) returns 200 with a full page but total:0 → UI shows '0 results'/disables paging with rows visible, no log to correlate.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-194 · MEDIUM · public_interfaces whitelist is enforced only client-side; raw /api/public/interfaces[/chart] leaks every interface of a public device

> **✅ RESOLVED (v0.11.215 · PR #223)** — the public_interfaces allowlist is now enforced server-side on the public paths.

**Firewall-Mon** — `internal/api/handlers/handlers_dashboard.go:171` · class: `security` · related: `cmd/api/static/js/public-dashboard.js`, `internal/api/handlers/handlers_settings.go`

**Defect.** GetPublicInterfaces returns the full []InterfaceStats and GetPublicInterfaceChart serves history for ANY index with no reference to public_interfaces; the narrowing is only in public-dashboard.js. GetPublicVPN/GetPublicConnections enforce their toggle server-side with a comment noting the SPA hides but the endpoint would dump. InterfaceStats carries Name/Alias/Description/MAC/VLAN/Speed/counters.

**Failure scenario.** An operator sets public_interfaces to expose only wan1; an anon caller GETs /api/public/interfaces?device_id=1 and receives every interface (internal LAN/DMZ names, MACs, VLANs, counters), and /chart for any non-whitelisted index — bypassing the explicit narrowing.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-195 · MEDIUM · public_interfaces allowlist enforced only client-side; /api/public/interfaces leaks all non-allowlisted interfaces unauthenticated

> **✅ RESOLVED (v0.11.215 · PR #223)** — same fix as AUDIT-194 — public_interfaces allowlist enforced server-side (empty list means show-all).

**Firewall-Mon** — `internal/api/handlers/handlers_dashboard.go:195` · class: `security` · related: `cmd/api/static/js/public-dashboard.js`, `internal/api/handlers/handlers_settings.go`, `cmd/api/main.go`

**Defect.** GetPublicInterfaces returns every interface for a public-visible device with no per-interface filter (`Where("device_id=? AND timestamp=?").Find(&ifaces)` → full InterfaceStats incl. Name, MACAddress, Description, Alias, VLANID, counters). The public_interfaces allowlist is applied ONLY client-side (public-dashboard.js:138-141). GetPublicVPN (420) and GetPublicConnections (462) DO enforce their toggles server-side with a comment noting the SPA only hides the widget. Routes are in the unauthenticated /public group (main.go:667-668).

**Failure scenario.** Operator marks a device public_visible but sets public_interfaces to expose only the WAN graph. An anonymous user requests GET /api/public/interfaces?device_id=<id> (or the chart variant) and receives names, MACs, descriptions/aliases, VLAN IDs and counters for ALL interfaces — leaking internal LAN/DMZ/MGMT segmentation and per-segment traffic volume the operator curated out. Fix: enforce the allowlist server-side like VPN/connections.

**Fix direction.** enforce the allowlist server-side like VPN/connections.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-196 · MEDIUM · Probe flow/telemetry ingest decodes the entire JSON array before the item cap, and truncateProbeBatch reslices (not copies) so the full decode allocation stays live — a 5MB body of empty objects amplifies to ~670MB-1GB per authed request, giving the 1000-item cap false safety

> **✅ RESOLVED (v0.11.218 · PR #226)** — probe telemetry ingest now caps the JSON decode, not just the saved slice.

**Firewall-Mon** — `internal/api/handlers/handlers_data.go:317` · class: `input-hardening` · related: `internal/api/middleware/middleware.go`, `cmd/api/main.go`, `internal/models`

**Defect.** Confirmed by reading handlers_data.go:305-321 and :68-74. ReceiveFlowSamples calls `c.ShouldBindJSON(&samples)` (full-array json.Decoder decode, no per-element/count limit) BEFORE truncateProbeBatch, and truncateProbeBatch applies `items = items[:capN]` — a reslice, NOT a copy — so the full backing array is retained through SaveFlowSamples. The only real bound is the global 5MB body cap (cmd/api/main.go:590 BodySizeLimitPerPath, MaxBytesReader), so 'no MaxBytesReader' is disproven, but the amplification is huge: FlowSample ≈400B; smallest legal element `{},` = 3 bytes ⇒ 5<<20/3 ≈ 1.68M elements × 400B ≈ 670MB final backing array, ~1GB transient during slice-growth doubling. truncateProbeBatch reslices to 1000 but the giant array stays referenced until the handler returns. SystemStatus/InterfaceStats/SyslogMessage share the identical post-decode-cap pattern.

**Failure scenario.** An attacker holding one valid/leaked probe registration key POSTs ~1.68M empty objects (~5MB) to /api/probes/:id/flows. validateProbe passes, ShouldBindJSON allocates a ~670MB (peak ~1GB) backing array, truncateProbeBatch reslices to 1000 but the array is retained until the 200 response. ProbeRateLimiter is 30 req/s / burst 60 PER SOURCE IP, so one key reused across many source IPs has effectively no rate limit — ~60 concurrent decodes ≈ 40GB, OOM-killing the single-container fwmon-api that co-hosts Postgres on rust-01 (31GB RAM). The 1000-item cap implies a ~400KB ceiling but the effective per-request ceiling is ~700MB. Fix: enforce a decoded-count limit at decode time (Decoder token loop with a counter) or size the per-path body cap to capN × realistic element size.

**Fix direction.** enforce a decoded-count limit at decode time (Decoder token loop with a counter) or size the per-path body cap to capN × realistic element size.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-197 · MEDIUM · UpdateDevice validates probe_id reassignment but not site_id — invalid site_id hits the FK → opaque 500 rollback of the whole update

> **✅ RESOLVED (v0.11.219 · PR #227)** — device create/update validate site_id (non-existent site returns 400, not a silent orphan).

**Firewall-Mon** — `internal/api/handlers/handlers_devices.go:221` · class: `input-hardening` · related: `internal/api/handlers/handlers_probes.go`, `internal/models/models.go`

**Defect.** allowedFields includes site_id but validation covers only probe_id (with a comment naming the exact 'saved but reverted' failure); Device.SiteID carries the same belongs-to FK and CreateDevice also skips it. UpdateProbe validates site_id via GetSite.

**Failure scenario.** An update with a nonexistent site_id alongside other edits is rejected by the FK → 500 and ALL fields roll back, instead of the 400 'Site not found' UpdateProbe returns.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-198 · MEDIUM · Landing dashboard fans out GetProbeStats per probe every 30s — 4 unbounded COUNT(*) over partitioned firehose tables + 96-query breakdown, mostly discarded

> **⛔ REFUTED** — dead, unreachable code (the active dashboard reads the cached /api/dashboard/health composite; the legacy per-probe fetch path was removed in the v0.11.221 cleanup, not a live defect).

**Firewall-Mon** — `internal/api/handlers/handlers_probes.go:1204` · class: `performance` · related: `cmd/api/static/js/admin-main.js`

**Defect.** GetProbeStats runs 4 unbounded full-history COUNTs (syslog/trap/flow/ping) + 96-query 24h breakdown; admin-main.js:441-445 calls it per-probe on a 30s refresh and consumes only r.data.last_hour. GetProbesStatsBatch (AUDIT-064) exists and is used by admin-probes.js but not admin-main.js.

**Failure scenario.** Every admin landing-page refresh triggers N probes × (4 full-table COUNTs + 100 queries) serially every 30s per tab against prod's ~99M-row syslog_messages on spinning disk, for numbers the card never shows.

*Verification: 3/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-199 · MEDIUM · Setup2FA silently disables an already-enrolled 2FA with password only, bypassing the Disable2FA current-code requirement

> **✅ RESOLVED (v0.11.215 · PR #223)** — enrolled two-factor auth can no longer be silently downgraded with the password alone (409 re-auth guard).

**Firewall-Mon** — `internal/api/handlers/handlers_totp.go:174` · class: `security` · related: `internal/api/handlers/handlers_auth.go`, `internal/database/totp.go`

**Defect.** Setup2FA re-authenticates ONLY the password then unconditionally writes totp_enabled=false via `db.SetAdminTOTP(admin.ID, ..., false)` (totp.go:16-25 sets `totp_enabled: enabled`), overwriting an existing enabled=true row. No admin.TOTPEnabled guard exists in Setup2FA. This violates the invariant Disable2FA (264-266) enforces: stripping the second factor requires BOTH password AND a current code. Login reads live adminRecord.TOTPEnabled, so once false the second factor is never requested.

**Failure scenario.** An attacker holding a live admin session AND the password (exactly what 2FA exists to survive) but NOT the TOTP device calls POST /admin/api/2fa/setup with just the password. Server sets totp_enabled=false and installs a new unconfirmed secret; attacker never completes Verify2FA. The account is downgraded to password-only on the next login, defeating the second-factor gate. Fix: reject Setup2FA when admin.TOTPEnabled is already true, or stage the new secret in a pending column.

**Fix direction.** reject Setup2FA when admin.TOTPEnabled is already true, or stage the new secret in a pending column.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-200 · MEDIUM · OPNsense secret digesting is not newline-preserving; a multi-line secret body silently disables ALL diff masking and renders every secret in cleartext

> **✅ RESOLVED (v0.11.216 · PR #224)** — OPNsense config-diff secret masking is now newline-safe AND fail-closed.

**Firewall-Mon** — `internal/configdiff/vendor_opnsense.go:241` · class: `security` · related: `internal/configdiff/linediff.go`, `internal/configdiff/normalize.go`

**Defect.** fingerprintXMLElement drops newlines inside the match ([^<]/[^"] match \n in RE2), unlike the line-count-preserving maskXMLElementLines. prepareDiffInput then degrades masking to nothing globally when len(rawLines)!=len(maskLines), so lineHasSecret never fires.

**Failure scenario.** One secret element whose body spans a newline collapses lines → mask shorter than raw → the whole revision's mask is discarded → every PSK/bcrypt hash renders verbatim in the config-diff UI and all volatile patterns show as delta noise, silently. Fix: re-append one newline per consumed newline (or use [^<\n]*).

**Fix direction.** re-append one newline per consumed newline (or use [^<\n]*).

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-201 · MEDIUM · HasFlowData runs an unbounded COUNT(*) over the device pair's entire flow_samples history to derive a boolean

> **✅ RESOLVED (v0.11.221 · PR #229)** — connection-detail HasFlowData uses an indexed existence probe instead of scanning the pair's whole flow history.

**Firewall-Mon** — `internal/database/connection_detail.go:530` · class: `performance` · related: `internal/database/flows.go`

**Defect.** Model(FlowSample).Where(device_id IN ?).Limit(1).Count(&flowCount) (and twin at :755); GORM Count keeps LIMIT but it bounds the single result row, not the scan. No timestamp predicate → no partition pruning across all monthly partitions. Correct existence-probe shape (Select(1).Limit(1).Scan) exists at flows.go:817.

**Failure scenario.** Opening any connection detail walks every matching index entry across all flow_samples partitions for both devices — multi-second on untuned prod PG, approaching the 30s statement_timeout as volume grows → the endpoint 500s. Paid per page view.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-202 · MEDIUM · Leftover per-request debug logging in GetConnectionDetail prints every tunnel row on every connection-detail view

> **✅ RESOLVED (v0.11.221 · PR #229)** — removed leftover per-request debug logging that printed internal subnet topology on every connection-detail view.

**Firewall-Mon** — `internal/database/connection_detail.go:611` · class: `maintainability`

**Defect.** Unconditional log.Printf of source/dest tunnel counts plus one line per tunnel (name/local/remote) on a hot admin read path — no error condition, no rate limit.

**Failure scenario.** Every connection-detail load emits 1+N_src+N_dst lines; a hub with dozens of phase2s floods the container log with internal subnet topology, burying rare warnings.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-203 · MEDIUM · Rollup/summary batch inserters silently discard time.Parse errors on the bucket string, writing zero-value timestamps that retention then deletes

> **✅ RESOLVED (v0.11.214 · PR #222)** — aggregation batch inserters now return time.Parse errors (tx rollback preserves raw rows) instead of swallowing them.

**Firewall-Mon** — `internal/database/flows.go:717` · class: `data-integrity` · related: `internal/database/syslog_agg.go`, `internal/database/charts.go`, `internal/database/dialect.go`

**Defect.** ts,_:=time.Parse(bucketFmt,r.Bucket) in batchInsertRollups and syslog_agg.go:218; a format mismatch yields year-0001 silently. AUDIT-145 fixed the same silent-zero on the READ path (charts.go) but the WRITE path still swallows it.

**Failure scenario.** A future TimeBucket format change (or the SQLite '5min' branch) makes Parse fail: rollup rows commit with Timestamp 0001-01-01 in the same tx that deletes the raw rows, then get deleted by retention — aggregated history vanishes with no log. One err!=nil returning rolls back and preserves raw rows.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-204 · MEDIUM · Flow-rollup and syslog-aggregation cycles cannot recover from a large backlog: paged GROUP BY aggregates the whole backlog per page under statement_timeout, wedging the pipeline while cleanup deletes never-summarized rows

> **✅ RESOLVED (v0.11.214 · PR #222)** — flow-rollup and syslog-aggregation passes now time-slice-chunk their GROUP BY so backlogs can actually be cleared.

**Firewall-Mon** — `internal/database/syslog_agg.go:159` · class: `performance` · related: `internal/database/flows.go`, `internal/database/cleanup.go`, `internal/database/database.go`, `internal/config/config.go`

**Defect.** LIMIT/OFFSET over a GROUP BY (also flows.go:845,957) forces full aggregation before any page; the per-connection 30s statement_timeout is never lifted (unlike migrateSyslogSeverityIndex's SET LOCAL statement_timeout=0). The file documents a 92M-row backlog that accumulated on prod.

**Failure scenario.** After any sustained failure window the first page's GROUP BY over the whole backlog exceeds 30s → 57014 rollback → retried identically every 5 min forever while CleanupOldData deletes severity 6-7 raw rows regardless of aggregation → permanent silent data loss. Fix: chunk by time slice or lift statement_timeout locally.

**Fix direction.** chunk by time slice or lift statement_timeout locally.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-205 · MEDIUM · Disabled IRC server gets auto-connected by the reconnect sweep after any channel edit

> **✅ RESOLVED (v0.11.223 · PR #231)** — a disabled IRC server is no longer auto-connected by the reconnect sweep after a channel edit.

**Firewall-Mon** — `internal/irc/bot.go:100` · class: `correctness` · related: `internal/api/handlers/handlers_irc.go`

**Defect.** reconnectDue never checks Server.Enabled — returns `AutoReconnect && Conn==nil && now.After(nextAttempt)`. RestartBot stores a fresh bot (with an OPEN quit channel) into m.bots even when disabled, skipping only Start(). CreateIRCChannel/UpdateIRCChannel/DeleteIRCChannel (handlers_irc.go:275,323,354) call RestartBot unconditionally; IRCServer.AutoReconnect defaults true (models.go:1950).

**Failure scenario.** Admin disables an IRC server (AutoReconnect left on, the default) then edits/creates/deletes any channel → RestartBot places a fresh bot (open quit, AutoReconnect=true, Conn=nil, not Started) in m.bots. Within 30s the reconnect sweep evaluates reconnectDue=true, spawns Start() whose open-quit check passes → the DISABLED server connects, joins channels, sends status boxes. The disable control is silently defeated.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-206 · MEDIUM · Bot.Stop racing an in-flight Bot.Start leaks a ghost IRC connection — Start never re-checks b.quit after Connect, and Connect() discards the queued QUIT

> **✅ RESOLVED (v0.11.223 · PR #231)** — a Bot.Stop racing an in-flight Bot.Start no longer leaks a live unowned IRC session.

**Firewall-Mon** — `internal/irc/bot.go:532` · class: `concurrency`

**Defect.** Start unlocks b.mu before conn.Connect and never re-checks b.quit afterwards; Stop's QUIT goes into the pre-Connect nil pwrite (parks/leaks) and is discarded when Connect recreates the channel. Connect succeeds, onConnected sees b.Conn==nil and bails, watcher blocks on ErrorChan forever → live registered session with no owner.

**Failure scenario.** Admin Restart/Disable (or the 30s reconnect sweep) while Start is mid-dial to a slow server leaves a zombie connection squatting the nick; the replacement collides (433) → nick_. Fix: re-check b.quit under b.mu after Connect and Disconnect.

**Fix direction.** re-check b.quit under b.mu after Connect and Disconnect.

*Verification: 3/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-207 · MEDIUM · AUDIT-117 table-name uniqueness guard has eroded: 20 of 69 TableName() models are missing from allTablers, with no completeness check

> **✅ RESOLVED (v0.11.226 · PR #234)** — the model TableName() guard is now self-maintaining and covers every model.

**Firewall-Mon** — `internal/models/models_test.go:24` · class: `test-gap` · related: `internal/models/models.go`

**Defect.** 69 TableName() methods vs 49 in allTablers(); 20 newer models (ServerMetric, EventRule, Incident, ApiToken, IPSecTunnel, ThreatIntel, AgentDrops, ...) never added; no reflection/count cross-check makes the list self-verifying.

**Failure scenario.** A future model whose TableName() collides with an existing table passes go test green; the collision surfaces only as AutoMigrate mangling schemas at runtime — the exact corruption this guard exists to prevent, now unguarded for 29% of models.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-208 · MEDIUM · Opsgenie close URL embeds the un-escaped alias — a '/' or space in MetricName (Cisco ASA interface names) breaks auto-resolve, incidents never close

> **✅ RESOLVED (v0.11.217 · PR #225)** — Opsgenie close-by-alias now encodes the dedup key so incidents for slashed interface names auto-close.

**Firewall-Mon** — `internal/notifier/incident_channels.go:132` · class: `input-hardening` · related: `internal/alerts/alerts.go`

**Defect.** close URL interpolates alertDedupKey(alert) (contains alert.MetricName like interface_GigabitEthernet0/0) with no neturl.PathEscape; cisco_asa iface names always contain slashes. Trigger side is unaffected (alias in JSON body); PagerDuty immune.

**Failure scenario.** INTERFACE_DOWN for GigabitEthernet0/0 opens an Opsgenie incident; on recovery the close URL path is mangled → 404, incident never closes, on-call keeps a stale page; a tunnel name with a space makes NewRequest fail outright.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-209 · MEDIUM · Plain-text alert email sends the comma-joined recipient list as a single RCPT — all alert emails fail for multi-recipient policies

> **✅ RESOLVED (v0.11.217 · PR #225)** — multi-recipient alert emails now deliver to every recipient (smtp_to split into envelope recipients).

**Firewall-Mon** — `internal/notifier/notifier.go:370` · class: `correctness` · related: `internal/alerts/policy.go`, `internal/alerts/escalation_steps.go`, `web/admin/admin.html`

**Defect.** sendEmail passes []string{nc.SMTPTo} (raw comma string) as one envelope recipient; SMTPTo comes from AlertPolicy.EmailRecipients / EscalationStep.Recipients and the UI placeholder invites a comma list. The HTML/report path splits on ',' correctly; sendEmail does not → client.Rcpt("a@x, b@y").

**Failure scenario.** Two comma-separated addresses in a policy → every alert email fails at RCPT TO (501/553), neither recipient paged, every cycle, while HTML reports to the same list deliver — masking it. Error only logged.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-210 · MEDIUM · Collector queue drop/depth/batch metrics are registered as the primary silent-data-loss signal but never fed — permanently zero even during real disk-spillover drops

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — the queue drop/depth/data-batch Prometheus metrics are now actually fed from the live spillover queues.

**Firewall-Collector** — `internal/observability/metrics.go:344` · class: `contract-drift` · related: `internal/relay/queue/queue.go`, `internal/relay/relay.go`, `cmd/collector/main.go`

**Defect.** IncQueueDropped (metrics.go:344), OnDataBatchSent (:331), SetQueueDepth/SetQueueDepthSource (:304) are defined but have NO production callers — verified: grep across the repo returns only the definitions plus internal/observability/observability_test.go. The registered series carry Help text promising alerting: firewall_collector_queue_dropped_total = 'Non-zero values mean silent data loss — investigate immediately.' (:205-208). The real drop counter lives in the spillover queue (internal/relay/queue/queue.go:296/309 do q.dropped++ on disk-cap eviction) and exposes purpose-built Depth()/Dropped() accessors (queue.go:380/438) that are never wired to SetQueueDepthSource. refreshDynamic() only refreshes queue_depth when queueDepthSource != nil, which is always nil in prod. The Send* drop sites in relay.go only log.Printf on enqueue failure and touch no metric.

**Failure scenario.** During a prolonged central-server outage the disk-spillover queue hits PROBE_QUEUE_*_MAX_BYTES and evicts oldest telemetry (real silent data loss). The Prometheus alert the metric's own Help text invites — rate(firewall_collector_queue_dropped_total[5m]) > 0 — never fires because IncQueueDropped is never called, and the queue_depth dashboard reads a flat 0 throughout the backlog. The one metrics surface built to expose data loss reports all-clear while data is being dropped.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-211 · MEDIUM · Server internal/relay DTOs (the declared cross-repo wire-contract source of truth) have drifted from the actual v1-v5 wire: whole Tranche-3 field set missing, phantom fields retained, wrong Drops semantics, missing v5 structs

> **✅ RESOLVED (v0.11.230 · PR #238)** — relay DTO synced across the repo contract.

**cross-repo** — `internal/relay/relay.go:85` · class: `docs-drift` · related: `internal/api/handlers/handlers_data.go`, `internal/models/models.go`, `internal/api/handlers/handlers_probes.go`

**Defect.** The package doc declares itself the MIGRATING.md/SUPPORT-MATRIX source of truth, but server relay.FlowSample omits flow_source, app_name, as_path, next_hop, flow_start/end, firewall_event, flow_end_reason, the 4 post-NAT fields, icmp_type_code, src_vlan/dst_vlan while keeping sample_pool/sample_algorithm/engine_id/type/src_mask/dst_mask the collector never sends; Drops comment says delta but collector corrected it to cumulative; ConfigRevision lacks trigger_source/backup_quality, DevicesResponse lacks tftp_server_ip, Heartbeat/RegistrationRequest agent_version drift; TopologyEntry/Neighbor structs referenced but absent.

**Failure scenario.** An engineer building/auditing against the advertised source of truth omits the entire NetFlow/IPFIX tranche or double-counts Drops, or wastes effort on engine_id fields the server ignores — the lockstep the file demands is honored for version consts but broken for DTOs.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-212 · MEDIUM · Heartbeat command executor runs on a bare `go` without panic recovery, and inFlight is cleared with a plain statement not defer — a panicking command crash-loops the collector via at-least-once redelivery

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — a panicking command handler no longer crash-loops the collector (safego wrap + inFlight cleanup + per-command recover).

**Firewall-Collector** — `internal/relay/relay.go:1295` · class: `concurrency` · related: `cmd/collector/commands.go`, `internal/safego/safego.go`

**Defect.** `go c.commandHandlerFn(hb.PendingCommands)` has no recover; safego package doc mandates safego.Go for lifetime goroutines and every other dispatch uses it. Secondary: handleOne sets e.inFlight[id]=true and clears it via a non-deferred statement (commands.go:257), so a recovered/contained panic leaves the CommandID wedged and every redelivery skipped.

**Failure scenario.** A command whose execution panics (malformed device REST response, nil-deref in fwapi) kills the whole collector — all polling/listeners stop; the crashed command is never reported (cache written only after return) and the server redelivers it on next heartbeat → crash loop until it expires (~15 min). Fix: safego.Go + deferred inFlight delete.

**Fix direction.** safego.Go + deferred inFlight delete.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-213 · MEDIUM · Requeue-then-rechunk breaks the M19 content-derived idempotency key — a committed-but-timed-out batch is re-inserted as duplicates

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — requeued batches replay under their original idempotency key (head-requeue; fixes AUDIT-213/214 together).

**Firewall-Collector** — `internal/relay/relay.go:1950` · class: `data-integrity`

**Defect.** contentBatchID is derived from the marshaled chunk, but chunk boundaries aren't stable: chunkSlice slices from index 0 while requeueItems pushes the failed chunk's items to the queue TAIL behind newly-arrived items. On the next sync [N new][requeued 1000] re-chunks at 1000 boundaries → the committed items get fresh hashes → server (probe_id,batch_id) dedup misses.

**Failure scenario.** Server commits a 1000-item flow batch but the response is lost; the chunk is requeued, 300 new samples arrive, next drain re-chunks and re-sends the committed items with new hashes → all 1000 rows inserted twice, skewing top-talker/bandwidth — the exact failure M19 closes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-214 · MEDIUM · Event-queue requeue regroups items into a new batch, changing the content-derived idempotency key and defeating server dedup (duplicate inserts)

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — same defect as AUDIT-213 — head-requeue gives byte-identical replay under the same contentBatchID.

**Firewall-Collector** — `internal/relay/relay.go:1978` · class: `correctness`

**Defect.** contentBatchID (936) is documented 'stable across send attempts, requeues, sync cycles' so the server's (probe_id, batch_id) dedup catches a committed-but-lost-response batch. That holds only for byte-identical replays (the metric path stores the exact marshaled body). The EVENT path re-pushes items individually via requeueItems `q.Push(data)` (1990); the next drain regroups them with newly-arrived items before re-marshaling, where `batchID := contentBatchID(jsonData)` (2108) is computed over the whole chunk. Low confidence.

**Failure scenario.** Collector POSTs a batch A,B,C; server commits but the response is lost (transport error) → transient → requeueItems pushes items back; new samples interleave before the next sync; the re-drain produces chunk A,B,C,D,E hashing to a fresh X-Probe-Batch-ID the server has never seen → content-key dedup misses → previously-committed rows re-inserted (skewed flow byte/delta math) — the exact double-count contentBatchID was introduced to prevent, fixed only for the metric path.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-215 · MEDIUM · Alert-frequency timeline is UTC-locked, ignoring report_timezone while every other report chart localizes

> **✅ RESOLVED (v0.11.226 · PR #234)** — the Alert Activity timeline now honors report_timezone and is deterministically clocked (no internal time.Now()).

**Firewall-Mon** — `internal/report/template_report.go:264` · class: `correctness` · related: `internal/report/model.go`, `internal/report/svg_charts.go`, `internal/report/png_charts.go`

**Defect.** The alert timeline is rendered without a timezone argument: template_report.go:264 `{{renderAlertChart .AlertBuckets $t}}` — vs device charts on the same template that DO pass tz (line 483 renderCPUMemChart $d $d.Timezone $t; 489 renderThroughputChart). The timeline's axis text comes from AlertBucket.Label/Tooltip, pre-baked in the SERVER's local zone by model.go bucketAlerts (521 now:=time.Now(); 552 t:=start.Add(...); 558 label=t.Format("15:04"); 566 tooltip t.Format("Jan 2, 15:04")) with no .In(loc). Both render paths inherit it: svg_charts.go:35 RenderAlertTimelineSVG and png_charts.go:116 RenderAlertTimelinePNG take no tz, and the PNG hardcodes png_charts.go:186 Timezone:"UTC" while the CPU/mem PNG uses pngTimeFormatter(card.Timezone).

**Failure scenario.** Operator sets report_timezone = America/New_York. The header and the CPU/Mem and throughput charts label ET, but the Alert Activity timeline bars/tooltips are labeled in the server's zone (UTC in prod) — a 4-5h offset. A 14:00 ET alert spike appears at 19:00 on the alert timeline while the device charts show 14:00, so two charts in the same email disagree about when the incident happened. Only manifests when report_timezone differs from the container zone.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-216 · MEDIUM · Collector unrecognized-trap path logs one line per varbind (unbounded) — a crafted trap is a log-volume/disk-fill amplification the server twin does not have

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — capped the unrecognized-trap varbind log dump (16 lines + summary) to stop log-flood amplification.

**Firewall-Collector** — `internal/snmp/trap.go:177` · class: `input-hardening`

**Defect.** Verified parseTrap's fall-through for an unrecognized trap (trapOID=='' AND no varbind matches the vendor registry) logs one line for EVERY varbind with no cap: `log.Printf("[SNMP Trap] Unrecognized trap from %s, varbinds:", addr.IP)` then `for _, v := range packet.Variables { log.Printf("[SNMP Trap] OID=%s Type=%d", v.Name, v.Type) }` (trap.go:176-180). The Firewall-Mon twin instead returns nil silently for an unrecognized trap (Firewall-Mon internal/snmp/trap.go `if trap.TrapOID == "" { ... return nil }`, no per-varbind logging). PROBE_TRAP_RATE_LIMIT_PPS (default 500) caps traps/sec/source but places NO bound on log lines per trap; PROBE_SNMP_TRAP_COMMUNITY is an optional allowlist (empty ⇒ allowCommunity returns true), listener binds 0.0.0.0:162, so the path is reachable unauthenticated by default.

**Failure scenario.** An attacker who can reach UDP/162 crafts a v2c trap that omits snmpTrapOID.0 and packs thousands of junk-OID varbinds into a single ~64KB datagram. Each datagram emits thousands of log lines; sustained at the 500 traps/sec/source ceiling this is millions of log lines/sec, filling the collector host disk — the same disk-fill outage class the project has hit before — while the server twin would discard each trap with zero log output.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-217 · MEDIUM · FortiGate dialup columns .7/.8 mapped as DstBegin/DstEnd, but fgVpnDialUpTable has DstAddr(.7)/Vdom(.8) — dialup RemoteSubnet always collapses to a /32

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — dialup VPN remote subnet no longer derives from mis-parsing the vdom column (.7 is the destination address).

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:61` · class: `correctness`

**Defect.** fgOIDVPNDialupDstBegin/End=...1.1.7/.8 but the MIB entry is {...,DstAddr(7),Vdom(8),InOctets(9),OutOctets(10)} — no dst begin/end pair. Column .8 (Vdom Integer32) → safeString(int) returns '' → rangeToCIDR hits the end=='' branch → begin+"/32". The .3=Lifetime and .9/.10 choices confirm the layout.

**Failure scenario.** A hub FortiGate with a dialup spoke advertising 192.168.50.0/24 emits remote_subnet '192.168.50.0/32' → a single-host claim for a whole subnet, feeding wrong data into VPN views and IPSec selective-subnet canonical keys.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-218 · MEDIUM · Test gap: FortiGate — the production default vendor — has zero parser tests beyond one hardware-sensor regression

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — added FortiGate parser fixture tests for the production-default vendor profile.

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:882` · class: `test-gap`

**Defect.** Only TestFortiGate_ParseHardwareSensors_DisplayStringValue exists; ParseSystemStatus/VPNStatus/DialupVPNStatus/rangeToCIDR/SSLVPNTunnels/HAStatus/SecurityStats/SDWANHealth/LicenseInfo (~700 lines) uncovered while cisco_asa/generic/opnsense have fixture tests. The SD-WAN/SSL-VPN/dialup/packet-loss defects all live in these untested functions.

**Failure scenario.** Any future OID/parse regression in the default profile (resolveVendor maps empty→fortigate) ships undetected because parse output is never asserted; paloalto/sonicwall parsers have no tests at all.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-219 · MEDIUM · SD-WAN packet-loss computed as uint64 subtraction PacketSend-PacketRecv — underflows to ~1.8e19 when Recv>Send from counter timing skew

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — SD-WAN packet loss now reads the device's own computed column with a guarded subtraction fallback.

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:945` · class: `data-integrity`

**Defect.** lost := h.PacketSend - h.PacketRecv on two uint64 read from different table columns (send column walked before recv); a probe answered between reads yields Recv>Send and the unsigned subtraction wraps. MIB provides device-computed fgVWLHealthCheckLinkPacketLoss (...4.9.2.1.9).

**Failure scenario.** Recv exceeds Send by 1 from walk skew → lost=2^64-1 → PacketLoss≈1.8e21% stored and shipped, poisoning the SD-WAN card and any future loss alerting. Latent only because the OID bug keeps both counters 0; fixing that arms this.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-220 · MEDIUM · Uptime unit contract drift: 7-8 non-FortiGate vendor profiles pre-divide sysUpTime by 100, but every server/frontend consumer divides by 100 again — non-FortiGate device uptime displayed 100x too small

> **✅ RESOLVED (v0.11.222 · PR #230 ; collector v1.3.40 · PR #104)** — device uptime unit fix across both repos: collector canonicalizes sysUpTime to raw hundredths and the server/device-detail formatters divide correctly.

**cross-repo** — `internal/snmp/vendor_opnsense.go:96` · class: `contract-drift`

**Defect.** opnsense/paloalto/cisco_asa/sonicwall/pfsense/firewalla/generic store ticks/100 (seconds) while fortigate stores raw hundredths; server uptime.go:203, admin-device-detail.js:2535, public-dashboard.js:346 all divide by 100 again (comment 'timeticks in hundredths'). FortiGate is the only unit the consumers were validated against.

**Failure scenario.** The live prod OPNsense box (or any non-FortiGate) with 100 days uptime displays '1d 0h' (86400/100); a 10-day uptime shows ~2.4h — silent plausible-wrong telemetry for every non-FortiGate vendor; no single-side fix is correct.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-221 · MEDIUM · Palo Alto VPN parser's 64-bit HC counter branches are dead code — GetVPNStatus walks only ifTable, so tunnel byte counters are always 32-bit and wrap at 4 GiB

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — Palo Alto VPN tunnel byte counters now use the 64-bit HC counters.

**Firewall-Collector** — `internal/snmp/vendor_paloalto.go:168` · class: `correctness`

**Defect.** VPNBaseOID returns BaseOIDInterface (ifTable) and snmp.go walks that subtree; the OIDIfHCInOctets/OIDIfHCOutOctets branches test ifXTable OIDs outside the walk → never match. parseBSDVPNFromInterfaces (pfSense/OPNsense) and parseLinuxVPNFromInterfaces (Firewalla) share the 32-bit-only exposure.

**Failure scenario.** A PAN-OS tunnel.N at 100 Mbps wraps ifInOctets every ~5.7 min; with 60s polls the delta pipeline misreads each wrap as a reset and discards/clamps → VPN throughput systematically under-reported on busy tunnels. Fix: walk ifXTable for the VPN base.

**Fix direction.** walk ifXTable for the VPN base.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-222 · MEDIUM · ParseInterfaceList can never parse TX errors/discards — outer gate requires 'rx', making the tx branch unreachable; combined rx/tx lines overwrite RX

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — SSH TX interface error/discard counters are now parseable (the rx-only line gate is fixed).

**Firewall-Collector** — `internal/ssh/parser.go:213` · class: `correctness`

**Defect.** The block is gated on line containing 'rx', so the inner `else if Contains(line,"tx")` assigning currentOutErrors/Discards is dead and a TX-only line never enters; a line with both groups funnels both matches into In* fields (TX overwrites RX). Tests assert only .Name.

**Failure scenario.** Every SSH interface-error poll ships iface.OutErrors/OutDiscards=0 → TX-side errors (duplex mismatch, congested egress, failing SFP) invisible and never alert; combined-format lines corrupt RX values too. Close the test gap alongside the fix.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-223 · MEDIUM · extractDeviceID compiles a regexp on every syslog message with structured data

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — interface packet counters now use the 64-bit HC ucast counters.

**Firewall-Collector** — `internal/syslog/syslog.go:615` · class: `performance`

**Defect.** regexp.MustCompile(`\[(\d+)\]`) inside extractDeviceID, called per non-FortiOS RFC5424 message with non-empty structured data — the only non-hoisted regex in a package whose own comment cites >1000/sec.

**Failure scenario.** Any standards-compliant RFC5424 source with structured data forces a MustCompile per message → measurable CPU recompiling a constant. Hoist to a package var.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

### LOW (85)

#### AUDIT-224 · LOW · No gosec job in collector CI, though the collector parses the most hostile input in the system and the server enforces gosec

> **✅ RESOLVED (collector v1.3.35 · PR #99)** — added a gosec CI gate to the collector.

**Firewall-Collector** — `.github/workflows/docker.yml:10` · class: `toolchain-ci`

**Defect.** The only workflow runs gofmt/vet/test-race/tidy/staticcheck/govulncheck — no gosec; server enforces gosec@v2.27.1. The collector packages parsing unauthenticated UDP (syslog/sflow/tftp/netflow/snmp) + ssh command construction are never security-scanned, contradicting the Dockerfile's own threat model.

**Failure scenario.** A G-class defect (e.g. G304 traversal from a tainted TFTP filename, or math/rand for a security token) merges with no machine gate; the same bug in the server repo would be caught. Highest-cost location — remote customer management LANs.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-225 · LOW · Collector CHANGELOG.md is missing the v1.3.30 and v1.3.31 entries — history jumps 1.3.32 to 1.3.29

> **✅ RESOLVED (collector v1.3.42 · PR #106)** — restored the missing 1.3.30 and 1.3.31 CHANGELOG entries.

**Firewall-Collector** — `CHANGELOG.md:28` · class: `docs-drift` · related: `CONTRIBUTING.md`

**Defect.** Headings run 1.3.33, 1.3.32, then 1.3.29 — no 1.3.30/1.3.31, though commits 0907817 (IPSec telemetry + phase2 selectors v1.3.30) and 1fd311a (agent version report v1.3.31) are on master.

**Failure scenario.** An operator on 1.3.29 evaluating 1.3.32 sees no record that the collector now sends IPSec telemetry and reports its agent version (new outbound behavior some sites must clear); changelog-derived release notes omit two shipped wire changes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-226 · LOW · Collector Docker build lacks the server's AUDIT-102 reproducibility flags (-trimpath -buildvcs=false)

> **✅ RESOLVED (collector v1.3.35 · PR #99)** — reproducible Docker builds via -trimpath -buildvcs=false (server parity).

**Firewall-Collector** — `Dockerfile:12` · class: `toolchain-ci`

**Defect.** Collector `go build -o firewall-collector ./cmd/collector` omits -trimpath -buildvcs=false; server Dockerfile adds both (AUDIT-102: byte-identical binaries across build hosts).

**Failure scenario.** The shipped collector binary embeds build/module-cache paths and VCS stamping, so the same source yields different bytes per host — an operator can't verify by rebuild-and-compare that a binary on a customer LAN matches the tagged source.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-227 · LOW · `make qa` claims 'same as CI' but omits staticcheck/gosec/govulncheck and -race

> **✅ RESOLVED (v0.11.231 · PR #239)** — make qa now runs every go-native CI gate (staticcheck, gosec, govulncheck, -race).

**Firewall-Mon** — `Makefile:27` · class: `docs-drift`

**Defect.** qa target = tidy-check fmt-check vet build test; CI additionally gates staticcheck, gosec, govulncheck and runs tests with -race. test-race/vuln targets exist but aren't in qa; staticcheck has no target.

**Failure scenario.** A contributor runs `make qa`, gets 'QA OK', pushes → CI fails ~8 min later on an SA-class finding or a race the local -race-less run missed. Nothing vulnerable ships; cost is burned cycles + misleading local green.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-228 · LOW · Server README version/toolchain facts are stale: badge 0.10.553 and 'Go 1.25.11 pinned in go.mod' vs actual 0.11.209 / go 1.25.13

> **✅ RESOLVED (v0.11.231 · PR #239)** — corrected README version/Go-toolchain drift and added anti-drift guardrail tests.

**Firewall-Mon** — `README.md:281` · class: `docs-drift`

**Defect.** README.md:281 says 'Go 1.25.11 (the version pinned in go.mod)' but go.mod:3 is `go 1.25.13`. README.md:13 badge version-0.10.553 and :83 'current 0.10.x release' but cmd/api/main.go:40 ServerVersion='0.11.209' and CHANGELOG top is [0.11.209]. The whole README Features/Upgrading narrative (pin to :0.10.x) is one minor behind.

**Failure scenario.** A contributor installs exactly Go 1.25.11 as the 'pinned' version; `go build ./...` then fails because go.mod's `go 1.25.13` directive requires 1.25.13+. A user files a bug reporting version 0.10.553 from the badge while running a 0.11.x binary, misdirecting triage.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-229 · LOW · Stale /admin/network route renders deleted network.html template → blank/broken page

> **✅ RESOLVED (v0.11.224 · PR #232)** — removed the dead /admin/network route.

**Firewall-Mon** — `cmd/api/main.go:918` · class: `contract-drift` · related: `internal/api/middleware/middleware.go`

**Defect.** `admin.GET("/network", func(c){ middleware.RenderHTML(c, 200, "network.html", nil) })` references a template that no longer exists (find web -name '*.html' lists only admin/login/device-detail/connection-detail/index). Commit ca301f2 'remove duplicate /network page' deleted network.html but left the route. In gin v1.12.0, ExecuteTemplate on an undefined name errors after `c.Status(200)`, flushing HTTP 200 with an empty body.

**Failure scenario.** An admin navigates to (or a bookmark hits) /admin/network → gin fails to resolve the deleted template and returns a blank HTTP 200 instead of a real view; the orphaned route is dead/broken and should be removed with the template.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-230 · LOW · Tunnel-group bandwidth charts silently reset display mode (Combined/Transfer) to Throughput on every 30s auto-refresh; the sibling traffic chart is immune

> **✅ RESOLVED (v0.11.224 · PR #232)** — connection-detail tunnel charts keep the operator's Combined/Transfer selection across auto-refresh.

**Firewall-Mon** — `cmd/api/static/js/admin-connection-detail.js:412` · class: `frontend-state` · related: `cmd/api/static/js/admin-bw-chart.js`

**Defect.** FwmonBwChart.mount persists the chosen mode (rate/total/mix) ONLY in the DOM, recovering it on re-mount by reading `box.previousElementSibling` for a `.fwmon-bw-toggle` (admin-bw-chart.js:267-273,296). renderTunnelCharts rebuilds the whole per-group wrap wholesale every poll via `host.innerHTML = html` (admin-connection-detail.js:412), where html contains `.range-pills` but NO toggle, then re-mounts (413-416). After the wipe mount's prev sibling is `.range-pills` (not `.fwmon-bw-toggle`), so toggle===null and view falls back to `opts.initialView || 'rate'`; loadGroupChart passes no initialView (line 461). renderTunnelCharts is called from loadConnectionDetail (336-337) which the 30s visibility-gated auto-refresh runs unconditionally (AC.pollWhenVisible, 819-837). The traffic chart is immune because its toggle lives outside the wiped node (#traffic-chart-host, 561/571), proving the asymmetry is the container rebuild.

**Failure scenario.** Operator on a connection-detail IPsec-tunnel page expands a tunnel-group chart and clicks 'Combined' or 'Transfer' to read bytes-per-bucket. Within 30s the auto-refresh fires renderTunnelCharts, `host.innerHTML = html` destroys the inserted toggle, the immediate re-mount finds no surviving toggle and defaults view to 'rate', and the chart snaps back to Throughput. The selection is unrecoverable and resets every poll, making Transfer/Combined effectively unusable on tunnel charts while the same page's traffic chart keeps its mode.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-231 · LOW · Device-detail formatVpnUptime divides tunnel_uptime by 100 — missed in the shared-helper conversion, renders OPNsense tunnel uptime 100x too small

> **✅ RESOLVED (v0.11.222 · PR #230)** — OPNsense tunnel uptime no longer renders as 0m on device detail.

**Firewall-Mon** — `cmd/api/static/js/admin-device-detail.js:2508` · class: `contract-drift` · related: `cmd/api/static/js/admin-common.js`, `cmd/api/static/js/admin-connection-detail.js`, `cmd/api/static/js/diagram-panels.js`

**Defect.** Local formatVpnUptime(hundredths){ secs=Math.floor(hundredths/100) } called for v.tunnel_uptime, but the canonical AC.formatTunnelUptime treats tunnel_uptime as SECONDS (comment: 'one divided by 100, rendering a 53-minute tunnel as 0m'); connection-detail and diagram-panels were converted, device-detail's renderVPN wasn't (also bypasses tunnelStateBadge/tunnelCountersObserved).

**Failure scenario.** On the VPN tab an OPNsense tunnel up 53 min (the one monotonic vendor) shows '0m' while connection-detail and the map show it correctly; config-sourced FortiGate rows show '0 B' and a raw 'unknown' badge.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-232 · LOW · Deploy modal polls the previous deploy record before the POST — redeploy of a rolled-back tunnel flashes a stale 'Deploy failed' banner

> **✅ RESOLVED (v0.11.224 · PR #232)** — a fresh IPSec deploy/rollback/recheck no longer flashes the previous deploy's failure banner or double-polls.

**Firewall-Mon** — `cmd/api/static/js/admin-ipsec.js:1918` · class: `frontend-state`

**Defect.** openDeployModal starts pollDeploy unconditionally at the end; startDeploy calls openDeployModal('deploy') BEFORE the POST and starts a second poll with the same generation. The first GET returns the prior deploy record; for a rolled-back tunnel deployTerminal('rolled_back') is true → renderDeployBody shows the failure banner.

**Failure scenario.** Redeploying a tunnel whose previous deploy auto-rolled back (an allowed recovery flow) opens the modal showing the OLD 'Deploy failed — rolled back' banner + Acknowledge, then flips to 'Deploying…' once the POST returns; on a slow POST the operator can Acknowledge and close mid-launch.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-233 · LOW · Threat-intel feed toggles throw ReferenceError on undeclared `AC`, killing the post-toggle refresh

> **✅ RESOLVED (v0.11.224 · PR #232)** — threat-intel feed toggles show their success toast and refresh the table (bare AC.showToast fixed).

**Firewall-Mon** — `cmd/api/static/js/admin-threatintel.js:176` · class: `frontend-state` · related: `internal/api/handlers/handlers_flow_control.go`

**Defect.** Strict-mode module with no module-scoped AC (only function-local in api()/renderSearch()); onMasterToggle/onFeedToggle/onStormSave reference bare `AC` in the .then, and the server always returns a non-empty note so `note && AC && ...` evaluates AC and throws before loadFeeds().

**Failure scenario.** Flipping the master switch or a per-feed Enable/Disable succeeds server-side but the callback throws ReferenceError before loadFeeds() → table never refreshes, no toast, per-feed button stays disabled; surfaces only as an unhandled rejection, stale until manual reload.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-234 · LOW · ReferenceError: bare `AC` in renderVPNTunnelRows crashes the VPN badge detail panel

> **✅ RESOLVED (v0.11.224 · PR #232)** — the rich VPN detail panel renders again (bare AC.formatTunnelUptime reference fixed).

**Firewall-Mon** — `cmd/api/static/js/diagram-panels.js:1380` · class: `correctness` · related: `cmd/api/static/js/admin-common.js`, `cmd/api/static/js/admin-main.js`

**Defect.** Line 1380 (strict-mode IIFE) uses `AC.formatTunnelUptime(...)` but `const AC = window.AdminCommon;` is declared only in four OTHER functions, never at module scope nor inside showRichVPNDetailPanel; no global AC exists.

**Failure scenario.** Opening the Connections map and clicking the VPN badge of any device with an UP tunnel evaluates the template literal → uncaught ReferenceError before panel.innerHTML is set → the panel never opens (error only in console). The rich VPN detail panel is dead for every real deployment.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-235 · LOW · Public dashboard 15m/30m range options silently broken: parseInt('0.25') → 0

> **✅ RESOLVED (v0.11.224 · PR #232)** — the public dashboard's 15m/30m ranges now show the correct window end to end.

**Firewall-Mon** — `cmd/api/static/js/public-dashboard.js:629` · class: `contract-drift` · related: `web/public/index.html`, `internal/httputil/httputil.go`, `internal/api/handlers/handlers_dashboard.go`

**Defect.** The range select offers value="0.25"/"0.5" but the handler does parseInt(e.target.value) → 0, which flows into /public/status-history?hours=0 (falls back to 24h) and /public/interfaces/chart?range=0 (falls back to 1h). connection-detail correctly uses parseFloat and the server accepts floats.

**Failure scenario.** Selecting 15m or 30m on the public wallboard shows 24h CPU/Mem and 1h bandwidth instead — the two shortest presets never work, no error. Fix: parseFloat.

**Fix direction.** parseFloat.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-236 · LOW · commands.go comments still claim IPSec writes are 'FortiGate only' while the code accepts OPNsense

> **✅ RESOLVED (collector v1.3.42 · PR #106)** — corrected stale FortiGate-only IPSec apply/remove comments in commands.go (OPNsense also accepted).

**Firewall-Collector** — `cmd/collector/commands.go:148` · class: `docs-drift`

**Defect.** runIPSecWrite/apply docstrings say 'FortiGate only; any other vendor is rejected' but the code allows `p.Vendor != "fortigate" && p.Vendor != "opnsense"`.

**Failure scenario.** A reviewer auditing the write allowlist for blast radius concludes OPNsense writes are impossible and misses that path when tightening vendor validation.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-237 · LOW · ifaceIPMap is never pruned on device-list refresh — stale IP→device attribution for reused/unassigned devices

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — added pruneIfaceIPMap (and the parallel device-keyed maps) on device-list refresh so a reassigned IP no longer resolves to a decommissioned device.

**Firewall-Collector** — `cmd/collector/main.go:2306` · class: `data-integrity`

**Defect.** cacheInterfaceAddresses only adds; deviceRefreshLoop prunes throughputCache/snmpARPFlags but nothing prunes ifaceIPMap, consulted by resolveDeviceByIP for every sFlow/NetFlow/syslog/trap. Sibling maps sshLastPoll/failCount/lastBackupAt/observedHostKeys share the gap.

**Failure scenario.** Device 42 decommissioned and its subnet IPs reused by new device 57: until the new device's first successful poll overwrites each entry, every datagram from a reused IP resolves to stale 42 and is relayed misattributed until collector restart.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-238 · LOW · PROBE_LOG_LEVEL / PROBE_LOG_FORMAT are inert in production — slog is never configured because main() never calls setupLoggerWith

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — VLAN PVIDs now attach to the correct interface via dot1dBasePortIfIndex resolution.

**Firewall-Collector** — `cmd/collector/main.go:2427` · class: `docs-drift`

**Defect.** setupLoggerWith (2427-2452) is the only code that reads PROBE_LOG_LEVEL/PROBE_LOG_FORMAT and calls slog.SetDefault; its only callers are slog_test.go — NEVER main(). main()'s sole logging setup is `log.SetFlags(...)` (204); no slog.SetDefault in production. Its signature takes *bytes.Buffer so prod can't even pass os.Stderr as its doc claims. Both vars are documented working knobs (docs/ENV-VARS.md:136-137, README.md:272,219-220).

**Failure scenario.** An operator sets PROBE_LOG_FORMAT=json (documented compose example) and/or PROBE_LOG_LEVEL=debug; because main() never invokes setupLoggerWith, slog keeps Go's zero-config default (text/Info/stderr): no JSON is ever emitted and debug output stays suppressed. Unit tests pass by calling setupLoggerWith directly, masking the gap.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-239 · LOW · Trap OctetString payload flows uncapped and unsanitized into process logs (CWE-117 log forgery) and the DB

> **✅ RESOLVED (v0.11.220 · PR #228)** — trap messages are length-capped and stripped of CR/LF and control characters at both producers.

**Firewall-Mon** — `cmd/trap-receiver/main.go:138` · class: `input-hardening` · related: `internal/snmp/trap.go`

**Defect.** log.Printf("Received trap: %s - %s ...", trap.TrapType, trap.Message, ...) with trap.Message built from the raw OctetString varbind (trap.go:398) with no length cap or control-char filter.

**Failure scenario.** Anyone knowing/sniffing the v2c community sends a trap whose OctetString contains a newline+fake FATAL line or ANSI escapes → forged log lines (CWE-117) polluting forensics; a ~60KB string stored verbatim per row. Fix: strip control chars and cap length in formatTrapMessage.

**Fix direction.** strip control chars and cap length in formatTrapMessage.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-240 · LOW · config.env.example (billed as the complete env inventory) is missing ~21 live env keys including PUBLIC_BASE_URL and the entire DDoS/deny-storm detector family

> **✅ RESOLVED (v0.11.231 · PR #239)** — config.env.example completed to a full inventory of the ~22 missing live keys.

**Firewall-Mon** — `config.env.example:381` · class: `docs-drift` · related: `internal/config/config.go`, `internal/models/models.go`, `README.md`

**Defect.** The file claims to be 'a complete inventory of every variable the code reads' and README calls it authoritative, but config.go reads PUBLIC_BASE_URL, SPIKE_MIN_THROUGHPUT_MBPS, RETENTION_DENIED_EVENT_DAYS, and the full DETECT_DDOS_*/DETECT_DENY_STORM_*/DETECT_DENIED_THEN_ALLOWED_*/DETECT_SAMPLING_RATE_CHANGE_* family — none present; AUDIT-107 guardrail only checks README keyword families.

**Failure scenario.** An operator can't discover PUBLIC_BASE_URL (alert deep-links silently never render) or the deny/DDoS tuning knobs from the reference; a completeness guardrail comparing config.go getEnv keys to the file would pin it.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-241 · LOW · Collector ENV-VARS.md ('authoritative reference') omits the live PROBE_NETFLOW_SAMPLING_OVERRIDES operator knob

> **✅ RESOLVED (collector v1.3.42 · PR #106)** — docs/ENV-VARS.md now documents PROBE_NETFLOW_SAMPLING_OVERRIDES.

**Firewall-Collector** — `docs/ENV-VARS.md:8` · class: `docs-drift`

**Defect.** ENV-VARS.md titles itself 'authoritative reference' and says 'Every variable on this page is wired [in config.go].' PROBE_NETFLOW_SAMPLING_OVERRIDES is a live knob absent from the page: config.go:184 `parseSamplingOverrides("PROBE_NETFLOW_SAMPLING_OVERRIDES")`, consumed in cmd/collector/main.go:606. It pins per-exporter NetFlow sampling rates.

**Failure scenario.** An operator whose NetFlow exporter advertises a wrong/zero sampling rate needs to override it, reads the 'authoritative' ENV-VARS.md, finds no such variable, and cannot correct the sampled-counter scaling without reading source — the documented-complete reference hides a shipped correctness knob.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-242 · LOW · Collector ENV-VARS.md (authoritative reference) omits PROBE_NETFLOW_SAMPLING_OVERRIDES and points at a removed server cmd/probe/main.go

> **✅ RESOLVED (collector v1.3.42 · PR #106)** — docs/ENV-VARS.md no longer points at a removed server path.

**Firewall-Collector** — `docs/ENV-VARS.md:145` · class: `docs-drift` · related: `internal/config/config.go`

**Defect.** The file claims every wired var is listed, but PROBE_NETFLOW_SAMPLING_OVERRIDES (config.go:184, format only in a code comment) is absent — the exact knob SUPPORT-MATRIX.md prescribes for the MikroTik ROS 6.49.x byte-order bug; and the sibling-repo pointer names cmd/probe/main.go which was removed.

**Failure scenario.** A MikroTik ROS 6.49.x operator whose flow bytes are ~16M× inflated is told to set a per-exporter override, finds no such var in the authoritative reference, and concludes the mitigation doesn't exist — corrupt magnitudes persist in every rollup.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-243 · LOW · Metric-alert recovery leg is dead once the type is disabled — open CPU/MEM/DISK/SESSIONS alerts stranded forever, contradicting the in-code contract

> **✅ RESOLVED (v0.11.217 · PR #225)** — disabling an alert type or a device's alerts no longer strands its open alerts forever.

**Firewall-Mon** — `internal/alerts/alerts.go:384` · class: `correctness` · related: `internal/alerts/policy.go`

**Defect.** Recovery gated on fireAt>0; fireAt=zscoreFireAt(resolved.Threshold)=0 whenever resolveAlertConfigProv early-returns on AlertsEnabled=false or event-toggle Off (policy.go:328,371), so sendRecovery is unreachable despite the docstring 'runs regardless of AlertEnabled'. No background sweep closes stale open alerts.

**Failure scenario.** CPU_HIGH fires, operator toggles CPU_HIGH Off; CPU recovers but the alert row never resolves → dashboard shows a live critical for a recovered condition forever; re-enabling re-fires nothing (dbCooldown sees the open row).

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-244 · LOW · ProcessSecurityEvent/ProcessSecurityDigest read policyCache and config via resolveAlertConfig/SnapshotConfig without am.mu — violates the resolver's lock contract

> **✅ RESOLVED (v0.11.217 · PR #225)** — three unlocked resolver/config reads closed under one ownership rule.

**Firewall-Mon** — `internal/alerts/alerts.go:897` · class: `concurrency` · related: `internal/alerts/policy.go`, `cmd/poller/main.go`

**Defect.** resolveAlertConfigProv is documented 'Caller holds am.mu' and walks maps RefreshPolicyCache replaces under Lock, yet ProcessSecurityEvent (897), ProcessSecurityDigest (1089), CheckProbeDataFlow (2266) call it/SnapshotConfig unlocked; siblings (StormThreshold) take RLock. Saved today only by the single poller goroutine topology.

**Failure scenario.** Any second goroutine (future async worker, API reuse, or moving RefreshThresholds to a ticker) makes it a live race — torn struct read or fatal concurrent map read/write killing the poller.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-245 · LOW · F17 adaptive baseline is built from the OLDEST 2000 samples (GetSystemStatusHistory ASC + Limit 2000), so a fast-cadence device baselines on stale hours

> **✅ RESOLVED (v0.11.217 · PR #225)** — same fix as AUDIT-172 — baselines built from the newest samples, free of SSH zero-disk rows.

**Firewall-Mon** — `internal/alerts/baseline_f17.go:53` · class: `correctness` · related: `internal/database/charts.go`, `internal/config/config.go`

**Defect.** ensureBaseline sources history via GetSystemStatusHistory(deviceID, 24h). That query (charts.go:148-149) is `Where(device_id=? AND timestamp>?).Order(timestamp ASC).Limit(2000)`, so LIMIT 2000 returns the OLDEST 2000 rows in the window, not the most recent — the opposite of what an adaptive baseline wants. A dual-writer FortiGate emits ~2 system_status rows/60s (~2880/24h > 2000), so the cap bites even at the default SNMP_POLL_INTERVAL of 60s (config.go:420); any deployment polling faster than ~43s/row hits it regardless of writer count.

**Failure scenario.** A device produces ~2880 system_status rows/24h; GetSystemStatusHistory returns the oldest ~16.7h and drops the most recent ~7h. When the device's normal operating range shifts (e.g. new steady-state CPU after a config change), the z-score baseline reflects only stale pre-shift samples until they age into the oldest-2000 window, producing mean+K*sigma thresholds calibrated to conditions that no longer hold. Root cause is the ASC+Limit ordering in the shared charts.go query, consumed by baseline_f17 as if it returned recent samples.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-246 · LOW · consultDeviceRuleLocked stamps a dangling rule PolicyID onto the alert before applyRulePolicy's nil-check, orphaning escalation (state path is immune)

> **✅ RESOLVED (v0.11.217 · PR #225)** — a rule pinning a deleted policy no longer stamps the dangling id onto saved alert rows.

**Firewall-Mon** — `internal/alerts/devicerules.go:114` · class: `correctness` · related: `internal/alerts/policy.go`, `internal/alerts/staterules.go`

**Defect.** The device-family evaluator assigns PolicyID unconditionally THEN calls the guarded overlay (devicerules.go:114-116): `if rule.policyID != nil { resolved.PolicyID = rule.policyID; am.applyRulePolicy(resolved, *rule.policyID) }`. applyRulePolicy only mutates channels when the policy exists (`if p := am.findPolicy(policyID); p != nil {...}`). When the rule references a deleted policy, findPolicy returns nil so channels stay as the device's resolved policy — but resolved.PolicyID was already overwritten to the nonexistent id. The sibling STATE evaluator has no such pre-assignment (staterules.go:95-97 calls only applyRulePolicy), and resolvedPolicyIDLocked (policy.go:275) returns only findPolicy-confirmed ids.

**Failure scenario.** Operator deletes an AlertPolicy still referenced by an enabled source=device event rule (e.g. INTERFACE_ERRORS/CONFIG_CHANGE with a pinned policy). A device-family alert fires: the row is persisted with PolicyID = the deleted id while notifying on the device's default channels. CheckEscalations looks up escalationPolicies[*alert.PolicyID] (alerts.go:2482), never finds the dangling id, and never escalates — even though the device's real resolved policy has escalation configured. The effective-config endpoint also names a policy that no longer exists.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-247 · LOW · SERVER_DISK_HIGH ignores maintenance suppression — Suppressed never set from resolved.InMaintenance, unlike every sibling fire path

> **✅ RESOLVED (v0.11.217 · PR #225)** — maintenance windows now suppress SERVER_DISK_HIGH, which can also escalate.

**Firewall-Mon** — `internal/alerts/serverdisk.go:141` · class: `correctness` · related: `internal/alerts/alerts.go`

**Defect.** checkOneServerVolume resolves config (computing InMaintenance) but the alert literal omits Suppressed and notify runs unconditionally; every other emitter stamps Suppressed:resolved.InMaintenance and gates notify on !Suppressed. Recovery leg does honor it — fire-only asymmetry.

**Failure scenario.** A global SuppressAll window for planned server work (disk migration, vacuum-full) mutes device alerts but SERVER_DISK_HIGH still pages email/Slack/PagerDuty and saves un-suppressed rows.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-248 · LOW · flow_agent_drops baseline keyed by agent only while batch max is keyed (agent,rate) — dual-rate sFlow agents fabricate drop deltas and false-fire SFLOW_SAMPLING_BACKOFF

> **✅ RESOLVED (v0.11.217 · PR #225)** — dual-rate sFlow agents no longer fabricate drop deltas (drop baseline keyed by agent plus rate).

**Firewall-Mon** — `internal/api/handlers/handlers_agent_drops.go:75` · class: `data-integrity` · related: `internal/models/models.go`

**Defect.** batch max keyed agentKey{addr,rate} (line 54) but agentDropsLast keyed by k.agent only (75-93); the file's own NetFlow comment warns mixing counter streams on one sampler corrupts the baseline.

**Failure scenario.** An agent exporting two sampling instances flip-flops the shared baseline every batch, writing large fabricated deltas into flow_agent_drops that the sampling_backoff detector SUMs → false alerts. Fix: baseline by the same (agent,rate) key.

**Fix direction.** baseline by the same (agent,rate) key.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-249 · LOW · Per-policy notification webhook URLs returned unredacted to viewer role / read-scoped tokens

> **✅ RESOLVED (v0.11.215 · PR #223)** — per-policy notification webhook URLs are masked on read with preserve-on-write.

**Firewall-Mon** — `internal/api/handlers/handlers_alert_policies.go:24` · class: `security` · related: `cmd/api/main.go`, `internal/models/models.go`, `internal/alerts/policy.go`, `internal/notifier/notifier.go`

**Defect.** ListAlertPolicies returns policies unredacted; AlertPolicy carries live Slack/Discord/generic webhook URLs. Route GET /admin/api/alert-policies is not in adminOnlyRoutes so defaults to RoleViewer; the equivalent global webhooks are admin-gated.

**Failure scenario.** A viewer-role account or read-scoped token reads every policy's webhook URL in cleartext — a postable bearer credential — a role-level redaction inconsistency.

*Verification: 3/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-250 · LOW · Data race on shared config.Alerts: API handlers read fields the per-minute RefreshThresholds goroutine rewrites under a different lock

> **✅ RESOLVED (v0.11.217 · PR #225)** — handler fallback reads of the alerts config no longer race the refresh loop.

**Firewall-Mon** — `internal/api/handlers/handlers_alert_policies.go:346` · class: `concurrency` · related: `cmd/api/main.go`, `internal/alerts/alerts.go`, `internal/api/handlers/handlers_settings.go`, `internal/api/handlers/handlers_reports.go`

**Defect.** cmd/api builds one *config.Config shared by Handler and AlertManager; the 60s alert-config-refresh goroutine writes am.config.Alerts.* under am.mu while handlers (alertGlobalDefaults:346, getNotificationSetting:588, reports:34) read the SAME fields with no lock. am.mu is invisible to Handler. M15 fixed this class for ReportScheduler by giving it a private mu-guarded copy.

**Failure scenario.** An admin opening the Alerting hub during a refresh tick reads h.config.Alerts concurrently with the writer — -race flags it; a two-word string field (SMTPPassword, webhook URL) can tear → garbage credential shipped to the SMTP diagnostic or a panic. Fix per M15: read via a locked snapshot.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-251 · LOW · Numeric query filters bound as raw strings in alerts/traps/syslog listings — non-numeric input → PG 22P02 500 (L24 class fixed only in flows)

> **✅ RESOLVED (v0.11.219 · PR #227)** — non-numeric device_id/site_id/probe_id filters return 400 instead of a Postgres 22P02 500.

**Firewall-Mon** — `internal/api/handlers/handlers_analytics.go:88` · class: `input-hardening`

**Defect.** applyAlertFilters binds raw c.Query("device_id") against uint columns; same in GetTraps (391-392) and GetSyslogMessages (434-439). The file's own L24 comment (505-509) declares this a bug fixed only for GetFlowSamples.

**Failure scenario.** GET /api/alerts?device_id=abc on prod Postgres raises 22P02 → 500; SQLite test suite silently matches nothing so CI never sees it.

*Verification: 2/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-252 · LOW · Unauthenticated /api/public/dashboard and /api/public/interfaces fall back to global latest telemetry, bypassing the public_visible gate

> **✅ RESOLVED (v0.11.215 · PR #223)** — the public dashboard/interfaces endpoints never fall back to a non-public device's telemetry.

**Firewall-Mon** — `internal/api/handlers/handlers_dashboard.go:143` · class: `security` · related: `internal/database/telemetry.go`, `cmd/api/main.go`, `internal/api/middleware/middleware.go`

**Defect.** GetPublicDashboard's `else if db != nil` branch (143-165) calls db.GetLatestSystemStatus() and GetPublicInterfaces's (198-204) db.GetLatestInterfaceStats() — neither filters public_visible. Route group is anonymous (main.go:661-673, CheckAdminAuth continues on missing cookie). resolvePublicDeviceID's own docstring says public_visible must be enforced here.

**Failure scenario.** No device is public_visible (or an anon caller requests a non-public device_id): hasDevice=false, handler discloses the newest-reporting NON-public device's hostname/version/CPU/mem/sessions (and full interface table) to an unauthenticated caller.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-253 · LOW · Eight metric endpoints silently truncate at 500 items then mark the batch ID processed, while the collector clamps to (and documents) a 1000-item server cap — a >500-row VPN batch loses its tail permanently and invisibly

> **✅ RESOLVED (v0.11.218 · PR #226)** — eleven metric endpoints that silently truncated at 500 now honor the collector's up-to-1000 batches.

**cross-repo** — `internal/api/handlers/handlers_data.go:924` · class: `contract-drift`

**Defect.** ReceiveVPNStatuses and 7 siblings (ProcessorStats/DiskUsage/LoadAverage/HardwareSensors/HAStatuses/SecurityStats/SDWANHealth) do statuses=statuses[:500] not truncateProbeBatch (whose M1 comment says silent truncation+marking lost tails 'permanently and invisibly'); they run batchDedupCheck/markBatchIfOK so even a resend dedup-drops. Collector const serverMaxBatchItems=1000; VPN batch is one POST/device combining IPSec+dialup+SSL-VPN rows.

**Failure scenario.** A hub with >500 combined dialup+SSL-VPN rows POSTs its VPN batch; rows 501+ dropped with no log/alert and the batch ID recorded so the tail can't resend — tunnels past index 500 never get rows, ever-up gate never arms, outages undetectable. The M1 class reintroduced on 8 endpoints.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-254 · LOW · ReceiveConfigRevision's row lock uses GORM v1's gorm:query_option — a silent no-op on GORM v2, concurrent backups not serialized

> **✅ RESOLVED (v0.11.218 · PR #226)** — the config-revision row lock (a GORM-v1 no-op) now uses a real FOR UPDATE.

**Firewall-Mon** — `internal/api/handlers/handlers_data.go:1228` · class: `concurrency` · related: `go.mod`

**Defect.** tx.Set("gorm:query_option","FOR UPDATE") under a comment claiming SELECT...FOR UPDATE serialization, but go.mod pins gorm v1.31.2 where nothing reads that key — generated SQL is a plain SELECT with no FOR UPDATE.

**Failure scenario.** Two overlapping ReceiveConfigRevision for the same device read the same prevRev without blocking, both take the INSERT path → two duplicate revisions + two CONFIG_CHANGE alerts, breaking the one-row-per-logical-config-state invariant. SQLite tests can't catch it.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-255 · LOW · ReceiveInterfaceErrors/SensorDetails/LicenseDetails return 500 on a fully-filtered/empty batch (gorm.ErrEmptySlice)

> **✅ RESOLVED (v0.11.218 · PR #226)** — interface-error/sensor/license batches of only not-owned devices return 200, not 500.

**Firewall-Mon** — `internal/api/handlers/handlers_data.go:1460` · class: `input-hardening`

**Defect.** Three direct h.db.Gorm().Create(&filtered) handlers with no len==0 guard; GORM Create on an empty slice returns ErrEmptySlice. Sibling ReceiveHardwareSensors guards len==0 → 200 {saved:0}. filtered empties when every row is dropped by the device allow-list.

**Failure scenario.** A device is reassigned/unassigned server-side while the collector still polls it: all rows filtered, Create → ErrEmptySlice, handler returns 500, collector retries as transient → persistent error loop each SSH cycle.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-256 · LOW · DeleteDeviceConfigRevision reports the stale parse-error variable instead of result.Error — real DB failure never logged

> **✅ RESOLVED (v0.11.219 · PR #227)** — a config-revision delete now logs the real database error, not a stale nil parse error.

**Firewall-Mon** — `internal/api/handlers/handlers_devices.go:1153` · class: `correctness`

**Defect.** InternalError(c,"Failed to delete config revision",err) where err is the (necessarily nil) revID ParseUint error; result.Error is dropped and InternalError only logs err when non-nil.

**Failure scenario.** A DB delete failure returns 500 with no error detail in the log — incident undiagnosable.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-257 · LOW · DeleteEventRuleProfile echoes the raw wrapped DB/transaction error to the client with a 400

> **✅ RESOLVED (v0.11.219 · PR #227)** — an event-rule-profile handler's error handling corrected (paired with AUDIT-256).

**Firewall-Mon** — `internal/api/handlers/handlers_event_profiles.go:170` · class: `contract-drift` · related: `internal/database/event_rule_profiles.go`, `internal/api/handlers/handlers_alert_policies.go`

**Defect.** `if err := db.DeleteEventRuleProfile(id); err != nil { c.JSON(400, response.Error(err.Error())) }`. DeleteEventRuleProfile (event_rule_profiles.go:89-118) returns fmt.Errorf-wrapped internal errors (e.g. `delete event rule profile %d: load: %w` wrapping gorm.ErrRecordNotFound or driver text) plus bare transaction errors — all reach the client verbatim. The established pattern (DeleteAlertPolicy, handlers_alert_policies.go:135-142; AUDIT-071/API3) matches only the known domain string and routes everything else through httputil.InternalError.

**Failure scenario.** An admin deletes a concurrently-removed profile id, or a delete hits an FK/transaction error: client gets HTTP 400 with internal detail (e.g. 'delete event rule profile 5: load: record not found' or raw SQL), leaking backend internals and mis-reporting not-found as 400. Fix: match the specific 'cannot delete the Default event rule profile' string; route the rest through InternalError (or 404 on not-found).

**Fix direction.** match the specific 'cannot delete the Default event rule profile' string; route the rest through InternalError (or 404 on not-found).

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-258 · LOW · GetIPSecPreflightResult polls by device+type, so two tunnels sharing a device cross-contaminate preflight reports and advisories

> **✅ RESOLVED (v0.11.219 · PR #227)** — IPSec preflight results are now tunnel-scoped (new preflight_json column, migration v58).

**Firewall-Mon** — `internal/api/handlers/handlers_ipsec.go:667` · class: `correctness` · related: `internal/database/probe_commands.go`, `internal/ipsec/deploystate.go`

**Defect.** GetLatestCommandByDeviceType(devID, IPSecPreflight) ignores the per-end CommandIDs; probe_commands.go:371 and deploystate.go:6 both document that device+type bleeds across tunnels on one box. The wrong tunnel's report bodies are then fed into this tunnel's driver/intent.

**Failure scenario.** A hub firewall terminating t1 and t2: polling t1's preflight returns t2's status/collision report, so a real t1 collision reads as all-clear (or vice versa). Fix: read via GetProbeCommandByCommandID with persisted preflight IDs.

**Fix direction.** read via GetProbeCommandByCommandID with persisted preflight IDs.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-259 · LOW · Two browser handlers (GetSyslogRetention, GetServerMetricChart) call reqDB(c) without the nil guard every sibling uses → panic/500 in the DB-unavailable state

> **✅ RESOLVED (v0.11.219 · PR #227)** — GetSyslogRetention returns 503 instead of panicking on the nil Store when the DB is unavailable.

**Firewall-Mon** — `internal/api/handlers/handlers_settings.go:47` · class: `correctness` · related: `internal/api/handlers/handlers.go`, `internal/api/handlers/handlers_system.go`

**Defect.** GetSyslogRetention: `c.JSON(200, response.Success(h.reqDB(c).SyslogVolume(...)))` (handlers_settings.go:47) and GetServerMetricChart: `h.reqDB(c).GetServerMetricWindow(...)` (handlers_system.go:160). reqDB (handlers.go:158-163) returns a true-nil database.Store when h.db==nil — the documented reason RequireDB/`==nil` guards exist. Every other DB-backed handler first calls httputil.RequireDB or checks h.db==nil; the h.db==nil state is explicitly contemplated (NewHandler guard, GetHealth/GetSettings special-cases).

**Failure scenario.** When the API runs in the DB-unavailable state the codebase deliberately supports (e.g. started to fix a lost ENCRYPTION_KEY), a request to either endpoint invokes a method on a nil interface and panics; gin turns it into an opaque 500 with a panic stack instead of the clean 503 sibling handlers return.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-260 · LOW · Public unauthenticated GET /api/public/display-settings issues a DB DELETE on every request

> **✅ RESOLVED (v0.11.215 · PR #223)** — the anonymous /api/public/display-settings read no longer writes to the database.

**Firewall-Mon** — `internal/api/handlers/handlers_settings.go:1223` · class: `performance` · related: `cmd/api/main.go`

**Defect.** A 'one-time cleanup' DELETE FROM system_settings WHERE key IN (...) runs unconditionally per request on the anon public group.

**Failure scenario.** Kiosks poll this every ~30s and any anon caller can force continuous no-op write transactions (WAL/row-lock) on untuned prod PG — write-amplification/mild DoS; the migration is mislocated in a hot read path.

*Verification: 2/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-261 · LOW · GetServerMetricChart calls a method on the nil Store from reqDB — panics instead of 503 when DB unavailable

> **✅ RESOLVED (v0.11.219 · PR #227)** — GetServerMetricChart returns 503 instead of panicking on the nil Store (paired with AUDIT-259).

**Firewall-Mon** — `internal/api/handlers/handlers_system.go:158` · class: `correctness` · related: `internal/api/handlers/handlers.go`, `internal/httputil/httputil.go`

**Defect.** h.reqDB(c).GetServerMetricWindow(...) with no nil check; reqDB returns nil when h.db==nil. Every sibling guards with RequireDB.

**Failure scenario.** In the documented DB-less degraded mode an admin chart poll dereferences a nil interface → runtime panic → opaque 500 instead of the 503 contract siblings honor.

*Verification: 3/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-262 · LOW · Username-enumeration timing oracle in ValidateCredentials: unknown usernames skip the bcrypt compare entirely

> **✅ RESOLVED (v0.11.215 · PR #223)** — unknown usernames now cost a full bcrypt comparison (timing-safe).

**Firewall-Mon** — `internal/auth/auth.go:271` · class: `security` · related: `internal/config/config.go`

**Defect.** On GetAdminByUsername miss the function returns ErrInvalidCredentials after a single indexed SELECT with no dummy hash compare, while a real user proceeds to bcrypt.CompareHashAndPassword at cost 12 (~150ms). The Disabled branch comment claims uniform timing but it's broken one branch earlier.

**Failure scenario.** AUDIT-105 tells operators to rename 'admin'; a remote attacker defeats that by classifying response latency (~1-5ms unknown vs ~150ms real) to recover the renamed username. Fix: compare against a fixed dummy bcrypt hash on the unknown path.

**Fix direction.** compare against a fixed dummy bcrypt hash on the unknown path.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-263 · LOW · parseBool silently maps any unrecognized value (True/TRUE) to false, disabling default-on listeners with no warning

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — parseBool is now case-insensitive over {true,1,yes,on}/{false,0,no,off} and warns+defaults on unrecognized values.

**Firewall-Collector** — `internal/config/config.go:276` · class: `input-hardening` · related: `cmd/collector/main.go`

**Defect.** parseBool returns v=="true"||"1"||"yes" (case-sensitive); any non-matching non-empty value returns false, not the default, with no log — unlike parseSamplingOverrides/setupLoggerWith which warn. M23 shows this class already bit PROBE_INSECURE_SKIP_VERIFY.

**Failure scenario.** `PROBE_SYSLOG_ENABLED: True` in docker-compose (YAML habit) returns false for a default-true flag → syslog listeners silently never start, syslog-triggered backups stop, no log explains it. Same for every default-on toggle.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-264 · LOW · parse_opnsense path-collision disambiguator embeds a document-global ordinal, so an unrelated earlier insertion renames colliding objects and diffs them as remove+add

> **✅ RESOLVED (v0.11.226 · PR #234)** — OPNsense config-diff synthetic paths are now stable under unrelated edits.

**Firewall-Mon** — `internal/configdiff/parse_opnsense.go:306` · class: `correctness` · related: `internal/configdiff/diff_objects.go`, `internal/configdiff/classify_opnsense.go`

**Defect.** `o.Path += "#" + Itoa(len(p.out)+1)` uses the global emission ordinal, not a per-path counter, violating the package's own positional-stability rule (objects.go:37). Collisions are reachable (Swanctl children sharing description|local_ts|remote_ts).

**Failure scenario.** An unrelated earlier insertion shifts the second colliding object's ordinal (P#42→P#44); DiffObjects keys on Path → reports 'removed P#42'+'added P#44' for an untouched object → two spurious medium 'policy' findings. A per-path occurrence counter fixes it.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-265 · LOW · Palo Alto and Cisco ASA have no LineMasker: their line diffs render secret churn as red/green deltas and stable secrets verbatim

> **✅ RESOLVED (v0.11.226 · PR #234)** — PAN-OS and Cisco ASA line diffs now mask volatile secrets.

**Firewall-Mon** — `internal/configdiff/vendor_paloalto.go:54` · class: `security` · related: `internal/configdiff/vendor_cisco_asa.go`, `internal/configdiff/linediff.go`, `internal/api/handlers/handlers_devices.go`, `cmd/api/static/js/admin-device-detail.js`

**Defect.** paloaltoNormalizer/ciscoASANormalizer implement only Normalize, not MaskVolatileLines; prepareDiffInput falls back to masked=clean for non-LineMasker vendors, so no row is 'volatile' and lineHasSecret never fires. PAN-OS <phash> re-salts each emit; ASA Type 7 is trivially reversible. UI legend advertises volatile patterns that never take effect.

**Failure scenario.** A PAN-OS diff shows dozens of <phash>/<secret> re-encryption lines as deltas (inflating Added/Removed, burying the real change) and any stable <password> verbatim; ASA 'username X password 7 <blob>' renders decodable in seconds. OPNsense got the masker; two other rich-normalized vendors didn't.

*Verification: 2/2 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-266 · LOW · GetAlertResponseStats truncates to 20000 rows with no ORDER BY — MTTA/MTTR and acked/resolved counts computed over an arbitrary DB-ordered slice

> **✅ RESOLVED (v0.11.221 · PR #229)** — alert response-time stats (MTTA/MTTR) computed deterministically with SQL-side conditional aggregation.

**Firewall-Mon** — `internal/database/alerts.go:405` · class: `data-integrity` · related: `internal/report/data.go`

**Defect.** alerts.go:403-405 selects timestamp/acknowledged_at/resolved_at/notes `Where(timestamp>? AND metric_name NOT IN ? AND (acknowledged_at IS NOT NULL OR resolved_at IS NOT NULL)).Limit(20000).Find(&rows)` with no Order(). Averages and ackedCount/resolvedCount are then computed in Go over whatever 20000 rows the scan returned. Called with a 30-day window from report/data.go:361 (const days = 30).

**Failure scenario.** On a fleet producing more than 20,000 acked/resolved alerts in the trailing 30 days (a flapping/noisy multi-device deployment), Postgres returns an implementation-defined 20,000-row subset (seq/index scan order), so the email report's MTTA/MTTR reflect an arbitrary non-deterministic slice and AckedCount/ResolvedCount silently cap at ~20000 — understating volume and biasing the averages, with no indication truncation occurred.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-267 · LOW · syslogPartitionDropDays is dead code encoding retired two-band semantics, kept alive only by its test

> **✅ RESOLVED (v0.11.228 · PR #236)** — removed the dead syslogPartitionDropDays helper and its test.

**Firewall-Mon** — `internal/database/cleanup.go:324` · class: `maintainability` · related: `internal/database/cleanup_syslog_partition_lc23_test.go`, `internal/database/syslogretention.go`

**Defect.** Zero production callers; live drop path uses syslogMaxWindow(sevDays) honoring per-severity overrides, while syslogPartitionDropDays reads only legacy env windows. Its test green-stamps semantics the product no longer runs.

**Failure scenario.** A future re-wire onto this purpose-built, unit-tested function would ignore per-severity overrides and drop partitions still holding long-retention severity-0 rows — silent data loss. Remove it and retarget its test.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-268 · LOW · Dead SaveConfigRevision enforces a 5-row-per-device cap that contradicts the live 500-cap merge-into-latest retention model

> **✅ RESOLVED (v0.11.228 · PR #236)** — removed the dead Database.SaveConfigRevision (zero callers).

**Firewall-Mon** — `internal/database/config_revisions.go:24` · class: `maintainability` · related: `internal/api/handlers/handlers_data.go`, `internal/database/cleanup.go`

**Defect.** config_revisions.go:24 prunes to five rows: `if count > 5 { deleteCount := count - 5 ... }`. A full-tree grep shows SaveConfigRevision has NO callers (only its own definition). The live write path is handlers_data.go ReceiveConfigRevision (own tx + merge-into-latest), and CleanupConfigRevisions in the SAME file documents the real policy as perDeviceCap = 500 (config_revisions.go:65) with 365-day retention. The two caps (5 vs 500) directly contradict.

**Failure scenario.** If a future change (or test) wires ingestion through SaveConfigRevision — the obvious-looking public method for its name — every device's config history is silently truncated to the five most recent revisions inside the same insert transaction, destroying the diff/audit history the 500-cap model and the config-history UI (handlers_devices.go GetDeviceConfigRevisions) assume is present.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-269 · LOW · GetConnectionFlowStats issues three DISTINCT scans over the pair's full unbounded vpn_status/interface_stats history per request

> **✅ RESOLVED (v0.11.221 · PR #229)** — connection flow-stats metadata queries are now time-bounded.

**Firewall-Mon** — `internal/database/connection_detail.go:1122` · class: `performance` · related: `internal/database/telemetry.go`, `internal/models/models.go`

**Defect.** Three raw queries (subnet-pair, phase1_name, interface fallback) carry no timestamp bound; vpn_status has no covering index for the filter and interface_stats none for name/desc/alias. telemetry.go:390 already fixed this exact shape ('bug fix rather than semantic change').

**Failure scenario.** Opening a connection's Flows tab heap-fetches the full history of both endpoints (~700k+ rows) — seconds on spinning-disk prod. Secondary: DISTINCT over all history over-matches selectors deleted months ago.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-270 · LOW · Server ResolveDeviceByIP uses exact-match .First with no ORDER BY — traps misattributed/collapsed across sites under NAT, HA VIP, or reused RFC1918 management IPs

> **✅ RESOLVED (v0.11.219 · PR #227)** — trap device-by-IP resolution is deterministic under shared IPs (stable tie-break).

**Firewall-Mon** — `internal/database/devices.go:37` · class: `security` · related: `internal/alerts/alerts.go`

**Defect.** Trap attribution is trap.DeviceID = am.db.ResolveDeviceByIP(trap.SourceIP) (alerts.go:535), and ResolveDeviceByIP does `Where("ip_address = ?", ip).Select("id").First(&device)` then an interface-address fallback `Where("ip_address = ?", ip).Select("device_id").First(&addr)` (devices.go:37-44). `.First` with no ORDER BY returns an arbitrary DB-dependent row when >1 device (or interface address) shares an IP — and in this single-tenant schema (no tenant_id) reused management IPs across sites, HA pairs sharing a VIP, and multiple firewalls NATed behind one collector all produce duplicate ip_address rows. The UDP source IP is the only attribution key.

**Failure scenario.** Sites B and C each run a firewall with management IP 192.168.1.1. A trap from B arrives with SourceIP = the NAT egress 192.168.1.1; ResolveDeviceByIP().First returns whichever row Postgres yields first (say C). The alert is stamped device_id=C, C's policy/maintenance window applies, and a later matching LINK_UP resolves C's alert instead of B's. Combined with the shared community, an attacker behind the same NAT/VIP can forge traps that deterministically resolve to a monitored device without knowing its real address.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-271 · LOW · Migration v10's doc comment is orphaned onto migrateSystemStatusSource; migrateFlowSamplesAddDropsColumn has no attached doc

> **✅ RESOLVED (v0.11.231 · PR #239)** — fixed the orphaned v10 migration doc comment that ran into the next function.

**Firewall-Mon** — `internal/database/migrate.go:1226` · class: `docs-drift`

**Defect.** The 28-line v10 doc block runs into the v52 comment with no blank line, so Go attaches the combined block to migrateSystemStatusSource while migrateFlowSamplesAddDropsColumn (1394) has no doc.

**Failure scenario.** godoc/IDE hover shows v10's flow_samples rationale on the wrong migration; v10's idempotency rationale is invisible. Pure comment relocation.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-272 · LOW · DeniedEvent stores unbounded attacker-controlled KV values — capStr applied only to countries; unvalidated srcip/dstip land in indexed columns

> **✅ RESOLVED (v0.11.216 · PR #224)** — denied-event ingest validates and bounds attacker-controlled fields.

**Firewall-Mon** — `internal/deny/project.go:143` · class: `input-hardening` · related: `internal/models/models.go`, `internal/database/batch_insert.go`, `internal/classify/classify.go`

**Defect.** capStr bounds only SrcCountry/DstCountry; PolicyName/Service and SrcAddr/DstAddr stored raw; src/dst never net.ParseIP-validated (classify.ScopeLocal returns false for garbage but still passes it through). idx_denied_src/idx_denied_dst are indexed text with no size tag.

**Failure scenario.** A spoofed syslog line with a >2704-byte srcip overflows the PG btree row limit → batch INSERT fails → M26 per-row fallback re-inserts 1000 rows individually with per-row logs; multi-KB policyname/service bloat rows contrary to capStr intent. Fix: ParseIP src/dst and capStr PolicyName/Service.

**Fix direction.** ParseIP src/dst and capStr PolicyName/Service.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-273 · LOW · c2_beacon 'small callout' gate compares ingest pre-multiplied byte estimates to a 1500-byte wire-size ceiling, structurally disabling the detector on sampled sFlow

> **✅ RESOLVED (v0.11.226 · PR #234)** — the c2_beacon byte gate now works on sampled sFlow.

**Firewall-Mon** — `internal/detect/security.go:253` · class: `correctness` · related: `internal/detect/detect.go`, `internal/detect/ddos.go`

**Defect.** Having(AVG(bytes)<=1500) but flow_samples.bytes is pre-multiplied by sampling_rate at ingest (ddos.go:23 contract), so AVG<=1500 needs avg frame <1500/rate (<3 bytes at rate 512) — no sampled candidate can pass. detectorValidity marks c2_beacon ValiditySampledOK, contradicting the gate.

**Failure scenario.** Any fleet on sFlow at realistic rates gets zero beacon candidates forever — not from timing-CV noise but wrong-units size gate; operators tuning beacon knobs see no effect. Works only on unsampled NetFlow. Fix: gate on AVG(bytes/GREATEST(sampling_rate,1)).

**Fix direction.** gate on AVG(bytes/GREATEST(sampling_rate,1)).

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-274 · LOW · FortiGate lifetime/DPD device ranges enforced only by the deploy-time conformance guard, not by Validate — a wizard-green intent 400s on Deploy

> **✅ RESOLVED (v0.11.225 · PR #233)** — a green wizard preview now implies a deployable config (fixed with AUDIT-275).

**Firewall-Mon** — `internal/ipsec/validation.go:325` · class: `contract-drift` · related: `internal/ipsec/conformance/fortigate.go`, `internal/api/handlers/handlers_ipsec.go`

**Defect.** Validate only blocks a NEGATIVE child lifetime and WARNs above it; IKE lifetime out of range is WARN-only (validation.go:340) and DPD has no upper bound. But the FortiGate conformance spec hard-rejects: keylifeseconds/keylife intRange[120,172800], dpd-retryinterval intRange[1,60] (conformance/fortigate.go). conformance.Validate runs ONLY in DeployIPSecTunnel (handlers_ipsec.go:995), never in the Preview paths the wizard uses.

**Failure scenario.** Operator sets a FortiGate end's child lifetime=60s (positive, below IKE) or DPD delay>60s via Custom profile. ipsec.Validate returns no block, wizard shows a green Save; on Deploy the FortiGate render emits keylifeseconds=60 and conformance flags it, so Deploy returns a generic 400 the wizard never anchored to the control. Deploy is safely blocked, but the field-linter and deploy contracts disagree on the accepted range.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-275 · LOW · Validation never bounds DPD delay or child lifetime, but FortiGate conformance hard-caps them — valid-looking intents refused at deploy with an unanchored 400

> **✅ RESOLVED (v0.11.225 · PR #233)** — same defect as AUDIT-274 seen from a second angle — preview/deploy parity.

**Firewall-Mon** — `internal/ipsec/validation.go:344` · class: `contract-drift` · related: `internal/ipsec/conformance/fortigate.go`, `internal/ipsec/vendors/fortigate/fortigate.go`, `internal/api/handlers/handlers_ipsec.go`

**Defect.** Validation only warns dpd_off and blocks child lifetime <0; render emits values verbatim and conformance caps dpd-retryinterval[1,60] and keylifeseconds[120,172800]. Preview/renderPreviewEnds skip conformance. The team already fixed this class for IKE lifetime (AUDIT-IP5).

**Failure scenario.** Via API set dpd.delay_secs=120 or child_lifetime_secs=60 on a FortiGate end: validation/preview clean, every deploy 400s 'outside [1,60]' with no field anchored — the tunnel can never deploy.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-276 · LOW · OPNsense ParseStatus reports a definitive SADown for a dynamic peer it can never match, driving a healthy tunnel to 'down'

> **✅ RESOLVED (v0.11.225 · PR #233)** — OPNsense SA status no longer forces down for an unmatched dynamic peer.

**Firewall-Mon** — `internal/ipsec/vendors/opnsense/opnsense.go:347` · class: `correctness` · related: `internal/api/handlers/handlers_ipsec.go`, `internal/ipsec/validation.go`, `cmd/api/static/js/admin-ipsec.js`

**Defect.** ParseStatus matches session rows by stored PeerIP and, if unmatched, returns definitive IKE/Child=SADown; no remote.Dynamic handling, though validation.go:447 documents a dialup end's PeerIP is its mgmt address, not the dial-in source. FortiGate driver matches by name/parent and is immune.

**Failure scenario.** A policy-based OPNsense⇄FortiGate tunnel with the FortiGate behind NAT establishes, but the OPNsense post-deploy probe finds no session for the stored private mgmt IP → transitions a working tunnel to 'down', inviting rollback. Fix: return SAUnknown when Remote().Dynamic.

**Fix direction.** return SAUnknown when Remote().Dynamic.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-277 · LOW · OPNsense preview pane hardcodes 'version = 2' while the applied REST body honors the intent's IKE version

> **✅ RESOLVED (v0.11.225 · PR #233)** — OPNsense IKEv1 tunnel preview no longer misreports the IKE version.

**Firewall-Mon** — `internal/ipsec/vendors/opnsense/opnsense.go:763` · class: `docs-drift` · related: `internal/api/handlers/handlers_ipsec.go`

**Defect.** swanctlPreview prints literal 'version = 2'; apply sets version:ikeVersion(in.IKEVersion). Preview is billed as authoritative; FortiGate preview has no equivalent drift.

**Failure scenario.** An IKEv1 tunnel's OPNsense preview (the artifact the operator approves) shows version=2 while config applies version 1 — misleads anyone diagnosing an IKE-version mismatch. One-line fix.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-278 · LOW · IRC PM'd commands are answered to the bot's own nick — the sender never sees the response

> **✅ RESOLVED (v0.11.223 · PR #231)** — IRC commands sent as a private message are now answered to the sender.

**Firewall-Mon** — `internal/irc/bot.go:652` · class: `correctness`

**Defect.** onPrivmsg replies to e.Arguments[0] (the PRIVMSG target = the bot's own nick for a PM) rather than e.Nick; isAdmin already special-cases target==ownNick, so PMs are anticipated but replies aren't redirected.

**Failure scenario.** A user PMs '!status'/'!help'; the bot PRIVMSGs itself, the user gets nothing and concludes the bot is dead. Standard fix: replyTo = target==ownNick ? e.Nick : target.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-279 · LOW · l2infer mergeCandidate: mirrored LLDP rows fail to collapse when the remote-port identity doesn't resolve — one cable becomes two parallel lldp_neighbor links sharing the same local port

> **✅ RESOLVED (v0.11.227 · PR #235)** — L2 inference no longer duplicates a link when a neighbor advertised an unresolvable remote port.

**Firewall-Mon** — `internal/l2infer/infer.go:917` · class: `correctness`

**Defect.** sideMatches tests only the reporter-side port; step-3 conflict gate exempts LLDP-vs-LLDP; resolveRemotePort returns the raw PortID as a name when unresolved (FortiGate ambiguous hw-switch base MAC, ifName/ifDescr mismatch), so a mirrored row with a KNOWN name finds no exact match and no fillable side → step 4 appends a second link. Test only covers PortID==Name.

**Failure scenario.** Device A reports B with an unresolvable remote port → link A:port5↔B:'<raw>' with a known B name; B's mirror creates A:port5↔B:lan3 → two lldp edges both claiming A:port5 (physically impossible), attribution flaps; transitive suppression never removes them (LLDP exempt).

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-280 · LOW · opnsense/pfsense filterlog extractors are stubs — structured-field event rules silently never match for the in-prod OPNsense vendor

> **✅ RESOLVED (v0.11.227 · PR #235)** — OPNsense/pfSense structured log field extraction and deny projection now work (was a no-op stub).

**Firewall-Mon** — `internal/logfields/opnsense.go:18` · class: `correctness` · related: `internal/logfields/pfsense.go`, `internal/alerts/rules.go`, `internal/deny/project.go`

**Defect.** opnsenseExtractor.Extract is a no-op STUB (same pfsense.go). Fails closed (no injected keys) but the event-rule engine evaluates via logfields.Fields(vendor,msg), and a rule on filterlog fields (action/interface/proto/src/dst) for a live OPNsense 26.1 box (in prod) can never match — no UI warning. OPNsense blocks also never reach denied_events (deny.Project hard-codes fortigate).

**Failure scenario.** An operator writes 'action=block AND interface=wan' for the live OPNsense firewall; the field map never contains 'action' so it never fires and blocked-traffic storms go unalerted while coverage appears to exist.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-281 · LOW · Unpinned GORM columns with acronym-mangled derived names (trap_o_id, ip_s_version, wf_http_s_blocked) — same class as the fixed v17 CIDR→c_id_r bug

> **✅ RESOLVED (v0.11.227 · PR #235)** — three acronym-heavy model fields pinned to their existing column names.

**Firewall-Mon** — `internal/models/models.go:386` · class: `contract-drift` · related: `internal/database/migrate.go`

**Defect.** TrapEvent.TrapOID, SystemStatus.IPSVersion, SecurityStats.WFHTTPSBlocked have no column: pin; NamingStrategy derives trap_o_id/ip_s_version/wf_http_s_blocked via commonInitialisms — exactly the v17 CIDR→c_id_r failure. AUDIT-D5 mandates pinning this class.

**Failure scenario.** Latent (all access via GORM structs), but the first raw SQL/Select/Updates(map)/ON CONFLICT written against the natural json name fails 'column does not exist'. Fix must freeze the existing mangled name or ship a v17-style rename migration.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-282 · LOW · IPFIX field-spec parser pre-allocates slice capacity from an unvalidated attacker-controlled count

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — bounded the IPFIX field-spec count by remaining bytes before allocation (no 512KB alloc from a tiny packet).

**Firewall-Collector** — `internal/netflow/ipfix.go:110` · class: `input-hardening` · related: `internal/netflow/v9.go`, `internal/netflow/template.go`

**Defect.** make([]templateField,0,count) with count = raw field-count word, validated only AFTER alloc (off+4>len(rem)); templateField is 8 bytes so count=65535→~512KB. The v9 path validates len(rem)<need before make.

**Failure scenario.** A ~24-byte IPFIX datagram with fieldCount=0xFFFF and no records → ~512KB alloc then immediate nil return; ~20,000× packet-to-allocation amplification at the per-source rate ceiling (~512 MB/s transient GC churn per spoofed source; UDP source forgeable to a monitored IP). Fix: bound count by remaining bytes before make.

**Fix direction.** bound count by remaining bytes before make.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-283 · LOW · seqTracker caps its state map but never evicts — forged observation domains permanently starve sequence-loss detection

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — added an idle TTL sweep to the NetFlow seqTracker on the maintenance ticker so it can't be permanently filled.

**Firewall-Collector** — `internal/netflow/seq.go:73` · class: `input-hardening` · related: `internal/netflow/netflow.go`, `internal/netflow/template.go`

**Defect.** observe() refuses new keys once len>=4096 but seq.go has no delete/sweep; every sibling cache (template/sampler/flowdedup) evicts. The key's domain field is an unauthenticated packet value.

**Failure scenario.** A sender enumerates the domain word across 4096+ values (spoofing a monitored IP or any source when allowlist off); the map fills and never shrinks → every genuine new (exporter,domain,version) returns "" → seq_gap/seq_resync detection permanently disabled until restart. Fix: TTL/idle sweep on the maintenance ticker.

**Fix direction.** TTL/idle sweep on the maintenance ticker.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-284 · LOW · v9 template field with Length 0xFFFF bypasses the field-width quarantine and is mis-decoded as an IPFIX variable-length field

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — reject a v9 template field Length 0xFFFF (IPFIX-only varlen marker) at parse time, quarantining that template.

**Firewall-Collector** — `internal/netflow/template.go:153` · class: `input-hardening`

**Defect.** templateCache.put's quarantine exempts the varlen sentinel: `if f.Length != varlenFieldLen && f.Length > maxFieldLen` (153, varlenFieldLen=0xFFFF). put() is shared by v9 and IPFIX. NetFlow v9 has no variable-length encoding (IPFIX-only, RFC 7011 §7), yet parseV9TemplateSet reads Length verbatim with no v9-specific 0xFFFF rejection. A v9 field Length=0xFFFF is neither quarantined nor rejected, and decodeDataRecord (record.go:326) then reads a nonexistent 1-byte varlen prefix.

**Failure scenario.** A broken/hostile v9 exporter (attributed by spoofable UDP source IP) registers a template with field Length=0xFFFF. Every data record is mis-framed: decodeDataRecord consumes a varlen chunk not present in v9 wire format, shifting all subsequent field offsets and desyncing the data-set walk → that exporter's records dropped as malformed and/or emit garbage values. Bounded to that exporter's set (no cross-record OOB). Fix: reject Length==0xFFFF in the v9 template parsers (or pass an isV9 flag).

**Fix direction.** reject Length==0xFFFF in the v9 template parsers (or pass an isV9 flag).

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-285 · LOW · SMTP loginAuth TLS gate is stricter than PlainAuth (no localhost exception) despite its 'Same rule as PlainAuth' comment — CompoundAuth silently drops every alert email to a localhost LOGIN-only relay without STARTTLS

> **✅ RESOLVED (v0.11.217 · PR #225)** — localhost LOGIN-only SMTP relays now work like PLAIN ones.

**Firewall-Mon** — `internal/notifier/smtp_auth.go:67` · class: `contract-drift`

**Defect.** Verified loginAuth.Start gates unconditionally on TLS: `if !server.TLS { return "", nil, errors.New("unencrypted connection") }` (smtp_auth.go:67-69), with an in-file comment claiming 'Same rule as PlainAuth.' But net/smtp PlainAuth sends creds over cleartext when connected to localhost/127.0.0.1/::1, so the two branches CompoundAuth dispatches to (smtp.PlainAuth vs LoginAuth) are NOT the same rule — loginAuth is strictly stricter. sendMailWithDeadline only runs STARTTLS when advertised, so a bare local relay yields server.TLS==false.

**Failure scenario.** Operator sets SMTPHost=127.0.0.1 with SMTPUsername/Password pointing at a local submission agent that advertises only AUTH LOGIN and no STARTTLS (the exact 'LOGIN-only backend' case this file exists for). CompoundAuth picks LoginAuth, whose Start returns 'unencrypted connection', so client.Auth fails and every alert email is dropped. The identical relay advertising PLAIN would succeed via PlainAuth's localhost exception — an inconsistent, invisible failure contradicting the in-file claim.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-286 · LOW · internal/ping is orphaned dead code whose Ping() can never succeed (udp4 socket + *net.IPAddr WriteTo EINVAL, ParseMessage proto 0) — delete, not test

> **✅ RESOLVED (v0.11.228 · PR #236)** — removed the orphaned dead internal/sflow package.

**Firewall-Mon** — `internal/ping/ping.go:235` · class: `correctness`

**Defect.** icmp.ListenPacket("udp4") wraps *net.UDPConn whose WriteTo rejects *net.IPAddr with EINVAL (needs *net.UDPAddr); ParseMessage(int(ICMPTypeEchoReply)=0,...) hits errInvalidProtocol; TTL hardcoded 64. go list -deps ./cmd/... and grep show ZERO importers (orphaned since cmd/probe removal, distinct from cmd/probe itself). No tests.

**Failure scenario.** If PingCollector is ever re-wired every Ping() errors at WriteTo → 100% packet loss for every device forever. Until then it is 295 lines of doubly-broken untested dead code taxing every refactor/scan. Correct resolution: delete.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-287 · LOW · isRetryableStatus treats 413/414 (payload too large) as transient — an oversized batch is requeued and retried forever

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — oversized batches (HTTP 413/414) are dropped instead of retried forever.

**Firewall-Collector** — `internal/relay/relay.go:2081` · class: `correctness`

**Defect.** isRetryableStatus's switch omits 413/414 → default:return true; sendBatch replays the byte-identical body (content-derived batch ID), so a body exceeding a proxy/server cap once exceeds it every retry. doDirectSend has the same hole for metric payloads.

**Failure scenario.** Behind an nginx client_max_body_size 1MiB a 1000-item syslog batch 413s → requeued as transient → rejected again every 30s forever, burning 3 attempts+backoff each cycle and (with the drained-tail bug) destroying the rest of every drain it heads.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-288 · LOW · One 404 on /flow-counters permanently collapses the negotiated schema to v1, silently disabling v3-v5 features (disk/load, command channel incl. IPSec deploys, topology) until a collector restart

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — a 404 on /flow-counters no longer silently disables half the collector.

**Firewall-Collector** — `internal/relay/relay.go:2136` · class: `correctness`

**Defect.** sendBatch stores negotiatedSchema=1 on a /flow-counters 404 but leaves approved=true, so Register() (the only re-negotiation) never re-runs. Every higher feature gates on that same atomic (handlePendingCommands <4, SendDiskUsage/LoadAverage <3, Topology <5), while the server keeps using probe.SchemaVersion (persisted 5).

**Failure scenario.** A brief server rollback or a proxy/deploy 404 on one /flow-counters POST → collector stores schema=1: SendDiskUsage/LoadAverage return nil successfully (no log), topology skipped, heartbeat pending_commands ignored while the server re-delivers admin-enqueued IPSec deploy/status commands until they expire — recovery needs a restart. The intended effect needed only a v2 gate.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-289 · LOW · Six relay Send* methods read c.probeID without c.mu, racing the mutex-guarded write in finishRegister during re-registration

> **✅ RESOLVED (collector v1.3.37 · PR #101)** — six unsynchronized probe-ID reads fixed with GetProbeID().

**Firewall-Collector** — `internal/relay/relay.go:2274` · class: `concurrency` · related: `cmd/collector/main.go`

**Defect.** SendConfigRevision (2274), SendProcessSnapshot (2456), SendInterfaceErrorSnapshot (2476/2499), SendSensorDetails (2522), SendLicenseDetails (2545) use bare fmt.Sprint(c.probeID); the field is written under c.mu in finishRegister (concurrently on heartbeat/dataSend/poll re-register paths). The GetProbeID() accessor exists and is used by every other sender.

**Failure scenario.** During a server-forced re-registration that changes the probe ID, an SSH-poll send reads c.probeID concurrently — a data race -race flags; in the torn window a stale ID posts to the wrong /api/probes/:id/ path → 404/403 bouncing a config backup into retry and churning re-registration. Mechanical fix: use c.GetProbeID().

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-290 · LOW · computeTraffic divides counter deltas by the nominal bucket width, not actual inter-bucket spacing — sparse buckets inflate report throughput and synthesize false spikes

> **✅ RESOLVED (v0.11.227 · PR #235)** — report throughput no longer inflates across polling gaps.

**Firewall-Mon** — `internal/report/data.go:119` · class: `correctness` · related: `internal/database/charts.go`, `internal/report/spike.go`, `internal/report/report.go`

**Defect.** bps=delta*8/bucketSeconds and windowSeconds=bucketSeconds*(len-1) use the fixed nominal width, but GetInterfaceChartData does no gap-fill, so buckets are pollInterval apart (>60s) and a post-outage bucket carries the whole gap's growth. The correct per-bucket timestamps are already parsed but unused as the denominator.

**Failure scenario.** A 300s poll interval inflates PeakBps/AvgBps/sparkline 5×; a 3h outage on a 7d/hourly series makes the recovery bucket read 3× → detectSpikesTimeOfDay reports a phantom critical spike at reconnect. Fix: divide each delta by times[i].Sub(times[i-1]).

**Fix direction.** divide each delta by times[i].Sub(times[i-1]).

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-291 · LOW · BuildDailyReport/BuildWeeklyReport render the EMAIL layout (cid: image refs) but discard the attachments, so the HTML references images that are never attached

> **✅ RESOLVED (v0.11.227 · PR #235)** — exported report wrappers no longer discard their chart attachments (latent).

**Firewall-Mon** — `internal/report/email.go:28` · class: `contract-drift` · related: `internal/report/template_report.go`

**Defect.** email.go:14/19 document BuildDailyReport/BuildWeeklyReport as 'self-contained HTML ... (no attachments).' But both route through buildReport -> BuildReport(..., collapsible=false) -> BuildReportWithOps, where line 58 sets m.IsEmail = !collapsible => true, so line 76 takes renderEmailWithCharts(m), which sets ChartCID/AlertChartCID and the template emits `<img src="cid:{{$d.ChartCID}}">` (template_report.go:454) and `cid:{{.AlertChartCID}}` (256). BuildReport then discards the attachments: email.go:29 `subject, html, _, _, err := BuildReportWithOps(...)`. The cid: parts have no backing MIME parts. Live email/preview paths call BuildReportWithOps directly and keep atts, so today these three exported wrappers are reached only by tests — a latent trap, not a live outage.

**Failure scenario.** A future caller trusts the doc comment and uses BuildDailyReport/BuildWeeklyReport to send a report (exported, named as the obvious entry points, documented 'no attachments'). The email goes out with `<img src="cid:report_cpumem_0">`/`cid:report_alerts` tags but zero attachments, so every chart renders as a broken-image chip and the 'no attachments' promise is false in the code as written.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-292 · LOW · RollingStats/AddAndCheck is dead code that z-scores raw cumulative octet counters — the exact bug class v0.10.236 removed

> **✅ RESOLVED (v0.11.228 · PR #236)** — removed the dead RollingStats type and its circularBuffer helper.

**Firewall-Mon** — `internal/report/spike.go:537` · class: `maintainability`

**Defect.** AddAndCheck(...,inBytes,outBytes,...) feeds float64(inBytes+outBytes) straight into mean+k*std; zero callers repo-wide. The same file (29-35) documents that running std-dev on a monotonic octet counter made the old detector fire constantly.

**Failure scenario.** No runtime failure today, but the first caller wiring per-poll counters in reinstates the always-firing spike detector the v0.10.236 rewrite removed. Delete the type or convert it to a bps-delta API.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-293 · LOW · Shared IfTypeNames maps have drifted: collector lacks 47/gre and 209/bridge, leaving TypeName empty for FortiGate LAN (bridge) and GRE at the source — currently masked by a server-side ingest backfill

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — batch-14 SNMP counter/attribution correctness plus observability wiring.

**cross-repo** — `internal/snmp/snmp.go:70` · class: `contract-drift`

**Defect.** Collector map (10 entries) lacks 47:gre and 209:bridge that the server map has; the server heals it at ingest (handlers_data.go:888). Type 209 is where FortiGate LAN IPs live. Vendor registry and TrapOIDs maps are otherwise in parity.

**Failure scenario.** No live misbehavior (server backfill compensates), but the 'same' maps already diverged unnoticed; any collector-side TypeName consumer sees '' for bridge/GRE, and if the backfill is ever removed FortiGate LAN type_name goes empty, breaking connection-map direct-link coloring. Fix: add 47/209 or pin with a cross-repo parity test.

**Fix direction.** add 47/209 or pin with a cross-repo parity test.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-294 · LOW · GetInterfaceStats packet/error counters read only 32-bit ifInUcastPkts although the code already walks ifXTable where ifHCInUcastPkts live

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — batch-14 SNMP counter/attribution correctness plus observability wiring.

**Firewall-Collector** — `internal/snmp/snmp.go:345` · class: `data-integrity`

**Defect.** InPackets/OutPackets read Counter32 ifInUcastPkts/ifOutUcastPkts; the ifXTable walk (384-422) upgrades bytes to ifHCInOctets but never reads ifHCInUcastPkts(.7)/ifHCOutUcastPkts(.11).

**Failure scenario.** A LAN port at ~200 Kpps wraps the 32-bit packet counter every ~6h; each wrap looks like a reset to the delta pipeline → packet-rate samples periodically discarded/clamped on the busiest interfaces (byte charts unaffected). One-line fix in the existing ifXTable walk.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-295 · LOW · dot1qPvid is indexed by dot1dBasePort but the code uses the index as ifIndex — VLAN IDs attach to the wrong interface on devices where bridge-port numbering diverges

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — batch-14 SNMP counter/attribution correctness plus observability wiring.

**Firewall-Collector** — `internal/snmp/snmp.go:425` · class: `correctness`

**Defect.** dot1qPvid instances are indexed by dot1dBasePort; the code indexes the ifIndex-keyed interfaces map directly with the base-port number, missing the dot1dBasePortIfIndex mapping.

**Failure scenario.** On a switch/bridge where base ports are offset from ifIndex, PVID 20 for base port 3 is written onto ifIndex 3 (a different interface) — wrong VLAN attribution into L2VLAN typing; when no ifIndex matches the VLAN silently vanishes. Both invisible without device cross-check.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-296 · LOW · Vendor enterprise traps are never classified: parseTrap matches varbind NAMES against notification OIDs that only ever arrive as the snmpTrapOID.0 VALUE

> **✅ RESOLVED (v0.11.220 · PR #228)** — vendor enterprise traps are classified by the snmpTrapOID.0 varbind value.

**Firewall-Mon** — `internal/snmp/trap.go:257` · class: `correctness` · related: `cmd/trap-receiver/main.go`, `internal/snmp/vendor_fortigate.go`, `internal/snmp/vendor_paloalto.go`, `internal/snmp/vendor_sonicwall.go`

**Defect.** Phase-2 loops lookupTrapOID(v.Name), but the notification identity (e.g. fgTrapVPNTunnelDown .1.3.6.1.4.1.12356.101.2.0.302) is the VALUE of snmpTrapOID.0; varbind names are payload objects never in any TrapOIDs() map. parseLinkTrap correctly reads v.Value; SNMPv1 Enterprise/SpecificTrap also unread. No test covers the vendor phase.

**Failure scenario.** A FortiGate VPN_TUNNEL_DOWN v2c trap → every varbind-name lookup misses → parseTrap returns nil → no TrapEvent, no ProcessTrap, no notification. Every enterprise trap (VPN/HA/IPS/AV/hw) is silently discarded; only linkUp/linkDown work.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-297 · LOW · Server ifTable prefix-match in parseLinkTrap misclassifies varbind columns 10-19/20-29 as ifIndex/ifDescr (HasPrefix with no dot boundary)

> **✅ RESOLVED (v0.11.220 · PR #228)** — link-trap interface-column matching now uses exact OID boundaries.

**Firewall-Mon** — `internal/snmp/trap.go:321` · class: `correctness`

**Defect.** Verified: oidIfIndex = ".1.3.6.1.2.1.2.2.1.1" and oidIfDescr = ".1.3.6.1.2.1.2.2.1.2" (trap.go:47-48) are matched with `strings.HasPrefix(oid, oidIfIndex)` / `HasPrefix(oid, oidIfDescr)` (trap.go:321/323) with no trailing-dot boundary. `.1.3.6.1.2.1.2.2.1.1` is a literal prefix of ifTable columns 10-19 (e.g. ifInOctets .1.3.6.1.2.1.2.2.1.10.<idx>), and `.1.3.6.1.2.1.2.2.1.2` is a prefix of columns 20-29 (e.g. ifOutErrors .1.3.6.1.2.1.2.2.1.20.<idx>). The ifIndex case is first and each uses plain assignment, so the last matching varbind wins and overwrites the true ifIndex/ifDescr.

**Failure scenario.** A trap (crafted, or a verbose vendor trap bundling interface counters) carries both the real ifIndex varbind .1.3.6.1.2.1.2.2.1.1.5 (value 5) and an ifInOctets varbind .1.3.6.1.2.1.2.2.1.10.5 (value 4000000000). Both satisfy HasPrefix(oid, oidIfIndex); the later wins, so the persisted LINK_DOWN/LINK_UP alert message shows ifIndex=4000000000 and a garbage interface identity.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-298 · LOW · Firewalla fan-sensor parsing is dead code — walk base OID excludes the fan subtree

> **✅ RESOLVED (collector v1.3.41 · PR #105)** — batch-14 SNMP counter/attribution correctness plus observability wiring.

**Firewall-Collector** — `internal/snmp/vendor_firewalla.go:202` · class: `correctness` · related: `internal/snmp/snmp.go`

**Defect.** HWSensorBaseOID() returns only the temperature subtree fwBaseOIDLmTempSensor = .1.3.6.1.4.1.2021.13.16.2.1; GetHardwareSensors does a single WalkAll(baseOID) (snmp.go:586). The fan branches match fwOIDLmFanSensorDescr/Value under .13.16.3.1 — a sibling subtree the .13.16.2.1 walk never enters. The comment hedges 'if present in same walk — different subtree.'

**Failure scenario.** A Firewalla exposing lm-sensors fan data via snmpd is polled; the subtree walk terminates before reaching .13.16.3.1, so no fan OIDs return and the fan-parsing branches (202-222) never execute → fan RPM silently absent with no error, while the code reads as if fan monitoring works.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-299 · LOW · rangeToCIDR validates only XOR contiguity, not that begin is the network address — non-aligned IP ranges are misrendered as wrong CIDR blocks

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — non-aligned selector ranges render as explicit ranges instead of wrong CIDR blocks.

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:477` · class: `correctness`

**Defect.** The function checks only that begin^end is 0...01...1 and never that begin's host bits are zero: rangeToCIDR('10.0.1.255','10.0.2.0')→XOR 0x03FF passes→'10.0.1.255/22' (a 2-address range rendered as 1024 addresses).

**Failure scenario.** A FortiGate dialup phase-2 iprange selector (not subnet-aligned) produces a Local/RemoteSubnet CIDR covering up to 512× more/different space than selected, feeding wrong data to the IPSec map and canonical keys. Fix: require begin&hostmask==0 or fall back to begin-end form.

**Fix direction.** require begin&hostmask==0 or fall back to begin-end form.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-300 · LOW · FortiGate voltage sensors labeled unit "mV" while fgHwSensorEntValue reports volts

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — FortiGate voltage sensors report V, not mV (collector path).

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:572` · class: `correctness`

**Defect.** inferSensorUnit voltage case sets `s.Type="voltage"; s.Unit="mV"`. The value comes from safeFloat(pdu.Value) where fgHwSensorEntValue is a DisplayString float like '52.500000' (the code's own comment, line 529). FortiGate voltage rails report decimal volts (e.g. '12.070000', '3.300000'), not integer millivolts — value in volts, unit says mV.

**Failure scenario.** A +12V rail returns '12.070000'; safeFloat yields 12.07 and inferSensorUnit stamps Unit='mV', so it stores/displays '12.07 mV' — a 1000x mislabel corrupting any voltage display or threshold comparison that trusts the unit. FortiGate is the user's primary vendor.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-301 · LOW · Server-side FortiGate voltage sensors report volts labeled 'mV' on the LIVE dashboard hardware-sensor path (not just the collector's dead probe path)

> **✅ RESOLVED (v0.11.220 · PR #228)** — FortiGate voltage sensors report V instead of mV on the server SNMP path.

**Firewall-Mon** — `internal/snmp/vendor_fortigate.go:634` · class: `correctness`

**Defect.** inferSensorUnit (vendor_fortigate.go:634) sets `s.Type="voltage"; s.Unit="mV"` for names matching vcc/vdd/+1./+3./+12/volt, but the value is `sensor.Value = safeFloat(pdu.Value)` from fgHwSensorEntValue, which FortiGate reports in VOLTS (e.g. "12.031", "3.300"). So a 12V rail renders as "12 mV". Distinct from the accepted collector filing: verified this server copy is reachable LIVE — h.snmpClient is set from cmd/api/main.go:420 snmp.NewSNMPClient(cfg), and handlers_dashboard.go:571 calls h.snmpClient.GetHardwareSensors() -> ParseHardwareSensors -> inferSensorUnit in single-firewall/dashboard SNMP mode, whereas the collector twin lives on a dead probe path. The regression test vendor_fortigate_test.go asserts only temperature (C) and fan (RPM); the voltage branch has no coverage.

**Failure scenario.** A directly-polled (single-firewall/dashboard-mode) FortiGate with power-supply voltage sensors shows every rail ~1000x too small with unit mV (12V shown as 12 mV) on the server dashboard. Because both repos hardcode the identical wrong unit, a cross-repo consistency test would pass while both remain wrong — the shared-bug blind spot.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-302 · LOW · PaloAlto hardware-sensor 'alarm' status is unreachable: status==3 rows are skipped before the alarm branch that tests status==3 (server + collector copies)

> **✅ RESOLVED (v0.11.220 · PR #228 ; collector v1.3.41 · PR #105)** — Palo Alto nonoperational hardware sensors (operStatus 3) now report alarm instead of being dropped, at both server and collector.

**cross-repo** — `internal/snmp/vendor_paloalto.go:306` · class: `correctness`

**Defect.** Loop `if sd.status==2 || sd.status==3 { continue }` precedes `if sd.status==3 { alarmStatus="alarm" }`, so nonoperational(3) sensors are dropped and the alarm assignment is dead; every emitted PA sensor is hardcoded 'normal'. Identical in Firewall-Collector/internal/snmp/vendor_paloalto.go:279.

**Failure scenario.** A PA fan/PSU goes nonoperational(3) → the sensor silently disappears from telemetry instead of reporting Status 'alarm' → no hardware alert exactly when a sensor matters — failure-reads-as-healthy.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-303 · LOW · ParsePerformanceStatus truncates FortiOS uptime to whole days — hours/minutes discarded, fresh-booted devices report Uptime=0 for 24h

> **✅ RESOLVED (collector v1.3.39 · PR #103)** — SSH uptime parsing keeps hours and minutes, not just whole days.

**Firewall-Collector** — `internal/ssh/parser.go:423` · class: `correctness`

**Defect.** uptimeRegex captures only `(\d+)\s+days` from 'Uptime: 20 days, 3 hours, 26 minutes' → info.Uptime=days*86400, dropping up to 23h59m.

**Failure scenario.** perf.Uptime feeds the SSH system_status writer; a firewall rebooted 2h ago shows uptime 0 all day, and a same-day reboot produces no observable uptime decrease from this source — masking restarts from consecutive-uptime comparisons. Extend the regex to capture hours/minutes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-304 · LOW · internal/syslog and internal/sflow are orphaned dead forks (unreachable since cmd/probe removal) still receiving audit fixes, carrying confirmed bugs the collector already fixed (TCP framing aliasing, non-digit PRIVAL, sflow double-return)

> **✅ RESOLVED (v0.11.228 · PR #236)** — removed the orphaned dead internal/ping package.

**Firewall-Mon** — `internal/syslog/syslog.go:171` · class: `maintainability` · related: `internal/sflow/sflow.go`, `internal/syslog/fuzz_audit119_test.go`, `internal/sflow/fuzz_audit119_test.go`

**Defect.** go list -deps ./cmd/... excludes internal/syslog and internal/sflow (zero importers since cmd/probe removal). Confirmed latent bugs: (a) TCP handleConnection sets line:=data[:idx] then messageBuf.Reset()+Write(data[idx+1:]) memmoves the tail over line BEFORE ParseRFC5424 — repro shows message 0 corrupted, message 1 parsed twice; (b) ParsePriority/bytesToInt accepts non-digit PRIVAL ('<abc>'→severity 0 Emergency) and overflows long digit runs negative; (c) sflow readLoop has both branches return. The collector's live twins fixed all three (M6, L10, REL-01).

**Failure scenario.** Audit effort keeps landing on zero-runtime-effect code, and the forks sit one accidental import away from reviving pre-audit parsing (coalesced-line corruption, severity-0 Emergency retention). Fix: delete both packages or replace with the collector-consistency tests.

**Fix direction.** delete both packages or replace with the collector-consistency tests.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-305 · LOW · UDP syslog logs one line per malformed datagram — the exact log-flood vector the TCP path's M16 fix removed

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — replaced the per-datagram UDP syslog parse-error log with a firewall_collector_syslog_parse_errors_total metric.

**Firewall-Collector** — `internal/syslog/syslog.go:411` · class: `input-hardening`

**Defect.** UDP path log.Printf's every ParseRFC5424 error; the TCP path (202-204) deliberately `continue`s without logging (M16: 'a flood would DoS the log'). The UDP rate limiter bounds volume but at the legitimate-traffic budget.

**Failure scenario.** A LAN host streams garbage UDP just under the syslog PPS budget → a log.Printf per datagram fills the journal/disk at the full allowed rate indefinitely. Fix: drop the per-datagram log, count via metric.

**Fix direction.** drop the per-datagram log, count via metric.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-306 · LOW · TFTP writeHandler runs on an untracked goroutine — Shutdown() returns while a just-received config upload is still being relayed

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — the TFTP writeHandler goroutine is now tracked by the server WaitGroup so Shutdown waits for an in-flight config-revision send.

**Firewall-Collector** — `internal/tftp/tftp.go:319` · class: `concurrency`

**Defect.** handleWRQ launches the handler in a `go func(){...}()` not registered with s.wg, so Shutdown()'s s.wg.Wait() doesn't wait for it (the device already got its final ACK before the handler runs).

**Failure scenario.** Collector shutdown right after a firewall completes a TFTP upload: Shutdown returns while the prod handler is mid-SendConfigRevision → the revision is silently lost though the firewall believes the backup succeeded. Fix: s.wg.Add(1)/Done around it or run synchronously.

**Fix direction.** s.wg.Add(1)/Done around it or run synchronously.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-307 · LOW · TFTP handleRRQ bypasses the AUDIT-050 source-IP allowlist and rate limit that handleWRQ enforces

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — handleRRQ now applies the same allowlist + rate-limit guards as handleWRQ.

**Firewall-Collector** — `internal/tftp/tftp.go:334` · class: `input-hardening`

**Defect.** handleRRQ runs the read handler with no isSourceAllowed()/checkAndUpdateRateLimit() (handleWRQ has both); serve() also logs one line per RRQ/WRQ before any allowlist check.

**Failure scenario.** Today latent (no SetHandler in prod), but the SetAllowedSourceIPs doc says only WRQs are restricted; the first future ReadHandler (e.g. serving a config back for restore) exposes data to every host reachable on UDP/69 with no rate limit. Cheap fix: gate handleRRQ identically and move the per-packet log after the check.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-308 · LOW · web/admin/README.md lists probe-pending.html as an existing standalone page; the file and its route are gone

> **✅ RESOLVED (v0.11.231 · PR #239)** — removed stale admin-page references (probe-pending.html) and corrected the SPA route list.

**Firewall-Mon** — `web/admin/README.md:8` · class: `docs-drift` · related: `README.md`, `cmd/api/main.go`, `web/admin/admin.html`

**Defect.** web/admin/README.md names probe-pending.html among 'remaining separate full-page documents' but web/admin/ has only admin.html, connection-detail.html, device-detail.html, login.html and no /admin/probe-pending route; top-level README repeats it (plus 'interfaces').

**Failure scenario.** A contributor asked to change the pending-probe screen searches for probe-pending.html, finds nothing, and burns time rediscovering it was folded into the SPA; route-coverage auditors chase two 404 routes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

### INFO (10)

#### AUDIT-309 · INFO · Collector still on go1.25.12 with 5 reachable stdlib CVEs the server already patched; CI go-version hardcode has drifted

> **✅ RESOLVED (collector v1.3.35 · PR #99)** — under the pinned go1.25.13 toolchain govulncheck reports zero reachable vulnerabilities (residual verified clean).

**Firewall-Collector** — `go.mod:3` · class: `security`

**Defect.** go.mod:3 `go 1.25.12` vs server 1.25.13 (v0.11.208 bump); verified GOTOOLCHAIN=go1.25.12 govulncheck ./... reports 5 reachable stdlib vulns (GO-2026-6218 net/url, 6090 crypto/tls, 6089 net/http, 5972 encoding/asn1, 5026 net/http) via fwapi/observability/relay TLS. docker.yml:20 also hardcodes go-version 1.25.11 instead of go-version-file.

**Failure scenario.** Deployed collector images embed the vulnerable net/http/tls/asn1 on hosts inside customer management LANs; the next push to collector master fails the govulncheck gate (GOTOOLCHAIN=auto resolves 1.25.12) and since build needs:test, ALL releases block until go.mod bumps to 1.25.13.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-310 · INFO · Validate() emits stale pre-AUDIT-008 warnings: 'tokens invalidated on restart' and 'database credentials will not be encrypted' are both false now

> **✅ RESOLVED (v0.11.211 · PR #219)** — corrected stale startup warnings about key generation and token invalidation.

**Firewall-Mon** — `internal/config/config.go:666` · class: `docs-drift` · related: `cmd/api/main.go`, `internal/secrets/secrets.go`

**Defect.** Both warnings are contradicted by the AUDIT-008 secrets.LoadOrGenerate flow that runs right after Validate() in all three daemons, persisting the JWT secret (tokens survive restart) and deriving the AES key (creds encrypted).

**Failure scenario.** An operator on the recommended empty-key config reads two authoritative-sounding false warnings, prompting unnecessary key-management churn and eroding trust in real warnings. Reword to reflect the persisted-secret flow.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-311 · INFO · SearchThreatIntel builds a LIKE pattern without escaping % / _ wildcards in the operator query

> **✅ RESOLVED (v0.11.216 · PR #224)** — threat-intel search treats % and _ as literals in the SQL LIKE pattern.

**Firewall-Mon** — `internal/database/threat_intel.go:178` · class: `input-hardening`

**Defect.** threat_intel.go:177-179: `if f.Query != "" { q = q.Where("cidr LIKE ?", "%"+f.Query+"%") }`. The raw operator query is embedded into a LIKE pattern with no ESCAPE handling, so `%` and `_` act as SQL wildcards rather than literals.

**Failure scenario.** An admin searching the threat-intel table for a literal underscore or percent (or pasting a value containing one) gets over-broad matches — e.g. querying 10_0 matches 10.0/10x0/etc. — so the admin search returns misleading result sets. No injection (parameterized), purely a correctness/UX defect in a rarely-hit admin path.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-312 · INFO · DeniedEvent PolicyName/Service stored uncapped — capStr row-bloat guard applied only to country fields

> **✅ RESOLVED (v0.11.216 · PR #224)** — denied-event ingest validation and bounds (paired with AUDIT-272).

**Firewall-Mon** — `internal/deny/project.go:157` · class: `input-hardening` · related: `internal/models/models.go`, `internal/database/ping.go`, `internal/api/handlers/handlers_data.go`

**Defect.** capStr (doc: 'bounds a stored FortiGate field so a crafted log can't bloat a row') is applied only to SrcCountry/DstCountry (48). PolicyName and Service are copied verbatim (`f["policyname"]`, `f["service"]`). models.DeniedEvent.PolicyName/Service are plain string → unbounded Postgres text, and SaveDeniedEvents (database/ping.go:230) batch-inserts with no length clamp.

**Failure scenario.** A misconfigured/compromised FortiGate (or rogue sender behind the authenticated relay) emits a deny line with a multi-kilobyte policyname/service (up to ~64KB). deny.Project copies it into the unbounded column; denied_events is a short-retention monthly-partitioned table sized for compact rows, so at deny-storm volume it bloats far beyond design — exactly what capStr was written to prevent.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-313 · INFO · IKEv1 + AES-GCM passes validation and conformance for FortiGate, but FortiOS accepts GCM only on IKEv2 — deploy fails on-device and auto-rolls back

> **✅ RESOLVED (v0.11.225 · PR #233)** — FortiGate IKEv1 plus a GCM (AEAD) IKE cipher is now blocked at validation/preview.

**Firewall-Mon** — `internal/ipsec/vendors/fortigate/fortigate.go:110` · class: `contract-drift` · related: `internal/ipsec/validation.go`, `internal/ipsec/conformance/fortigate.go`, `internal/api/handlers/handlers_ipsec.go`, `cmd/api/static/js/admin-ipsec.js`

**Defect.** The pkg doc states 'GCM is IKEv2-only' but nothing enforces it: Capabilities advertises IKEv1 and GCM as independent sets, Render emits both, validation only warns ikev1_deprecated, and conformance fgIKEProposal validates version-agnostically. Wizard offers both.

**Failure scenario.** Custom profile with IKEv1 + AES-256-GCM passes preview/validation/conformance; FortiOS rejects the phase1 POST mid-apply → live deploy fails and auto-rolls back — the fwm-t3 class conformance exists to catch pre-dispatch.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-314 · INFO · IRC sendWithTimeout abandons a permanently-parked sender goroutine per send during a wedged connection — the code's own 'bounded, self-reclaiming' comment is wrong in the wedge because close(pwrite) is never reached, so goroutines + dead-conn refs accumulate for the life of the process

> **✅ RESOLVED (v0.11.223 · PR #231)** — a wedged IRC connection no longer accumulates parked senders (paired with AUDIT-206).

**Firewall-Mon** — `internal/irc/bot.go:1254` · class: `resource-leak`

**Defect.** Confirmed by reading bot.go:1235-1285. sendWithTimeout spawns a goroutine per send that calls `send()` (conn.Privmsg -> go-ircevent's 10-slot pwrite channel) then `done <- nil`; on the 15s timer it logs 'abandoning parked sender' and returns an error, leaving the goroutine parked. The function's own doc states that once writeLoop dies the pwrite buffer fills and a bare send 'parks FOREVER — Disconnect() cannot free it, because its irc.Wait() deadlocks on the library's own pingLoop parked on the same full channel, so close(pwrite) is never reached', then characterizes it as 'a bounded leak of one goroutine ... per quiet-death event, self-reclaiming if a later close(pwrite) panics the parked send.' The self-reclaim path is, per the same comment, unreachable in the wedge — contradicting 'bounded/self-reclaiming'. Every send routes here: safePrivmsg/safeNotice (1275/1279), sendAutoStatus status-box sends, and alert delivery via SendToChannel->SendMessage->safePrivmsg.

**Failure scenario.** A bot's InspIRCd connection quiet-deaths (writeLoop dead, socket half-open, Connected() still true — the documented 2026-08 prod wedge). statusLoop fires every 30s -> sendAutoStatus -> safePrivmsg parks a goroutine on the full pwrite buffer; after 15s the caller returns a timeout and abandons it. Because Disconnect()'s irc.Wait() deadlocks, close(pwrite) is never reached, so the parked goroutine never exits — the self-reclaim escape hatch cannot fire in exactly the scenario it was built for. Each subsequent send against that conn (every 30s status tick until reconnect swaps the conn, plus every alert delivery) leaks another goroutine pinning a dead *irc.Connection and its message string. Under the documented reconnect churn the count grows monotonically for the process lifetime rather than being 'bounded per quiet-death event'.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-315 · INFO · RestartBot spawns Bot.Start without the REL-01 panic recover its two sibling launch sites have — one panic crashes all of fwmon-api

> **✅ RESOLVED (v0.11.223 · PR #231)** — RestartBot no longer launches Bot.Start on an unguarded goroutine (panic-recovering).

**Firewall-Mon** — `internal/irc/bot.go:1370` · class: `concurrency`

**Defect.** RestartBot: `go func(){ defer m.wg.Done(); newBot.Start() }()` with no defer logging.Recover; loadAndStartBots (193) and reconnectLoop (268) both guard with Recover-first. The file's M8 comment documents un-recovered IRC panics crash the whole fwmon-api process.

**Failure scenario.** Admin clicks Restart on an IRC server whose config triggers any panic in Bot.Start → the unguarded goroutine kills the entire fwmon-api (admin UI, ingestion, NOC) instead of being contained. One-line fix: add defer logging.Recover("irc-bot").

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-316 · INFO · Server internal/sflow and internal/syslog receiver packages are dead — no cmd binary depends on them; they duplicate the collector's live parsers and can silently drift

> **✅ RESOLVED (v0.11.228 · PR #236)** — removed the orphaned dead internal/syslog package.

**Firewall-Mon** — `internal/sflow/sflow.go:68` · class: `maintainability` · related: `internal/syslog/syslog.go`, `internal/api/handlers/handlers_data.go`

**Defect.** `go list -deps ./cmd/...` includes neither firewall-mon/internal/sflow nor internal/syslog, and no non-test constructor of NewSFlowReceiver/NewSyslogReceiver/SyslogServer exists. Live syslog/sflow ingest is the collector-relay HTTP handlers (ReceiveSyslogMessages/ReceiveFlowSamples) binding already-parsed models. The 562-line syslog and 506-line sFlow receivers (incl. the bytes×sampling_rate block mirroring the collector) run in no server process.

**Failure scenario.** A maintainer may 'fix' input-hardening in these unreachable server packages while prod ingest is untouched, or a scaling/semantics fix landed in the collector diverges here with no compile/test signal. Reframes edge-ingest scope: input-hardening bugs in these two server packages are NOT reachable in production.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-317 · INFO · Collector trap community check uses non-constant-time != — the server twin's AUDIT-012 subtle.ConstantTimeCompare hardening never propagated to the actual network-facing receiver

> **✅ RESOLVED (collector v1.3.43 · PR #107)** — the SNMP trap community check uses subtle.ConstantTimeCompare (parity with the server twin).

**Firewall-Collector** — `internal/snmp/trap.go:114` · class: `security`

**Defect.** allowCommunity compares attacker-supplied community against the shared secret with a plain short-circuiting `if community != t.community { ...; return false }` (trap.go:114-121). The Firewall-Mon twin was explicitly hardened under AUDIT-012 with subtle.ConstantTimeCompare and a comment explaining the prefix-length leak the != caused; the collector never imports crypto/subtle and never got the fix, despite being the ACTUAL deployed network-facing trap receiver. Documented server-side hardening that drifted out of twin parity. NOTE: exploitability is essentially nil today — SNMP traps are one-way with no response whose latency reflects the compare — so this is a parity/hygiene note, load-bearing only if a future change adds an observable per-trap timing signal.

**Failure scenario.** With a community configured, the byte-by-byte short-circuit compare's duration correlates with the guessed prefix length — the side channel AUDIT-012 closed server-side. Not directly observable over one-way UDP today, but any later addition of an observable per-trap timing signal (metrics, response, downstream effect) resurrects the leak the server already fixed on the twin.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-318 · INFO · Uptime tracker is never fed: RecordUptime/SaveUptimeRecord have zero callers, so /api/uptime and dashboard uptime_stats serve permanently-zero, fabricated data

> **✅ RESOLVED (v0.11.229 · PR #237)** — wired the device uptime tracker (previously dead).

**Firewall-Mon** — `internal/uptime/uptime.go:100` · class: `contract-drift` · related: `internal/api/handlers/handlers_analytics.go`, `internal/api/handlers/handlers_dashboard.go`, `cmd/api/main.go`, `internal/database/events.go`

**Defect.** RecordUptime and database SaveUptimeRecord have no callers; downtime field never written, so TotalDowntime is structurally 0 and CalculateFiveNines returns a constant '315.58 seconds remaining'. Yet /api/uptime, dashboard UptimeData and public uptime_stats serve it live. Feeding call lost when server direct-poll was retired (v0.11.74).

**Failure scenario.** An admin opening the uptime view (or hitting GET /api/uptime) gets uptime_percent 0, empty history, and a confident fabricated five-nines figure presented as monitoring data; reset appears to work but changes nothing.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

## Appendix A — Refuted candidates (do NOT re-flag)

These candidates were raised by a finder but **killed by ≥2 refuter lenses**. Recorded so future audits don't re-raise them.

- **ReceiveLicenseInfo is the only replay-exposed direct-send endpoint without the AUDIT-042 batch dedup — a timeout-after-commit replay inserts** — `internal/api/handlers/handlers_data.go:1079` — refuted: misread-behavior.
- **Flows detection modal fetches nonexistent route /admin/api/flows/samples — sampled-flows section always fails** — `cmd/api/static/js/admin-flows.js:705` — refuted: mitigated-elsewhere, overstated-no-residual.
- **Collector CI hardcodes go-version 1.25.11 instead of go-version-file, silently defeating the 'bump go.mod is the whole fix' patch flow** — `.github/workflows/docker.yml:20` — refuted: misread-behavior, mitigated-elsewhere, overstated-no-residual.
- **device-detail esc() leaves quotes unescaped → attribute-injection stored XSS from device-supplied strings** — `cmd/api/static/js/admin-device-detail.js:2556` — refuted: mitigated-elsewhere.
- **In-flight device-WRITE commands are neither drained on shutdown nor deduped across restart — SIGTERM mid-apply + at-least-once redelivery re** — `cmd/collector/commands.go:256` — refuted: mitigated-elsewhere.
- **Forged/spoofed LINK_UP trap silently auto-resolves AND auto-acknowledges a genuine LINK_DOWN alert, bypassing every policy/severity/cooldown** — `internal/alerts/alerts.go:540` — refuted: misread-behavior, mitigated-elsewhere, unrealistic-preconditions.
- **digestSecrets breaks the 1:1 line-count invariant MaskVolatileLines depends on, disabling all volatile folding (and re-leaking secrets) for ** — `internal/configdiff/vendor_opnsense.go:228` — refuted: overstated-no-residual, unreachable.
- **UpsertAutoConnection uses the documented Model(loaded).Updates(map) FK-clobber anti-pattern while its sibling UpsertAutoL2Connection uses th** — `internal/database/devices.go:326` — refuted: misread-behavior, overstated-no-residual.
- **FortiGate SSL-VPN user/tunnel scalars use scalar suffix .0 on VDOM-indexed table columns — fgVpnSslStatsLoginUsers/ActiveTunnels always NoSu** — `internal/snmp/vendor_fortigate.go:36` — refuted: intended-and-documented.
- **Server-side FortiGate VPN SNMP OID mappings (dialup table + site-to-site mask columns) are wrong and drift from the collector's correct mapp** — `internal/snmp/vendor_fortigate.go:45` — refuted: intended-and-documented, unreachable.
- **BackupConfigSCP embeds the SCP password in the FortiOS CLI command line (device-audit-logged) — and is dead code with no caller** — `internal/ssh/ssh.go:410` — refuted: unreachable.

## Appendix B — Standing do-not-re-flag (accepted-risk / by-design)

Carried from prior audits and confirmed still intentional: HSTS-behind-proxy; threat-feed env-only URL; proxy rate-limit (AUDIT-097); NOC SSE admin-only ceiling; SSH alert-only TOFU (AUDIT-071); AuthManager bcrypt mutex / login-map pruner; single-admin `user_id=1` fallback; MD5 config-checksum; documented `gosec` excludes; FortiGate SSL-VPN OID 12.3.1.1 (WONTFIX — feature unused, returns `noSuchObject`→0); `tunnel_uptime` FortiGate semantics; dashboard `computing`-sentinel; poller-as-alert-engine split; obsolete server `cmd/probe`.

## Findings surfaced during remediation (AUDIT-319+)

These were noticed while remediating the 148 findings above. They are **not** dispositions of the original 148 — they are new items, now assigned ids and verified refute-by-default (next free id is AUDIT-327).

### AUDIT-319 — Server — IRC SASL error path strands loops and a socket per attempt (MED)

`internal/irc/bot.go`: go-ircevent's `Connect()` allocates the socket and spawns `readLoop`/`writeLoop`/`pingLoop` **before** it negotiates capabilities, then returns the `negotiateCaps` error without unwinding any of it. `Bot.Start`'s error branch dropped the connection without a `Disconnect()`, so a SASL server rejecting our credentials stranded `writeLoop`, `pingLoop` and the socket — repeated by the manager's 30s reconnect sweep for the life of the process. (`readLoop` does exit on its own 16-minute read deadline; the other two never observe `end` close.)

> **✅ RESOLVED (v0.11.234 / #242)** — teardown added to the Connect-error branch, gated on `conn.ErrorChan() != nil`. That gate is load-bearing: `Connect` allocates `irc.Error` immediately before `irc.Add(3)`, so a nil channel means it bailed during validation or the dial with nothing to unwind — and `Disconnect` there would **hang forever**, since it ends by sending on that nil channel while holding the connection lock. Teardown sends QUIT first so `readLoop` unblocks instead of stalling on its read deadline. 3 tests, all verified fail-on-revert.

### AUDIT-320 — Server — FortiGate dialup SNMP columns copied from the tunnel table (LOW)

`internal/snmp/vendor_fortigate.go`: the dialup-table columns `.2/.3/.4/.11/.12` were copied from the site-to-site tunnel table (12.2.2.1) into the dialup table (12.2.1.1).

> **CONFIRMED — defect is real but unreachable.** The authoritative FORTINET-FORTIGATE-MIB `FgVpnDialupEntry` SEQUENCE has exactly **10** columns: `Index(1), Gateway(2), Lifetime(3), Timeout(4), SrcBegin(5), SrcEnd(6), DstAddr(7), Vdom(8), InOctets(9), OutOctets(10)`. The server's `.11` (Status) and `.12` (UpTime) therefore do not exist at all, and `.2/.3/.4` are mislabelled as Phase1Name/Name/RemoteGW. However `SNMPClient.GetAllVPNTunnels()` has **zero callers** — collectors have owned all polling since v0.11.74 — so none of it can execute. The collector's own copy was already corrected under AUDIT-217. Resolution is deletion of the dead chain, not a column fix.

> **✅ RESOLVED (v0.11.235 / #243)** — deleted `SNMPClient.GetAllVPNTunnels`, the `VendorProfile` interface method and its 8 vendor implementations, the linux/bsd/paloalto walk helpers, FortiGate's `ParseVPNDialupStatus`/`ParseGRETunnels`, and the dialup OID constants. The shared `parse{Linux,BSD}VPNFromInterfacePDUs` helpers and `ParseVPNStatus` stay because `ParseVPNStatus` is part of the `VendorProfile` vendor-extension contract and mirrors the collector's interface — **not** because they are currently reached: `SNMPClient.GetVPNStatus()` is itself uncalled. That residual family is recorded separately as AUDIT-326 and deliberately left out of scope here. A guardrail test fails if a server-side VPN walk or the dialup OIDs reappear under `internal/snmp` or `cmd/poller`.

### AUDIT-321 — Cross-repo — dialup Local/Remote subnet mapping divergence (MED)

The collector maps `src → Local` / `dst → Remote` for dialup peers while the server maps the opposite.

> **❌ REFUTED for the live path — the collector is correct.** Settled against production rather than the MIB text, because **the MIB's own DESCRIPTION strings are inverted**: `fgVpnDialupSrcBegin` reads *"Remote subnet address of the tunnel"* and `fgVpnDialupDstAddr` reads *"Local subnet address of the tunnel"*, which is the opposite of observed device behaviour. Verified on prod (138,643 `ipsec-dialup` rows): device 3 (NUDAY-FW) owns interfaces `192.168.25.254/24` and `192.168.35.1/24`, and those are exactly the subnets the collector labels `local_subnet` — while `remote_subnet` resolves to the far-end `192.168.5.0/24` (device 1's `192.168.5.2/24`). The FortiClient dial-up rows agree: `(.5,.6)` yields the protected `0.0.0.0/0` selector and `.7` yields the client's assigned pool address. `.6` also behaves as a range **end**, not the "subnet mask" its DESCRIPTION claims — prod values render as clean `/24` blocks, which a mask could not produce through `rangeToCIDR`. The only wrong mapping is the server's, which is dead code (AUDIT-320). **Do not "correct" the collector to match the MIB text.** The server's inverted copy was deleted with AUDIT-320 (v0.11.235), so only the correct mapping remains in the codebase. The direction is already locked on the collector side by `TestFortiGate_ParseDialupVPNStatus_VdomColumnUnread` (`internal/snmp/vendor_fortigate_test.go`), which asserts both halves — `.5/.6 → LocalSubnet` and `.7 → RemoteSubnet`.

### AUDIT-322 — Server — `admin-ipsec.js` pollDeploy generation guard is tautological (LOW)

`cmd/api/static/js/admin-ipsec.js`: the deploy/rollback/recheck POST handlers guarded their own resolution with `deployLive(deployGen)`, comparing the live generation against itself. Only the modal-is-open half did any work, and that stays true once the operator has opened a *different* tunnel's progress modal — letting a late POST start a rogue second poll loop against it.

> **✅ RESOLVED (v0.11.234 / #242)** — all three deferred-poll sites capture `var gen = deployGen` after `openDeployModal` and check that. `openDeployModal`'s own internal call keeps the live value, which is correct there since it runs immediately after the bump. Guardrail test verified fail-on-revert.

### AUDIT-323 — Server — `GetPublicInterfaceChart` unclamped range overflows (LOW)

`internal/api/handlers/handlers_dashboard.go`: the numeric `range` fallback had only a lower bound, so `range=Inf` produced `+Inf`, whose int conversion is implementation-defined (minimum int64 on amd64) and yielded an arbitrary cutoff. Device- and public-gated throughout, so a correctness bug rather than a disclosure one.

> **✅ RESOLVED (v0.11.234 / #242)** — the range table moved to a pure `publicChartLookback` helper bounded by `maxPublicChartRangeHours` (8760), mirroring `httputil.ParseHours`. The upper bound also screens `+Inf` and `NaN`, which fail every `<=` comparison. 2 tests over the full range table, verified fail-on-revert.

### AUDIT-324 — Collector — OID index arc in parsed interface IP addresses (REFUTED)

Noticed while verifying AUDIT-321 against production: 25 of 65 rows in `interface_addresses` hold malformed five-octet strings — `10.10.10.1.1`, `192.168.5.2.1`, `76.66.145.98.1` — i.e. an OID index arc appended to the parsed address.

> **❌ REFUTED — already fixed, and the residue is inert.** The root cause was corrected in collector commit `fcdd66b` (2026-06-21), *"parse ipAddrTable IPs that carry an extra OID sub-index (FortiOS)"*, which added `ipv4FromTableIndex`; `GetInterfaceAddresses` applies it to both the ifIndex and netmask columns. Every malformed row in prod dates from a single 17-second window on **2026-06-22 21:55–21:56**, before the fixed build was deployed; no malformed row has been written since, while clean rows run through 2026-08-30. The residue is also unreachable: it is strictly older than every clean row for the same device (devices 1/2/3 all have current rows), and both consumers select latest-per-device — `GetLatestInterfaceAddresses` joins on `MAX(timestamp)` per device, and the connection-detail resolver takes the newest row. A five-octet string can never match a real source IP either, so it cannot cause mis-attribution, only a miss that cannot occur. No code change; the 25 stale rows can be deleted at an operator's convenience but affect nothing.

### AUDIT-325 — Server — admin "Test IRC Connection" strands loops on BOTH paths (MED)

Found by the adversarial review of the AUDIT-319 fix, which correctly objected that the sibling case had not been swept. `TestBot` carries the same defect on both branches:

- `TestBot.Connect` ended with a bare `return conn.Connect(addr)`. A rejected SASL/CAP negotiation — precisely what testing credentials provokes — left `writeLoop`, `pingLoop` and the socket running.
- `TestBot.Disconnect` sent only `safeQuit`. QUIT never closes the library's `end` channel, so the loops and the socket survived on the **success** path too: one stranded set per admin test-connection click, with `pingLoop` eventually parking forever on the full `pwrite`.

Lower rate than AUDIT-319 (admin-triggered rather than amplified by the 30s reconnect sweep), but the same defect class.

> **✅ RESOLVED (v0.11.234 / #242)** — both paths now call the shared `teardownConn` (QUIT → unlatch → Disconnect), the failure path behind the same non-nil `ErrorChan` gate, and both off the request goroutine so a server that ignores the QUIT cannot stall the admin handler. `teardownFailedConn` was renamed `teardownConn` to reflect that it unwinds any connection this package owns. Guardrail test verified fail-on-revert.

### AUDIT-326 — Server — a further zero-caller SNMP client family (LOW, OPEN)

Surfaced by the adversarial review of the AUDIT-320 deletion, which correctly refuted the first draft's claim that the retained VPN parsers were "reached by the live `ParseVPNStatus` path". They are not. `ParseVPNStatus` is reached only from `SNMPClient.GetVPNStatus()`, and that method has zero callers — the same criterion AUDIT-320 used. The live server SNMP surface is only `GetSystemStatus`, `GetInterfaceStats` and `GetHardwareSensors`; `GetVPNStatus`, `GetInterfaceAddresses` and `GetProcessorStats` are all uncalled.

Left out of AUDIT-320's scope on purpose, and the distinction is about the COLLECTOR's interface, not the server's. `GetAllVPNTunnels` was on the server's `VendorProfile`, but it has **no counterpart in the collector at all**, so deleting it converged the two repos. These three do have live collector counterparts — `ParseVPNStatus` on the collector's `VendorProfile` (`internal/snmp/vendor.go:35`) and `GetInterfaceAddresses`/`GetProcessorStats`/`GetVPNStatus` on its `SNMPClient` interface (`cmd/collector/main.go:57-60`), all reached from the poll loop — so deleting them would diverge the repos. That makes it a design decision rather than dead-code removal. (`GetInterfaceAddresses` is vendor-neutral in both repos: it walks `ipAddrTable` directly and resolves no vendor profile.) Note also that the deleted walker was the only code stamping `TunnelType = "ipsec"` on FortiGate site-to-site results, so anything reviving `GetVPNStatus` would get an empty `TunnelType` — a pre-existing gap in `ParseVPNStatus`, not a regression.

> **OPEN** — decide deliberately whether the server keeps a vendor-extension SNMP contract at all.
