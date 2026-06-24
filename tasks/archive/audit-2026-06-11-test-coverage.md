# Firewall-Mon Test Coverage Review (2026-06-11)

Method: re-ran `go test -coverprofile=coverage.out ./...` (and `-count=1 -short`); inspected every critical package, every handler method, every test file, and the new v0.10.409/v0.10.410 tests in detail. Head SHA `8e0cfff` (the doc-only `tasks/audit-2026-06-10.md` save commit, on top of v0.10.410's chart-window work).

Aggregate: the prior audit's numbers are **almost entirely correct** — the small upticks (relay 1.8 → 1.8%, ping 0 → 0%, sflow 8.5 → 8.5%) and small drops (syslog 26.6 → 26.6%, api/handlers 13.7 → 13.7%) are noise. The blocker (relay at 1.8%) is still here, with **zero new test coverage added** in 24 days despite multiple releases touching the same code path (v0.10.382 schema_version handshake, v0.10.401 e2e test for the server side, v0.10.405 prod crash-loop triage).

## Coverage snapshot (re-measured 2026-06-11)

| Package | Test files | LoC (src) | Coverage % | Risk | Δ from prior |
|---|---|---|---|---|---|
| `internal/api/response` | 0 | 43 | 0.0% | Low | unchanged |
| `internal/ping` | 0 | 292 | 0.0% | High (ICMP) | unchanged |
| `cmd/api` | 0 | ~1500 | 0.0% | Medium (wiring) | unchanged |
| `cmd/poller` | 0 | ~700 | 0.0% | Medium | unchanged |
| `cmd/trap-receiver` | 0 | ~200 | 0.0% | Low | unchanged |
| `internal/notifier` | 1 | 536 | 1.8% | Critical (CVE-adjacent) | unchanged |
| `internal/relay` | 1 | 822 | 1.8% | **Critical** | unchanged |
| `internal/snmp` | 1 | 3,750 | 2.3% | Critical (binary parsers) | unchanged |
| `internal/alerts` | 1 | 1,242 | 2.6% | High | unchanged |
| `internal/irc` | 1 | 1,005 | 4.3% | High | unchanged |
| `internal/sflow` | 2 | 414 | 8.5% | High (parsers, no fuzz) | unchanged |
| `internal/api/handlers` | 24 | 4,884 | 13.7% | Critical (bus surface) | unchanged |
| `internal/database` | ~30 | 7,107 | 20.0% | High | unchanged |
| `internal/syslog` | 2 | 556 | 26.6% | High | unchanged |
| `internal/api/middleware` | 4 | 569 | 31.3% | Medium | unchanged |
| `internal/uptime` | 1 | 200 | 32.1% | Low | +5.3 pp (new prop tests) |
| `internal/httputil` | 4 | ~250 | 42.4% | Medium | unchanged |
| `internal/config` | 5 | ~400 | 43.3% | Medium | unchanged |
| `internal/report` | 5 | ~750 | 57.4% | Medium | unchanged |
| `internal/logging` | 1 | ~200 | 59.3% | Low | unchanged |
| `internal/auth` | 1 | 275 | 66.7% | Low | unchanged |
| `internal/metrics` | 1 | 63 | 68.8% | Low | unchanged |
| `internal/secrets` | 1 | 286 | 70.8% | Low | unchanged |
| `internal/tracing` | 1 | 150 | 71.4% | Low | unchanged |
| `internal/models` | 1 | 188 | 98.1% | Low | unchanged |
| `internal/audit` | 1 | 117 | 88.9% | Low | unchanged |
| `internal/configdiff` | 2 | ~750 | 92.1% | Low | unchanged |
| `internal/shell` (audit pins) | 102 | n/a | n/a | n/a | unchanged |

**Aggregate ~28%** by `go test -cover`. Real behavioral coverage is closer to ~20% once the shell pin tests are excluded.

Test LoC: `internal/shell/` = **4,661 LoC** across 102 files (28% of total test LoC; the prior audit's "~50%" was a slight over-estimate; 28% is still a heavy dose of static pins vs. real behavior).

Test runtime: `go test -count=1 -short ./...` = **13.7s cold / 5.2s warm** (the prior audit reported the warm figure; cold is what CI sees after a clean checkout). `go test -p=4 ./...` = 15.3s (no improvement — the package compiler is the floor, not the test bodies).

## Verification of the new v0.10.409 / v0.10.410 tests

### `TestReportHTMLWellFormed` — `internal/report/render_validate_test.go:86-169`
**Verdict: solid.** Five-way matrix (24h/168h × flat/collapsible × rich model) asserts (1) no template artifacts (`<no value>`, `ZgotmplZ`, `%!`, `<nil>`), (2) parses cleanly via `golang.org/x/net/html`, (3) skeleton present, (4) tag-pair balance for `table`/`svg`/`defs`/`style`/`g`/`details`, (5) **every embedded SVG fragment parses as strict XML**, (6) image/CID-free, (7) `Collapsible` toggles `<details>`, (8) expected sections + data points present. The `svgFragmentRe` extraction + `xml.Unmarshal` round-trip is exactly the right check — it catches the class of bug (unclosed `<g>`, stray `&`) that pure substring assertions miss. The 2-axis matrix catches both the email and admin-preview templates and both the 24h-hourly and 168h-daily alert bucketing. PASS in 0.04s.

One small gap: the test only validates a single rich model. A model with `[]Sparkline{}` (no data) or a single device with nil alerts isn't exercised. Cheap to extend — `t.Run` per data shape.

### `TestParseChartWindow` — `internal/httputil/chartwindow_test.go:20-77`
**Verdict: solid for the surface, narrow scope.** Five sub-cases (explicit from/to wins; range preset maps to `[now-dur, now]`; absent range uses default; junk range falls back; inverted from/to falls through to range). Uses `t.Parallel()` and only a real `time.Duration` check, no real Gin middleware in the path — that's the right unit-test boundary.

Missing case: the malformed-from/to scenarios the changelog says the function guards against (e.g. `from=abc`, negative `to`, `from=1&to=2` for sub-100ms windows). The current test treats only the 2000/1000 inverted case. Not high-priority — the happy paths cover the drag-to-zoom and the preset flows.

### `TestBucketUnitForWindow` — `internal/database/chart_window_test.go:12-37`
**Verdict: solid.** Table-driven, all 5 ladder boundaries (`≤3h→minute`, `≤30h→5min`, `≤8d→hour`, `≤60d→6hour`, `else→day`) covered with off-by-one cases on both sides. 100% on `bucketUnitForWindow`. Good.

### `TestGetInterfaceChartWindow` / `TestGetVPNChartWindow` — `internal/database/chart_window_test.go:41-138`
**Verdict: useful but two structural caveats.** The tests do verify (a) `bucket_ms` is populated, (b) sub-window returns only rows inside the bounds, (c) inverted window returns no rows, (d) VPN delta sum is 400 (deltas: 100→200→350→500). They do **not** cover:
- the `GetInterfaceChartData` (legacy) and `GetVPNChartData` (legacy) consumers are at **0%** and **58.8%** coverage respectively — only the new `_Window` variants are tested. A regression in the legacy codepath that the report still uses would not be caught.
- the dialected `TimeBucket` branch is at 0% (the SQLite test never hits the Postgres path; the integration test hits it but only for 3 of 5 units).
- the new `6hour` TimeBucket tier added in v0.10.410 has **no test asserting the actual SQL output** — the unit test exercises the bucket-selector but not the bucket-encoder.

### `TestEntrypointSupervision_AUDIT094` — `internal/shell/entrypoint_supervision_audit094_test.go`
**Verdict: pin test, adequate.** It is a string-grep over `entrypoint.sh` (not a behavioral mock harness as the changelog claim "verified locally: a mock harness confirms a crashing child triggers exit 1 and a SIGTERM triggers exit 0" suggests). The assertions are correct (must contain `wait "$API_PID"`, must not contain unguarded `wait $API_PID $POLLER_PID $TRAP_PID`, must have `teardown` + `exit 1`, must have `trap shutdown INT TERM`) but the "verified locally" claim is not reproducible in CI. There is **no harness** in this repo that actually exec's a mock crashing child + SIGTERM and asserts the entrypoint's exit code. The static-pin alone is fine for regression detection (a typo in `wait "$API_PID"` would be caught), but the real coverage is the *integration* of the bash `wait -n` semantics with PID tracking — and that's untested.

## Prior findings re-validation

| Prior TC finding | Status as of 2026-06-11 | Notes |
|---|---|---|
| B-1 relay at 1.8% | **STILL OPEN** | Zero new tests in 24 days. Only `jitter()` tested. The H-3 wire-format break (separate CTO finding) was a symptom of this — no test ever drove `Register`/`sendBatch` end-to-end. |
| H-1 notifier at 1.8% | **STILL OPEN** | Only `SanitizeHeader` + fuzz on it. The whole `SendAlert`/`sendEmail`/`sendSlack`/`sendDiscord`/`sendWebhook`/`SendHTMLEmail`/`SnapshotConfig` surface (389 LoC of notifier.go) is untested. **`SMTPCompoundAuth` (the v0.10.222 LOGIN auth that the changelog says is the only way the alert emails work against some Postfix/Dovecot servers) is also untested** — `internal/notifier/smtp_auth.go:147` is 100% uncovered. |
| H-2 130+ handler methods never invoked | **RE-CONFIRMED, slightly worse** | I found **156 distinct handler methods** (not 148), of which **only 30 (~19%)** are reached by any test, and only **20 (~13%)** are invoked directly (the other 10 are reached through `router.GET(...).Handle` registration in test files that don't actually call the route). See "Handler coverage matrix" below. |
| H-3 ping at 0% | **STILL OPEN, intentionally so** | `internal/ping/ping.go` opens a raw ICMP socket — `os.Getpid() & 0xffff` + `icmp.ListenPacket("udp4", ...)`. Windows can't open raw ICMP without admin. The prior audit's "left uncovered here" decision is the right one, but **the DB-side rollup math (`updateStats` / `pingTarget` 100% uncovered) is reachable from SQLite unit tests via a mocked `Ping` function and a fake `DB` — those branches are easy targets and were not picked up.** |
| H-4 sflow 8.5% + snmp 2.3% | **PARTIALLY CLOSED, but mostly not** | sflow's `parseDatagram` (the 414-line binary parser for production sFlow v5 packets) is **0% tested**; the fuzz target only covers the 28-byte diagnostic `ParseSFlowDatagram`. The actual flow-record + raw-packet-header + IPv4 parsing is untested. Same story for snmp's `vendor_*.go` (8 files, ~3,200 LoC) — only the trap rate-limiter is covered. |
| H-5 database at 20% | **STILL OPEN** | 207 functions across 22 files in `internal/database/` have **0% coverage**. The largest concentrations: `sites_probes.go` (30), `alerts.go` (29), `ping.go` (21), `devices.go` (19), `events.go` (14), `crypto.go` (14). Most of these are CRUD that should be trivially testable on the SQLite harness. |
| M-1 irc at 4.3% | **STILL OPEN** | Only `channelNickAllowed` + `Bot.isAdmin` are tested. 27 other functions in `bot.go` (1005 LoC) are uncovered: `loadAndStartBots`, `seedDefaultCommands`, `loadCommands`, `reconnectLoop`, `statusLoop`, `sendAutoStatus`, `createBot`, `Bot.Start`, `Bot.Stop`, `onConnected`, `onPrivmsg`, `handleCommand`, `onJoin`, `onPart`, `onQuit`, `onNotice`, `updateStatus`, etc. Most are networking-bound but the command-handler logic and `decryptServerSecrets` are pure. |
| M-2 vendor_*.go 0% | **STILL OPEN** | 8 vendor parsers totalling ~3,200 LoC. The FortiGate parser (the one production uses) has zero tests. |
| M-3 response/ at 0% | **STILL OPEN** | 43 LoC, 4 trivial constructors. Pin test exists (`transporttypes_audit073_test.go`) but no actual round-trip JSON test. |
| M-4 handlers_auth.go | **STILL OPEN** | `Login`/`Logout`/`ChangePassword` are not exercised at the HTTP boundary. The `auth` package is tested (66.7%), but the handler wrappers (`httputil.InternalError`, CSRF cookie issuance, response envelope) aren't. |
| M-5 events/flows write-side | **STILL OPEN** | `database/events.go` (114 LoC) and `database/flows.go` (603 LoC, including the per-window delta math) are at 0%. `flows.go` is the actual storage path that the relay client's `SendFlowSample` data lands in — a regression here would silently lose flow data. |
| M-6 config/LoadFromEnv precedence | **STILL OPEN** | The 5 test files in `internal/config` are mostly env-var parsing, but the *precedence* rules (config file > env > default) have no explicit test. |
| L-1 integration_pg_test handler-level | **CLOSED (v0.10.401)** | `internal/api/handlers/integration_pg_test.go` now does the full gin→handler→DB→partition-routing flow. |
| L-2 audit pins 50% of test LoC | **REVISED to 28%** | shell = 4,661 / (4,661 + 11,745) = 28% of test LoC. The absolute volume of pins is still a code smell (they are 102 separate `_test.go` files). |
| L-3 no browser/E2E | **STILL OPEN, no change** | No `*.test.js`, no Playwright config, no Cypress, no jest in `package.json`. `npx playwright` was mentioned in the prior audit but is not present in the repo. |
| L-4 no t.Parallel in handler tests | **STILL OPEN** | Only `internal/api/handlers/integration_pg_test.go` and a handful in `handlers_config_diff_test.go` use `t.Parallel()`. Test runtime is dominated by package-compile (cold) + handler setup (warm). `t.Parallel` at test level would help, but `go test -p=N` package-level parallelism is already implicit and doesn't reduce wall time because `internal/database` is 7.5s of the 13.7s cold total. |

## Handler coverage matrix (full enumeration)

156 distinct `func (h *Handler) Xxx` methods. 20 invoked directly in tests, 10 reached only through `router.GET/POST(...).Handle` in test setup (not actually called), **126 never reached by any test**.

The 20 directly-invoked: `BulkAcknowledgeAlerts`, `BulkAcknowledgeAlertsByFilter`, `GetAuditLogs`, `GetDashboardAll`, `GetDeviceConfigDiff`, `GetDeviceConfigHistory`, `GetHealth`, `GetProbesStatsBatch`, `ReceiveConfigRevision`, `ReceiveSyslogMessages`, `ReceiveSystemStatuses`, `RegenerateProbeKey`, `RegisterProbe`, `ReportClientError`, `TestIRCServer`, `UpdateDevice`, `UpdateMaintenanceWindow`, `UpsertDeviceAlertConfig`, `UpsertSiteAlertConfig`, plus the SSRF-input validation on `TestIRCServer`/`TestProbeConnection`/`TestEmail` (negative path only).

The 136 zero-coverage handlers (representative, not exhaustive): all 14 `Get*`/`Update*`/`Create*`/`Delete*` for **IRC servers/channels/commands**, all 5 `*AlertPolicy`, **3 of 3** `GetPublic*` (`GetPublicDashboard`/`GetPublicConnections`/`GetPublicDisplaySettings`/`GetPublicInterfaceChart`/`GetPublicInterfaces`/`GetPublicStatusHistory`/`GetPublicVPN`) — including the one that **leaks the full fleet topology** (H-1 from the security review), all 4 `SendIRCMessage`/`SendReportNow`/`TestProbeConnection`/`TestEmail`/`TestWebhook` — the SSRF-vector surface, all 4 `SendReport*` / `PreviewReport` (the new v0.10.408 report path), all 4 `Get*`/`Update*` for **Sites**, all 4 `Get*`/`Update*` for **MaintenanceWindows**, all 4 `GetVPN*` / `GetConnection*` / `GetFlow*` / `GetSyslog*` / `GetTrap*` (the read side of the high-volume tables that the write side of the relay pushes into), 13 of 17 `Receive*` ingestion endpoints (`ReceiveTrapEvents`, `ReceiveFlowSamples`, `ReceivePingResults`, `ReceiveInterfaceAddresses`, `ReceiveProcessorStats`, `ReceiveHardwareSensors`, `ReceiveInterfaceStats`, `ReceiveVPNStatuses`, `ReceiveHAStatuses`, `ReceiveSecurityStats`, `ReceiveSDWANHealth`, `ReceiveLicenseInfo`, `ReceiveProcessSnapshot`, `ReceiveInterfaceErrors`, `ReceiveSensorDetails`, `ReceiveLicenseDetails` — only `ReceiveConfigRevision`, `ReceiveSystemStatuses`, `ReceiveSyslogMessages` are tested), all 6 `GetDeviceDetail`/`GetDeviceProcessHistory`/`GetDeviceHAStatus`/`GetDeviceSDWANHealth`/`GetDeviceSecurityStats`/`GetDeviceInterfaceErrors`/`GetDeviceDataDiag` (the device-detail page reads).

## New findings (post-prior-audit)

### [blocker] TC-N1 — Relay wire-format "fixed" but no test exists to prevent regression of H-3
**File:** `internal/relay/relay.go:151-822` (entire package) + `internal/api/handlers/handlers_probes.go:670-688` (server side)
**Gap:** Zero behavioral tests for `NewRelayClient`/`Register`/`Heartbeat`/`SendTrap`/`SendPingResult`/`SendSyslogMessage`/`SendFlowSample`/`syncLoop`/`sendBatch`/`flushQueues`/`FetchDevices`/`SendSystemStatuses`/`SendInterfaceStats`/`SendVPNStatuses`/`SendConfigRevision`/`SendProcessSnapshot`/`SendInterfaceErrorSnapshot` + 4 `ConvertModel*` helpers. The schema_version handshake (v0.10.382) is a literal JSON tag in `RegistrationRequest` with no test that drives it. The prior CTO's top-5 #2 was "the relay client never sends `Authorization: Bearer`" — fixed in the same line of code that has *no test that would have caught it*. The 4 handler tests in `handlers_probes_schemaversion_test.go` (server side) assert 426 on too-old/too-new, but **the client side has nothing that asserts the request shape it sends**.
**Risk:** Every release risks re-introducing the H-3 wire-format break (relay stops sending `Authorization`), the queue-overflow FIFO drop bug (a refactor of the `if len(r.trapQueue) >= maxQueueSize` block), the retry-on-500 path consuming the queue twice, and the heartbeat-404 → un-approve transition. These are silent data-loss bugs.
**Fix:**
```go
// internal/relay/relay_test.go
func TestRelay_Register_HeaderShape(t *testing.T) {
    var gotReq *http.Request
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotReq = r.Clone(r.Context())
        w.Header().Set("X-Probe-Schema-Version-Supported", "1-1")
        json.NewEncoder(w).Encode(RegistrationResponse{Approved: true, ProbeID: 7})
    }))
    defer srv.Close()
    c := NewRelayClient(RelayConfig{ServerURL: srv.URL, RegistrationKey: "k", ProbeName: "p"})
    c.httpClient = srv.Client()
    if err := c.Register(); err != nil { t.Fatal(err) }
    if got, want := gotReq.Header.Get("Authorization"), "Bearer k"; got != want { ... }
    if gotReq.Header.Get("Content-Type") != "application/json" { ... }
    // body asserts: registration_key, probe_name, schema_version=1
}
func TestRelay_QueueOverflow_DropsOldest(t *testing.T) { /* send >10k events, assert head dropped */ }
func TestRelay_Heartbeat_404_UnApproves(t *testing.T) { /* 2nd heartbeat: srv returns 404, assert r.approved.Load()==false */ }
func TestRelay_SendBatch_500RetriesThenDrops(t *testing.T) { /* 3 500s, assert data is gone (not silently held) */ }
func TestRelay_Stop_FlushesQueues(t *testing.T) { /* queue 5 events, Stop(), assert server saw them */ }
func TestRelay_ConvertModel* (4×) { /* round-trip trap/ping/syslog/flow */ }
func TestRelay_RegistrationSchemaVersion_Old(t *testing.T) { /* server returns 426, client returns error, queue still empty */ }
```
**Effort:** M (1 day). ~250 LoC. `httptest.NewServer` + 1 ad-hoc fake of the server-side handler.

### [blocker] TC-N2 — `internal/notifier/` is the SMTP/Slack/Discord/webhook fan-out path and is 98.2% untested
**File:** `internal/notifier/notifier.go:101-389` (288 LoC) + `internal/notifier/smtp_auth.go:42-147` (105 LoC) — **neither is tested**
**Gap:** `SendAlert` (the entire policy-driven email/Slack/Discord/webhook fan-out) and `SendHTMLEmail` (the multipart/related MIME builder used by `report.BuildCriticalAlertEmail`) are uncovered. `sendEmail` calls `smtp.SendMail` — a fake SMTP server via `net/smtp` is a 5-line harness. `sendSlack`/`sendDiscord`/`sendWebhook` are pure JSON POSTs — `httptest.NewServer` is enough. The `CompoundAuth` PLAIN-or-LOGIN selector (the v0.10.222 fix for Postfix/Dovecot operators) is also untested despite being on the security boundary (the `Start` method's host-match check is the MITM guard). 13 of 14 notifier files have **0% coverage**.
**Risk:** A regression in the multipart attachment base64 wrapping, the recipient-list split, the policy-active vs legacy-fallback branch (lines 105-108 are the branchy bit), or the SANITIZE-on-the-`Subject`-line injection guard (line 305) would be caught by **zero tests**. The post-AUDIT-014 SanitizeHeader guard is the only thing tested.
**Fix:**
```go
func TestNotifier_SendAlert_PolicyDisablesEmail(t *testing.T) {
    n := NewNotifier(&config.Config{})
    var emailHits int
    srv := httptest.NewServer(...) // counts hits on Slack/Discord/webhook paths
    // nc.PolicyActive=true, EnableEmail=false → email NOT called even if SMTP is "set"
    // assert emailHits==0, assert slackHits==1
}
func TestNotifier_SendHTMLEmail_MultipartBoundaries(t *testing.T) {
    // fake smtp via smtp.NewClient + a pipe; assert Content-Type matches boundary,
    // assert CID header present, assert recipient list split on comma
}
func TestNotifier_SendAlert_LegacyFallbackWhenNoPolicy(t *testing.T) {
    // PolicyActive=false; if nc.EmailEnabled && nc.SMTPHost!="" → email must send
}
func TestCompoundAuth_Start_PrefersPlain(t *testing.T) {
    a := CompoundAuth("u", "p", "host")
    mech, _, err := a.Start(&smtp.ServerInfo{Name: "host", TLS: true, Auth: []string{"PLAIN", "LOGIN"}})
    if err != nil || mech != "PLAIN" { t.Errorf(...) }
}
func TestCompoundAuth_Start_FallsBackToLogin(t *testing.T) { /* Auth: [LOGIN] */ }
func TestCompoundAuth_Start_RejectsUnencrypted(t *testing.T) { /* TLS=false → error */ }
func TestLoginAuth_Next_SequenceIsUsernameThenPassword(t *testing.T) { /* step 0 → "u", step 1 → "p", step 2 → error */ }
```
**Effort:** M (1.5 days). 200 LoC.

### [high] TC-N3 — The 17 `Receive*` ingestion handlers (the relay→server data path) are 14-of-17 untested
**File:** `internal/api/handlers/handlers_data.go:52-995` (18 `Receive*` handlers)
**Gap:** Only `ReceiveConfigRevision`, `ReceiveSystemStatuses`, `ReceiveSyslogMessages` have handler tests. **14 are silent**:
- `ReceiveTrapEvents` (SNMP trap ingestion)
- `ReceiveFlowSamples` (sFlow ingestion)
- `ReceivePingResults` (ICMP ping results)
- `ReceiveInterfaceAddresses`, `ReceiveInterfaceStats`, `ReceiveInterfaceErrors`
- `ReceiveProcessorStats`, `ReceiveHardwareSensors`, `ReceiveSensorDetails`
- `ReceiveVPNStatuses`, `ReceiveHAStatuses`, `ReceiveSDWANHealth`, `ReceiveSecurityStats`
- `ReceiveLicenseInfo`, `ReceiveLicenseDetails`, `ReceiveProcessSnapshot`
- `ProbeHeartbeat` (separate file)

All share the same probe-Bearer-auth + `batchDedupCheck` + `markBatchIfOK` + per-record validation + write path. The shared `batchDedupCheck` / `markBatchIfOK` ARE tested (`handlers_data_idempotency_audit042_test.go` — `TestReceiveBatch_Idempotent_AUDIT042`) but only for the one `ReceiveConfigRevision` happy path. The validation rules (size cap, device ownership, truncation, JSON shape) of the 14 untested handlers are unverified.
**Risk:** A regression in `ReceivePingResults` truncation (the 100-record cap) would silently drop pings; a regression in `ReceiveFlowSamples` device-ownership filter would let probes insert flow data for devices they don't own.
**Fix:** A table-driven harness in `handlers_data_test.go` (or a new `handlers_data_receive_table_test.go`) using a fake probe + device, asserting the 4 invariants per handler: (1) 200 happy path with 1 record, (2) 400 on >max-size body, (3) 403 on device not owned by probe, (4) auth boundary (401 on missing key, 401 on wrong key). 14 handlers × 4 cases = 56 sub-tests; ~150 LoC if extracted to a helper. The boilerplate the prior CTO flagged (H-1 code-quality) is actually a feature here — the table-driven test is short.
**Effort:** S (0.5 day).

### [high] TC-N4 — `internal/sflow/` `parseDatagram` and `parseFlowSample` (the production binary parser) are **0% covered**
**File:** `internal/sflow/sflow.go:174-299` (130 LoC of v5 flow-record parsing)
**Gap:** The `FuzzParseSFlowDatagram` target only exercises the trivial 28-byte header parser (`ParseSFlowDatagram` at line 388) — the one whose only output is `(version, sequence, agentIP, sampleCount, error)`. The actual binary flow-record parser (`parseDatagram` → `parseFlowSample` → `parseRawPacketHeader` → `parseIPv4` → the dispatch to `FlowHandler`) — the function chain that runs in production on every inbound sFlow UDP datagram — has **no test at all**. The `parseIPv4` helper (TCP/UDP port extraction, VLAN tag handling, Ethernet header parse) is uncovered. The expanded-flow-record (format=3) branch is uncovered. The version-1 vs version-3 dispatch is uncovered. The early-return guards (`len(data) < 28`, `addrType == 2` IPv6, `len(data) < offset+16`) are uncovered.
**Risk:** A regression in the IPv4 header length parsing (e.g. `ihl := int(data[0]&0x0F) * 4` — if the IHL field gets read as big-endian, the function silently returns and flow data vanishes), the VLAN-tag handling (`etherType == 0x8100`), or the expanded-record offset arithmetic, is silent data loss. No sFlow test exists at the handler layer either — `SaveFlowSample` (relay→DB write path) is at 0%.
**Fix:** A `FuzzParseSFlowDatagram_Direct` target that exercises `r.parseDatagram` (need to expose it as `ParseFlowDatagram(r *SFlowReceiver, data []byte) []ParsedFlow` or use a `flowHandler` test sink), with a corpus of 10-20 hand-crafted datagrams:
```go
// IPv4 flow record, Ethernet header, TCP, ports
// Same with VLAN tag (etherType=0x8100)
// Expanded flow sample (format=3)
// IPv6 agent address (addrType=2)
// Truncated datagram at every offset boundary
// Non-IPv4 transport (e.g. 0x86DD IPv6) → flow.SrcAddr should stay empty
```
**Effort:** S (0.5 day).

### [high] TC-N5 — 207 functions in `internal/database/` are at 0% coverage, including the data-loss-risk surfaces
**File:** `internal/database/{alerts,devices,events,flows,sites_probes,connection_detail,telemetry,ping}.go` (top offenders)
**Gap:** The SQLite harness in `testing.go` makes it trivial to test these — most are pure GORM CRUD. Per the `go tool cover -func` output, **207 distinct functions at 0.0%**. The biggest concentrations:
- `sites_probes.go` (30 funcs, 329 LoC) — all site/probe assignment CRUD. The `UpdateDevice`/`UpdateProbe` "loaded-belongs-to clobbers foreign-key" bug (v0.10.394) was a direct symptom of `sites_probes.go` being uncovered.
- `alerts.go` (29 funcs, 348 LoC) — every alert policy CRUD + the bulk-ack / bulk-snooze SQL is uncovered (the handler test in `handlers_alerts_bulk_test.go` only checks HTTP; the DB-layer method is not asserted).
- `ping.go` (21 funcs, 192 LoC) — every ping-stats rollup query is uncovered.
- `devices.go` (19 funcs, 333 LoC) — `GetAllDevices`/`GetDevice`/`ResolveDeviceByIP`/`CreateDevice` etc. are at 0%. The `UpdateDevice` (v0.10.394) test only covers the FK-clobber regression; the rest of the function is uncovered.
- `events.go` (14 funcs, 114 LoC) — `SaveSyslogMessage`/`SaveTrapEvent`/`SavePingResult` (the batcher write paths the relay client's `Send*` methods feed into) are uncovered.
- `flows.go` (10 funcs, 603 LoC) — the LAG-based delta math that the v0.10.408 chart endpoint relies on is **0% covered** (only `vpnDeltaQuery` at 100% and `GetVPNChartData` at 58.8%). The `GetInterfaceChartData` legacy consumer is 0%.
- `connection_detail.go` (5 funcs, 677 LoC) — the N+1 hot path from the perf review (GetConnectionDetail:104 queries) is uncovered.

**Risk:** A regression in the LAG-based flow delta math, the ping-stat rolling mean, or the alert policy filter SQL is silent.
**Fix:** A `database_crud_test.go` per file using the `NewDatabaseForTesting` harness. Each test seeds 1 device + 1 alert + 1 ping + 1 syslog + 1 flow, calls the function, asserts the result. ~50 LoC × 7 files = ~350 LoC. The `NewDatabaseForTesting` function already has the full model list registered.
**Effort:** M (1.5 days).

### [high] TC-N6 — `internal/notifier/smtp_auth.go` CompoundAuth / LoginAuth is on the security boundary and 100% untested
**File:** `internal/notifier/smtp_auth.go:42-147` (105 LoC)
**Gap:** The PLAIN-or-LOGIN selector is a security boundary (the `Start()` method's `server.Name != a.host` check is the MITM guard; the `server.TLS` check is the cleartext-password guard — both are exactly the "wrong host" and "no TLS" preflight that the v0.10.222 incident postmortem identifies). The v0.10.397 changelog says "verified locally: a mock harness confirms" — but the harness is not in the repo. `TestSMTPLoginAuth_*` does not exist anywhere.
**Risk:** A refactor that drops the `server.TLS` check would let a man-in-the-middle capture the LOGIN username/password (sent in cleartext per RFC). A refactor that drops the `server.Name != a.host` check would let a DNS-redirected TLS handshake to a wrong host pass. These are CVE-class bugs.
**Fix:** Table-driven `smtp_auth_test.go`:
```go
func TestLoginAuth_Start(t *testing.T) {
    cases := []struct{ name string; server *smtp.ServerInfo; wantMechanism string; wantErrSub string }{
        {"plain_login_over_tls_match", &smtp.ServerInfo{Name: "host", TLS: true}, "LOGIN", ""},
        {"host_mismatch",              &smtp.ServerInfo{Name: "evil", TLS: true}, "", "wrong host"},
        {"unencrypted",                &smtp.ServerInfo{Name: "host", TLS: false}, "", "unencrypted"},
    }
    for _, c := range cases { ... }
}
func TestLoginAuth_Next(t *testing.T) {
    // step 0 → "user", step 1 → "pass", step 2 → error
}
func TestCompoundAuth_SelectsPlainWhenOffered(t *testing.T) { /* server.Auth: [PLAIN, LOGIN] */ }
func TestCompoundAuth_SelectsLoginWhenNoPlain(t *testing.T) { /* server.Auth: [LOGIN] */ }
func TestCompoundAuth_RejectsNeither(t *testing.T) { /* server.Auth: [CRAM-MD5] */ }
func TestCompoundAuth_PassesHostToInner(t *testing.T) { /* server.Name = "evil" → error from inner */ }
```
**Effort:** S (0.5 day).

### [high] TC-N7 — `internal/ping/` ICMP socket can't be unit-tested on Windows, but the DB-side rollup math in `pingTarget`/`updateStats` is reachable
**File:** `internal/ping/ping.go:124-229` (the `PingTarget`/`pingTarget`/`updateStats` methods)
**Gap:** The `Ping()` function (`ping.go:231-288`) is genuinely integration-only (raw ICMP socket). But `PingCollector.pingTarget` (lines 124-186) and `updateStats` (lines 188-229) take a target IP and call `Ping` — refactor `PingTarget` to be a function-pointer (`type Pinger func(targetIP string) (latency, ttl, err)`) and the whole `pingTarget`/`updateStats` math becomes a pure unit test. The rolling-mean `((existing.AvgLatency * float64(existing.Samples)) + latency) / float64(newSamples)` (line 217) is the same class of code that `internal/uptime/format.go` has property tests for (AUDIT-120) — but ping has nothing.
**Risk:** A regression in the rolling-mean math (off-by-one, integer-division trap) silently corrupts every device's `avg_latency` in the database.
**Fix:** Inject the `Pinger` interface; add a `ping_collector_test.go` with a fake `Pinger` that returns canned latencies. Assert the rolling mean is correct for 1, 10, 100 samples with the audit-120 property-test style.
**Effort:** S (0.5 day, and the refactor is ~5 LoC).

### [high] TC-N8 — `internal/snmp/vendor_*.go` (3,200 LoC, the actual vendor config parsers) are 0% covered
**File:** `internal/snmp/{vendor, vendor_fortigate, vendor_paloalto, vendor_sonicwall, vendor_pfsense, vendor_opnsense, vendor_firewalla, vendor_linux_vpn, vendor_bsd_vpn}.go`
**Gap:** The fortigate vendor (851 LoC) is what production uses most — and it has zero tests. Every other vendor is also 0%. A single config-text fixture per vendor + a round-trip parse would catch regressions in normalizer patterns (the `configdiff` tests do this for the diff side, not the parse side).
**Risk:** A pattern regression in `vendor_fortigate.go`'s interface-name normalizer (`"port1"` vs `"Port 1"` vs `"port-channel1"`) would silently mismatch devices in the connection-detail view.
**Fix:** `vendor_fortigate_test.go` (and a small test per other vendor) with 5-10 fixtures per vendor: known config strings → expected parsed structure. The tests exist as static pins in `configdiff/validate_test.go`; copying the same fixtures into the parse-side test is cheap. ~80 LoC × 8 vendors = ~640 LoC.
**Effort:** M (1 day, mostly fixture-curation).

### [high] TC-N9 — 136 of 156 handler methods have **zero** test invocation; the handler package is 13.7% covered
**File:** `internal/api/handlers/handlers_*.go` (24 files)
**Gap:** See "Handler coverage matrix" above. The biggest missing clusters:
- All IRC endpoints (15 funcs: `GetIRCServer`, `GetIRCServerByID`, `CreateIRCServer`, `UpdateIRCServer`, `DeleteIRCServer`, `ConnectIRCServer`, `DisconnectIRCServer`, `GetIRCChannels`, `CreateIRCChannel`, `UpdateIRCChannel`, `DeleteIRCChannel`, `GetIRCCommands`, `CreateIRCCommand`, `UpdateIRCCommand`, `DeleteIRCCommand`, `SendIRCMessage`)
- All `*AlertPolicy` (8 funcs)
- All `*Site` (5 funcs)
- All `*MaintenanceWindow` (5 funcs)
- All `GetPublic*` (7 funcs, including the H-1 leak)
- All `GetVPN*` / `GetConnection*` / `GetFlow*` / `GetSyslog*` / `GetTrap*` (the read side of high-volume tables)
- All device-detail reads (`GetDeviceDetail`, `GetDeviceProcessHistory`, `GetDeviceHAStatus`, `GetDeviceSDWANHealth`, `GetDeviceSecurityStats`, `GetDeviceInterfaceErrors`, `GetDeviceDataDiag`, `GetDeviceStatusHistory`, `GetDeviceConnections`, `GetDeviceAlertConfig`, `GetDeviceConfigRevision`, `GetDeviceConfigRevisionDownload`, `GetSiteAlertConfig`)
- All `Receive*` not in the tested trio (see TC-N3)
- All `Settings` (4 funcs), `PublicDisplay` (1), `Test*` (3 SSRF-vector funcs tested only for the negative path)

The reason it's not catastrophic: the **handler boilerplate is short** (most are 5-15 LoC) and most delegate to the `database` package, which IS tested (where the test exists). The high-impact ones to add are the 14 `Receive*` (TC-N3), the IRC `SendIRCMessage` (security H-4 from the internal audit, no max length), and the public `GetPublicConnections` (security H-1).
**Risk:** A handler refactor (e.g. JSON-tag rename) in any of these silently breaks the admin UI for that feature.
**Fix:** The `testhelper_test.go` `doTestRequest` is already set up; a single `doAdminTestRequest` helper for non-probe routes is already there. A 5-minute copy-paste per handler is feasible. Priority: 14 `Receive*` (TC-N3), 4 IRC, 1 `GetPublicConnections` (security H-1).
**Effort:** L (3+ days at 1 handler/test pair each), but the high-value subset is M (1.5 days).

### [medium] TC-N10 — `internal/irc/` 4.3% (only the `isAdmin` helper, the 1005 LoC bot is essentially untested)
**File:** `internal/irc/bot.go:1-1005`
**Gap:** Only `channelNickAllowed` and `Bot.isAdmin` are tested. The Bot lifecycle (`Start`/`Stop`/`onConnected`), the command dispatch (`handleCommand`), the auto-status loop (`sendAutoStatus`), the reconnect loop (`reconnectLoop`), the seed commands (`seedDefaultCommands`), the join/part/quit/notice handlers, and the per-server `createBot` factory are all uncovered. The `decryptServerSecrets` method (which reads the encrypted `{enc}` SMTP/IRC passwords out of the DB and decrypts them) is **uncovered and security-sensitive** — a refactor that uses the wrong key or returns the wrong fallback would silently leak the wrong password.
**Risk:** A `seedDefaultCommands` regression would silently remove the built-in `!status` / `!help` commands.
**Fix:** A `bot_test.go` with a `Bot` constructed with a stub `irc.Connection` (the 3rd-party `github.com/thoj/go-ircevent` lib has a `MockConnection` you can use, or roll a tiny shim). Assert: `seedDefaultCommands` populates the expected built-ins; `handleCommand` dispatches to the right handler; `decryptServerSecrets` returns the right values; `isAdmin` for an unknown channel is `false`.
**Effort:** M (1 day).

### [medium] TC-N11 — `internal/api/response/` 0% (43 LoC, the JSON envelope)
**File:** `internal/api/response/response.go:1-43`
**Gap:** The transport envelope is **the only** data structure every handler returns. A regression in the `omitempty` tags would change the wire shape — every frontend page would break. A simple JSON-roundtrip test (3-5 lines) is the minimum.
**Risk:** A typo in `Data interface{} \`json:"data,omitempty"\`` (e.g. removing `omitempty` so `null` is sent) would break frontend parsers that don't handle `null`.
**Fix:**
```go
func TestAPIResponse_JSONShape(t *testing.T) {
    cases := []struct{ name string; r APIResponse; want string }{
        {"success with data",  Success(map[string]int{"x": 1}),  `{"success":true,"data":{"x":1}}`},
        {"error omits data",   Error("boom"),                     `{"success":false,"error":"boom"}`},
        {"message omits data", Message("ok"),                     `{"success":true,"message":"ok"}`},
    }
    for _, c := range cases {
        b, _ := json.Marshal(c.r)
        if string(b) != c.want { t.Errorf(...) }
    }
}
```
**Effort:** XS (10 min).

### [medium] TC-N12 — `internal/auth/auth.go` at 66.7%: the **handler-level** auth (`Login`/`Logout`/`ChangePassword`) is not exercised
**File:** `internal/api/handlers/handlers_auth.go` (`Login`, `Logout`, `ChangePassword`)
**Gap:** The `internal/auth` package itself is tested (66.7%) — but the **handler wrapper** is not. A regression in the `Login` handler's response envelope (e.g. `c.SetCookie` typo), the CSRF-token issuance, or the bcrypt-cost default for the test environment, would not be caught.
**Risk:** A cookie-attribute bug (HttpOnly, SameSite, Path, Domain) would silently break the admin UI's session. The CTO's H-1 (login fail-open) and H-2 (CSRF) findings both touch this surface.
**Fix:** A `handlers_auth_test.go` with: `Login` returns 200 + sets cookie on valid creds, returns 401 on bad creds, returns 429 on rate-limited, returns 200 + sets `X-CSRF-Token` header for the SPA. `Logout` returns 200 + clears cookie. `ChangePassword` requires `current_password`, returns 400 on mismatch, returns 200 + invalidates existing sessions.
**Effort:** S (0.5 day).

### [medium] TC-N13 — `internal/api/middleware/middleware.go` at 31.3%: the H-2 login-LRU fail-open fix is not tested
**File:** `internal/api/middleware/middleware.go:85-92, 174-187` (the rate-limiter logic the security H-2 finding points at)
**Gap:** The middleware package has 4 test files and 31.3% coverage — but the **`LoginRateLimiter` fail-open behavior** is not asserted. The security H-2 finding was: "When the 50k-IP LRU table fills, the eviction policy gives any unknown IP a fresh full burst — exactly the credential-spray scenario." A regression that re-introduces this is silent.
**Risk:** A refactor of the LRU eviction policy (e.g. changing the cap or the eviction trigger) reintroduces the fail-open path.
**Fix:** A `TestLoginRateLimiter_FailOpen_OnMapFull` (or the opposite — assert it does NOT fail open) — fill the LRU with N entries, send a request from a new IP, assert either (a) the request is rejected with 503, or (b) a documented test fixture shows the new behavior. Whatever the policy is, **lock it in**.
**Effort:** S (0.5 day, requires reading the actual current behavior first).

### [medium] TC-N14 — `internal/config/` `LoadFromEnv` precedence rules mostly untested
**File:** `internal/config/config.go` (the `LoadFromEnv` function and the precedence: env > file > default)
**Gap:** The config package has 5 test files and 43.3% coverage. The env-var-vs-config-file precedence is the primary way production is configured, and a regression (e.g. env var no longer overrides file) would silently revert a deployed config to a default.
**Risk:** A typo in the precedence order of two env-var helpers silently inverts production.
**Fix:** Table-driven test with `t.Setenv` to set env, write a temp YAML file, call `Load`, assert the env value won. ~80 LoC.
**Effort:** S (0.5 day).

### [medium] TC-N15 — `internal/syslog/` `UDPSyslogReceiver` and the TCP `handleConnection` are uncovered; the L-5 security finding (no per-source rate limit) is on this surface
**File:** `internal/syslog/syslog.go:391-555` (UDP receiver) + `139-197` (TCP `handleConnection`)
**Gap:** The syslog package has 26.6% coverage and the only test is the `FuzzParseRFC5424` panic-check (no assertions on the parsed result). The TCP `handleConnection` (which parses, persists, and tags `SourceIP`) and the `UDPSyslogReceiver` (separate code path from TCP) are uncovered. The L-5 finding ("UDP syslog receiver no per-source rate limit") is on the uncovered surface.
**Risk:** A regression in the per-message buffer-bound handling (`messageBuf.Reset()` + Write, the M-4 perf finding's O(N²) pattern) is silent; the L-5 rate-limit fix would land on uncovered code.
**Fix:** A `udp_syslog_test.go` that creates a `UDPSyslogReceiver` on `127.0.0.1:0`, sends a few datagrams, asserts the handler is called with the right `SourceIP`. A `tcp_syslog_test.go` that does the same over TCP, plus a "message > MaxMessageSize gets dropped" test. ~120 LoC.
**Effort:** M (1 day).

### [medium] TC-N16 — No browser/E2E test suite — frontend has zero `*.test.js`, no Playwright, no Cypress
**File:** `web/admin/*.html`, `cmd/api/static/js/admin-*.js` (the 4,022-LoC `admin-main.js` and the 2,089-LoC `admin-device-detail.js` are 100% untested at the runtime layer)
**Gap:** The frontend is a 17-page SPA with 12 admin-*.js files. The 102 static-pin tests in `internal/shell/` assert source-shape (e.g. "this IIFE must be wrapped", "this selector must exist"), but **none assert runtime behavior** (e.g. "clicking the IRC disconnect button actually calls `/api/irc/servers/:id/disconnect` and the row updates"). The M-12 code-quality finding (44 hardcoded `/admin/api/...` literals across 8 files with internal inconsistency in `admin-irc.js`) is exactly the bug a Playwright test would catch.
**Risk:** A frontend refactor that breaks the IRC disconnect flow is silent. The static pins catch the obvious ("the file is wrapped in IIFE") but not the subtle ("`loadPageData('irc')` actually calls the IRC endpoints").
**Fix:** Add Playwright (`npm i -D @playwright/test`) and write 5-10 smoke tests for the critical admin flows: login → load dashboard → drill into a device → view the chart → send a test webhook → disconnect IRC server. ~300 LoC. The `package.json` already exists.
**Effort:** L (3+ days, mostly environment setup and the first test's flake-quieting).

### [medium] TC-N17 — `cmd/api/main.go` and `cmd/poller/main.go` are 0% covered (wiring tests)
**File:** `cmd/api/main.go` (~1500 LoC), `cmd/poller/main.go` (~700 LoC)
**Gap:** The two production daemons' `main()` functions — including the OpenTelemetry init, the slog init, the singleton-lock acquisition, the graceful-shutdown defer chain, the route registration, and the `cobra` flag set — are 0% covered. The CTO's H-1 ops finding ("`/api/health` is the only liveness/readiness probe; no `/readyz` separation") and the v0.10.405 prod-crash-loop incident both touch the entrypoint.
**Risk:** A typo in the shutdown order (kill API before draining background goroutines, or vice-versa) would be silent. A new env-var flag with no default would be silent.
**Fix:** A `cmd/api/main_test.go` that uses the `api.APIServer` constructor with fake config + fake DB, asserts the routes are registered (using a captured `*httptest.Server` over the registered mux) and the health endpoint returns 200. ~150 LoC.
**Effort:** M (1 day, with some integration-test helpers from `cmd/api/static.go`).

### [medium] TC-N18 — The 102 audit-pin tests in `internal/shell/` are static regex/string checks; ~28% have low value-add
**File:** `internal/shell/*_test.go` (102 files, 4,661 LoC)
**Gap:** Many of the pin tests are valuable (e.g. `TestSchemaVersionHandshake`, `TestStaticFilesEmbed_ReferencesStaticDir_AUDIT139`, `TestVendoredLibrariesPinned_AUDIT160`, `TestSecretAtomicPublish_AUDIT008`, `TestDeploymentBackup_AUDIT098` — these assert *behavior* the audit cared about). But a meaningful subset is "did somebody edit a comment in the right direction":
- `TestInternalErrorSweep_AUDIT071`, `TestFaintText_AUDIT066`/`AUDIT067`, `TestSidebarAria_AUDIT057`, `TestFormatDate_LocaleAware_AUDIT128`, `TestAriaExpanded_AUDIT070`, `TestNoES5BracketWorkaround_AUDIT132`, `TestJSStandardDocumented_AUDIT131` — string-over-`os.ReadFile` checks for substrings that often appear in unrelated comments.
- The 8 README tests (`readme_*_audit1*_test.go`) — `strings.Contains(readme, "go test ./...")` style. These will pass even if the README is otherwise wrong.
- `TestApifetch401_TopFrame_AUDIT058`, `TestApifetchRetriesTransient_AUDIT130` — these grep for tokens in JS files; they will pass even if the surrounding logic is broken.

**The risk**: pin-test rot. Once a pin is written, it's very hard to delete (every "remove obsolete pin" PR looks like removing the audit's protection), and over time the pins grow stale while the code drifts in unrelated ways. The current `internal/shell/` dir is already 4,661 LoC; if not pruned, it will pass 10k by EOY.
**Fix:** A `internal/shell/PINS.md` manifest (one-line per test: what bug it caught, when it was last validated, what a future agent should check). The pins that have zero behavior to assert should be **moved to a checklist** (e.g. `docs/CHECKLISTS.md`) or deleted. Concrete examples to remove or convert: the 4 `TestReadmeHas*` / `TestReadmeDocuments*` tests (replace with a single `TestReadmeStructure` that runs `markdownlint` or `mdq`).
**Effort:** S (1 day for the triage; ongoing for the diet).

### [medium] TC-N19 — `internal/database/events.go` (114 LoC) and the 3 batched save paths are 0% covered
**File:** `internal/database/events.go:1-114` (`SaveSyslogMessage`, `SaveTrapEvent`, `SavePingResult`)
**Gap:** The relay client's `SendSyslogMessage` / `SendFlowSample` / `SendTrap` / `SendPingResult` ultimately call these (or their batched counterparts) — but neither the batched nor the singular paths have any test. The `batcher.go` (`TestBatcher_*` tests) covers the *batcher mechanism* (in-process queue + flush timer), not the *underlying save query*. A regression in the `Create()` call (e.g. wrong field) would be silent.
**Risk:** Silent data loss in the write path of the most-touched tables.
**Fix:** A `events_test.go` with 3 simple CRUD tests, each ~10 LoC. `TestSaveSyslogMessage_RoundTrip`, `TestSaveTrapEvent_RoundTrip`, `TestSavePingResult_RoundTrip`. The `testing.go` harness has all the models.
**Effort:** XS (30 min).

### [medium] TC-N20 — `internal/snmp/` `NewTrapReceiver`/`Start` UDP-listener / `handlePacket` parse path is 0% covered
**File:** `internal/snmp/snmp.go` (the 578 LoC main file — only the `allow()` rate-limiter is tested via the `trap_test.go` in the same dir)
**Gap:** The 4 vendor parsers (TC-N8) are the biggest hole, but the *core* `Start` + `handlePacket` (which actually runs in production) is also uncovered. A regression in the OID→severity mapping or the per-vendor dispatch would be silent.
**Risk:** Silent SNMP-trap-data loss.
**Fix:** A `snmp_test.go` that sends a canned UDP packet to a `NewTrapReceiver` bound to `127.0.0.1:0`, asserts the handler fires with the right `TrapEvent`. The `TestTrapReceiver_Start_RequiresCommunity` test in `trap_test.go` shows the pattern. ~100 LoC.
**Effort:** S (0.5 day).

### [low] TC-N21 — No race-detector coverage on Windows dev or in the unit-test lane
**File:** `Makefile`, `go test -race` runs only in CI
**Gap:** The 7 timing- and concurrency-dependent tests are gated behind `-short` (AUDIT-142) — so on a developer's `go test ./...` run, **the race detector never runs**. The CTO's reliability-blocker "Probe goroutine deadlock / lockout cascade" requires `-race` to confirm, and that's only in CI. A Windows dev (no gcc → no cgo → no -race) cannot run them at all (I confirmed: `cgo: C compiler "gcc" not found`).
**Risk:** A data race in `RelayClient.syncData` (which copies 4 queues under one mutex, then sends outside the lock — a refactor that moves the send inside the lock would race with `SendTrap`) is silent on the developer's machine.
**Fix:** Add a `make test-race` target that requires CGO_ENABLED=1 and a docker-based runner; document the constraint; add a CI matrix entry.
**Effort:** S (a few hours).

### [low] TC-N22 — Test runtime could drop from 5.2s warm to ~2s with broader `t.Parallel()` adoption
**File:** All non-shell `*_test.go` files in the repo
**Gap:** The AUDIT-140 commit added `t.Parallel()` to 59 tests in pure-logic packages, but the **integration-style tests** (handler tests, database tests, syslog tests) are still serial. The `internal/database` test suite alone is **7.5s cold / ~1s warm** because every test opens a fresh `NewDatabaseForTesting(t)` and runs the AutoMigrate. If 5 of those tests ran in parallel, you'd save 3-4s.
**Risk:** None — `t.Parallel` is safe when tests don't share state. The `NewDatabaseForTesting(t)` returns a fresh in-memory DB per call, so it's trivially parallelizable.
**Fix:** Add `t.Parallel()` to the top of every test in `internal/database/`, `internal/api/handlers/`, `internal/syslog/`. The handler tests share `gin.SetMode(gin.TestMode)` (a global), which is the only conflict — that one is already set in `init()`. ~30 LoC of mechanical edits.
**Effort:** S (1 hour).

### [low] TC-N23 — `TestReportHTMLWellFormed` could also exercise the 3rd rendering mode + a model with empty sections
**File:** `internal/report/render_validate_test.go:86-169`
**Gap:** As noted, the test only exercises one model. Adding an "empty" model (no devices, no alerts, no flow) and a "weekly with 1 spike" model would catch regressions in the section-iterators (the `range` over a nil slice, the `if` guards, the section-collapse logic).
**Risk:** Low — the existing test catches the most common (unclosed tags, template artifacts).
**Fix:** Add 2 more model shapes + 1 more layout (the report has a 3rd layout for very-long reports that paginates). ~40 LoC.
**Effort:** XS (15 min).

### [low] TC-N24 — `TestParseChartWindow` is missing the malformed-input cases
**File:** `internal/httputil/chartwindow_test.go:20-77`
**Gap:** No test for `from=abc`, `to=abc`, `from=-1`, `to=0`, `from=0&to=0` (same instant), `from=99999999999999999` (out of int64 range). The 5 sub-cases cover the happy paths and 1 inverted case.
**Risk:** Low — `strconv.ParseInt` errors fall through cleanly.
**Fix:** Add 4-5 negative cases. ~20 LoC.
**Effort:** XS.

### [low] TC-N25 — The new `6hour` TimeBucket tier (v0.10.410) has no test asserting the actual SQL output
**File:** `internal/database/dialect.go:22-49` (the `TimeBucket` function) + `internal/database/chart_window_test.go`
**Gap:** The Postgres `TimeBucket("6hour", "timestamp")` SQL is added in v0.10.410. The unit test `TestBucketUnitForWindow` covers the bucket *selector* (when to choose 6hour) but not the bucket *encoder* (what SQL does 6hour emit). The integration test `TimeBucketRoundTrip` covers `minute`/`hour`/`day` — not `6hour`.
**Risk:** A typo in the `6hour` SQL (e.g. `date_trunc('hour', timestamp)` instead of `'6 hour'`) would bucket at 1h, returning 6× the rows expected, blowing up the chart.
**Fix:** Add a `6hour` case to `integration_pg_test.go`'s `TimeBucketRoundTrip` subtest, and a `sqliteDialect.TimeBucket("6hour", "x")` string assertion in a new `dialect_test.go`. ~15 LoC.
**Effort:** XS.

### [low] TC-N26 — The `NewIntegrationDB` testkit (v0.10.401) is shared but the `database` package's other in-memory tests don't use it
**File:** `internal/database/integration_testkit.go` (exposes `NewIntegrationDB`)
**Gap:** The `NewIntegrationDB` is build-tagged `integration` (skipped without `TEST_PG_DSN`). All the other in-memory tests use `NewDatabaseForTesting(t)` from `testing.go`. These are two parallel harnesses with different model lists (the integration one has 1 extra model — `models.SchemaMigration` — and the same others). A regression in the model-list (e.g. forgetting to add a new model) breaks one harness and not the other.
**Risk:** Low — easy to spot.
**Fix:** Extract the `testModels` list from `testing.go` to a `commonModels()` helper, and have both harnesses call it. ~10 LoC.
**Effort:** XS.

### [low] TC-N27 — The `internal/shell/parallel_audit140_test.go` "representative" file list will rot
**File:** `internal/shell/parallel_audit140_test.go:16-26`
**Gap:** The audit-140 pin test asserts that 9 specific files contain `t.Parallel()`. If any of those files is renamed or refactored to add a sub-test in a separate file, the pin fires spuriously. The list is also an **opt-in** — a 10th pure-logic file with `t.Parallel` would not be required.
**Risk:** Low — the pin is conservative.
**Fix:** Walk the test tree for `func TestXxx` declarations and assert each has `t.Parallel()` somewhere in its file, with a per-file allowlist for the timing/global-state files. ~30 LoC.
**Effort:** XS.

## Quick wins (< 1 day, high signal)

1. **TC-N11 (10 min)**: `internal/api/response/response_test.go` — JSON-roundtrip of the 3 constructors. Catches wire-shape regressions on every endpoint.
2. **TC-N19 (30 min)**: `internal/database/events_test.go` — 3 round-trip tests for the relay→DB write path. The cheapest data-loss-prevention test in the repo.
3. **TC-N25 (15 min)**: Add the `6hour` case to `TimeBucketRoundTrip` and to `TestBucketUnitForWindow`'s sibling test. The 6hour tier is brand-new in v0.10.410; locking it down is free.
4. **TC-N23 (15 min)**: Add 2 more model shapes to `TestReportHTMLWellFormed`. Free coverage.
5. **TC-N24 (20 min)**: Add 5 malformed-input cases to `TestParseChartWindow`. Free coverage.
6. **TC-N27 (1 hour)**: Make `parallel_audit140_test.go` walk the test tree instead of hard-coding 9 files.
7. **TC-N22 (1 hour)**: Mechanical `t.Parallel()` adds across `internal/database`, `internal/api/handlers`, `internal/syslog`. Drops the warm runtime from 5.2s to ~2s.
8. **TC-N26 (10 min)**: Dedupe the two model lists between `testing.go` and `integration_testkit.go`.
9. **TC-N6 + TC-N4 (3 hours)**: Two `sflow` + `notifier` fuzz targets plus 4 hand-crafted corpus entries for each. The most-bang-per-LoC path to data-loss coverage.

## What looks solid

- **`TestReportHTMLWellFormed`** (v0.10.409, `internal/report/render_validate_test.go:86`) — the SVG-strict-XML check is exactly the right test for a renderer that hands HTML to a mail client. Catches the class of bug (unclosed tag, stray `&`) pure substring assertions miss.
- **`TestParseChartWindow`** (v0.10.410, `internal/httputil/chartwindow_test.go:20`) — well-scoped unit test for the precedence rules. The 5 sub-cases cover the production drag-to-zoom path.
- **`TestBucketUnitForWindow`** (v0.10.410, `internal/database/chart_window_test.go:12`) — table-driven with off-by-one cases on both sides of each boundary. The right shape for a pure-function pin.
- **`handlers_config_revision_fortigate_test.go`** (6 tests) — the v0.10.326 fortigate merge / suspect-byte logic is well-covered. The `FortiGateIVDrift_MergesIntoLatest`, `RealChange_FiresExactlyOneAlert`, `SuspectBytes_DoNotOverwriteGood`, `TriggerSourceAndQualityRoundTrip`, and `ResponseShape` tests all hit realistic data shapes.
- **`handlers_data_idempotency_audit042_test.go`** — `TestReceiveBatch_Idempotent_AUDIT042` exercises the `batchDedupCheck` + `markBatchIfOK` shared boilerplate the way it should be exercised (drives an end-to-end request, not a mocked method).
- **`handlers_alerts_bulk_test.go`** (10 sub-tests) — covers all 3 input shapes (IDs, by-filter, mixed) and the validation edge cases. The first time the alert-package had real handler-level coverage.
- **`handlers_partial_update_test.go`** — `TestUpdateDevice_partial_update_preserves_other_fields` is the right test for the v0.10.396 partial-update-pattern fix.
- **`handlers_probes_schemaversion_test.go`** (3 tests) — `TestSchemaVersion_DefaultsTo1_WhenAbsent`, `TestSchemaVersion_OldVersion_Returns426`, `TestSchemaVersion_UnsupportedVersion_Returns426_WithRange` lock in the v0.10.382 wire-format handshake. Catches the regression where the server's 426 logic could be silently bypassed.
- **`handlers_health_audit091_test.go`** (3 tests) — `GetHealth` with healthy DB / nil DB / failed DB ping all assert the right status code. The trio is exactly what the audit (H-1 ops) flagged.
- **`handlers_irc_audit013_test.go`** (3 tests) — the SSRF guard for `TestIRCServer` is asserted against 3 inputs (loopback, private IP, missing port). The `TestTestIRCServer_RejectsSSRFTargets_AUDIT013` is a good negative-path test.
- **`handlers_data_test.go`** (16 sub-tests) — covers the `validateProbe` auth boundary (missing/wrong token, pending approval) AND the `ReceiveConfigRevision` + `ReceiveSystemStatuses` happy/sad paths. Solid for the trio that's tested.
- **`internal/api/middleware/trap_test.go`** (5 tests) — `TestTrapReceiver_Allow_*` covers the rate-limiter exhaust, per-IP isolation, map cap, and concurrency-safety. Catches the race that an LRU refactor would introduce.
- **`internal/auth/auth_test.go`** (16 sub-tests) — `TestValidateToken_RejectsAlgConfusionAUDIT117` + `TestValidateToken_RejectsWrongSecretAUDIT117` lock in the two classic JWT bypasses. Excellent.
- **`internal/syslog/fuzz_audit119_test.go`** + **`internal/sflow/fuzz_audit119_test.go`** — the seed corpus runs as a fast regression under plain `go test`, AND the `go test -fuzz=FuzzParse*` form is the actual fuzz run. Good model.
- **`internal/report/spike_property_test.go`** + **`internal/uptime/uptime_property_test.go`** (v0.10.398) — `testing/quick` property tests, not example-based. The right shape for numeric code.
- **`internal/logging/logging_test.go`** (v0.10.396) — covers the redaction hook, the stdlib→slog bridge, the level parsing. Solid.
- **`internal/tracing/tracing_test.go`** (v0.10.403) — the `WrapTransport` cross-process propagation test is the right shape for verifying the `traceparent` injection.
- **`integration_pg_test.go`** (v0.10.401) — `TestEndToEndIngestion_Postgres_AUDIT123` is the genuine cross-package end-to-end test. Closes the prior CTO's L-1 finding.
- **`internal/api/handlers/testhelper_test.go`** — `setupProbeAndDevice` is the right shape (seeded with hashed key, returns the plaintext for auth). The shared test fixture is exactly what was missing.
- **`internal/shell/transporttypes_audit073_test.go`** + **`internal/shell/entrypoint_supervision_audit094_test.go`** + **`internal/shell/spa_pages_nav_test.go`** + **`internal/shell/staticfiles_audit139_test.go`** — these are the GOOD kind of pin: they assert an *invariant* (the type lives in the right package, the entrypoint supervises the right process, the SPA_PAGES list matches the HTML divs, the embed points at the right directory) that a regex would miss.
- **The whole `internal/configdiff/` package at 92.1%** — the 750-LoC normalizer/validator for vendor config diffs is the most-tested pure-logic code in the repo. The diff is the part of the UI operators spend the most time looking at; the coverage shows.
- **`internal/models/models_test.go`** at 98.1% — the reflection-style `TableName()` uniqueness + snake_case guard catches the copy-paste-bug class. AUDIT-117 first test for the critical path.

## Summary

The repo's test suite is **compartmentalized well** (good pin tests for invariants, good unit tests for pure logic, good handler tests for the SSRF/security boundaries, good property tests for the numeric code) but has **two systemic holes**:

1. **The relay→server data path** (relay package 1.8%, 14 of 17 `Receive*` handlers untested, sFlow binary parsers 0%, ICMP `ping` 0%, `events.go`/`flows.go` write paths 0%) — a regression in any of these is silent data loss in production. 24 days after the prior CTO's top-5 finding on this, no test has been added. The fix is mechanical: `httptest.NewServer` for the relay side, `t.Parallel` + `setupProbeAndDevice` for the handler side, `f.Add()` corpus entries for the sFlow/syslog parsers.

2. **The notifier fan-out** (1.8% coverage, `CompoundAuth` 100% untested) — the security-adjacent surface that the v0.10.222 changelog admits is "the only way the alert emails work against some Postfix/Dovecot servers" and the v0.10.397 changelog says "verified locally: a mock harness" — but the harness is not in the repo. A regression in the LOGIN `server.TLS` check would be a CVE.

The 102 pin tests in `internal/shell/` are the project's signature and they are 28% of the test LoC; they work well for catching re-introductions of fixed bugs but are **not a substitute for behavioral coverage** of the data-path code. The right balance is what `TestReportHTMLWellFormed` and `TestSchemaVersion_*` show: one strong behavioral test per critical invariant, pinned by the audit number.

Recommended sequencing (per the prior audit's Sprint plan + this review's additions):

- **Sprint 1 (this week)**: TC-N1 (relay httptest harness, ~250 LoC), TC-N2 (notifier send + SMTP auth, ~300 LoC), TC-N11/19/25/27 (the 4 quick wins, ~2 hours total).
- **Sprint 2 (next week)**: TC-N3 (14 `Receive*` table-driven, ~150 LoC), TC-N4 (sFlow binary parsers, ~200 LoC), TC-N5 (database CRUD fill-in, ~350 LoC), TC-N6 (SMTP auth standalone tests, ~80 LoC).
- **Sprint 3 (next 2 weeks)**: TC-N9 (the 50ish handlers with the most impact, ~500 LoC), TC-N10 (irc `bot.go` lifecycle, ~150 LoC), TC-N16 (Playwright smoke suite, ~300 LoC).
- **Sprint 4+**: TC-N13 (H-2 lock-in), TC-N15 (syslog UDP), TC-N22 (the `t.Parallel()` sweep), TC-N18 (the pin diet).
