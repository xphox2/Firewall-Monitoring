# Firewall-Mon Public-Release Audit

**Version audited:** 0.10.239 (build baked at `cmd/api/main.go:34`)
**Audit date:** 2026-06-02
**Audited by:** Multi-agent sweep — security, stability, code quality, frontend, features, database/architecture, testing/CI, docs/operations
**Source of truth:** `E:\Golang\OpenCode\Firewall-Mon` on `master` (521 commits, 0 tags at audit time)

---

## How to use this document

Each finding has a stable ID in the form `AUDIT-NNN` so progress can be tracked in commit messages (e.g. `git commit -m "fix(audit): AUDIT-001 — track *_test.go in git"`).

**Status legend**

- `[ ]` open
- `[~]` in progress
- `[x]` resolved (move to "Resolved" section with the release version)
- `[!]` wontfix / accepted risk (write justification inline)

**Severity**

- **CRITICAL** — deployment blocker. Public release cannot ship.
- **HIGH** — will cause real incidents for a public user. Must fix in v0.11.0.
- **MEDIUM** — real but bounded risk. Should fix in v0.11.0 or v0.11.1.
- **LOW** — polish / nice-to-have.
- **INFO** — note for posterity, no action required.

**File references** are `path:line` against the v0.10.239 tree. If a refactor moves the code, fix the audit entry in the same PR — don't ship code that orphans the audit.

**Progress log** at the bottom — append a one-line entry per resolved finding with the commit SHA and release version.

---

## Executive summary

The codebase is well-defended in many dimensions (parameterised SQL, AES-256-GCM at rest, HMAC CSRF, recent bug-bash CHANGELOG entries, vendor profile abstraction supporting 8 vendors). The recent v0.10.236 report rewrite is genuinely good. **However, the public release is not yet ready** because of:

- **10 CRITICAL deployment blockers** (test files gitignored, no LICENSE, no CI, in-memory JWT secret breaks encryption on restart, batcher data loss on crash, trap-receiver drops every trap, no leader lock, no key rotation, no SECURITY policy, hardcoded third-party domain default).
- **~25 HIGH-priority gaps** across security, stability, frontend, Docker, docs, and tests.
- **~40 MEDIUM/LOW polish items** worth addressing before tagging a v0.11.0 "stable".

Estimated work: 1 week of focused fixes for blockers + 1 week for the long tail + 1 week for tests/CI = a clean v0.11.0 in roughly 3 weeks.

---

## CRITICAL — deployment blockers (must fix before any public tag)

### AUDIT-001 — `*_test.go` is in `.gitignore`
- **File:** `.gitignore:6`
- **Issue:** The two most important test files — `internal/configdiff/normalize_test.go` (631 LOC) and `internal/report/report_test.go` (192 LOC) — are **not tracked in git**. Public clones silently lose them. Recent CHANGELOG entries (v0.10.236, 0.10.238, 0.10.239) cite these as the regression net; the net doesn't exist for downstream users.
- **Fix:** Remove `*_test.go` from `.gitignore`. `git add -f internal/configdiff/normalize_test.go internal/report/report_test.go`. Verify with `git ls-files | grep _test.go` ≥ 11 files.
- **Verified at audit time:** confirmed via `git status --ignored`.

### AUDIT-002 — No `LICENSE` file (README claims MIT)
- **File:** repo root (missing)
- **Issue:** README:135-137 claims "MIT" but no `LICENSE` text is shipped. By Berne Convention, no license file means All Rights Reserved. Public release cannot ship.
- **Fix:** Add `LICENSE` with the standard MIT text. Add a license badge to README.

### AUDIT-003 — `THIRD-PARTY-NOTICES.md` missing
- **File:** repo root (missing)
- **Issue:** 8 vendored JS libraries (Chart.js, chartjs-plugin-zoom, uPlot, Cytoscape, fcose, cose-base, layout-base, Gridstack) and 2 fonts (Inter, JetBrains Mono) all carry attribution clauses. None provided.
- **Fix:** Create `THIRD-PARTY-NOTICES.md` with each library's name, version, license, copyright line, and source URL. Reference it from README.

### AUDIT-004 — No git tags, no CI, no release flow
- **File:** repo root
- **Issue:** 521 commits, `git tag -l` returns 0. `ServerVersion = "0.10.239"` at `cmd/api/main.go:34` but no `v0.10.239` tag. `package.json:3` is stale at `0.10.157`. No `.github/workflows/`, no `Makefile`, no `.goreleaser.yml`, no `.golangci.yml`. 16 files fail `goffmt -l` (incl. `internal/irc/bot.go` which has **CR-only line endings**). 4 `.exe` binaries + a stray `nul` file in the working tree.
- **Fix:**
  1. Add `.github/workflows/ci.yml` running `go build`, `go test -race -count=1`, `gofmt -l`, `go vet`, `golangci-lint`, `govulncheck`.
  2. Add `.github/workflows/release.yml` triggered by tag push.
  3. Add `.goreleaser.yml` producing multi-arch binaries + Docker image.
  4. Add `Makefile` with `test`, `lint`, `build`, `docker` targets.
  5. Add `.golangci.yml` enabling `gofmt`, `goimports`, `staticcheck`, `errcheck`, `ineffassign`, `unused`, `gosec`.
  6. One-time `git tag -a v0.10.X` backfill for shipped versions, or document the cutover.
  7. `gofmt -w .` once and commit.
  8. Fix `internal/irc/bot.go` line endings (CR → LF).
  9. Delete the 4 `.exe` files and `nul` from the working tree.
  10. Bump `package.json` to current version; make `Dockerfile` `org.opencontainers.image.version` come from a `VERSION` build-arg so it can't drift again.

### AUDIT-005 — Trap-receiver drops every trap silently
- **File:** `cmd/trap-receiver/main.go:29`
- **Issue:** `alerts.NewAlertManager(cfg, notif, nil)` passes `db=nil`. In `ProcessTrap` (alerts.go:196-245), `am.saveAlert()` is a no-op when `db==nil` (alerts.go:532-539). The trap-receiver logs to stdout and forgets. The trap-batcher's buffer is also never written to.
- **Fix:** Either (a) construct a real `*database.Database` in the trap-receiver and pass it to the AlertManager, or (b) delete the trap-receiver daemon and have `cmd/api` own UDP 162 (Gin + `net.ListenUDP`).

### AUDIT-006 — Batcher is not crash-durable and has a shutdown race
- **File:** `internal/database/batcher.go:53-87`
- **Issue:** In-memory `[]T` buffer with no WAL, no fsync, no spill-to-disk. A `SIGKILL` or OOM loses up to `maxSize` × flushInterval of un-flushed items. Caller returns `nil` believing the data was persisted. `Stop()` calls `Flush()` after `<-b.doneCh` returns, racing with concurrent `Add()` from handlers.
- **Fix:**
  1. Move the final `Flush()` into the ticker goroutine before it closes `doneCh`.
  2. Add a `stopped atomic.Bool` checked at the top of `Add` and `Stop`.
  3. Back the buffer with a tmpfs-spilled write-ahead log (`batcher_wal_<type>.log`, size cap, fsynced per batch).
  4. Add a `DroppedCount` metric exposed via `/admin/api/system` or `/metrics`.
  5. Set a `maxBytes` cap and return an error when full instead of unbounded growth.

### AUDIT-007 — No leader lock for the poller
- **File:** `cmd/poller/main.go:76-114`
- **Issue:** `pollAllDevices`, `RunFlowRollupCycle`, `RunSyslogAggregationCycle`, `CleanupOldData`, daily report, alert escalations all run with no Postgres advisory lock. Two poller instances → 2× polls, 2× alerts (cooldown map is in-memory and per-process), 2× reports emailed, 2× DB lock contention on cleanup.
- **Fix:** Wrap each cron tick in `tryAcquirePollerLock()` / `release` using `pg_try_advisory_lock` keyed to `"POLLERWORK"`. Reuse the existing `tryAcquireStartupLock` pattern at `internal/database/database.go:113-183`. Add `RECOMMENDED_SINGLETON_POLLER=1` to README.

### AUDIT-008 — Auto-generated JWT secret is in-memory only and breaks AES decrypt
- **File:** `cmd/api/main.go:42-48` + `internal/database/database.go:80-83`
- **Issue:** `cfg.Server.JWTSecretKey` is auto-generated if `JWT_SECRET_KEY` env is empty. On every restart a new secret is generated, which (a) invalidates every existing JWT and (b) derives a new AES-256 key via SHA-256, making **all stored `{enc}` SNMP/IRC/SMTP credentials permanently unreadable**. The auto-generated admin password is also lost on a fresh volume (only persisted to `/data/.admin-password` if `os.WriteFile` succeeds — `cmd/api/main.go:118-120`).
- **Fix:**
  1. `log.Fatalf` on first run if both `JWT_SECRET_KEY` and `ADMIN_PASSWORD` are empty (do not generate-and-continue).
  2. Persist the auto-generated secret to `/data/.jwt-secret` (chmod 600) on first run and reload on subsequent runs.
  3. Same treatment for the auto-generated admin password.
  4. Document the `JWT_SECRET_KEY` rotates-everything behaviour in the runbook.

### AUDIT-009 — Crypto key rotation is impossible
- **File:** `internal/database/crypto.go:23`
- **Issue:** `encKey []byte` is a single field. No `prevKey`, no `keyVersion` column, no migration path. First time the operator needs to rotate (or accidentally rotates the JWT secret) → unrecoverable ciphertext.
- **Fix:**
  1. Add `keyVersion` column to `models.SystemSetting` (or a new `crypto_keys` table).
  2. Add a `keyHistory [][]byte` field on `crypto.go` keyed by version.
  3. On encrypt, write `keyVersion || nonce || ciphertext`.
  4. On decrypt, read `keyVersion`, look up the key from history, fall back gracefully.
  5. Write a one-shot re-encryption migration `cmd/keyrotate/main.go` for operators.

### AUDIT-010 — `PROBE_SERVER_URL` default hardcodes the author's domain
- **File:** `internal/config/config.go:247`
- **Issue:** Default is `https://stats.technicallabs.org`. A public release must not phone home to a third party by default. Also a real `cookies.txt` for that domain was committed to the working tree at some point (currently gitignored — but the values were ever there).
- **Fix:** Change the default to `""`. Document that probes require an explicit `PROBE_SERVER_URL`. Audit `cmd/probe/main.go` for any other baked-in default URLs.

### AUDIT-011 — No SECURITY.md, no runbook, no CONTRIBUTING.md
- **File:** repo root (all missing)
- **Issue:** Public release with no vulnerability disclosure policy, no runbook, no contributor on-ramp, no Code of Conduct.
- **Fix:**
  1. Add `SECURITY.md` (GitHub-recognized) with contact email, PGP fingerprint, response-time SLO, supported-versions table.
  2. Serve `/.well-known/security.txt` route via admin handler.
  3. Add `CONTRIBUTING.md` (dev env, `go test ./...`, commit style, PR process).
  4. Add `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1).
  5. Add `.github/ISSUE_TEMPLATE/bug.yml`, `feature.yml`, `security.yml` (security one is a redirect to SECURITY.md).
  6. Add `.github/PULL_REQUEST_TEMPLATE.md` (checklist mirroring CI gates).
  7. Add `CODEOWNERS`.
  8. Add `docs/RUNBOOK.md` or `docs/OPERATIONS.md` — see AUDIT-046.

---

## HIGH-priority findings — security

### AUDIT-012 — Trap receiver binds 0.0.0.0:162 with empty community string
- **File:** `internal/snmp/trap.go:44-52`, `config.env.example:37`
- **Issue:** `if t.config.SNMP.TrapCommunity != "" && packet.Community != ...` is short-circuited when `TrapCommunity` is empty, so any UDP packet on port 162 is accepted and stored as a "trap" with `SourceIP = packet.SourceIP`. An attacker can spoof source IPs and flood the DB with bogus alerts / mask real outages.
- **Fix:** Require `SNMP_TRAP_COMMUNITY` to be set; fail-closed in `config.Validate()`. Add a token-bucket rate limiter per source IP. Use `subtle.ConstantTimeCompare` for the community check.

### AUDIT-013 — `TestIRCServer` SSRF — odd one out
- **File:** `internal/api/handlers/handlers_irc.go:437-476`
- **Issue:** Accepts an arbitrary `server_host` from the admin, dials it via `irc.NewTestBot → conn.Connect(addr)`, with no IP validation. Other `Test*` endpoints (`TestProbeConnection`, `TestEmail`) call `isValidExternalIP()`; `TestIRCServer` does not.
- **Fix:** Add the same `isBlockedIP` / `isValidExternalIP` check that `TestProbeConnection` has at `handlers_probes.go:362`.

### AUDIT-014 — SMTP critical-alert subject built from `device.Name` without CRLF sanitisation
- **File:** `internal/report/email.go:94`
- **Issue:** `subject := fmt.Sprintf("[CRITICAL] %s — %s (%s)", alert.AlertType, device.Name, device.IPAddress)`. `device.Name` is from the DB; an attacker who can register a device (or compromise a probe) can set it to `"X\r\nBcc: attacker@evil.com"`. The subject folds into MIME headers → header injection. The notifier's `sanitize` helper exists but is not applied here.
- **Fix:** Apply the `sanitize` helper from `notifier.go:284-288` to `device.Name` and `device.IPAddress` before formatting the subject. Better: sanitise inside `BuildCriticalAlertEmail`.

### AUDIT-015 — CORS `*` allowed with `Allow-Credentials: true`
- **File:** `internal/api/middleware/middleware.go:281-294`
- **Issue:** If the operator sets `CORS_ALLOWED_ORIGINS=*`, the wildcard short-circuits the origin check and any third-party site can issue authenticated cross-origin requests against the cookie-based auth.
- **Fix:** Reject `*` in `CORS_ALLOWED_ORIGINS` at config-load time when `Allow-Credentials: true` is in use. Document this in the runbook.

### AUDIT-016 — Probe registration key compared with `!=` not `hmac.Equal`
- **File:** `internal/api/handlers/handlers_probes.go:555-574`
- **Issue:** Bearer token (the probe's registration key) is looked up by `Where("registration_key = ?", token)` — string compare via SQL, not constant-time. Theoretical timing vector on a LAN.
- **Fix:** After fetching the probe by primary key (indexed lookup), compare the stored key to the presented key with `subtle.ConstantTimeCompare`.

### AUDIT-017 — Probe registration key stored in plaintext
- **File:** `internal/api/handlers/handlers_probes.go`, `internal/models/models.go` (Probe struct)
- **Issue:** `models.Probe.RegistrationKey` is stored unencrypted. Compromise of the DB → all probe tokens leaked. Other secrets (SNMP, IRC) are encrypted via `crypto.go`; probes are the odd one out.
- **Fix:** Encrypt at rest using the same AES-256-GCM pattern as IRC secrets at `crypto.go:122-148`. Add a `EncryptProbeSecrets` / `DecryptProbeSecrets` pair.

### AUDIT-018 — Stale dependencies
- **File:** `go.mod`
- **Issue:** `gin-gonic/gin v1.9.1` (2023, multiple CVEs), `thoj/go-ircevent` (2021, unmaintained), `gosnmp v1.37.0` (2023), `wcharczuk/go-chart/v2 v2.1.2` (2022). `golang-jwt/jwt/v5 v5.2.0` is missing CVE fixes addressed in 5.2.2+.
- **Fix:** Bump `gin` to 1.10.x, `golang-jwt` to 5.2.2+, `gosnmp` to 1.40+, and migrate off `thoj/go-ircevent` to `github.com/lrstanley/girc` (or pin a maintained fork). Run `govulncheck ./...` in CI.

### AUDIT-019 — IRC bot's `isAdmin` is "is this the bot's own nick?"
- **File:** `internal/irc/bot.go:493-500`
- **Issue:** The bot treats *itself* as admin. Any `AdminOnly: true` command is only executable by the bot itself (so an IRC channel operator can't accidentally trigger destructive actions), but the bot has no per-user RBAC. If a channel gets compromised the bot's `!reset`, `!config` etc. can be invoked by anyone who can speak in the channel.
- **Fix:** Add per-channel admin allow-list (`models.IRCAdmin` join table, or admin nick list in the `IRCChannel` model). Compare to e.Nick in `isAdmin` instead of the bot's own nick.

### AUDIT-020 — SSRF allowlist has DNS-rebinding TOCTOU
- **File:** `internal/api/handlers/handlers.go:103-125`
- **Issue:** `isBlockedIP` resolves the hostname at request time but the actual outbound dial re-resolves. An attacker controlling DNS returns a public IP on the first lookup and a private/loopback/link-local IP on the second. The check also doesn't reject 100.64.0.0/10 (CGNAT) or 0.0.0.0/8.
- **Fix:** Resolve once, dial the captured IP, pass the hostname as `ServerName` for TLS. For TCP/SMTP probes accept only IP literals. Add 100.64.0.0/10 and 0.0.0.0/8 to the block list.

### AUDIT-021 — `NoNewPrivileges` and friends not set in systemd units
- **File:** `deploy.sh:161-180`
- **Issue:** Generated systemd unit runs as `User=root` with no hardening directives. In Docker the binary runs as `fwmon` non-root. The two paths disagree.
- **Fix:** Use `User=fwmon`, add `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadOnlyPaths=/`, `PrivateTmp=yes`, `MemoryDenyWriteExecute=yes`.

### AUDIT-022 — CSP allows `'unsafe-inline'` for script and style
- **File:** `internal/api/middleware/middleware.go:257`
- **Issue:** `script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`. With `'unsafe-inline'` the CSP provides no XSS defense-in-depth. 12 inline `<script>` blocks, 8 inline `<style>` blocks across the 8 HTML files. 0 `eval` / `new Function` / `setTimeout(string)` (good).
- **Fix:** Generate a per-request nonce in `SecureHeaders` middleware, set it in `script-src 'nonce-<x>'`, have the admin templates reference it via `<script nonce="{{.}}">`. Drop `'unsafe-inline'`. Same for style-src via nonce or SHA-256 hashes.

### AUDIT-023 — `ReadHeaderTimeout` not set on the HTTP server
- **File:** `cmd/api/main.go:216-223`
- **Issue:** `ReadTimeout` is 30s but `ReadHeaderTimeout` is not. Slow-loris attacks that hold connections open with partial headers can tie up a goroutine per connection.
- **Fix:** Add `ReadHeaderTimeout: 10 * time.Second`.

### AUDIT-024 — `HSTS` only sent over TLS, but `COOKIE_SECURE=true` is the example default with `SERVER_ENABLE_TLS=false`
- **File:** `config.env.example:7,15` + `internal/api/middleware/middleware.go:254-256`
- **Issue:** `COOKIE_SECURE=true` ships as the example default but `SERVER_ENABLE_TLS=false` is the example default. Over plain HTTP the `Secure` cookie is dropped by the browser, so login doesn't work. Misleading config.
- **Fix:** Either tie `CookieSecure` to `SERVER_ENABLE_TLS` automatically, or reject the combination at startup, or send HSTS with `max-age=0` so clients learn.

### AUDIT-025 — `Permissions-Policy` header missing
- **File:** `internal/api/middleware/middleware.go:245-260`
- **Issue:** No `Permissions-Policy` header. The admin panel doesn't need camera, microphone, geolocation, USB, payment, accelerometer.
- **Fix:** Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=(), accelerometer=(), gyroscope=(), magnetometer=()`.

### AUDIT-026 — `IsSecret` not the gate for `EncryptField`
- **File:** `internal/api/handlers/handlers_settings.go:222`
- **Issue:** `s.Value = h.db.EncryptField(s.Value)` runs unconditionally on every setting save. Every system_setting row is encrypted, even non-sensitive ones like `cpu_threshold`. Wasteful and invites the v0.10.226-style "ciphertext as plaintext" bug class for a future field.
- **Fix:** Check `IsSecret` before encrypting. Or add a compile-time reflection check that flags new `Device` / `Probe` fields with names containing `Pass|Secret|Key|Community` and not redacted.

### AUDIT-027 — `decryptField` returns ciphertext on GCM auth failure
- **File:** `internal/database/crypto.go:86-91`
- **Issue:** On `gcm.Open` failure, the function returns the raw `{enc}<base64>` ciphertext to the caller. This is the v0.10.226 bug class — any other path that uses this value as plaintext leaks. The success path was fixed in v0.10.226; failure paths still leak.
- **Fix:** On any decrypt error, return an empty string and log at ERROR. Callers should treat empty as "missing" and fall through to the config/env fallback. Add a startup round-trip test.

---

## HIGH-priority findings — stability and data

### AUDIT-028 — `interface_stats` and `system_status` are not partitioned
- **File:** `internal/database/database.go:353-480`, `internal/models/models.go:8-74`
- **Issue:** 50 devices × 60s poll × 90d retention = ~130 M rows on `interface_stats` and ~7 M on `system_status`. Both are un-partitioned, no downsampling. Autovacuum tuning doesn't help at this scale. `syslog_messages`, `syslog_summaries`, `trap_events`, `flow_samples` are partitioned; these two are not.
- **Fix:** Add monthly partitions for both tables. Write the in-place migration `docs/partition-migration.md` references. Verify with `EXPLAIN` a 90-day-old chart query → should prune to <5 M rows.

### AUDIT-029 — Four tables have zero retention
- **File:** `internal/database/database.go:881-958`
- **Issue:** `interface_errors`, `processor_stats`, `process_stats`, `irc_message_logs` are not in the `entries` slice of `CleanupOldData`. Every probe poll appends a row forever. Will OOM the DB on a long-running deployment.
- **Fix:** Add entries to the `entries` slice. Default retention: 30 days for errors/processors, 7 days for IRC logs.

### AUDIT-030 — `interface_addresses` keeps appending the same IP every poll
- **File:** `internal/database/database.go:546-551`
- **Issue:** `SaveInterfaceAddresses` is a `Create`, not a deduped insert. 50 devices × 4 polls/min × 90d ≈ 25 M rows of mostly-redundant data.
- **Fix:** Switch to `INSERT ... ON CONFLICT (device_id, ip_address) DO UPDATE SET timestamp = EXCLUDED.timestamp` on Postgres; equivalent UPSERT for SQLite.

### AUDIT-031 — Alerts retention ignores unacknowledged alerts
- **File:** `internal/database/database.go:953-956`
- **Issue:** `DELETE FROM alerts WHERE acknowledged = true AND timestamp < ?`. A critical device that pages off-hours and goes unacked accumulates alert rows forever.
- **Fix:** Either (a) also delete unacked alerts older than N days with a warning log, or (b) move unacked alerts to an `alerts_archive` table and add a "stale unack" alert type.

### AUDIT-032 — `c.Request.Context()` is never passed to DB calls
- **File:** `internal/api/handlers/*.go` (186 `h.db.Gorm()` sites)
- **Issue:** Every DB call runs with `context.Background()`. A client disconnect does not cancel the query, the connection stays checked out, the goroutine doesn't exit until the DB returns. Under dashboard polling load (500 dashboards × 6 charts × 30s ≈ 100 RPS) this is the "DB pool exhausted" outage pattern.
- **Fix:** `h.db.Gorm().WithContext(c.Request.Context())` at the start of every handler. Or wrap GORM with a context-injecting middleware.

### AUDIT-033 — `GetDashboardAll` is textbook N+1
- **File:** `internal/api/handlers/handlers_dashboard.go:547-687`
- **Issue:** ~9 queries × N devices per dashboard load. At 50 devices, half a second per dashboard.
- **Fix:** Replace per-device loops with 6 batched aggregate queries using `LATERAL` joins or `DISTINCT ON` (Postgres) or window functions. Verify with `EXPLAIN ANALYZE` and a 50-device benchmark.

### AUDIT-034 — `cidrToLikePattern` → un-indexable LIKE on `flow_samples`
- **File:** `internal/database/database.go:3648-3697`
- **Issue:** Builds patterns like `192.168.1.%` and uses them in `WHERE src_addr LIKE ?` against `flow_samples`. No index on `src_addr` or `dst_addr`. Every flow stats query on a connection is a full table scan.
- **Fix:** Add `idx_flow_src_addr` and `idx_flow_dst_addr` (btree on `inet` if Postgres). Or replace LIKE with a `(src_addr <<= cidr OR dst_addr <<= cidr)` predicate using an `inet` column type and a `spgist` index.

### AUDIT-035 — `GetLatestVPNStatuses` does a per-peer sequential scan
- **File:** `internal/database/database.go:643-657`
- **Issue:** Loop over peerIDs, each iteration is a full `WHERE device_id = ? ORDER BY timestamp DESC`. For a device with 30 peers × 10 tunnels = 30 full scans per click.
- **Fix:** Single `WHERE device_id IN (?)` with `ROW_NUMBER() OVER (PARTITION BY device_id, tunnel_name ORDER BY ts DESC)`. Gated to `dialect.IsPostgres()`.

### AUDIT-036 — DB pool sized for one process, not three daemons
- **File:** `internal/database/database.go:70-73`
- **Issue:** `SetMaxOpenConns(25)`. The container runs `api`, `poller`, `trap-receiver` — each with its own pool. Actual ceiling is 75 conns/host. On a 50-device fleet the pool saturates and dashboard handlers block.
- **Fix:** Make the pool size per-process configurable. Default to something like 15 for `api`, 10 for `poller`, 5 for `trap-receiver`. Document in runbook.

### AUDIT-037 — No statement timeout / query deadline
- **File:** `internal/database/database.go` (`NewDatabase`)
- **Issue:** No `SET statement_timeout` in `NewDatabase`. No `WithContext(ctx, ...)` with `context.WithTimeout` on chart queries. A single slow query can hold a conn for tens of seconds.
- **Fix:** Add `SET statement_timeout = '30s'` per-connection in the Postgres `NewDatabase` branch. Add `WithContext(c.Request.Context())` everywhere (covered by AUDIT-032).

### AUDIT-038 — `CleanupOldData` does N full DELETEs serially
- **File:** `internal/database/database.go:907-956`
- **Issue:** Each `DELETE FROM x WHERE timestamp < ?` on a 130 M-row `interface_stats` table takes a long row lock, bloats the table, and blocks other writes. The 24h cleanup runs on every poller (no leader lock — see AUDIT-007) so two pollers deadlock-style wait.
- **Fix:** Batch deletes: `DELETE ... WHERE id IN (SELECT id FROM x WHERE ts < ? LIMIT 10000)` in a loop with `SET LOCAL lock_timeout = '5s'` on Postgres. Sleep 100ms between batches. Add the leader lock (AUDIT-007) so only one process runs it.

### AUDIT-039 — Per-daemon `BatchInserter` instances but only the api uses them
- **File:** `internal/database/database.go:88-96`, `cmd/poller/main.go`, `cmd/trap-receiver/main.go`
- **Issue:** All three daemons create a `syslogBatch`/`trapBatch`/`pingBatch`. The poller and trap-receiver never call `SaveSyslogMessage`/`SaveTrapEvent`/`SavePingResult`. Wasted overhead + the trap-receiver's nil DB means the batcher would fail anyway.
- **Fix:** Move batcher creation into a `NewDatabaseForAPI` constructor. Poller/trap-receiver use direct `db.Create` or no batcher at all.

### AUDIT-040 — Two `cmd/api` instances → 2 IRC bots, 2× login lockout, 2× rate limit
- **File:** `cmd/api/main.go:147-211`, `internal/auth/auth.go:46-58`, `internal/api/middleware/middleware.go:33-69`, `internal/uptime/uptime.go:38-51`
- **Issue:** All four state stores are in-process memory. Two api instances → 2 IRC bots with the same nick (collision), 2× login attempts before lockout, 2× rate limit, divergent uptime tracking.
- **Fix:** Short-term: document `RECOMMENDED_SINGLETON_API=1`, add a startup check that uses Postgres advisory lock to refuse if another api holds it. Long-term: move login attempts, rate limit, and uptime baseline to Postgres.

### AUDIT-041 — Probe ping write path is not batched
- **File:** `internal/database/database.go:1732` (`SavePingResult`)
- **Issue:** All other high-volume writes (`SaveSyslogMessage`, `SaveTrapEvent`) go through the batcher. `SavePingResult` is synchronous, one INSERT per probe per poll. On a 50-probe fleet this is 50 inserts × poll rate — enough to tax WAL at 10s polls.
- **Fix:** Add a 4th batcher for ping results. Same durability fix as AUDIT-006 applies.

### AUDIT-042 — Relay client has no idempotency key
- **File:** `internal/relay/relay.go:402-471`
- **Issue:** `syncData` sends a batch over HTTP. If the request times out at 30s and the server actually received it, the relay retries (3 attempts) → duplicate syslog/trap/ping rows. For traps harmless; for ping, double-counts downtime.
- **Fix:** Generate an `X-Probe-Batch-ID` UUID per batch on the probe, send it as a header, have the server dedupe via a `(probe_id, batch_id)` unique index or in-memory LRU.

### AUDIT-043 — Time-series chart SQL uses window functions unsupported by SQLite
- **File:** `internal/database/database.go:1373-1379, 3183-3212, 3588-3612`
- **Issue:** `LAG() OVER (PARTITION BY ...)` and tuple-`IN` in shared query path. SQLite ≥3.25 supports window functions, but the `WINDOW w AS (...)` named syntax differs from the inline form. Tests use SQLite, prod is Postgres — paths untested in CI.
- **Fix:** Gate the window-function queries behind `dialect.IsPostgres()` and add a non-window implementation for SQLite. Or bump the SQLite minimum version to 3.30 and document the requirement.

### AUDIT-044 — AutoMigrate is called on every startup with no schema version table
- **File:** `internal/database/database.go:185-348`
- **Issue:** 44 models, 12+ `AddColumn` shims, one destructive IRC drop-and-recreate heuristic (lines 242-263), no `schema_migrations` table. Two parallel `api` rollouts race. An on-call engineer at 3am about a column-not-found error has no migration log to consult.
- **Fix:** Adopt `golang-migrate` or `pressly/goose` with versioned up/down files. Add a `schema_migrations(version, applied_at)` table. Run only on explicit operator command (`./firewall-mon migrate`), not on startup. Remove the IRC drop-and-recreate heuristic.

### AUDIT-045 — `GetHealth` is a no-op
- **File:** `internal/api/handlers/handlers.go:82-93`
- **Issue:** Returns `{status: "healthy", snmp_connected, database}` without `db.Ping()`, without checking the batcher, without checking the notifier. A load balancer marking the instance healthy based on this has zero liveness signal.
- **Fix:** Call `db.Ping()`, check `sql.DBStats().InUse` against a threshold, check the three batchers aren't in `stopped` state, check notifier config. Return non-200 if any check fails. Add a separate `/api/live` (cheap) and `/api/ready` (deep) per Kubernetes convention.

---

## HIGH-priority findings — frontend (verified reproducible)

### AUDIT-046 — `probes.html` modals render on first paint
- **File:** `web/admin/probes.html:13`, `web/admin/probes.html:74`, `:110`
- **Issue:** Inline rule `.modal:not(.hidden) { display: flex }` (specificity 0,2,0) beats `.modal { display: none }` from `admin-shared.css:506` (0,1,0). Both `#probe-modal` and `#deploy-modal` carry `class="modal"` with no `.hidden` in markup, and `AdminCommon.openModal()` toggles `.active`, not `.hidden`. The bug is dormant only because the operator closes them.
- **Fix:** Replace `.modal:not(.hidden) { display: flex }` with `.modal.active { display: flex }` to match the convention in `admin-shared.css:516`.

### AUDIT-047 — Logout link is dead on `/admin/irc`
- **File:** `web/admin/irc.html:32`, `cmd/api/static/js/admin-irc.js:466-495`
- **Issue:** `admin-irc.js` delegated click switch has no `case 'logout'`. Every other admin page does. Clicking Logout navigates to `#` and stays on the page.
- **Fix:** Add `case 'logout': AC.doLogout(); return;` to the switch.

### AUDIT-048 — `.section-tab` redefines display, nullifying `.hidden` fix
- **File:** `web/admin/connection-detail.html:36-38, 82-83`, `admin-connection-detail.js:149,153`
- **Issue:** Inline `.section-tab { display: inline-block }` is loaded after `admin-shared.css` and `tailwind.css`. Equal specificity (0,1,0) for both, cascade order wins → `inline-block` overrides `display: none`. The v0.10.230 `classList.toggle('hidden', ...)` fix produces zero visual change on `#tab-phase2` and `#tab-flows`.
- **Fix:** Add `.section-tab.hidden { display: none !important; }` to the same inline `<style>` block.

### AUDIT-049 — IRC tab nav active state never updates
- **File:** `web/admin/irc.html:44-49`, `admin-irc.js:31-42`
- **Issue:** No `.tab-btn.active` rule exists anywhere (`grep` confirms only `.tab-btn:hover` and `.tab-btn:focus-visible`). JS toggles `.active` on the buttons with no visual effect. The active-tab highlight is hard-coded as Tailwind utility classes on the Servers button.
- **Fix:** Add `.tab-btn.active { color:#58a6ff; border-bottom-color:#58a6ff; }` to the inline `<style>`. Strip the static Tailwind active classes from the Servers button.

### AUDIT-050 — `admin-irc.js` is not IIFE-wrapped
- **File:** `cmd/api/static/js/admin-irc.js:1-3`
- **Issue:** `let servers = [];`, `let channels = [];`, `let commands = [];` and every function become globals on `window`. Inconsistent with every other admin JS file. `tasks/lessons.md` "Blank Admin Pages" entry explicitly called out IIFE as the safe pattern. ES6+ syntax used inconsistently.
- **Fix:** Wrap entire file in `(function() { 'use strict'; ... })();`. Convert to `var` / `function` style to match the rest of the codebase.

### AUDIT-051 — `probes.html` Reject uses native `window.prompt()`
- **File:** `cmd/api/static/js/admin-probes.js:325`
- **Issue:** Inconsistent with the styled reject modal that already exists on `/admin/probe-pending` (`probe-pending.html:37-55`). Lessons.md explicitly noted `AdminCommon.confirm()` is the standard.
- **Fix:** Move the reject modal markup into `probes.html` and reuse `showRejectModal()` from `admin-probe-pending.js`.

### AUDIT-052 — Public dashboard libs load WITHOUT `defer`
- **File:** `web/public/index.html:113-115`
- **Issue:** `chart.umd.min.js`, `chartjs-plugin-zoom.min.js`, `gridstack-all.min.js` block parsing while they download. ~290 KB blocks first paint on the public wallboard — exactly the page that matters most for time-to-render.
- **Fix:** Add `defer` to all three. Load order is already correct via DOM placement.

### AUDIT-053 — Dynamic `onclick="..."` in admin-device-detail
- **File:** `cmd/api/static/js/admin-device-detail.js:1118, 1119, 1120, 1442, 1446`
- **Issue:** Inline `onclick="viewConfigRevision(${r.id})"` etc. Works only because `script-src 'unsafe-inline'`. Inconsistent with the `data-action` + delegation pattern. Blocks any future CSP tightening.
- **Fix:** Convert to `data-action="view-config-revision" data-id="${r.id}"` and add cases to the existing `AC.delegateEvent` block.

### AUDIT-054 — admin.html has 1,500-line `<style>` block buried in `<body>`
- **File:** `web/admin/admin.html:1463-1478`
- **Issue:** Browsers re-parse and re-style → forced layout. Same `.modal { display:none }` rules are duplicated in `admin.html:40-47`, `connection-detail.html:39-40`, `probes.html:13`, `sites.html:11` — all redundant with `admin-shared.css:506-530`.
- **Fix:** Delete the inline duplications. Rely on `admin-shared.css` as the single source of truth.

### AUDIT-055 — Mobile sidebar only on `admin.html`
- **File:** `web/admin/irc.html`, `sites.html`, `probes.html`, `probe-pending.html`, `connection-detail.html`
- **Issue:** Only `admin.html` has the `.mobile-header` / `.sidebar.open` overlay machinery. The 240px fixed sidebar covers half a 375px viewport on the other pages and there's no menu button to collapse it.
- **Fix:** Extract `admin.html:185-203, 227-231, 167-180` into `AdminCommon.renderMobileChrome()` and call on every admin page.

### AUDIT-056 — Inline `<label>` without `for=""` (~60 inputs)
- **File:** `web/admin/probes.html`, `sites.html`, `irc.html`, `probe-pending.html`, most of `admin.html` modals
- **Issue:** Screen readers can't pair label to input. Only `login.html` does it right.
- **Fix:** Sweep and add `for=""` matching each input's `id`. Mechanical `sed`-style edit.

### AUDIT-057 — JS-rendered nav has no `aria-current` or `aria-hidden` on icons
- **File:** `cmd/api/static/js/admin-common.js:807-828`
- **Issue:** Active sidebar nav item has `.active` class but no `aria-current="page"`. JS-injected nav icons have no `aria-hidden="true"`. Screen readers can't identify the active page and read out every Unicode icon name.
- **Fix:** Inject `aria-current="page"` on the active link, wrap icons in `<span class="nav-icon" aria-hidden="true">`.

### AUDIT-058 — `apiFetch` 401 redirect fires inside iframes
- **File:** `cmd/api/static/js/admin-common.js:163-166`
- **Issue:** Reports preview iframe triggering a 401 redirects the iframe to the login page — login page rendered inside the report frame, confusing for the operator.
- **Fix:** Scope redirect to top frame: `(window.top || window).location.href = ...`.

### AUDIT-059 — `escapeHtml` short-circuits on falsy including numeric 0
- **File:** `cmd/api/static/js/admin-common.js:51`, `admin-irc.js:612`
- **Issue:** `if (!str) return '';` — `0`, `false`, `''`, `null`, `undefined`, `NaN` all become `''`. Numeric 0 fields render blank ("0 bytes in" silently empty).
- **Fix:** `if (str == null) return '';` (only nullish check).

### AUDIT-060 — No `@media print` rule, `.no-print` class is dead
- **File:** `web/admin/admin.html:930` (only `.no-print` usage)
- **Issue:** No `@media print` rule hides `.no-print`. Reports iframe has its own print styling baked in via the server template, but Ctrl+P on the main admin page prints the sidebar and all controls.
- **Fix:** Add `@media print { .sidebar, .no-print, .mobile-header, .toast-container { display: none } }` to `admin-shared.css`.

### AUDIT-061 — Per-tab Chart.js instances not destroyed on tab leave
- **File:** `cmd/api/static/js/admin-device-detail.js:460, 491`
- **Issue:** `proc-ssh-chart` and `iface-err-chart` Chart instances are created on first tab activation and never destroyed. After dozens of tab switches in a long operator session, stale handlers and chart contexts hold canvas references.
- **Fix:** In `switchTab` (line 1628), if leaving Process Monitor or Interface Errors, call `.destroy()` on the relevant chart and null the reference.

### AUDIT-062 — `admin-irc.js:23-28` showAlert uses inline `style.display` toggling
- **File:** `cmd/api/static/js/admin-irc.js:23-28`
- **Issue:** Resets to the v0.10.232 trap pattern. Each call schedules a new 5s `setTimeout` without clearing the prior one; back-to-back alerts hide each other prematurely.
- **Fix:** Toggle `.hidden` via `classList`. Track the timer id and `clearTimeout` before setting a new one.

### AUDIT-063 — Public dashboard "Reset Layout" wipes localStorage with no confirmation
- **File:** `web/public/index.html:93`, `public-dashboard.js:234-238`
- **Issue:** Single misclick destroys the operator's saved widget arrangement.
- **Fix:** Wrap in `AdminCommon.confirm({ title: 'Reset dashboard layout?', confirmLabel: 'Reset', danger: true })` — and include admin-common.js on the public dashboard for this.

### AUDIT-064 — N+1 in probes page loadProbeSummaryStats
- **File:** `cmd/api/static/js/admin-probes.js:45-69`
- **Issue:** One API call per approved probe to `/probes/:id/stats`. 20 probes = 20 sequential `apiFetch` calls. Lessons.md acknowledged this N+1 elsewhere.
- **Fix:** Add `GET /admin/api/probes/stats?ids=1,2,3` returning a map. Update the JS to call it once.

### AUDIT-065 — `cmd/api/static/js/admin-connection-detail.js:141` unescaped `conn.status` in innerHTML
- **File:** `cmd/api/static/js/admin-connection-detail.js:141`
- **Issue:** `statusEl.innerHTML = '<span class="badge ' + conn.status + '">'...`. Server validates to enum but defense-in-depth gap.
- **Fix:** Use `AC.escapeHtml(conn.status)` or build via `document.createElement`.

### AUDIT-066 — Color contrast `#484f58` on `#161b22` fails WCAG AA
- **File:** `web/admin/admin.html:91`
- **Issue:** Ratio 2.6:1, fails even AA-large. Used as `.lbl` text under stat values.
- **Fix:** Use `#8b949e` (5.31:1) consistently for subdued text.

### AUDIT-067 — Color contrast `#6e7681` on `#0d1117` passes AA only for large text
- **File:** multiple `.muted` rules
- **Issue:** Ratio 4.07:1, passes AA for large text only.
- **Fix:** Lift to `#8b949e` (5.31:1) for any text smaller than 18pt regular or 14pt bold.

### AUDIT-068 — Mobile chart/table overflow on device-detail
- **File:** `web/admin/device-detail.html:88`, processes table
- **Issue:** `style="display:none"` on `#extendedStats` — when shown, `grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))` can render two columns side-by-side with overflow. The 15-column processes table is unscrollable on mobile.
- **Fix:** Wrap in `overflow-x: auto` containers. Test at 375px / 768px / 1280px.

### AUDIT-069 — Focus management on modals
- **File:** `cmd/api/static/js/admin-common.js:653-696`
- **Issue:** `openModal` does focus trap + Esc-to-close. But the static modal markup has no `role="dialog"`, `aria-modal="true"`, or `aria-labelledby` — these are retroactively tagged by `tagStaticModals()` at line 725-744. Verify every modal has its title element with the correct id.
- **Fix:** Sweep all `web/admin/*.html` modals and add the `aria-*` attributes directly in markup so they don't depend on JS to be accessible.

### AUDIT-070 — `mobile-menu-btn aria-expanded` never updates
- **File:** `web/admin/admin.html:229`, JS toggle at `admin.html:191-194`
- **Issue:** `aria-expanded="false"` is in markup, but `classList.toggle('open')` never updates the attribute. Screen readers always think the menu is closed.
- **Fix:** Toggle the attribute alongside the class.

---

## HIGH-priority findings — code quality

### AUDIT-071 — 388 sites of `c.JSON(http.StatusInternalServerError, models.ErrorResponse(...))` boilerplate
- **File:** `internal/api/handlers/*.go`
- **Issue:** Repeated 388 times across the handlers. None log the underlying `err`.
- **Fix:** Add `httputil.InternalError(c, "operation X", err)` that logs `err` and returns the standard 500 JSON. Sweep all handlers.

### AUDIT-072 — `internal/database/database.go` is 4,210 LOC, 175 functions
- **File:** `internal/database/database.go`
- **Issue:** Single file contains connection lifecycle, every query, partition management, retention, rollup, autovacuum, crypto, vendor audit, migration. Hard to navigate, hard to test.
- **Fix:** Split along concern lines:
  - `database.go` — connection, lifecycle (~200 LOC)
  - `crud.go` — per-model reads/writes (~2,500 LOC)
  - `retention.go` — `CleanupOldData`, partition management (~400 LOC)
  - `rollup.go` — `RunFlowRollupCycle`, `RunSyslogAggregationCycle` (~400 LOC)
  - `migrate.go` — `AutoMigrate` + versioned migration runner (~300 LOC)
  - `audit.go` — `auditDeviceVendors` (~100 LOC)

### AUDIT-073 — `internal/models/models.go` mixes GORM structs with HTTP transport
- **File:** `internal/models/models.go:921-934`
- **Issue:** `APIResponse` / `SuccessResponse` / `ErrorResponse` are HTTP transport concerns that have no business in a GORM model package. Same for `LastUpAt` field at line 100 which is marked `gorm:"-"` and `omitempty` — dead.
- **Fix:** Move transport types to `internal/api/response`. Remove `LastUpAt` or wire it up.

### AUDIT-074 — `internal/irc/bot.go` has CR-only line endings
- **File:** `internal/irc/bot.go`
- **Issue:** Only file in the repo with broken line endings. Confuses diff tools, makes the file 3.7MB-bytes-per-line heavier than necessary.
- **Fix:** `unix2dos`-in-reverse: `sed -i 's/\r$//' internal/irc/bot.go`. Commit.

### AUDIT-075 — 16 files fail `gofmt -l`
- **Files:** `internal/configdiff/{normalize,validate,vendor_*}.go`, `internal/snmp/{snmp,vendor_firewalla}.go`, `internal/api/handlers/{handlers_data,handlers_devices,handlers_probes,handlers_config_diff_test}.go`, `internal/irc/bot.go`, `internal/ping/ping.go`, `internal/configdiff/normalize_test.go`, `internal/report/report_test.go`
- **Fix:** `gofmt -w .` once, commit. Add a CI gate: `test -z "$(gofmt -l .)"`.

### AUDIT-076 — No structured logging
- **File:** 151+ `log.Printf` sites across the codebase
- **Issue:** No `slog`, no `zerolog`, no `logrus`. No log levels, no request ID, no user ID, no correlation. The v0.10.236 + v0.10.238 bug chain shows the team relies on logs to diagnose issues, and a flat `log.Printf` stream is not searchable.
- **Fix:** Adopt `log/slog` (Go 1.21+ stdlib). Set `slog.New(slog.NewJSONHandler(os.Stderr, ...))` in `cmd/api/main.go`. Replace `log.Printf` with `slog.Info/Warn/Error`. Add a request-ID middleware. Add a `log/slog` field redaction layer for `password|secret|token|key|community` substrings.

### AUDIT-077 — No Prometheus `/metrics` endpoint
- **File:** repo root
- **Issue:** No `prometheus/client_golang` dependency, no `/metrics` route. No visibility on batcher queue depth, DB pool in-use/wait, HTTP request latency by endpoint, per-type alert firing rate, drop counters.
- **Fix:** Add `github.com/prometheus/client_golang`. Wire at `/metrics` (no auth, network-ACL protected). Counters: `alerts_fired_total{severity, type}`, `poll_cycles_total{result}`, `flow_samples_received_total`, `notification_send_duration_seconds`. Gauges: `batcher_queue_depth{type}`, `db_pool_in_use`, `db_pool_wait_count`, `goroutine_count`. Histograms: `http_request_duration_seconds{path, method, status}`.

### AUDIT-078 — No admin-action audit log
- **File:** repo root
- **Issue:** No record of who reset uptime, who changed alert thresholds, who deleted a device, who approved a probe, who snoozed an alert. `login_attempts` is logged but no privileged-action log.
- **Fix:** New `models.AuditLog (id, actor, action, target, before, after, at)`. New `internal/audit/audit.go` middleware that wraps every `POST/PUT/DELETE`. New page `/admin/audit` with filter by actor/action/date. Optionally make it tamper-evident (HMAC chain — see AUDIT-117).

### AUDIT-079 — `c.Request.Context()` not used; no per-request cancellation
- **File:** `internal/api/handlers/*.go`
- **Fix:** Same as AUDIT-032 — `WithContext(c.Request.Context())` everywhere.

### AUDIT-080 — Many `if err == gorm.ErrRecordNotFound` instead of `errors.Is`
- **File:** `internal/database/database.go:578,591,613,864,1388`, `internal/auth/auth.go:75`, `internal/notifier/notifier.go:112`
- **Issue:** 8 sites of direct `==` comparison with sentinels. Works today but breaks silently if any caller ever wraps with `%w`.
- **Fix:** Sweep to `errors.Is(err, gorm.ErrRecordNotFound)` and `errors.Is(err, auth.ErrAccountLocked)`.

### AUDIT-081 — 46 sites of `return err` raw in `internal/database/database.go`
- **File:** `internal/database/database.go:833,838,849,854,1170,1214,1263,1267,1408,1490, etc.`
- **Issue:** GORM `tx.Error` is not wrapped. Callers can't tell "not found in a tx" from "constraint violation in a tx".
- **Fix:** Wrap with `fmt.Errorf("operation X: %w", err)` so callers can use `errors.Is` / `errors.As`.

### AUDIT-082 — Mutex held across HTTP call in relay
- **File:** `internal/relay/relay.go:38-43, 317-323`
- **Issue:** `mu.Lock()` + `n.client.Do(req)` happens under the lock, blocking all other queue producers.
- **Fix:** Snapshot the queue under lock, release, then send. Send failures re-queue with a `trylock` or a non-blocking push to a dead-letter channel.

### AUDIT-083 — Rate limiter cleanup goroutine leaks
- **File:** `internal/api/middleware/middleware.go:57-69`
- **Issue:** `go rl.cleanup()` is never stopped, and the `limiters` map has no size cap. An attacker spraying unique source IPs grows it to millions → OOM.
- **Fix:** Add `Stop()` method, plumb a global `ctx` from main, cap map size at e.g. 50k entries with LRU eviction.

### AUDIT-084 — `authManager.PruneExpiredAttempts` goroutine leak
- **File:** `cmd/api/main.go:97-103`
- **Issue:** Process exit terminates it, but it has no shutdown hook and no `ctx`. If `log.Fatal` triggers elsewhere, defers don't run.
- **Fix:** Use `select { case <-ticker.C: ...; case <-ctx.Done(): return }`.

### AUDIT-085 — Probe auth handler not transactional
- **File:** `internal/api/handlers/handlers_probes.go:472-484`
- **Issue:** Old `registration_key` `SystemSetting` is deleted before the new key is generated and written. If the new key generation fails, the probe is locked out permanently.
- **Fix:** Wrap in a transaction: generate new key → update probe → delete old setting → create new setting → commit.

### AUDIT-086 — `cmd/api/main.go:225-236` listen goroutine uses `log.Fatal`
- **File:** `cmd/api/main.go:225-236, 240-250`
- **Issue:** `log.Fatal` from inside a goroutine bypasses all defers — `db.Close()`, `ircManager.Stop()`, `snmpClient.Close()` not called, batchers not flushed. Data loss on listen failure.
- **Fix:** Replace `log.Fatal` with `log.Printf` and a done channel; let the main goroutine pick it up and shut down gracefully via the existing signal handler.

### AUDIT-087 — `cmd/probe/main.go:343-408` pollDevice no ctx
- **File:** `cmd/probe/main.go:343-408`
- **Issue:** `pollDevice` doesn't accept a `ctx`, and `go p.pollDevice(dev)` (line 337) is untracked. After `p.stopChan` is closed, in-flight polls continue without bounds.
- **Fix:** Add `ctx` everywhere. Bounded `time.AfterFunc` cancels in probe `Stop`.

### AUDIT-088 — `time.Sleep` in retry loops without jitter
- **File:** `internal/relay/relay.go:370, 450, 469`, `internal/irc/bot.go:910`
- **Issue:** `time.Sleep(100*time.Millisecond)` / `time.Sleep(1*time.Second)` deterministic. Thundering herd against the server when many probes come back online simultaneously.
- **Fix:** `time.Duration(crypto_rand.Int(...))` jitter or a proper backoff library (`cenkalti/backoff`).

### AUDIT-089 — Dead code
- **File:** `internal/models/models.go:100`, `internal/httputil/httputil.go:43-53` (`ParseHours`), `internal/httputil/httputil.go:67` (`FilterAllowedFields`), `internal/api/handlers/handlers.go:127-...` (`validVendors`), `config.env.example:14` (`ADMIN_SECRET_KEY`)
- **Fix:** Remove or wire up. Run `staticcheck -unused` after the CI linter is enabled.

### AUDIT-090 — No OpenAPI spec / no API versioning
- **File:** `cmd/api/main.go:67-76` (path-rewrite hack), `cmd/api/main.go:297-562` (route table)
- **Issue:** 100+ endpoints hand-rolled, no OpenAPI, no `/api/v1` for real versioning (just a path-rewrite synonym), no deprecation markers. The JS frontend is the de-facto contract.
- **Fix:** Add `swaggo/swag` annotations to handlers. Generate `docs/api/openapi.yaml`. Add real `/api/v1` route group with a deprecation policy for old paths.

---

## HIGH-priority findings — Docker / deploy

### AUDIT-091 — No `HEALTHCHECK` in Dockerfile
- **File:** `Dockerfile`
- **Issue:** Docker, compose, k8s, Portainer, Uptime Kuma all rely on `HEALTHCHECK` to distinguish "container is up" from "ready to serve." The 3-process entrypoint + Postgres makes liveness vs readiness critical.
- **Fix:** `HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/api/health || exit 1`. Make the `/api/health` check meaningful first (AUDIT-045).

### AUDIT-092 — `.dockerignore` missing many entries
- **File:** `.dockerignore`
- **Issue:** Missing: `cookies.txt`, `interfaces.json`, `IRC-FORMAT.txt`, `node_modules/`, `tasks/`, `.claude/`, `lessons.md`. They sit in the working tree; if a future PR `COPY`s more loosely they end up in the image.
- **Fix:** Add the missing lines.

### AUDIT-093 — Hardcoded Postgres password `fwmon`
- **File:** `entrypoint.sh:51,63`
- **Issue:** `CREATE USER fwmon WITH PASSWORD 'fwmon'` is the embedded DB used in production Docker. Anyone reading the Dockerfile can log in.
- **Fix:** Generate a random DB password on first init, write to `/config/pg-credentials` mode 0600, readable by the app.

### AUDIT-094 — `entrypoint.sh:134` runs 3 binaries with bare `wait`
- **File:** `entrypoint.sh:134`
- **Issue:** When any one process exits, the container exits. No supervisor; no restart of the other two. Combined with `restart: unless-stopped` in compose, a crash loop on one binary takes the whole stack down with no log retention.
- **Fix:** Use `s6-overlay` or `supervisord` for per-process supervision. Or split into 3 containers in `docker-compose.yml`.

### AUDIT-095 — `entrypoint.sh:37` sets `logging_collector = off`
- **File:** `entrypoint.sh:37`
- **Issue:** Crash forensics lost.
- **Fix:** Enable `logging_collector = on`. Set `log_destination = 'stderr'` so Postgres logs go to Docker's log driver.

### AUDIT-096 — `docker-compose.yml` no healthcheck
- **File:** `docker-compose.yml`
- **Issue:** No `healthcheck:` for `firewall-mon` or any service. `depends_on` with health conditions not used.
- **Fix:** Add `healthcheck:` blocks. Use `depends_on: firewall-mon: condition: service_healthy`.

### AUDIT-097 — `docker-compose.proxy.yml` is stock with no reverse-proxy config
- **File:** `docker-compose.proxy.yml`
- **Issue:** No TLS termination config, no HSTS header injection, no gzip/brotli, no WebSocket upgrade headers, no real client IP. Gin has `router.SetTrustedProxies(nil)` so X-Forwarded-For is ignored.
- **Fix:** Ship a companion `nginx.conf` with: TLS termination, HSTS preload, gzip/brotli, WebSocket upgrade for `/admin/connections` and IRC WS, `set_real_ip_from 172.0.0.0/8; real_ip_header X-Forwarded-For;`. Update `SetTrustedProxies` to trust the proxy subnet.

### AUDIT-098 — `deploy.sh:98` is destructive
- **File:** `deploy.sh:98`
- **Issue:** `rm -rf ${REMOTE_DIR}/*` wipes the install dir before rsync. No rollback, no healthcheck after.
- **Fix:** Use rsync's `--delete` with explicit exclusion list, run a healthcheck after `systemctl start`, write a `pre-deploy` backup step.

### AUDIT-099 — `deploy.sh:64-114` overwrites live config
- **File:** `deploy.sh:64-114, 102, 107`
- **Issue:** `cp /tmp/config.env.example /etc/firewall-mon/config.env` overwrites the operator's live config on every deploy.
- **Fix:** `if [ ! -f /etc/firewall-mon/config.env ]; then cp ...; fi`.

### AUDIT-100 — `deploy.sh` systemd units run as `User=root`
- **File:** `deploy.sh:161-180`
- **Issue:** Contradicts the Docker `fwmon` non-root user.
- **Fix:** Use `User=fwmon`. Add hardening directives (see AUDIT-021).

### AUDIT-101 — Dockerfile OCI labels hardcoded
- **File:** `Dockerfile:47-48`
- **Issue:** `org.opencontainers.image.version="0.10.239"` is hardcoded. Was caught stale at v0.10.237. Will recur.
- **Fix:** `ARG VERSION=dev`, set `LABEL org.opencontainers.image.version=$VERSION`. CI passes `--build-arg VERSION=${GITHUB_REF_NAME}`. Add `.source`, `.revision`, `.created`, `.licenses="MIT"`, `.vendor` labels.

### AUDIT-102 — `go build` lacks `-trimpath -buildvcs=false`
- **File:** `Dockerfile:15-18`
- **Issue:** Binaries not reproducible. Same source on two machines produces different bytes (GOPATH paths, build IDs, VCS info).
- **Fix:** `RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-X main.ServerVersion=${VERSION}" ...`. Set `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`.

### AUDIT-103 — `Dockerfile:5-6` installs unused `gcc musl-dev`
- **File:** `Dockerfile:5-6`
- **Issue:** `apk add --no-cache gcc musl-dev` in the builder stage, but `CGO_ENABLED=0` means gcc is never used.
- **Fix:** Remove. Or switch to a `golang:1.23-alpine` builder and `gcr.io/distroless/static:nonroot` runtime.

### AUDIT-104 — No `make install` / native-binary path
- **File:** repo root
- **Issue:** README only documents Docker. Users on FreeBSD, Synology, RHEL without systemd, or k8s without a Docker socket are stranded.
- **Fix:** Add `make install` and `make tarball` targets. Document non-Docker install in the runbook.

### AUDIT-105 — Default `ADMIN_USERNAME=admin`
- **File:** `config.env.example:20`
- **Issue:** No warning when the default is kept.
- **Fix:** Add a startup warning if `ADMIN_USERNAME=admin`. Suggest `ADMIN_USERNAME=<something-unique>`.

---

## HIGH-priority findings — docs

### AUDIT-106 — README documents 12 endpoints; code registers 100+
- **File:** `README.md:109-125` vs `cmd/api/main.go:297-562`
- **Issue:** README silently omits the entire `/admin/api/sites`, `/admin/api/probes*`, `/admin/api/syslog`, `/admin/api/flows`, `/admin/api/maintenance`, `/admin/api/alert-policies`, `/admin/api/reports/preview`, `/admin/api/reports/send`, `/admin/api/network`, plus all 16 probe ingestion POSTs.
- **Fix:** Auto-generate from the route table. Or hand-sweep and add the missing sections. Add "Who is this for" / "When NOT to use this" / "Comparison to PRTG/Nagios/Zabbix/LibreNMS/Checkmk/Uptime Kuma/StatusCake" sections.

### AUDIT-107 — Documented env vars are 6 lines; `config.env.example` is 70+
- **File:** `README.md:72-78`, `config.env.example:1-71`
- **Issue:** No mention of `ENCRYPTION_KEY`, `RETENTION_*`, `PROBE_*`, `REPORT_*`, `SPIKE_*`, `SERVER_*_TIMEOUT`. Operator has to read the source to find defaults.
- **Fix:** Reference `config.env.example` in README. Add inline `// default: 7` comments to the struct fields. Generate a defaults table.

### AUDIT-108 — No architecture diagram
- **File:** `README.md:17-43`
- **Issue:** Text tree, not a real diagram. No data-flow showing poller→DB→API→public-dashboard, no probe↔server flow, no trap-receiver ingress.
- **Fix:** Add Mermaid `graph` block under "Architecture." Sequence diagrams for: probe registration, poll cycle, alert firing.

### AUDIT-109 — README feature list stale
- **File:** `README.md:7-13`
- **Issue:** Omits: reports (`/admin/reports`, v0.10.236), sites, alert policies, maintenance windows, IRC bot, connection diagram, sFlow/syslog/ICMP collection via probe, multi-tenant probe architecture.
- **Fix:** Update feature list to match reality.

### AUDIT-110 — CHANGELOG not Keep-A-Changelog
- **File:** `CHANGELOG.md` (3,324 lines)
- **Issue:** No "Unreleased" section. No "Breaking Changes" callout. Section headings are free-form (`### Fixed`, `### Improved`, `### Redesigned`). Not machine-readable. No `KNOWN-ISSUES.md` link. No `git-cliff` or `release-please` automation.
- **Fix:** Adopt Keep-A-Changelog strictly. Add `## [Unreleased]`. Add `### BREAKING CHANGES` per release. Add `KNOWN-ISSUES.md`. Consider `git-cliff` to auto-generate from conventional commits.

### AUDIT-111 — No RUNBOOK.md / OPERATIONS.md
- **File:** repo root (missing)
- **Issue:** No first-24h checklist, no common-failure-mode runbook, no debug-logging procedure, no admin password reset procedure, no JWT secret rotation procedure, no backup/restore procedure, no upgrade procedure, no scale/HA procedure, no disaster-recovery playbook.
- **Fix:** Create `docs/OPERATIONS.md` with sections: First-24h checklist, Failure modes (8+ items), Debug logging (`LOG_LEVEL`, `GIN_MODE=debug`, Postgres `log_min_messages=info`), Password reset, JWT secret rotation (with a feature flag for the rotation period), Backup & restore (`pg_dump` + baseline-file copy + probe-key backup), Upgrade (compose pull, breaking-change callouts from CHANGELOG), Scale (multi-instance caveats, advisory lock for poller), DR (target RTO < 1h).

### AUDIT-112 — No `.well-known/security.txt` route
- **File:** repo root
- **Issue:** Many vulnerability disclosure programs require this.
- **Fix:** Add a route `/.well-known/security.txt` (RFC 9116) returning a static text. Or have it served from the admin handler.

### AUDIT-113 — No "How to add a vendor" doc
- **File:** repo root
- **Issue:** 7 SNMP vendor files and 4 configdiff vendor files share an obvious convention but it's nowhere written.
- **Fix:** Add `docs/ADDING-A-VENDOR.md` with steps: register in `internal/snmp/vendor.go` + `internal/configdiff/normalize.go` + tests in both. Document the interface contract for each.

### AUDIT-114 — README "Build" instructions may not work on fresh Ubuntu
- **File:** `README.md:53-70`
- **Issue:** No prereqs list (no `apt install rsync`, no `bash ≥4`, no `systemd` mention for `install`, no `rsync` for `deploy`, no firewall port hints 162/514/6343/8089).
- **Fix:** Add a prereqs section. Test on a fresh Ubuntu 24.04 box.

### AUDIT-115 — `lessons.md` and `tasks/` should not be public
- **File:** repo root
- **Issue:** `lessons.md` is AI agent session memory, not for human contributors. `tasks/todo.md` and `tasks/lessons.md` are operator-private notes.
- **Fix:** Move to `.claude/` (already gitignored) or delete from public tree. Or rename to `docs/internal/` and add a clear "internal — not for users" header.

---

## HIGH-priority findings — testing (after AUDIT-001)

### AUDIT-116 — `*_test.go` in `.gitignore` (also AUDIT-001)
- **Status:** duplicated here so the testing section is self-contained.
- **Fix:** See AUDIT-001.

### AUDIT-117 — Critical-path packages have zero test coverage
- **Files:** `internal/auth/`, `internal/api/middleware/`, `internal/database/`, `internal/notifier/`, `internal/snmp/`, `internal/irc/`, `internal/syslog/`, `internal/sflow/`, `internal/uptime/`, `internal/relay/`, `internal/ping/`, `internal/httputil/`, `internal/config/`, `internal/models/`
- **Issue:** 14 of 22 Go packages have 0% test coverage. Includes the security boundary (auth, middleware), the data layer (database, batcher, crypto), and all untrusted-input parsers (snmp, syslog, sflow, irc, trap).
- **Fix:** Add `_test.go` for each. Start with:
  1. `internal/auth/` — login lockout, bcrypt round-trip, JWT sign + alg-confusion rejection, `ValidateToken` TokenVersion check, `GenerateSecureToken` length invariant
  2. `internal/api/middleware/` — CSRF (missing header / mismatch), CORS (unknown origin), `LoginRateLimiter` (429 after burst), `BodySizeLimit` (413)
  3. `internal/database/batcher.go` — concurrent Add+Flush, Stop blocks until drain (run with `-race`)
  4. `internal/database/crypto.go` — round-trip, key-rotation with old+new keys, GCM auth failure returns empty
  5. `internal/notifier/` — Slack/Discord/webhook via `httptest.Server`, SMTP via `net.Pipe` exercising STARTTLS/LOGIN/PLAIN
  6. `internal/httputil/redact.go` — table-driven + reflection-based test that flags new secret fields
  7. `internal/snmp/trap.go` — fuzz the parser
  8. `internal/syslog/`, `internal/sflow/` — fuzz the parsers

### AUDIT-118 — Tests run on SQLite; production is Postgres
- **File:** `internal/database/testing.go:21`, `internal/database/database.go:62`
- **Issue:** Test DB is `:memory:` SQLite. Production is Postgres exclusively. Every Postgres-specific path (partitions, advisory lock, `to_char` minute-bucket that broke spike timestamps in v0.10.238, autovacuum SQL) is verified only by hand on the operator's box.
- **Fix:** Add a build-tagged `_integration_test.go` suite using `testcontainers-go` (or accept a `TEST_PG_DSN` env). Run migrations, assert partitions exist, assert `TimeBucket("minute", ...)` produces a string Go can `time.Parse`. Gate behind `make test-integration`.

### AUDIT-119 — No fuzz tests for untrusted network parsers
- **Files:** `internal/syslog/`, `internal/sflow/`, `internal/snmp/trap.go`, `internal/configdiff/normalize.go`
- **Issue:** All parse untrusted input from the LAN. A malformed sFlow datagram or syslog frame is an instant DoS / panic vector. Zero fuzz tests.
- **Fix:** Add `FuzzSyslogParse`, `FuzzSflowDatagram`, `FuzzParseTrap`, `FuzzNormalizeConfig`. Seed corpus with one valid frame. CI burns 30s of fuzz per target on every PR.

### AUDIT-120 — No property-based tests
- **Files:** `internal/uptime/`, `internal/report/spike.go`
- **Issue:** Uptime %, counter-delta math, spike-detect math are textbook candidates for `testing/quick` style property tests. None exist.
- **Fix:** Use `github.com/leanovate/gopter` or hand-roll property tests.

### AUDIT-121 — No race detector in CI
- **File:** CI config (missing)
- **Issue:** Even forcing `CGO=1`, batcher and rate-limiter have known goroutines and have never been raced.
- **Fix:** `go test -race -count=1 ./...` in the CI workflow.

### AUDIT-122 — Dead test in `handlers_config_revision_retention_test.go:282`
- **File:** `internal/api/handlers/handlers_config_revision_retention_test.go:282`
- **Issue:** `_unused_legacy_top50_test(t *testing.T)` is a 60-line "deleted" test left in place with a leading underscore.
- **Fix:** Delete.

### AUDIT-123 — No integration tests
- **File:** repo root
- **Issue:** No `make test-integration`, no `_integration_test.go`, no build tag splitting.
- **Fix:** Add `//go:build integration` tag. `make test-integration` target. CI runs on a Postgres service container.

### AUDIT-124 — No benchmark tests
- **File:** repo root
- **Issue:** `BenchmarkX` functions absent. No baseline for `interface_stats` ingestion rate or report rendering time.
- **Fix:** Add benchmarks for the hot paths identified in AUDIT-033/034/035.

---

## MEDIUM-priority findings

### AUDIT-125 — Inline event handler generation in admin-device-detail
- **File:** `cmd/api/static/js/admin-device-detail.js:697, 764, 819, 840, 899, 962, 991`
- **Issue:** `innerHTML` with template literals. Currently uses `AC.escapeHtml` but the pattern is risky for new contributors.
- **Fix:** Build DOM via `document.createElement` for any new code. Document the rule in `cmd/api/static/js/README.md` (create if missing).

### AUDIT-126 — `cmd/api/static/js/admin-device-detail.js:3740` lines, 213KB
- **File:** `cmd/api/static/js/admin-device-detail.js`
- **Issue:** Largest file in the static dir. Single IIFE, 120 functions, every tab's logic mixed in.
- **Fix:** Split per tab: `admin-device-detail-{tab}.js`. Load via `<script defer>` per page.

### AUDIT-127 — `admin-controls.js:150` history.replaceState only for filter pills
- **File:** `cmd/api/static/js/admin-controls.js:150`
- **Issue:** No router. Each page is a separate URL; back-button doesn't work as expected.
- **Fix:** Implement minimal hash-based or History API router. Or accept the limitation and document.

### AUDIT-128 — `formatDate` hardcodes en-US locale
- **File:** `cmd/api/static/js/admin-common.js:38, 42`
- **Fix:** Read locale from `navigator.language`. Use `Intl.DateTimeFormat`.

### AUDIT-129 — No Sentry / frontend error reporting
- **File:** `cmd/api/static/js/admin-common.js`
- **Issue:** When something fails in production the operator has no visibility. The toast shows the error, but it's gone after 5s.
- **Fix:** Optional `window.FwmonSentryDsn` config. POST errors to `/admin/api/client-error`. Or just persist to localStorage and let the operator download the log.

### AUDIT-130 — No retry on transient API failures
- **File:** `cmd/api/static/js/admin-common.js:151-181`
- **Issue:** `apiFetch` does not retry 502/503/504. A flaky network surfaces as a 500-equivalent toast.
- **Fix:** Add exponential-backoff retry on 502/503/504, max 3 attempts, with jitter.

### AUDIT-131 — `admin-irc.js` uses ES6+ while codebase is ES5
- **File:** `cmd/api/static/js/admin-irc.js`
- **Issue:** `let`, `const`, arrow functions, template literals, `async/await`, spread. The codebase pattern is `var` / `function`. `admin-login.js:40` even has `['catch']` for IE11 safety. Pick one.
- **Fix:** Standardise on ES5 + `async/await` (or full ES2020 everywhere). Document in `cmd/api/static/js/README.md`.

### AUDIT-132 — `:has()` CSS used; needs Safari 15.4+ / Chrome 105+
- **File:** `web/admin/admin.html:104, 124`, `connection-detail.html:33`, `admin-device-detail.css`
- **Issue:** Modern but worth knowing baseline. No `<script type="module">` so no actual ES2022 features.
- **Fix:** Document baseline in README. If "evergreen" is OK, drop the IE11 `['catch']` workaround in `admin-login.js:40`.

### AUDIT-133 — `formatBytes(NaN)` falls through to `Math.log(NaN) / Math.log(1024) = NaN`
- **File:** `cmd/api/static/js/admin-common.js`
- **Issue:** Renders "NaN.0 undefined". Edge case.
- **Fix:** `if (!isFinite(bytes)) return '—';` at the top of `formatBytes`.

### AUDIT-134 — Hardcoded version of `package.json`
- **File:** `package.json:3`
- **Issue:** Stale at `0.10.157`. Not enforced.
- **Fix:** Make `package.json` version come from `go run ./cmd/api -version` in a Makefile target. Or remove the `version` field — it's not used by anything.

### AUDIT-135 — No `slog` request-ID middleware
- **File:** `internal/api/middleware/middleware.go:308-329`
- **Issue:** RequestLogger logs only method/path/status/latency. No request ID. Impossible to trace a single click through the logs.
- **Fix:** Generate a UUID per request, set it in the response header `X-Request-ID`, include in every log line via `slog.With("request_id", id)`.

### AUDIT-136 — `cmd/api/main.go:104-121` IsGeneratedPassword heuristic
- **File:** `cmd/api/main.go:104-121`
- **Issue:** Uses `os.LookupEnv` to detect if `ADMIN_PASSWORD` was set. Fragile — if the env is set to empty, it doesn't count.
- **Fix:** Set a `cfg.Auth.AdminPasswordIsGenerated bool` in `config.Load()` based on whether the env was actually set.

### AUDIT-137 — `cmd/api/main.go:114` logs masked password
- **File:** `cmd/api/main.go:114`
- **Issue:** `log.Printf("Password: %s ...", masked)` — the first 3 / last 3 chars of the password end up in container logs. Narrows brute-force space.
- **Fix:** Don't log even masked passwords. Print the file path and instruct the operator to fetch it.

### AUDIT-138 — `cmd/api/main.go:67-76` URL-rewrite prefix-collision
- **File:** `cmd/api/main.go:67-76`
- **Issue:** Safe today but fragile. A `..` in a public path can't escape into admin paths, but the rewrite is hand-coded.
- **Fix:** Replace with a proper `gziphandler`-style middleware, or document the v1 path-rewrite as deprecated and move to real versioning (AUDIT-090).

### AUDIT-139 — `cmd/api/static.go` embeds with `//go:embed static`
- **File:** `cmd/api/static.go:5-6`
- **Issue:** No minification of project JS. `admin-main.js` is 213 KB unminified, shipped as-is.
- **Fix:** Add an `esbuild` step to `Makefile` / CI that minifies into `cmd/api/static/js/dist/`. Have the embed point there.

### AUDIT-140 — 0 `t.Parallel()` in any test
- **File:** all test files
- **Issue:** Every test runs serially.
- **Fix:** Mark safe tests with `t.Parallel()`. Especially in `batcher_test.go`, `middleware_test.go`.

### AUDIT-141 — No `t.TempDir()` / `t.Cleanup()`
- **File:** all test files
- **Issue:** Tests that touch the filesystem (uptime baseline) would benefit.
- **Fix:** Adopt the pattern. Run `staticcheck` to enforce.

### AUDIT-142 — No `testing.Short()` gating
- **File:** all test files
- **Issue:** No fast/slow test split. `go test -short` does nothing.
- **Fix:** Add a `testing.Short()` skip around integration tests.

### AUDIT-143 — Bulk-ack by filter, not bulk snooze
- **File:** `internal/api/handlers/handlers_analytics.go:480` (bulk ack); no bulk snooze
- **Fix:** Add `BulkSnoozeAlertsByFilter` mirroring the ack handler.

### AUDIT-144 — Auto-resnooze when alert clears
- **File:** `internal/alerts/alerts.go:497` (`sendRecovery`)
- **Issue:** A snoozed alert doesn't auto-unsnooze when the underlying issue clears.
- **Fix:** In `sendRecovery`, clear the snooze fields on matching active alerts.

### AUDIT-145 — `parseBucketToMillis` zero-row → 1970 datapoint
- **File:** `internal/database/database.go:2104-2118`
- **Issue:** Empty bucket returns `0` (Jan 1 1970 epoch ms) which the chart renders as a 1970 datapoint.
- **Fix:** Return `nil` or `time.Time{}` for empty buckets; chart code should skip.

### AUDIT-146 — `EnsurePartitions` logs warning and skips for non-partitioned tables
- **File:** `internal/database/database.go:401-478`
- **Issue:** Initial tables are non-partitioned (AutoMigrate doesn't create partitioned tables), so partitions are never created and high-volume tables grow unbounded.
- **Fix:** Detect and offer a migration, or run a one-time `ALTER TABLE ... PARTITION BY RANGE (timestamp)` after first start.

### AUDIT-147 — `ConfigureAutovacuum` table list hard-coded
- **File:** `internal/database/database.go:484-521`
- **Issue:** New tables (`AlertPolicy`, `AlertRule`, etc.) not included.
- **Fix:** Make the table list a config field or auto-discover.

### AUDIT-148 — `cidrToLikePattern` doesn't escape `%` and `_`
- **File:** `internal/database/database.go:3648-3697`
- **Issue:** If a device publishes `local_subnet = "10.0.0._"` the LIKE pattern is `10.0.0._` which is `LIKE 10.0.0.<any char>`. Unlikely but unexpected.
- **Fix:** `LIKE` `ESCAPE '\'` with explicit escape on the input.

### AUDIT-149 — GORM `Logger: logger.Silent` swallows all DB errors
- **File:** `internal/database/database.go:160-163`
- **Issue:** Combined with AutoMigrate-warnings-as-info, the entire DB layer is silent on errors that don't propagate to the caller.
- **Fix:** At least `logger.Warn` for production. Or a custom logger that logs statements > 500ms.

### AUDIT-150 — No OpenTelemetry tracing
- **File:** repo root
- **Issue:** No `otelhttp` middleware. The cross-process call (probe → api) is invisible end-to-end. The relay retries show up as 3 separate `log.Printf` lines with no correlation ID.
- **Fix:** Adopt `go.opentelemetry.io/otel`. Wire otelhttp middleware. Add trace IDs to log lines.

---

## LOW-priority findings (polish)

### AUDIT-151 — 103 `console.*` calls in admin JS
- **File:** all `cmd/api/static/js/admin-*.js`
- **Issue:** None leak credentials (verified). Unfiltered `console.error` in `admin-main.js:2579` ("Password change failed:") prints error stack trace to browser console. Fine for debugging; gate behind `DEBUG` flag for public release.

### AUDIT-152 — No `gofmt` enforcement in CI
- **File:** CI config
- **Fix:** Add CI gate: `test -z "$(gofmt -l .)"`.

### AUDIT-153 — `MODEL.go` LastUpAt is dead
- **File:** `internal/models/models.go:100`
- **Fix:** Remove or wire up.

### AUDIT-154 — `internal/httputil/httputil.go:43-53` ParseHours unused
- **File:** `internal/httputil/httputil.go`
- **Fix:** Remove or wire up.

### AUDIT-155 — `internal/httputil/httputil.go:67` FilterAllowedFields unused
- **File:** `internal/httputil/httputil.go`
- **Fix:** Remove or wire up.

### AUDIT-156 — `internal/api/handlers/handlers.go:127-...` validVendors map unused
- **File:** `internal/api/handlers/handlers.go`
- **Fix:** Remove or wire up.

### AUDIT-157 — `config.env.example:14` ADMIN_SECRET_KEY referenced nowhere
- **File:** `config.env.example:14`
- **Fix:** Remove from the example or implement.

### AUDIT-158 — Hardcoded `defaultPassword` in module scope
- **File:** `internal/config/config.go:399-420`
- **Issue:** Lingers in GC until next collection. After `cfg.Auth.AdminPassword = ""` zeroing in `cmd/api/main.go:124`, the underlying byte slice may be visible in core dumps.
- **Fix:** Build the random password directly into `cfg.Auth.AdminPassword` without a module-level intermediate. After hashing, scrub with `for i := range buf { buf[i] = 0 }`.

### AUDIT-159 — `cmd/probe/main.go:151-282` uses `fmt.Println` for banner lines
- **File:** `cmd/probe/main.go`
- **Issue:** Inconsistent with `log.Println` used elsewhere.
- **Fix:** Use `log.Println` with a `[probe]` prefix.

### AUDIT-160 — No vendored library version pinning
- **File:** `cmd/api/static/js/chart.umd.min.js`, etc.
- **Issue:** No entry in any `package.json` dependency list and no version pinning. Outside contributors cannot `npm install` to get the matching source.
- **Fix:** Add every library to `package.json`. Install with `npm`. Copy/transform via `esbuild`. Commit only the minified output with a hash comment + NOTICE entry.

### AUDIT-161 — HTML has 100+ duplicate sidebar markup instances
- **File:** 7 of 8 `web/admin/*.html` files
- **Issue:** Sidebar, header, `<script>` tag list duplicated.
- **Fix:** Move to Go `embed` + `template.ParseGlob` or use `htmx`. Or accept the duplication and document.

### AUDIT-162 — No README test instructions
- **File:** `README.md`
- **Issue:** README never says `go test ./...`.
- **Fix:** Add to "Build" section.

### AUDIT-163 — No CODEOWNERS
- **File:** repo root
- **Fix:** Add `.github/CODEOWNERS` with sensible defaults.

### AUDIT-164 — No FUNDING
- **File:** repo root
- **Fix:** Add `.github/FUNDING.yml` if accepting donations.

### AUDIT-165 — No GitHub release notes automation
- **File:** repo root
- **Fix:** Add `release-drafter` or `gh-release` workflow.

### AUDIT-166 — No community channel
- **File:** `README.md`
- **Issue:** Project ships an IRC bot feature but doesn't link its own support channel.
- **Fix:** Add a Matrix / Discord / IRC channel link. Or accept the limitation.

### AUDIT-167 — No "Known Issues" doc
- **File:** repo root
- **Fix:** Add `KNOWN-ISSUES.md` linked from README. Move deferred items from CHANGELOG footnotes here.

### AUDIT-168 — No browser support baseline documented
- **File:** `README.md`
- **Fix:** Document baseline (Safari 15.4+ / Chrome 105+ / Firefox 121+ given `:has()` and ES2020).

### AUDIT-169 — `cmd/api/static.go` is a 2-line wrapper around `//go:embed`
- **File:** `cmd/api/static.go`
- **Issue:** Should it be in `internal/` for layering?
- **Fix:** Acceptable as-is. Document the choice.

### AUDIT-170 — No example of a custom vendor profile
- **File:** `docs/`
- **Fix:** Walk through "Adding SonicWall" or another shallow vendor as a tutorial.

---

## Feature recommendations for v0.11.0 and beyond

These are not bugs. Sized S/M/L. Use these to plan the next release.

### Reports

- **AUDIT-F01** — **Ad-hoc date-range report** (S). Generalize `BuildReportModel` to `(start, end)`. New `GET /admin/api/reports/preview?start=…&end=…`.
- **AUDIT-F02** — **Comparison report** (M). Add `Previous: *ReportPeriod` to `ReportModel`. Render with delta badges.
- **AUDIT-F03** — **SLA report** (M). New `internal/report/sla.go`. Monthly availability bars per device. Per-SLA-target green/yellow/red.
- **AUDIT-F04** — **Capacity-planning report** (M). New `internal/report/capacity.go`. Linear regression on weekly throughput, project saturation, "Capacity Watchlist" section.
- **AUDIT-F05** — **MTTR/MTTA report** (S). `alerts.acknowledged_at - alerts.timestamp` and `alerts.resolved_at - alerts.timestamp`. Render as horizontal bars.
- **AUDIT-F06** — **Alert-noise report** (S). Group by `(alert_type, device_id)` over last 30d. "Top 10 noisiest rules."
- **AUDIT-F07** — **Security posture report** (M). Aggregate `SecurityStats` (IPS/AV/webfilter). "Top blocked categories", "Critical IPS hits" timeline.
- **AUDIT-F08** — **On-call handover report** (S). Reuse `BuildReportModel` with `hours=1` and a `Now` section.
- **AUDIT-F09** — **Device-comparison report** (M). Per-metric z-score against fleet baseline.
- **AUDIT-F10** — **Weekly-delta executive one-pager** (M). New `BuildExecutiveOnePager`. PDF download via `wkhtmltopdf` or browser print.
- **AUDIT-F11** — **Server-side PDF export** (L). Use `unidoc/unipdf` or `jung-kurt/gofpdf`.

### Alerting

- **AUDIT-F12** — **Alert grouping / correlation** (L). New `models.Incident` + `models.IncidentEvent`. Correlator runs each poll cycle.
- **AUDIT-F13** — **Flapping detection** (M). In `sendRecovery`, if alert was active <2 min and has fired >5 times in 1h, mark next as `Suppressed`.
- **AUDIT-F14** — **Alert hysteresis (clear-band)** (S). New `AlertRule.ClearThreshold`. `sendRecovery` uses `current < (Threshold - ClearHysteresis)`.
- **AUDIT-F15** — **Time-of-day aware thresholds** (M). New `AlertRule.TimeWindows []TimeWindow`.
- **AUDIT-F16** — **Per-interface thresholds** (M). New `InterfaceAlertRule` table.
- **AUDIT-F17** — **Baseline deviation (z-score)** (M). New `AlertRule.Mode = "static" | "zscore"` with `ZScoreThreshold`.
- **AUDIT-F18** — **Webhook signing (HMAC of payload)** (S). Add `X-FirewallMon-Signature: sha256=...`.
- **AUDIT-F19** — **Escalation policy rich model** (L). New `AlertPolicy.EscalationSteps [{after_minutes, channels, recipients}]`.

### Analytics & dashboards

- **AUDIT-F20** — **Traffic heatmap (hour-of-day × day-of-week)** (M). New `GetTrafficHeatmap(deviceID, ifIndex, days)` endpoint. 7×24 grid.
- **AUDIT-F21** — **Top talkers (src/dst IP)** (S). New `GET /admin/api/analytics/top-talkers?hours=24&limit=10&dir=src|dst`.
- **AUDIT-F22** — **Top destinations (DNS, apps, blocked sites)** (M). Pattern-match syslog messages. New `internal/analytics/syslog_aggregator.go`.
- **AUDIT-F23** — **Geo-IP breakdown** (M). `geoip2-golang` against MaxMind GeoLite2. New `GetTopCountries`.
- **AUDIT-F24** — **ASN breakdown** (M). Mirror of F23 with ASN dataset.
- **AUDIT-F25** — **Threat category breakdown** (S). Aggregate `SecurityStats`. New endpoint + UI.
- **AUDIT-F26** — **Capacity forecast widget** (M). Live on the dashboard, not just in the report.
- **AUDIT-F27** — **Conversation matrix (who talks to whom)** (M). New `internal/analytics/conversations.go`. Heatmap of `(src_addr/24, dst_addr/24)`.

### Visualization

- **AUDIT-F28** — **Network topology view** (M). Cytoscape is **already loaded** (`web/admin/admin.html:213-214`). New `/admin/topology` showing devices as nodes and `DeviceConnection` as edges. Pan/zoom, click → device-detail.
- **AUDIT-F29** — **Geographic world map of sites** (M). Add Leaflet or jvectormap. `Site.Latitude/Longitude` fields. `/admin/api/sites/geo` endpoint.
- **AUDIT-F30** — **Device dependency graph** (M). New `DeviceService` table. Cytoscape tab on device-detail.
- **AUDIT-F31** — **Real-time event stream (SSE/WS)** (M). `GET /admin/api/events/stream`. AlertManager broadcasts on save. Gin `c.Stream` with `c.Request.Context()`.
- **AUDIT-F32** — **Time-travel scrubber on charts** (L). Brush selection; underlying data loads on the fly.
- **AUDIT-F33** — **SLA calendar heatmap** (S). 365-cell grid, color = outage minutes that day.

### Device & vendor coverage

- **AUDIT-F34** — **FortiGate: SD-WAN SLA, web-filter categories, FortiSandbox, ZTNA, FortiClient EMS** (M).
- **AUDIT-F35** — **Cisco ASA: failover history, AnyConnect sessions, IPS** (M).
- **AUDIT-F36** — **Palo Alto: GlobalProtect, App-ID, threat logs, HA cluster** (M). Add `palo_api.go` for non-SNMP.
- **AUDIT-F37** — **SonicWall: full enterprise OIDs** (S).
- **AUDIT-F38** — **pfSense/OPNsense: BEGEMOT-PF-MIB, gateway latency, queue stats** (M).
- **AUDIT-F39** — **Firewalla: API-based collector** (M). New `firewalla_api.go`.
- **AUDIT-F40** — **Linux VPN (strongSwan/WireGuard) MIBs** (S).

### Operations

- **AUDIT-F41** — **Scheduled maintenance calendar view** (M). Reuse `MaintenanceWindow` + `RecurDays` fields.
- **AUDIT-F42** — **Device decommissioning (soft delete + archive)** (S). `Device.DecommissionedAt`. New endpoint.
- **AUDIT-F43** — **Device tags (freeform key/value)** (M). New `DeviceTag` model.
- **AUDIT-F44** — **Freeform notes per device** (S). `Device.Notes` or new `DeviceNote` table.
- **AUDIT-F45** — **Attachments (runbook, vendor contract PDF)** (M). New `Attachment` model. Files on disk under `data/attachments/<device_id>/<sha256>.<ext>`.
- **AUDIT-F46** — **Audit log (see AUDIT-078)**.
- **AUDIT-F47** — **Bulk actions on filtered set** (M). Snooze, tag-set, policy assign, enable/disable.
- **AUDIT-F48** — **Per-device change log** (M). Tied to AUDIT-078.
- **AUDIT-F49** — **Link to external wiki per device** (XS). `Device.WikiURL`.

### Self-monitoring

- **AUDIT-F50** — **`/admin/system` page** (M). New `web/admin/system.html` + `internal/api/handlers/handlers_system.go`. Goroutine count, DB pool stats, last-poll staleness, trap receive rate, alert volume, queue depth, build info.
- **AUDIT-F51** — **Dropped-trap counter** (XS). Increment atomic on each `OnNewTrap`. Expose via `/admin/api/system/snmp-stats`.
- **AUDIT-F52** — **SMTP/webhook health** (S). `last_email_failure` / `last_webhook_failure` timestamps. Surface via /admin/system.
- **AUDIT-F53** — **Disk usage of the server** (XS). `syscall.Statfs` on data dir.
- **AUDIT-F54** — **Days-of-data-retention indicator** (S). `MIN(timestamp)`, `MAX(timestamp)`, row count per table.
- **AUDIT-F55** — **Last-poll staleness per device** (S). `Device.LastPolled`. New alert type `POLL_STALE`.
- **AUDIT-F56** — **Self-alerting ("if our own alert email fails, alert the admin")** (S). Tied to F52.

### Public dashboard

- **AUDIT-F57** — **Public status page** (M). New `web/public/status.html`. "All systems operational" + per-component status + 90-day history.
- **AUDIT-F58** — **Incident banner** (S). Active critical alert on a public-visible device.
- **AUDIT-F59** — **"Subscribe to updates" email signup** (L). `models.Subscriber`. Double opt-in + unsubscribe link.
- **AUDIT-F60** — **JSON Feed (RFC 7468) for status** (S). `GET /api/public/status.json`.
- **AUDIT-F61** — **PII / internal IP scrubber for public JSON** (S). Audit all `GetPublic*` endpoints.

### API & extensibility

- **AUDIT-F62** — **Stable `/api/v1/...` versioning** (M). Real versioning, not the path-rewrite hack.
- **AUDIT-F63** — **OpenAPI spec** (L). `swaggo/swag` annotations. Serve at `/api/openapi.yaml`.
- **AUDIT-F64** — **API tokens (in addition to admin login)** (M). `models.ApiToken` with scope. `Authorization: Bearer <token>` middleware.
- **AUDIT-F65** — **Webhooks OUT per event** (L). New `OutboundWebhook` model. `internal/events/events.go` pubsub bus.
- **AUDIT-F66** — **Webhooks IN (generic)** (L). `POST /api/ingest/{type}` accepts any vendor's data, normalizes to a `RawIngest` table.
- **AUDIT-F67** — **OIDC/SSO login** (L). `github.com/coreos/go-oidc/v3`. Map IdP groups to admin roles.
- **AUDIT-F68** — **Multi-factor auth (TOTP)** (M). `pquerna/otp`. `Admin.MFAEnabled` / `Admin.MFASecret`.

### Onboarding

- **AUDIT-F69** — **Interactive setup wizard** (M). Detect first run. `/setup` flow.
- **AUDIT-F70** — **"Add your first device" with SNMP discover** (M). Scan a subnet.
- **AUDIT-F71** — **Sample data mode (demos)** (S). `--demo` flag. Banner: "DEMO — data is fake."
- **AUDIT-F72** — **In-admin tooltips linking to docs** (M). `?` icon next to every setting.
- **AUDIT-F73** — **Keyboard shortcuts + command palette (Cmd-K)** (M). Existing `data-action` is the perfect index.
- **AUDIT-F74** — **Dark/light mode toggle** (L). CSS variables + `[data-theme="light"]`.

### Compliance & audit

- **AUDIT-F75** — **Signed config backups (HMAC chain)** (M). `DeviceConfigRevision.Signature + PrevSignature`.
- **AUDIT-F76** — **Tamper-evident audit log** (M). Per-row HMAC chain.
- **AUDIT-F77** — **GDPR data export / purge** (M). `POST /admin/api/gdpr/purge?pattern=…` redacts syslog messages.
- **AUDIT-F78** — **SOC2 evidence collector** (M). `GET /admin/api/audit/evidence?start=&end=`.

### Performance & scale

- **AUDIT-F79** — **Downsampling of `interface_stats` and `system_status`** (L). Nightly 1-min → 1-hour → 1-day rollups.
- **AUDIT-F80** — **Materialized view for dashboard time-series** (M). Postgres `CREATE MATERIALIZED VIEW dashboard_hourly`. Refresh every 5 min.
- **AUDIT-F81** — **More indexes on hot queries** (S). `idx_iface_device_name_ts`, `idx_flow_src_addr`, `idx_flow_dst_addr`.
- **AUDIT-F82** — **Partition migration path** (L). One-shot `docs/partition-migration.md` step.
- **AUDIT-F83** — **Archive strategy (cold storage export)** (M). `cmd/archive/main.go` exporting to Parquet/CSV.
- **AUDIT-F84** — **SQLite tuning** (XS). `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`.
- **AUDIT-F85** — **Read replica support** (L). `Database.readDB` for report queries.

### Theming & branding

- **AUDIT-F86** — **Multi-tenant support** (XL). `Organization` model. Big refactor.
- **AUDIT-F87** — **White-label (per-tenant logo + brand color)** (M). `Organization.LogoURL` / `PrimaryColor` / `PublicName`.
- **AUDIT-F88** — **Custom domain per tenant** (L). `Organization.CustomDomain` + reverse-proxy hint header.
- **AUDIT-F89** — **Branded email templates (per-tenant)** (M). `Organization.EmailHeaderHTML` / `FooterHTML`.

---

## Top 10 features recommended for v0.11.0

By leverage × risk × fit with existing architecture:

1. **AUDIT-F28** — **Network topology view** (M). Cytoscape is already loaded. Add `/admin/topology` and the rest of the UI is wire-up. Massive visual upgrade.
2. **AUDIT-F50** — **`/admin/system` self-monitoring page** (M). Without this the operator can't tell if the monitor is healthy. Includes AUDIT-F51, F52, F53, F54, F55.
3. **AUDIT-F01** — **Ad-hoc date-range report** (S). The current 1×/day cron is great for routine but useless for incident investigation. Reuses the entire v0.10.236 template.
4. **AUDIT-F12 + F13 + F14** — **Alert grouping, flapping detection, hysteresis** (L). Fixes the "switch reboot = 8 emails" problem and the threshold-flapping problem. The alert pipeline already has the right hooks (`activeAlerts` map, `sendRecovery`).
5. **AUDIT-F78** — **SOC2 evidence collector** (M). Compliance-driven. Reuses AUDIT-078 audit log.
6. **AUDIT-F19** — **Escalation policy rich model** (L). The current `EscalationEnabled/EscalationMinutes/Repeat` is too thin. "First 5 min Slack, after 5 min PagerDuty + SMS."
7. **AUDIT-F20** — **Traffic heatmap (hour-of-day × day-of-week)** (M). Instantly shows weekly patterns. Easy to render, easy to read.
8. **AUDIT-F62 + F63** — **API versioning + OpenAPI spec** (M–L). For any external integration. Self-documenting.
9. **AUDIT-F41** — **Scheduled maintenance calendar view** (M). Existing `MaintenanceWindow` model + `RecurDays` field unused. Just needs a UI.
10. **AUDIT-F64** — **API tokens for read-only programmatic access** (M). "I want my Grafana to poll the alerts list." Scoped tokens.

---

## Resolved findings

(Populated as work is completed. Format: `AUDIT-NNN — short title — v0.11.X (commit SHA)`)

| ID | Title | Version | Commit | Notes |
|----|-------|---------|--------|-------|
| AUDIT-001 | Untrack `*_test.go` from `.gitignore` | 0.10.241 | 671dbd8 | Removed line 9 of `.gitignore`; added `internal/configdiff/normalize_test.go` (631 LOC) and `internal/report/report_test.go` (192 LOC) so the regression net cited in v0.10.236/0.10.238/0.10.239 actually ships with public clones. |
| AUDIT-074 | `internal/irc/bot.go` CRLF line endings | 0.10.242 | 842fcf6 | Normalized via `gofmt -w .`. Was flagged as "CR-only" in the audit — actually CRLF, now LF like the rest of the tree. |
| AUDIT-075 | 16 files fail `gofmt -l` | 0.10.242 | 842fcf6 | Whole-tree `gofmt -w .` pass; whitespace-only diff (`git diff -w` is empty). After: `gofmt -l .` returns nothing. CI enforcement (AUDIT-152) follows once the CI workflow exists. |
| AUDIT-002 | No `LICENSE` file (README claims MIT) | 0.10.243 | 0f5ac25 | Added standard MIT text with `Copyright (c) 2026 Firewall-Mon Contributors`. README continues to claim MIT. |
| AUDIT-010 | `PROBE_SERVER_URL` default hardcodes author's domain | 0.10.243 | 0f5ac25 | `internal/config/config.go:247` default changed from `https://stats.technicallabs.org` to `""`. Probe binary already required the env var (`cmd/probe/main.go:67`); server-side `cfg.Probe.ServerURL` is not consumed. Defensive removal of a public-release smell. |
| AUDIT-023 | `ReadHeaderTimeout` not set on HTTP server | 0.10.243 | 0f5ac25 | Added `ReadHeaderTimeout: 10 * time.Second` to the `http.Server` in `cmd/api/main.go:216`. Closes the slow-loris partial-header window left by the unset field (only `ReadTimeout=30s` was set). |
| AUDIT-025 | `Permissions-Policy` header missing | 0.10.243 | 0f5ac25 | `SecureHeaders` middleware now sends `Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=(), sync-xhr=()`. The admin panel uses none of these APIs. |
| AUDIT-122 | Dead `_unused_legacy_top50_test` orphan | 0.10.243 | 0f5ac25 | Deleted the 60-line dead test function (originally retained with a leading underscore when the legacy retention policy was removed). |
| AUDIT-014 | SMTP critical-alert subject built from `device.Name` without CRLF sanitisation | 0.10.244 | 813a452 | New `notifier.SanitizeHeader` exported helper; `report/email.go:94` now sanitises `alert.AlertType`, `device.Name`, `device.IPAddress` before `fmt.Sprintf`. Defense-in-depth — `notifier.SendHTMLEmail` already sanitised the final header value, this closes the construction-site gap. Tests: `notifier/notifier_test.go` (11-case table + fuzz) and `report/email_test.go` (CRLF-laden device name produces sanitized subject). |
| AUDIT-027 | `decryptField` returns ciphertext on decrypt failure (v0.10.226 bug class) | 0.10.245 | (pending) | Every failure path inside `decryptField` after the `{enc}` prefix check now returns `""` and logs at ERROR (no key, bad base64, AES init, GCM init, short ciphertext, GCM auth failure). Legacy plaintext (no prefix) still passes through unchanged. 9 regression tests in `internal/database/crypto_test.go` cover round-trip, legacy passthrough, no-key, wrong-key, bad-base64, tamper, short ciphertext, double-encrypt idempotency, encrypt-empty passthrough. `internal/database` now has its first test file. |

---

## Progress log

Append a one-line entry per resolved finding in chronological order.

```
# Format: YYYY-MM-DD — AUDIT-NNN — short title — version — commit SHA — author
2026-06-02 — AUDIT-001 — untrack *_test.go — v0.10.241 — 671dbd8 — opencode
2026-06-02 — AUDIT-074 — fix CRLF line endings in irc/bot.go — v0.10.242 — 842fcf6 — opencode
2026-06-02 — AUDIT-075 — project-wide gofmt -w sweep — v0.10.242 — 842fcf6 — opencode
2026-06-02 — AUDIT-002 — add MIT LICENSE — v0.10.243 — 0f5ac25 — opencode
2026-06-02 — AUDIT-010 — PROBE_SERVER_URL default empty — v0.10.243 — 0f5ac25 — opencode
2026-06-02 — AUDIT-023 — ReadHeaderTimeout=10s — v0.10.243 — 0f5ac25 — opencode
2026-06-02 — AUDIT-025 — Permissions-Policy header — v0.10.243 — 0f5ac25 — opencode
2026-06-02 — AUDIT-122 — delete dead _unused_legacy_top50_test — v0.10.243 — 0f5ac25 — opencode
2026-06-02 — AUDIT-014 — SMTP subject CRLF sanitization at build site — v0.10.244 — 813a452 — opencode
2026-06-02 — AUDIT-027 — decryptField fail-closed (returns empty on any decrypt error) — v0.10.245 — (pending) — opencode
```

---

## Notes for the next agent

- The two repos are separate: this is **Firewall-Mon** (the server). The **Firewall-Collector** is at `E:\Golang\OpenCode\Firewall-Collector`. Don't cross-post CHANGELOG entries. See `lessons.md:1-35` for the prior incident.
- The `tasks/lessons.md` file (in the working tree but gitignored) is operator session memory. It is *not* a public doc.
- The `lessons.md` at the repo root is AI session memory. It is *not* a public doc. Either move to `.claude/` (gitignored) or document the convention.
- After AUDIT-001 lands, the test files `internal/configdiff/normalize_test.go` and `internal/report/report_test.go` will be visible in `git ls-files`. Existing CHANGELOG entries (v0.10.236, 0.10.238, 0.10.239) that reference them as the regression net are now accurate.
- The `CHANGELOG.md` must be updated for *every* commit that resolves an AUDIT-NNN. Add the entry at the very top, above all other version entries, with a brief description and the AUDIT-NNN reference. The "Server-repo only" discipline applies here.
- **QA is mandatory before every push.** `go build ./...`, `go test -race -count=1 ./...`, `gofmt -l . | (! grep .)`, `go vet ./...`. Show results in the commit message or PR description.
- The `package.json` version (currently 0.10.157) and the `Dockerfile` `org.opencontainers.image.version` label should come from a single source of truth (cmd/api/main.go:34). Fix as part of AUDIT-004.
