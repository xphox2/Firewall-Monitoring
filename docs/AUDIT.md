# Firewall-Mon — Audit & Resolution Tracker

> **Single source of truth** for the public-release hardening effort. This file
> merges the original 170-finding audit, the live resolution status, and the
> per-session working notes (it absorbed the former `docs/HANDOFF.md`).

## 📊 Status at a glance — updated 2026-06-06

| Metric | Value |
|---|---|
| Server version | **v0.10.368** |
| Bug findings resolved | **141 / 170  (83%)** |
| CRITICAL still open | **0** ✅ |
| Open bug findings | **29** |
| Feature ideas (F01–F89) | out of scope — future v0.11.0+ |

**Where the effort stands:**
- ✅ All 11 CRITICAL deployment blockers — resolved (v0.10.241–292)
- ✅ Security, DB-performance, and frontend/accessibility quick wins — resolved
- ✅ Build/repo hygiene + operator documentation — resolved (Sessions 18–19)
- ✅ Mid-size code/config cleanups (`errors.Is`, autovacuum coverage, security.txt, apiFetch retry, …) — resolved (Session 20)
- ✅ Operator docs — runbook + architecture diagrams + vendor guide (Session 21)
- ✅ Request-ID log correlation + JS-standard decision (Session 22)
- ✅ Parser fuzz + benchmark tests, line-ending hygiene (Session 23)
- ✅ Code-quality cleanups: ES5 `['catch']` sweep, `database.go` error wrapping, release-notes automation (Session 24)
- ✅ Handler 500s now log their cause via `httputil.InternalError` (133-site sweep) (Session 25)
- ⏳ Remaining 29: large refactors, observability, the rest of test infrastructure, a few docs

## 🧭 How to read this file

1. **Status at a glance** (above) — where we are right now.
2. **What's left** (next section) — the open work, grouped by theme.
3. **Recent activity** — the last few work sessions in plain language.
4. **Resolved findings** table + **Progress log** — the complete audit trail: every fix with its version and commit SHA.
5. **Part II — the original audit** — all 170 findings + 89 feature ideas in full detail. `file:line` references are against the **v0.10.239** baseline and may have since moved.
6. **Part III — maintainer & session notes** — the per-commit workflow and session-by-session completion logs (formerly `HANDOFF.md`).

## ⏳ What's left (the 29 open findings)

These are no longer quick wins — they cluster into five themes. Search the
`AUDIT-NNN` ID in **Part II** for the full issue + suggested fix of any item.

- **Large refactors** — `AUDIT-072` (split the 4,200-LOC `database.go`), `AUDIT-032` (request-context propagation, ~188 call sites), `AUDIT-044` (adopt `golang-migrate`/`goose`), `AUDIT-028` (partition `interface_stats`/`system_status`), `AUDIT-040` (two-instance shared state).
- **Observability** — `AUDIT-076` (structured logging / `slog`), `AUDIT-077` (Prometheus `/metrics`), `AUDIT-078` (admin-action audit log), `AUDIT-150` (OpenTelemetry tracing).
- **Test infrastructure** — `AUDIT-117` (per-package coverage), `AUDIT-118` (Postgres CI matrix), `AUDIT-120` (property-based), `AUDIT-122` (handler coverage), `AUDIT-123` (integration), `AUDIT-140`/`142` (`t.Parallel`/`Short`). *(119 fuzz + 124 bench now done.)*
- **Docs & repo hygiene** — `AUDIT-106` (README endpoint sweep), `AUDIT-114` (fresh-Ubuntu build steps), `AUDIT-164`/`166` (FUNDING / community channel). *(165 release automation now done.)*
- **Smaller code cleanups** — `073` (gorm/DTO split), `079` (ctx, see 032), `094` (entrypoint supervision), `129` (Sentry). *(071 JSONError helper + 081 `return err` wrapping + 132 ES5 `['catch']` sweep now done.)*

## 🗓 Recent activity

| Session / range | Theme | Highlights |
|---|---|---|
| **Session 25** (v0.10.368) | Handler error observability | added `httputil.InternalError(c, msg, err)` (logs cause + method/route/`X-Request-ID`, writes clean 500 JSON) and swept all 133 `c.JSON(500, ErrorResponse(…))` sites across 13 handler files (071); 4 of them had been leaking `err.Error()` to the client — now logged, not leaked |
| **Session 24** (v0.10.365–367) | Code-quality cleanups + release automation | swept the ES5 `['catch']`/`['finally']` bracket workaround to dot notation across 121 sites/14 JS files (132); wrapped 25 raw `return err` in `database.go` with `%w` so callers keep operation context + `errors.Is` (081); tag-triggered CHANGELOG-driven `release.yml` GitHub-Release automation (165) |
| **Session 23** (v0.10.363–364) | Test infra + repo hygiene | Go fuzz tests for the syslog + sFlow parsers — 3.5M+ execs, zero crashes (119); parser hot-path benchmarks (124); `.gitattributes` to stop CRLF/LF diff churn |
| **Session 22** (v0.10.361–362) | Observability + JS standard | `RequestID` middleware (X-Request-ID log correlation, log-forge guard) (135); declared ES2020 the frontend JS standard (131) |
| **Session 21** (v0.10.358–360) | Operator documentation | confirmed the vendor guide covers both sides (113), `docs/OPERATIONS.md` runbook (111), `docs/architecture.md` Mermaid component + sequence diagrams (108) |
| **Session 20** (v0.10.352–357) | Mid-size code/config cleanups | `errors.Is` for gorm sentinels, autovacuum covers `interface_stats`/`system_status` + `DB_AUTOVACUUM_TABLES`, RFC 9116 `security.txt`, `apiFetch` 5xx retry, dropped stale `package.json` version, prune goroutine graceful shutdown |
| **Session 19** (v0.10.343–351) | Build hygiene + operator docs | drop unused Docker C-toolchain, reproducible builds, `make install`/`tarball` (+ fixed a binary-naming bug), `CODEOWNERS`, README test/feature/env/browser docs, custom-vendor tutorial |
| **Session 18** (v0.10.336–342) | Deploy safety + probe robustness | `.dockerignore`, deploy.sh config-guard + backup + `--dry-run`, hardened nginx companion, jittered backoffs, probe poll context + bounded drain |
| **Prod hotfixes** (v0.10.320–324) | Firefighting | color-sweep revert + 3 prod bugs (42P10 index, probe-offline alerting, redacted-secret write-back) |
| **Sessions 13–17** (v0.10.293–333) | Frontend/a11y, security, DB perf | see the Progress log + Part III session logs |

Full chronological history: the **Progress log** and the **Part III** session logs below.

---

# Part II — The original audit (v0.10.239 baseline)

> The sections below are the original multi-agent audit as written at
> **v0.10.239** on 2026-06-02. They are kept as the canonical per-finding
> reference (`SECURITY.md` and `KNOWN-ISSUES.md` link to `AUDIT-NNN` rows here).
> **For current status, use the dashboard at the top** — many findings below are
> now resolved (see the **Resolved findings** table). `file:line` references are
> against the v0.10.239 tree and may have moved.

**Audit metadata:** version audited 0.10.239 (`cmd/api/main.go:34`); audited 2026-06-02 by a multi-agent sweep (security, stability, code quality, frontend, features, database/architecture, testing/CI, docs/operations); source `master` (521 commits, 0 tags at audit time).

### How to use the per-finding sections

Each finding has a stable `AUDIT-NNN` ID for commit-message tracking. Severity: **CRITICAL** (deployment blocker) · **HIGH** (will cause real incidents) · **MEDIUM** (real but bounded) · **LOW** (polish) · **INFO** (note only). When a refactor moves cited code, fix the audit entry in the same PR.

### Executive summary — *historical (the v0.10.239 assessment)*

> **⚠ Historical snapshot.** The dashboard at the top of this file reflects current reality — every CRITICAL blocker listed here is now resolved.

At v0.10.239 the codebase was well-defended in many dimensions (parameterised SQL, AES-256-GCM at rest, HMAC CSRF, the vendor-profile abstraction) but was **not yet ready for public release** because of **10 CRITICAL deployment blockers** (test files gitignored, no LICENSE, no CI, in-memory JWT secret breaking encryption on restart, batcher data loss on crash, trap-receiver dropping every trap, no leader lock, no key rotation, no SECURITY policy, hardcoded third-party domain default), **~25 HIGH-priority gaps**, and **~40 MEDIUM/LOW polish items**. That assessment drove the resolution effort tracked in this file; the CRITICAL set and most HIGH items are now closed.

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

This table is the audit trail — one row per resolved finding, with the release
version and commit SHA. **It is the canonical resolved-count.** To count it
(scoped, since Part III's session-log tables also use `| AUDIT-` rows):

```sh
awk '/^## Resolved findings/{f=1} /^## Progress log/{f=0} f && /^\| AUDIT-/{c++} END{print c}' docs/AUDIT.md
```

Per-commit workflow (see Part III for the full conventions): append a row here
**and** a line to the Progress log, both with the version and commit SHA
(`(pending)` until the code commit lands, then backfilled).

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
| AUDIT-027 | `decryptField` returns ciphertext on decrypt failure (v0.10.226 bug class) | 0.10.245 | 41cd6ae | Every failure path inside `decryptField` after the `{enc}` prefix check now returns `""` and logs at ERROR (no key, bad base64, AES init, GCM init, short ciphertext, GCM auth failure). Legacy plaintext (no prefix) still passes through unchanged. 9 regression tests in `internal/database/crypto_test.go` cover round-trip, legacy passthrough, no-key, wrong-key, bad-base64, tamper, short ciphertext, double-encrypt idempotency, encrypt-empty passthrough. `internal/database` now has its first test file. |
| AUDIT-016 | Probe registration key compared with `!=` not `hmac.Equal` | 0.10.246 | 90afae6 | `validateProbe` (`handlers_probes.go:606`) now uses `subtle.ConstantTimeCompare` for the post-PK-lookup token check. `authenticateProbeByBearer`'s SQL `WHERE registration_key = ?` lookup is a separate timing channel that needs the AUDIT-017 hashed-token refactor; this fix covers the high-leverage path used by 18 ingestion handlers. 9-case regression test in `handlers_probes_audit016_test.go`. |
| AUDIT-015 | CORS `*` allowed with `Allow-Credentials: true` | 0.10.247 | 210d4a8 | New `parseCORSAllowedOrigins` helper rejects `*` (anywhere in the list, after trim) with a clear error. `CORS()` calls `log.Fatalf` so the server refuses to start with an unsafe config. 14-case test suite in `internal/api/middleware/cors_test.go` (5 wildcard-rejection scenarios + 9 happy-path edge cases). First test file for the middleware package. |
| AUDIT-086 | `cmd/api/main.go` listen goroutine uses `log.Fatal` | 0.10.248 | b8357db | Listener goroutine now surfaces errors on a buffered `errCh`. Main goroutine `select`s on either the signal channel or `errCh`, then runs the graceful-shutdown sequence so the deferred `ircManager.Stop` / `snmpClient.Close` / `cancel` run before exit. `server.Shutdown` failure also no longer `log.Fatal`s. No automated test — would need integration-level harness. |
| AUDIT-013 | `TestIRCServer` SSRF — odd one out among Test* endpoints | 0.10.249 | c23ed1b | `handlers_irc.go:TestIRCServer` now runs the server host through `isValidExternalIP` (same helper used by `TestProbeConnection` and `TestEmail`) and validates the port range. 16-case regression test in `handlers_irc_audit013_test.go` covers IPv4/IPv6 loopback, unspecified, link-local (incl. AWS metadata), RFC 1918, RFC 4193, `localhost` name, unresolvable hosts, and bad ports. First test file for the IRC handlers. |
| AUDIT-012 | Trap receiver binds 0.0.0.0:162 with empty community string | 0.10.250 | 0a5a383 | (1) `TrapReceiver.Start` now fails closed if `SNMP_TRAP_COMMUNITY` is empty, (2) constant-time `subtle.ConstantTimeCompare` community check, (3) per-source-IP token-bucket rate limit (10/s sustained, burst 50, map capped at 10k IPs) applied BEFORE community check. 5 regression tests in `internal/snmp/trap_test.go` cover empty-community refusal, burst-then-refill, per-IP isolation, map cap, and concurrency-safe accounting. First test file for the SNMP package. |
| AUDIT-083 | Rate limiter cleanup goroutine leaks, no map cap | 0.10.251 | 35a829b | `ipRateLimiter` map capped at 50,000 entries with `container/list`-backed LRU eviction (amortized O(1)). New `Stop()` method closes a `quit` channel that the cleanup goroutine selects on. Wired-through Stop on the public `RateLimiter/PublicRateLimiter/LoginRateLimiter` handlers is a follow-up (would change the public API). 7 regression tests in `ratelimit_test.go`. |
| AUDIT-008 | Auto-generated JWT secret is in-memory only and breaks AES decrypt | 0.10.252 | 03d2e6e | New `internal/secrets` package (10 tests). `cmd/api/main.go` now persists auto-generated JWT secret to `$SECRETS_DIR/.jwt-secret` (default `/data`) chmod 0600 on first run; subsequent runs reload. Same treatment for admin password. Any I/O failure is `log.Fatal`. Collaterally closes AUDIT-137 (masked password no longer logged). |
| AUDIT-137 | Logs masked admin password | 0.10.252 | 03d2e6e | Removed alongside AUDIT-008 — the rewritten flow logs the file path instead of any password characters. |
| AUDIT-005 | Trap-receiver drops every trap silently | 0.10.253 | c0ae1f4 | `cmd/trap-receiver/main.go` now constructs a real `*database.Database` and passes it to `AlertManager`. Also wired AUDIT-008 secrets-loading to `cmd/trap-receiver` AND `cmd/poller` so all three processes derive the same AES key from `/data/.jwt-secret`. `secrets.LoadOrGenerate` updated to use `O_CREATE\|O_EXCL` for safe concurrent first-start. New race-safe test verifies 16 concurrent callers converge on identical secret. |
| AUDIT-003 | `THIRD-PARTY-NOTICES.md` missing | 0.10.254 | 4743ca7 | Top-level `THIRD-PARTY-NOTICES.md` inventories 10 vendored browser assets + 10 direct Go deps with version / license / copyright / source URL, plus full license texts for MIT / BSD-2 / BSD-3 / Apache-2.0 / OFL-1.1. README links to it. |
| AUDIT-011 | No SECURITY.md / no runbook / no CONTRIBUTING.md | 0.10.254 | 4743ca7 | Added `SECURITY.md` (private disclosure policy, response-SLOs, scope), `CONTRIBUTING.md` (dev env, QA gate, PR workflow), `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1). README now links all four governance docs + the audit doc. Deferred: `.well-known/security.txt` route (AUDIT-112), GitHub issue templates (AUDIT-163), `docs/OPERATIONS.md` runbook (AUDIT-111). |
| AUDIT-004 | No git tags, no CI, no release flow | 0.10.255 | 6be86a0 | Partial: `.github/workflows/ci.yml` (build-test job + vuln-scan job — closes AUDIT-018, AUDIT-075/AUDIT-152, AUDIT-121 gates in CI), `Makefile` with `qa`/`test`/`test-race`/`build`/`vet`/`fmt`/`tidy`/`vuln`/`docker` targets. Deferred (separate commits): release.yml, goreleaser, golangci.yml linter (would surface waivers needing triage), backfill git tags, build-flags (`-trimpath -buildvcs=false`). |
| AUDIT-007 | No leader lock for the poller | 0.10.256 | f32396e | New `Database.TryAcquirePollerWorkLock` / `ReleasePollerWorkLock` (Postgres advisory lock keyed `0x504f4c4c45525357`). New `Poller.runUnderLeaderLock(name, fn)` wrapper in `cmd/poller` — all 3 cron ticks (pollAllDevices, rollup, cleanup) now skip cleanly when another poller is active. 2 SQLite no-op tests in `poller_lock_test.go`. Cross-process Postgres semantics covered by doc contract until AUDIT-118 lands. |
| AUDIT-006 (partial) | Batcher is not crash-durable and has a shutdown race | 0.10.257 | 9dcb153 | Shutdown-race half: `stopped atomic.Bool` set BEFORE `close(stopCh)`; Add checks fast-path + under-lock; final Flush moved into goroutine BEFORE `close(doneCh)`. New `Dropped() int64` counter. Stop now idempotent via CompareAndSwap. 8 regression tests in new `batcher_test.go` (incl. concurrent Add+Stop conservation invariant). Crash-durability half (WAL+fsync+spill-to-disk) deferred — needs disk format design. |
| AUDIT-009 | Crypto key rotation is impossible | 0.10.258 | d41b2c3 | New `keyChain{current, legacy}` type. `Database.encKey` → `Database.encKeys` (chain). Decrypt tries current then each legacy key in order. Wire format unchanged (backward compat — same `{enc}<base64>`). New `ENCRYPTION_KEY_HISTORY` env var. 9 regression tests in `crypto_keychain_test.go`. `cmd/keyrotate` re-encryption migration tool deferred — operators can re-save through the admin UI today, or wait for the tool. |
| AUDIT-022 | CSP allows `'unsafe-inline'` for script and style | 0.10.259 | 21df1b4 | Per-request 128-bit nonce in `middleware.SecureHeaders()` (crypto/rand → base64). `'unsafe-inline'` removed from `script-src` and `style-src`; both directives now carry `'nonce-<x>'`. New `middleware.RenderHTML(c, code, name, data)` wrapper that surfaces `{{ .Nonce }}` to templates. All 22 `c.HTML(...)` calls in `cmd/api/main.go` rewritten to use it. 16 inline blocks across 8 HTML files stamped with `nonce="{{ .Nonce }}"`. 9 unit tests in `csp_nonce_test.go` (header shape, freshness, other-headers-preserved, RenderHTML happy paths, nonce format, concurrency) + 1 integration test with 9 subtests in `csp_nonce_html_test.go` that renders every HTML file through a real gin engine and asserts the inline tag nonces exactly match the CSP header nonce. Deferred: `'strict-dynamic'` (would simplify bundle ordering), CSP violation reporting endpoint (AUDIT-110), SHA-256 hash allowlist for static blocks. |
| AUDIT-019 | IRC bot's `isAdmin` is "is this the bot's own nick?" | 0.10.260 | bb4174d | New `IRCChannel.AdminNicks` field (semicolon-separated nicks, case-insensitive, empty = no admins = fail-closed). `Bot.isAdmin(target, nick)` now consults the target channel's allow-list; the bot's own nick is no longer auto-admin (the old code path was dead — the bot never PRIVMSGs itself, so "admin only" used to mean "nobody"). Private messages to the bot are denied for admin commands. 30 regression cases in `internal/irc/bot_audit019_test.go` (16 for `channelNickAllowed`, 14 for `Bot.isAdmin` end-to-end). Deferred: per-nick permission levels (read vs write vs destructive), separate `models.IRCAdmin` join table. |
| AUDIT-021 | `NoNewPrivileges` and friends not set in systemd units | 0.10.261 | 5d8c0dd | `deploy.sh` now creates a dedicated `fwmon` system user (idempotent, `--system --no-create-home --shell /usr/sbin/nologin --home-dir /var/lib/firewall-mon`). All three generated units (`fwmon-{api,poller,trap}.service`) now run as `User=fwmon Group=fwmon` with a full hardening block: `NoNewPrivileges`, `ProtectSystem=strict` + `ReadWritePaths=/var/lib/firewall-mon`, `PrivateTmp`, `ProtectHome`, `ProtectKernel{Tunables,Modules,ControlGroups}`, `RestrictAddressFamilies={AF_UNIX,AF_INET,AF_INET6}`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service ~@privileged @resources`, `CapabilityBoundingSet=` empty, `AmbientCapabilities=` empty. Post-install `chown -R fwmon:fwmon` on install/data/config dirs, `chmod 0640` on config files. `bash -n deploy.sh` passes. Deferred: socket activation, DynamicUser=yes, systemd `LoadCredential=` for JWT secret, post-deploy `systemd-analyze syscall-filter` for any needed syscalls not in `@system-service`. |
| AUDIT-024 | `HSTS` only sent over TLS, but `COOKIE_SECURE=true` is the example default with `SERVER_ENABLE_TLS=false` | 0.10.262 | 1278601 | `config.env.example` now ships `COOKIE_SECURE` commented-out (with a docblock explaining the inheritance from `SERVER_ENABLE_TLS`). New `Server.CookieSecureExplicit` field on the config struct, populated by `os.Getenv("COOKIE_SECURE") != ""`. `Validate()` logs a multi-line actionable warning when `CookieSecure && !EnableTLS && CookieSecureExplicit` (the silent-login-break path). Warning is intentionally not fatal — TLS-terminating reverse proxy is a legitimate reason for plain HTTP on the app. 4 regression cases in `internal/config/config_audit024_test.go` (broken config warns, inherited config silent, explicit-false config silent, static check on `config.env.example` rejects the `COOKIE_SECURE=true + SERVER_ENABLE_TLS=false` combination). First test file for `internal/config`. Deferred: silent auto-correction of the mismatch (rejected — would mutate a config the operator may have set deliberately). |
| AUDIT-026 | `IsSecret` not the gate for `EncryptField` | 0.10.263 | 98022df | `UpdateSettings` (`handlers_settings.go:222`) now gates `db.EncryptField(s.Value)` on `secretKeys[s.Key]` (the same source-of-truth map that drives the `IsSecret = true` line). The pre-fix behavior encrypted every system_settings row on save, including non-secret thresholds / display prefs / boolean toggles. Other call sites of `db.EncryptField` (`handlers_devices.go`, `handlers_irc.go`) are already correctly gated by explicit field lists — no changes needed. 2 regression tests in `handlers_settings_audit026_test.go` pin the `settingsSecretKeys` map: `smtp_password` is in it, 25 known non-secrets are explicitly NOT in it, and a no-overlap check guards against accidental reclassification. Deferred: compile-time reflection check on `Device`/`Probe` field names containing `Pass|Secret|Key|Community`; historical `{enc}` rows for non-secret keys (a backfill migration is dangerous — see CHANGELOG for why). |
| AUDIT-091 | No `HEALTHCHECK` in Dockerfile | 0.10.264 | 3950cb0 | New `HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD wget -qO- http://localhost:8080/api/health` in the Dockerfile. The endpoint it hits is now meaningful (collocated with AUDIT-045): `GetHealth` pings the DB with a 1-second `context.WithTimeout` and returns 503 with `{"status":"unhealthy","db_error":"..."}` on any failure. SNMP client liveness is NOT probed (a target device being down is not a reason to restart the API container). 3 regression cases in `handlers_health_audit091_test.go`: healthy-DB → 200, nil-DB → 503, force-closed-DB → 503 with the SQL error in the body. Deferred: readiness vs liveness probe split (K8s convention), probing IRC bot / batcher / alert-queue depth, embedding `/api/version` in the health response. |
| AUDIT-093 | Hardcoded Postgres password `fwmon` | 0.10.265 | 37067e0 | `entrypoint.sh` now auto-generates a 32-character random alphanumeric password on first init (`/dev/urandom` → base64 → alnum filter), persists to `/config/pg-credentials` (chmod 0600, chown fwmon:fwmon), and sources it on every boot. `CREATE USER` and `ALTER USER` use the random value (the `ALTER` is idempotent and serves as the migration path for upgrades from a pre-AUDIT-093 image). `export DB_PASSWORD="$PG_PASSWORD"` instead of the literal `fwmon`. Static regression test in the new `internal/shell` package asserts the entrypoint contains none of `PASSWORD 'fwmon'`, `PASSWORD "fwmon"`, `DB_PASSWORD=fwmon`, or `DB_PASSWORD="fwmon"` in executable form (bash comments are stripped first so a CHANGELOG-style explanation doesn't false-positive). Deferred: TCP listening + SCRAM auth, scheduled password rotation, two-credential model for ad-hoc psql. |
| AUDIT-096 | `docker-compose.yml` no healthcheck | 0.10.266 | a976e9f | New explicit `healthcheck:` block on the `firewall-mon` service in `docker-compose.yml`, mirroring the Dockerfile's `HEALTHCHECK` (v0.10.264) — same interval (30s), timeout (3s), retries (3), start_period (20s), and `/api/health` probe path. The pre-fix compose file showed only "Up" in `docker compose ps` with no health qualifier, and `depends_on: condition: service_healthy` was unavailable to dependent services. Static regression test in the `internal/shell` package asserts the compose file contains a `healthcheck:` block and that the block probes `/api/health`. Deferred: parity enforcement between Dockerfile `HEALTHCHECK` and compose `healthcheck` (would need a real YAML parser), `docker-compose.proxy.yml` audit, readiness vs liveness split. |
| AUDIT-105 | Default `ADMIN_USERNAME=admin` | 0.10.267 | f13a322 | New `Auth.AdminUsernameExplicit bool` field (populated by `os.Getenv("ADMIN_USERNAME") != ""`). `Validate()` logs a multi-line actionable warning when `!AdminUsernameExplicit && strings.EqualFold(AdminUsername, "admin")` — the OWASP #1 brute-force target. Warning is intentionally not fatal (SSO portal / VPN in front is a legitimate reason to keep the default). Case-insensitive match: `Admin`, `ADMIN`, `aDmIn` all trigger. 4 regression tests with 6 subtests in `config_audit105_test.go`: default-warns, explicit-does-not-warn, non-default-silent, case-insensitive variants. Deferred: disallow "admin" entirely, top-N common-username list, README pre-install checklist. |
| AUDIT-148 | `cidrToLikePattern` doesn't escape `%` and `_` | 0.10.268 | f83ea8b | The four `LIKE ?` clauses in `GetConnectionFlowStats` (`database.go:3819-3820`) now carry `ESCAPE '\'` so `\%` and `\_` are treated as literal `%` and `_` rather than wildcards. The patterns themselves are safe by construction (input is `net.ParseIP`/`net.ParseCIDR` validated; only an intentional trailing `%` is emitted) — the `ESCAPE` is the defense-in-depth layer the audit asked for. 20 regression cases in `cidr_audit148_test.go`: 14 pinning the helper's output for every accepted input shape (empty/whitespace/default-route/invalid/`/32`/`/24`/`/16`/`/8`/too-broad/IP-range/single-IP/IPv6), and 6 enforcing the "no literal `_`, at most one `%`, only in trailing position" contract. Deferred: escape the input explicitly inside cidrToLikePattern (rejected — would suggest the IP validation isn't trustworthy), refactor `GetConnectionFlowStats`'s 100-line hand-built query. |
| AUDIT-157 | `config.env.example:14` ADMIN_SECRET_KEY referenced nowhere | 0.10.269 | f708489 | `ServerConfig.AdminSecretKey` field removed, the `getEnv("ADMIN_SECRET_KEY", "")` line in `Load()` removed, the `ADMIN_SECRET_KEY=` line in `config.env.example` removed. No code path ever read the field; it was a leftover from the pre-AUDIT-008 "admin secret" concept. Two-axis regression test (`TestNoDeadAdminSecretKey_AUDIT157`): static check on `config.go` rejects any re-introduction of `"ADMIN_SECRET_KEY"` or `"AdminSecretKey"` strings; runtime check sets a unique sentinel via the env var and asserts it doesn't surface in the rendered `Server` block. Deferred: re-introduce as a real knob if a future feature needs it (e.g. SSO callback HMAC), audit other dead-config candidates (AUDIT-154/155/156). |
| AUDIT-101 | Dockerfile OCI labels hardcoded | 0.10.270 | dd76868 | New `ARG VERSION=dev`, `ARG REVISION=unknown`, `ARG CREATED="1970-01-01T00:00:00Z"` build-args in the Dockerfile, with the `LABEL` block sourcing `.version`, `.revision`, `.created` from them. Additional OCI annotations added: `.description`, `.source`, `.url`, `.licenses=MIT`, `.vendor`, `maintainer`. Bare `docker build .` still works (defaults to "dev"); CI passes `--build-arg VERSION=$GITHUB_REF_NAME` etc. Three-axis regression test (`TestDockerfile_OCILabelsUseBuildArgs_AUDIT101`): ARG declarations present, LABEL block references build-args, no hardcoded `org.opencontainers.image.version="..."` literal survives. Deferred: CI workflow that actually passes the build-args (AUDIT-004 deferred halves), `-trimpath -buildvcs=false` build flags (AUDIT-102), per-architecture image variants. |
| AUDIT-159 | `cmd/probe/main.go:151-282` uses `fmt.Println` for banner lines | 0.10.271 | c81cc41 | Every `fmt.Println` and `fmt.Printf` in the probe binary's banner / status output (lines 151-289 and 442-448) is now `log.Println` / `log.Printf`. The pre-fix output went to stdout with no timestamp, inconsistent with the rest of the codebase's logs. `fmt.Errorf` is left alone — wrapping errors with `%w` is a different concern. Two regression tests in `probe_audit159_test.go`: `TestProbe_NoFmtPrintln_AUDIT159` regex-scans for any `fmt.Print` call; `TestProbe_HasLogImport_AUDIT159` defensive sibling confirms the `"log"` import survives. Deferred: structured logging migration (AUDIT-076, project-wide), `[probe]` log prefix, stdout vs stderr routing audit. |
| AUDIT-169 | `cmd/api/static.go` is a 2-line wrapper around `//go:embed` | 0.10.272 | 015c4eb | Multi-paragraph package-level doc comment on `cmd/api/static.go` names the audit, the two views (layering purist vs pragmatic), the choice we made, and the trigger that would justify migrating the embed to `internal/webassets/` (a second consumer appearing). `TestStaticGo_HasLayeringDocComment_AUDIT169` pins three signals: `"AUDIT-169"`, `"staticFiles"`, and `"internal/"` — any future agent who deletes the comment fails the test, with a message pointing at the audit. Deferred: move to `internal/` (audit explicitly accepted the current location), add a `static_test.go` exercising the embed. |
| AUDIT-133 | `formatBytes(NaN)` falls through to `Math.log(NaN) / Math.log(1024) = NaN` | 0.10.273 | 6d19d47 | `formatBytes` in `cmd/api/static/js/admin-common.js` now guards with `if (!isFinite(bytes) || bytes == null) return '—';` so NaN/Infinity/null inputs return the em-dash "no data" marker instead of rendering as "NaN.0 undefined". The other `formatBytes` in `admin-connection-detail.js:19` is a separate iterative-division algorithm that already short-circuits on `!bytes` and needed no fix. Three-signal regression test (`TestAdminCommon_FormatBytesHandlesNaN_AUDIT133`): file still defines `function formatBytes(bytes)`, `!isFinite(bytes)` guard present, fallback is the literal em-dash `—` (not "0 B" or "N/A"). Deferred: centralize the two `formatBytes` copies, audit `formatNum` for the same NaN class, server-side NaN sanitization (root-cause fix). |
| AUDIT-145 | `parseBucketToMillis` zero-row → 1970 datapoint | 0.10.274 | 32a28ed | New `bucketUnparseableMillis int64 = -1` sentinel returned by `parseBucketToMillis` for empty / whitespace / unparseable inputs (pre-fix returned 0, which the chart rendered as a literal "1970" datapoint). The consumer in `GetSystemStatusHistory` now filters rows with `millis == bucketUnparseableMillis` and logs a warning, so the API response never contains a `-1` `bucket_ms`. Sentinel exposed via `BucketMillisUnparseableSentinel() int64` for the test. 17 regression subtests in `parsebucket_audit145_test.go`: 10 in the headline test (4 unparseable inputs → sentinel, 5 valid inputs → real ms computed via `time.Parse`), 7 in a "never returns 0" defense-in-depth test. Deferred: audit the other `time.Parse` call sites in `database.go` (different functions, different concerns), surface skip count via metrics endpoint. |
| AUDIT-115 | `lessons.md` and `tasks/` should not be public | 0.10.275 | ff09e4d | `git rm` of `lessons.md`, `tasks/lessons.md`, `tasks/todo.md`. The three files were AI agent session memory, not for human contributors. The audit's alternative (move to `.claude/`, already gitignored) was rejected in favor of full removal — the content is re-derivable from the codebase, and the AI can keep session memory outside the repo entirely. `TestNoTrackedAgentMemoryFiles_AUDIT115` runs `git ls-files` and asserts none of the three files (or the `tasks/` directory) re-appear in the tracked-file list. Deferred: maintain an in-repo `docs/lessons.md` for human contributors (separate content project), broader sweep for other internal-process files, pre-commit hook. |
| AUDIT-127 | `admin-controls.js:150` history.replaceState only for filter pills | 0.10.276 | 0c48e92 | New multi-paragraph doc block in `admin-controls.js` file-level comment explains the back-button limitation, the design intent (replaceState was deliberate, to avoid back-stack pollution from slider drags), the trade-off (filter history is session-only), and the upgrade path (a minimal hash-based router would require lifting `load()` callbacks out of per-page IIFEs). The audit's first option ("implement the router") was a 200-300 LOC refactor; we chose the second option ("accept and document"). `TestAdminControls_DocumentsRouterLimitation_AUDIT127` pins four signals: `"AUDIT-127"`, `"history.back"`, `"replaceState"`, `"minimal hash-based"`. Deferred: build the hash-based router, add a `popstate` listener (partial fix), switch to `pushState` (rejected — would pollute back stack). |
| AUDIT-029 | Four tables have zero retention | 0.10.277 | 380d034 | `CleanupOldData` now has entries for `interface_errors`, `processor_stats`, `process_stats`, and `irc_message_logs` with per-table retention knobs on `RetentionConfig` (defaults 30/30/30/7 days). `ret.Days(0)` falls back to `DefaultDays` (90) so operators who don't set the new env vars get a sane default. Four new env vars in `config.env.example`. 2 regression tests in `cleanup_audit029_test.go`: headline test seeds 60-day-old rows in all four tables, asserts all are deleted with the AUDIT-029 defaults; defensive sibling seeds mixed-age rows in one table, asserts only the stale row is deleted. `internal/database/testing.go` updated to also `AutoMigrate` the four newly-tested models plus a few others missing from the test list. Deferred: per-device or per-tag retention, backfill cleanup for existing million-row tables. |
| AUDIT-030 | `interface_addresses` keeps appending the same IP every poll | 0.10.278 | d362613 | New `uniqueIndex:idx_ifaddr_dev_ip` on `(DeviceID, IPAddress)` of the `InterfaceAddress` model. `SaveInterfaceAddresses` now uses GORM's `clause.OnConflict` to emit `INSERT ... ON CONFLICT (device_id, ip_address) DO UPDATE SET timestamp, if_index, net_mask` on Postgres (and the equivalent UPSERT syntax on SQLite). Pre-fix behavior (a row per poll × IP, ~25M rows over 90 days for 50 devices) is replaced with a row per (device, IP) that updates in place. 3 regression tests in `ifaddr_audit030_test.go`: dedup-on-poll (same address twice, 15s apart, asserts one row with latest values), per-device dedup (same IP on two devices asserts two rows), multi-address call (three distinct tuples in one Save call asserts three rows). Migration note documented in CHANGELOG: existing deployments with duplicate rows need a one-shot dedup query before the AutoMigrate will succeed. Deferred: migration automation, historical IP audit log, single-column index tuning. |
| AUDIT-031 | Alerts retention ignores unacknowledged alerts | 0.10.279 | e4588a3 | `CleanupOldData` now has two cleanup windows for `alerts`: acked (default 30 days, `RETENTION_ALERT_DAYS`, pre-fix behavior) and unacked (default 90 days, new `RETENTION_UNACK_ALERT_DAYS` env var). Unacked window is clamped to be at least as long as the acked window so a future env misconfig can't accidentally auto-archive unacked alerts before the operator has had time to ack them. Each auto-archived stale unack alert fires a `WARNING` log with the alert ID, device, severity, message, and timestamp so the operator can reconstruct the "stale unack" event from the logs. 4 regression tests in `cleanup_audit031_test.go`: headline (3 alerts, only the recent unacked survives), clamp (unack < ack in config, 20-day unacked row survives), bulk delete (5 stale unack → 0), boundary (5-day unacked stays, isn't silently flipped to acked). Deferred: archive table instead of hard-delete, operator-visible stale-unack notification, per-severity retention. |
| AUDIT-037 | No statement timeout / query deadline | 0.10.280 | df4a831 | New `DatabaseConfig.StatementTimeout time.Duration` field (default 30s, `DB_STATEMENT_TIMEOUT` env var, 0 = disabled). `NewDatabase` now appends `options='-c statement_timeout=NNNms'` to the DSN when StatementTimeout > 0 so the timeout is enforced server-side for every connection the pool opens. Backstop to AUDIT-032's `WithContext(c.Request.Context())` rollout (the two are complementary: client-disconnect cancel vs fixed wall-clock deadline). 3 regression tests in `statementtimeout_audit037_test.go`: 30s default → DSN contains `statement_timeout=30000ms`, 0 → DSN has no `options=` clause, custom duration (5s) → 5000ms. Deferred: AUDIT-032's `WithContext` rollout, per-query deadline differentiation, SQLite tuning, per-transaction timeout. |
| AUDIT-154 | `internal/httputil/httputil.go:43-53` ParseHours unused | 0.10.281 | 93070ee | **Wontfix** — the audit was wrong. `ParseHours` is called in 7 places (`handlers_analytics.go:294,332,350,368`, `handlers_connections.go:60,331`, plus the comment at `:59`). `TestParseHours_IsUsed_AUDIT154` pins the call-site count via `git grep` (threshold ≥ 2 files); a future refactor that genuinely orphans the function would drop the count and fail the test. |
| AUDIT-155 | `internal/httputil/httputil.go:67` FilterAllowedFields unused | 0.10.281 | 93070ee | **Wontfix** — the audit was wrong. `FilterAllowedFields` is called in `handlers_connections.go:193` (and any future PATCH-style handler). `TestFilterAllowedFields_IsUsed_AUDIT155` pins the call-site count via `git grep` (threshold ≥ 1 file). |
| AUDIT-156 | `internal/api/handlers/handlers.go:127-...` validVendors map unused | 0.10.281 | 93070ee | **Wontfix** — the audit was wrong. `isValidVendor` is called in `handlers_devices.go:69` (device create) and `:207` (device update). `validVendors` is the authoritative "which vendors do we support" list. `TestIsValidVendor_IsUsed_AUDIT156` pins the call-site count via `git grep` (threshold ≥ 1 file). |
| AUDIT-110 | CHANGELOG not Keep-A-Changelog | 0.10.282 | 41b63c1 | `CHANGELOG.md` now strictly follows Keep-A-Changelog 1.1.0: added a header that links to the spec and to Semantic Versioning 2.0.0, and an `## [Unreleased]` section at the top with the standard sub-section placeholders (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`). New top-level `KNOWN-ISSUES.md` catalogues operator-known limitations that don't yet have a fix (cross-links to the audit doc for each). 2 regression tests in `internal/shell/changelog_audit110_test.go`: the header must reference both specs, the `[Unreleased]` section must be the first version section; the KNOWN-ISSUES.md must exist and must cross-link to at least 3 of the AUDIT-NNN references listed in it. Deferred: `git-cliff` / `release-please` automation, `### BREAKING CHANGES` per release (no breaking changes have shipped yet, so the sub-section is a no-op for now), commit-message convention enforcement. |
| AUDIT-138 | `cmd/api/main.go:67-76` URL-rewrite prefix-collision | 0.10.283 | b67962b | The doc block for the `/api/v1/` → `/api/` and `/admin/api/v1/` → `/admin/api/` path-rewrite is now explicitly tagged with `AUDIT-138` and explains the fragility (hand-coded, not config-driven), the design constraints (the slice math is `p[len(prefix):]`, which is safe against `..` escapes), and the upgrade path (real versioning per AUDIT-090). The behavior is unchanged; only the documentation is more complete. `TestAPIVersioningRewrite_BehaviorPinned_AUDIT138` in `internal/shell/` pins the four invariants (both prefixes present, both rewrites use the safe slice form, mounted via `router.Use`, audit ID referenced in a comment) so a future refactor that drops the rewrite without addressing AUDIT-090 fails the test. Deferred: real versioning per AUDIT-090 (would replace the hand-coded middleware with a config-driven version list). |
| AUDIT-139 | `cmd/api/static.go` embeds with `//go:embed static` | 0.10.284 | 97472b5 | `cmd/api/static.go` doc block now states that the embed ships JS unminified (213 KB for `admin-main.js`), names the audit's recommendation (esbuild → `cmd/api/static/js/dist/`), and points at the doc block as the migration's starting point. Behavior unchanged. `TestStaticFilesEmbed_ReferencesStaticDir_AUDIT139` pins four invariants (directive exists, declaration exists, audit ID is referenced, `static/` directory contains the expected `js/`, `css/`, `fonts/` sub-paths). Deferred: actual esbuild migration (Makefile dev-dep, CI step, dist directory layout, source-map shipping — all meaningful infra work). |
| AUDIT-149 | GORM `Logger: logger.Silent` swallows all DB errors | 0.10.285 | 114e676 | New `internal/database/logging.go` with `dbLogLevelFromEnv()` reads `DB_LOG_LEVEL` (default `warn`, valid: `silent` / `error` / `warn` / `info`). Pre-fix `logger.Silent` swallowed slow-query warnings, errors, and migration warnings; new `warn` default logs slow queries and errors without flooding the log with every successful statement. Unknown values fall back to `warn` and log a notice so a typo doesn't silently disable logging. 3 regression tests in `logging_audit149_test.go`: default-is-warn, all 4 valid values (plus case-insensitive + trim), unknown-falls-back-to-warn. Deferred: query-time-threshold slow-query logger (GORM has a `SlowThreshold` field; a future commit could expose it via `DB_SLOW_QUERY_THRESHOLD`). |
| AUDIT-151 | 103 `console.*` calls in admin JS | 0.10.286 | 3060613 | New `fwmonLog` wrapper in `admin-common.js` (`window.fwmonLog`, four levels: `.debug` / `.info` / `.warn` / `.error`). Wrapper is the only blessed path; the 3 existing `console.*` calls in `admin-common.js` were migrated to `fwmonLog.*` in the same commit. Migration of the other 8 first-party admin JS files is deferred — `TestConsoleCalls_DeferringToFwmonLog_AUDIT151` pins the current count (≤ 100) as a soft regression gate, so a future commit that migrates more files brings the count down and a regression that adds new `console.*` calls fails the test. `.debug` is silent in production by default and can be enabled per-session via `localStorage.setItem('fwmonLog.debug', '1')`. Deferred: migrate the remaining ~100 `console.*` calls in `admin-main.js`, `admin-device-detail.js`, `admin-flows.js`, `admin-connection-detail.js`, `admin-probes.js`, `admin-sites.js`, `diagram-panels.js`, `public-dashboard.js`. |
| AUDIT-143 | Bulk-ack by filter, not bulk snooze | 0.10.287 | 6f6174b | New `Database.SnoozeAlertsBulk(ids, until, by, reason)` and `Database.SnoozeAlertsByFilter(filter, until, by, reason)` mirror the existing `AcknowledgeAlertsBulk` / `AcknowledgeAlertsByFilter` shape. New HTTP endpoints: `POST /admin/api/alerts/bulk-snooze` (IDs in body) and `POST /admin/api/alerts/bulk-snooze-filter` (filter via query params, hours+reason via body). Pre-fix an operator who wanted to snooze N alerts at once had to write a loop of single-alert `SnoozeAlert(id, ...)` calls (N round-trips, no atomicity). Post-fix, the bulk-snooze flow matches the bulk-ack flow shape for both endpoints. Same `maxBulkAckIDs = 500` cap and `[1, 720]` hour clamp from the single-alert handler apply. 3 regression tests in `snooze_audit143_test.go`: by-IDs (3 alerts, all snoozed with audit fields), empty-IDs-is-noop, by-filter (3 high + 2 low, only the 3 high are snoozed). |
| AUDIT-144 | Auto-resnooze when alert clears | 0.10.288 | 9e00a0f | `internal/alerts/alerts.go:sendRecovery` now clears the snooze fields (`snoozed_until`, `snoozed_by`, `snoozed_reason`) on the matching alerts in the same UPDATE that sets `resolved_at`. Pre-fix a snoozed alert that was actually resolved would still appear in the "snoozed" view as if it were active — operators had to manually unsnooze every resolved-but-was-snoozed alert. Post-fix the recovery event does it for them. The WHERE clause is unchanged so the auto-unsnooze is scoped to the same set the recovery already touches; already-resolved or acked alerts are unaffected. 2 regression tests in `autoresnooze_audit144_test.go`: headline (2 unresolved-snoozed alerts, recovery sets `resolved_at` AND clears all 3 snooze fields), defensive sibling (3 rows that should NOT be touched — already-resolved, acknowledged, different alert_type — verify RowsAffected is 0 and snooze fields are intact). |
| AUDIT-146 | `EnsurePartitions` logs warning and skips for non-partitioned tables | 0.10.289 | 15f7de1 | The partition-skip log message now uses a `WARNING: AUDIT-146` prefix (grep-able) and explicitly notes that without monthly partitions the table will grow unbounded and the AUDIT-029 cleanup cron will eventually run full-table DELETE statements that take minutes. `TestEnsurePartitions_SurfacesWarning_AUDIT146` in `internal/shell/` pins the `WARNING: AUDIT-146` prefix and the `docs/partition-migration.md` pointer. Deferred: actual `docs/partition-migration.md` document (the log currently points at a file that doesn't exist; the migration is a separate, larger project). |
| AUDIT-128 | `formatDate` hardcodes en-US locale | 0.10.290 | acc0106 | The hardcoded `'en-US'` first arg to `toLocaleString` is gone from `formatDate` and `formatDateShort`. New `getBrowserLocale()` helper reads `navigator.language` (falling back to `'en-US'`) and both date-formatting functions use it. Pre-fix the admin UI displayed US-format dates (MM/DD/YYYY, 12-hour AM/PM) to every operator regardless of locale; post-fix an operator with `navigator.language = 'de-DE'` sees `DD.MM.YYYY, 14:23:45`, an operator with `'fr-FR'` sees `DD/MM/YYYY 14:23:45`, and an operator with `'en-US'` (or no language set) sees the original MM/DD/YYYY. `TestFormatDate_LocaleAware_AUDIT128` in `internal/shell/` pins the four invariants (hardcoded `'en-US'` argument is gone, helper exists, helper is wired in, audit ID is referenced). |
| AUDIT-136 | `cmd/api/main.go:104-121` IsGeneratedPassword heuristic | 0.10.291 | 52d81c2 | New `Auth.AdminPasswordGenerated` field on `Config`, populated once at config-load time via `os.LookupEnv`. The `IsGeneratedPassword()` method now reads the field (not the env). Pre-fix this re-queried `os.LookupEnv("ADMIN_PASSWORD")` on every call — a TOCTOU risk (the env could change between config-load and a later call) and duplicated work. The fix uses `LookupEnv` (not `Getenv == ""`) so an operator who explicitly sets `ADMIN_PASSWORD=""` is treated as "I want an empty password" (not "the env is unset, auto-generate") — that's the distinction the audit was about. 3 regression subtests in `config_audit136_test.go`: unset (returns true), set (returns false even with empty string), TOCTOU (post-load env mutation doesn't change the bool). |
| AUDIT-158 | Hardcoded `defaultPassword` in module scope | 0.10.292 | 66b6d2a | `getDefaultPassword` no longer caches in a module-level `var defaultPassword string`. Pre-fix the cache lingered in GC until the next collection, could surface in core dumps after the caller zeroed `cfg.Auth.AdminPassword`, and was a single global variable any test or code path could read. Post-fix the function returns a freshly-generated password every call. The `defer func() { defaultPassword = "" }()` in `Load()` is removed (it was zeroing the wrong thing — the string had already been copied into `cfg.Auth.AdminPassword` and the bcrypt hash, so the post-Load lifecycle sees copies the defer can't reach). 2 regression tests in `config_audit158_test.go`: behavioral (two consecutive calls produce different passwords, length = 16, charset matches) and concurrent (10 goroutines all get different passwords, ruling out a `sync.Once`-style re-introduction). |
| AUDIT-046 | `probes.html` modals render on first paint | 0.10.293 | 64efad9 | Inline `.modal:not(.hidden) { display: flex; }` replaced with `.modal.active { display: flex; }`. Neither `#probe-modal` nor `#deploy-modal` ever carries a `.hidden` class (`AdminCommon.openModal()` toggles `.active`, the admin-shared.css convention), so the old rule (specificity 0,2,0) beat the base `.modal { display: none }` and forced both modals visible on first paint — dormant only because the operator immediately closes them. `TestProbesModal_UsesActiveClass_AUDIT046` in `internal/shell/` pins the `:not(.hidden)` form is gone, the `.active` form is present, and the audit ID is referenced. |
| AUDIT-047 | Logout link is dead on `/admin/irc` | 0.10.294 | db0b62f | `admin-irc.js` delegated-click `switch` had no `case 'logout'`, so the sidebar Logout link (`data-action="logout"`) navigated to `#` and stayed on the page. Added `case 'logout': AdminCommon.doLogout(); return;` — this file uses the full `AdminCommon` reference (no `AC` alias defined here). `TestIRCLogout_HasLogoutCase_AUDIT047` in `internal/shell/` pins the case, the reference, and the audit ID. |
| AUDIT-048 | `.section-tab` redefines display, nullifying `.hidden` fix | 0.10.295 | 25ad013 | Inline `.section-tab { display: inline-block }` (loaded after admin-shared.css) overrode `.hidden { display: none }` on `#tab-phase2` / `#tab-flows`, so the v0.10.230 `classList.toggle('hidden', ...)` fix was a no-op. Added `.section-tab.hidden { display: none !important; }` to the same inline `<style>` block. `TestSectionTab_HiddenOverride_AUDIT048` in `internal/shell/` pins the rule and the audit ID. |
| AUDIT-049 | IRC tab nav active state never updates | 0.10.296 | 0188631 | No `.tab-btn.active` rule existed, so `switchTab()`'s `classList.add('active')` had no visual effect; the highlight was hardcoded as Tailwind utilities on the Servers button and never moved. Added `.tab-btn.active { color:#58a6ff; border-bottom-color:#58a6ff; }` and normalized the Servers button to the same class list as the other tabs. `TestIRCTab_ActiveRuleExists_AUDIT049` in `internal/shell/` pins the rule, the removal of the hardcoded border utility, and the audit ID. |
| AUDIT-050 | `admin-irc.js` is not IIFE-wrapped | 0.10.297 | cacca59 | The file declared `let servers/channels/commands` and every function at top level, leaking them onto `window`. Wrapped the whole file in `(function () { 'use strict'; ... })();` and converted the three top-level declarations to `var`. Minimal body diff (no re-indent); full ES6→ES5 conversion is tracked as AUDIT-131. Safe because irc.html has zero inline `onclick` (all handlers are data-action delegated). `TestIRCIife_Wrapped_AUDIT050` in `internal/shell/` pins the IIFE, strict mode, the `var` conversion, and the audit ID. |
| AUDIT-051 | `probes.html` Reject uses native `window.prompt()` | 0.10.298 | 1e94946 | `admin-probes.js` rejected via `prompt('Enter rejection reason:')`. Added a `#reject-modal` to probes.html (matching the page's modal styling, labelled textarea) and routed rejection through `AC.openModal` + a `#reject-form` submit handler, with `close-reject-modal` wired into the existing event delegation — mirroring the /admin/probe-pending flow. `TestProbesReject_UsesModal_AUDIT051` in `internal/shell/` pins the removal of `prompt()`, the modal-based JS path, and the modal markup. |
| AUDIT-052 | Public dashboard libs load WITHOUT `defer` | 0.10.299 | 8b1686f | `chart.umd.min.js`, `chartjs-plugin-zoom.min.js`, `gridstack-all.min.js` (~290 KB) blocked first paint on the public wallboard. Added `defer` to all three; `defer` executes in document order so `public-dashboard.js` (already `defer`) still runs after the libs. `TestPublicDashboard_LibsDeferred_AUDIT052` in `internal/shell/` pins each lib's `defer` and the audit marker. |
| AUDIT-053 | Dynamic `onclick="..."` in admin-device-detail | 0.10.300 | f8ca027 | Config-history row buttons (View/Download/Delete) and the two config-modal close buttons used inline `onclick` (only valid under `script-src 'unsafe-inline'`). Converted all five to `data-action` + `data-id`, handled by the existing `AC.delegateEvent` block; the file now has zero inline event attributes. `TestDeviceDetail_NoInlineOnclick_AUDIT053` in `internal/shell/` pins the absence of `onclick=` and the delegated handlers. |
| AUDIT-054 | admin.html has duplicate inline `.modal` rules | 0.10.301 | d391d30 | The `.modal { display:none }` / `.modal.active { display:flex }` display rules (plus admin.html's identical `.modal-header` / `.modal-close` / `.modal-footer`) were duplicated inline across admin.html, sites.html, probes.html — all redundant with admin-shared.css:506-573. Removed the duplicates; admin-shared.css is now the single source of truth (admin.html keeps only its genuinely-different `.modal-content` 92vw/85vh override). The AUDIT-046 test was updated to pin the enduring invariant after the inline `.modal.active` was removed from probes.html. `TestModalDedup_SingleSource_AUDIT054` in `internal/shell/` pins the removal across all three pages. |
| AUDIT-055 | Mobile sidebar only on `admin.html` | 0.10.302 | 888a7d6 | Only admin.html had the mobile header / hamburger / slide-in sidebar (inline); every other page had a fixed 240px sidebar covering half a phone viewport. Moved the chrome CSS to a shared section in admin-shared.css, added `AdminCommon.renderMobileChrome()` (injects markup + wires an idempotent toggle that syncs `aria-expanded`), and call it after `renderSidebar()` on all 7 admin pages. admin.html's inline CSS/markup/script were removed. `TestMobileChrome_OnAllPages_AUDIT055` in `internal/shell/` pins the method, the shared CSS, and the per-page call. |
| AUDIT-057 | JS-rendered nav has no `aria-current`/`aria-hidden` | 0.10.303 | 9eddf4b | `renderSidebar` marked the active item with only a `.active` class and left nav-icon glyphs readable by AT. Added `aria-current="page"` to the active link and `aria-hidden="true"` to all 16 `<span class="nav-icon">`. `TestSidebarAria_AUDIT057` in `internal/shell/` pins both attributes. |
| AUDIT-058 | `apiFetch` 401 redirect fires inside iframes | 0.10.304 | 4cf18fe | The 401/302 handler did `window.location.href = '/admin/login'`, navigating the Reports preview iframe to /login. Changed to `(window.top \|\| window).location.href`. `TestApiFetch401_TopFrame_AUDIT058` in `internal/shell/` pins the top-frame redirect. |
| AUDIT-059 | `escapeHtml` short-circuits on falsy incl. numeric 0 | 0.10.305 | 419baf4 | `if (!str)`/`if (!text)` blanked `0`, `false`, `''` alike (admin-common.js + admin-irc.js). Changed to nullish-only (`== null`). `TestEscapeHtml_NullishGuard_AUDIT059` in `internal/shell/` pins both files. |
| AUDIT-060 | No `@media print` rule, `.no-print` is dead | 0.10.306 | ffa440b | Added a `@media print` block to admin-shared.css hiding `.sidebar`, `.mobile-header`, `.sidebar-overlay`, `.toast-container`, `.no-print` and zeroing the `.main`/`.main-content` margin. Ctrl+P now prints just page content. `TestPrintCss_AUDIT060` in `internal/shell/` pins the rule and selectors. |
| AUDIT-061 | Per-tab Chart.js instances not destroyed on tab leave | 0.10.307 | 46e9c54 | `proc-ssh-chart` / `iface-err-chart` held canvas contexts for the whole page session. `switchTab` now destroys + nulls each chart when leaving its tab and recreates it from current controls on re-entry. `TestChartTeardown_AUDIT061` in `internal/shell/` pins the teardown. |
| AUDIT-062 | `admin-irc.js` showAlert uses inline `style.display` | 0.10.308 | fb19621 | showAlert toggled inline `style.display` and scheduled an uncleared 5s `setTimeout` each call, so back-to-back alerts hid each other early. Now toggles the shared `.hidden` class and `clearTimeout`s a tracked `alertTimer`; `#alertMessage` starts with `class="hidden"`. `TestIRCShowAlert_AUDIT062` in `internal/shell/` pins the change. |
| AUDIT-063 | Public dashboard "Reset Layout" wipes localStorage with no confirmation | 0.10.309 | 4941a8a | Added a `confirm()` guard to `resetLayout()`. Used a native `confirm()` deliberately rather than loading admin-common.js (~36 KB + a /admin/api fetch) onto the public wallboard, which would partly undo AUDIT-052. `TestResetConfirm_AUDIT063` in `internal/shell/` pins the confirm-before-clear ordering. |
| AUDIT-065 | Unescaped `conn.status` in innerHTML (connection-detail) | 0.10.310 | b1c5483 | `statusEl.innerHTML` concatenated raw `conn.status` into the badge class + text. Server validates to an enum (defense-in-depth gap, not live XSS); wrapped with `AC.escapeHtml` (uppercase then escape). `TestConnStatusEscape_AUDIT065` in `internal/shell/` pins it. |
| AUDIT-064 | N+1 in probes page loadProbeSummaryStats | 0.10.311 | ecefba0 | Added `GET /admin/api/probes/stats?ids=` (`GetProbesStatsBatch`) returning total + last-hour counts for all probes in 8 grouped queries (`WHERE probe_id IN (...) GROUP BY probe_id`), regardless of N; `admin-probes.js` makes one batched call instead of one per approved probe. Static route, sibling of `/api/probes/:id`. Tests: `TestGetProbesStatsBatch_AUDIT064` (+EmptyIDs) handler/DB, `TestProbesBatchStats_FrontendUsesBatch_AUDIT064` JS. |
| AUDIT-056 | Inline `<label>` without `for=""` (~60 inputs) | 0.10.312 | 41c6836 | Swept probes/sites/irc/probe-pending/admin.html and added `for="<input id>"` to 88 non-wrapping labels (wrapping + header labels left alone; id-less inputs skipped, not guessed). Transform in `scripts/audit056_labels.py`. `TestLabelFor_AUDIT056` in `internal/shell/` pins that every `<label for>` resolves to an id + per-page minimum counts. |
| AUDIT-068 | Mobile chart/table overflow on device-detail | 0.10.315 | 818a69e | Made `#systemStats` / `#extendedStats` `overflow-x-auto` scroll containers. All 7 data tables were already wrapped; the audit's "15-col processes table" doesn't exist (that tab renders a chart). `TestDeviceDetailOverflow_AUDIT068` in `internal/shell/` pins both grids are scroll containers. |
| AUDIT-069 | Focus management on modals | 0.10.316 | 2f0f847 | Baked `role="dialog"` / `aria-modal="true"` / `aria-labelledby` into the 10 static modals in admin.html + device-detail.html (injecting title ids where missing), so modals are accessible without waiting for `tagStaticModals()`. `scripts/audit069_modal_aria.py`. `TestModalAria_AUDIT069` in `internal/shell/` pins the attributes + labelledby resolution. |
| AUDIT-070 | `mobile-menu-btn aria-expanded` never updates | 0.10.317 | 7033abd | Resolved by AUDIT-055 (v0.10.302): `renderMobileChrome` creates the hamburger with `aria-expanded="false"` and its open/close handler keeps it in sync. This commit adds the explicit `AUDIT-070` reference + `TestAriaExpanded_AUDIT070` in `internal/shell/` to pin it against regression. |
| AUDIT-034 | `cidrToLikePattern` → un-indexable LIKE on `flow_samples` | 0.10.318 | a450ad1 | Added `idx_flow_src_addr` / `idx_flow_dst_addr` btree indexes (gorm struct tags, created by AutoMigrate). The flow-stats `src_addr LIKE 'x%'` prefix match is sargable on a btree, so connection-stats queries no longer full-scan `flow_samples`. `TestFlowSampleIndexes_AUDIT034` in `internal/database/` verifies both exist after migration. |
| AUDIT-035 | `GetLatestVPNStatuses` does a per-peer sequential scan | 0.10.319 | 6a45065 | Replaced the per-peer loop (N `WHERE device_id = ?` scans) with a single `WHERE device_id IN (...) AND (local_subnet != '' OR remote_subnet != '')` query (subnet filter in SQL, `ORDER BY device_id, timestamp DESC` preserves the cross-fill result). Chosen over a Postgres `ROW_NUMBER()` window because the single `IN` query fixes the N+1 with identical, cross-dialect, testable semantics. `TestGetLatestVPNStatuses_PeerCrossFill_AUDIT035` in `internal/database/` proves the peer subnet + RemoteDeviceID cross-fill still works. |
| AUDIT-020 | SSRF allowlist has DNS-rebinding TOCTOU | 0.10.326 | 2c9f0a2 | New `internal/httputil/ssrf.go`: `IsBlockedIP` adds multicast + CGNAT `100.64.0.0/10` + `0.0.0.0/8` (fail-closed on nil); `SafeDialContext` resolves + validates every candidate IP and dials the pinned IP, closing the resolve-vs-dial rebinding gap. The notifier webhook client uses `SafeDialContext`; handlers' `isBlockedIP` delegates to the shared helper. Tests in `internal/httputil/ssrf_test.go`. Deferred: pinning SMTP/SNMP/IRC dials (admin-configured, lower risk). |
| AUDIT-042 | Relay client has no idempotency key | 0.10.327 | 9790df6 | Collector sends a stable `X-Probe-Batch-ID` (random 128-bit hex, reused across a batch's retries); server records `(probe_id, batch_id)` in a new `processed_batches` table and dedupes repeat requests, recording the key only after a 2xx save (a failed save isn't dedupe-dropped on retry). Applied to `/syslog` `/traps` `/flows` `/pings`; 2-day cleanup retention. Collector v1.2.74. Tests: `handlers_data_idempotency_audit042_test.go` (server), `relay_idempotency_audit042_test.go` (collector). Deferred: direct-send endpoints. |
| AUDIT-018 | Stale dependencies | 0.10.328 | 56f3efd | Bumped gin 1.9.1→1.10.1, golang-jwt/jwt/v5 5.2.0→5.2.2, gosnmp 1.37.0→1.40.0, x/net 0.25.0→0.38.0 (reachable html.Tokenizer DoS), x/crypto→0.36.0; pinned to keep `go 1.23` (a blanket @latest pulls gin 1.12 + go-1.25 toolchain, breaking the golang:1.23 Docker build). govulncheck CI job already present (AUDIT-004); `godeps_audit018_test.go` pins floors. Deferred: stdlib CVEs need a Go-1.25 build-toolchain bump (Dockerfile + go directive); thoj/go-ircevent→girc is a separate rewrite. |
| AUDIT-017 | Probe registration key stored in plaintext | 0.10.329 | dfba9c1 | Keys stored as `sha256:`+SHA-256 (hashed, not encrypted — a by-value-looked-up token can't use non-deterministic AES-GCM, and a reversible store still leaks on key+DB compromise). Plaintext is show-once (RegenerateProbeKey response). Idempotent startup migration hashes legacy plaintext keys + `probe_registration_` settings in place; live probe unaffected (collector keeps sending plaintext → hashes to stored value). validateProbe/authenticateProbeByBearer/RegisterProbe/GetProbeByRegistrationKey updated. HashProbeKey ALWAYS hashes (not idempotent) so the stored hash can't be replayed as a token (caught in review). Tests: probekey_audit017_test.go, handlers_probe_keyhash_audit017_test.go. |
| AUDIT-036 | DB pool sized for one process, not three daemons | 0.10.330 | 34304df | Pool size now per-process: api/poller/trap mains set 15/10/5 (DB_MAX_OPEN_CONNS overrides); NewDatabase reads cfg.Database.MaxOpenConns (fallback 25), idle capped at open limit. Was a flat SetMaxOpenConns(25) on each of 3 daemons = 75 conns/host. TestDBPoolPerProcess_AUDIT036. |
| AUDIT-038 | CleanupOldData does N full DELETEs serially | 0.10.331 | 28d81ab | Each table deleted in 10k-row batches (`id IN (SELECT id ... LIMIT N)`, portable PG+SQLite); on PG each batch in a txn with `SET LOCAL lock_timeout='5s'`, 100ms sleep between. Retention semantics unchanged (AUDIT-029/031 tests pass). TestBatchedDeleteOlderThan_AUDIT038. Deferred: leader lock (AUDIT-007). |
| AUDIT-043 | Time-series chart SQL uses window functions unsupported by SQLite | 0.10.332 | b6f8a23 | Premise outdated: the `LAG() OVER w`/`WINDOW w AS` queries (GetVPNChartData, GetConnectionTraffic) run correctly on the modernc SQLite test backend AND Postgres — no gating needed. Closed the real gap (untested in CI) with TestGetVPNChartData_WindowDeltas_AUDIT043 (delta + counter-reset math on SQLite); documented dialect-safety in-code. |
| AUDIT-033 | GetDashboardAll is textbook N+1 | 0.10.333 | 8be35f3 | Per-device enrichment loop (~13 queries x N devices, ~650 at 50 devices) replaced with ~7 batched aggregates (one per data type) via the max-timestamp self-join (portable PG+SQLite). O(1) in device count, same output shape. TestGetDashboardAll_BatchedEnrichments_AUDIT033 verifies latest-timestamp selection + up/alive counts. |
| AUDIT-066 | Color contrast `#484f58` on `#161b22` fails WCAG AA | 0.10.334 | 924085c | Surgical redo of the reverted v0.10.319 sweep: only `color:` TEXT uses of `#484f58` changed to `#768390` (~4.6:1, passes AA) across CSS + 5 admin JS files; decorative uses (borders/backgrounds/hover/chart colors) left as `#484f58` to preserve the hierarchy that caused the v0.10.320 revert. `TestNoFaintTextColor_AUDIT066` pins no text `color:#484f58` remains. Sibling AUDIT-067 still open. |
| AUDIT-067 | Color contrast `#6e7681` passes AA only for large text | 0.10.335 | 554beb0 | Surgical: all TEXT uses of `#6e7681` (the `--fwmon-text-faint` token + literal `color:` + `text-[#6e7681]` utilities; ~42 sites) retargeted to `#8b949e` (~5.8:1, AA). Distinct from AUDIT-066 `#768390` to keep faint tiers separate (avoids the v0.10.320 flatten revert). 2 decorative `border-color: var(--fwmon-text-faint)` pinned to literal `#6e7681`. `TestNoFaintTextColor_AUDIT067` walks the frontend tree. |
| AUDIT-041 | Probe ping write path is not batched | (verified) | 2026-06-06 | Verification sweep — already resolved: Already done — `pingBatch` exists (database.go) and `SavePingResult` routes through it; code evolved after the v0.10.239 audit. |
| AUDIT-082 | Mutex held across HTTP call in relay | (verified) | 2026-06-06 | Verification sweep — already resolved: `relay.go syncData()` snapshots the queues under the lock then `mu.Unlock()` BEFORE `sendBatch`/HTTP — no HTTP under lock. |
| AUDIT-089 | Dead code | (verified) | 2026-06-06 | Verification sweep — already resolved: Superseded — split into AUDIT-154/155/156 (those symbols ARE used → wontfix) + AUDIT-157 (ADMIN_SECRET_KEY removed, v0.10.269); `LastUpAt` now used. |
| AUDIT-100 | `deploy.sh` systemd units run as `User=root` | (verified) | 2026-06-06 | Verification sweep — already resolved: Fixed by AUDIT-021 (v0.10.261): deploy.sh systemd unit uses `User=fwmon` + hardening directives. |
| AUDIT-116 | `*_test.go` in `.gitignore` | (verified) | 2026-06-06 | Verification sweep — already resolved: Fixed by AUDIT-001 (v0.10.241): the `.gitignore` entry was removed; 30+ `_test.go` files are tracked. |
| AUDIT-121 | No race detector in CI | (verified) | 2026-06-06 | Verification sweep — already resolved: Fixed by AUDIT-004: `.github/workflows/ci.yml` runs `go test -race -count=1 ./...`. |
| AUDIT-125 | Inline event handler generation in admin-device-detail | (verified) | 2026-06-06 | Verification sweep — already resolved: Fixed by AUDIT-053 (v0.10.300): `admin-device-detail.js` has 0 inline `onclick`, uses `addEventListener`. |
| AUDIT-141 | No `t.TempDir()` / `t.Cleanup()` | (verified) | 2026-06-06 | Verification sweep — already resolved: Adopted — `internal/secrets/secrets_test.go` uses `t.TempDir()` at 6 sites. |
| AUDIT-152 | No `gofmt` enforcement in CI | (verified) | 2026-06-06 | Verification sweep — already resolved: Fixed by AUDIT-075/004: `ci.yml` runs `gofmt -l .` and fails the build on any output. |
| AUDIT-153 | `MODEL.go` LastUpAt is dead | (verified) | 2026-06-06 | Verification sweep — already resolved: `LastUpAt` is now populated by GetLatestVPNStatuses and consumed by the VPN-status UI — no longer dead. |
| AUDIT-167 | No "Known Issues" doc | (verified) | 2026-06-06 | Verification sweep — already resolved: `KNOWN-ISSUES.md` exists at the repo root (added v0.10.282, AUDIT-110). |
| AUDIT-085 | Probe auth key rotation not transactional | 0.10.325 | ccd602f | `RegenerateProbeKey` deleted the old key's `SystemSetting` first and only logged a warning if the new setting failed to write — a mid-sequence failure could rotate the key but leave no usable registration setting, locking the probe out. Now generates the new key before any write and wraps update-probe → delete-old → create-new in one `gorm.Transaction` (rollback keeps the working key). `TestRegenerateProbeKey_Atomic_AUDIT085` in `internal/api/handlers/` pins the success contract. |
| AUDIT-092 | `.dockerignore` missing many entries | 0.10.336 | a673c9c | Added `cookies.txt`, `interfaces.json`, `IRC-FORMAT.txt`, `node_modules/`, `tasks/`, `.claude/`, `lessons.md`, `*.csv` to the build-context ignore list. Nothing leaks today (the Dockerfile COPYs specific paths), but a future `COPY . .`-style broadening would otherwise ship these working-tree artifacts. `TestDockerignore_CoversWorkingTreeArtifacts_AUDIT092` pins each required entry. |
| AUDIT-095 | `entrypoint.sh` sets `logging_collector = off` | 0.10.337 | e25299d | Documentation-only. The audit's "crash forensics lost" premise is half-true: PG is started with `pg_ctl -l "$PGDATA/postgresql.log"`, so stderr is retained on the bind-mounted volume even with the collector off. Added an in-config rationale comment (where logs live + the `log_destination = stderr` alternative). No runtime change — entrypoint runs the live prod DB. `TestEntrypoint_LoggingRationale_AUDIT095` pins the rationale + the `pg_ctl -l` redirect together. |
| AUDIT-099 | `deploy.sh` overwrites live config | 0.10.338 | b5c2019 | The remote-install heredoc unconditionally `cp`'d `config.env.example` over `/etc/firewall-mon/config.env` on every deploy, wiping the operator's real secrets/thresholds back to placeholders. Now guarded by `if [ ! -f /etc/firewall-mon/config.env ]` — the example only seeds a first install; later deploys preserve the existing file (example still staged at `/tmp/config.env.example`). `TestDeploy_PreservesLiveConfig_AUDIT099` pins the guard. |
| AUDIT-098 | `deploy.sh` is destructive | 0.10.339 | 2983f73 | The unconditional `rm -rf ${REMOTE_DIR}/*` had no backup/rollback. Added (1) a `--dry-run` flag that makes zero remote changes, and (2) a timestamped backup tarball to `${REMOTE_DIR}-backups/` taken before the wipe. `TestDeploy_BackupAndDryRun_AUDIT098` pins both + backup-before-rm ordering. Deferred: post-start healthcheck (this script hands off to install.sh; healthcheck belongs there, with AUDIT-096). |
| AUDIT-097 | `docker-compose.proxy.yml` is stock | 0.10.340 | 252d114 | Shipped `docs/nginx.conf`: a hardened plain-nginx example with TLS termination, HSTS, gzip, WebSocket upgrade for `/admin/connections` + `/admin/irc`, and real-client-IP from the Docker subnets. `docker-compose.proxy.yml` now references it + carries a commented `nginx` service that mounts it. `TestNginxCompanionConfig_AUDIT097` pins the features + compose reference. Deferred: app-side `SetTrustedProxies` (currently `nil` — the safe default; honoring X-Forwarded-For weakens it and needs config wiring). |
| AUDIT-088 | `time.Sleep` in retry loops without jitter | 0.10.341 | 84b13e2 | Added a `crypto/rand`-backed `jitter(d)` (returns `d + [0,d)`) in `internal/relay` and `internal/irc`; applied to relay `sendBatch` retry backoffs (both error + non-2xx paths) and the IRC bot restart delay, so a shared recovery doesn't retry in lock-step. `TestJitter_BoundsAndSpread_AUDIT088` (relay unit) + `TestBackoffJitter_CallSites_AUDIT088` (shell pin). `runCollectorHandler`'s 100 ms idle poll left unchanged (not a server retry). |
| AUDIT-087 | `cmd/probe/main.go` pollDevice no ctx | 0.10.342 | e25ee81 | `go p.pollDevice(dev)` was untracked + context-less, so polls ran unbounded after `Stop()`. `pollDevice` now takes a `context.Context` and checkpoints between stages; the probe holds `ctx`/`cancel`/`pollWG`, tracks each poll, and `cleanup()` cancels then drains in-flight polls bounded to 5s (before stopping the relay client). `cmd/probe` unit tests (cancel+drain + 5s ceiling) + `TestProbePollDeviceContext_AUDIT087` shell pin. Deferred: ctx into gosnmp ops (lib uses its own timeout). |
| AUDIT-103 | Dockerfile installs unused `gcc musl-dev` | 0.10.343 | 8c24348 | Builder built with `CGO_ENABLED=0`, so the `apk add gcc musl-dev` C toolchain was never used — removed it (kept a comment). `TestDockerfile_NoUnusedCToolchain_AUDIT103` pins the packages stay out while `CGO_ENABLED=0` remains. |
| AUDIT-102 | `go build` lacks `-trimpath -buildvcs=false` | 0.10.344 | 3923924 | Added `-trimpath -buildvcs=false` to all four Dockerfile build lines and the Makefile `build` target (`GOFLAGS_REPRO`), so binaries are byte-reproducible across hosts. `TestReproducibleBuildFlags_AUDIT102` pins both paths. Deferred: SOURCE_DATE_EPOCH + ldflags version injection (`ServerVersion` is a const, not ldflags-injectable). |
| AUDIT-104 | No `make install` / native-binary path | 0.10.345 | 6f0631a | Added `make install`/`uninstall` (PREFIX/DESTDIR-aware) + `make tarball` (`dist/firewall-mon-$(VERSION).tar.gz`). Also fixed a latent bug: `build` named binaries after their dirs (`api`/`poller`/…) instead of the canonical `fwmon-*` the install/systemd paths expect — now emits `fwmon-*`. Validated via staged install + tarball. `TestMakefileNativeInstall_AUDIT104` pins targets + names + PREFIX/DESTDIR. |
| AUDIT-163 | No CODEOWNERS | 0.10.346 | aadfbfb | Added `.github/CODEOWNERS` with a `*` catch-all + specific owners for security-sensitive code, schema/migrations, build/deploy/CI, and the audit docs. (The verification sweep had found the CHANGELOG referenced this file before it existed.) `TestCodeownersExists_AUDIT163` pins existence + catch-all + every-pattern-has-an-owner. |
| AUDIT-162 | No README test instructions | 0.10.347 | b1d394b | Added README **Test** (`go test ./...`, `make qa`, `make test-race`) + **Install Natively** (`make install`/`tarball`) subsections. `TestReadmeHasTestInstructions_AUDIT162` pins `go test ./...` stays documented. |
| AUDIT-109 | README feature list stale | 0.10.348 | 3056a84 | Rewrote the Features list to cover reports, sites + connection map, alert policies, maintenance windows, IRC bot, sFlow/syslog/ICMP, multi-tenant probes, multi-vendor SNMP. `TestReadmeFeatureListCurrent_AUDIT109` requires a keyword per subsystem in the `## Features` section. |
| AUDIT-107 | Documented env vars are 6 lines | 0.10.349 | dc1b01d | Added a README env-var defaults table (verified against `internal/config`, not guessed) + a cross-link naming `config.env.example` as authoritative; covers ENCRYPTION_KEY / RETENTION_* / PROBE_* / REPORT_* / DB_MAX_OPEN_CONNS / SERVER_*_TIMEOUT. `TestReadmeEnvVarDocs_AUDIT107` pins the cross-link + families. |
| AUDIT-168 | No browser support baseline documented | 0.10.350 | 4f30ff2 | Added a README **Browser Support** section: Chrome/Edge 105+, Safari 15.4+, Firefox 121+ (the `:has()`/ES2020 floor), no legacy support. `TestReadmeBrowserBaseline_AUDIT168` pins the section + the three engines. |
| AUDIT-170 | No example of a custom vendor profile | 0.10.351 | 3e5d3ad | Added `docs/custom-vendor.md`: end-to-end tutorial (full `VendorProfile` interface, copy-pasteable shallow profile, `init()`/`RegisterVendor`, the `validVendors` edit, optional `configdiff` normalizer, checklist). Code verified against the real API (`gosnmp.ToBigInt`, real float64 fields). README-linked. `TestCustomVendorDoc_AUDIT170` pins the doc + extension points + README link. |
| AUDIT-080 | `== gorm.ErrRecordNotFound` instead of `errors.Is` | 0.10.352 | e31d677 | Swept all 15 direct `==`/`!=` comparisons against `gorm.ErrRecordNotFound` in `database.go` to `errors.Is` (unwraps `%w`-wrapped errors; future-proof against AUDIT-081 wrapping). Cited auth/notifier sites had since moved (no sentinel compare there now). `TestErrorsIsForGormSentinels_AUDIT080` pins no direct comparison remains. |
| AUDIT-147 | `ConfigureAutovacuum` table list hard-coded | 0.10.353 | f67dfaa | Default list now includes the omitted `interface_stats`/`system_status` (+ processor/process/vpn/ha/ifaddr) and is overridable via `DB_AUTOVACUUM_TABLES`; resolution moved to a testable `autovacuumTables()`. Table names verified vs `TableName()` (`vpn_status`/`ha_status` are singular). `TestAutovacuumTables_AUDIT147` pins coverage + override. |
| AUDIT-112 | No `.well-known/security.txt` route | 0.10.354 | d77cad1 | Added RFC 9116 `security.txt` at `/.well-known/security.txt` (+ `/security.txt`) with `Contact`/`Policy`/`Preferred-Languages` and a request-time `Expires` (6 months out, never stale). `TestSecurityTxtRoute_AUDIT112` pins the route + required fields. |
| AUDIT-130 | No retry on transient API failures | 0.10.355 | d7c6fcd | `apiFetch` now retries 502/503/504 up to 3 attempts with exponential backoff + jitter before erroring; 401/403/`!ok` handling unchanged. `TestApiFetchRetriesTransient_AUDIT130` pins the statuses + jittered backoff. |
| AUDIT-134 | Hardcoded `package.json` version | 0.10.356 | 2aedf38 | Removed the stale unused `"version": "0.10.157"` (read by nothing; app version lives in `ServerVersion`) and marked the package `"private": true` so no version is needed and none can go stale. `TestPackageJsonNoStaleVersion_AUDIT134` pins no version field + private. |
| AUDIT-084 | `PruneExpiredAttempts` goroutine leak | 0.10.357 | 6eb0c1f | The prune goroutine ran a bare `for range ticker.C` with no exit. Added a cancellable `bgCtx`; the pruner now `select`s on `<-bgCtx.Done()` and the shutdown path calls `bgCancel()` before draining the server. `TestPruneGoroutineHasShutdown_AUDIT084` pins the wiring. |
| AUDIT-113 | No "How to add a vendor" doc | 0.10.358 | 1ec0457 | Covered by `docs/custom-vendor.md` (AUDIT-170), which documents both the SNMP profile side (`RegisterVendor`/`validVendors`) and the `internal/configdiff` normalizer (Step 5). `TestVendorDocCoversBothSides_AUDIT113` pins both-sided coverage so it can't be trimmed away. |
| AUDIT-111 | No RUNBOOK.md / OPERATIONS.md | 0.10.359 | 7c2d000 | Added `docs/OPERATIONS.md` (first-24h, failure-mode table, debug logging, admin reset, JWT rotation, backup/restore, upgrade, scale, DR), grounded in real mechanisms (verified vs code — e.g. admin reset = `DELETE FROM admins`+restart since `InitAdmin` is create-when-absent; no `GIN_MODE` toggle). README-linked. `TestOperationsRunbook_AUDIT111` pins the sections + link. |
| AUDIT-108 | No architecture diagram | 0.10.360 | 40c68df | Added `docs/architecture.md`: Mermaid component flowchart + 3 sequence diagrams (probe registration, poll cycle, alert firing) + package map. README-linked. `TestArchitectureDiagram_AUDIT108` pins the Mermaid blocks, ≥3 sequence diagrams, README link. |
| AUDIT-135 | No request-ID middleware | 0.10.361 | a2c6d7f | New `RequestID` middleware: reuses a safe inbound `X-Request-ID` (`^[A-Za-z0-9._-]{1,64}$`, log-forge guarded) or mints a 128-bit hex one, stores it on the context + echoes the `X-Request-ID` response header; `RequestLogger` logs `req=<id>`. Unit tests cover generate/reuse/reject-hostile. Full slog migration is AUDIT-076 (open). |
| AUDIT-131 | `admin-irc.js` ES6 amid ES5 (pick one) | 0.10.362 | 139c3a9 | Added `cmd/api/static/js/README.md` declaring **ES2020** the standard (justified by the AUDIT-168 browser baseline), so the ES6 code is correct; legacy `['catch']` flagged as not-to-be-extended (cleanup = AUDIT-132). `TestJSStandardDocumented_AUDIT131` pins it. |
| AUDIT-119 | No fuzz tests for untrusted network parsers | 0.10.363 | 12c896b | Added `FuzzParseRFC5424` (syslog) + `FuzzParseSFlowDatagram` (sflow) with malformed seeds. Active fuzzing: 3.3M execs (sflow) + 267k (syslog), **zero crashes** — durable no-panic guard. First tests in `internal/syslog`/`internal/sflow` (also chips at AUDIT-117). |
| AUDIT-124 | No benchmark tests | 0.10.364 | 2f58589 | Added `BenchmarkParseRFC5424`/`ParsePriority` (syslog) + `BenchmarkParseSFlowDatagram` (sflow) — per-packet CPU hot paths, no DB fixtures. `b.ReportAllocs()`+`SetBytes()`. Deferred: DB-bound hot paths (BatchInserter/GetConnectionFlowStats) need a seeded test DB. |
| AUDIT-132 | ES5 `['catch']` bracket workaround | 0.10.365 | a372758 | Swept the legacy IE11 reserved-word bracket form (`promise['catch']`/`['finally']`, `searchParams['delete']`) to dot notation across **all 121 sites / 14 files** in `cmd/api/static/js`; vendored bundles untouched. Baseline is ES2020 (AUDIT-168/131) so `.catch`/`.finally`/`.delete` are valid. All files pass `node --check`. `TestNoES5BracketWorkaround_AUDIT132` guards `*.js` (README excluded — it quotes the syntax). Completes the AUDIT-131 deferred cleanup. |
| AUDIT-081 | 46× raw `return err` in database.go | 0.10.366 | 9666eb6 | Wrapped all **25 remaining** bare `return err` (GORM `tx.Error`) in `database.go` with `fmt.Errorf("operation: %w", err)`, naming the operation + entity id; `%w` preserves the `errors.Is(err, gorm.ErrRecordNotFound)` checks from AUDIT-080. Two trailing returns where `err` could be nil (`CreateDevice`, `MarkBatchProcessed`) converted to guarded wraps so success never yields a non-nil error. `TestNoBareReturnErrInDatabase_AUDIT081` statically asserts zero bare returns remain + a `%w` wrap exists. Handler-side `models.ErrorResponse` boilerplate (AUDIT-071) stays open. |
| AUDIT-165 | No GitHub release-notes automation | 0.10.367 | 7b62ac0 | Added `.github/workflows/release.yml`: tag-triggered (`v*`), lifts the matching `## [X.Y.Z]` block out of `CHANGELOG.md` (falls back to `## [Unreleased]`) and publishes it via `gh release create`/`edit` (idempotent). CHANGELOG-driven by design (repo is direct-to-master, not labelled PRs, so release-drafter doesn't fit). `contents: write` scoped to the job; dormant until the first tag. `TestReleaseWorkflow_AUDIT165` pins the trigger/permission/extraction/publish and that it's not branch-triggered. `.goreleaser.yml` artifact build (AUDIT-004) still open. |
| AUDIT-071 | 134× silent `c.JSON(500, ErrorResponse)` | 0.10.368 | (pending) | Added `httputil.InternalError(c, msg, err)` (logs `err` + method/route/`X-Request-ID`, writes standard 500 JSON with only `msg`) and swept **all 133 sites** across 13 handler files. Bonus: 4 sites were leaking `err.Error()` into the client body (IRC connect/send, report build) — now logged not leaked. Edge cases by hand: nil-err sites pass `nil`, `DeleteConnection`/`ReceiveConfigRevision` pass `result.Error`/`txErr`. `TestInternalError_AUDIT071` (behaviour) + `TestInternalErrorSweep_AUDIT071` (static guard). 4xx left as-is; `slog` migration is AUDIT-076. |

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
2026-06-02 — AUDIT-027 — decryptField fail-closed (returns empty on any decrypt error) — v0.10.245 — 41cd6ae — opencode
2026-06-02 — AUDIT-016 — probe key constant-time compare in validateProbe — v0.10.246 — 90afae6 — opencode
2026-06-02 — AUDIT-015 — reject CORS=* at startup (Allow-Credentials always true) — v0.10.247 — 210d4a8 — opencode
2026-06-02 — AUDIT-086 — HTTP listener errors no longer bypass graceful shutdown — v0.10.248 — b8357db — opencode
2026-06-02 — AUDIT-013 — TestIRCServer SSRF check (isValidExternalIP) — v0.10.249 — c23ed1b — opencode
2026-06-02 — AUDIT-012 — trap receiver fail-closed community + per-IP rate limit — v0.10.250 — 0a5a383 — opencode
2026-06-02 — AUDIT-083 — rate limiter LRU cap + Stop() hook — v0.10.251 — 35a829b — opencode
2026-06-02 — AUDIT-008 — JWT secret + admin password persistence (new internal/secrets pkg) — v0.10.252 — 03d2e6e — opencode
2026-06-02 — AUDIT-137 — stop logging masked admin password (collateral with AUDIT-008) — v0.10.252 — 03d2e6e — opencode
2026-06-02 — AUDIT-005 — trap-receiver real DB + race-safe multi-process JWT secret — v0.10.253 — c0ae1f4 — opencode
2026-06-02 — AUDIT-003 — THIRD-PARTY-NOTICES.md — v0.10.254 — 4743ca7 — opencode
2026-06-02 — AUDIT-011 — SECURITY.md + CONTRIBUTING.md + CODE_OF_CONDUCT.md — v0.10.254 — 4743ca7 — opencode
2026-06-02 — AUDIT-004 — CI workflow + Makefile (partial) — v0.10.255 — 6be86a0 — opencode
2026-06-02 — AUDIT-007 — cross-process poller leader lock (pg_try_advisory_lock) — v0.10.256 — f32396e — opencode
2026-06-02 — AUDIT-006 — batcher shutdown race fix + Dropped counter (partial) — v0.10.257 — 9dcb153 — opencode
2026-06-02 — AUDIT-009 — encryption keyChain for rotation (current + legacy) — v0.10.258 — d41b2c3 — opencode
2026-06-02 — AUDIT-022 — CSP nonce for inline scripts/styles (per-request 128-bit, no more unsafe-inline) — v0.10.259 — 21df1b4 — opencode
2026-06-02 — AUDIT-019 — IRC bot per-channel admin allow-list (AdminNicks, fail-closed) — v0.10.260 — bb4174d — opencode
2026-06-02 — AUDIT-021 — systemd units run as fwmon with full hardening block — v0.10.261 — 5d8c0dd — opencode
2026-06-02 — AUDIT-024 — COOKIE_SECURE / SERVER_ENABLE_TLS mismatch warns at startup + example fix — v0.10.262 — 1278601 — opencode
2026-06-02 — AUDIT-026 — system_settings encryption gated on IsSecret (no more encrypting thresholds) — v0.10.263 — 98022df — opencode
2026-06-02 — AUDIT-091 + AUDIT-045 — /api/health pings DB with 1s timeout + Dockerfile HEALTHCHECK — v0.10.264 — 3950cb0 — opencode
2026-06-02 — AUDIT-093 — Postgres password auto-generated, persisted to /config/pg-credentials (chmod 0600) — v0.10.265 — 37067e0 — opencode
2026-06-02 — AUDIT-096 — docker-compose.yml has explicit healthcheck block (mirrors Dockerfile v0.10.264) — v0.10.266 — a976e9f — opencode
2026-06-02 — AUDIT-105 — default ADMIN_USERNAME=admin warns at startup (case-insensitive) — v0.10.267 — f13a322 — opencode
2026-06-02 — AUDIT-148 — LIKE clauses carry ESCAPE '\' modifier (CIDR pattern defense in depth) — v0.10.268 — f83ea8b — opencode
2026-06-02 — AUDIT-157 — dead ADMIN_SECRET_KEY env var + field removed from config + example — v0.10.269 — f708489 — opencode
2026-06-02 — AUDIT-101 — Dockerfile OCI labels sourced from ARG (no more stale version) — v0.10.270 — dd76868 — opencode
2026-06-02 — AUDIT-159 — probe banner output now uses log.* (consistent with codebase) — v0.10.271 — c81cc41 — opencode
2026-06-02 — AUDIT-169 — cmd/api/static.go layering decision documented in source (audit accepts as-is) — v0.10.272 — 015c4eb — opencode
2026-06-02 — AUDIT-133 — formatBytes(NaN) returns em-dash "no data" marker instead of "NaN.0 undefined" — v0.10.273 — 6d19d47 — opencode
2026-06-02 — AUDIT-145 — parseBucketToMillis returns -1 sentinel (not 0) for unparseable, chart no longer renders 1970 — v0.10.274 — 32a28ed — opencode
2026-06-02 — AUDIT-115 — AI agent session-memory files (lessons.md, tasks/) removed from public tree — v0.10.275 — ff09e4d — opencode
2026-06-02 — AUDIT-127 — admin-controls.js back-button limitation documented in source (router upgrade path noted) — v0.10.276 — 0c48e92 — opencode
2026-06-02 — AUDIT-029 — interface_errors, processor_stats, process_stats, irc_message_logs now in CleanupOldData — v0.10.277 — 380d034 — opencode
2026-06-02 — AUDIT-030 — interface_addresses UPSERTs on (device_id, ip_address) — v0.10.278 — d362613 — opencode
2026-06-02 — AUDIT-031 — stale unacked alerts auto-archived after 90d (warning log per row) — v0.10.279 — e4588a3 — opencode
2026-06-02 — AUDIT-037 — per-connection statement_timeout enforced server-side (default 30s) — v0.10.280 — df4a831 — opencode
2026-06-02 — AUDIT-154/155/156 — WONTFIX (audit was wrong: ParseHours / FilterAllowedFields / validVendors are all used) — v0.10.281 — 93070ee — opencode
2026-06-02 — AUDIT-110 — CHANGELOG strictly Keep-A-Changelog 1.1.0 + new KNOWN-ISSUES.md — v0.10.282 — 41b63c1 — opencode
2026-06-02 — AUDIT-138 — URL-rewrite prefix-collision documented (hand-coded, fragile; upgrade via AUDIT-090) — v0.10.283 — b67962b — opencode
2026-06-02 — AUDIT-139 — static.go doc block names the lack-of-minification + esbuild migration path — v0.10.284 — 97472b5 — opencode
2026-06-02 — AUDIT-149 — GORM log level is no longer hardcoded to Silent (DB_LOG_LEVEL=warn default) — v0.10.285 — 114e676 — opencode
2026-06-02 — AUDIT-151 — fwmonLog wrapper introduced (admin-common.js migrated; ~100 calls in 8 other files deferred) — v0.10.286 — 3060613 — opencode
2026-06-02 — AUDIT-143 — bulk-snooze by IDs and by filter (mirrors bulk-ack shape) — v0.10.287 — 6f6174b — opencode
2026-06-02 — AUDIT-144 — auto-resnooze on alert resolution (recovery event clears snooze fields) — v0.10.288 — 9e00a0f — opencode
2026-06-02 — AUDIT-146 — EnsurePartitions skip-message now uses WARNING: AUDIT-146 prefix (grep-able) — v0.10.289 — 15f7de1 — opencode
2026-06-02 — AUDIT-128 — formatDate / formatDateShort now locale-aware (navigator.language) — v0.10.290 — acc0106 — opencode
2026-06-02 — AUDIT-136 — IsGeneratedPassword no longer re-queries env (captured at load time) — v0.10.291 — 52d81c2 — opencode
2026-06-02 — AUDIT-158 — getDefaultPassword no longer caches in module-level var (password didn't linger in GC) — v0.10.292 — 66b6d2a — opencode
2026-06-03 — AUDIT-046 — probes.html modals use .modal.active (no longer render on first paint) — v0.10.293 — 64efad9 — opencode
2026-06-03 — AUDIT-047 — add logout case to admin-irc.js delegated switch (dead Logout link) — v0.10.294 — db0b62f — opencode
2026-06-03 — AUDIT-048 — .section-tab.hidden override so JS toggle hides tabs — v0.10.295 — 25ad013 — opencode
2026-06-03 — AUDIT-049 — add .tab-btn.active rule + normalize Servers button — v0.10.296 — 0188631 — opencode
2026-06-03 — AUDIT-050 — IIFE-wrap admin-irc.js (no more global scope leak) — v0.10.297 — cacca59 — opencode
2026-06-03 — AUDIT-051 — probes.html reject uses styled modal (no window.prompt) — v0.10.298 — 1e94946 — opencode
2026-06-03 — AUDIT-052 — defer public dashboard libs (chart/zoom/gridstack) — v0.10.299 — 8b1686f — opencode
2026-06-03 — AUDIT-053 — data-action delegation replaces inline onclick in device-detail — v0.10.300 — f8ca027 — opencode
2026-06-03 — AUDIT-054 — dedup inline .modal rules (single source: admin-shared.css) — v0.10.301 — d391d30 — opencode
2026-06-03 — AUDIT-055 — AdminCommon.renderMobileChrome() on all admin pages — v0.10.302 — 888a7d6 — opencode
2026-06-03 — AUDIT-057 — aria-current + aria-hidden on rendered sidebar nav — v0.10.303 — 9eddf4b — opencode
2026-06-03 — AUDIT-058 — apiFetch 401 redirects top frame (iframe-safe) — v0.10.304 — 4cf18fe — opencode
2026-06-03 — AUDIT-059 — escapeHtml nullish guard (no longer blanks numeric 0) — v0.10.305 — 419baf4 — opencode
2026-06-03 — AUDIT-060 — @media print hides admin chrome (.no-print now works) — v0.10.306 — ffa440b — opencode
2026-06-03 — AUDIT-061 — destroy per-tab Chart.js on tab leave (device-detail) — v0.10.307 — 46e9c54 — opencode
2026-06-03 — AUDIT-062 — irc showAlert uses .hidden class + clears timer — v0.10.308 — fb19621 — opencode
2026-06-03 — AUDIT-063 — confirm() before public dashboard layout reset — v0.10.309 — 4941a8a — opencode
2026-06-03 — AUDIT-065 — escape conn.status before innerHTML (connection-detail) — v0.10.310 — b1c5483 — opencode
2026-06-03 — AUDIT-064 — batch /probes/stats?ids= endpoint (kills probes N+1) — v0.10.311 — ecefba0 — opencode
2026-06-03 — AUDIT-056 — add for= to 88 form labels (screen-reader association) — v0.10.312 — 41c6836 — opencode
2026-06-03 — AUDIT-068 — overflow-x-auto on device-detail stat grids — v0.10.315 — 818a69e — opencode
2026-06-04 — AUDIT-066/067 — REVERTED the color sweep (flattened the text hierarchy → UI looked worse in prod); reopened — v0.10.320 — (pending) — opencode
2026-06-03 — AUDIT-069 — bake role/aria-modal/aria-labelledby into modal markup — v0.10.316 — 2f0f847 — opencode
2026-06-03 — AUDIT-070 — pin mobile-menu aria-expanded sync (done in AUDIT-055) — v0.10.317 — 7033abd — opencode
2026-06-03 — AUDIT-034 — btree indexes on flow_samples src_addr/dst_addr — v0.10.318 — a450ad1 — opencode
2026-06-03 — AUDIT-035 — single IN-query for VPN peer cross-fill (kills N+1) — v0.10.319 — 6a45065 — opencode
2026-06-05 — AUDIT-085 — wrap probe key rotation in a transaction (generate-first, rollback-safe) — v0.10.325 — ccd602f — opencode
2026-06-05 — AUDIT-020 — SSRF: pinned SafeDialContext + widen block list (CGNAT/0.0.0.0/8/multicast) — v0.10.326 — 2c9f0a2 — opencode
2026-06-05 — AUDIT-042 — X-Probe-Batch-ID idempotency (collector v1.2.74 + server processed_batches dedup) — v0.10.327 — 9790df6 — opencode
2026-06-05 — AUDIT-018 — bump gin/jwt/gosnmp/x-net (conservative, keep go1.23); defer go-ircevent + stdlib toolchain — v0.10.328 — 56f3efd — opencode
2026-06-05 — AUDIT-017 — hash probe registration keys at rest (sha256, show-once, live-probe-safe migration) — v0.10.329 — dfba9c1 — opencode
2026-06-06 — AUDIT-036 — per-process DB pool sizing (15/10/5, DB_MAX_OPEN_CONNS override) — v0.10.330 — 34304df — opencode
2026-06-06 — AUDIT-038 — batched retention deletes (10k LIMIT, PG lock_timeout, 100ms sleep) — v0.10.331 — 28d81ab — opencode
2026-06-06 — AUDIT-043 — verify window-chart queries SQLite-safe + regression test (no gating) — v0.10.332 — b6f8a23 — opencode
2026-06-06 — AUDIT-033 — batch GetDashboardAll enrichment (kills ~13xN query N+1) — v0.10.333 — 8be35f3 — opencode
2026-06-06 — AUDIT-066 — surgical WCAG fix: #484f58 text -> #768390 (decorative untouched) — v0.10.334 — 924085c — opencode
2026-06-06 — AUDIT-067 — surgical WCAG fix: #6e7681 text -> #8b949e (token+literal+utility; decorative untouched) — v0.10.335 — 554beb0 — opencode
2026-06-06 — AUDIT-041 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-082 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-089 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-100 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-116 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-121 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-125 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-141 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-152 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-153 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-167 — verification sweep: already resolved (see resolved-table note) — (verified) — 2026-06-06 — opencode
2026-06-06 — AUDIT-092 — add missing .dockerignore entries (working-tree artifacts) — v0.10.336 — a673c9c — opencode
2026-06-06 — AUDIT-095 — document logging_collector=off rationale in entrypoint.sh (logs retained in postgresql.log) — v0.10.337 — e25299d — opencode
2026-06-06 — AUDIT-099 — guard deploy.sh config.env copy with [ ! -f ] (preserve live config) — v0.10.338 — b5c2019 — opencode
2026-06-06 — AUDIT-098 — deploy.sh pre-deploy backup tarball + --dry-run flag before destructive rm — v0.10.339 — 2983f73 — opencode
2026-06-06 — AUDIT-097 — ship hardened docs/nginx.conf companion + compose reference — v0.10.340 — 252d114 — opencode
2026-06-06 — AUDIT-088 — jittered relay retry + IRC reconnect backoffs (crypto/rand) — v0.10.341 — 84b13e2 — opencode
2026-06-06 — AUDIT-087 — probe pollDevice ctx + tracked goroutines + bounded drain on Stop — v0.10.342 — e25ee81 — opencode
2026-06-06 — AUDIT-103 — drop unused gcc/musl-dev from Dockerfile builder (CGO_ENABLED=0) — v0.10.343 — 8c24348 — opencode
2026-06-06 — AUDIT-102 — reproducible builds: -trimpath -buildvcs=false (Dockerfile + Makefile) — v0.10.344 — 3923924 — opencode
2026-06-06 — AUDIT-104 — make install/uninstall/tarball + canonical fwmon-* build names — v0.10.345 — 6f0631a — opencode
2026-06-06 — AUDIT-163 — add .github/CODEOWNERS (catch-all + sensitive paths) — v0.10.346 — aadfbfb — opencode
2026-06-06 — AUDIT-162 — README Test + native-install instructions (go test ./...) — v0.10.347 — b1d394b — opencode
2026-06-06 — AUDIT-109 — refresh stale README feature list — v0.10.348 — 3056a84 — opencode
2026-06-06 — AUDIT-107 — README env-var defaults table + config.env.example cross-link — v0.10.349 — dc1b01d — opencode
2026-06-06 — AUDIT-168 — document browser support baseline (Chrome 105+/Safari 15.4+/Firefox 121+) — v0.10.350 — 4f30ff2 — opencode
2026-06-06 — AUDIT-170 — docs/custom-vendor.md tutorial (add an SNMP vendor profile) — v0.10.351 — 3e5d3ad — opencode
2026-06-06 — AUDIT-080 — sweep gorm.ErrRecordNotFound == to errors.Is in database.go (15 sites) — v0.10.352 — e31d677 — opencode
2026-06-06 — AUDIT-147 — autovacuum: add interface_stats/system_status + DB_AUTOVACUUM_TABLES override — v0.10.353 — f67dfaa — opencode
2026-06-06 — AUDIT-112 — RFC 9116 security.txt route (/.well-known/security.txt) — v0.10.354 — d77cad1 — opencode
2026-06-06 — AUDIT-130 — apiFetch retry 502/503/504 with backoff+jitter — v0.10.355 — d7c6fcd — opencode
2026-06-06 — AUDIT-134 — remove stale unused package.json version + mark private — v0.10.356 — 2aedf38 — opencode
2026-06-06 — AUDIT-084 — prune goroutine exits on bgCtx cancel (graceful shutdown) — v0.10.357 — 6eb0c1f — opencode
2026-06-06 — AUDIT-113 — how-to-add-a-vendor covered by docs/custom-vendor.md (both-sided test) — v0.10.358 — 1ec0457 — opencode
2026-06-06 — AUDIT-111 — docs/OPERATIONS.md runbook (grounded in real mechanisms) — v0.10.359 — 7c2d000 — opencode
2026-06-06 — AUDIT-108 — docs/architecture.md Mermaid component + sequence diagrams — v0.10.360 — 40c68df — opencode
2026-06-06 — AUDIT-135 — RequestID middleware (X-Request-ID, log correlation, log-forge guard) — v0.10.361 — a2c6d7f — opencode
2026-06-06 — AUDIT-131 — declare ES2020 the JS standard (cmd/api/static/js/README.md) — v0.10.362 — 139c3a9 — opencode
2026-06-06 — AUDIT-119 — Go fuzz tests for syslog + sflow parsers (no crashes in 3.5M+ execs) — v0.10.363 — 12c896b — opencode
2026-06-06 — AUDIT-124 — benchmarks for syslog + sflow parser hot paths — v0.10.364 — 2f58589 — opencode
2026-06-06 — AUDIT-132 — sweep ES5 ['catch']/['finally']/['delete'] bracket workaround to dot notation (121 sites/14 files) — v0.10.365 — a372758 — opencode
2026-06-06 — AUDIT-081 — wrap 25 raw `return err` in database.go with fmt.Errorf %w (errors.Is-preserving) — v0.10.366 — 9666eb6 — opencode
2026-06-06 — AUDIT-165 — tag-triggered CHANGELOG-driven release-notes workflow (.github/workflows/release.yml) — v0.10.367 — 7b62ac0 — opencode
2026-06-06 — AUDIT-071 — httputil.InternalError helper + sweep 133 silent handler 500s (now log err; stop leaking err to 4 clients) — v0.10.368 — (pending) — opencode
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


---

# Part III — Maintainer & session working notes

> Absorbed from the former `docs/HANDOFF.md`. These are the per-commit workflow
> conventions and the chronological session-by-session completion logs.
> **Counts and "remaining" lists within this Part are historical** — the
> Status dashboard at the **top** of this file is authoritative for current status.


**Written:** 2026-06-03 (end of a multi-session audit-resolution effort)
**Source of truth:** `docs/AUDIT.md` (the original audit document, which has been
updated in lockstep with each resolved finding).

## Executive summary

The public-release audit at v0.10.239 produced **170 bug findings** (AUDIT-001
through AUDIT-170) and **89 feature recommendations** (AUDIT-F01 through F89).
After the audit-resolution effort through v0.10.333, **106 of the 170 bug
findings are resolved** and **0 are still in CRITICAL status**. (Session 15
reached 88, v0.10.320 reverted AUDIT-066/067 → 86, Session 16 added 5 → 91,
Session 17 added 4 → 95, then a **2026-06-06 verification sweep** reclassified 11
already-fixed-but-unmarked audits → **106**.) Three production hotfixes
(v0.10.322–324, 2026-06-04) shipped outside the audit cadence — see the
"Production hotfix interlude". This document catalogs the remaining work so a
future session can pick up without re-reading the entire audit.

> **Session 13 (2026-06-03) completed all 10 of its HIGH frontend quick wins
> (AUDIT-046 through 055), v0.10.293 → v0.10.302.** See the "Session 13
> completion log" near the bottom of this file.
>
> **Session 14 (2026-06-03) completed all 10 of AUDIT-056 through 065,
> v0.10.303 → v0.10.312** (incl. the AUDIT-064 batch-stats backend endpoint).
> See the "Session 14 completion log".
>
> **Session 15 (2026-06-03) completed AUDIT-066–070 + 034 + 035,
> v0.10.313 → v0.10.319** (two WCAG color sweeps, mobile overflow, modal ARIA,
> two DB N+1/index fixes). The wontfix trio in the Session-15 table needed no
> action: **155/156 were already resolved (wontfix) at v0.10.281**, and the
> "AUDIT-081 ParseHours" row is a mislabel of AUDIT-154 (also done at
> v0.10.281) — the real AUDIT-081 is a Session-19 item. See the "Session 15
> completion log".
>
> **⚠ After Session 15 (2026-06-04): AUDIT-066/067 were REVERTED and three
> production hotfixes shipped — see the "Production hotfix interlude" below.**
> v0.10.320 reverted the AUDIT-066/067 color sweep (it flattened the UI in
> prod), reopening both → resolved count **86**. v0.10.321 = AUDIT-022b (CSP
> style-src). v0.10.322–324 were production firefighting, not audit work.
> **Session 16 (security-adjacent: AUDIT-085, 020, 042, 018, 017) is now DONE**
> (v0.10.325–329, 2026-06-05) — see its completion log below. Next: Session 17
> (DB performance: AUDIT-041, 043, 044, 036, 038, 039, 033).

**Remaining scope:**

| Bucket | Count | Notes |
|---|---|---|
| **Resolved bug audits** | **108** | per the `docs/AUDIT.md` resolved table (`grep -c '^\| AUDIT-'`); includes 11 verification-sweep reclassifications + AUDIT-066/067 (v0.10.334/335); 0 remain CRITICAL |
| **Open bug audits** | **62** | 170 total − 108 resolved |
| Feature recommendations (F01–F89) | 89 | out of scope for "complete the audit"; future v0.11.0+ work |

> **Per-severity split:** the earlier hand-maintained HIGH/MEDIUM/LOW open counts
> drifted (they were a pre-Session-13 snapshot and never reconciled — they summed
> to 83 while the row claimed 109). Read the live split from `docs/AUDIT.md`'s
> section headers (`## HIGH`, `## MEDIUM`, `## LOW`) rather than trusting a cached
> number here. The per-session HIGH lists below remain the practical execution order.

**The realistic answer to "complete all issues" is multi-session.** The 84
remaining bug audits break down roughly into:

- **~60 quick wins** (each ≤1 commit, ≤2 files). One focused session can
  knock out 10-20 of these. Three to four such sessions would clear the queue.
- **~25 medium features** (multi-file changes, real design work). One per
  commit; each is a session unto itself.
- **~9 large refactors** (AUDIT-032's 388-site rollout, AUDIT-072's 4,210-LOC
  database.go split, AUDIT-076 structured logging, etc.). Each needs a
  dedicated session with a planning step.

## Conventions established in the existing 61 resolutions

A future session should follow the same pattern. Skipping any of these
breaks the workflow that 61 prior commits established.

1. **One commit per audit.** The commit message format is
   `v0.X.Y: AUDIT-NNN - short description`. The body lists what's in/out of
   scope. Use a `.commit-msg.tmp` file and `git commit -F .commit-msg.tmp` to
   avoid bash glob expansion issues with `*_test.go` paths in the message body.
2. **Version bump in every commit.** Update **`cmd/api/main.go:35`**
   (`const ServerVersion`) — and ONLY that file. The Dockerfile bump is
   **obsolete**: `Dockerfile` uses `ARG VERSION=dev` fed via `--build-arg` at
   build time (AUDIT-101), so there is no version line to edit there. Increment
   `.patch` from the previous version.
3. **CHANGELOG entry at the top.** Add a new `## [X.Y.Z] - YYYY-MM-DD` block
   above the previous block. Per the AUDIT-110 fix (v0.10.282), the file
   now follows Keep-A-Changelog 1.1.0 — use the `### Fixed` / `### Added`
   / `### Changed` / `### Security` subsections.
4. **Audit-doc update in the same commit.** Two edits to `docs/AUDIT.md`:
   - Add a row to the "Resolved findings" table (search for `| AUDIT-` at
     the start of a line for the table format).
   - Add a line to the "Progress log" at the bottom.
   Both use `(pending)` for the commit SHA; the next step is the SHA
   backfill.
5. **SHA backfill as a separate commit.** Once the code commit is pushed,
   a tiny follow-up commit replaces `(pending)` with the real SHA in the
   audit doc. This is mechanical and runs without re-running QA.
6. **Regression tests where feasible.** Every resolved audit has at least
   one regression test. For small Go changes, a `_test.go` in the same
   package; for shell/Dockerfile/docs/JS changes, a static check in
   `internal/shell/`. The test message should name the audit ID so a
   future agent who breaks the invariant sees the audit context.
7. **CHANGELOG deferred section.** Every commit ends with a "What this
   does NOT do (deferred)" paragraph in the CHANGELOG entry. The deferred
   half is often the work the next session picks up; the doc is the
   starting point.

## Severity × effort matrix

Read the audit doc row by row to get the issue + fix. The severity
(CRITICAL / HIGH / MEDIUM / LOW) is set by the doc's section headers
(`## CRITICAL` = v0.10.239 deployment blockers, `## HIGH` = the seven
HIGH-priority sub-sections, `## MEDIUM` = MEDIUM-priority findings,
`## LOW` = LOW-priority findings). The effort column is my estimate
based on the audit's "Fix" field and the size of the affected code.

Effort legend:
- **XS** = 1-line config / comment / test-pin (≤1 hour)
- **S** = 1 commit, 1-3 files, ≤200 LOC (≤2 hours)
- **M** = 1-3 commits, multi-file, needs design thought (half day)
- **L** = multi-commit, many files, real refactor (1-2 days)
- **XL** = multi-session, breaks the API or schema (project-scale)

## Original execution plan — HIGH-priority buckets (HISTORICAL)

> ⚠ **This is the original forward plan (written ~v0.10.333), kept for the
> per-audit fix hints.** It is **not** a current open-work list — execution
> diverged from it and most buckets are now resolved. For the authoritative
> current state use the **Status dashboard** and **What's left** at the top of
> this file, and the **Resolved findings** table for per-finding truth.
>
> **Naming caveat:** the "Session N" labels below are this plan's *bucket*
> numbers and do **not** correspond to the "Session N" completion logs further
> down (those record what was actually shipped, which mixed items across these
> buckets). Status markers (✅/⏳) on each bucket header below reflect the
> 2026-06-06 reconciliation.

### Session 13: HIGH quick wins (S) — 10 audits ✅ DONE (v0.10.293–302, 2026-06-03)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-046 | `probes.html` modals render on first paint | S | One-line `hidden` class on the modal divs; tested via static check on the HTML. |
| AUDIT-047 | Logout link is dead on `/admin/irc` | S | The IRC page lacks a logout link; the other admin pages have one. Add the same `<a href="/admin/logout">` markup. |
| AUDIT-048 | `.section-tab` redefines display, nullifying `.hidden` fix | S | CSS specificity issue. One-line fix: make `.section-tab[hidden]` more specific. |
| AUDIT-049 | IRC tab nav active state never updates | S | JS click handler bug. ~5 lines in `admin-controls.js`. |
| AUDIT-050 | `admin-irc.js` is not IIFE-wrapped | S | Wrap the IIFE. ~10 lines. |
| AUDIT-051 | `probes.html` Reject uses native `window.prompt()` | S | Replace with a modal. The framework already has a modal pattern (see `probes.html` Accept modal). |
| AUDIT-052 | Public dashboard libs load WITHOUT `defer` | S | Add `defer` to the `<script>` tags. |
| AUDIT-053 | Dynamic `onclick="..."` in admin-device-detail | S | Replace with `addEventListener`. ~10 sites. |
| AUDIT-054 | admin.html has 1,500-line `<style>` block buried in `<body>` | S | Move to `<head>`. CSP doesn't need a nonce for this style (the v0.10.259 CSP doesn't set style-src-attr). |
| AUDIT-055 | Mobile sidebar only on `admin.html` | S | Copy the `<button class="mobile-menu-btn">` markup to other admin pages. |

### Session 14: HIGH quick wins (S) — 10 audits ✅ DONE (v0.10.303–312, 2026-06-03)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-056 | Inline `<label>` without `for=""` (~60 inputs) | S | Add `for="<id>"` to each label. Mechanical; ~60 changes across 8 HTML files. |
| AUDIT-057 | JS-rendered nav has no `aria-current` or `aria-hidden` | S | Add `aria-current="page"` to the active nav item; `aria-hidden="true"` to the icon `<span>`. |
| AUDIT-058 | `apiFetch` 401 redirect fires inside iframes | S | When inside an iframe, the 401 response should not redirect (the iframe would navigate to /login and break the embed). |
| AUDIT-059 | `escapeHtml` short-circuits on falsy including numeric 0 | S | Change `if (!str)` to `if (str == null)`. |
| AUDIT-060 | No `@media print` rule, `.no-print` class is dead | S | Add `@media print { .no-print { display: none; } }` to admin-design-system.css. |
| AUDIT-061 | Per-tab Chart.js instances not destroyed on tab leave | S | Hook the `hidden` event or use a `beforeDestroy` callback. |
| AUDIT-062 | `admin-irc.js:23-28` showAlert uses inline `style.display` toggling | S | Replace with a CSS class. |
| AUDIT-063 | Public dashboard "Reset Layout" wipes localStorage with no confirmation | S | Add a confirm() prompt. |
| AUDIT-064 | N+1 in probes page loadProbeSummaryStats | S | Add a `?ids=` IN-clause to the underlying `GetProbes` call. |
| AUDIT-065 | `cmd/api/static/js/admin-connection-detail.js:141` unescaped `conn.status` in innerHTML | S | Wrap with `AC.escapeHtml`. |

### Session 15: HIGH quick wins (S) — 10 audits ✅ DONE (v0.10.313–319, 2026-06-03)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-066 | Color contrast `#484f58` on `#161b22` fails WCAG AA | S | Pick a brighter color. The audit names the issue; the design system has the list of approved tokens. |
| AUDIT-067 | Color contrast `#6e7681` on `#0d1117` passes AA only for large text | S | Same as AUDIT-066. |
| AUDIT-068 | Mobile chart/table overflow on device-detail | S | Add `overflow-x: auto` on the table wrapper. |
| AUDIT-069 | Focus management on modals | S | On modal show, focus the first input. On escape, close + restore focus to the trigger. |
| AUDIT-070 | `mobile-menu-btn aria-expanded` never updates | S | Toggle `aria-expanded` in the open/close handler. |
| AUDIT-035 | `GetLatestVPNStatuses` per-peer sequential scan | M | Window function approach. 1 commit, ~30 LOC in `database.go`. |
| AUDIT-034 | `cidrToLikePattern` → un-indexable LIKE on `flow_samples` | S | Add the btree indexes named in the fix. |
| AUDIT-081 | `internal/httputil/httputil.go` `ParseHours` unused | **Wontfix** | Wrong audit; already covered by AUDIT-154 fix (v0.10.281). |
| AUDIT-155 | `FilterAllowedFields` unused | **Wontfix** | Wrong audit; already covered by v0.10.281. |
| AUDIT-156 | `validVendors` map unused | **Wontfix** | Wrong audit; already covered by v0.10.281. |

### Session 16: HIGH security-adjacent quick wins (S) — 5 audits ✅ DONE (all 5: 017/020/018/085/042, v0.10.325–329)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-017 | Probe registration key stored in plaintext | M | Encrypt at rest using the existing `crypto.go` AES-256-GCM pattern. Big jump in security value. |
| AUDIT-020 | SSRF allowlist has DNS-rebinding TOCTOU | M | Resolve once, dial the captured IP. The fix is a 30-line refactor. |
| AUDIT-018 | Stale dependencies | M | `go get -u gin@1.10.x golang-jwt@5.2.2+ gosnmp@1.40+`. Run `govulncheck` in CI. Migrate off `thoj/go-ircevent`. |
| AUDIT-085 | Probe auth handler not transactional | S | Wrap in a single transaction. |
| AUDIT-042 | Relay client has no idempotency key | M | Add `X-Probe-Batch-ID` UUID. ~50 LOC. |

### Session 17: HIGH DB performance quick wins (S–M) — 8 audits ✅ MOSTLY DONE (041/043/036/038/033/045 done; ⏳ 044, 039 still open)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-041 | Probe ping write path is not batched | M | Add a 4th batcher. Same durability fix as AUDIT-006 applies. |
| AUDIT-043 | Time-series chart SQL uses window functions unsupported by SQLite | M | Gate behind `dialect.IsPostgres()`. |
| AUDIT-044 | AutoMigrate is called on every startup with no schema version table | L | Adopt `golang-migrate` or `pressly/goose`. |
| AUDIT-036 | DB pool sized for one process, not three daemons | S | Per-process configurable. Default 15/10/5. |
| AUDIT-038 | `CleanupOldData` does N full DELETEs serially | M | Batched delete with `LIMIT 10000` + `SET LOCAL lock_timeout`. |
| AUDIT-039 | Per-daemon `BatchInserter` instances but only the api uses them | S | Move to `NewDatabaseForAPI`. Poller/trap use no batcher. |
| AUDIT-033 | `GetDashboardAll` is textbook N+1 | M | 6 batched aggregate queries. |
| AUDIT-045 | `GetHealth` is a no-op | **Already done** | Fixed by v0.10.264 (AUDIT-091/045). |

### Session 18: HIGH critical-feature quick wins (S–M) — 5 audits ⏳ MOSTLY OPEN (004/006 done; ⏳ 040, 028, 032 are the big refactors, still open)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-040 | Two `cmd/api` instances → 2 IRC bots, 2× login lockout, 2× rate limit | L | Short-term: advisory-lock startup check. Long-term: move state to Postgres. |
| AUDIT-028 | `interface_stats` and `system_status` are not partitioned | L | Monthly partitions for both tables. Requires migration path. |
| AUDIT-006 | Batcher is not crash-durable and has a shutdown race | L | WAL+fsync+spill-to-disk. Already half-done (v0.10.257). |
| AUDIT-004 | No git tags, no CI, no release flow | L | Already half-done (v0.10.255: Makefile, ci.yml). Deferred: release.yml, goreleaser. |
| AUDIT-032 | `c.Request.Context()` is never passed to DB calls | L | **188 sites** to touch. The right approach is a middleware-injection wrapper, not a hand-edit. |

### Session 19: HIGH frontend polish (S) — 10 audits ⏳ MOSTLY OPEN (080/082 done; ⏳ 071, 072, 073, 076, 077, 078, 079, 081 still open)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-071 | 388 sites of `c.JSON(http.StatusInternalServerError, models.ErrorResponse(...))` boilerplate | M | A small helper `httputil.JSONError(c, status, msg)` eliminates the boilerplate. |
| AUDIT-072 | `internal/database/database.go` is 4,210 LOC, 175 functions | **XL** | This is a multi-session refactor. Strategy: split by domain (alerts.go, devices.go, syslog.go, ...) using `internal/database/{domain}.go`. |
| AUDIT-073 | `internal/models/models.go` mixes GORM structs with HTTP transport | M | Split into `models/gorm.go` (DB structs) and `models/dto.go` (HTTP transport). |
| AUDIT-076 | No structured logging | **L** | Migrate to `log/slog`. |
| AUDIT-077 | No Prometheus `/metrics` endpoint | M | Add `prometheus/client_golang`. |
| AUDIT-078 | No admin-action audit log | M | New `AdminAuditLog` model + middleware. |
| AUDIT-079 | `c.Request.Context()` not used; no per-request cancellation | (See AUDIT-032) | Same fix. |
| AUDIT-080 | Many `if err == gorm.ErrRecordNotFound` instead of `errors.Is` | S | Global sed: `err == gorm.ErrRecordNotFound` → `errors.Is(err, gorm.ErrRecordNotFound)`. |
| AUDIT-081 | Many `return err` raw in `internal/database/database.go` | S | Wrap with context. Mostly mechanical. |
| AUDIT-082 | Mutex held across HTTP call in relay | S | Restructure the relay client to release the lock before the HTTP call. |

### Session 20: HIGH docs (S) — 10 audits ✅ MOSTLY DONE (087/088/089/092/095/097/098/099 done; ⏳ 094 open, 090 documented-not-solved)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-087 | `cmd/probe/main.go:343-408` pollDevice no ctx | S | Use `c.Request.Context()` analog. |
| AUDIT-088 | `time.Sleep` in retry loops without jitter | S | Replace `time.Sleep(5*time.Second)` with `time.Sleep(5*time.Second + jitter)`. |
| AUDIT-089 | Dead code | S | `go vet` + manual removal. Test before deleting. |
| AUDIT-090 | No OpenAPI spec / no API versioning | (See AUDIT-138 + F62) | Already half-done (v0.10.219 v1 aliasing). |
| AUDIT-092 | `.dockerignore` missing many entries | S | Add `.git`, `*.test`, `coverage.out`, etc. |
| AUDIT-094 | `entrypoint.sh:134` runs 3 binaries with bare `wait` | S | Trap signals explicitly. |
| AUDIT-095 | `entrypoint.sh:37` sets `logging_collector = off` | S | Add a comment in entrypoint.sh explaining why. |
| AUDIT-097 | `docker-compose.proxy.yml` is stock | S | Add a Caddy config example. |
| AUDIT-098 | `deploy.sh:98` is destructive | S | Add a `--dry-run` flag. |
| AUDIT-099 | `deploy.sh:64-114` overwrites live config | S | Add a backup step before overwriting. |

### Session 21: HIGH test/CI (S–M) — 7 audits ✅ MOSTLY DONE (100/102/103/104/107/108/109 done; ⏳ 106 open)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-100 | `deploy.sh` systemd units run as `User=root` | **Wontfix** | Already fixed by AUDIT-021 (v0.10.261). |
| AUDIT-102 | `go build` lacks `-trimpath -buildvcs=false` | S | Update Makefile + Dockerfile. |
| AUDIT-103 | `Dockerfile:5-6` installs unused `gcc musl-dev` | S | AUDIT-139's esbuild migration will revisit; for now drop them. |
| AUDIT-104 | No `make install` / native-binary path | S | Add to Makefile. |
| AUDIT-106 | README documents 12 endpoints; code registers 100+ | M | Audit the route table; update README or generate. |
| AUDIT-107 | Documented env vars are 6 lines; `config.env.example` is 70+ | S | Cross-link. |
| AUDIT-108 | No architecture diagram | M | Add a `docs/architecture.md` with a Mermaid diagram. |
| AUDIT-109 | README feature list stale | S | Update. |

### Session 22: HIGH testing — 5 audits (XS–S) ⏳ MOSTLY OPEN (116/121 done; ⏳ 117, 118, 119, 120, 123, 124 — the test-infra block — still open)

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-116 | `*_test.go` in `.gitignore` | **Wontfix** | Already fixed by AUDIT-001 (v0.10.241). |
| AUDIT-117 | Critical-path packages have zero test coverage | **L** | Add at least one test per package in `internal/api/handlers/`, `internal/alerts/`, etc. |
| AUDIT-118 | Tests run on SQLite; production is Postgres | **XL** | Add a CI matrix with Postgres service container. |
| AUDIT-119 | No fuzz tests for untrusted network parsers | M | `testing.F` for SNMP, syslog, IRC parsers. |
| AUDIT-120 | No property-based tests | M | Use `github.com/leanovate/gopter`. |
| AUDIT-121 | No race detector in CI | S | Add `go test -race -count=1` to the `ci.yml` matrix. |
| AUDIT-123 | No integration tests | L | Spin up a real Postgres in CI. |
| AUDIT-124 | No benchmark tests | S | `go test -bench=.` on hot paths (BatchInserter, GetConnectionFlowStats). |

### Session 23: HIGH docs (S) ✅ MOSTLY DONE (111/112/113/115 done; ⏳ 114 open; 117/118 = the test-infra items in Session 22)

- AUDIT-111: No RUNBOOK.md / OPERATIONS.md (S)
- AUDIT-112: No `.well-known/security.txt` route (S)
- AUDIT-113: No "How to add a vendor" doc (S)
- AUDIT-114: README "Build" instructions may not work on fresh Ubuntu (M)
- AUDIT-115: `lessons.md` and `tasks/` should not be public (already done v0.10.275)
- AUDIT-117: covered above
- AUDIT-118: covered above

## MEDIUM-priority bug audits (original list — partially RESOLVED)

> ⚠ **Stale as a "remaining" list.** Since this was written, **125, 130, 134,
> 141, 147 are RESOLVED** (see the Resolved findings table). Genuinely still
> open: **126, 129, 131, 132, 135, 140, 142, 150** (132's "document the
> baseline" half is done via AUDIT-168, but the `['catch']` ES5-workaround
> sweep is not — so it stays open). The full per-finding detail is in Part II.

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-125 | Inline event handler generation in admin-device-detail | S | Replace `onclick="..."` with `addEventListener`. |
| AUDIT-126 | `cmd/api/static/js/admin-device-detail.js:3740` lines, 213KB | L | Already split; this is the migration to the esbuild build pipeline (AUDIT-139). |
| AUDIT-129 | No Sentry / frontend error reporting | L | Add `@sentry/browser` + a server-side mirror. |
| AUDIT-130 | No retry on transient API failures | S | Wrap `apiFetch` with exponential-backoff retry on 5xx. |
| AUDIT-131 | `admin-irc.js` uses ES6+ while codebase is ES5 | S | Babel-rewrite `admin-irc.js`. |
| AUDIT-132 | `:has()` CSS used; needs Safari 15.4+ / Chrome 105+ | XS | Either drop `:has()` or document the browser baseline. |
| AUDIT-134 | Hardcoded version of `package.json` | S | Makefile injects `${VERSION}` at build. |
| AUDIT-135 | No `slog` request-ID middleware | S | Add request-ID propagation. |
| AUDIT-140 | 0 `t.Parallel()` in any test | S | Bulk add. |
| AUDIT-141 | No `t.TempDir()` / `t.Cleanup()` | S | Bulk add. |
| AUDIT-142 | No `testing.Short()` gating | S | Add to slow tests. |
| AUDIT-147 | `ConfigureAutovacuum` table list hard-coded | S | Make it configurable. |
| AUDIT-150 | No OpenTelemetry tracing | L | Bigger project. |

## LOW-priority bug audits (original list — partially RESOLVED)

> ⚠ **Stale as a "remaining" list.** Since this was written, **152, 153, 162,
> 163, 167, 168, 170 are RESOLVED** (see the Resolved findings table).
> Genuinely still open: **160, 161, 164, 165, 166**. Full detail in Part II.

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-152 | No `gofmt` enforcement in CI | XS | Already enforced (CI runs `gofmt -l .`). Verify. |
| AUDIT-153 | `MODEL.go` LastUpAt is dead | XS | Remove the field. |
| AUDIT-160 | No vendored library version pinning | S | Already mostly pinned via go.sum. Add a LICENSE-audit step. |
| AUDIT-161 | HTML has 100+ duplicate sidebar markup instances | M | Refactor to a `<web-component>` or `template` tag. |
| AUDIT-162 | No README test instructions | XS | Add a "Testing" section. |
| AUDIT-163 | No CODEOWNERS | XS | Add `.github/CODEOWNERS`. |
| AUDIT-164 | No FUNDING | XS | Add `FUNDING.yml` if a project org wants GitHub Sponsors. |
| AUDIT-165 | No GitHub release notes automation | M | Set up `release-please`. |
| AUDIT-166 | No community channel | XS | Add a Discord/Slack link in README. |
| AUDIT-167 | No "Known Issues" doc | **Already done** | Fixed by v0.10.282 (KNOWN-ISSUES.md). |
| AUDIT-168 | No browser support baseline documented | XS | Add to README. |
| AUDIT-170 | No example of a custom vendor profile | S | Add `docs/custom-vendor.md` with a copy-paste example. |

## 89 feature recommendations (F01–F89, **out of scope for "complete the audit"**)

These are not bugs. The original audit doc has them at `docs/AUDIT.md:1130`
onwards, sorted into 10 categories (Reports, Alerting, Analytics, etc.). The
top-10-priority list is at `docs/AUDIT.md:1248`. They are sized S through XL
in the audit doc itself.

If a future session wants to do one of these, the workflow is identical to
the bug audits: a single commit with a version bump, CHANGELOG entry, audit
doc update, and a regression test where feasible. The naming convention
would be `v0.X.Y: AUDIT-FNN - short description`.

## How to use this doc as a future session

1. **Pick a session number from above** (e.g. "Session 13: 10 HIGH quick wins").
2. Run the QA baseline before starting:
   ```sh
   go build ./... && go test -count=1 ./... | grep -E "^(ok|FAIL|---)" \
     && gofmt -l . && go vet ./...
   ```
   Expected: all green, ~270 tests across 11 packages.
3. For each audit in the session, follow the conventions above:
   - Make the code change.
   - Add a regression test.
   - Update the CHANGELOG, audit doc resolved table, and audit doc
     progress log.
   - Commit with the `v0.X.Y: AUDIT-NNN - short description` format.
   - Push.
   - Commit the SHA backfill as a follow-up.
4. **One commit per audit** is the right cadence. Larger audits
   (AUDIT-072, AUDIT-006, AUDIT-032) may take 2-3 commits; treat
   the first as "start" and the rest as "continue".
5. **Update this doc at the end of each session.** Append a
   "Session N completion log" section with the commits, the
   version range, and any discoveries for future sessions.

## Quick-start copy-paste for the next session

```sh
# Verify clean baseline
cd E:\Golang\OpenCode\Firewall-Mon
go build ./... && go test -count=1 ./... | grep -E "^(ok|FAIL|---)" \
  && gofmt -l . && go vet ./...
# Expected: all 11 packages pass, no gofmt diffs, no vet warnings.

# Pick the next audit to work on. From the HIGH list:
# - For one-commit wins: sessions 13, 14, 15 are the most accessible.
# - For one-session features: sessions 16, 17, 18.
# - For multi-session refactors: sessions 19, 21 (XL items).

# Read the audit row in docs/AUDIT.md (e.g. `grep -A 5 "### AUDIT-046"`).
# Implement, test, commit per the conventions.

# Pre-commit message template (save to .commit-msg.tmp):
cat > .commit-msg.tmp <<EOF
v0.X.Y: AUDIT-NNN - short description

<1-3 line body explaining what changed and why>

Deferred: <list of related work that's NOT in this commit>.
EOF
git add CHANGELOG.md Dockerfile cmd/api/main.go <other files>
git commit -F .commit-msg.tmp
rm .commit-msg.tmp
git push origin master
# Then the SHA-backfill commit (see convention #5).
```

## Useful commands

- `git log --oneline | head -20` — recent commit history
- Count of resolved audits — **scope to the Resolved-findings table** (since
  Part III now also contains `| AUDIT-` rows in its session-log tables, a bare
  `grep -c "^| AUDIT-"` over-counts):
  `awk '/^## Resolved findings/{f=1} /^## Progress log/{f=0} f && /^\| AUDIT-/{c++} END{print c}' docs/AUDIT.md`
  (currently **124**; the Status dashboard at the top is the authoritative figure)
- `grep -E "^### AUDIT-" docs/AUDIT.md | wc -l` — count of total audit entries
  in the doc (170, plus 89 F-entries = 259)
- `go test -v -count=1 ./... | grep -E "^--- (PASS|FAIL)" | wc -l` — test count
  (currently 254+; should grow)
- `git status --short` — should always be clean between sessions
- `go test -count=1 -race ./... 2>/dev/null` — race tests (run only with
  gcc available; CI handles this; locally on Windows the build fails
  with CGO errors which is expected)

## Session 13 completion log (2026-06-03)

All 10 HIGH frontend quick wins resolved, one commit + one SHA-backfill
commit each, following every convention in this doc. Versions
**v0.10.293 → v0.10.302**. Resolved-audit count in `docs/AUDIT.md` grew
**61 → 71**. QA baseline stayed green throughout (`go build ./...`,
`go test ./...` ~11 packages, `gofmt -l .`, `go vet ./...`); JS edits
were additionally validated with `node --check`.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-046 | 0.10.293 | 64efad9 | probes.html modal rule `.modal:not(.hidden)` → `.modal.active` (no first-paint render) |
| AUDIT-047 | 0.10.294 | db0b62f | admin-irc.js delegated switch gains `case 'logout'` (uses `AdminCommon.doLogout`, no `AC` alias here) |
| AUDIT-048 | 0.10.295 | 25ad013 | connection-detail.html `.section-tab.hidden { display:none !important }` so the JS toggle hides tabs |
| AUDIT-049 | 0.10.296 | 0188631 | irc.html `.tab-btn.active` rule + Servers button normalized; active state now moves |
| AUDIT-050 | 0.10.297 | cacca59 | admin-irc.js IIFE-wrapped (no global leak); ES6→ES5 body conversion left to AUDIT-131 |
| AUDIT-051 | 0.10.298 | 1e94946 | probes.html reject uses a styled `#reject-modal`, not `window.prompt()` |
| AUDIT-052 | 0.10.299 | 8b1686f | public/index.html chart/zoom/gridstack libs load with `defer` |
| AUDIT-053 | 0.10.300 | f8ca027 | admin-device-detail.js 5 inline `onclick` → `data-action` delegation (zero inline handlers left) |
| AUDIT-054 | 0.10.301 | d391d30 | inline `.modal` display rules de-duped across admin/sites/probes (admin-shared.css is canonical) |
| AUDIT-055 | 0.10.302 | 888a7d6 | `AdminCommon.renderMobileChrome()` gives every admin page the mobile sidebar; admin.html inline version removed |

**Discoveries for the next session:**

- **Regression-test gotcha:** the `internal/shell` static checks assert a
  fix-token is *present* and a bug-token is *absent*. An explanatory code
  comment that quotes the old buggy selector (e.g. `.modal:not(.hidden)`)
  will trip the absence check. Word marker comments to avoid the literal
  bug token (hit this on AUDIT-046, 049, 053, 054).
- **AUDIT-046 ↔ AUDIT-054 interaction:** AUDIT-054 removed probes.html's
  inline `.modal.active` (normalized by 046), so the AUDIT-046 test was
  updated to pin the enduring invariant (no `:not(.hidden)`; canonical
  rule lives in admin-shared.css) rather than the now-removed inline rule.
- **Dockerfile no longer needs a version bump** — `ARG VERSION=dev` is fed
  via `--build-arg` at build time (AUDIT-101). Convention #2 in this doc is
  stale on that point: only `cmd/api/main.go:35` changes per commit.
- **`govulncheck` flags GO-2026-5039** (`net/textproto`, fixed in go1.25.11)
  via the SMTP-diagnostic and HTTP-server paths — see the untracked
  `docs/SCAN.md`. Relevant to **AUDIT-018** (stale deps) in a future session.
- **Next up: Session 14 (AUDIT-056–065)** — labels/`for=`, aria, iframe-401,
  `escapeHtml` falsy-0, print CSS, Chart.js teardown, N+1 in probes, etc.

## Session 14 completion log (2026-06-03)

All 10 of AUDIT-056 through 065 resolved, one commit + one SHA-backfill
commit each. Versions **v0.10.303 → v0.10.312**. Resolved-audit count in
`docs/AUDIT.md` grew **71 → 81**. Full suite green throughout (`go build`,
`go test ./...`, `gofmt -l .`, `go vet ./...`); JS edits validated with
`node --check`. This batch was not purely frontend — AUDIT-064 added a real
backend endpoint with a DB-level test.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-057 | 0.10.303 | 9eddf4b | renderSidebar adds `aria-current="page"` to active link + `aria-hidden="true"` to all 16 nav icons |
| AUDIT-058 | 0.10.304 | 4cf18fe | apiFetch 401 redirects `(window.top \|\| window)` so a 401 in the Reports iframe doesn't navigate the iframe |
| AUDIT-059 | 0.10.305 | 419baf4 | escapeHtml nullish guard (`== null`) in admin-common.js + admin-irc.js — no longer blanks numeric 0 |
| AUDIT-060 | 0.10.306 | ffa440b | `@media print` block in admin-shared.css hides sidebar/mobile-header/overlay/toasts/.no-print |
| AUDIT-061 | 0.10.307 | 46e9c54 | device-detail switchTab destroys proc-ssh / iface-err charts on leave, recreates from controls on enter |
| AUDIT-062 | 0.10.308 | fb19621 | irc showAlert toggles `.hidden` + clears a tracked timer (back-to-back alerts no longer cut each other off) |
| AUDIT-063 | 0.10.309 | 4941a8a | public dashboard "Reset Layout" guarded by `confirm()` (native, to avoid bloating the wallboard) |
| AUDIT-065 | 0.10.310 | b1c5483 | connection-detail escapes `conn.status` with AC.escapeHtml before innerHTML |
| AUDIT-064 | 0.10.311 | ecefba0 | **backend**: `GET /admin/api/probes/stats?ids=` (8 grouped queries) replaces the per-probe N+1; admin-probes.js calls it once |
| AUDIT-056 | 0.10.312 | 41c6836 | 88 form `<label>`s get `for="<input id>"` via `scripts/audit056_labels.py` (integrity-tested) |

**Discoveries for the next session:**

- **AUDIT-070 is now incidentally resolved** by the AUDIT-055 (Session 13)
  `renderMobileChrome` — it sets `aria-expanded` on the hamburger button in
  its open/close handler. A future session should verify and close AUDIT-070
  in the doc rather than re-implement it.
- **Pre-existing tab bug found (not yet an audit):** in
  `web/admin/device-detail.html` the Processes/SSH tab uses
  `data-tab="processes-ssh"` but its content div is `id="tab-processors-ssh"`
  (processes vs processors). `switchTab` does `getElementById('tab-' + name)`,
  so that tab's *content* never shows (the button still highlights). Worth a
  one-line fix in a future pass — left untouched here to keep AUDIT-061 scoped.
- **AUDIT-064 pattern for batch endpoints:** one grouped query per table
  (`COUNT(*) ... WHERE x IN (?) GROUP BY x`) instead of looping. The new route
  is a *static* sibling of `/api/probes/:id` and works because gin already
  tolerates `/api/probes/pending` next to `:id`. Handler tests live in
  `internal/api/handlers/` (real SQLite DB via `setupTestHandler`), not
  `internal/shell/`.
- **The label-sweep script (`scripts/audit056_labels.py`)** can be reused/
  extended: it skips wrapping labels and id-less controls. A few public-
  settings inputs (`public_show_vpn`, `public_show_connections`,
  `public_refresh_interval`) have only `name=`, no `id=`, so their labels were
  left unassociated — a tiny follow-up could add ids if desired.

## Session 15 completion log (2026-06-03)

Resolved AUDIT-066–070 (HIGH) + 034 (HIGH) + 035 (MEDIUM), one commit +
one SHA-backfill commit each. Versions **v0.10.313 → v0.10.319**.
Resolved-audit count **81 → 88** — but **AUDIT-066/067 were REVERTED the next
day by v0.10.320** (the color sweep flattened the UI in prod), so the durable
count is **86** and both are OPEN again. See the "Production hotfix interlude".
Full suite green throughout; JS edits validated with `node --check`. The wontfix
trio (081/155/156) needed no action — see the note in the executive summary.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-066 | 0.10.313 | 9b09dc7 | `#484f58`→`#8b949e` (WCAG AA) — **⚠ REVERTED by v0.10.320; AUDIT-066 is OPEN again** |
| AUDIT-067 | 0.10.314 | d04a4e3 | `#6e7681`→`#8b949e` via `--fwmon-text-faint` — **⚠ REVERTED by v0.10.320; AUDIT-067 is OPEN again** |
| AUDIT-068 | 0.10.315 | 818a69e | device-detail `#systemStats`/`#extendedStats` made `overflow-x-auto` (tables were already wrapped) |
| AUDIT-069 | 0.10.316 | 2f0f847 | `role`/`aria-modal`/`aria-labelledby` baked into the 10 modals in admin.html + device-detail.html |
| AUDIT-070 | 0.10.317 | 7033abd | pinned the mobile-menu `aria-expanded` sync (already fixed by AUDIT-055's renderMobileChrome) |
| AUDIT-034 | 0.10.318 | a450ad1 | `idx_flow_src_addr`/`idx_flow_dst_addr` btree indexes (gorm tags) — flow-stats LIKE no longer full-scans |
| AUDIT-035 | 0.10.319 | 6a45065 | `GetLatestVPNStatuses` peer cross-fill: N per-peer scans → one `device_id IN (...)` query |

**Discoveries / decisions for the next session:**

- **Color sweeps had to touch the bundled `tailwind.css`** — it's the
  *last-linked* stylesheet and re-declares custom classes (e.g.
  `.nav-section-title{color:#484f58}`), so editing only the source CSS would
  be shadowed. The `scripts/audit_brighten_color.py` sweep is safe on the
  minified bundle because it's an equal-length hex swap scoped to the `color:`
  property + `text-[…]` utilities (never `*-color:` or quoted chart values).
  **No build step regenerates `tailwind.css`** (esbuild migration is AUDIT-139),
  so source + bundle must be kept in sync by hand.
- **AUDIT-035 deviates from the audit's prescription on purpose:** a single
  `WHERE device_id IN (...)` query fixes the N+1 with identical, cross-dialect,
  testable semantics, whereas the suggested Postgres `ROW_NUMBER()` window
  would be Postgres-only + untestable on the SQLite harness + a subtle
  behavior change (latest-per-tunnel vs scan-all-history). The window remains a
  possible future row-reduction enhancement.
- **`internal/database` tests:** `NewDatabaseForTesting` does NOT migrate every
  model — `DeviceConnection` (and likely others) must be `AutoMigrate`d in the
  test itself. Two helper-style scripts now live under `scripts/`
  (`audit_brighten_color.py`, `audit069_modal_aria.py`, plus
  `audit056_labels.py` from Session 14) — committed for provenance/reuse.
- **Next: Session 16** is the security-adjacent batch (AUDIT-017 hash the probe
  registration key, 020 SSRF DNS-rebinding TOCTOU, 018 stale deps + govulncheck,
  085 probe-auth transaction, 042 relay idempotency key). Note `docs/SCAN.md`
  (untracked govulncheck output) already flags GO-2026-5039 for the 018 work.

## Production hotfix interlude (2026-06-04, v0.10.320–324)

Between Session 15 and the next audit session, production issues pulled work
outside the audit cadence. With the exception of AUDIT-022b these are **not**
audit resolutions — they are logged here so the next agent understands the
v0.10.320–324 version jump and doesn't mistake it for audit progress. (The next
*audit* session is still "Session 16: security-adjacent", below — that name is
unchanged.)

| Version | What shipped | Audit? |
|---|---|---|
| v0.10.320 | **Reverted** the AUDIT-066/067 color sweep — it flattened the text hierarchy and looked worse in prod. **AUDIT-066/067 are reopened.** | reopens 066/067 |
| v0.10.321 | **AUDIT-022b** — CSP `style-src` allows `'unsafe-inline'` again (the v0.10.259 nonce-lock broke the public GridStack dashboard; `script-src` stays strict). | yes (022b) |
| v0.10.322 | `/api/probes/:id/interface-addresses` was 500ing with SQLSTATE 42P10 — AUDIT-030's UPSERT conflict-target unique index `idx_ifaddr_dev_ip` was never created on deployments with legacy duplicate rows (AutoMigrate logged the failure as a warning and continued). Added idempotent `ensureInterfaceAddrUniqueIndex()` (dedup + create). | no (audit-missed) |
| v0.10.323 | Probe-monitored devices flipped offline with **zero** alerts/emails — they're polled by the collector, never reaching `updateDeviceStatus` (the only caller of `CheckDeviceOffline`). The poller now fires offline alert + recovery for probe devices via `MarkStaleProbeDevicesOffline` returning the transition set. | no (audit-missed) |
| v0.10.324 | **Redacted-secret write-back**: GET masks SNMP secrets as `********`; `UpdateDevice` re-saved that mask as the real secret, so any device edit wiped its SNMP community → the collector then polled with `********` and the device went dark (root cause of a multi-hour prod outage). Guarded the write path against `httputil.RedactedMask`. | no (audit-missed) |

**Why this matters for the audit:** v0.10.322–324 were three real production bugs
the original 170-finding audit did **not** catch — the probe-offline alerting gap
and the redacted write-back are exactly the kind of cross-process / data-integrity
issues worth a dedicated future audit pass. The redacted-write-back pattern was
checked against the probe update path and found **safe** there (`UpdateProbe`'s
`allowedFields` allowlist strips the masked `registration_key`/TLS fields before
write), so no further fix is pending. Root-cause detail lives in the project
memory (`project_redacted_secret_writeback`, `project_alert_manager_process_split`,
`project_automigrate_unique_index_gotcha`).

## Session 16 completion log (2026-06-05)

All 5 security-adjacent audits resolved, one commit + one SHA-backfill commit
each. Versions **v0.10.325 → v0.10.329** (server); collector **v1.2.74** for the
AUDIT-042 probe half. Resolved-audit count **86 → 91**. Full suite green
throughout (`go build`, `go test ./...`, `go vet`).

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-085 | 0.10.325 | ccd602f | Probe key rotation wrapped in a `gorm.Transaction` (generate-first); a mid-rotation failure rolls back instead of locking the probe out |
| AUDIT-020 | 0.10.326 | 2c9f0a2 | SSRF DNS-rebinding TOCTOU closed via `httputil.SafeDialContext` (pinned-IP dial) on the webhook client; block list widened (CGNAT 100.64.0.0/10, 0.0.0.0/8, multicast) |
| AUDIT-042 | 0.10.327 + collector v1.2.74 | 9790df6 | Probe batches idempotent: collector sends stable `X-Probe-Batch-ID`, server dedupes via `processed_batches` (recorded only after a 2xx save) |
| AUDIT-018 | 0.10.328 | 56f3efd | Bumped gin 1.10.1 / jwt 5.2.2 / gosnmp 1.40.0 / x-net 0.38.0, conservatively (kept `go 1.23`); `govulncheck` CI job already present |
| AUDIT-017 | 0.10.329 | dfba9c1 | Probe registration keys hashed at rest (sha256, show-once); idempotent live-probe-safe startup migration |

**Discoveries / decisions for the next session:**

- **AUDIT-017's audit text was wrong** ("encrypt with AES-GCM"). The key is
  looked up BY VALUE (`WHERE registration_key = ?`), so it must be **hashed**,
  not encrypted (non-deterministic AES-GCM can't be queried; a reversible store
  still leaks on key+DB compromise). Implemented as hashing with a show-once
  reveal. **Security subtlety:** `HashProbeKey` must ALWAYS hash (never
  idempotent) or the stored hash replays as a valid token — caught by the auth
  regression test. The startup migration is idempotent via the `sha256:` prefix
  guard instead.
- **AUDIT-018 was split.** The named module bumps shipped, pinned conservatively
  to keep `go 1.23` (a blanket `@latest` pulls gin 1.12 + quic-go/mongo-driver
  and forces go 1.25, breaking the `golang:1.23` Docker build). **Deferred:**
  (a) the remaining `govulncheck` findings are Go **stdlib** CVEs fixed only in
  go 1.25.2/1.25.3 — needs a build-toolchain bump (Dockerfile `golang:1.23`→
  `golang:1.25` + the `go` directive), a platform change to schedule on its own;
  (b) the `thoj/go-ircevent`→`girc` migration (full IRC-bot rewrite).
- **AUDIT-020 deferred** pinning the SMTP/SNMP/IRC dials (admin-configured,
  lower rebinding risk; `smtp.SendMail` resolves internally and needs a larger
  refactor). Only the webhook client is pinned.
- **AUDIT-042 deferred** the direct-send endpoints (system-status/interface-stats
  etc. also retry, but are time-series or already UPSERT — lower duplicate harm).
- **Next: Session 17** (HIGH DB performance — AUDIT-041 batched ping writes, 043
  SQLite window-function gating, 044 schema-version migrations, 036 per-process
  DB pool, 038 batched cleanup deletes, 039 batcher-per-daemon, 033 GetDashboardAll
  N+1). Mostly S–M; AUDIT-044 (adopt golang-migrate/goose) is the larger one.

## Session 17 completion log (2026-06-06)

Targeted the DB-performance batch (AUDIT-041/043/044/036/038/039/033). **4
shipped** (v0.10.330 → v0.10.333), resolved count **91 → 95**. Three of the
seven turned out to have premises that no longer hold against the current code —
documented below rather than implemented as written (implementing them would
have been a regression or a no-op).

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-036 | 0.10.330 | 34304df | Per-process DB pool sizing: api/poller/trap mains set 15/10/5 (DB_MAX_OPEN_CONNS overrides); `NewDatabase` reads `cfg.Database.MaxOpenConns`. Was a flat 25 × 3 daemons = 75 conns/host. |
| AUDIT-038 | 0.10.331 | 28d81ab | Retention cleanup deletes in 10k-row batches (`id IN (SELECT id … LIMIT N)`, portable PG+SQLite); PG batches in a txn with `SET LOCAL lock_timeout='5s'` + 100ms sleep. AUDIT-029/031 tests still pass (semantics unchanged). |
| AUDIT-043 | 0.10.332 | b6f8a23 | The `LAG()/WINDOW w AS` chart queries **run fine on the modernc SQLite backend AND Postgres** — premise ("SQLite-unsupported") is outdated, so NO gating was added. Resolved the real gap (untested in CI) with `TestGetVPNChartData_WindowDeltas_AUDIT043` (delta + counter-reset math). |
| AUDIT-033 | 0.10.333 | 8be35f3 | `GetDashboardAll` N+1 (~13 queries × N) → ~7 batched aggregates via the max-timestamp self-join; O(1) in device count, same output shape. |

**Audits NOT implemented (stale/incorrect premise — verified against code):**

- **AUDIT-041 (ping write not batched) — ALREADY DONE.** `pingBatch` exists and
  `SavePingResult` uses it (`if d.pingBatch != nil { d.pingBatch.Add(...) }`).
  Nothing to do; the code evolved since the audit.
- **AUDIT-039 (batchers only used by API) — premise INVERTED.** In reality the
  API uses the *plural* `Save…s` methods (direct `Create`); the *singular*
  batchers are used by `cmd/probe` (ping/syslog) and `cmd/trap-receiver` (trap
  via `ProcessTrap → SaveTrapEvent`). The poller is the only daemon that builds
  batchers it never uses. The audit's prescribed `NewDatabaseForAPI` fix is
  backwards — it would make trap/probe writes synchronous. **Do not implement as
  written.** The only valid kernel is "skip batcher creation in the poller"
  (minor); re-scope before touching.

**Deferred (correctly L-sized, own session needed):**

- **AUDIT-044** — adopt golang-migrate/goose, drop startup AutoMigrate, remove
  the IRC drop-and-recreate heuristic, run migrations only on explicit operator
  command. Changes migration strategy on a live prod DB — a platform change with
  a planning step, not a quick win.

**Discoveries for the next session:**

- **A corrupted Go build cache** surfaced mid-session ("package X is not in std" /
  "cannot find the path" errors), likely a leftover from the AUDIT-018 toolchain
  juggling. `go clean -cache` fixed it (one file may be locked by gopls — harmless).
- **Per-table batched-delete table names:** `batchedDeleteOlderThan` uses gorm's
  model resolution, so it's immune to the `e.name` singular/plural mismatch in the
  cleanup `entries` list (those names are display-only).
- **Next accessible: Session 18** (HIGH critical-feature — AUDIT-040 two-instance
  state, 028 partition interface_stats/system_status, 006 crash-durable batcher,
  004 release flow, 032 ctx propagation) — all L-sized. Or pick remaining S/M
  wins from sessions 19-23. AUDIT-039 (re-scoped) and AUDIT-044 still open here.

## Verification sweep (2026-06-06)

Because the audit was written at v0.10.239 and the code is now v0.10.333 (~94
versions on), all 75 then-open audits were re-verified against the current code
(5 parallel review agents, read-only). Result: **11 were already resolved**
(fixed by later commits/other audits but never reclassified) and several more are
partial/changed. **Do not spend effort on the 11 below — they're done.**

**Reclassified to RESOLVED (now in the AUDIT.md resolved table, marked `(verified)`):**
AUDIT-041 (ping batcher exists), 082 (relay unlocks before HTTP), 089 (superseded
by 154/155/156/157), 100 (deploy.sh User=fwmon, via AUDIT-021), 116 (test gitignore
removed, via AUDIT-001), 121 (`-race` in ci.yml, via AUDIT-004), 125 (admin-device-
detail inline onclick gone, via AUDIT-053), 141 (`t.TempDir` adopted), 152 (gofmt CI
gate), 153 (LastUpAt now wired), 167 (KNOWN-ISSUES.md exists).

**PARTIAL — some of the fix landed, a remainder is still open (re-scope, don't redo):**
- **AUDIT-045** — DB-ping health check landed (AUDIT-091); no separate `/live`+`/ready`, no batcher/notifier checks.
- **AUDIT-073** — the dead `LastUpAt` field is now used; the gorm-vs-DTO struct split is NOT done.
- **AUDIT-117** — 7 packages gained a first test; `auth/syslog/sflow/uptime/relay/ping/models` still at 0.
- **AUDIT-126** — file was split (213KB→~100KB, `admin-device-detail-charts.js`); the esbuild-minify migration (AUDIT-139) is not done.
- **AUDIT-160** — vendored libs are inventoried in `THIRD-PARTY-NOTICES.md` (AUDIT-003) but not pinned in `package.json`.
- **AUDIT-161** — nav links centralized in `AdminCommon.renderSidebar()`; a ~11-line per-page sidebar shell + duplicated `<script>` lists remain.

**CHANGED — premise no longer matches the code:**
- **AUDIT-066** — **NOW FIXED (v0.10.334).** The "border-only" verdict above was wrong — `#484f58` was still a `color:` text rule in `admin-shared.css`/`styles.css`/public dashboard + 5 admin JS files. Fixed surgically: text `color:#484f58` → `#768390` (AA), decorative uses (borders/backgrounds/hover/chart colors) left as `#484f58` to avoid re-triggering the v0.10.320 hierarchy-flattening revert. Its sibling **AUDIT-067** (`#6e7681`) is **now also FIXED (v0.10.335)** — text → `#8b949e` (distinct from 066's `#768390` so the faint tiers stay separate), via the `--fwmon-text-faint` token + literals + `text-[#6e7681]` utilities; the token's decorative border uses pinned to literal `#6e7681`.
- **AUDIT-090** — no OpenAPI/versioning was added; the `/api/v1` path-rewrite was documented + test-pinned under AUDIT-138. Premise (no versioning) technically still holds; treat as "documented, not solved".

**Confirmed GENUINELY OPEN (the real backlog — premises hold, cited file:line in agent reports):**
028, 032, 039 (re-scope per Session-17 note), 040, 044, 071, 072, 073(transport),
076, 077, 078, 079, 080, 081, 084, 087, 088, 092, 094, 095, 097, 098, 099, 102, 103,
104, 106, 107, 108, 109, 111, 112, 113, 114, 118, 119, 120, 123, 124, 129, 130, 131,
132, 134, 135, 140, 142, 147, 150, 162, 163, 164, 165, 166, 168, 170. These are
overwhelmingly large refactors (028/032/044/072/076), structured-logging/metrics/audit
(076/077/078), test-infra (117–124/140/142), and docs/CI/repo-hygiene (the 1xx block).

**Data-integrity note:** the CHANGELOG references `.github/CODEOWNERS` under AUDIT-163,
but the file does **not** exist on disk — AUDIT-163 is correctly still open; the
CHANGELOG mention is a stray/aspirational reference, not a completed change.

## Session 18 completion log (2026-06-06) — Session-20 docs/deploy + probe batch

Picked off the accessible S-sized wins from the "Session 20" (docs/deploy)
bucket plus the two Go items (AUDIT-087/088). **7 shipped**
(v0.10.336 → v0.10.342), resolved count **108 → 115** (per
`grep -c '^| AUDIT-' docs/AUDIT.md`). Full suite green throughout
(`go build`, `go test ./...` — now **14** packages since `cmd/probe` gained
tests, `gofmt -l`, `go vet`).

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-092 | 0.10.336 | a673c9c | `.dockerignore` adds cookies.txt/interfaces.json/IRC-FORMAT.txt/node_modules/tasks/.claude/lessons.md/*.csv (durable guard against a future broad COPY) |
| AUDIT-095 | 0.10.337 | e25299d | entrypoint.sh in-config comment: `logging_collector = off` is fine — PG stderr is redirected to `$PGDATA/postgresql.log` (bind-mounted, survives restarts). Doc-only, no runtime change |
| AUDIT-099 | 0.10.338 | b5c2019 | deploy.sh guards the `config.env.example` copy with `[ ! -f ]` so deploys never clobber the operator's live config |
| AUDIT-098 | 0.10.339 | 2983f73 | deploy.sh `--dry-run` flag + timestamped pre-deploy backup tarball to `${REMOTE_DIR}-backups/` before the destructive rm |
| AUDIT-097 | 0.10.340 | 252d114 | shipped `docs/nginx.conf` (TLS/HSTS/gzip/WS-upgrade/real-ip) + commented `nginx` service in docker-compose.proxy.yml |
| AUDIT-088 | 0.10.341 | 84b13e2 | `crypto/rand` `jitter(d)` on relay sendBatch retries + IRC reconnect (thundering-herd de-sync); idle poll left alone |
| AUDIT-087 | 0.10.342 | e25ee81 | probe `pollDevice(ctx, ...)` + `pollWG` tracking + `cleanup()` cancels & drains in-flight polls (bounded 5s) before stopping the relay client |

**Discoveries / decisions for the next session:**

- **Several "Session 20" premises were half-stale (verify-first paid off again):**
  AUDIT-095's "crash forensics lost" is wrong here — PG logs to `postgresql.log`
  via `pg_ctl -l` on the bind mount, so the fix is documentation, not a risky
  `logging_collector = on` flip on the live prod DB. AUDIT-088's `relay.go:370`
  is an **idle 100 ms poll loop**, not a server retry — jitter there only slows
  shutdown detection, so it was deliberately left unchanged (only the two
  `sendBatch` backoffs + the IRC reconnect got jitter).
- **AUDIT-097 has a deferred app-side half:** `cmd/api/main.go` sets
  `router.SetTrustedProxies(nil)` (the safe default — X-Forwarded-For ignored).
  The nginx example forwards the real client IP, but the app won't honor it
  until trusted-proxy config is wired — that's a deliberate security-loosening
  change for its own commit, documented inline in `docs/nginx.conf`.
- **AUDIT-094 still OPEN (deliberately deferred):** the entrypoint already traps
  signals (the S-scope), but the real value (per-process supervision/restart via
  s6/supervisord, or a `wait -n` fail-fast loop) is an L-sized change to the
  **live production entrypoint** — left for a careful dedicated pass given the
  v0.10.322-324 prod-hotfix history.
- **The comment-quotes-the-bug-token gotcha bit again** (AUDIT-098): an
  explanatory comment that quoted `rm -rf ${REMOTE_DIR}/*` tripped the test's
  backup-before-rm ordering check. Reword marker comments to avoid the literal
  bug token (same lesson as Sessions 13/15).
- **`cmd/probe` is now a tested package** (first tests: `probe_ctx_audit087_test.go`).
  The 5s bounded-drain test runs in real time (~5s) but is `testing.Short()`-gated.
- **Next accessible:** the rest of the "Session 20"/21/23 S-sized docs+repo-hygiene
  wins (AUDIT-092-style): 102 (`-trimpath`), 103 (drop gcc/musl-dev), 104
  (`make install`), 107 (env-var cross-link), 109 (README), 162/163/168/170 (docs),
  092-sibling 094 (re-scope first). The large refactors (028/032/044/072/076) each
  still need their own planning session.

## Session 19 completion log (2026-06-06) — build-hygiene + docs batch

Continued the small-S-wins sweep: build/repo hygiene (Sessions 20/21) + repo
docs (Session 23). **9 shipped** (v0.10.343 → v0.10.351), resolved count
**115 → 124**. Full suite green throughout (14 packages).

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-103 | 0.10.343 | 8c24348 | drop unused `gcc musl-dev` from the Dockerfile builder (CGO_ENABLED=0) |
| AUDIT-102 | 0.10.344 | 3923924 | `-trimpath -buildvcs=false` on all Dockerfile builds + the Makefile `build` target |
| AUDIT-104 | 0.10.345 | 6f0631a | `make install`/`uninstall`/`tarball` + **fixed a latent bug** — `build` now emits canonical `fwmon-*` names (was naming them after dirs) |
| AUDIT-163 | 0.10.346 | aadfbfb | real `.github/CODEOWNERS` (the sweep had found a stray CHANGELOG ref to a non-existent file) |
| AUDIT-162 | 0.10.347 | b1d394b | README **Test** + native-**Install** subsections (`go test ./...`, `make qa/test-race`, `make install/tarball`) |
| AUDIT-109 | 0.10.348 | 3056a84 | refreshed the stale README Features list (reports/sites/policies/maintenance/IRC/sFlow-syslog-ICMP/probes/multi-vendor) |
| AUDIT-107 | 0.10.349 | dc1b01d | README env-var defaults table (values **verified against `internal/config`**, not guessed) + `config.env.example` cross-link |
| AUDIT-168 | 0.10.350 | 4f30ff2 | README **Browser Support** baseline (Chrome 105+/Safari 15.4+/Firefox 121+, the `:has()` floor) |
| AUDIT-170 | 0.10.351 | 3e5d3ad | `docs/custom-vendor.md` — end-to-end "add an SNMP vendor profile" tutorial (code verified against the real API) |

**Discoveries / decisions for the next session:**

- **AUDIT-104 surfaced a real latent bug, not just a doc gap:** the Makefile
  `build` target used `go build -o bin/ ./cmd/...`, which names binaries after
  their directories (`api`/`poller`/`trap-receiver`/`probe`) — mismatching the
  canonical `fwmon-*` names every other surface uses (Dockerfile, deploy.sh,
  systemd `ExecStart`). `make install` would have referenced non-existent
  files. The build target now emits `fwmon-*`. If anything depended on the bare
  names, check it. (`make` isn't installed on the Windows dev box; the install/
  tarball recipes were validated by running their commands directly against a
  staged DESTDIR — they work. CI/Linux has make.)
- **AUDIT-107 verify-first paid off:** several env vars the audit/README would
  document (`DB_MAX_OPEN_CONNS`, `SERVER_*_TIMEOUT`, `REPORT_*`,
  `RETENTION_SYSLOG_CRITICAL_DAYS`) are **not** in `config.env.example` but ARE
  read by `internal/config` — so `config.env.example` is itself incomplete
  (a latent follow-up: sync the example to the code). The README table was
  written against the code, with the two specific defaults (`30s`, per-process
  15/10/5) checked at the source.
- **AUDIT-170/113 overlap:** `docs/custom-vendor.md` is a hands-on tutorial; the
  still-open **AUDIT-113** ("How to add a vendor" doc) is largely satisfied by
  it — a future session can likely close 113 by verifying coverage rather than
  writing a second doc. There's already a `vendor_sonicwall.go`, so the tutorial
  uses a hypothetical "acme" shallow profile and points at `pfsense`/`sonicwall`
  as real worked examples.
- **Still-open easy-ish S/M docs wins:** AUDIT-106 (M — full README endpoint
  sweep, 100+ routes), 108 (M — Mermaid architecture diagram), 164
  (FUNDING.yml — only if the org wants Sponsors), 166 (community channel —
  needs a real channel to link), 113 (verify vs 170). Larger refactors
  (028/032/044/072/076/077/078) still each need a planning session.
- **Comment-quotes-the-bug-token gotcha struck again** (AUDIT-103): a comment
  saying "no `gcc musl-dev`" tripped the absence check — reworded to "no C
  toolchain". Standing lesson for the `internal/shell` static tests.

## Session 20 completion log (2026-06-06) — mid-size code/config cleanups

**6 shipped** (v0.10.352 → v0.10.357), resolved count **124 → 130**. Plus a
`chore:` gofmt fix for pre-existing whitespace drift in `ssrf_test.go`. Full
suite green throughout (14 packages).

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-080 | 0.10.352 | e31d677 | `database.go`: 15 direct `==`/`!=` vs `gorm.ErrRecordNotFound` → `errors.Is` (future-proof against `%w` wrapping) |
| AUDIT-147 | 0.10.353 | f67dfaa | autovacuum default set now includes `interface_stats`/`system_status` (+5 more) + `DB_AUTOVACUUM_TABLES` override; testable `autovacuumTables()` |
| AUDIT-112 | 0.10.354 | d77cad1 | RFC 9116 `security.txt` route (`/.well-known/security.txt` + legacy) with request-time `Expires` |
| AUDIT-130 | 0.10.355 | d7c6fcd | `apiFetch` retries 502/503/504 ×3 with backoff + jitter before erroring |
| AUDIT-134 | 0.10.356 | 2aedf38 | removed stale unused `package.json` version (0.10.157), marked package `private` |
| AUDIT-084 | 0.10.357 | 6eb0c1f | login-attempt prune goroutine exits via a cancellable `bgCtx` on graceful shutdown |

**Discoveries / decisions for the next session:**

- **Verify-first paid off (again):** AUDIT-080's cited `auth.go:75`/`notifier.go:112`
  sites had moved (no sentinel compare there now) — only `database.go` had them.
  AUDIT-147's audit example (`AlertPolicy`/`AlertRule`) was wrong — those are
  low-volume config tables; the real omissions were the high-volume time-series
  tables `interface_stats`/`system_status`. AUDIT-134's version was ~200 releases
  stale and read by nothing.
- **Table-name correctness matters** (AUDIT-147): GORM `TableName()` overrides make
  `VPNStatus`→`vpn_status` and `HAStatus`→`ha_status` (singular). I initially wrote
  the plural and caught it against `internal/models`. The `ALTER` is failure-tolerant
  so a wrong name is only a harmless log line, but verify names against `TableName()`.
- **AUDIT-132 is bigger than the audit implied:** the ES5 `['catch']` bracket-notation
  workaround is **pervasive** (dozens of sites across many JS files), not the single
  `admin-login.js:40` the audit named. Its "document the baseline" half is already done
  (AUDIT-168). Closing it means a full `['catch']`→`.catch` sweep (mechanical, but a
  large diff) — left for its own focused pass.
- **AUDIT-081 is the natural follow-up to 080** — now that not-found checks use
  `errors.Is`, wrapping `return err` raws in `database.go` with `%w` is safe and
  won't break callers.
- **`bgCtx` is now available in `cmd/api/main.go`** for any future background worker
  that needs graceful-shutdown cancellation (AUDIT-084).

## Session 21 completion log (2026-06-06) — operator documentation

**3 shipped** (v0.10.358 → v0.10.360), resolved count **130 → 133**. Full suite
green throughout.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-113 | 0.10.358 | 1ec0457 | confirmed `docs/custom-vendor.md` is the "adding a vendor" guide; test now pins it covers BOTH the SNMP profile + the `internal/configdiff` normalizer |
| AUDIT-111 | 0.10.359 | 7c2d000 | `docs/OPERATIONS.md` runbook (first-24h, failure modes, debug logging, admin reset, JWT rotation, backup/restore, upgrade, scale, DR) |
| AUDIT-108 | 0.10.360 | 40c68df | `docs/architecture.md` Mermaid component flowchart + 3 sequence diagrams + package map |

**Discoveries / decisions for the next session:**

- **AUDIT-111 was grounded in the real code, not generic ops boilerplate:** admin
  reset is `DELETE FROM admins` + restart (because `InitAdmin` only *creates* when
  no admin exists — it never overwrites); there is **no `GIN_MODE=debug` toggle**
  (gin is hardcoded to release mode in `main.go`), so debug logging is via
  `DB_LOG_LEVEL` + `postgresql.log`; JWT rotation is flagged destructive because
  `.jwt-secret` seeds the at-rest AES key (AUDIT-008). Verify these before editing.
- **AUDIT-081 is the next obvious code item but deserves its own pass:** 25 bare
  `return err` sites in `database.go` (mapped to their functions during Session 20
  triage). Wrapping them with `%w` is now *safe* (the 080 `errors.Is` sweep means
  no caller breaks), but doing it *well* means 25 per-site context messages — a
  focused session, not a blanket function-name wrap.
- **Remaining docs are now thin:** 106 (full README endpoint sweep, M), 114
  (fresh-Ubuntu build verification), 164/165/166 (FUNDING / release-please /
  community channel — the last two need a maintainer decision). The bulk of the
  remaining 37 is large refactors (028/032/040/044/072), observability
  (076/077/078/135/150), and test-infra (117–124/140/142) — each its own session.

## Session 22 completion log (2026-06-06) — observability + JS standard

**2 shipped** (v0.10.361 → v0.10.362), resolved count **133 → 135**. Full suite
green. (This session also reconciled the stale by-session HIGH/MEDIUM/LOW
planning lists above — see the ⚠ banners.)

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-135 | 0.10.361 | a2c6d7f | `RequestID` middleware — reuses a safe inbound `X-Request-ID` or mints a 128-bit hex one, echoes the response header, `RequestLogger` logs `req=<id>`; inbound is charset/length-guarded against log forging |
| AUDIT-131 | 0.10.362 | 139c3a9 | `cmd/api/static/js/README.md` declares ES2020 the JS standard (justified by the AUDIT-168 browser baseline); legacy `['catch']` flagged, cleanup tracked as AUDIT-132 |

**Discoveries / decisions for the next session:**

- **AUDIT-131 resolved by decision, not code change:** the evergreen browser
  baseline (AUDIT-168) makes ES2020 fine, so `admin-irc.js`'s ES6 is *correct* —
  the audit's "maybe downgrade to ES5" framing is obsolete. Documenting the
  standard is the resolution; the `['catch']` removal is the separate AUDIT-132.
- **AUDIT-135 shipped with the current logger, not slog:** the audit suggested
  `slog.With("request_id", …)`, but the slog migration is AUDIT-076 (open). The
  request-ID is on the gin context (`RequestIDKey`) ready for slog to pick up
  later; for now `RequestLogger` includes it. **Security caught in design:** an
  inbound `X-Request-ID` must be charset/length-validated or a client can inject
  newlines into the logs — the regex guard + a test cover that.
- **AUDIT-081 STILL deferred (with reason):** the 25 bare `return err` in
  `database.go` need `%w` context, but wrapping changes `err.Error()` strings —
  and some of those errors reach API clients via `models.ErrorResponse`, so a
  blanket wrap could leak internal function names into responses. It needs
  per-site analysis of which errors are user-facing vs internal-only. Genuinely
  its own careful pass, not a mechanical sweep.

## Session 23 completion log (2026-06-06) — test infra + repo hygiene

**2 audits shipped** (v0.10.363 → v0.10.364), resolved count **135 → 137**, plus
a `.gitattributes` line-ending hygiene fix. Full suite green.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-119 | 0.10.363 | 12c896b | Go native fuzz tests for `syslog.ParseRFC5424` + `sflow.ParseSFlowDatagram`; active fuzzing 3.3M (sflow) + 267k (syslog) execs, **zero crashes** |
| AUDIT-124 | 0.10.364 | 2f58589 | benchmarks for the syslog + sFlow parser hot paths (`ReportAllocs`/`SetBytes`) |

**Discoveries / decisions for the next session:**

- **The wire parsers are robust:** millions of fuzz executions found no panic in
  either the text (syslog) or binary (sFlow) parser. The fuzz seed corpus now
  runs under plain `go test` as a permanent no-panic regression guard — these
  are also the **first tests** in `internal/syslog` and `internal/sflow` (toward
  AUDIT-117).
- **Line-ending root cause fixed:** `CHANGELOG.md` had drifted to CRLF in the
  git index, so every LF edit produced a whole-file flip in the diff. Added
  `.gitattributes` (`text=auto eol=lf`) and renormalized — only CHANGELOG was
  affected; the rest of the tree was already LF. Future diffs stay clean.
- **Process note:** test files slipped through unformatted twice this stretch
  (135 test, 119 fuzz test) because the per-commit `gofmt -l` check listed only
  the non-test files. Run `gofmt -l` over **all** staged files (incl. `*_test.go`)
  before committing.
- **Parser quirk worth knowing:** `syslog.ParseRFC5424` treats PRI and VERSION as
  **separate** space-delimited tokens (`<165> 1 <ts> …`), not the glued RFC 5424
  `<165>1`. Any future syslog fixture/test must use the space-separated form to
  hit the happy path.
- **AUDIT-081 still the top deferred code item** (per-site `%w` wrapping with
  user-facing-vs-internal analysis). Remaining work is now dominated by the big
  refactors (028/032/040/044/072), observability (076/077/078/150), and the
  heavier test-infra (117/118/120/122/123).

## Session 24 completion log (2026-06-06) — code-quality cleanups + release automation

**3 audits shipped** (v0.10.365 → v0.10.367), resolved count **137 → 140**.
Full suite green; every modified JS file passes `node --check`.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-132 | 0.10.365 | a372758 | Swept the ES5/IE11 reserved-word bracket member-access workaround (`['catch']`×117, `['finally']`×2, `searchParams['delete']`×2 = 121 sites / 14 files) to dot notation. README baseline (ES2020) was already documented in Session 22, so this was the deferred code half of AUDIT-131. |
| AUDIT-081 | 0.10.366 | 9666eb6 | Wrapped all 25 remaining bare `return err` in `database.go` with `fmt.Errorf("op: %w", err)`. `%w` keeps the AUDIT-080 `errors.Is(gorm.ErrRecordNotFound)` checks working. |
| AUDIT-165 | 0.10.367 | 7b62ac0 | Tag-triggered, CHANGELOG-driven `release.yml` that publishes a GitHub Release from the matching changelog section (Unreleased fallback). |

**Discoveries / decisions for the next session:**

- **The `['catch']` sweep had a doc trap:** `cmd/api/static/js/README.md`
  *intentionally* quotes the literal `['catch']` syntax (and `TestJSStandardDocumented_AUDIT131`
  asserts that quote stays present). A naive directory-wide sed rewrote the doc
  too — the AUDIT-132 guard therefore scopes to `*.js` and the README keeps a
  literal `['catch']` reference (reframed from "to be cleaned up" → "cleaned up
  in v0.10.365"). **Lesson:** when sweeping a token, exclude docs that document
  the token.
- **Not every `return err` is in a guaranteed-error path.** Two sites
  (`CreateDevice`, `MarkBatchProcessed`) were *trailing* returns where `err`
  could be `nil` on success — blindly wrapping with `fmt.Errorf("…: %w", nil)`
  would have manufactured a non-nil error and broken every happy path. Those
  were converted to guarded `if err != nil { return fmt.Errorf(...) }; return nil`.
  A future bulk error-wrapping pass (e.g. AUDIT-071's handler sweep) must make
  the same distinction.
- **Release automation is CHANGELOG-driven, not PR-driven.** `release-drafter`
  (the audit's first suggestion) keys off labelled PRs; this repo is
  direct-to-master, so it would produce empty notes. `release.yml` reads the
  CHANGELOG instead. It's **dormant until the first `vX.Y.Z` tag** — the
  one-time tag backfill/cutover is still AUDIT-004's open half, as is the
  `.goreleaser.yml` artifact build.
- **AUDIT-071 is the natural next code cleanup** — the handler-side
  `c.JSON(500, models.ErrorResponse(...))` boilerplate (~hundreds of sites)
  that, like the old `database.go` returns, *drops the underlying `err`*. It
  wants an `httputil.InternalError(c, "op", err)` helper that logs `err`, then a
  careful sweep (the err-variable name differs per site, so it's not a blind
  find/replace). Bigger than a one-session quick win.

## Session 25 completion log (2026-06-06) — handler error observability

**1 audit shipped** (v0.10.368), resolved count **140 → 141**. A single
focused audit, but a 133-site sweep across the whole handler layer. Full suite
green.

| Audit | Version | Code commit | What shipped |
|---|---|---|---|
| AUDIT-071 | 0.10.368 | (pending) | `httputil.InternalError(c, msg, err)` logging 500 helper + swept all 133 `c.JSON(http.StatusInternalServerError, models.ErrorResponse(…))` sites in `internal/api/handlers` (13 files). |

**Discoveries / decisions for the next session:**

- **The sweep uncovered an info-disclosure, not just missing logs.** 4 of the
  "boilerplate" sites (IRC connect/send, two report-build) were concatenating
  `err.Error()` into the **client** response body (`"Failed to connect: " +
  err.Error()`). They didn't match the plain-string regex, which is how they
  surfaced. Routing them through the helper both adds the missing server log and
  **stops** leaking raw error text (SQL, dial errors) to the browser. These are
  admin-only endpoints so the risk was low, but it's the right hardening and is
  now consistent with the rest of the 500s.
- **The compiler was the safety net for err-scope.** A blind regex `→
  httputil.InternalError(c, msg, err)` produced 6 `undefined: err` build
  failures — exactly the sites where no error was in scope. Resolved by reading
  each: 4 were nil-checks / failed type-assertions (`pass nil`), and 2 had the
  error under a different name (`result.Error`, `txErr`). **Lesson for the next
  bulk sweep (e.g. a 4xx pass, or AUDIT-073):** don't trust the variable name —
  let `go build` enumerate the exceptions, then fix each by hand.
- **Scope was deliberately the 500 path only.** `c.JSON(400/404/409, …)`
  client-error responses were left untouched — a 4xx is the caller's mistake,
  not a server fault worth a log line. If a future audit wants 4xx telemetry,
  that's a separate helper (`httputil.ClientError`?) and a separate decision.
- **This is the logging *chokepoint* the observability work needs.** AUDIT-076
  (structured logging / `slog`) can now convert one helper's `log.Printf` into a
  structured record and every handler 500 upgrades at once, instead of editing
  133 call sites again. Same for AUDIT-077 (a `metrics.Inc("http_5xx")` would
  live here). Worth doing 076 before any more logging-shaped audits.
- **Next smaller-cleanup candidate: AUDIT-073** (move the HTTP transport types
  `APIResponse`/`SuccessResponse`/`ErrorResponse` out of `internal/models` into
  an `internal/api/response` package, and remove the dead `LastUpAt` field). Be
  warned: those types are referenced in ~120 files, so it's a large import-churn
  commit (a `gofmt`-able mechanical move, but big). Might pair better with the
  AUDIT-076 logging work than with a quick-win batch.

## Closing

The 61 resolutions made in v0.10.241 → v0.10.292 (May–June 2026) cover
**all 11 CRITICAL findings** and a **majority of the highest-leverage
HIGH findings**. The remaining 109 audits are mostly small quick wins
(60-90 minutes each) and a few medium features that need real design
thought. The 9 large refactors (AUDIT-032, 072, 076, 118, 006, 028,
040, 044, 004) need their own dedicated sessions with planning docs.

**Recommended pacing for the next agent:**

- Sessions 13-15: 30 small HIGH fixes, ~3-4 focused sessions
- Sessions 16-17: security/DB performance work, ~2 sessions
- Sessions 18-21: large refactors + frontend polish, ~5-6 sessions
- Sessions 22-23: docs and testing, ~1 session

That's roughly 10-13 focused sessions to clear the bug-audit queue. After
that, the feature recommendations (F01-F89) are a separate project that
will drive v0.11.0+.
