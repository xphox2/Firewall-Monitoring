# Changelog
## [0.10.254] - 2026-06-02

### Added — AUDIT-002 (LICENSE doc reference) + AUDIT-003 + AUDIT-011: public-release governance documents

Six new top-level docs covering the open-source housekeeping the audit called out as deployment blockers. Pure documentation; no binary rebuild required.

- **`THIRD-PARTY-NOTICES.md`** (AUDIT-003) — inventories every vendored browser-side asset (Chart.js 4.4.7, chartjs-plugin-zoom 2.0.1, uPlot 1.6.31, Cytoscape.js 3.30.4, cytoscape-fcose 2.2.0, cose-base 2.2.0, layout-base 3.1.0, Gridstack.js 10.3.1, Tailwind CSS, Inter font, JetBrains Mono font) and every direct Go dependency from `go.mod` with version, license (MIT / BSD-2 / BSD-3 / Apache-2.0 / OFL-1.1), copyright line, source URL, and (where vendored) the file path. Includes the full text of every license that applies — required by the attribution clauses of MIT / BSD / OFL.
- **`SECURITY.md`** (AUDIT-011 part 1) — GitHub-recognized vulnerability disclosure policy with the standard "don't open public issues" preamble, response-time SLOs (5 business days to ack, 10 for assessment, 30 for HIGH/CRITICAL fix), 90-day default disclosure, supported-versions table, scope/out-of-scope sections, operator hardening guidance pointing at the audit doc, and a hall-of-fame stub.
- **`CONTRIBUTING.md`** (AUDIT-011 part 2) — dev environment requirements (Go 1.24, Postgres 14+ optional, Node 20 for Tailwind only), in-scope vs out-of-scope work, branch + PR workflow, the **mandatory QA gate** (`go build` / `go test -count=1` / `gofmt -l` / `go vet` — and optional `-race`), CHANGELOG / version-bump / AUDIT.md update steps, commit message style with a working example from v0.10.246, code-style rules (no new global state, no new browser libraries without `THIRD-PARTY-NOTICES.md` update), and a dedicated security-sensitive-contributions section pointing back at `SECURITY.md`.
- **`CODE_OF_CONDUCT.md`** (AUDIT-011 part 3) — Contributor Covenant v2.1 verbatim, with the contact-method placeholder pointed at `SECURITY.md`.
- **`README.md`** — replaced the bare `MIT` license line with proper links to `LICENSE`, `THIRD-PARTY-NOTICES.md`, plus a new "Contributing & community" section linking the four new docs and the audit doc.

This unblocks the AUDIT-011 deployment-blocker (no security disclosure path, no contributor on-ramp, no Code of Conduct) and the AUDIT-003 deployment-blocker (8 vendored libraries + 2 fonts carry attribution clauses that were not honoured).

Still open from the AUDIT-011 fix list (deferred — different scope):

- `.well-known/security.txt` route (AUDIT-112).
- `.github/ISSUE_TEMPLATE/*.yml` and `PULL_REQUEST_TEMPLATE.md` (AUDIT-163).
- `.github/CODEOWNERS` (AUDIT-163).
- `docs/OPERATIONS.md` runbook (AUDIT-111).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Docs-only change → no rebuild required. Server-repo only.

## [0.10.253] - 2026-06-02

### Fixed — AUDIT-005: trap-receiver and poller now have a real DB + matching ENC key

Two related fixes for the multi-process secret-derivation problem.

**AUDIT-005**: `cmd/trap-receiver/main.go:29` passed `nil` to `alerts.NewAlertManager`. `am.saveAlert` (`alerts.go:532-539`) is a no-op when `db==nil`, so every trap that arrived was logged to stdout and immediately dropped on the floor. The trap-batcher's buffer in the API process was never written to either (the trap-receiver has its own process, not shared memory).

Fix: trap-receiver now calls `database.NewDatabase(cfg)`, hands the result to the AlertManager, and `defer db.Close()`s on shutdown. `alertManager.RefreshThresholds(db.Gorm())` is called the same way `cmd/api` and `cmd/poller` do so threshold lookups don't hit the DB on every alert.

**AUDIT-008 (multi-process completion)**: `cmd/trap-receiver` and `cmd/poller` opened DBs without first loading the persisted JWT secret. Each derived a DIFFERENT AES key — same DB, three keys. SMTP password / SNMP creds / IRC secrets saved through the admin UI were decryptable from `cmd/api` but garbage from the other two processes. The v0.10.252 fix only ran in `cmd/api`.

Fix: hoisted the `secrets.LoadOrGenerate(cfg.Server.JWTSecretKey, secretsDir, ".jwt-secret")` call to the top of `main()` in both `cmd/trap-receiver` and `cmd/poller`. All three processes now derive identical ENC keys from `/data/.jwt-secret`.

**Concurrent first-start race fix**: the three processes start in parallel from `entrypoint.sh:106-115`. On a fresh `/data` volume all three see the secret file as missing and would race to write three different secrets, then race to read whichever won the filesystem write — leaving two processes with mismatched in-memory copies. `secrets.LoadOrGenerate` now uses `os.OpenFile(..., O_CREATE|O_EXCL|O_WRONLY, 0o600)` so exactly one process wins; the others receive `os.ErrExist`, re-read the file, and use the winner's value. Best-effort empty-file cleanup (`_ = os.Remove(path)`) before the create attempt closes the "old empty file blocks new generate" footgun the AUDIT-008 test caught.

Regression tests:

- `internal/secrets/secrets_test.go::TestLoadOrGenerate_ConcurrentRaceSafe` — 16 goroutines all calling `LoadOrGenerate("", tmpdir, ".jwt-secret")`. Asserts exactly one returns `Generated`, the other 15 return `FromFile`, and all 16 values are identical. Fails loud with "AUDIT-008 race regression" if any pair diverges.
- `internal/secrets/secrets_test.go::TestLoadOrGenerate_EmptyFileTreatedAsMissing` — existing-but-empty file regenerates cleanly (the empty-file cleanup path).

QA: `go build ./...`, `go test -count=1 ./...` (8 pkgs, 96 tests), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Operator action: same as v0.10.252 (re-enter encrypted creds after upgrade, since the new shared key replaces three previously-divergent random keys). Server-repo only.

## [0.10.252] - 2026-06-02

### Fixed — AUDIT-008: JWT secret and admin password now persist across restarts

`cmd/api/main.go` previously regenerated both the JWT signing secret and the auto-generated admin password on every restart if their env vars were unset. The downstream damage:

- **JWT secret**: a new in-memory secret on each start invalidates every existing login JWT. Worse, the AES-256 key for `{enc}<base64>` stored credentials (SNMP, IRC, SMTP) is derived from the same secret via SHA-256 (`internal/database/database.go:82` `deriveKey(cfg.Server.JWTSecretKey)`), so a regenerated key made **every encrypted credential in the DB permanently unreadable**.
- **Admin password**: `getDefaultPassword()` cached a fresh random per `config.Load()` call, but `db.InitAdmin` only sets the bcrypt hash on the FIRST run. Result: on restart the operator saw a brand-new "AUTO-GENERATED ADMIN PASSWORD" printed in the logs that did NOT match the existing DB hash — and got locked out with no recovery path.

The previous `os.WriteFile("/data/.admin-password", ...)` attempt at persistence was best-effort — if the write failed, the code silently continued with an in-memory-only password the operator could never recover.

**New package** `internal/secrets` (10 unit tests):

- `LoadOrGenerate(envValue, baseDir, filename) (value, source, err)` — env > file > generate+persist, with fatal-on-IO-error semantics.
- `PersistGeneratedPassword(pw, baseDir, filename) (written, err)` — write-once helper for the admin-password flow (existing files are NEVER overwritten so a manually-edited file is honoured).
- `LoadPassword(baseDir, filename) (pw, ok, err)` — read-only counterpart for the load-side.

**`cmd/api/main.go` wiring**:

- `SECRETS_DIR` env (default `/data`) chooses where secrets live. Override for non-Docker installs.
- JWT secret: `LoadOrGenerate("", "/data", ".jwt-secret")` runs at startup. First run generates + persists chmod 0600. Subsequent runs reload the same value.
- Admin password: if env empty, attempt to load `/data/.admin-password`. If present, override the config-generated default. If absent (true first run), persist the just-generated default with `PersistGeneratedPassword`. Any I/O failure is `log.Fatal` — no silent fallback.
- Stopped logging the masked password (`pw[:3] + "***" + pw[len(pw)-3:]`) — that was a separate finding (AUDIT-137: 6 chars of the auto-generated password leaked into container logs narrowed brute-force space). Now the log directs operators to the chmod-0600 file instead.

`config.env.example` updated to explain both env vars + `SECRETS_DIR`.

QA: `go build ./...`, `go test -count=1 ./...` (8 packages, 95 tests), `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`.

**Operator action required** on upgrade:

- If `JWT_SECRET_KEY` was previously unset and the volume `/data` survives the upgrade: existing `{enc}` ciphertext was already broken by the regenerate-on-restart bug — the new `.jwt-secret` file generated on first run after upgrade will be a fresh key, so any existing `{enc}` values stored under previous random keys remain unreadable. Re-enter SMTP / SNMP credentials in the admin UI after upgrade.
- If `JWT_SECRET_KEY` IS set in env: nothing changes — env value still wins.
- For brand-new installs: `/data/.jwt-secret` and `/data/.admin-password` will be created chmod 0600 on first start. Treat them like SSH host keys: back them up, don't share them.

Server-repo only. Also collaterally closes AUDIT-137 (no longer logs masked password).

## [0.10.251] - 2026-06-02

### Fixed — AUDIT-083: per-IP rate limiter is now capped + has a Stop() hook

`internal/api/middleware/middleware.go`'s `ipRateLimiter` had two scaling defects:

1. **Map had no size cap.** An attacker spraying unique source IPs (trivial with X-Forwarded-For when behind an untrusted proxy, or an IPv6 /64 walk) could grow `limiters` to millions of entries and OOM the process. The 5-minute stale-prune loop took 5 minutes to react, far longer than any flood.
2. **Cleanup goroutine had no shutdown hook.** Started with `go rl.cleanup()` at construction, never stopped. Process exit terminated it (via OS), but tests that constructed-and-discarded limiters leaked one goroutine per test — and any future code that wants to recycle a limiter at runtime had no way to release the resource.

Both fixed:

- New `maxRateLimiterEntries = 50000` cap (≈ 7.5 MiB headroom). `getLimiter` evicts the LRU entry when at cap, before inserting the new one. The LRU is a `container/list` doubly-linked list — `MoveToFront` on access, `Back()` is the eviction target. Amortized O(1).
- New `Stop()` method closes `rl.quit`; the cleanup goroutine `select`s on `ticker.C` or `quit` and returns cleanly.
- Reworked stale-prune loop to walk the LRU from the back (oldest first) and stop on the first not-expired entry, instead of scanning the whole map — O(stale-count) instead of O(map-size).

Wire-through note: `RateLimiter`, `PublicRateLimiter`, and `LoginRateLimiter` still return raw `gin.HandlerFunc`s and do not expose Stop. The cap addresses the OOM half of the audit; surfacing Stop on the public API requires returning a struct that bundles handler + stop, which is a larger refactor not in scope here. Tracked as a follow-up.

Regression tests (`internal/api/middleware/ratelimit_test.go`, new):

- `TestIPRateLimiter_GetLimiter_NewIPCreatesLimiter` — basic happy path.
- `TestIPRateLimiter_GetLimiter_SameIPReusesLimiter` — repeated calls share state (rate limits accumulate).
- `TestIPRateLimiter_LRUEviction_AUDIT083` — fills cap, touches one IP to make it MRU, asserts the LRU (not the touched one) is evicted on overflow.
- `TestIPRateLimiter_LRUEviction_ManyOverflow` — 3 × cap inserts; map size never exceeds cap; last `cap` IPs survive.
- `TestIPRateLimiter_Cleanup_RemovesStale` — back-dates 3 entries, drives a cleanup pass inline, asserts the fresh entry survives and the 3 stale ones are gone.
- `TestIPRateLimiter_Stop_TerminatesGoroutine` — second `Stop()` panics on close-of-closed-channel (proves the first Stop actually closed it).
- `TestIPRateLimiter_Concurrent` — 100 goroutines × 100 calls under cap=50; final size ≤ cap; lru length == map length (no divergence under race).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.250] - 2026-06-02

### Fixed — AUDIT-012: trap receiver is no longer an open relay

`internal/snmp/trap.go:46` had this short-circuit:
```go
if t.config.SNMP.TrapCommunity != "" && packet.Community != t.config.SNMP.TrapCommunity {
    return
}
```
When `SNMP_TRAP_COMMUNITY` was empty (or unset), the whole check was skipped and **every** UDP packet on port 162 was accepted, parsed, and stored as a trap event with `SourceIP = packet.SourceIP`. An attacker spoofing source IPs could inject thousands of bogus alerts, mask real outages, or just OOM the trap-event table.

Three changes:

1. **Fail-closed config**: `TrapReceiver.Start` now refuses to listen when `SNMP_TRAP_COMMUNITY` is empty: `"SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string"`. Operators who want the listener disabled should not run the `trap-receiver` daemon at all.
2. **Constant-time community compare**: replaced `packet.Community != expected` with `subtle.ConstantTimeCompare`. Closes a byte-by-byte timing oracle that let a network attacker recover the prefix length of any guessed community.
3. **Per-source-IP token-bucket rate limit**: 10 traps/sec sustained, burst 50, applied BEFORE the community check so a flooding attacker can't burn CPU on the crypto / parser. The IP map is capped at 10,000 entries to prevent unbounded growth under unique-source-IP spraying — when the cap is hit, *new* IPs are rejected (logged as drops); existing buckets continue to refill and serve.

The defaults (10/s, burst 50, cap 10k) are tight enough that a spoofed flood needs ~6,000 unique source IPs/min to sustain even 1,000 trap rows/sec; loose enough that a chassis link-flap storm from a real device stays within budget.

`config.env.example:36` now documents the requirement with an AUDIT-012 reference.

Regression tests (`internal/snmp/trap_test.go`, new — first test file for the SNMP package, closes part of AUDIT-117):

- `TestTrapReceiver_Start_RequiresCommunity` — empty community → Start returns error mentioning `SNMP_TRAP_COMMUNITY`.
- `TestTrapReceiver_Allow_BurstThenRefill` — first `burst` calls succeed; the next fails; after a refill window, one more succeeds.
- `TestTrapReceiver_Allow_PerIPIsolated` — draining IP A's bucket does not affect IP B's bucket (spoofing-defense requirement).
- `TestTrapReceiver_Allow_MapCapped` — fills the map to `maxRateLimitedIPs`, asserts the (cap+1)th NEW IP is rejected while EXISTING tracked IPs still serve.
- `TestTrapReceiver_Allow_ConcurrencySafe` — 50 goroutines × 5 calls under a burst of 10 → exactly 10 succeed (locking is neither too loose nor too tight). Race-detector compatible; runs under `-race` in CI once AUDIT-121 / AUDIT-004 land.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Operator action required: confirm `SNMP_TRAP_COMMUNITY` is set if running the trap-receiver daemon. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.249] - 2026-06-02

### Fixed — AUDIT-013: `TestIRCServer` now SSRF-gated (and validates port)

`POST /admin/api/irc/test` accepted an arbitrary `server_host` from the request body and dialed it via `irc.NewTestBot(...).Connect()` with **no** SSRF allow-list — even though sibling `TestProbeConnection` (`handlers_probes.go:351`) and `TestEmail` (`handlers_settings.go:667`) have called `isValidExternalIP` since v0.10.140. An admin (or anyone who phished an admin session cookie) could turn the endpoint into an internal port-scanner against the monitor's LAN — loopback, RFC 1918, link-local, the AWS metadata endpoint at `169.254.169.254`, etc.

Changes (`internal/api/handlers/handlers_irc.go:437`):

- Reject ports `< 1` or `> 65535` with 400 (mirrors the validation in `TestProbeConnection`).
- Run the host through `isValidExternalIP` and 400 with "Invalid or disallowed server host" if it resolves to a blocked range.

Regression tests (`internal/api/handlers/handlers_irc_audit013_test.go`, new):

- `TestTestIRCServer_RejectsSSRFTargets_AUDIT013` — 13 sub-cases covering IPv4/IPv6 loopback, unspecified, link-local (incl. `169.254.169.254`), RFC 1918 / RFC 4193, `localhost` name, and an unresolvable `.invalid` host. All must return 400 and mention "disallowed" or "invalid" in the body.
- `TestTestIRCServer_RejectsInvalidPort` — 2 sub-cases (negative, > 65535) must return 400.
- `TestTestIRCServer_RejectsMissingHost` — `binding:"required"` catches the empty case.

Side-effect on the package: this is the first test file for the IRC handler family (previously 0% coverage on `handlers_irc.go` — closes part of AUDIT-117).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.248] - 2026-06-02

### Fixed — AUDIT-086: HTTP listener errors no longer skip graceful shutdown

The listener goroutine in `cmd/api/main.go:226` called `log.Fatal` if `ListenAndServe[TLS]` returned anything other than `http.ErrServerClosed`. `log.Fatal` calls `os.Exit(1)` immediately, which **skips every `defer`** registered earlier in `main`: `defer ircManager.Stop()`, `defer snmpClient.Close()`, and the deferred `cancel` for the JWT-prune ticker. Result: bind-conflict / cert-load failure → IRC bot left connected with a half-open SASL session, SNMP socket leaked, batchers not flushed.

The same pattern existed at the post-signal `server.Shutdown` call (`cmd/api/main.go:248`). A 10-second shutdown timeout, plus `log.Fatal` on overrun, also skipped the defers.

Both paths now use the same graceful-shutdown sequence:

- Listener goroutine writes the error onto a buffered `errCh` (no `log.Fatal`).
- Main goroutine `select`s on either the signal channel or `errCh`, logs which one fired, then runs `server.Shutdown`.
- `server.Shutdown` failure logs the error and returns normally so the deferred `ircManager.Stop` / `snmpClient.Close` / `cancel` all run before the process exits.

No automated test (would require integration-level harness: spawn a real `http.Server` and trigger a bind-conflict mid-flight); the change is small and obvious from inspection. Manually verified: rebuilt, started, sent SIGTERM — saw "Received signal terminated, shutting down server..." → "Server exited" with all defers logged.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.247] - 2026-06-02

### Fixed — AUDIT-015: CORS `*` rejected at startup when Allow-Credentials=true

The CORS middleware always sends `Access-Control-Allow-Credentials: true` (cookie-based admin session). Combining that with a wildcard `Access-Control-Allow-Origin: *` is forbidden by the CORS spec (browsers drop the response) AND is dangerous because the old code reflected the requesting origin verbatim when the configured list contained `*` — letting any third-party site issue authenticated cross-origin requests against the admin API once an operator was logged in.

Changes:

- Extracted origin parsing into `parseCORSAllowedOrigins(raw string) (map[string]bool, error)` for testability.
- The helper returns an error if any entry in `CORS_ALLOWED_ORIGINS` is `*` (after `strings.TrimSpace`).
- `CORS()` calls `log.Fatalf` on that error so the server refuses to start with an unsafe config.
- Removed the `origins["*"]` short-circuit from the per-request path (no longer reachable, but defense-in-depth).

Regression tests (`internal/api/middleware/cors_test.go`, new):

- `TestParseCORSAllowedOrigins_WildcardRejected` — 5 sub-cases (bare `*`, `*` mixed with a real origin, `*` with leading/surrounding whitespace, `*` in the middle of a list) all return an error mentioning both `*` and `credentials`.
- `TestParseCORSAllowedOrigins_ValidInputs` — 9 sub-cases for happy paths and edge cases (empty / whitespace-only / one origin / two origins / surrounding whitespace trimmed / empty entries skipped / trailing comma / port suffix / http vs https as distinct origins) returning the expected map.

`internal/api/middleware` now has its first test file (was 0% coverage — closes part of AUDIT-117).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Operator action required if they had `CORS_ALLOWED_ORIGINS=*`: replace with an explicit comma-separated allow-list. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.246] - 2026-06-02

### Fixed — AUDIT-016: probe registration key compared in constant time

`validateProbe` in `handlers_probes.go:606` compared the presented Bearer token to the stored registration key with a plain Go `!=`. Go string comparison short-circuits at the first mismatching byte, so a network attacker on the LAN can in principle reduce the key search space by measuring how long the server takes to reject a wrong token. We replaced the comparison with `subtle.ConstantTimeCompare`, which (a) returns `0` if the lengths differ and (b) compares all bytes of equal-length inputs without short-circuiting.

Changes:

- `internal/api/handlers/handlers_probes.go`: added `crypto/subtle` import; `validateProbe`'s post-PK-lookup token check now uses `subtle.ConstantTimeCompare([]byte(token), []byte(probe.RegistrationKey)) != 1` with an explanatory comment referencing AUDIT-016.

Scope note: `authenticateProbeByBearer` (the only other key-check site, used by `ProbeHeartbeat`) looks the probe up directly by `WHERE registration_key = ?` against an indexed column. The DB engine's hash-bucket compare for that lookup is constant-ish, but the underlying lookup is still a timing channel for "token exists" vs "token does not exist". A complete fix requires restructuring the heartbeat protocol to carry an explicit probe ID (so we can fetch by PK and then constant-time-compare). That is tracked under AUDIT-017 (probe key stored in plaintext) and will be addressed when the at-rest encryption / hashed-token refactor lands. The validateProbe path patched here is the higher-leverage one — it is invoked by **18 ingestion handlers** vs. heartbeat's single call site.

Regression tests (`handlers_probes_audit016_test.go`, new):

- `TestValidateProbe_ConstantTimeKeyCompare_AUDIT016` — 9 sub-cases asserting the behavioral contract: correct key accepted; same-length flipped-byte (last/first/middle) all rejected; shorter-by-one / longer-by-one rejected; uppercase-cased rejected; empty rejected; whitespace-padded rejected. Timing assertion is not feasible in CI but every variant a naive `==` could short-circuit on is covered.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.245] - 2026-06-02

### Fixed — AUDIT-027: `decryptField` no longer returns ciphertext on decryption failure

This is the **v0.10.226 bug class** patched at its other doorway. v0.10.226 stopped `UpdateSettings` from gating decrypt on a never-persisted `IsSecret` flag, so the *normal* read path stopped sending `"{enc}<base64>"` to remote servers as a credential. But the failure paths inside `decryptField` itself still leaked the ciphertext back to the caller: if the JWT key changed, the DB was tampered with, or the ciphertext was truncated, the function dutifully returned the raw `"{enc}<base64>"` string and any caller (SMTP, IRC, SNMP) then transmitted it verbatim to the remote server. Postfix logged it; Dovecot logged "Password mismatch"; the operator chased their tail for days.

**Behavior change** (`internal/database/crypto.go:57`):

| Condition | Before | After |
|-----------|--------|-------|
| No `{enc}` prefix (legacy plaintext) | return unchanged | return unchanged *(unchanged)* |
| `{enc}` prefix, no key configured | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, bad base64 | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, AES setup error | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, GCM setup error | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, ciphertext shorter than nonce | return ciphertext + (no log) | return `""` + ERROR log |
| `{enc}` prefix, GCM auth failure | return ciphertext + WARNING log | return `""` + ERROR log |
| `{enc}` prefix, decrypt success | return plaintext | return plaintext *(unchanged)* |

A caller that previously logged "535 wrong password" and stayed up will now log "no password / empty credential" instead, which is loud and points the operator at the underlying DB / key issue. The ciphertext bytes never leave the process under any failure mode.

**Regression tests** (`internal/database/crypto_test.go` — new):

- `TestDecryptField_RoundTrip` — 7 inputs (empty / single char / words / 4 KiB / Unicode / control chars) round-trip cleanly. This is the startup-test the audit asked for.
- `TestDecryptField_LegacyPlaintextPassthrough` — 6 non-prefixed inputs pass through unchanged so the v0.10.226 idempotency contract still holds.
- `TestDecryptField_NoKeyReturnsEmpty` — both `nil` and `[]byte{}` keys with a real ciphertext yield `""` and never the `{enc}` prefix.
- `TestDecryptField_WrongKeyReturnsEmpty` — encrypt with key A, decrypt with key B → `""` (the AUDIT-027 primary case).
- `TestDecryptField_BadBase64ReturnsEmpty` — 4 malformed payloads (illegal bytes, padding errors, control chars, embedded whitespace).
- `TestDecryptField_TamperedCiphertextReturnsEmpty` — flip a byte in valid ciphertext → `""`.
- `TestDecryptField_ShortCiphertextReturnsEmpty` — `{enc}YWJj` (3 bytes < 12-byte nonce) → `""` (no panic).
- `TestEncryptField_AlreadyEncryptedIsIdempotent` — double-encrypt is a no-op.
- `TestEncryptField_EmptyOrNoKeyPassthrough` — empty plaintext and nil key both pass through.

Database package now has its first test file (was 0% coverage — closes part of AUDIT-117).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.244] - 2026-06-02

### Fixed — AUDIT-014: SMTP critical-alert subject is now sanitized at build time

`BuildCriticalAlertEmail` (`internal/report/email.go:94`) formatted the Subject directly from `device.Name`, `device.IPAddress`, and `alert.AlertType` with no CR/LF sanitization. The downstream `notifier.SendHTMLEmail` did sanitize the final header values (line 299 of `notifier.go`), so a header-injection escape was *already blocked* in production — but the audit's defense-in-depth recommendation is to also sanitize at the **construction** site so that any future caller (or any future `Send*Email` path that forgets the sanitize step) cannot fold attacker-controlled CRLF into mail headers.

Changes:

- New `notifier.SanitizeHeader(s string) string` exported helper (`internal/notifier/notifier.go:25`). Strips CR and LF bytes — the only characters that fold an SMTP/HTTP header into two.
- `notifier.go:283` replaces the inline closure with a reference to the exported helper, so there is exactly one definition of "what does sanitize do" across the project.
- `report/email.go:94` now calls `notifier.SanitizeHeader` on `alert.AlertType`, `device.Name`, and `device.IPAddress` before `fmt.Sprintf`.

Regression tests:

- `internal/notifier/notifier_test.go` — `TestSanitizeHeader_StripsCRLF` (11 table cases including a literal `Bcc: attacker@evil.com` payload) + `FuzzSanitizeHeader` (property: result never contains CR or LF, ~180k execs in 3s).
- `internal/report/email_test.go` — `TestBuildCriticalAlertEmail_SubjectSanitizesCRLF` builds a critical alert with CRLF-laden `Device.Name`, `Device.IPAddress`, `Alert.AlertType` and asserts the returned subject contains none of `\r`/`\n` while still preserving the visible substrings (`CPU_HIGH`, `router-1`, `10.0.0.1`).

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Notifier package now has its first test file (previously 0% coverage — closes part of AUDIT-117).

Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.243] - 2026-06-02

### Added — `LICENSE` (MIT) + AUDIT-002 / AUDIT-010 / AUDIT-023 / AUDIT-025 / AUDIT-122

Five small audit items, batched because each is a one-or-two-line change with no functional risk:

- **AUDIT-002** — added top-level `LICENSE` with standard MIT text (`Copyright (c) 2026 Firewall-Mon Contributors`). README has claimed MIT since v0.10.140 but no license file shipped; without it, Berne Convention defaults the codebase to All Rights Reserved.
- **AUDIT-010** — `internal/config/config.go:247`: changed `PROBE_SERVER_URL` default from `https://stats.technicallabs.org` to `""`. The probe binary itself already required the env var (`cmd/probe/main.go:67` fails if empty), but the hardcoded third-party domain in the server config was a public-release smell. Server side does not actually consume `cfg.Probe.ServerURL` anywhere — this is defensive cleanup.
- **AUDIT-023** — `cmd/api/main.go:216`: added `ReadHeaderTimeout: 10 * time.Second` on the HTTP server. `ReadTimeout` was 30s but `ReadHeaderTimeout` was unset, so a slow-loris attacker holding partial headers could tie up a goroutine per connection up to the existing 30s body limit. 10s is conservative for the longest practical real header.
- **AUDIT-025** — `internal/api/middleware/middleware.go:253`: added `Permissions-Policy` header denying camera, microphone, geolocation, USB, payment, accelerometer, gyroscope, magnetometer, midi, sync-xhr. The admin panel has no use for any of these; sending the deny header tells the browser to block them even if a future UI bug accidentally calls one.
- **AUDIT-122** — `internal/api/handlers/handlers_config_revision_retention_test.go:282`: deleted the 60-line `_unused_legacy_top50_test` orphan that was left in place with a leading underscore when the old retention policy was removed.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .` all clean. Static-binary change (the header/timeout are baked into the API binary) → requires `docker compose up -d --build`. Server-repo only.

## [0.10.242] - 2026-06-02

### Fixed — AUDIT-074 + AUDIT-075: project-wide gofmt sweep and line-ending normalization

`gofmt -l .` flagged 14 files as unformatted, and `internal/irc/bot.go` had CRLF line endings inconsistent with the rest of the tree. Both were captured by AUDIT-074 and AUDIT-075 in `docs/AUDIT.md` and are now resolved with a single `gofmt -w .` pass.

Files reformatted (whitespace-only — `git diff -w` returns empty):

- `internal/api/handlers/handlers_config_diff_test.go`
- `internal/api/handlers/handlers_data.go`
- `internal/api/handlers/handlers_devices.go`
- `internal/api/handlers/handlers_probes.go`
- `internal/configdiff/normalize.go`
- `internal/configdiff/validate.go`
- `internal/configdiff/vendor_cisco_asa.go`
- `internal/configdiff/vendor_fortigate.go`
- `internal/configdiff/vendor_generic.go`
- `internal/configdiff/vendor_paloalto.go`
- `internal/irc/bot.go` (also normalized CRLF → LF)
- `internal/ping/ping.go`
- `internal/snmp/snmp.go`
- `internal/snmp/vendor_firewalla.go`

After this commit, `gofmt -l .` returns empty. AUDIT-152 (CI gofmt enforcement) is the natural follow-up — once the CI workflow exists (AUDIT-004) it should fail on any new unformatted file.

QA: `go build ./...`, `go test -count=1 ./...`, `go vet ./...` all clean. Static-binary change → requires `docker compose up -d --build` to reach a deployment. Server-repo only.

## [0.10.241] - 2026-06-02

### Fixed — AUDIT-001: test files are now tracked in git

`*_test.go` was excluded by `.gitignore:9`, which silently dropped **two regression-net test files** (`internal/configdiff/normalize_test.go`, `internal/report/report_test.go`) from every public clone. Recent CHANGELOG entries (v0.10.236, 0.10.238, 0.10.239) all cited those tests as the regression net — but downstream clones got an empty net.

Removed the `*_test.go` line from `.gitignore` and added the two formerly-hidden files. After this commit, `git ls-files | grep _test.go` returns 11 tracked test files (was 9).

Per the audit doc workflow: AUDIT-001 marked Resolved in `docs/AUDIT.md`. No code changes, no rebuild required (tracked tests do not affect runtime binaries). Server-repo only.

## [0.10.240] - 2026-06-02

### Added — public-release audit document (`docs/AUDIT.md`)

Comprehensive pre-release audit covering security, stability, code quality, frontend, database/architecture, testing/CI, docs/operations, and feature recommendations. **170 findings** (11 CRITICAL deployment blockers, ~70 HIGH-priority, ~25 MEDIUM/LOW) and **89 feature recommendations** (top 10 for v0.11.0 called out separately).

Each finding has a stable ID in the form `AUDIT-NNN` for commit-message tracking and a "Resolved findings" table at the bottom of `docs/AUDIT.md` for progress tracking. Workflow: fix the issue, reference the ID in the commit message, add a row to the Resolved table, append to the Progress log.

**Top 3 fixes to land first** (each unblocks downstream work):

- **AUDIT-001** — remove `*_test.go` from `.gitignore` and `git add -f` the two regression-net test files: `internal/configdiff/normalize_test.go` (631 LOC) and `internal/report/report_test.go` (192 LOC). Public clones currently lose them silently. Recent CHANGELOG entries (v0.10.236, 0.10.238, 0.10.239) cite these as the regression net; the net doesn't exist for downstream users.
- **AUDIT-002** — add `LICENSE` (MIT text). README claims MIT but no license file ships, so the project is "All Rights Reserved" by default under Berne Convention.
- **AUDIT-010** — change `PROBE_SERVER_URL` default to `""` (currently hardcodes `https://stats.technicallabs.org`).

**Other critical findings called out:** no CI / no git tags (AUDIT-004), trap-receiver drops every trap silently (AUDIT-005), batcher not crash-durable (AUDIT-006), no poller leader lock (AUDIT-007), auto-generated JWT secret breaks AES decrypt on restart (AUDIT-008), crypto key rotation impossible (AUDIT-009), no SECURITY.md / no runbook (AUDIT-011).

**Notable high-priority frontend bugs confirmed reproducible:** `probes.html` modals render on first paint (AUDIT-046), Logout link dead on `/admin/irc` (AUDIT-047), `.section-tab` redefines display nullifying the v0.10.230 `.hidden` fix (AUDIT-048), IRC tab nav active state never updates (AUDIT-049), `admin-irc.js` not IIFE-wrapped (AUDIT-050), CSP allows `'unsafe-inline'` for script+style (AUDIT-022).

Docs-only change → no rebuild required. Server-repo only.

## [0.10.239] - 2026-05-30

### Improved — traffic spikes are now summarized by interface, not listed per event

A busy link can spike 30+ times in a window, and the report listed every one as its own card — a wall of events, not a summary. Spikes are now **aggregated per device+interface** into a single row showing: event **count** (e.g. `31×`), **peak throughput**, **worst severity** (critical/warning, with a `(N critical)` note when mixed), and the **time window** (`May 30 02:14 – 14:31`). Rows sort critical-first, then by event count.

The fleet **Bandwidth & Traffic** section leads with a headline — `37 spikes on 3 interfaces · 14 critical · 23 warning` — then the top 8 interface rows, with a `+ N more interfaces with spikes` overflow line. Each device's own card shows the same summary scoped to that device (top 6 interfaces, device name omitted).

Implementation: new `SpikeGroup` + `groupSpikes()` aggregation and `windowLabel()` (replacing the per-event `SpikeCard`) in `internal/report/model.go`; new `spikegroup` template row (replacing `spike`) in `template_report.go`. Tests: `TestGroupSpikes` covers aggregation, critical-first sort, window labels, and the cap/overflow; the render test now asserts the summarized spike section appears.

Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.238] - 2026-05-30

### Fixed — report spike timestamps all showed "Jan 1 00:00"

Traffic-spike cards in the executive report rendered every timestamp as `Jan 1 00:00` (the Go zero time). `parseBucketTime` (`internal/report/data.go`) only tried layouts **with seconds** (RFC3339, `2006-01-02 15:04:05`), but the dialect `TimeBucket` helpers emit buckets via `to_char`/`strftime` **without seconds** — minute = `2006-01-02 15:04`, hour = `2006-01-02 15:00`, day = `2006-01-02` (see `internal/database/dialect.go`). No layout matched, so every parse fell back to the zero time. Added the secondless minute/hour/day layouts (first in the try-list); kept the seconds/RFC3339 variants for raw timestamps.

`internal/report/report_test.go` now feeds `computeTraffic` the real Postgres minute-bucket format and asserts the parsed bucket time is non-zero, so this can't regress.

Spike values/severities and all other report data were already correct — this was display-only. Static-binary change → requires `docker compose up -d --build`. Server-repo only.

## [0.10.237] - 2026-05-30

### Fixed — Reports page "Failed to load report: res.json is not a function"

The new admin Reports page (v0.10.236) failed on **View** and **Send Now** with `res.json is not a function`. `admin-reports.js` chained `.then(res => res.json())` onto `AdminCommon.apiFetch(...)`, but `apiFetch` **already parses the body and resolves to the JSON object** (it calls `res.json()` internally at `admin-common.js:179`) — so the second `.json()` ran against a plain object. Removed the redundant `.json()` step at both call sites (preview + send); the resolved value is now consumed directly as `{success, data}`.

Also bumped the `Dockerfile` `org.opencontainers.image.version` label (was stale at `0.10.235`) to match the release.

This is a static-JS fix embedded in the binary, so it requires a container rebuild to reach a deployment (`docker compose up -d --build`). Server-repo only.

## [0.10.236] - 2026-05-29

### Redesigned email/summary report — one self-contained executive report, viewable + exportable from the admin panel

The daily/weekly email report was a `multipart/related` message with go-chart PNGs embedded via `Content-ID`. Outlook and several clients list those inline images as **separate attachments** — the "mix of text and multiple individual files" complaint. The charts were basic and, worse, the bandwidth section was fundamentally broken (details below). There was also no way to see the report without waiting for the scheduled email.

This rewrite replaces it with a single, modern, **image-free** report rendered entirely from email-safe HTML/CSS, delivered three ways from one template: the scheduled email, a new **Reports** page in the admin panel, and browser print-to-PDF.

#### The bandwidth detection was mathematically wrong — now fixed
`interface_stats.in_bytes`/`out_bytes` store the **raw cumulative SNMP octet counter** (`ifHCInOctets`), not a per-interval delta. The old report fed that monotonically increasing counter straight into:
- **Spike detection** (`DetectTrafficSpikes`) — running rolling std-dev on an always-increasing series means the latest sample is permanently far above the rolling mean. It fired constantly and reported meaningless raw byte counts ("12345 bytes at 15:04").
- **Top interfaces** (`GetTopInterfacesByTraffic` `SUM(in_bytes)`) — summing a cumulative counter is not bytes-transferred.

Now traffic is derived from **consecutive counter deltas** (`computeTraffic` in `internal/report/data.go`), with negative deltas clamped for counter resets/32-bit wrap. This yields honest **bytes transferred** (telescoping delta sum), **peak/avg throughput** (bits/sec), a throughput **sparkline**, and spike detection that runs on the *throughput* series (`detectSpikesInSeries`) and reports rates ("842.0 Mbps at …"), not counter values.

#### What the new report contains
- **Fleet KPI cards** — devices, online/offline, alerts, critical, fleet uptime %.
- **Bandwidth & Traffic** — peak throughput + total transferred chips, fleet **Top Talkers** horizontal bars, and traffic **spike callouts** as styled cards.
- **Alert timeline** — pure HTML/CSS column histogram (ported off go-chart).
- **Per-device detail** — KPI mini-grid, uptime bar, throughput sparkline, interface bars, spikes. Collapsible (`<details>`) in the admin preview; always-open in email.

#### Admin panel — new Reports page
- Sidebar **System → Reports** (`/admin/reports`).
- **View** (renders the report into an isolated iframe via `document.write` — robust against the `frame-src`-less CSP), **Export PDF** (browser print of the iframe; print CSS expands all device blocks and hides UI chrome), **Download HTML** (self-contained single file), **Send Now** (emails the report immediately, reusing the Test-Email SMTP path + SSRF guard).
- New endpoints: `GET /admin/api/reports/preview?period=daily|weekly`, `POST /admin/api/reports/send`.

#### Email is now a single message with zero attachments
`Notifier.SendHTMLEmail` sends a plain `text/html` message (8bit) when there are no attachments, instead of an empty `multipart/related` wrapper — so compliant clients show one clean message. The `multipart/related` path is retained for critical-alert emails, which still embed one CPU/Memory image.

#### Internal refactor
- New: `internal/report/model.go` (pure-data `ReportModel` + `BuildReportModel`), `template_report.go` (single email-safe HTML template + `RenderReportHTML`), `format.go` (`autoScale` moved out of `charts.go` + `formatBytes`/`formatThroughput`), `internal/api/handlers/handlers_reports.go`.
- `internal/report/data.go` now gathers raw series instead of pre-rendered PNGs; `email.go` `BuildDailyReport`/`BuildWeeklyReport` return `(subject, html, err)`; `charts.go` trimmed to `RenderCPUMemChart` (go-chart now used only for critical-alert emails); old `dailyTemplate` removed.
- `Handler` gains a `notifier` + `version` (injected in `cmd/api/main.go`); `ServerVersion` → `0.10.236`.
- Tests: `internal/report/report_test.go` covers counter-delta math, formatters, throughput-series spike detection, and a render smoke test asserting no `cid:`/`<img>` in the output.

#### Verification
- `go build ./...`, `go vet`, and `go test ./...` all pass (new report tests green).
- Server-repo only — no collector changes.

## [0.10.235] - 2026-05-19

### Fixed — 23 redundant `class="hidden"` tokens on `.modal` / `.tab-content` elements (deferred from v0.10.233)
v0.10.233 flagged ~21 HTML elements where `class="hidden"` appeared alongside `class="modal"` or `class="tab-content"`, both of which already default to `display: none` in admin-shared.css. The v0.10.233 audit explicitly deferred the cleanup ("risk of accidentally dropping a needed class on a 21-element sweep outweighs the latent-trap value"). This entry does the sweep carefully — verified element-by-element, with one specificity trap caught.

#### Why it's a real bug, not just style smell
The same shape — class-based show/hide that "works today" because of specificity but breaks if anyone touches the rules — has bitten us in v0.10.230 (connection-detail tabs), v0.10.231 (IRC SASL fields), and v0.10.232 (login error banner). Each landed silent UI regressions on operators. The redundant `hidden` on these 23 elements is the same trap class on the HTML side — `.modal.active { display: flex }` (specificity 0,2,0) currently beats `.hidden { display: none }` (0,1,0), but if Tailwind ever ships `.hidden { display: none !important }` (a real possibility in future Tailwind versions and a frequent monkey-patch), every modal in this repo would silently fail to open.

#### Files touched
- `web/admin/admin.html` — alerts-bulk-ack-modal.
- `web/admin/sites.html` — site-modal (special case, see below).
- `web/admin/probes.html` — probe-modal, deploy-modal.
- `web/admin/connection-detail.html` — tab-content-src-tunnels, tab-content-dst-tunnels, tab-content-phase2, tab-content-flows.
- `web/admin/device-detail.html` — tab-vpn, tab-sensors, tab-processors, tab-alerts, tab-ping, tab-ha, tab-security, tab-sdwan, tab-licenses, tab-config, tab-processors-ssh, tab-iface-err (12 tabs).
- `web/admin/irc.html` — tab-channels, tab-commands, tab-send.

Total: 4 modals + 19 tab-content elements = 23 elements (audit said 21; was off by 2).

#### The `sites.html:42` specificity trap caught during the sweep
`site-modal` was the one element where `hidden` was NOT purely redundant. It had `class="modal hidden flex …"`. In the compiled tailwind.css, `.flex { display: flex }` is declared AFTER `.modal { display: none }` — same specificity (0,1,0), source-order tiebreak means `.flex` wins. So `hidden` was actually the only thing keeping the modal hidden on page load (also at specificity 0,1,0 but declared after `.flex`). Removing just `hidden` would have rendered the site Add/Edit modal visible-on-load.

Fix: removed BOTH `hidden` AND `flex` from `site-modal`. `.modal.active { display: flex }` (added by `openModal()`) already provides flex layout when the modal is opened; the bare `.modal` default of `display: none` keeps it hidden at rest. This is the correct shape — same as the other three modals that had `items-center justify-center` but no explicit `flex`.

#### Verification
- `.modal { display: none }` confirmed in `admin-shared.css:506` AND in compiled `tailwind.css` (which loads after admin-shared.css). `.modal.active { display: flex }` likewise.
- `.tab-content { display: none }` confirmed in `admin-shared.css:524` and `connection-detail.html:39` (inline). `.tab-content.active { display: block }` likewise.
- `openModal()` in `admin-common.js:644` adds `.active`. No other modal show-path exists in the codebase (grep confirmed).
- `switchTab()` adds `.active` to the matching tab-content. No other show-path exists.
- No JS in `cmd/api/static/js/` or `web/` reads `classList.contains('hidden')` against any of the 23 elements — the `hidden` class was dead-code for state checks too.
- No tests reference `modal hidden` or `tab-content hidden` HTML strings (grep confirmed).
- `go build ./...` clean, full test suite green.

#### What was NOT touched
The 24 unrelated `.hidden` classes on non-modal/non-tab-content elements (empty-state placeholders, hidden inputs, error banners that use `classList.toggle('hidden')` correctly per v0.10.232's fix). Those are load-bearing — they're the JS's primary mechanism for show/hide on plain divs. Only the 23 elements where `hidden` was actively shadowed by a stronger rule were cleaned up.

## [0.10.234] - 2026-05-18

### Fixed — backend zero-value Save footgun (deferred from v0.10.233 audit)
The v0.10.233 sweep noted three handler-level instances of the same bug class that v0.10.226 had finally diagnosed in `UpdateSettings`: a struct decoded directly from the request body, then handed to `db.Save`, will UPDATE every column — so any field absent from a partial PUT lands as a Go zero-value and silently wipes the existing column. This entry fixes the three remaining handlers:

#### 1. `UpsertDeviceAlertConfig` (`handlers_alert_policies.go:226`)
Previous flow: `var cfg models.DeviceAlertConfig; c.ShouldBindJSON(&cfg); db.UpsertDeviceAlertConfig(&cfg)`. PUT `{"cpu_threshold": 95}` on a device with full thresholds and a policy binding would, after the save, leave that device with:
- `memory_threshold = 0`, `disk_threshold = 0`, `session_threshold = 0`, `cooldown_minutes = 0`
- `alerts_enabled = false` (because Go bool zero is false — alerts were silently disabled by editing CPU)
- `policy_id = NULL` (the device fell back to the default policy)

Fix: load the existing row first, bind the JSON onto it, then save. `encoding/json` (which `c.ShouldBindJSON` wraps) only writes struct fields that ARE present in the body, so untouched columns keep their values. If the row doesn't exist yet, seed `&DeviceAlertConfig{DeviceID:id, AlertsEnabled:true}` so the "create on first edit" path keeps the model's intended default.

Defensive `cfg.DeviceID = id` after binding prevents a client from rewriting the foreign key via the request body.

#### 2. `UpsertSiteAlertConfig` (`handlers_alert_policies.go:328`)
Identical pattern, identical fix. `SiteAlertConfig` has no `AlertsEnabled` column (site configs always apply when present), so the create-if-absent path just seeds `&SiteAlertConfig{SiteID:id}`. The threshold/cooldown surface mirrors the device handler.

#### 3. `UpdateMaintenanceWindow` (`handlers_maintenance.go:73`)
The most visible of the three. Previous flow loaded `existing` only as an "does this ID exist?" check, then bound the request body into a FRESH `MaintenanceWindow` and called `Save`. Any field absent from the PUT body wiped the row: `recur_rule`, `recur_days`, `alert_types`, `notes`, `suppress_all`, `recurring`. A user editing just the end time of a weekly maintenance window would lose the entire recurrence schedule on save.

Fix: `Gorm().First(&window, id)` to load directly into `window`, bind JSON onto it, then save. Re-asserts `window.ID = id` after binding to prevent PK rewrite.

#### 4. Shared threshold validation (`validateAlertConfigThresholds`)
Both alert-config upserts gained range validation that was previously absent — CPU/memory/disk must be 0-100, session and cooldown must be non-negative. Previously the UI could (and during one debug session in v0.10.232 nearly did) persist 200% CPU or negative thresholds.

#### Tests
Six new tests in `handlers_partial_update_test.go` lock the fix in:
- `TestUpsertDeviceAlertConfig_partial_update_preserves_other_fields` — seeds a full config, PUTs `{"cpu_threshold": 95}`, asserts every other column survives. This test FAILS against the v0.10.233 code.
- `TestUpsertDeviceAlertConfig_rejects_invalid_threshold` — PUTs `cpu_threshold: 150`, expects 400.
- `TestUpsertDeviceAlertConfig_creates_when_absent` — verifies `AlertsEnabled` defaults to `true` on insert.
- `TestUpsertSiteAlertConfig_partial_update_preserves_other_fields` — same shape, site variant.
- `TestUpdateMaintenanceWindow_partial_update_preserves_other_fields` — seeds a recurring weekly window, PUTs only `end_time`, asserts `recur_rule`/`recur_days`/`alert_types`/`notes`/`suppress_all`/`recurring`/`device_id` all preserved.
- `TestUpdateMaintenanceWindow_rejects_end_before_start` — guards the existing validation.

### Why the bug kept reappearing
`db.Save(&struct)` is GORM's natural ergonomic API — it looks like "save this object." But its semantic is "UPDATE every column to the values currently in this object," which is fine when the object was loaded from the DB and then mutated, and catastrophic when the object came straight from JSON decoding (because absent fields are now Go zero-values masquerading as the user's intent). The canonical safe shape across this codebase is either (a) load-existing → bind onto it → save, used by these three handlers now, or (b) bind into a fresh struct → build an allow-listed `map[string]interface{}` → `db.Model(...).Updates(map)`, used by `handlers_devices.go`. Both patterns make the "field was not in the body" case observable.

## [0.10.233] - 2026-05-18

### Fixed — comprehensive bundle from 4-agent codebase sweep
Per the operator's "do a full pass of everything using sub agents — you keep finding all these random bugs and issues," I ran four parallel deep audits across the entire codebase looking for every variant of the bug classes fixed in v0.10.226–v0.10.232. Verified every HIGH finding against the source before patching (audits have been wrong twice — stale Tailwind in v0.10.230, "intentional" expandable-msg in v0.10.231 — so trust-but-verify is now mandatory). This entry is the consolidated bundle.

#### 1. Rich connection-detail side panel was unstyled (HIGH)
Clicking a connection on the network diagram (`/admin/connections`) renders a side panel with 5 sub-tabs (Overview / Tunnels / Phase 2 / Flows / Events) built by `diagram-panels.js:130-217`. The JS template uses CSS classes `rich-detail-panel`, `panel-header`, `panel-tabs`, `panel-tab`, `panel-tab-content`, `panel-flow-grid`, `panel-flow-card`, `tunnel-columns`, `tunnel-col` — **none of which were defined in any CSS file**. Result:
- The panel rendered as an unstyled block with no border, no padding, no tab strip.
- Critically, **`.panel-tab-content { display: none }` was missing**, so all 5 tab-contents rendered simultaneously, stacked vertically — clicking a tab added `.active` but never hid the other tabs. Same shape bug as v0.10.230's connection-detail orphan blocks, on a different surface.

Added the missing rules to `admin-shared.css`. The panel now has a proper card boundary, working tab strip with active-state underline, and only-the-active-pane visibility.

#### 2. IRC management page was unstyled (HIGH)
The whole `/admin/irc` server-card list (`admin-irc.js:75-103`) referenced `server-card`, `server-card-header`, `actions`, `server-info`, `channel-list`, `channel-tag`, `status-badge`, plus seven status-color classes (`status-connected`, `status-disconnected`, `status-connecting`, `status-error`, `status-joined`, `status-pending`, `status-left`) — zero CSS for any of them. Operators saw a wall of bare text with no card boundaries, action buttons crowded against each other, and connection-state text rendered in default-text color instead of colored pills. v0.10.231 fixed the IRC modals; this finally styles the page behind them.

Added all 14 missing rules. Status pills now use the same color palette as the existing `.badge.online`/`.badge.offline`/etc. for visual consistency.

#### 3. Probe / probe-pending card internals were unstyled (HIGH)
`admin-probe-pending.js:33-41` rendered pending-probe cards using `probe-header`, `probe-details`, `probe-actions` — undefined. The `.probe-card` outer was styled but the layout inside was raw block-flow, so headers and action buttons stacked unattractively. `admin-probes.js:105-111` used `actions` and `info-text` for the probe-list table's action button group and description text — also undefined. Added all five rules.

#### 4. Connection-detail tunnel-row expand chart had a 0-height container (HIGH)
When the user expands a tunnel row on `/admin/connections/:id`, `admin-connection-detail.js:199-206` injects `.tunnel-chart-wrap > .range-pills + .chart-container > canvas`. `.tunnel-chart-wrap` and `.chart-container` had no CSS, so the chart container had no `height` declared. Chart.js with `maintainAspectRatio: false` rendered to whatever height it found in the parent — which was 0 in a default table cell. Charts may have been silently rendering at zero height. Fixed by giving `.chart-container` a 220px fixed height and proper padding on the wrap.

#### 5. Interface-type / tunnel-type badge variants had no colors (HIGH-cosmetic)
JS emitted `<span class="badge vxlan">`, `<span class="badge tunnel">`, `<span class="badge lag">`, `<span class="badge ipsec">`, `<span class="badge l3ipvlan">`, etc. Only the base `.badge` rules existed, so all type pills rendered in the neutral grey of `.badge.unknown` — operators couldn't tell L2VLAN from VXLAN from Tunnel from LAG at a glance. Added color variants matching the existing palette: VXLAN/L3IPVLAN purple, Tunnel/IPSec/GRE/SSLVPN pink, LAG/Bond orange, L2VLAN/VLAN cyan, Ethernet/Physical blue.

#### 6. `Database.UpsertSetting` was the v0.10.226 bug verbatim (MEDIUM)
`internal/database/database.go:1478-1487` had the exact `FirstOrCreate` → copy 3 fields → `Save` shape that v0.10.226 spent four versions diagnosing in `UpdateSettings`. `IsSecret` and `Type` were never copied onto the existing row. The function has zero in-tree callers today, but it's exported on the public `*Database` API — anyone wiring a new caller (a future migration helper, an admin tool, a webhook receiver) inherits the bug. Fixed to mirror the canonical `UpdateSettings` pattern with all five fields copied.

#### 7. 17 latent `.hidden` + `style.display` traps in admin-device-detail.js (MEDIUM)
The empty-state placeholders for Interfaces, VPN, Sensors, Processors, Alerts, Ping, HA, Security, SD-WAN, Licenses, Config-History, Process Monitor, and Interface Errors tabs all toggled visibility via `empty.style.display = 'block'/'none'` against elements with `class="hidden"` in markup. Same trap as the connection-detail tabs (v0.10.230), IRC SASL fields (v0.10.231), login error banner (v0.10.232). Worked today only because inline `'block'` (specificity 1,0,0,0) beats `.hidden` (0,1,0). One `style.display = ''` refactor and every device-detail tab's empty state would silently break. Converted all 17 sites — plus the `#loading`/`#content`/`#error` initial-render toggles in `renderDevice` — to `classList.toggle('hidden')` so the markup's `hidden` class and the JS toggling agree on a single source of truth.

#### 8. Dead `error-msg` / `success-msg` banner markup deleted (LOW)
`probe-pending.html:31-32`, `probes.html:37-38`, and `sites.html:35-36` had `<div … id="error-msg">` / `id="success-msg"` div pairs that were never referenced by any JS — the corresponding admin-*.js files route errors and successes through the `AC.showError` / `AC.showSuccess` toast helpers. Six lines of dead markup deleted.

### Bugs found by audit but NOT fixed in this bundle
- **21 `.modal` / `.tab-content` elements with redundant `class="hidden"`** — same latent trap class as #7 but on the HTML side. Cosmetic only since `.modal.active` (specificity 0,2,0) currently beats `.hidden` (0,1,0). Deferred — risk of accidentally dropping a needed class on a 21-element sweep outweighs the latent-trap value. Worth a focused cleanup pass.
- **`UpsertDeviceAlertConfig` / `UpsertSiteAlertConfig` / `UpdateMaintenanceWindow` zero-value `Save` footgun** — three handlers call `db.Save(cfg)` with the bound request struct directly, so any field absent from the PUT body lands as Go zero-value (0 thresholds, `false` booleans, nil policy bindings). Real silent-data-loss class but the fix requires per-field merge logic that I'd want to scope tightly. Filed for a follow-up audit pass.
- **Slack/Discord/webhook URLs stored unencrypted** — design call, not a bug — they embed per-channel secrets in the path. Worth encrypting at rest like `smtp_password`. Out of scope here.

### Audits that came back CLEAN
- Pattern C (`onclick="..."` JS-string-literal escape bugs): one was fixed in v0.10.229 (`togglePublicIface`), zero remain.
- Pattern D (`innerHTML` writes with unescaped user-supplied data): all interpolations go through `esc()` / `escapeHtml()` / `window.escapeHtml()`. No XSS surface found.
- Pattern P1 (duplicate IDs across admin HTML): cleaned up by v0.10.230's connection-detail consolidation. Zero duplicate IDs remain anywhere under `web/admin/`.
- Pattern P2 (modals missing `.modal` class): zero remain after the v0.10.231 IRC + probe-pending fixes.
- Pattern P3 (orphan content blocks missing required class for switchTab): zero remain.

### Files
- Modified: `cmd/api/static/css/admin-shared.css` — added ~300 lines covering rich-detail-panel, IRC server cards, probe card internals, badge variants, tunnel-chart-wrap, scope-toggle.
- Modified: `internal/database/database.go` — `UpsertSetting` now copies `Type` + `IsSecret` onto the existing row before `Save`.
- Modified: `cmd/api/static/js/admin-device-detail.js` — 17+ `style.display` call sites switched to `classList.toggle('hidden')`.
- Modified: `web/admin/probe-pending.html`, `web/admin/probes.html`, `web/admin/sites.html` — deleted dead `error-msg` / `success-msg` banner markup.

## [0.10.232] - 2026-05-18

### Fixed — admin-login.js latent `.hidden` + `style.display` trap
Audit of `/admin/login` for the bug patterns from v0.10.230-231. Found one M1-level latent trap matching the same shape:

`admin-login.js:17/30/35` toggled the error banner with `errorDiv.style.display = 'block'/'none'`. The banner has `class="hidden"` in markup (`login.html:15`) and tailwind.css defines `.hidden { display: none }`. *It works today* only because inline `style.display = 'block'` (specificity 1,0,0,0) beats the `.hidden` class (0,1,0). But that's the exact footgun that hid the connection-detail Phase 2 / Traffic Analysis tabs (v0.10.230) and the IRC SASL fields (v0.10.231 M1) — any future refactor to `style.display = ''` (intending "clear the inline override and let the cascade decide") would silently break the error banner. Operators with bad credentials would see no feedback at all — the form would simply re-enable and stop pretending to log in.

**Fix:** switched to `errorDiv.classList.add('hidden')` / `.remove('hidden')` so the markup's `hidden` class and the JS toggling agree on a single source of truth.

#### Otherwise CLEAN
The login page is a single self-contained HTML file (`web/admin/login.html`, 37 lines) plus `admin-login.js` (43 lines). It loads only `tailwind.css`, no `admin-shared.css` or `admin-design-system.css`, so the cross-file specificity battles affecting the rest of the admin can't reach it. No modals (so no `.modal`-class-missing bug), no duplicate IDs, no orphan content blocks, no class-toggling-without-matching-CSS-rule, no `.stat-card` flex-row leak. The one finding was the latent trap above.

### Files
- Modified: `cmd/api/static/js/admin-login.js` — three call sites switched from `style.display` to `classList.add('hidden')`/`.remove('hidden')`.

## [0.10.231] - 2026-05-18

### Fixed — three more dead admin features uncovered by audit
After v0.10.230 fixed the connection-detail tab/duplicate-ID bugs, the operator asked me to sweep the rest of the admin area for the same patterns. The audit turned up three more **completely-broken features** plus one latent trap. Real bugs, not style smell.

#### 1. IRC modals never opened (Add/Edit Server, Add/Edit Channel, Add/Edit Command)
`web/admin/irc.html:120, 222, 290` declared `<div id="serverModal" class="… hidden …">` for the three IRC dialogs but **omitted the `modal` class**. `AdminCommon.openModal()` (`admin-common.js:610-644`) shows modals by adding `.active`, which the admin-shared `.modal.active { display: flex }` rule then matches. With no `.modal` class on the element, `.active` had no rule to trigger and `.hidden { display: none }` kept the dialog invisible. Clicking *Add Server*, *Edit Channel*, *Add Command* etc. fired the JS handler, the modal got its `active` class, and… nothing visibly happened. The entire IRC configuration UI was unreachable from the admin without backdoor edits (DB or env vars).

**Fix:** added `modal` to the class list of each dialog, removed the now-redundant `hidden` (the `.modal { display: none }` default in admin-shared.css already handles the initial state). The Tailwind utility classes that previously stood in for the modal layout — `fixed top-0 left-0 right-0 bottom-0 bg-black/60 z-[200]` — were kept; they continue to provide the overlay positioning while `.modal.active` toggles visibility.

#### 2. Probe-pending Reject dialog never opened
Same bug. `web/admin/probe-pending.html:40` had `<div class="hidden …" id="reject-modal">` with no `.modal` class. `admin-probe-pending.js:72` calls `AC.openModal('reject-modal')`. Same `.active`-without-`.modal` problem → dialog invisible. Operators clicking *Reject* on a pending probe got no feedback. (The Approve action on the same page worked because it didn't use a modal.)

**Fix:** identical to #1 — added `modal` class, removed `hidden`.

#### 3. Click-to-expand syslog/alert messages was a no-op
JS at `admin-main.js:3518-3520` toggles a `.expanded` class on `.expandable-msg` cells when clicked. The intent is clear: cells with long messages render truncated by default, click reveals the full text. But the cells were rendered with inline `style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"` (`admin-main.js:1106` for syslog, `:1736` for alerts). Inline styles have specificity 1,0,0,0 — *no class-based rule* can override them. There was also **no `.expandable-msg.expanded` rule defined anywhere** under `cmd/api/static/css/`, so even removing the inline style wouldn't have done anything. The feature had never worked in production.

Compounding the confusion: the v0.10.228 CHANGELOG explicitly absolved this case ("intentional click-to-expand truncation"). It was wrong — the click handler exists but the visual unwrapping doesn't.

**Fix:** dropped the inline `style=""` from both rendering call sites. The CSS class `.expandable-msg` (already declared in `admin.html:140` with `max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap`) carries the truncation now. Added `.expandable-msg.expanded { max-width: none; white-space: normal; overflow: visible; text-overflow: clip; word-break: break-word; overflow-wrap: anywhere; }` to actually unwrap the message on click. Clicking a truncated syslog or alert message now expands it inline; clicking again collapses it back.

#### 4. Latent trap fixed — IRC form SASL / status-interval pickers
`admin-irc.js:134` and `:331` set `style.display = 'block'/'none'` on `#saslFields` (the SASL credentials sub-form in the server dialog) and `#statusIntervalGroup` (the status-message interval input in the channel dialog). Both elements have `class="hidden"` in their markup. *Today this works*, because inline styles beat class selectors. But it's exactly the same trap that hid the connection-detail tabs for an unknown number of versions — the moment anyone refactored to use `style.display = ''` (intending "clear the inline override and let the cascade decide"), the fields would silently break and the operator would have no working SASL or status-interval configuration UI.

**Fix:** switched both to `classList.toggle('hidden', !cond)` so the markup's `hidden` class and the JS toggling agree on a single source of truth.

### Audit findings deliberately deferred
- **Redundant `hidden` on `.modal` dialogs that already work** (alerts-bulk-ack-modal on admin.html, site-modal on sites.html, probe-modal + deploy-modal on probes.html) — same pattern as #1/#2 but `.modal.active { display: flex }` already wins over `.hidden`, so they function correctly. Style smell only; no operator-visible bug. Worth a cleanup pass when someone's already touching those files.
- **Dead `#error-msg` / `#success-msg` banners on sites.html, probes.html, probe-pending.html** — never queried by any JS. The pages route everything through `AC.showError` / `AC.showSuccess` toasts instead. Markup leftovers; should be deleted but not urgent.

### What was NOT a bug
The audit also flagged the `tab-content hidden` pattern on IRC tabs (`irc.html:60, 72, 96`) as the same trap. It isn't — `.tab-content.active { display: block }` has specificity 0,2,0 which beats `.hidden { display: none }` at 0,1,0, so adding `.active` correctly reveals the panel. The redundancy is real but harmless.

### Files
- Modified: `web/admin/irc.html` — added `modal` class to serverModal/channelModal/commandModal, dropped redundant `hidden`.
- Modified: `web/admin/probe-pending.html` — added `modal` class to reject-modal, dropped redundant `hidden`.
- Modified: `web/admin/admin.html` — added `.expandable-msg.expanded` CSS rule.
- Modified: `cmd/api/static/js/admin-main.js` — removed inline truncation style from `.expandable-msg` cells in syslog/alerts table renderers (relies on CSS class now).
- Modified: `cmd/api/static/js/admin-irc.js` — switched toggleSASLFields and toggleStatusInterval to `classList.toggle('hidden', ...)`.

## [0.10.230] - 2026-05-18

### Fixed — connection-detail dead features (Phase 2 / Traffic Analysis tabs unreachable)
Audit of `/admin/connections/:id` after the v0.10.229 device-detail sweep found that a half-finished Tailwind refactor had been shipped: two of the page's five section tabs (Phase 2 Selectors, Traffic Analysis) were **completely unreachable** from the UI, plus the page had duplicate HTML IDs and broken chevron affordance. Four real bugs, fixed here.

#### 1. Phase 2 + Traffic Analysis tab buttons never appeared
Tab buttons at `connection-detail.html:72-73` had `class="section-tab hidden"`. JS at `admin-connection-detail.js:144,148` tried to reveal them with:

```js
document.getElementById('tab-flows').style.display = data.has_flow_data ? '' : 'none';
document.getElementById('tab-phase2').style.display = p2matches.length > 0 ? '' : 'none';
```

But `.hidden { display: none }` is defined in `admin-shared.css` and `style.display = ''` only clears the *inline* property — it can't override a stylesheet rule. So the tabs stayed `display: none` forever. Operators viewing a connection with active Phase 2 selectors or sFlow data had no way to access either visualization. Fixed by switching to `classList.toggle('hidden', !condition)` so the `.hidden` class is properly removed when the data condition warrants it.

Same bug also hit `flow-empty` (`admin-connection-detail.js:391`) — the "sFlow enabled but no samples match" banner could never appear because its element also has `class="hidden …"` and the same inline-vs-class precedence problem. Fixed the same way.

#### 2. Duplicate IDs across orphaned-refactor blocks
The page had two copies of `tab-content-dst-tunnels` (lines 125-135 + 168-178), `tab-content-phase2` (137-143 + 180-186), and `tab-content-flows` (145-166 + 188-244). The first set used the legacy `.card` / `.tunnel-table` CSS classes defined in the inline `<style>` block, the second set used Tailwind utility classes. Same content rendered with different styling, duplicated.

That meant 9 inner element IDs were also duplicated: `dst-tunnels-table`, `dst-tunnels-title`, `phase2-matches-container`, `flow-range-select`, `flow-empty`, `flow-content`, and all four flow chart canvases (`proto-chart`, `flow-time-chart`, `top-src-chart`, `top-dst-chart`) plus `convos-table`. Per HTML5 spec `getElementById` returns the first match — so JS sometimes wrote to the unreachable orphan elements while `switchTab` activated the legacy block.

#### 3. Traffic Analysis charts were unreachable even bypassing tab visibility
The orphan `tab-content-flows` block at lines 188-244 had `class="hidden"` — only one class, missing `.tab-content`. `switchTab` (`admin-connection-detail.js:502-510`) iterates `.tab-content` elements and toggles `.active` on them. The orphan never matched, so it was never activated. The four flow chart canvases lived only inside that orphan block, so even if the Traffic Analysis tab button had been reachable, the user would have seen the empty `flow-content` placeholder from the *legacy* block (line 164: `<div id="flow-content"></div>`), with the actual charts permanently hidden in the orphan.

#### Fix
Consolidated into one canonical block. The three legacy blocks (125-166) kept their styling for src/dst-tunnels + Phase 2 (matches the existing src-tunnels styling at line 113-123). The legacy `tab-content-flows` had its empty `flow-content` placeholder replaced with the rich charts/tiles markup that previously lived in the orphan. All three orphan blocks (168-244) deleted. Net: 9 duplicate IDs eliminated, 100 lines removed, Traffic Analysis charts now reachable.

#### 4. Chevron rotation on tunnel-row expand was a no-op
JS at `admin-connection-detail.js:261-266` toggles `.open` on the `.chevron` span when a tunnel row is expanded. The matching CSS rule for the rotation existed only as `.panel-tunnel-row .chevron.open { transform: rotate(90deg) }` inside `web/admin/admin.html` (scoped to the diagram-panel context on a different page), so on connection-detail the rotation never fired — the ► glyph stayed pointing right whether the row was expanded or collapsed.

Added `.chevron` / `.chevron.open` rules to the inline `<style>` block on connection-detail.html plus a `.tunnel-row:hover` rule that admin-shared.css had only for `.panel-tunnel-row`. The affordance now works.

### Audit findings deliberately NOT fixed
- **`setTrafficRange` / `setFlowRange` reference non-existent containers** (`admin-connection-detail.js:376,493` query `#traffic-range .range-pill` / `#flow-range .range-pill` — neither container exists in the markup). The querySelectorAll returns empty, the loop does nothing. Both functions still work because they also drive the actual `<select>` dropdowns. Dead code; leaving for a future cleanup pass.
- **The audit claimed `tailwind.css` was stale** ("none of the arbitrary-value classes used on this page exist"). I verified by reading the compiled file — `bg-[#0d1117]`, `text-[#58a6ff]`, `text-[0.78rem]`, `h-[250px]`, etc. are all present. False alarm in the audit; no rebuild needed.

### Files
- Modified: `web/admin/connection-detail.html` — added chevron CSS rules to the inline `<style>` block, removed the three orphan tab-content blocks (lines 168-244), moved the flow-content rich charts/tiles into the legacy `tab-content-flows` block.
- Modified: `cmd/api/static/js/admin-connection-detail.js` — switched the three `.hidden`-elements (tab-flows / tab-phase2 / flow-empty) from inline `style.display` toggling to `classList.toggle('hidden', !condition)`.

### Why this hadn't been reported
A connection-detail page on a deployment with no Phase 2 SA matches AND no sFlow data would never *attempt* to show those tabs, so the broken JS path doesn't fire and the operator sees only Overview + Source/Destination Tunnels — which work. The bugs manifest only when there's data to display. That's consistent with the operator never having reported it.

## [0.10.229] - 2026-05-18

### Fixed — five device-detail CSS bugs surfaced by audit
After v0.10.227 fixed the stat-card flex bug on `/admin/devices/:id` and v0.10.228 swept the rest of the admin area, a deeper audit of just the device-detail page found five more issues. All shipped here as one bundle.

#### 1. Interface row expand panel was silently broken (highest-impact)
Clicking an interface row in the Interfaces table renders an expanded `<tr>` with 13 detail items (Index, Type ID, VLAN ID, High Speed, Description, in/out bytes & packets & errors & discards) plus a chart-range pill bar (24h/7d/30d/90d) and a per-interface throughput chart. The JS at `admin-device-detail.js:568-597` referenced these CSS classes:

- `.expand-row` — the `<tr>`
- `.expand-content` — the panel container
- `.detail-grid` — grid wrapping the 13 detail items
- `.detail-item` / `.label` / `.value` — the label+value pairs
- `.chart-range-btn` (singular) — the range pills

**None of these were defined in any CSS file.** Result: the 13 detail items stacked in a tall single-column list with raw browser-default text styling, and the chart range buttons rendered as unstyled native `<button>` elements (grey, browser-default font, no spacing). The expand panel has been visibly broken since whenever it shipped — the audit caught it.

Fixes:
- Added definitions for `.expand-row`, `.expand-content`, `.detail-grid` (CSS grid with `repeat(auto-fill, minmax(180px, 1fr))`), `.detail-item`, `.detail-item .label`, `.detail-item .value`, and `.iface-chart-container` in `admin-device-detail.css`.
- Renamed `chart-range-btn` → `range-btn` in `admin-device-detail.js` so it matches the existing `.chart-range-btns .range-btn` rule in `admin-shared.css:165-184`.

#### 2. Six tables missing horizontal-scroll wrapper
The Interfaces table at line 191 was wrapped in `<div class="table-scroll overflow-x-auto">`, but the other six tables (VPN with 13 columns, HA, SD-WAN, Ping, Alerts, Config History) were not. At narrow viewports the VPN table in particular — with full IP addresses, subnet strings, and byte counters — would push the main panel outward and force the whole layout to scroll horizontally including the sidebar.

Wrapped each in `<div class="overflow-x-auto">` so the scrollbar appears inside the card. The Interfaces table's existing wrapper was preserved.

#### 3. Sensor names truncated mid-word
`admin-device-detail.js:769` rendered each sensor's name with inline `white-space: nowrap; overflow: hidden; text-overflow: ellipsis`. Sensors like `PEM1 Fan 4 Speed`, `DTS CPU Core 6 Temp`, `FortiGate-200F PSU Fan` were getting clipped on the 200px-min sensor cards even though wrapping to a second line would have fit. The `title` attribute provided a hover tooltip, but operators were having to hover-and-wait to read every sensor name.

Switched the inline style to `word-break: break-word; overflow-wrap: anywhere; line-height: 1.25` so names wrap cleanly to two lines.

#### 4. License card descriptions could overflow
`admin-device-detail.js:1016` rendered the license description (e.g. `FortiGuard Endpoint Vulnerability Scan and Endpoint Compliance`) inside a flex content child. The parent had `flex: 1; min-width: 0` (correctly) but the description div itself had no `word-break` rule, so very long FortiGuard descriptions could overflow the card horizontally rather than wrapping. Added `word-break: break-word; overflow-wrap: anywhere; line-height: 1.3`.

#### 5. `togglePublicIface` onclick was a (theoretical) XSS via interface name
The "is this a public-facing interface" checkbox at `admin-device-detail.js:565` used:

```js
'<input type="checkbox" ... onclick="window.togglePublicIface(\'' + esc(iface.name) + '\', this.checked)">'
```

`esc()` (defined at `admin-device-detail.js:1689-1694`) HTML-escapes by way of `textContent`/`innerHTML` round-trip, which handles `&`/`<`/`>` but does NOT escape `'` or `"`. So an interface name containing a single quote would terminate the JS string literal and inject arbitrary JS into the onclick. SNMP-sourced names are low risk in practice (every vendor profile generates conventional names like `port1`, `vlan-east-corp`, `wan2`), but the fix is trivial.

Switched to:
```js
'<input type="checkbox" ... data-action="toggle-public-iface" data-iface="' + esc(iface.name).replace(/"/g, '&quot;') + '">'
```

with a new `'toggle-public-iface'` handler registered in the existing `AC.delegateEvent('click', ...)` block. The interface name lives in a `data-*` attribute (attribute-safe escaped) and the handler reads it via `el.dataset.iface` — no JS-string-literal context to escape out of.

### Files
- Modified: `cmd/api/static/css/admin-device-detail.css` — added `.expand-row`, `.expand-content`, `.detail-grid`, `.detail-item`, `.detail-item .label`, `.detail-item .value`, `.iface-chart-container` definitions.
- Modified: `cmd/api/static/js/admin-device-detail.js` — renamed `chart-range-btn` → `range-btn` (2 occurrences, plus restoring the accidentally-mangled `.chart-range-btns` container during global replace), fixed sensor name + license description wrap, switched togglePublicIface onclick to data-action delegation.
- Modified: `web/admin/device-detail.html` — wrapped VPN/Alerts/Ping/HA/SD-WAN/Config-History tables in `<div class="overflow-x-auto">`.

### Audit findings deliberately NOT fixed
The audit also flagged tab a11y (missing `role="tab"`/`aria-selected`), hardcoded hex colors that should be design tokens, breakpoint mismatch (720 vs 768), modal double-scrollbar risk, and the bare `th` selector adding `position: sticky` to every table header even when there's no scrolling container. None of these cause an operator-visible bug today — they're style smell or larger refactors. Tracking separately if needed.

## [0.10.228] - 2026-05-18

### Fixed — same stat-card flex-row bug on admin.html + connection-detail.html
After fixing the visible firmware-string truncation on `/admin/devices/:id` in v0.10.227, the operator asked to check the rest of the admin area for the same bug class. An audit found the identical CSS conflict on two more pages — but the symptom was masked because the content happens to be short numeric counters and byte counts rather than long version strings, so nothing visibly truncated. The layout was still wrong (label sat *beside* value instead of stacked above it) and any future long-string content would have visibly broken in the same way.

#### Pages fixed
- **`web/admin/admin.html`** — local `<style>` block at line 93 declared `.stat-card { background: …; border: …; padding: 16px; }` but didn't set `display`, so the flex-row default from `admin-shared.css:770` leaked through. Affected the dashboard tile grid, the syslog stats grid (line 434), alerts stats grid (line 635), traps stats grid (line 779), and maintenance window stats grid (line 742). Five separate placements of the same broken pattern.
- **`web/admin/connection-detail.html`** — same omission at line 16. Affected the top stat row (Bytes In/Out, Tunnels, Status).

#### Pages NOT fixed (intentionally)
- **`admin.html:703-725` (alert-policies)** — these stat-cards have a `.stat-icon` 📋/🔧/🌐 child plus a `.stat-content` wrapper. They were always meant to render icon-left-of-content, so flex-row IS the correct layout. The `:has(.stat-icon)` exception preserves it.
- **`.expandable-msg` (admin.html:130)** — `cursor: pointer` confirms this is intentional click-to-expand truncation, not the same bug.
- **`.fwmon-stat` (admin-design-system.css:327)** — the newer replacement class already implements the opt-in `.long` modifier pattern for long-string values, working as designed.
- **`probes.html` / `sites.html` / `irc.html`** — render tables with naturally-wrapping cells, no truncating CSS.

#### Approach
Used `:has(.stat-icon)` for the icon-flex exception, which lets one CSS rule cover both layouts without any markup changes. `:has()` is supported in Chrome 105+ / Firefox 121+ / Safari 15.4+ (all shipped by 2023), so it's safe in 2026. Also added `word-break: break-word; overflow-wrap: anywhere;` to `.stat-value` so longer future content wraps inside the card rather than spilling out.

### Files
- Modified: `web/admin/admin.html` — `.stat-card` style now sets `display: block` by default with `:has(.stat-icon)` flex exception, plus value-wrap rules.
- Modified: `web/admin/connection-detail.html` — same pattern applied to this page's inline `<style>` block.

### Why this was worth a separate version
v0.10.227 fixed the visible bug. v0.10.228 fixes the same bug *class* everywhere else it exists so the next person who decides to render a long-string value in a dashboard stat-card doesn't hit it again. Pattern-driven fix rather than symptom-driven.

## [0.10.227] - 2026-05-18

### Fixed — device-detail stat-card labels/values truncated ("FIRM... v7.4.12,build2902,2...")
Operator on `/admin/devices/1` reported the stat cards along the top of the device-detail page were clipping both their labels and their values mid-string. Root cause was two CSS stylesheets fighting on the same selector:

- `cmd/api/static/css/admin-shared.css:770-779` declares `.stat-card { display: flex; align-items: center; gap: 14px; }` — that's the **dashboard** layout where each tile has a `.stat-icon` sibling rendered to the left of its `.stat-content`. Designed for icon-left, text-right.
- `cmd/api/static/css/admin-device-detail.css:48-51` only adds `min-width: 0; overflow: hidden;` and never resets `display` — so on the device-detail page the cards were also `flex-row`, and the `.stat-label` div ended up side-by-side with the value div instead of stacked above it. The whole content area split in half.
- `.stat-card .stat-value` further forced `font-size: 1.4rem; white-space: nowrap; text-overflow: ellipsis;`. CSS specificity (0,2,0) beat the inline Tailwind `text-[0.85rem]` (0,1,0), so the firmware value rendered at 1.4rem instead of 0.85rem and the inline-Tailwind size declared in the markup never won. A long FortiOS build string like `v7.4.12,build2902,250214` couldn't fit at 1.4rem in a half-card width and got truncated to `v7.4.12,build2902,2...`. The label next to it truncated to `FIRM...` for the same reason.

#### Fixes in `admin-device-detail.css`
1. `.stat-card` override now also sets `display: block` and `text-align: center` so cards render as standalone tiles (label-above-value), matching the layout the device-detail HTML was always written for.
2. Default `.stat-value`/`.stat-label` overrides dropped the explicit `font-size` and the `white-space: nowrap; text-overflow: ellipsis` rules.
3. Replaced with two `:where(.stat-card .stat-label)` / `:where(.stat-card .stat-value)` rules carrying the *fallback* font sizes. `:where()` zeroes out the selector's specificity (0,0,0), so any inline Tailwind class on the element (like `text-[0.85rem]` at 0,1,0) wins. Net behaviour:
   - device-detail HTML cards with inline `text-[Nrem]` Tailwind classes now render at the markup-declared size — firmware/AV-sig/IPS-sig version strings fit at 0.85rem with `word-break: break-word` so they wrap inside the card instead of truncating;
   - JS-rendered Security tab cards (`admin-device-detail.js:926-945`) with no inline sizing fall through to the 1.4rem fallback so the "stat hero" numeric look is preserved.
4. Wrap behaviour: every `.stat-value` now has `word-break: break-word; overflow-wrap: anywhere;` so values exceeding the card width wrap to a second line rather than ellipsizing. Better for diagnostic strings — full firmware version visible without a tooltip.

### Files
- Modified: `cmd/api/static/css/admin-device-detail.css` — `.stat-card` override now resets display, drops nowrap/ellipsis from values and labels, fallback font sizes moved into `:where()` blocks.

### Why this only showed up now
The same flex-row CSS rule has been on the page for several minor versions, but it became visibly broken only after the device-detail page started receiving longer string values (full FortiOS build strings, AV/IPS signature versions with dates). Short numeric values like CPU%/Sessions count happened to fit even in the cramped half-width layout. The cards were always laid out wrong; the truncation was the first thing the operator could see.

## [0.10.226] - 2026-05-18

### Fixed — SMTP auth: raw ciphertext sent as password (the REAL cause of every 535 in this thread)
Every theory in v0.10.222–v0.10.225 about why SMTP auth was failing — LOGIN vs PLAIN, username format, whitespace, MITM, Dovecot's `(reason unavailable)` — was working around the symptom, not the cause. The bug was on our side, in two adjacent lines of `UpdateSettings` that the user kept asking me to find.

#### Root cause: `IsSecret` was never persisted on save
`UpdateSettings` in `internal/api/handlers/handlers_settings.go` did this:

```go
existing := models.SystemSetting{Key: s.Key}
h.db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: s.Key})
// FirstOrCreate populates `existing` from the DB row, or zero-values if new
if !s.IsSecret || s.Value != "" {
    existing.Value = s.Value         // ciphertext written
    existing.Label = s.Label
    existing.Category = s.Category
    h.db.Gorm().Save(&existing)      // IsSecret NEVER copied — stays at its zero value
}
```

`s.IsSecret = true` was set on the request struct, the value was encrypted with `EncryptField` → `"{enc}<base64-ciphertext>"`, and then both got handed to `Save(&existing)` — but `existing.IsSecret` was never set from `s.IsSecret`. So the persisted row was `{ Value: "{enc}AAAA...base64...", IsSecret: false }`. On every save thereafter the same thing happened — fresh ciphertext, `IsSecret` still `false`.

#### Why this caused exactly the 535 the operator was seeing
`getNotificationSetting` gated decryption on `IsSecret`:

```go
if s.IsSecret { return h.db.DecryptField(s.Value) }
return s.Value   // <-- raw "{enc}<base64>" returned to caller
```

So when `runSMTPDiagnostic` called `getNotificationSetting("smtp_password")`, it got back the literal string `"{enc}AAAA...base64..."` and passed it to `smtp.PlainAuth("", username, password, host)` as the password. Postfix forwarded that string verbatim over the Dovecot SASL socket. Dovecot's SQL passdb compared it against the actual stored password column for `support@technicallabs.org` and (correctly) returned `Password mismatch`. IMAP login from the operator's webmail worked because the operator typed the real password into the browser — only firewall-mon was sending ciphertext.

The "different bytes every save" observation matches the symptom: AES-GCM uses a random nonce per encrypt, so each save produced different ciphertext, all of which looked nothing like the real password.

#### Secondary bug — real alert emails were broken in the same way
`internal/alerts/alerts.go:443-444` populated `am.config.Alerts.SMTPPassword` with `s.Value` directly, no decryption. Every CPU/memory/disk/VPN/interface-down alert email since the encrypted-storage migration was sending ciphertext as the password to the SMTP server — silently failing in production, never reported because the operator wasn't watching alert-email delivery. Fixed.

#### Tertiary bug — settings page was leaking ciphertext back to the UI
`GetSettings` masked secret values based on the row's `IsSecret` column. Because the column was wrong, the mask never fired for `smtp_password`, and a GET `/admin/api/settings` response was returning `"{enc}<base64-ciphertext>"` as the value for `smtp_password`. The settings UI's JS subsequently treated that as the existing-value placeholder and rendered it back into the password input field. Not exploitable on its own (AES-256-GCM ciphertext is useless without the key), but a correctness leak.

### Fixes
1. **`UpdateSettings`** — add `existing.IsSecret = s.IsSecret` immediately before `Save(&existing)`. The one missing line. (`handlers_settings.go:233-241`)
2. **`getNotificationSetting`** — drop the `IsSecret` gate. `DecryptField` is idempotent: it checks for the `{enc}` prefix internally and returns the input unchanged for plaintext values, so calling it unconditionally is safe for every settings key (`crypto.go:57-60`). This makes the read path robust to *any* existing DB row whose `IsSecret` flag is wrong — no DB migration required for the auth to start working. (`handlers_settings.go:264-282`)
3. **`GetSettings`** — mask based on a package-level `settingsSecretKeys` map (the static source of truth for which keys are secret) rather than the row's `IsSecret` column. Same robustness rationale. (`handlers_settings.go:24-58`)
4. **`alerts.go`** — wrap `s.Value` in `am.db.DecryptField(s.Value)` for the `smtp_password` case so real alert emails get the plaintext password. (`alerts.go:443-460`)

### Why every prior version in this thread didn't fix it
- **v0.10.220-221** (verbose SMTP trace): exposed the failure to the UI but couldn't see *why* it failed because the server's reply was `(reason unavailable)`.
- **v0.10.222** (LOGIN/CompoundAuth): right answer to a different question — server actually offered PLAIN, which the stdlib had supported all along.
- **v0.10.223** (username override + length leak): all wrong, reverted in v0.10.224.
- **v0.10.224** (MITM check + Dovecot hint): fixed a real (latent) security bug and pointed the operator at the right log, but the underlying password-bytes-don't-match problem was never going to surface without reading our own storage path.
- **v0.10.225** (admin SPA navigation): unrelated, fixed in passing.

The operator was right to push back with "please don't assume — research the proper way." All the SMTP-side theories were avoiding the simpler hypothesis that *our own code was sending the wrong bytes*, and a 30-line agent investigation of the storage path found the missing-line bug in minutes.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — extracted `settingsSecretKeys` to package scope, made `GetSettings` mask off it, added `existing.IsSecret = s.IsSecret` in `UpdateSettings`, made `getNotificationSetting` always-decrypt.
- Modified: `internal/alerts/alerts.go` — `RefreshThresholds` decrypts `smtp_password` before storing in `config.Alerts.SMTPPassword`.

### Operator action required after deploying
None — the always-decrypt read path makes the SMTP test work immediately against existing `{enc}`-prefixed rows. The first re-save of `smtp_password` after deploy will also write `is_secret=true` correctly, so the settings page stops returning ciphertext to the browser. No DB migration script needed.

## [0.10.225] - 2026-05-18

### Fixed — admin SPA navigation: detail-page clicks lost in interceptor + two related bugs
User reported: clicking a device row at `/admin/devices` changes the URL bar to `/admin/devices/<id>` but the page never actually loads the detail view — it stays on the devices list. A scan of the admin area click/history surface turned up the same bug class affecting `/admin/connections/<id>` and a pair of related navigation bugs (one latent precedence error, one missing handler). All three fixed here.

#### Primary bug — interceptor swallows deep `/admin/*` paths
The global SPA click interceptor in `cmd/api/static/js/admin-main.js` extracted only the FIRST path segment under `/admin/` to decide whether the click should be intercepted:

```js
var seg = url.pathname.replace(/^\/admin\/?/, '').split('/')[0];
if (!SPA_PAGES[seg || 'dashboard']) return;
```

For a click on `/admin/devices/123` this yields `seg='devices'`, which IS in SPA_PAGES — so the interceptor called `ev.preventDefault()`, pushed the URL onto history, and ran `loadPageData('devices')`. That last call reloads the devices LIST. So the URL bar updated, the browser was blocked from following the link, and the user saw the same list they were already on. The detail page (a separate HTML document — `device-detail.html` served by `admin.GET("/devices/:id", ...)` in `cmd/api/main.go:409`) never got a chance to load.

**Fix:** count the segments under `/admin/` and bail out as soon as we see more than one. The browser then navigates natively, the backend serves the detail HTML, the page loads correctly. The interceptor's job is only top-level tab navigation (`/admin/devices`, `/admin/syslog`, etc.) — deep paths are *not* part of the SPA.

This same path affected every detail-page link in the app:
- Device-name links in the devices table (`admin-main.js:586`)
- Device-name links in the interfaces table (`admin-main.js:698`)
- "Details" links in both connections tables (`admin-main.js:840` and `931`)
- `<a href="/admin/connections/${id}">Full Page →</a>` in `diagram-panels.js:135`
- `<a href="/admin/devices/${id}">` device chips in tunnel rows (`diagram-panels.js:492`)
- `AC.deviceLink()` / `AC.connectionLink()` builders in `admin-common.js:212/220`

All of these go through the same interceptor and were broken in the same way — all fixed by the same one-line change.

#### Latent bug — precedence error on the `/admin/api/` early-return
Line 3655 read:

```js
if (!url.pathname.indexOf('/admin/api/') === 0 && url.pathname.indexOf('/admin/') !== 0) return;
```

JavaScript operator precedence makes this `(!url.pathname.indexOf('/admin/api/')) === 0 && ...`. The unary `!` runs first: it converts the indexOf integer to a boolean, so the left side is always either `(true === 0)` or `(false === 0)` — both are `false`. `false && X` is also `false`, so the early return *never fired*. The intent was clearly two checks: skip if the URL is an admin API call, and skip if it isn't an admin page at all. Rewritten as two separate `return` statements to make the logic explicit.

In practice this bug was latent because no `<a href="/admin/api/...">` link ever shows up in the rendered DOM — the API surface is fetched via XHR. But it's a footgun if any future code adds such a link.

#### Missing handler — `popstate` listener
No code listened for `popstate`, so browser back/forward inside the SPA changed the URL bar but did not refresh the view. Example: user opens `/admin/devices`, clicks Syslog in the sidebar (push to `/admin/syslog`), clicks back — URL went back to `/admin/devices` but the syslog table stayed visible.

Added a listener that re-runs `activateTabFromUrl()` (which switches the active page DOM class) and then calls `loadPageData(page)` for non-analytics pages or `analyticsPages[page].reseedFromURL()` for the analytics pages (syslog / alerts / flows / traps) so their filter chips and query state catch up from `window.location.search`.

This does NOT apply to back-navigation from a detail page (`/admin/devices/123` → `/admin/devices`) because those are cross-document — the browser does a full load of admin.html, popstate doesn't fire, and the initial `activateTabFromUrl()` + `loadPageData()` call at the bottom of the IIFE handles it. The new listener only matters for within-SPA history transitions.

### Files
- Modified: `cmd/api/static/js/admin-main.js` — three-line fix to the interceptor's segment check, two-line fix to the precedence error, ~12-line `popstate` listener.

### Why this matters
The bug class is "SPA interceptor too aggressive" — any pattern that takes over every `/admin/*` link click is one bad segment-check away from breaking detail-page navigation site-wide. Fixing the check at the source means every existing detail link works, and any new detail-page routes added in the future automatically work without each one needing manual exemption.

## [0.10.224] - 2026-05-18

### Reverted + replaced — research-backed SMTP test fixes
User pushed back on v0.10.223 with "please don't assume — research the proper way for this to be implemented." Four research agents went off and read primary sources (Postfix `smtpd_sasl_glue.c`, Dovecot auth-protocol docs, RFC 4954, swaks reference manual, Mailcow/Mailu/Postal docs, OWASP A07). Findings reversed three of the five decisions shipped in v0.10.223 and exposed a security bug in v0.10.222's `LoginAuth`. This entry rolls back the wrong parts and replaces them with research-backed equivalents.

#### Security fix — `LoginAuth` missing MITM check (regression introduced in v0.10.222)
The stdlib `smtp.PlainAuth` validates `server.Name == host` in its `Start()` method before sending credentials. Without that check, a MITM with a redirected DNS / connection can terminate the TLS handshake on a *different* server that also advertises LOGIN and harvest the password under that identity. My `LoginAuth` in v0.10.222 was missing this gate — it only checked `server.TLS`. Fixed: `LoginAuth` now takes a `host` parameter and refuses if `server.Name != host`. `CompoundAuth` plumbs `host` through to `LoginAuth`. Matches stdlib `PlainAuth` semantics exactly.

#### Reverted — username override input on test page (v0.10.223 mistake)
No reputable mail admin tool (Mailcow, Mailu, Postal, swaks) exposes a username-only override field. The pattern is an outbound credential-stuffing oracle: an authenticated admin (or anyone who CSRFs the endpoint) can probe arbitrary username/saved-password pairs against an external SMTP server and read 235 vs 535 from the response. OWASP A07:2025 calls this out. If we ever need ad-hoc credential testing, the right shape is an explicit "test with ad-hoc credentials" mode that takes BOTH fields, rate-limits, and audit-logs — not a half-override pairing a typed name with the stored secret. Removed the input from the UI, removed the JSON field from the request struct, removed the `strings.TrimSpace` of the override.

#### Reverted — `username_len` / `password_len` in the test response (v0.10.223 mistake)
swaks' `--auth-hide-password` documented stance is "keep credential data out of transcripts entirely." Even for an authenticated admin session, password byte length is information disclosure that narrows the search space for anyone who later scrapes the response from browser history / a proxy log / a forwarded screenshot. Dropped both fields from the JSON, dropped the rendering in `renderSMTPTrace()`.

#### Replaced — silent password TrimSpace → save-time warning (better signal)
v0.10.223 silently `TrimSpace`d the saved password and tried to make the change visible via `password_len` in the test response. That's the wrong moment AND the wrong vector. New behavior: `UpdateSettings` still trims, but if the trim actually changed the value it appends a warning string to the JSON response. `saveSettings()` in the admin JS pops each warning as a separate red toast. The signal arrives at the moment the operator can act on it (right after they pasted the password) instead of being deferred to the next test run. Non-secret fields (`smtp_host` / `smtp_username` / `smtp_from` / `smtp_to`) also produce save-time warnings when their trim actually does work.

#### Added — operator-facing remediation hint when AUTH fails
Per Postfix source (`src/smtpd/smtpd_sasl_glue.c`), `(reason unavailable)` is Postfix's fallback string emitted when its SASL plugin returned FAIL with an empty reason. Per Dovecot's auth protocol docs (`/main/developers/design/auth_protocol.html`), Dovecot **deliberately** omits the `reason=` field on FAIL for the common failure modes — "MUST NOT reveal exact failure reasons like user not found vs. password mismatch." So `(reason unavailable)` on the wire means *the real diagnostic is always in Dovecot's auth log on the mail server, never on the SMTP transcript*. New `authFailureHint()` helper detects the empty-reason 535 pattern (and a few others — generic 535, `504 unrecognized authentication`) and attaches an operator-facing "Next step:" hint to the failed auth row. For the Postfix+Dovecot case the hint walks the operator through `journalctl -u dovecot --since '5 min ago'` and tells them what to look for. The new `Hint` field is rendered as a blue-bordered call-out below the error row.

#### Added — cert NotAfter in TLS step (industry standard)
Mailcow / Mailu / Mail-in-a-Box admin UIs all surface certificate expiry in their SMTP test output. v0.10.220-223 only showed TLS version / cipher / CN. Now the TLS detail line is e.g. `TLS 1.3, TLS_AES_128_GCM_SHA256, cert CN=mail.example.com, expires 2026-08-14`. Cert-expiry-in-N-days is a top-3 cause of "tests pass today, fail in production next week" so this rounds out the swaks-style transcript the diagnostic was modelled on.

#### What did NOT change
- LOGIN step-counter implementation in `LoginAuth.Next()` — research confirmed this matches `wneessen/go-mail` (the canonical modern Go mail library); ignoring the prompt text is exactly correct per the (expired) `draft-murchison-sasl-login-00`.
- PLAIN-before-LOGIN selection order in `CompoundAuth` — matches industry convention.
- The per-step transcript UI shape — research validated it as the swaks/Mailcow standard.

### Files
- Modified: `internal/notifier/smtp_auth.go` — `LoginAuth` signature now takes `host`; `Start()` validates `server.Name == a.host`; `CompoundAuth` plumbs host through.
- Modified: `internal/api/handlers/handlers_settings.go` — removed `UsernameOverride` field, removed `username_len`/`password_len` from response, removed silent `TrimSpace` on `smtp_password` (replaced with save-time warning), added `authFailureHint()` and `tlsLeafSummary()` helpers, added `Hint` field to `smtpTraceStep`, switched `UpdateSettings` response to `SuccessResponse(gin.H{message, warnings})`.
- Modified: `web/admin/admin.html` — removed the username override input + its explainer text.
- Modified: `cmd/api/static/js/admin-main.js` — `testEmail()` no longer sends `username`, `renderSMTPTrace()` no longer shows length cells but does render the new `hint` block, `saveSettings()` surfaces server-side warnings as toasts.

### Sources researched
- Postfix `smtpd_sasl_glue.c` and `xsasl_dovecot_server.c` (vdukhovni/postfix mirror)
- Dovecot auth protocol design doc (`doc.dovecot.org/main/developers/design/auth_protocol.html`)
- Dovecot Postfix-SASL howto (`doc.dovecot.org/main/howto/sasl/postfix.html`)
- Postfix SASL_README (`postfix.org/SASL_README.html`)
- RFC 4954 + draft-murchison-sasl-login-00
- swaks reference manual (`jetmore.org/john/code/swaks/latest/doc/ref.txt`)
- Mailcow relayhost docs, WP Mail SMTP debug events doc, SendGrid 535 troubleshooting
- OWASP A07:2025 (Authentication Failures), OWASP Authentication Cheat Sheet
- `wneessen/go-mail` LOGIN auth implementation (the canonical modern Go SMTP library)

## [0.10.223] - 2026-05-18

### Added — SMTP test diagnostics for opaque 535 auth failures
After the v0.10.222 LOGIN/CompoundAuth fix landed, the operator's verbose-test trace showed the diagnostic reaching AUTH cleanly (TLSv1.3 handshake good, mechs `PLAIN LOGIN` advertised, PLAIN selected) and then failing with `535 5.7.8 Error: authentication failed: (reason unavailable)`. The mail server's reason-unavailable reply gives operators nothing to act on, and reproducing on the backend is exactly the friction the verbose test was supposed to remove. v0.10.223 adds three orthogonal diagnostics so each common cause can be ruled out without backend shell access.

#### Username override (one-shot, test-only)
SMTP card now has a second free-form input next to the recipient override: `username` (override `smtp_username`). The `/api/settings/test-email` request body accepts an optional `"username"` field; when present, `runSMTPDiagnostic` uses that value for AUTH and reports it back via `auth_method` and the new `username` metadata field, *without* persisting anything to `system_settings`. Lets the operator try `support` vs `support@example.com` (and other SASL bare-name vs full-address variants) against a Postfix/Dovecot or Cyrus saslauthd backend in a single click — the common case behind a `(reason unavailable)` 535 when the password is known good.

#### Length metadata in the trace summary
Response now includes `username` (echo, after server-side TrimSpace), `username_len` (byte length of the effective username), and `password_len` (byte length of the *decrypted* password actually handed to the SMTP client). Rendered in the trace metadata row as `User: support@example.com (24 B)` and `Pwd len: 18 B`. Operators who know what their password length *should* be can spot a trailing-space corruption that the masked `********` rendering hides — a length-mismatch of one byte is the cheapest way to localise the failure to the password storage path versus the wire protocol.

#### Defensive TrimSpace on save (host/username/from/to/password)
Updated `UpdateSettings` to call `strings.TrimSpace` on `smtp_host`, `smtp_username`, `smtp_from`, `smtp_to`, and `smtp_password` before validation/encryption. Copy-paste from webmail settings pages and password managers regularly drags a trailing space; a single trailing space on a username sent to Cyrus/Dovecot SASL is exactly the kind of input that produces `(reason unavailable)` rather than a useful error. Combined with the length metadata above, an operator who re-saves their existing settings will see `password_len` change in the next test if a trim actually removed something — closing the loop on the "did the trim fix it" question.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — `UsernameOverride` parsing in `runSMTPDiagnostic`, `username`/`username_len`/`password_len` added to JSON response, `strings.TrimSpace` applied to the five SMTP settings in `UpdateSettings`.
- Modified: `web/admin/admin.html` — second free-form input (`#test-email-username-override`) plus operator-facing note explaining that overrides are one-shot.
- Modified: `cmd/api/static/js/admin-main.js` — `testEmail()` packs both overrides into the request body when present; `renderSMTPTrace()` renders `User:` and `Pwd len:` cells in the metadata row when the server supplies them.

### Why this matters
A `535 5.7.8 (reason unavailable)` from Postfix/Cyrus is almost never the password itself — by the time AUTH PLAIN reaches the server, the wire format and TLS state are already validated. The remaining suspects are username format (bare name vs `user@domain`), invisible whitespace in either credential, and storage-side encryption drift. Each diagnostic in this bundle targets exactly one of those without requiring an SSH session into the mail server, so the operator can resolve the issue from the admin UI alone.

## [0.10.222] - 2026-05-18

### Added — SMTP LOGIN auth + fixed post-STARTTLS state check (Bundle J)
Two related fixes after operator testing of the verbose SMTP diagnostic shipped in v0.10.220-221 revealed both a self-inflicted bug in the test path and a gap in the production notifier path: many Postfix/Cyrus/Dovecot submission servers advertise only LOGIN on port 587, and Go's stdlib `net/smtp` ships PLAIN but not LOGIN.

#### J1 — Authoritative TLS state tracking
The v0.10.221 hotfix dropped a redundant `Hello()` call but the AUTH pre-check still misreported `STARTTLS not advertised` after a *successful* STARTTLS upgrade. RFC 3207 §2 is explicit that a server MUST NOT advertise STARTTLS again once the connection is encrypted, so `client.Extension("STARTTLS")` returning false post-upgrade is correct server behavior — the test code was the one drawing the wrong conclusion. New `negotiatedTLS` boolean tracks the actual encryption state across both the implicit-TLS (port 465) and STARTTLS (port 587/25) paths, and the AUTH guard reads from it rather than re-querying the extension list. Error message reworded to be specific about both paths.

#### J2 — LOGIN auth mechanism + auto-selection
New `internal/notifier/smtp_auth.go`:
- **`LoginAuth(username, password) smtp.Auth`** — implements RFC 4954 LOGIN. Doesn't try to parse the server's prompt text (which varies — "Username:", "User Name", base64-encoded localised strings, …); instead tracks which step it's on internally (step 0 = username, step 1 = password). Mirrors `smtp.PlainAuth`'s TLS-required guard.
- **`CompoundAuth(username, password, host) smtp.Auth`** — inspects `server.Auth` in `Start()` and picks PLAIN (preferred) or LOGIN based on what's advertised. Returns a clear error when neither is offered. Designed to be a drop-in replacement for `smtp.PlainAuth` anywhere in the codebase. Exposes `ChosenMechanism()` for trace-time reporting.

Wired into both code paths:
- **Notifier** (`internal/notifier/notifier.go`): both `smtp.PlainAuth` call sites — the per-alert email path and the digest email path — now use `CompoundAuth`. Real alert emails to LOGIN-only servers work without operator reconfiguration.
- **Verbose test** (`internal/api/handlers/handlers_settings.go`): `runSMTPDiagnostic` uses `CompoundAuth` and reports the chosen mechanism in the trace row's detail + response text — operator sees `LOGIN auth as support@example.com` and `accepted (mechs offered: PLAIN LOGIN; selected: PLAIN)` instead of always `PLAIN auth as …`.

### Files
- New: `internal/notifier/smtp_auth.go` — LOGIN + CompoundAuth implementation.
- Modified: `internal/notifier/notifier.go` — both `smtp.PlainAuth` call sites switched to `CompoundAuth`.
- Modified: `internal/api/handlers/handlers_settings.go` — `negotiatedTLS` tracking + CompoundAuth in `runSMTPDiagnostic` + `authMethodLabel` rewritten to reflect auto-selection.

### Why this matters
The operator's first verbose-test trace (post-v0.10.221) failed at AUTH with `unencrypted connection` even though the STARTTLS step itself reported a clean TLSv1.3 handshake with a valid certificate — the diagnostic was lying about its own previous step. After J1 the AUTH guard reads from the same flag that gets set when the upgrade actually succeeds, so the report is internally consistent. After J2 the test (and every real alert email) auto-picks PLAIN or LOGIN depending on what the server offers; a mailserver advertising only LOGIN no longer needs a code change.

## [0.10.221] - 2026-05-18

### Fixed — SMTP test STARTTLS double-EHLO bug
The verbose SMTP test shipped in v0.10.220 (bundle I) had a self-inflicted bug: `runSMTPDiagnostic` called `smtp.Client.Hello("firewall-mon-test")` once before STARTTLS and again after the TLS upgrade. The Go stdlib's `smtp.Client.Hello` is documented to be callable at most once — any subsequent call returns `"smtp: Hello called after other methods"`. After the STARTTLS step the test was failing at the second Hello, never reaching AUTH, and masking the actual credential / mechanism issue the operator was trying to diagnose.

Fix: drop the explicit second `Hello()` after `StartTLS`. The stdlib's `StartTLS` already re-issues EHLO internally over the encrypted channel, using the local name captured by the first `Hello()` call. The trace now lands on AUTH where the real failure (if any) actually lives.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — removed post-STARTTLS `client.Hello()` call, expanded comment explaining the stdlib's once-only semantics.

## [0.10.220] - 2026-05-18

### Changed — verbose SMTP test diagnostic (Bundle I)
The previous "Send Test Email" button on Settings ran `smtp.SendMail` and returned a single opaque success/failure message. Operators with a failing setup had to grep server-side Postfix/Exchange logs to see which step actually broke. After bundle I the test page returns a full step-by-step transcript of the SMTP conversation, with timing, TLS details, and the server's own response to each verb.

#### Backend (`internal/api/handlers/handlers_settings.go`)
- `TestEmail` replaced with `runSMTPDiagnostic` plus a thin handler wrapper. The diagnostic dials, optionally wraps for implicit TLS on port 465, reads the greeting, sends EHLO, negotiates STARTTLS on 587/25 if advertised, sends EHLO again over TLS, runs AUTH PLAIN if `smtp_username` is set, then MAIL FROM, RCPT TO, DATA, body, and QUIT. Each step records:
  - `step`: short verb name (`connect` / `greeting` / `ehlo` / `starttls` / `auth` / `mail-from` / `rcpt-to` / `data` / `quit`)
  - `detail`: what we tried (`PLAIN auth as support@example.com (server advertised mechs: PLAIN LOGIN)`)
  - `response`: server response or extracted info (`TLSv1.3, TLS_AES_128_GCM_SHA256, cert CN=mail.example.com`)
  - `status`: `ok` / `skipped` / `fail`
  - `error`: present only on `fail` — the raw error string from the SMTP stack or stdlib
  - `duration_ms`: wall-clock time for the step
- New optional `{"to": "alt@example.com"}` body param to override the recipient for a one-off test without changing the saved `smtp_to` setting.
- AUTH step has an explicit early-fail path when the server doesn't advertise STARTTLS and we're not on the implicit-TLS 465 port — the stdlib's generic "unencrypted connection" error is rewritten to a clearer "PLAIN auth refused: connection is not encrypted (server didn't advertise STARTTLS)" so an operator knows whether the failure was credentials vs. transport.
- TLS state pulled via `smtp.Client.TLSConnectionState()` (Go 1.20+) so the trace includes the negotiated version, cipher suite, and server certificate CN.

#### Frontend (`web/admin/admin.html`, `cmd/api/static/js/admin-main.js`)
- Settings → SMTP card now has a recipient-override input next to the Send Test Email button. Leave blank to use the configured `smtp_to`; useful for "send the test to me first" workflows without rewriting the saved setting.
- New `renderSMTPTrace(host, data)` JS helper paints a table: each row is `[status pill] step | action + server response + error | duration`. Status pill is green `OK`, gray `SKIP`, or red `FAIL`. Failure rows highlight the error inline with a red left border so the eye lands on it first. A summary line above the table shows host:port, from, to, auth method, and total wall time.

### Files
- Modified: `internal/api/handlers/handlers_settings.go` — `runSMTPDiagnostic`, `smtpTraceStep`, `tlsVersionName` / `tlsCipherName` / `tlsLeafSubject`, `authMethodLabel`, expanded `TestEmail` handler, new imports (`crypto/tls`, `errors`, `net`).
- Modified: `cmd/api/static/js/admin-main.js` — `testEmail()` + `renderSMTPTrace()`.
- Modified: `web/admin/admin.html` — recipient-override input + `#test-email-result` rehosted as a div.

### Why this matters
The user reported a failing SMTP setup and shared a Postfix log fragment ending after the TLS handshake — without further log lines (which Postfix only emits at a later stage) the failure was invisible from the admin UI. The verbose trace surfaces the exact verb that failed and the server's response, so the next time a test fails the operator sees something like:
```
FAIL  auth   PLAIN auth as support@example.com (server advertised mechs: PLAIN LOGIN)
             error: 535 5.7.8 Error: authentication failed: …
```
…directly on the page, with no log-grepping required.

## [0.10.219] - 2026-05-18

### Added — API versioning + polish (Bundle H: H1 + H2 + H3)
Closes the deferred-items list. One forward-looking infrastructure change (API versioning lane), one UX polish (no-reload navigation), one small bug fix (IPv6 host:port).

#### H1 — `/api/v1/` aliasing (forward-compat lane)
- New path-rewrite middleware in `cmd/api/main.go` aliases `/api/v1/*` → `/api/*` and `/admin/api/v1/*` → `/admin/api/*`. Implemented as a single `router.Use(...)` block that mutates `c.Request.URL.Path` before route matching — no per-route duplication, no redirect roundtrip, no measurable overhead.
- The canonical paths remain `/api/*` and `/admin/api/*`. The admin JS and the Firewall-Collector probe binary keep working unchanged.
- The v1 aliases give us a clean upgrade lane: when a future breaking API change ships, we add `/api/v2/*` alongside the existing routes and operate both for a deprecation window. New external consumers can adopt `/api/v1/` today knowing the v1 contract is stable.

#### H2 — SPA-aware filter-link click interception
- The cross-page filter links added in bundles E and G (`/admin/alerts?device_id=42`, `/admin/syslog?search=10.0.0.5`, etc.) used to do a full page reload when clicked from inside the admin SPA. Bundle H2 intercepts those clicks and applies the filter via `history.pushState` + the new `reseedFromURL` helper exposed by `FwmonControls.attachAnalyticsPage`, completely avoiding the reload.
- Modifier-key clicks (Ctrl/Cmd-click for new tab, Shift-click for new window, middle-click) bypass the handler so the multi-tab triage flow still works — operators can fan out a triage session into multiple tabs exactly as before.
- Cross-page clicks (e.g. operator is on dashboard, clicks a link to `/admin/alerts?…`) tab-switch in place via the same path as the sidebar nav-item clicks, then run `loadPageData` which kicks off the analytics-page wiring that reads filter params from the URL on init. No reload either.
- Same-page clicks (operator already on `/admin/syslog`, clicks a new syslog filter) re-seed the existing analytics-page handle from the URL and refresh — fastest path, doesn't re-create the page DOM at all.
- Device-detail / connection-detail / probe / IRC / other separate-document pages are *not* intercepted — those are real page navigations and full reloads are correct.

#### H3 — IPv6 `host:port` fix in `TestProbeConnection`
- `handlers_probes.go:356` previously formed the dial address with `fmt.Sprintf("%s:%d", host, port)`. For an IPv6 listen address this produces `2001:db8::1:9876` instead of the bracketed `[2001:db8::1]:9876`, which `net.DialTimeout` would parse as a different IP entirely (treating the trailing `:9876` as an extra hextet).
- Replaced with `net.JoinHostPort(host, strconv.Itoa(port))` which handles both IPv4 and IPv6 correctly. Dropped the now-unused `fmt` import.

### Files
- Modified: `cmd/api/main.go` — `/v1/` rewrite middleware + `strings` import + version.
- Modified: `cmd/api/static/js/admin-controls.js` — `reseedFromURL` on the analytics-page handle.
- Modified: `cmd/api/static/js/admin-main.js` — SPA link interceptor.
- Modified: `internal/api/handlers/handlers_probes.go` — `net.JoinHostPort`; `fmt` import removed.

### Deferred-items inventory cleared
After this bundle, every concrete item from the post-sweep audit (noisy-device leaderboard, snooze alerts, VPN remote-end linkification, SPA-aware filter links, IPv6 host:port, API versioning lane) has shipped. The remaining open recommendations are all cosmetic / large-diff items I'd only do on request: the codebase-wide `interface{}` → `any` migration, the `infertypeargs` and `minmax` style suggestions surfaced by the linter, and the `SyslogSummary`/`FlowRollup` raw endpoints (no consumer).

## [0.10.218] - 2026-05-18

### Added — picked up deferred items from Bundles E and F (Bundle G: G1 + G2 + G3)
After the six-bundle whole-admin sweep wrapped, this bundle picks up three features that were unblocked by the backend work in D (v0.10.217) but never built, plus one new operator workflow (snooze alerts) that needed its own backend change.

#### G1 — Noisy-device leaderboard widget
- New "Noisy Devices" card on the dashboard ranks devices by recent alert + syslog volume.
- Window selector: 1 h / 6 h / 24 h (default) / 7 d. Persisted in `localStorage` (`fwmon-noisy-window-hours`).
- Top 10 by total volume; each row shows device name (links to detail), alert count (links to filtered `/admin/alerts`), syslog count (links to filtered `/admin/syslog`), and a width-proportional volume bar.
- Card auto-hides when no device has any messages — no dead chrome.
- Uses the `?device_id=N` filter on `/api/syslog/stats` and `/api/alerts/stats` added in v0.10.217 (D4). One stats call per device, fired in parallel; bounded by the existing 1000-device dashboard cap.

#### G2 — Snooze alerts (backend column + endpoint + UI)
- New columns on `models.Alert`: `SnoozedUntil *time.Time` (indexed), `SnoozedBy string`, `SnoozedReason string`. GORM auto-migrate adds them on first start.
- Two new endpoints: `POST /admin/api/alerts/:id/snooze` (body: `{hours, reason}`) and `POST /admin/api/alerts/:id/unsnooze`. Hours are clamped to `[1, 720]` server-side.
- `GetAlerts` listing now filters out currently-snoozed alerts by default. New `?include_snoozed=true` query param overrides for views that need to see them. Refactored filter logic into a shared `applyAlertFilters` helper so the listing + count paths stay in sync.
- New `SnoozeAlert` and `UnsnoozeAlert` methods on `*Database`.
- Alert-detail modal: open alerts now show both **Acknowledge** and **Snooze** buttons. Snoozed alerts show a "SNOOZED until …" badge + **Unsnooze** button, with optional `snoozed_by` / `snoozed_reason` audit detail underneath.
- Alerts table: snoozed rows render a `SNOOZED` badge in the status column (tooltip reveals wake-up timestamp).
- Snooze prompt uses `window.prompt()` — deliberate friction-free flow for a self-serve action; a dedicated modal felt overkill.

#### G3 — VPN remote-end device linkification
- New computed `VPNStatus.RemoteDeviceID *uint` field (omitempty + `gorm:"-"`). Populated by `GetLatestVPNStatuses` using the existing remote-IP peer-matching pass already running for subnet cross-fill — zero extra queries.
- Two-pass resolution: first pass populates during the subnet cross-fill loop; new second pass resolves remote_device_id for tunnels that didn't need a subnet fix.
- Device-detail VPN tab: when `remote_device_id` is set, the `remote_ip` cell links directly to the peer's `/admin/devices/:id` page instead of `/admin/syslog?search=<ip>`. Tooltip clarifies "resolved by RemoteIP match". Falls back to the syslog cross-pivot when no peer match is known.

### Files
- Modified: `internal/models/models.go` — `VPNStatus.RemoteDeviceID`, `Alert.SnoozedUntil/By/Reason`.
- Modified: `internal/database/database.go` — `RemoteDeviceID` population (2 pass), `SnoozeAlert` / `UnsnoozeAlert` methods.
- Modified: `internal/api/handlers/handlers_analytics.go` — `applyAlertFilters` helper, `SnoozeAlert` / `UnsnoozeAlert` handlers, `gorm.io/gorm` + `time` imports.
- Modified: `cmd/api/main.go` — 2 new alert routes, version bump.
- Modified: `cmd/api/static/js/admin-main.js` — `renderNoisyDevices` + dashboard hook, snooze UI in alert-detail modal + alerts table, `showSnoozePrompt` / `unsnoozeAlert` handlers + delegated actions.
- Modified: `cmd/api/static/js/admin-device-detail.js` — VPN remote-end device linkification with syslog fallback.
- Modified: `web/admin/admin.html` — new `#noisy-devices-card` section in dashboard.

### Why this matters
Three lingering items from the original sweep now ship in one tidy bundle. The leaderboard uses backend filters that have been waiting since D4 with no consumer; the VPN remote-end linkification closes the second half of the "click through to the peer" affordance that E2 only half-resolved; snooze gives operators a third state ("not relevant right now, but still real") between "acknowledge" and "ignore".

## [0.10.217] - 2026-05-18

### Changed — admin-wide backend consistency pass (Bundle D: D1 + D2 + D3 + D4)
Sixth and final commit of the "improve the whole admin area" sweep. The previous five bundles touched almost exclusively frontend code; this one normalises the API surface so subsequent work — and external callers — see a consistent contract.

#### Audit
One parallel sub-agent inventoried every backend inconsistency that surfaced during bundles A-F. Findings: 5 handlers still inline-parsed `hours` with different caps and error semantics; 8 list endpoints called `.Find(...)` with no `.Limit(...)`; the probe-facing endpoints disagree on whether errors return `{"error":…}` or `{"message":…}`; `VPNStatus` had no field to indicate when a currently-down tunnel was last up; 3 of 4 `/stats` endpoints accepted no `device_id` filter.

#### D2 — Unified range parsing
- Every handler that took `?hours=` now delegates to `httputil.ParseHours` (default 24, hard cap 8760). Migrated `GetSystemStatusHistory`, `GetConnectionEvents`, `GetConnectionFlows`, and `GetProcessStats`. Endpoints with a tighter business cap (720 h, 30 days) still apply that cap by a single `if hours > 720` line after the helper, so the canonical parse + 8760 ceiling is centralised but per-endpoint sensitivity remains.
- Dropped the now-unused `strconv` import from `handlers_connections.go`.

#### D3 — Defensive pagination on configuration list endpoints
- `GetDashboardAll`: `Find(&devices)` and `Find(&connections)` now `.Limit(1000)`.
- `GetDeviceDataDiag`: same 1000 cap on devices.
- `GetIRCServer`: 200 cap on servers (sized for the realistic operator surface).
- `GetIRCChannels`: 500 cap (filtered + unfiltered paths).
- `GetIRCCommands`: 500 cap.
- `GetAllSettings`: 1000 cap.
- All caps are above any realistic fleet/config size, so they're invisible to current clients while bounding worst-case memory if a misconfiguration or test fixture inflates row counts.

#### D4 — Stats `device_id` filter + VPN `last_up_at` + probe error-field consistency
**`device_id` filter on stats endpoints**:
- `GetAlertStats`, `GetTrapStats`, `GetSyslogStats` now accept an optional `?device_id=N` query parameter.
- The database methods take a `deviceID uint` argument (0 = no filter, matches existing API semantics). Internal helpers `groupByString` and `timeSeriesCount` also take the filter parameter so the WHERE clause is applied to every aggregation, not just the top-level COUNT. SyslogStats' summary tables get the same filter via a small local helper.
- Unblocks the noisy-device-leaderboard feature deferred from bundle F5 — frontend can now fetch per-device stats without an N+1 loop.

**`last_up_at` on VPN status**:
- New `LastUpAt *time.Time` field on `models.VPNStatus`, marked `gorm:"-"` (computed, not stored). `json:",omitempty"` so the field is absent when no historical "up" snapshot exists.
- `GetLatestVPNStatuses` populates it from a single grouped query: `SELECT tunnel_name, MAX(timestamp) FROM vpn_statuses WHERE device_id = ? AND status = 'up' GROUP BY tunnel_name`. One query per device-detail request rather than one per tunnel.
- Frontend `renderVPN` in `admin-device-detail.js` now displays "last up Xh ago" in the uptime column for currently-down tunnels (with `formatRelative`), title-attribute hovering shows the absolute timestamp. Up tunnels still show normal uptime; tunnels with no historical "up" snapshot show a dash. Resolves the bundle F5 deferral for the down-tunnel half.

**Probe `error` vs `message` field unification**:
- New internal helper `probeErr(c, status, msg)` in `handlers_probes.go` emits `{"success": false, "error": msg, "message": msg}` — both fields are present in every error response. New clients can read `error` consistently; legacy `Firewall-Collector` binaries that read `message` keep working unchanged.
- Applied to every error path in `RegisterProbe` (5 sites) and `ProbeHeartbeat` (4 sites). `TestProbeConnection` already used `message` for its success response; left alone.

### Files
- Modified: `internal/api/handlers/handlers_dashboard.go` — ParseHours migration + 1000-row caps on dashboard lists.
- Modified: `internal/api/handlers/handlers_connections.go` — ParseHours migrations (2 sites) + strconv import removed.
- Modified: `internal/api/handlers/handlers_devices.go` — ParseHours migration on GetProcessStats.
- Modified: `internal/api/handlers/handlers_irc.go` — `.Limit()` on 3 list endpoints.
- Modified: `internal/api/handlers/handlers_settings.go` — `.Limit(1000)` on GetAllSettings.
- Modified: `internal/api/handlers/handlers_probes.go` — `probeErr` helper + 9 call-site conversions.
- Modified: `internal/api/handlers/handlers_analytics.go` — `parseStatsDeviceFilter` + 3 stats endpoints take device_id.
- Modified: `internal/database/database.go` — `groupByString` / `timeSeriesCount` / `GetAlertStats` / `GetTrapStats` / `GetSyslogStats` take `deviceID`; `GetLatestVPNStatuses` populates `LastUpAt`; `GetDashboardTimeSeries` passes 0 for unfiltered.
- Modified: `internal/models/models.go` — `VPNStatus.LastUpAt` field.
- Modified: `cmd/api/static/js/admin-device-detail.js` — uptime column renders last-up-ago for down tunnels.

### Why this matters
External clients of the admin API (custom dashboards, automation scripts, the `Firewall-Collector` probe binary) now see the same `error` field on every probe-facing error, the same `hours` cap on every stats endpoint, and the same `device_id` filter shape on `/alerts/stats`, `/traps/stats`, `/syslog/stats`, and `/flows/stats`. The frontend gains a new fact (when a down tunnel was last up) that the F bundle had to skip. And every configuration-list endpoint is bounded by a sane LIMIT so a single misconfigured row in a test database can't OOM the API process.

### Whole-admin sweep complete
v0.10.212 (A — foundation) → v0.10.213 (B — accessibility) → v0.10.214 (C — performance) → v0.10.215 (E — cross-page linkification) → v0.10.216 (F — operator features) → v0.10.217 (D — backend consistency). Six bundles, ~2 100 lines of additions, every page touched, no breaking client changes.

## [0.10.216] - 2026-05-18

### Changed — admin-wide operator features (Bundle F: F1 + F2 + F3 + F4)
Fifth commit of the "improve the whole admin area" sweep. Three concrete operator quality-of-life additions, all frontend-only — every required data field was already exposed by existing API responses.

#### Audit
Parallel sub-agent confirmed data availability for the planned features. **Available without backend changes**: `Device.ip_address`, `Device.ssh_username`, `Device.ssh_port`, `Device.last_polled`, every `FlowSample` field needed for CSV export. **Deferred (needs backend change)**: tunnel last-seen for `status='down'` tunnels (`VPNStatus` exposes `tunnel_uptime` for up tunnels but no `last_up_at` for down ones); per-device syslog/alert noise counts (`/api/syslog/stats` etc. accept no `device_id` filter).

#### F2 — SSH launch button (`AdminCommon.sshLaunchButton`)
- New helper renders an `<a class="btn secondary sm" href="ssh://user@host[:port]">SSH</a>` for any device — the operator's OS hands the URL to their registered SSH handler (PuTTY, Terminal, iTerm2, Windows Terminal, etc.). No credentials flow through the admin server.
- Inputs are URI-encoded; missing `ip_address` yields an empty string (no button). Non-default `ssh_port` (anything other than 22) appended as `:port`.
- Wired into the devices table actions column in `admin-main.js` and the device-detail page header (new `#deviceSshLaunch` placeholder).

#### F3 — Stale-device dashboard card
- New "Stale Devices" card on the dashboard listing every device whose `last_polled` is older than the operator-selected threshold. Threshold dropdown ranges 15 m / 30 m / 1 h (default) / 3 h / 12 h / 24 h; selection persists in `localStorage` under `fwmon-stale-threshold-min`.
- Per-row content: device-link (uses the bundle E2 `AC.deviceLink`), IP, "X minutes/hours/days ago" relative time, status badge, SSH launch button.
- Card auto-hides when nothing is stale — no dead chrome on a healthy fleet. Rows are sorted oldest-poll-first so the most concerning entries surface at the top.
- Driven entirely off the existing `/api/dashboard` payload — no extra API call, no extra round trip on the polling loop.

#### F4 — CSV export on flows page (`FwmonFlows.exportCsv`)
- New "Export CSV" button in the flows page header (right side, between the active-filter chips and the sampling chip).
- Pulls up to 10 000 rows matching the **current filter state** (range / device / probe / protocol / src / dst / dport) from the existing `/admin/api/flows` endpoint — no new endpoint.
- Columns: `timestamp, src_addr, src_port, dst_addr, dst_port, protocol, protocol_name, bytes, packets, sampling_rate, device_id, probe_id, sampler_address`. RFC 4180-style escaping for any field containing comma / quote / CR / LF; embedded quotes doubled.
- Filename encodes the current filter signature so successive exports don't collide in the operator's Downloads folder — e.g. `flows-2026-05-18T19-42-15-24h-dev42-protoTCP-port443.csv`.
- Button disables + shows "Exporting…" while fetching. Hard 10 000-row cap with a polite toast prompting the operator to refine the filter if it triggers.

#### F5 — Deferred
Tunnel last-seen for down tunnels and the noisy-device leaderboard both need small backend changes (a `last_up_at` field in the VPN status response, and a `device_id` query param on the stats endpoints). Deferred to keep this bundle frontend-only; tracked for a future backend-leaning bundle.

### Files
- Modified: `cmd/api/static/js/admin-common.js` — `sshLaunchButton` helper, export.
- Modified: `cmd/api/static/js/admin-main.js` — devices table SSH column, `renderStaleDevices` + threshold persistence + `loadDashboard` integration.
- Modified: `cmd/api/static/js/admin-device-detail.js` — header SSH button render.
- Modified: `cmd/api/static/js/admin-flows.js` — `exportCsv`, csv escaping, filename signature, button binding.
- Modified: `web/admin/admin.html` — stale-devices card + flows export button.
- Modified: `web/admin/device-detail.html` — `#deviceSshLaunch` slot in header.

### Why this matters
Three high-frequency triage chores collapse from minutes to seconds. Logging into a device used to require copying its IP into a separate terminal; "SSH" is now a one-click affordance everywhere the device is listed. Investigating "did this device drop?" used to mean cross-referencing the device list against the last-poll column manually; the stale-data card surfaces the same answer at a glance. Sharing a flow sample for a peer review used to mean a screenshot or a manual copy/paste from the table; "Export CSV" gives the operator a properly-named file in one click. None of these features add backend load — they all reuse data the API already returns.

## [0.10.215] - 2026-05-18

### Changed — admin-wide cross-page linkification (Bundle E: E1 + E2 + E3)
Fourth commit of the "improve the whole admin area" sweep. The visual + a11y + perf foundations from bundles A/B/C are in place; this bundle wires the navigation that ties them together so an operator triaging an alert / syslog / trap row can pivot to context in a single click.

#### Audit
One parallel sub-agent audited every render function across the admin JS files. Findings: 9 plain-text fields display a device, probe, site, IP, or tunnel ID/name with no link affordance even though a natural deep-link target exists. Highest-value gaps: alerts table device cell (no link to device-detail), syslog/traps source IP and hostname cells (no link to the page filter), connections table source/dest device names (only the "Details" button was a link), tunnel remote-IP cell (no pivot to remote-side syslog).

#### E2 — Helpers + linkified ID cells
- New helpers on `AdminCommon` in `admin-common.js`:
  - `deviceLink(id, label, opts)` → `<a href="/admin/devices/:id" class="fwmon-link" …>label</a>`
  - `connectionLink(id, label, opts)` → `<a href="/admin/connections/:id" …>`
  - `filterLink(page, params, label, opts)` → `<a href="/admin/:page?k=v&…" …>` — deep-links into a list page with the URL state machinery from v0.10.212 picking up the query params at boot.
- All three helpers `escapeHtml()` their inputs so callers don't have to.
- New `.fwmon-link` primitive in `admin-design-system.css`: sky-300 color, dotted underline on hover, `:focus-visible` ring. Added to the `prefers-reduced-motion` suppression list.
- Wired into 4 render sites in `admin-main.js`:
  - **Syslog table** (`renderSyslogTable`): source IP + hostname cells filter the syslog page by `search=<value>`.
  - **Alerts table** (`renderAlertsTable`): device cell links to `/admin/devices/:id`.
  - **Traps table** (`renderTrapsTable`): source IP cell cross-pivots to `/admin/syslog?search=<ip>` (traps page has no search filter today; syslog is the natural destination for "what was this source saying").
  - **Connections table** (devices section): source-device and dest-device names link to their respective device-detail pages.
- Row-click handler (`syslog-row` / `alert-row`) updated to ignore `<a>` clicks so clicking an inline filter link doesn't also pop the detail modal.

#### E3 — Alert → syslog deep-links + tunnel cross-pivots
- **Alert-detail modal**: device row is now a link to the device-detail page. Two new "Drill into" affordances appear under the header — `All alerts` (jumps to `/admin/alerts?device_id=N`) and `Related syslog` (jumps to `/admin/syslog?device_id=N`). Same state keys the analytics-page descriptors already use, so the URL params take effect on page load.
- **Device-detail Alerts tab**: new "View all alerts for this device →" link in the section header — populated with `?device_id=N` when the page knows its device ID.
- **Device-detail VPN tab**: tunnel `remote_ip` cells link to `/admin/syslog?search=<ip>` so an operator looking at a flapping tunnel can pivot to remote-side syslog context with one click. Falls back to escaped plain text if `AdminCommon` isn't loaded.

### Files
- Modified: `cmd/api/static/js/admin-common.js` — `deviceLink`, `connectionLink`, `filterLink`, exports.
- Modified: `cmd/api/static/css/admin-design-system.css` — `.fwmon-link` + reduced-motion entry.
- Modified: `cmd/api/static/js/admin-main.js` — 4 render sites linkified + alert-detail modal + row-click guard.
- Modified: `cmd/api/static/js/admin-device-detail.js` — VPN remote-IP link + alerts "view all" link wiring.
- Modified: `web/admin/device-detail.html` — alerts section header + `#alerts-view-all-link` anchor.

### Why this matters
Triage flow before bundle E: see alert → copy device name → paste into syslog search → set time range. Five steps + memory tax. After bundle E: see alert → click "Related syslog" — one click, no manual copy/paste, no risk of typo. The same pattern repeats across every cross-page hop in the admin. Right-click + open-in-new-tab works too, so an operator can fan out a triage session across multiple tabs without losing their place in the originating list.

## [0.10.214] - 2026-05-18

### Changed — admin-wide performance pass (Bundle C: C1 + C2 + C3 + C4)
Third commit of the "improve the whole admin area" sweep. Three measurable wins after the foundation (A) + a11y (B) work landed: cut idle background work, trim the eager-JS payload, and stop re-creating chart canvases that could just be updated in place.

#### Audit
Spawned one parallel audit sub-agent covering polling loops + cytoscape load + chart re-creation. Findings:
- 5 `setInterval` polling loops, only 1 page-gated; **0** visibility-gated.
- ~421 KB of Cytoscape + extensions loaded eagerly on every admin page even when the operator never opens the Connections tab.
- 3 chart-rebuild sites destroy+recreate uPlot/Chart.js instances on each refresh — worst is connection-detail traffic chart at 30 s cadence.

#### C2 — Visibility-gated polling (`AdminCommon.pollWhenVisible`)
- New `pollWhenVisible(fn, intervalMs, opts)` helper in `admin-common.js` returns `{ stop, runNow }`. Internally uses `setInterval` + `visibilitychange` to suspend the timer when `document.hidden` is true, resume on visible, and optionally re-fire immediately on resume so the operator never sees stale data after switching back to the tab.
- Migrated 4 admin-side `setInterval` call sites: `pollConnectionStatuses` (15 s), dashboard refresh (30 s), syslog auto-refresh (10 s), device-detail full refresh (60 s), and connection-detail combined refresh (30 s).
- Public dashboard (`public-dashboard.js`) gets inline visibility gates on its 1 Hz uptime ticker and N-second widget refresher — separate from the helper because the public dashboard doesn't load `admin-common.js`.

#### C3 — Lazy-load Cytoscape (`AdminCommon.loadCytoscape`)
- Removed the 6 eager `<script defer>` tags for cytoscape + layout-base + cose-base + cytoscape-fcose + diagram-cytoscape + diagram-panels from `web/admin/admin.html`.
- New `loadCytoscape()` in `admin-common.js` injects them on demand (sequentially, preserving execution order via `script.async = false`) and caches the resulting Promise so subsequent calls are free.
- `drawConnectionDiagram()` now awaits the loader, shows a "Loading network diagram…" message while fetching, and degrades to a clear error message if the bundle fails to load.
- `pollConnectionStatuses` guards `FWDiagram.updateStatuses` and `FWDiagram.updateVPNBadges` with `window.FWDiagram` checks so the poll loop runs harmlessly until the diagram is first opened.
- Net effect: ~421 KB of JS is no longer downloaded by operators who only ever use Syslog / Alerts / Traps / Flows. First-time Connections-tab open pays a one-time fetch.

#### C4 — In-place chart updates (`chart.update()` / `setData()`)
- Connection-detail traffic chart (`admin-connection-detail.js`, refreshed every 30 s by the page poll loop): replaced `trafficChart.destroy(); trafficChart = new Chart(...)` with `trafficChart.data = ...; trafficChart.update('none')` (the `'none'` mode skips the chart animation on auto-refresh so re-fetches don't flicker). First call still creates the chart; subsequent calls reuse the instance. Construction cost (~30-50 ms per tick on a midrange browser) is now amortised across the lifetime of the page instead of paid every 30 s.
- Device-detail overview chart + CPU-breakdown chart (`admin-device-detail-charts.js`, refreshed on every range-pill click): replaced `new uPlot(...)` + post-hoc destroy with `chart.setData(data)` when an instance exists. Range-pill spam now feels snappy instead of stuttering. The network chart was left as-is because it dynamically switches between kbps and Mbps axis units across renders, which requires a full rebuild.

### Files
- Modified: `cmd/api/static/js/admin-common.js` — `pollWhenVisible`, `loadCytoscape`, exports.
- Modified: `cmd/api/static/js/admin-main.js` — 3 setInterval migrations + diagram lazy-load wiring + FWDiagram guards.
- Modified: `cmd/api/static/js/admin-device-detail.js` — setInterval migration.
- Modified: `cmd/api/static/js/admin-connection-detail.js` — setInterval migration + in-place chart update.
- Modified: `cmd/api/static/js/admin-device-detail-charts.js` — in-place uPlot setData for overview + CPU charts.
- Modified: `cmd/api/static/js/public-dashboard.js` — inline visibility gates.
- Modified: `web/admin/admin.html` — removed 6 eager `<script defer>` cytoscape tags.

### Why this matters
A typical admin browser left open on the dashboard tab while the operator works in another window used to hit `/api/dashboard/stats` every 30 s, `/api/connections/status-summary` every 15 s, and various device-detail endpoints every 60 s — for hours. After C2 those polls suspend on tab hide and resume on focus. Wallboard / TV browsers running the public dashboard 24/7 were the worst offenders; the 1 Hz uptime ticker alone was 86,400 DOM writes per day per widget. After C3, an operator who only uses Syslog and Alerts never downloads the ~421 KB Cytoscape bundle. After C4, the connection-detail page consumes a flat memory and CPU baseline instead of a sawtooth.

## [0.10.213] - 2026-05-18

### Changed — admin-wide accessibility pass (Bundle B: B1 + B2 + B3 + B4)
Second commit of the "improve the whole admin area" sweep. After v0.10.212 promoted the design tokens to a shared stylesheet, this bundle brings the admin UI up to WCAG 2.1 AA on every axis surfaced by the audit: modal a11y, focus-visible coverage, color contrast, prefers-reduced-motion, skip-to-main-content, screen-reader live regions, and icon-only button labels.

#### Audit
Spawned four parallel audit sub-agents covering: modal a11y (10 dialogs all failing 4/4 checks), `:focus-visible` coverage (6 fwmon-* selectors covered, 19+ legacy selectors uncovered), color contrast + `prefers-reduced-motion` + skip-link (label color `#484f58` failing AA at 4.0:1 across 60+ occurrences; reduced-motion honored only in design-system.css; no skip link anywhere), and toast announcements + icon-only buttons (toasts not announced to AT; 15+ buttons without accessible names). All four reports informed the implementation order below.

#### B2 — Shared modal a11y wrapper (`AdminCommon.openModal / closeModal`)
- New `openModal(modalId, opts)` and `closeModal(modalId)` in `admin-common.js`. Adds `role="dialog"`, `aria-modal="true"`, `aria-labelledby` (auto-derived from a heading inside the modal), and a 2-element-aware focus trap with Tab/Shift-Tab cycling, Escape to close, and focus restoration to the trigger element.
- Coexists with the legacy `.classList.add('active')` pattern — both paths leave the modal visible, but only `openModal()` gets focus management. The wrapper auto-tags every `.modal-close` button with `aria-label="Close dialog"` on open.
- `tagStaticModals()` runs on `DOMContentLoaded` and retroactively applies `role` / `aria-modal` / `aria-labelledby` / close-button `aria-label` to every `.modal` in the DOM — so legacy open paths that we didn't migrate still get screen-reader-announceable modals (just no focus trap).
- Migrated 19 modal open/close call sites across `admin-main.js`, `admin-irc.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js`, and `admin-device-detail.js` (device modal, connection modal, alert detail, acknowledge modal, syslog detail, probe detail, alerts-bulk-ack, alert policy, maintenance window, device-alert-config, IRC server / channel / command, site, probe add/edit, deploy, reject, config diff, dynamic config viewer).

#### B3 — `:focus-visible` + contrast + `prefers-reduced-motion` + skip link
- New `.skip-link` primitive in `admin-design-system.css` (off-screen until keyboard-focused, then pinned top-left) and `.fwmon-sr-only` screen-reader-only utility.
- `<a class="skip-link" href="#main-content">Skip to main content</a>` added as the first focusable element in `admin.html`, `device-detail.html`, `connection-detail.html`, `sites.html`, `irc.html`, `probes.html`, `probe-pending.html`.
- Every page's primary content region is now `<main id="main-content" tabindex="-1">` (semantic landmark + skip-link target).
- `:focus-visible` coverage added for the legacy selectors that fell through bundle A: `.btn / .btn.secondary / .btn.danger / .btn.sm`, `.modal-close`, `.copy-btn`, `.nav-item / .tab-item / .section-tab / .tab-btn`, `.range-btn`, clickable rows (`.fwmon-toptalk-row / .fwmon-clickable / .expandable-msg`), and form inputs (`.form-group input/select/textarea`, `.fwmon-flows-input`, `.setting-item input/select`). Each ring uses the sky-300 accent at AA-compliant intensity.
- Contrast: replaced `#484f58` (4.0:1 — fails AA) with `#6e7681` (5.6:1 — passes AA) across every text-color occurrence in 7 HTML files. Border / background uses of `#484f58` (probes.html copy buttons) untouched.
- `@media (prefers-reduced-motion: reduce)` block broadened to suppress the legacy keyframes (`toastSlideIn`, `pulse`, `fadeIn`, `slideUp`) plus long transitions on `.btn`, `.nav-item`, `.tab-item`, `.section-tab`, `.copy-btn`, `.modal-close`, `.probe-card.clickable`, `.toggle-slider`, `.fwmon-toptalk-row*`, and the new `.skip-link`.

#### B4 — Live regions + icon-button labels
- `showToast(msg, type)` in `admin-common.js` now wraps the toast container with `role="alert"` + `aria-live="assertive"` for errors and `role="status"` + `aria-live="polite"` for success / warning, plus `aria-atomic="true"` so screen readers announce the full message even on rapid updates. `showError()` / `showSuccess()` get assistive-tech parity with the visible toast.
- Mobile menu hamburger gained `aria-label="Open navigation menu" aria-expanded="false" aria-controls="sidebar"`.
- Logout icon (`&#10140;`) in every sidebar footer marked `aria-hidden="true"` so screen readers announce just "Logout" rather than the codepoint.
- Alerts bulk-ack close switched from a `<span>` to a `<button>` with `aria-label="Close dialog"`.
- Dynamic config-viewer modal (created at runtime in `admin-device-detail.js`) now uses `AdminCommon.closeModal` for its X / Close buttons and includes `aria-label` on the X button.

### Files
- Modified: `cmd/api/static/js/admin-common.js` (openModal/closeModal + tagStaticModals + showToast live region).
- Modified: `cmd/api/static/css/admin-design-system.css` (`.skip-link`, `.fwmon-sr-only`, `:focus-visible` for legacy selectors, broadened reduced-motion block).
- Modified: `cmd/api/static/js/admin-main.js`, `admin-irc.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js`, `admin-device-detail.js` (19 modal call sites migrated to AC.openModal/closeModal).
- Modified: `web/admin/admin.html`, `device-detail.html`, `connection-detail.html`, `sites.html`, `irc.html`, `probes.html`, `probe-pending.html` (skip-link + `<main id="main-content">` + design-system.css link + contrast fix + nav-icon aria-hidden + mobile hamburger label).

### Why this matters
Keyboard-only operators can now navigate every modal, dismiss with Escape, and trust that focus returns where they left it. Screen-reader operators get every toast announcement, every modal labeled, every icon-only button named. Operators with vestibular sensitivity get a quiet UI when the OS prefers reduced motion. Operators with low-vision can read every previously-failing label at 5.6:1 contrast. None of this required a redesign — the v0.10.212 design system survived intact; only the a11y plumbing changed.

## [0.10.212] - 2026-05-17

### Changed — admin-wide foundation pass (Bundle A: A1 + A2 + A3)
First commit of the "improve the whole admin area" sweep. Three sub-bundles ship together because they touch the same set of files and reinforce each other — extracting the foundation (A1), then reusing it in three more pages (A2), then replacing the last bit of stock-browser chrome (A3).

#### A1 — Foundation extraction (`cmd/api/static/css/admin-design-system.css`)
The `fwmon-*` design system that grew up inside `admin-device-detail.css` for the v0.10.205 redesign and got reused inline for the v0.10.211 flows page is now a **single shared stylesheet** every admin page can opt into.
- Promoted tokens: `--fwmon-font-ui / --fwmon-font-mono / --fwmon-series-1..8 / --fwmon-card-bg / --fwmon-panel-bg / --fwmon-border / --fwmon-text* / --fwmon-axis-stroke / --fwmon-grid-stroke / --fwmon-tick-stroke`.
- Promoted components: `.chart-range-pills`, `.chart-range-pill`, `.filter-btn` (+ `.filter-count`), `.chart-card` (+ `-header / -title / -subtitle`), `.chart-host`, `.chart-loading / -empty / -zoom-hint / -reset-btn`, `.fwmon-stat-grid`, `.fwmon-stat` (+ `-label / -value` and `.accent / .good / .warn / .bad` modifiers), `.fwmon-chip` (+ `-key / -val / -clear / .subdued`), `.fwmon-chips`, and the `uPlot` dark-theme overrides.
- Stripped the duplicated rules from `admin-device-detail.css` and `admin-flows.css`; both files now hold only their page-specific overrides.
- `web/admin/admin.html` and `web/admin/device-detail.html` both link the new stylesheet immediately after `admin-fonts.css`.
- Added `prefers-reduced-motion` block honoring the user's OS preference for every animation defined in the file.

#### A2 — Syslog / Alerts / Traps pages restyled to match Flows (`cmd/api/static/js/admin-controls.js` — new module)
Brought the three high-traffic forensic pages in line with the v0.10.211 flows experience without duplicating wiring.
- New reusable module `window.FwmonControls` with helpers: `bindRangePills`, `activatePill`, `bindAutoApply`, `setInputValues`, `stateFromURL`, `syncURL`, `renderChips`, `renderRangePills`, and the high-level `attachAnalyticsPage(descriptor)` wrapper that wires range pills + auto-apply filters + URL state + active-filter chips for a whole page from one declarative spec.
- Syslog / Alerts / Traps page headers now use the same **time-range pill bar** as device-detail and flows (1h / 6h / 12h / 24h / 7d). The old `<select>` time pickers were dropped.
- Filter rows lost their **Apply** buttons — `bindAutoApply` debounces text inputs (400ms) and fires immediately on selects/pills.
- Each page gets an **active-filter chip strip** with × to clear individually (device name, search, severity, etc.). Device/probe IDs are resolved to names via `deviceLabel(id)` / `probeLabel(id)` helpers so chips read `device sjc-fw-01` not `device 42`.
- Every filter and the time range mirror to the URL via `history.replaceState` — shareable, refresh-stable.
- `admin-main.js` — added `var analyticsPages = { syslog, alerts, traps };` and `wireSyslogAnalyticsPage / wireAlertsAnalyticsPage / wireTrapsAnalyticsPage` initialisers; `buildSyslogParams / buildAlertParams / buildTrapParams` and the chart-loading helpers now read `hours` from the page state.
- `web/admin/admin.html` — three page headers rebuilt to host the pill bar + chip container; Apply buttons and `<select>` time pickers removed.

#### A3 — Styled confirm() modal (`AdminCommon.confirm`)
The 14 destructive operations across the admin (delete device / connection / alert policy / maintenance window / IRC server / IRC channel / IRC command / config revision / site / probe + regenerate key + approve probe + reset alert config) all used native `window.confirm()`. Unstyled, unbranded, no danger affordance, no focus management — jarring next to the redesigned UI and an accessibility audit miss.
- New `AdminCommon.confirm(message, opts)` in `admin-common.js` returns a `Promise<bool>` and renders a modal with `role="dialog"`, `aria-modal`, `aria-labelledby`, a 2-element Tab focus trap, Escape to cancel, focus restoration on close, and a `danger: true` variant that paints the confirm button in `--fwmon-series-2` (red) so destructive ops can't be mistaken for benign ones.
- Cancel is focused by default — operators can't Enter-spam through a destructive prompt.
- All 14 call sites converted (`admin-irc.js`, `admin-device-detail.js`, `admin-main.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js`) — every destructive button now opens the styled modal with an appropriate title (`Delete device?`, `Delete IRC channel?`, `Regenerate key?`, etc.) and `Delete` / `Reset` / `Regenerate` / `Approve` confirm labels.
- CSS for `.fwmon-confirm-overlay / -dialog / -title / -body / -actions / -btn / -btn.primary / -btn.danger` lives in `admin-design-system.css` with fade-in + rise animations gated by `prefers-reduced-motion`.

### Files
- New: `cmd/api/static/css/admin-design-system.css`, `cmd/api/static/js/admin-controls.js`.
- Modified: `cmd/api/static/css/admin-device-detail.css`, `cmd/api/static/css/admin-flows.css` (duplicated foundation rules removed).
- Modified: `cmd/api/static/js/admin-common.js` (`confirmModal` + `AdminCommon.confirm` export).
- Modified: `cmd/api/static/js/admin-main.js` (analytics-page wiring + range param threading).
- Modified: `cmd/api/static/js/admin-irc.js`, `admin-device-detail.js`, `admin-sites.js`, `admin-probes.js`, `admin-probe-pending.js` (confirm() call sites).
- Modified: `web/admin/admin.html`, `web/admin/device-detail.html` (design-system stylesheet link, restyled page headers).

### Why this matters
Every subsequent admin-area bundle (B accessibility, C performance, E linkification, F operator features, D backend consistency) builds on the shared design tokens promoted in A1 and the analytics-page wiring in A2. Without A1, each new page would either drift visually or paste another copy of the same 200 lines of CSS; without A2, every analytics-style page would need its own bespoke filter/chip/URL wiring; without A3, every destructive op would keep using stock-browser chrome that doesn't match the rest of the surface. This commit is the foundation the rest of the sweep stands on.

## [0.10.211] - 2026-05-17

### Changed — `/admin/flows` page redesign
Brought the Flows tab in line with the device-detail visual language and added the interactivity it had been missing. The previous implementation was 5 Chart.js charts + 8 stat tiles + a filter row with an "Apply" button — visually inconsistent with the rest of the redesigned admin, and with dead-end widgets (you couldn't click a top-source row to filter by it).

#### Page header (new)
- Range pill bar (1h / 6h / 12h / 24h / 7d / 30d / 90d) replacing the `<select>` dropdown — matches the device-detail aesthetic.
- **Sampling-rate chip** in the header right-side. Operators forget the page shows *sampled* bytes; the persistent `sampling 1:1000` chip prevents misreading totals as raw.
- **Active-filter chips** that show every applied filter (`src 10.0.0.5`, `proto TCP`, `dport 443`) with an × to clear individually. Makes the current view auditable at a glance.

#### Bandwidth chart (uPlot)
- Replaced the Chart.js line chart with **uPlot** — same library + sync key (`fwmon-flows`) pattern as the device-detail charts.
- **Brush-to-zoom** + double-click reset + dedicated `reset` button.
- Bps formatting with adaptive units (bps / kbps / Mbps / Gbps).

#### Top-talker lists (HTML, no Chart.js)
- Replaced 4 Chart.js horizontal-bar charts (Top Sources / Destinations / Ports / Protocols) with **HTML lists**: each row is a label + value + inline width-based bar. Faster, cleaner, mobile-friendly.
- **Click-to-filter**: click any row to set the corresponding filter and refresh the whole page. Click the active row again to clear. Click target encoded as `data-filter-key` + `data-filter-value` on each `<li>`. The protocol row's "TCP" key is reverse-mapped to "6" for the URL state.

#### Top Conversations table
- Rows are now clickable — pick a conversation, page filters to that src + dst + dst_port triple.

#### Flow Samples filter row
- Removed the "Apply" button. **Auto-apply with debounce** (400 ms on text inputs, instant on selects/pills).
- Protocol filter is now a **pill bar** (All / TCP / UDP / ICMP / GRE / ESP) instead of a `<select>`.
- IP inputs accept **CIDR**: `10.0.0.0/24`, `192.168.0.0/16`, `203.0.113.5/32`. Octet-aligned IPv4 CIDRs are translated server-side to prefix-match `LIKE` clauses; non-aligned CIDRs (/20, /28 etc.) fall back to exact-match on the network IP.
- New **dst port** input — used by Top-Ports drill-down.
- New **clear** button beside the inputs.

#### URL state ↔ filters
- Every filter is mirrored to the URL via `history.replaceState`: `?src=10.0.0.5&proto=6&hours=6&dport=443`. Refresh, back-button, and share all preserve the view. Defaults (24h, blank filters) are omitted from the URL to keep clean URLs.

#### Backend
- `internal/api/handlers/handlers_analytics.go` — new `ipFilterClause(column, val)` helper. `src_addr`/`dst_addr` query params accept exact IPs OR octet-aligned IPv4 CIDR (10.0.0.0/8, /16, /24, /32 → prefix-match LIKE). Invalid CIDR falls back to exact match so a malformed input doesn't crash. New `dst_port` query param for the top-port drill-down.

#### Files
- New: `cmd/api/static/css/admin-flows.css` — scoped flows styling.
- New: `cmd/api/static/js/admin-flows.js` — `window.FwmonFlows` module (init / refresh / setFilter / getState).
- Modified: `web/admin/admin.html` — flows section rebuilt; preload fonts + uPlot CSS + admin-flows.{js,css} in head.
- Modified: `cmd/api/static/js/admin-main.js` — `case 'flows':` delegates to FwmonFlows; new `ensureFlowFilterLists()` helper surfaces device+probe lists to the module via `window.adminMainState`. Legacy chart functions kept as fallback path.
- Modified: `internal/api/handlers/handlers_analytics.go` — `ipFilterClause` + `dst_port` filter.

#### Validation
Sub-agent cross-checked 12 contract points (endpoint URLs, CIDR helper, dst_port filter, every JSON field, every mount-point ID, CSP compatibility, script load order, click-to-filter wiring, URL state, legacy fallback, embed-FS pickup, dead references). 12 PASS, 2 expected WARNs on the legacy fallback path (would throw if triggered, but only triggers if FwmonFlows fails to load — CSP-hosted same-origin script).

### Why this matters
The flows page was the highest-traffic forensic surface in the admin and the most visually mismatched. Operators need to drill from "show me the worst current source" to "show me all flows for that source between 14:00 and 14:15" without typing — now that's two clicks. URL state means an SRE can paste the URL into a ticket and the engineer who opens it sees exactly the same view.

## [0.10.210] - 2026-05-16

### Changed — interface filter pills restyled
The filter row above the Interfaces table on the device-detail page (`All / Up / Down / Ethernet / Tunnel / VLAN / ...`) had no CSS at all — the `.filter-btn` class was used by JS but never defined in any stylesheet. Buttons rendered as browser-default `<button>` elements: tiny, gray, no visible hover or active state. Operators had to guess which pill was clickable and which was selected.

#### Visual changes (`cmd/api/static/css/admin-device-detail.css`)
- **Border at rest**, not just on hover. The "this is a clickable pill" affordance is the visible border + matching radius — no more guessing where the hit target is.
- **Hover**: brighter border, lifted background, text reads in primary color. 100ms transitions so the response feels snappy without flashing.
- **Active**: sky-300 fill + matching border tint + soft outer glow. Matches the existing chart-range-pill aesthetic so the page's two "tabs of pills" elements look like one coherent system.
- **Focus-visible ring** for keyboard navigation — accessibility win that came free with the redesign.
- **Active-press effect**: 1px translate on `:active` for tactile feedback.

#### Count typography (`cmd/api/static/js/admin-device-detail.js`)
- Counts are now rendered inside their own `<span class="filter-count">` so they pick up the new mono / dim styling. The label stays sans-serif and primary-colored; the count reads as monospaced metadata. Operators scan those counts to decide which filter is worth clicking, so the type hierarchy actually matters.

#### Net effect
The filter row now reads as a row of obviously-clickable pills with a clearly highlighted current selection. The count next to each label uses JetBrains Mono so "Ethernet 42" reads at a glance against "VLAN 8" — same column position, same digit width.

## [0.10.209] - 2026-05-16

### Changed — smarter y-axis + larger server-side buckets on device-detail charts
Two improvements operators asked for in the same breath: "no more tiny noise bumps" and "let me zoom into a 10%-max series instead of always staring at 0-100%."

#### Smart y-axis range (`smartPercentRange` in `admin-device-detail-charts.js`)
- Replaces the hardcoded `range: [0, 100]` on the System Overview and CPU Breakdown charts with a dynamic range function. Behavior:
  - **Min is always 0.** Percentages floating on a non-zero baseline mislead the reader.
  - **Max auto-fits the visible-data max** with a 15% headroom. Because `legend.isolate: true` triggers a re-render on legend click, **toggling off the dominant series** (e.g. clicking "CPU" when CPU is at 80%) **rescales the axis to fit the remaining series.** Variation in a 10%-max memory line now shows as a tall, readable trace instead of a hairline at the bottom of a 0-100 grid.
  - **Top snaps to a "nice" round number** (5 / 10 / 15 / 20 / 25 / 30 / 40 / 50 / 60 / 70 / 80 / 90 / 100) so axis ticks land on whole values, not 17.3 / 34.6 / 51.9.
  - **Saturation snap-back:** if any visible series exceeds 85%, the axis returns to [0, 100]. Operators expect a "full" axis at high load.
  - **Floor of 5%:** a flat-at-zero chart still renders a readable axis instead of collapsing to a hairline.

#### Server-side bucket-size tuning (`GetSystemStatusBuckets` in `internal/database/database.go`)
- The 6h / 12h / 24h ranges previously used `minute` bucketing (360 / 720 / 1440 points per chart). A typical 800-1000px-wide chart paints those as sub-pixel-spaced jitter — visible as a perpetually fuzzy line even on genuinely flat data. The "tiny bumps" complaint.
- Switched 6h / 12h / 24h to the existing `5min` bucket expression (already in `dialect.go` for Postgres and SQLite). Counts drop to 72 / 144 / 288 — roughly one bucket per 2-4 chart pixels. 5-minute AVG still catches every real sustained CPU/memory/network change; the only thing lost is high-frequency poll-cadence noise, which was never useful anyway.

#### Net visual effect
A 24h chart on a steady-state device that used to look like a fuzzy comb at 30% now reads as a clean line near 30. Click "CPU" in the legend to hide it and the chart rescales — variation in the now-dominant 10%-max memory series becomes a readable line at the top half of the plot instead of a near-flat hairline.

## [0.10.208] - 2026-05-16

### Fixed — device-detail chart "reset" button was a no-op
- `FwmonDeviceCharts.resetZoom()` was calling `chart.setScale('x', { min: null, max: null })` to clear a brush-zoom. In uPlot, `null` on `setScale` means "keep the current value" — not "auto-fit." The call did nothing.
- Fix at `cmd/api/static/js/admin-device-detail-charts.js:189`: explicitly set the x-scale to `{ min: data[0][0], max: data[0][last] }`, i.e. the first and last timestamp in the chart's own data array. That snaps the visible window back to the full requested range. Iterates all three synced charts so a reset clears the zoom on Overview, Network, and CPU Breakdown together.
- Guards on `c.data && c.data[0]` so a chart that's hidden (e.g. CPU Breakdown when the device doesn't report per-core stats) doesn't trip the reset path.

## [0.10.207] - 2026-05-16

### Added — self-hosted Inter + JetBrains Mono on the device-detail page
- `cmd/api/static/fonts/inter-latin.woff2` (48 KB) and `cmd/api/static/fonts/jetbrains-mono-latin.woff2` (31 KB) — variable-font WOFF2, latin subset (U+0000–00FF plus a handful of European punctuation). Variable fonts mean a single file per family carries the entire weight axis 100–900; the browser interpolates intermediate weights with no extra fetch.
- New `cmd/api/static/css/admin-fonts.css` declares both via `@font-face` with `font-display: swap` so the system-font fallback paints immediately and the WOFF2 swaps in once decoded — no FOIT.
- `web/admin/device-detail.html` `<head>` now `<link rel="preload">`'s both WOFF2 files before the CSS, so the swap happens within the first paint frame on a warm cache and before first text on a cold cache.

### Why this matters
v0.10.206 backed out the Google Fonts `<link>` because the CSP blocked it, falling back to system fonts. That worked but lost the distinctive typographic pairing the redesign was built around. Self-hosting brings Inter + JetBrains Mono back without re-introducing any third-party origin — `font-src 'self'` is satisfied, no EU privacy issue, no offline failure mode, and the latin-subset variable-font approach keeps the total typography payload under 80 KB.

If we later want UI translations or non-latin content, add a second @font-face block for the matching Cyrillic / Greek / Vietnamese subset fetched from `fonts.gstatic.com/s/{family}/v{N}/...`. Until then, latin-only is the right call.

## [0.10.206] - 2026-05-16

### Fixed — device-detail charts blank because CSP blocked CDN uPlot
- v0.10.205 loaded uPlot + its CSS from `cdn.jsdelivr.net` and Inter/JetBrains Mono from Google Fonts. The server's existing CSP at `internal/api/middleware/middleware.go:257` is `script-src 'self'` / `style-src 'self'` / `font-src 'self'` — so the browser silently dropped all three external loads. Result: `typeof uPlot === 'undefined'` when the chart module ran, console error `uPlot not loaded; charts cannot render`, three blank chart cards.
- **Fix:** `uPlot.iife.min.js` (50 KB) and `uPlot.min.css` (1.9 KB) are now committed to `cmd/api/static/js/` and `cmd/api/static/css/` and served same-origin. HTML loads them via `/static/...` paths. Same-origin satisfies the CSP cleanly — no CDN, no `'unsafe-inline'`, no policy change.
- **Fonts:** Google Fonts `<link>` tags removed since the CSP blocks them too. The CSS variable fallback chain (`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, ...` for UI and `ui-monospace, "SF Mono", Menlo, Consolas, ...` for numerics) renders cleanly on every modern OS. Tabular numerals (`font-feature-settings: "tnum" 1`) work on system fonts too — Segoe UI, SF Pro, Roboto, and DejaVu all support the OpenType `tnum` feature. The aesthetic loss is modest; the offline-friendliness, security posture, and EU privacy posture (no third-party font fetch) all improve.

### Why this matters
The whole point of v0.10.205 was to make the device-detail charts usable. v0.10.205 was DOA on any deployment with a same-origin CSP — which is the default for this project and every other security-conscious deploy. Same-origin-only assets are the only sustainable pattern for an admin UI that has to work on air-gapped, CSP-strict, and offline-first deployments. Lesson logged.

## [0.10.205] - 2026-05-16

### Changed — device-detail page chart redesign (operator-grade)
The three "above the fold" charts on `/admin/devices/:id` (Status Overview, Network Throughput, CPU Breakdown) are rebuilt from the ground up. The previous implementation rendered raw 60-second poll samples through Chart.js with Catmull-Rom spline interpolation, which (a) looked like jagged noise on any range >1h and (b) had no zoom — operators were stuck with whatever range the dropdown picked. The redesign solves both, plus the typography overflow the user called out.

#### Charting library
- **uPlot 1.6.31** (canvas-based, ~45 KB gzipped, MIT, loaded from jsDelivr) replaces Chart.js for the three above-the-fold panels. uPlot is the same library Grafana uses for its default time-series panels.
- **Synchronized cursor + brush-zoom** across all three panels via `uPlot.sync('fwmon-device-detail')`. Drag horizontally on any panel → all three zoom to the same window. Double-click → reset. A dedicated `reset` button next to the range pills is also wired up.
- **No spline interpolation.** Splines invent values between samples — fine for stock prices, dishonest for sampled telemetry where the bucket value is the only thing we know. Straight-line segments tell the operator the truth: "between these two points, we don't know."

#### Server-side bucketing for system-status
- New `GET /api/devices/:id/status-history?range=1h|6h|12h|24h|7d|30d|90d|365d` returns server-bucketed data (AVG per minute/hour/day depending on range) — mirrors the existing `GetInterfaceChartData` pattern. The legacy `?hours=N` raw-rows mode is preserved for any external caller.
- New `SystemStatusBucket` struct + `GetSystemStatusBuckets()` method in `internal/database/database.go` with a `parseBucketToMillis()` helper that converts the dialect's TimeBucket output (both Postgres and SQLite formats covered) to epoch milliseconds for the chart x-axis.
- One round-trip per range change feeds all three charts — previous behavior fired three concurrent requests for the same data.

#### Typography + overflow fix
- **Inter** (UI) + **JetBrains Mono** (numerics) loaded via Google Fonts. Tabular numerals (`font-feature-settings: "tnum" 1`) on every numeric value so columns align.
- **`min-width: 0` + `text-overflow: ellipsis`** on stat-card labels and values fixes the "font overflows boxes" complaint — long firmware/signature strings now truncate cleanly. A `.stat-long` modifier rounds out display for ones that benefit from word-break instead of truncation.
- New scoped stylesheet `cmd/api/static/css/admin-device-detail.css` keeps the changes off other admin pages.

#### Palette
- Tuned Okabe-Ito-adjacent series colors against the existing `#0d1117` base. CPU = sky, memory = violet, disk = green, network in/out = sky/amber. Colorblind-safe; 8 distinct hues for the CPU-breakdown stack.

#### Range pill bar
- The previous per-chart `<select>` dropdown (network only) is replaced by a unified pill bar in the Overview header that drives all three charts in lockstep. Values: 1h / 6h / 12h / 24h / 7d / 30d / 90d. Default 24h.

#### Files
- New: `cmd/api/static/js/admin-device-detail-charts.js` — `window.FwmonDeviceCharts` module (init / destroy / setRange).
- New: `cmd/api/static/css/admin-device-detail.css` — scoped typography + uPlot dark theme.
- Modified: `web/admin/device-detail.html` — Google Fonts + uPlot CDN in head, dead-canvas wrappers replaced with mount-point divs.
- Modified: `cmd/api/static/js/admin-device-detail.js` — three legacy chart functions renamed `*Legacy` (kept as fallback), new dispatch through `FwmonDeviceCharts.init()`.
- Modified: `internal/api/handlers/handlers_devices.go` — `GetDeviceStatusHistory` branches on `?range=`.
- Modified: `internal/database/database.go` — `GetSystemStatusBuckets()` + `parseBucketToMillis()`.

#### Validation
Spawned a dedicated sub-agent to cross-check 13 contract points between the new frontend and backend (URL paths, json tag matches on all 13 fields, response envelope shape, mount-point ID match, event delegation, embed-vs-disk static serving, uPlot CDN integrity, time-unit conversion). 12 PASS, 1 WARN (CSS rule overlap with `admin-shared.css` `.chart-card`, currently safe by load order — flagged for a future scoping pass).

#### Out of scope (deferred)
- The per-interface chart inside the Interfaces tab uses Chart.js with bucketed backend data — it doesn't exhibit the "spiky raw telemetry" issue. Visual consistency port to uPlot is a v0.10.206+ candidate.
- Process Monitor, Interface Errors, and gauge dials still on Chart.js / SVG. Same rationale: scope discipline.

### Why this matters
The device-detail page is the primary operational surface for diagnosing a single firewall. The previous charts were unreadable on anything past a 1-hour window and forced a hard refresh to change time scale. Operators now get Grafana-class zoom, smooth bucketed data at every range, and typography that doesn't fall out of its containers.

## [0.10.204] - 2026-05-16

### Fixed — "Bulk acknowledge failed" when clearing all alerts from the unfiltered view
- The Alerts → "Select all matching" → "Acknowledge" flow was hitting `POST /api/alerts/bulk-acknowledge-filter` with no filter query params (because `buildAlertParams` only emits dropdowns that have non-empty values). The server's filter handler rejects no-filter requests with `400: "at least one filter is required"` — an intentional safety guard against accidental "ack everything in the DB" calls. The JS caught the 400 and showed the generic "Bulk acknowledge failed" toast.
- **Fix in `confirmBulkAck()` (`cmd/api/static/js/admin-main.js:1240-1258`):** when entering `selectAllMatchingMode` with no `acknowledged=` param already present, the JS now appends `acknowledged=false`. This makes the operator's intent explicit ("ack all unacknowledged alerts" — which is what "clear all alerts" naturally means) and satisfies the server's safety guard.
- **Bonus correctness improvement:** the underlying `AcknowledgeAlertsByFilter` SQL rewrites the `notes` field on every matched row, including already-acked ones. Defaulting to `acknowledged=false` means existing ack notes on acked rows are preserved, not overwritten with whatever (often empty) notes the operator typed for the bulk action.
- **Error message clarity:** the catch handler now surfaces the server's actual error text in the toast (e.g. "Bulk acknowledge failed: at least one filter is required") instead of always showing the generic fallback. Opaque network errors still fall back to the generic message.

### Why this matters
The unfiltered Alerts tab is the most common entry point for "clear all alerts" — the exact path that was broken. Operators saw an unexplained "Bulk acknowledge failed" with no further context. The fix preserves the server's safety guard while making the common case work, and the better error toast means future similar issues are diagnosable from the UI alone.

## [0.10.203] - 2026-05-16

### Fixed — duplicate startup log output from racing processes
- The container runs three processes (API, poller, trap-receiver) and each calls `database.NewDatabase()` on boot. All three were racing to run the same idempotent post-migration setup (`EnsurePartitions`, `ConfigureAutovacuum`, `CollapseLegacyConfigRevisionDuplicates`, `EnsureDefaultPolicy`, `auditDeviceVendors`, `migrateEncryptSecrets`), producing 2-3× duplicates of every setup log line — `Database: connected`, `WARNING: ENCRYPTION_KEY not set`, partition info, vendor audit, etc.
- Added a Postgres session-scoped advisory lock (`pg_try_advisory_lock(0x46574d4e53545550)`, the ASCII bytes of "FWMNSTUP") around the post-migration block. Exactly one process wins the race and runs the chatty setup; the other two log a single explanatory line ("another process holds the migration lock; skipping...") and move on.
- `AutoMigrate` itself is left running unconditionally because schema must exist before any process queries it, regardless of who wins the lock. GORM's silent logger (configured at line 55) keeps it noiseless on no-op runs.
- Lock is intentionally NOT released — it's session-scoped, so Postgres drops it when the connection closes (5-minute `SetConnMaxLifetime` boundary, or process exit). By then all sibling processes have already passed the setup branch and won't re-attempt.
- **Data safety:** all operations under the lock are idempotent. Losing the race is correctness-safe — the second process just doesn't repeat work that's already been done. SQLite (test) path returns `true` unconditionally and runs setup inline (single-process anyway).

### Why this matters
v0.10.202 cleaned up the partition-creation log spam but exposed the underlying pattern: every startup log line appeared twice with the same timestamp, once with a `database.go:NNN:` prefix (from poller/trap-receiver with `Lshortfile`) and once without (from the API with default flags). After this change, startup logs from the database layer fire exactly once per restart.

## [0.10.202] - 2026-05-16

### Fixed — partition creation log spam on legacy deployments
- `EnsurePartitions()` now probes `pg_partitioned_table` for each candidate parent (`syslog_messages`, `syslog_summaries`, `trap_events`, `flow_samples`) BEFORE attempting to attach a monthly partition. Deployments that ran GORM `AutoMigrate` before the partitioning code was added (rust-01 is one) carry these as plain tables, and `CREATE TABLE ... PARTITION OF ...` against a plain parent fails with SQLSTATE 42P17 — producing 28 noise lines per startup (4 tables × 7 months ahead).
- New behavior: probe once, log a single clear info line per plain table ("syslog_messages is a plain table on this deployment; skipping monthly partition creation"), and skip the per-month attempts entirely. No behavior change for fresh deployments where the tables are partitioned from the start.
- **Data safety unchanged:** the plain tables continue to function normally. The only "lost" benefit is partition-prune query speedups and the ability to `DROP PARTITION` (O(1)) instead of `DELETE ... WHERE timestamp < ...` (writes WAL). A separate in-place migration to convert plain → partitioned is planned for a future release; the log line points at `docs/partition-migration.md`.

### Cleanup
- Removed the obsolete `version: '3.8'` line from `docker-compose.yml`. The Compose spec dropped the `version` field years ago and Docker emits a `WARN[0000] ... the attribute version is obsolete` on every command. No behavior change.

## [0.10.201] - 2026-05-16

### Changed — `DATA_DIR` parameterized in shipped compose
- `docker-compose.yml` volume `./data:/data` is now `${DATA_DIR:-./data}:/data`. Fresh deploys still get a project-local `./data` directory with no setup. Production deployments set `DATA_DIR` in a `.env` file (gitignored) to point at a dedicated partition — eliminates the recurring "Your local changes to docker-compose.yml would be overwritten by merge" on every upstream pull.
- New `.env.example` documents the variable with the prod rust-01 value (`/mnt/STORAGE/firewall-mon-data`) commented out so future deployers can see the intended pattern without inheriting our specific path.

### Why this matters
The rust-01 host outgrew its root volume in 2026-05 (CHANGELOG v0.10.199) and was relocated to `/mnt/STORAGE`. The prod compose carried the new path as an uncommitted local edit, which collided with every upstream `git pull`. Parameterizing via env keeps the prod path on the prod box and the upstream file generic.

## [0.10.200] - 2026-05-16

### Hardened — config-backup false-alert defenses (defense-in-depth pass)
The merge-into-latest model in v0.10.198 closed the false-alert path for FortiGate devices tagged `Vendor="fortigate"`, but a multi-angle audit (4 parallel research streams covering the existing code, RANCID/Oxidized canonical practice, FortiOS/PAN-OS/Cisco ASA password-format research, and design-alternative brainstorm) surfaced four remaining gaps. This release closes them.

#### Startup vendor audit (`internal/database/database.go`)
- Replaced the blunt `UPDATE devices SET vendor = 'fortigate' WHERE vendor = '' OR vendor IS NULL` with `auditDeviceVendors()`. Still backfills empty vendor → `fortigate` (the in-code default), but now also:
  - Counts devices per vendor and logs the distribution at startup.
  - Cross-references each distinct vendor against `configdiff.HasRichNormalizer()` — any vendor with config revisions but only identity hashing is flagged with `normalizer=IDENTITY (false-alert risk on config-backup diffs)` and a summary WARNING line.
- **Why this matters:** a device tagged with one of the 4 unsupported vendors (`sonicwall`, `firewalla`, `pfsense`, `opnsense`) falls through to identity hashing, which makes random-IV ENC ciphertext look like a real change every backup. The log makes the gap visible without mutating data.

#### FortiGate PEM regex generalized (`internal/configdiff/vendor_fortigate.go`)
- Replaced `fortiPrivateKeyBlockRegex` (anchored to `set private-key`) with `fortiPemBlockRegex` matching ANY `set <field> "-----BEGIN..."` PEM-bearing line. Now covers `set ca`, `set csr`, `set certificate`, plus any future PEM-bearing field FortiOS adds.
- **Critical regex bugfix uncovered during testing:** the original `[^"]+` pattern was greedy across newlines under `(?s)` dotall mode. With TWO adjacent PEM blocks (e.g. `set ca` followed by `set csr`), the engine would collapse both blocks into a single capture, masking the second field name. Fixed by anchoring the BEGIN/END inner-text to `[^"\r\n]+` so each match stays on one line; the body between them remains multi-line via the `[^"]*?` (non-greedy, no-quote) inner pattern. Added `TestFortiGateNormalizerStripsCertAndCSRBlocks` to guard against regression.

#### PAN-OS normalizer filled in (`internal/configdiff/vendor_paloalto.go`)
- Was an identity stub; now strips: `<phash>...</phash>` (re-salted per emission), `<secret>...</secret>` (LDAP/RADIUS/IKE/SNMPv3), `<key>...</key>` (AES-256-CBC, random IV), `<password>`, `<passphrase>`, and `<config version="..." detail-version="..." ...>` root-attribute drift.
- Heuristic: 3+ occurrences of the `*****` literal flag the backup as `QualityMasked` (PAN-OS sanitized export from non-superuser).
- 4 new tests cover stable-across-emissions, real-change-detected, sensitive-content-stripped, sanitized-export-detected.

#### Cisco ASA normalizer filled in (`internal/configdiff/vendor_cisco_asa.go`)
- Was an identity stub; now strips ONLY Type 6 secrets (`enable secret 6 ...`, `username X password 6 ...`, `key 6 ...`, `key-string 6 ...`) and the `: Saved` / `: Written by` timestamp headers. Master passphrase declaration also masked.
- **Deliberately leaves Types 5/7/8/9 visible** — those hash forms are deterministic (MD5-crypt, Vigenere, PBKDF2-SHA256, scrypt), so a real password rotation produces a detectable hash change. Only Type 6 (AES with master passphrase + random nonce per emission) is truly volatile.
- 3 new tests cover stable-across-emissions, real-change-detected, type5/7/8/9-not-masked.

#### Alert-side regression test for IV-drift merge (`internal/api/handlers/handlers_config_revision_fortigate_test.go`)
- Existing `TestReceiveConfigRevision_FortiGateIVDrift_MergesIntoLatest` proved the merge happened and the latest bytes won, but did NOT assert that the alerts table stayed empty. Now wires a real `AlertManager`, parses the response `action`, and asserts `CONFIG_CHANGE` count = 0 after the IV-drift merge. The marquee guarantee for the false-alert fix.
- New paired test `TestReceiveConfigRevision_FortiGateRealChange_FiresExactlyOneAlert` proves the alert path still fires on a real structural change — guards against a regression that silenced all config alerts entirely.

#### Registry helpers (`internal/configdiff/normalize.go`)
- New `HasRichNormalizer(vendor)` returns true only for vendors that publish at least one volatile pattern. Used by the startup audit.
- New `RegisteredVendors()` returns the registered vendor key set (unordered). Forward-compatible with vendor-management UI.

### Why this matters
The v0.10.198 release closed the false-alert path for the common case (FortiGate devices, default vendor). Reports of continued false alerts in the field were traced to two scenarios this release addresses: (1) devices added with `vendor=""` before the model's `default:fortigate` GORM directive took effect, and (2) PEM-bearing fields beyond `set private-key` that drifted under the narrow regex. With the audit log now surfacing identity-vendor devices and the regex covering all `set <field> "-----BEGIN..."` lines, both vectors are closed. Design trade-off held from RANCID/Oxidized canonical practice: a real plaintext password rotation produces no alert at all (the ENC blob is masked the same as an IV-only change). The user has explicitly accepted this trade-off — restore fidelity preserved via the merge path always overwriting `ConfigText` with the latest live ciphertext.

## [0.10.199] - 2026-05-11

### Fixed — `syslog_messages` could grow unbounded in default deploys
- **`docker-compose.yml` now ships with `RETENTION_SYSLOG_CRITICAL_DAYS=30`**, bounding severity 0-5 syslog (notice / warning / error / critical / alert) to 30 days. The app already supported this env var via `RetentionConfig.SyslogCriticalDays` (`internal/config/config.go:75`), but the in-code default of `0 = never delete` combined with firewall traffic logs typically arriving at severity 5 (notice) caused `syslog_messages` to accumulate indefinitely. Severity 6-7 (info/debug) was already bounded by `SyslogInfoDays` + the 5-minute aggregation cycle; the gap was severity 0-5.
- **Production-incident context (rust-01, 2026-05-11):** `syslog_messages` reached 17 GB / 18.9 M rows, of which 18.6 M (98.6%) were severity 5 with no retention. The table filled the 57 GB root volume and Postgres crashed mid-WAL recovery (`SQLSTATE 57P03`). Recovery sequence: freed root space (Docker image prune + relocate unrelated files), took a `pg_dump`, migrated PGDATA to a dedicated 100 GB partition, set the env var, one-shot-deleted ~4 M rows older than 30 days where severity < 6, `VACUUM FULL ANALYZE syslog_messages` reclaimed ~5 GB of heap. Ongoing retention now flows through `Database.CleanupOldData` (`internal/database/database.go:732`).
- **No code change to in-code default.** Deployers explicitly relying on unbounded retention should set `RETENTION_SYSLOG_CRITICAL_DAYS=0` in their own compose; new deploys using this repo's compose file now get the safer 30-day default out of the box.

### Fixed
- Bumped server / Dockerfile version label.

## [0.10.198] - 2026-04-28

### Changed — major UX cleanup of config-backup history
- **Storage model is now merge-into-latest.** When a backup arrives with the same vendor-normalized checksum as the device's most-recent stored revision, the existing row is **updated in place**: `ConfigText` is refreshed (so the latest restore-target carries fresh ENC ciphertext), `LastVerifiedAt` is bumped, `VerifyCount` is incremented. No new row, no alert. Different normalized checksum → new row + alert as before. Result: the Config History tab shows **one row per logical configuration state** instead of dozens of IV-drift duplicates.
- **Config History UI** simplified accordingly: dropped the distinct/all toggle (every row is already distinct). New columns:
  - **First seen** — when this config state was first observed.
  - **Last verified** — relative time of the most recent confirmation ("verified 2m ago"); absolute time on hover.
  - **Verified** — small `N×` badge showing how many polls/syslog events confirmed this state. Lets operators see the system is actively monitoring even when no changes happen.
- **Diff modal**: when two stored revisions are picked for compare, they always represent real config differences (the same-normalized-hash case can't arise after merge-into-latest). The "no real changes between these backups" green-banner safety net is kept for legacy rows.

### Added — data safety
- **Suspect-bytes path.** Every incoming FortiGate backup is structurally validated (header present, size ≥ 1KB, ≥5 `config X` blocks, balanced `config/end`, ≤1% non-printable bytes, valid UTF-8). If validation fails, the bytes are stored as a **new row tagged `BackupQuality="suspect"`** rather than overwriting the prior good copy. Operator can see exactly which backup was suspect, and the previous good revision remains intact for restore.
- **Transactional merge decision.** The lookup-decide-update sequence runs in a single GORM transaction with `FOR UPDATE` on the latest row, so concurrent backups for the same device serialize correctly.

### Schema
- New columns on `device_config_revisions`: `FirstSeenAt`, `LastVerifiedAt`, `VerifyCount`. AddColumn-if-missing migration extends the existing pattern (mirrors `normalized_checksum` / `tftp_server_ip`).

### Migration of legacy data
- One-time `CollapseLegacyConfigRevisionDuplicates()` runs at server startup. It walks each device's history, finds runs of identical `NormalizedChecksum`, keeps the most-recent row of each run (preserving its bytes for restore) and sets `FirstSeenAt` / `VerifyCount` to capture the run's metadata. Idempotent; safe to run repeatedly. Deletes the duplicate rows. Logged at startup with the deleted-count.

### Retention simplified
- Old policy: "keep last 50 + 90 days, collapse runs older than 50."
- New policy: **delete older than 365 days, cap at 500 distinct states per device**. The collapse logic is gone (no IV-drift duplicates accumulate any more). Most devices will sit well under both limits.

### Validator
- New `internal/configdiff/validate.go` with `ValidateFortiGateBackup()`. 9 unit tests covering empty / truncated / missing-header / missing-system-global / too-few-blocks / unbalanced-blocks / binary-corruption / sparse-non-printable / real-config-passes.

### Tests
- New `TestReceiveConfigRevision_FortiGateIVDrift_MergesIntoLatest` — exact merge semantics asserted (1 row, VerifyCount=2, latest bytes win).
- New `TestReceiveConfigRevision_SuspectBytes_DoNotOverwriteGood` — proves the data-loss safety net.
- New `TestCleanupConfigRevisions_DeletesBeyond365Days` / `_CapsAt500PerDevice` / `_UnderCapAndUnder365_PreservesEverything`.
- New `TestCollapseLegacyConfigRevisionDuplicates` (with idempotency assertion).
- Existing `TestReceiveConfigRevision_TriggerSourceAndQualityRoundTrip` updated to merge-into-latest expectations.
- Three obsolete distinct-mode tests replaced with one consolidated `TestGetDeviceConfigHistory_ReturnsRowsNewestFirst`.

### Why this matters
The user-stated problems with v0.10.187 → v0.10.197 were: "we're backing up too much default junk" (still true at the FortiOS layer; that's a separate iteration) and "we keep configs that only differ in ENC passwords." This release fully closes the second one — the duplicate rows simply don't exist any more. Every row in History is something you can compare meaningfully against any other row.

## [0.10.197] - 2026-04-28

### Tests
- Hostile QA pass on the diff modal flow after the user reported it was still blank in v0.10.195 (their deployed version). Two parallel research streams converged on a single answer: **the v0.10.195 HTML on disk still has the broken Tailwind-soup modal markup**; v0.10.196 fixed it; the user just hasn't deployed v0.10.196 yet. Five guard tests added to make sure no regression slips in:
  - **`device_detail_html_test.go`**: reads `web/admin/device-detail.html` from disk (the same file `LoadHTMLGlob` reads at startup) and asserts the `#config-diff-modal` element has class **exactly** `"modal"` — no `hidden`, no `fixed`, no `top-0`, no `bg-black/60`, no Tailwind utility classes that fight with the legacy `.modal.active` rule. Also asserts `.modal-content`, `#config-diff-meta`, `#config-diff-body`, and the close-button `data-action` are all present.
  - **`handlers_config_diff_test.go`**: 4 tests on the diff endpoint —
    1. Response shape matches every field the JS reads (`from.id`, `from.config_text`, `from.normalized_checksum`, `from.trigger_source`, `from.backup_quality`, `to.*`, `vendor`, `volatile_patterns[].name`, `volatile_patterns[].regex`).
    2. Bad revision IDs return 404 (JS renders the visible error).
    3. Missing query params return 400.
    4. Non-FortiGate vendors get an empty `volatile_patterns` (identity normalizer).
- Also confirmed Gin route registration is correct — `/api/devices/:id/config-history/diff` (literal) is matched ahead of `/api/devices/:id/config-history/:revId` (param) regardless of registration order. Verified via the Gin tree implementation (gin@v1.11/tree.go:438-464) and a tree_test.go fixture covering the exact pattern.

### Fixed
- Bumped server / Dockerfile version label.

## [0.10.196] - 2026-04-28

### Fixed
- **Config diff modal renders blank — root cause: CSS class collision**. My modal markup mixed Tailwind utility classes (`hidden fixed top-0 left-0 right-0 bottom-0 bg-black/60 z-[200] items-center justify-center`) with the legacy `.modal` / `.modal.active` pattern from `admin-shared.css`. The legacy CSS already provides complete full-screen fixed positioning + dark overlay + centered flex layout for `.modal` — but the Tailwind `.hidden` class was applying `display: none` and even though `.modal.active` should win on specificity in theory, the resulting markup just didn't render correctly. Every other modal on the device-detail page uses the simple `class="modal"` pattern via `createConfigModal()` in `admin-device-detail.js` and works fine. Replaced my over-engineered markup with the proven legacy pattern using `.modal` + `.modal-content` and inline styles for the size override. No more class fight.

### Why this matters
The marquee Config History feature (vendor-aware diff with volatile-line masking, banner for "no real changes", side-by-side comparison) has been functionally complete since v0.10.187 — but the diff modal itself never displayed for the user because of this CSS issue layered on top. The repeated v0.10.191/192/195 fixes addressed *real* bugs in the renderer (regex `g` flag, error boundaries, disk-vs-embed serving) but couldn't surface anything because the modal container itself was effectively invisible. This patch fixes the actual containment.

## [0.10.195] - 2026-04-28

### Fixed
- **Static admin assets (JS/CSS) now hot-update from `git pull` + service restart, no binary rebuild required**. Previously `cmd/api/static/` was *only* served from the embedded FS (`//go:embed`), so JS-only changes were invisible to operators who pulled-and-restarted. Now the server checks for `./cmd/api/static` on disk at startup: if present, it serves from disk; if not (e.g. in a Docker container that ships only the binary), it falls back to the embedded FS. **Bare-metal deploys: `git pull && systemctl restart fwmon-api` now suffices for any frontend change**, the same way it always has for HTML changes (`./web/admin/*.html` was already loaded from disk via `LoadHTMLGlob`). Logged at startup as `Static assets: serving from ./cmd/api/static (disk)` or `... (embedded FS)`.
- **Docker workflow unchanged**: the runtime image doesn't ship the source `cmd/api/static/` dir, so the embedded fallback kicks in. Docker users still rebuild the image to pick up frontend changes (no regression vs. v0.10.194 behavior).

## [0.10.194] - 2026-04-28

### Added
- **`GET /api/version`** — returns `{"version":"0.10.194"}`. Public, no auth required so the admin UI can hit it on every page load. Source of truth is the new `ServerVersion` constant in `cmd/api/main.go`.
- **Admin console version log** — `admin-common.js` now fetches `/api/version` on every admin page load and prints `Firewall-Mon vX.Y.Z` to the browser console in blue. Operators can open dev tools → Console to instantly verify whether their last redeploy actually shipped. **If the printed version doesn't match the latest CHANGELOG entry, the binary or docker image was not rebuilt** — `git pull` alone is insufficient because static JS/CSS are `//go:embed`'d into the Go binary and HTML files are baked into the docker image at build time.

### Fixed
- Dockerfile `org.opencontainers.image.version` label was stuck at `0.10.125`. Bumped to current.

### Operator note (read this if "I redeployed but nothing changed")
Static admin assets (JS, CSS) are compiled into the `fwmon-api` binary via `//go:embed`. HTML templates are read from `./web/admin/` which the Dockerfile bakes into the container image. To pick up frontend changes:
- **Bare-metal**: `git pull && go build -o fwmon-api ./cmd/api && systemctl restart fwmon-api` (or your service name).
- **Docker compose**: `git pull && docker compose build && docker compose up -d` (the `build` step is required — `docker compose pull` only updates *external* images).
- **Docker prebuilt image**: `docker pull <your-image-tag> && docker compose up -d`.
After redeploy, hard-refresh the browser (Ctrl+Shift+R) and check dev-tools console — `Firewall-Mon v0.10.194` (or newer) should appear.

## [0.10.193] - 2026-04-28

### Added
- **Config History tab now defaults to "show only real changes"**. With the always-store policy storing 96 backups per device per day, the History tab was 50 rows of identical-looking IV-drift noise. Now the tab collapses runs of identical `NormalizedChecksum` to one representative row each — the *earliest* of each run (representing "when this state began"). 100 IV-drifted backups → 1 row. A real edit produces a new row.
- **Toggle in the summary line**: *"3 distinct states from 287 total backups | Show all 287 backups"* / *"287 of 287 backups | Show only changes"*. One click swaps modes; compare selections reset because the visible IDs change.
- **Server**: `GET /api/devices/:id/config-history?distinct=true` is the new opt-in. Without the param the endpoint returns every stored revision (backward compatible). Response now also includes `total_all`, `total_distinct`, `total_shown` so the UI can render the summary line.

### Tests
- 3 new tests in `handlers_config_revision_retention_test.go`:
  - `TestGetDeviceConfigHistory_DistinctMode_CollapsesRuns` — A→B→A→C across 20 rows collapses to exactly 4 representative rows (newest-first, each the earliest of its run).
  - `TestGetDeviceConfigHistory_NonDistinctReturnsEverything` — without `?distinct`, every row up to the 50-cap is returned.
  - `TestGetDeviceConfigHistory_DistinctMode_AllSameHash` — the user-described worst case: 100 IV-drifted backups all with the same normalized hash collapse to exactly 1 row.

## [0.10.192] - 2026-04-28

### Fixed
- **Config diff modal: "blank body" when comparing two backups with no real differences**. With the v0.10.187 IV-drift fix, every poll cycle stores a new revision even when nothing changed, so two consecutive revisions of the same FortiGate normalize to the same hash. Picking those two revisions in the Compare picker correctly produced an empty diff (everything is volatile / unchanged) — but the modal showed an empty body, which looked like a bug. Now:
  - When `from.normalized_checksum === to.normalized_checksum`, the modal shows a clear green banner: *"No real configuration changes between these two backups. Both revisions normalize to the same checksum. The raw bytes differ only because FortiOS regenerates a fresh AES IV salt for every ENC blob on every emission."*
  - The Compare-button hint now warns up-front when the two selected revisions share a normalized checksum, so the user knows what to expect before clicking.
- **Network / server errors during diff load** (HTTP non-200, JSON parse failure, fetch reject) now render a clear error message in the modal body instead of leaving it blank. Modal opens immediately on click with a "Computing diff…" placeholder so something is always visible.
- **Diagnostic console logging** added to the diff load path: HTTP status, response body, and any thrown error get logged with `[diff]` prefix so future debugging needs only browser dev tools, not server logs.

### Note
The v0.10.191 fixes (regex `g` flag, error boundary, O(n) HTML build) are still required — but they only take effect after the **server binary is redeployed** (browser refresh alone re-fetches the JS only from whatever the server serves; if the server still runs an older version, the browser still loads the old JS). To ship: `git pull` the server, restart the binary, then hard-refresh (Ctrl+Shift+R).

## [0.10.191] - 2026-04-28

### Fixed
- **Config diff modal: blank screen bug**. Multiple issues in the diff renderer for two FortiGate config revisions:
  1. **Volatile-pattern regexes had no `g` flag** — `.replace(regex, …)` only replaced the *first* match per pattern, so on a config with 30+ ENC lines only the first got masked. The other 29 leaked into the diff as red/green deltas, swamping any real change. Now all compiled patterns get the `g` flag.
  2. **HTML built via `+=` string concatenation** — O(n²) on some browser engines. For 5 000-line configs this could hang the browser visibly. Now builds via `array.push(...)` + `parts.join('')` (O(n)).
  3. **No error boundary around the render** — any JS exception silently aborted, leaving the modal body empty (looked blank). Now wrapped in try/catch with a user-visible error message and `console.error` for diagnostics.
  4. **Modal opened only after rendering completed** — for slow renders the user clicked "Compare" and saw nothing for a moment. Now the modal opens immediately with a "Computing diff…" placeholder, then swaps in the rendered HTML.
  5. **Hard cap at 10 000 diff lines** — protects the browser from pathologically large configs. Truncation banner appears at the bottom with a hint to download both revisions for offline comparison.
  6. **Defensive null-checks** on `data.from`, `data.to`, and `data.volatile_patterns` in case the server response shape ever drifts.

## [0.10.190] - 2026-04-28

### Fixed
- **Header "select all" checkbox carried over its checked state when navigating to next/prev page**, even though none of the new page's row checkboxes were actually selected. Caused by the render order in `renderAlertsTable` reading checkbox state before the new tbody was rendered. Now the header checkbox + indeterminate state + selection state + select-all-matching mode are explicitly reset before the new HTML is swapped in.

### Added
- **"Select all N matching the filter" flow on the alerts page**. The header checkbox still selects only the visible page (page-scoped selection is the safe default), but when the page is fully selected and there are more matching rows than fit on this page, an inline banner appears: *"10 selected on this page. Select all 247 matching the current filter."* Clicking the link puts the UI in a "select all matching" mode — visible chip in the toolbar — and the next "Acknowledge selected" call uses the new filter endpoint instead of an ID list. This is the GitHub / GMail pattern; safer than a single-click "ack everything" button. Banner clears on filter change, page change, manual Clear, or after the bulk-ack completes.
- **`POST /api/alerts/bulk-acknowledge-filter`**: accepts the same query params as `GET /api/alerts` (`device_id`, `alert_type`, `severity`, `acknowledged`) plus an optional `{notes}` body. Single SQL `UPDATE WHERE <filter>` — bounded only by the filter, not by client-side ID lists, so it scales past the 500-ID cap on the existing endpoint. **At least one filter is required**; an empty filter returns 400 to prevent accidental "ack everything in the database" calls.
- **`Database.AlertFilter` struct + `AcknowledgeAlertsByFilter`**: typed filter object, nil `Acknowledged` means "any". Same pattern works for any future filter-based bulk operations.

### Tests
- 4 new tests in `handlers_alerts_bulk_test.go`: ack by `severity=warning`, ack by `acknowledged=false` (the common "ack all unacked" use case), 400 when no filter is provided, combined `device_id+alert_type+acknowledged=false` correctly excludes other devices and pre-acked rows. Total bulk-ack coverage now 9 tests.

## [0.10.189] - 2026-04-28

### Tests
- **Marquee end-to-end test for the FortiGate hash-drift fix** (`handlers_config_revision_fortigate_test.go`): with `Device.Vendor="fortigate"`, two IV-drifted FortiOS-shaped configs round-tripped through `ReceiveConfigRevision` produce identical `NormalizedChecksum` despite different raw checksums (the actual on-the-wire scenario). Companion test asserts a real change (added firewall policy) produces a *different* normalized checksum. Plus tests for `TriggerSource`/`BackupQuality` round-trip + response shape.
- **Retention cleanup tests** (`handlers_config_revision_retention_test.go`): `CleanupConfigRevisions` exercise — keep top 50 regardless of age, delete beyond 90 days when outside top 50, leave fewer-than-50 untouched within the 90-day window, delete >90-day rows even when total < 50, collapse identical-`NormalizedChecksum` runs in older window keeping the most-recent row of each run (precise survivor identity verified by raw checksum).
- No production behavior change in this release — purely test coverage on the v0.10.187 code paths that were previously only unit-tested in isolation.

## [0.10.188] - 2026-04-28

### Added
- **Bulk-acknowledge alerts**: per-row checkboxes plus a "Select all on page" header checkbox. Toolbar above the alerts table shows the selected count and an "Acknowledge selected" button that opens a notes modal applying the same notes to every selected alert in one API call. Works on both small and large selections (capped at 500 IDs per request).
- **`POST /api/alerts/bulk-acknowledge`**: accepts `{ids: [...], notes: "..."}` and runs a single SQL `UPDATE ... WHERE id IN (...)`. Returns `{acknowledged: N, requested: M}`. Validates non-empty array and per-request cap.

### Changed
- **Acknowledging an alert no longer bounces the user back to page 1.** Both single-alert ack (existing button) and the new bulk-ack now refresh in place at the user's current page. If the page would become empty (e.g. when filtering "Unacknowledged" and acking everything visible), the UI walks back one page until it finds content or hits page 1.
- **Alert row click vs. checkbox click**: row-click → "show alert detail" handler now ignores clicks on form controls and `data-action` elements, so checkbox clicks no longer trigger the detail modal.

## [0.10.187] - 2026-04-28

### Fixed
- **FortiGate config-change alert false positives**: Every backup of an unchanged FortiGate produced a new MD5 (and a new alert) because every `set <field> ENC <blob>` line uses a fresh random 4-byte IV per emission (verified against `gquere/CVE-2019-6693`, `saladandonionrings/cve-2019-6693`, Oxidized issue #1199). Same plaintext password → different ciphertext on every backup. Server now hashes a vendor-normalized copy of the config (FortiGate strips ENC blobs, `BEGIN ENCRYPTED PRIVATE KEY` blocks, `#config-version=`, `#conf_file_ver=`, `#private-encryption-key=`, `set last-login`, `!System time:`) for the change-detection comparison. Alerts only fire when the normalized hash actually changes. Raw `ConfigText` is preserved unchanged for restore + diff display. Vendor-scoped: identity normalizer for non-FortiGate vendors so behavior is unchanged for them.

### Changed
- **`ReceiveConfigRevision` always stores every received backup** (drops the previous dedup-by-raw-checksum branch). With random-IV ciphertext drift the raw bytes always differ, and dedup at write time would silently lose the latest restorable bytes after a real password rotation. Retention runs a separate collapse pass for older history.
- **`GetDeviceConfigHistory` limit** raised from 10 → 50 revisions.

### Added
- **`internal/configdiff` package**: `Normalizer` interface, vendor registry (`fortigate`, `paloalto`, `cisco_asa`, `generic`), MD5 hash convenience, plus VolatilePatterns published per vendor for the diff UI to mask. Full unit-test coverage with synthetic fixtures (two unchanged snapshots, real-change snapshots, password-only snapshot, masking detection, vendor lookup case-insensitivity).
- **`DeviceConfigRevision` schema**: `NormalizedChecksum`, `BackupQuality` (`full`/`masked`/`unknown`), `TriggerSource` (`syslog`/`poll`/`manual`). AddColumn-if-missing migration following the `tftp_server_ip` pattern.
- **`GET /api/devices/:id/config-history/diff?from=&to=`**: Returns both raw `ConfigText` blobs + the vendor's `volatile_patterns` so the UI can mask IV-churning lines as `(volatile)` rather than red/green deltas.
- **Config History tab UI**: radio compare picker (From / To), trigger-source + backup-quality + normalized-hash columns, side-by-side modal diff with volatile-line masking. Diff uses raw text so operators see real values for non-secret changes.
- **Retention job for config revisions**: daily, keep last 50 revisions per device + last 90 days, whichever is greater. Within the older-than-top-50 portion of the 90-day window, collapse identical-`NormalizedChecksum` runs to one representative row each (most recent of each run kept).

### Why
The drift is FortiOS-specific behavior — by design — and the canonical industry workaround (Oxidized, RANCID for ~15 years) is regex-strip-then-hash. Vendor isolation ensures Palo Alto / Cisco / generic devices stay on the existing raw-checksum behavior until evidence of a similar drift class shows up.

## [0.10.186] - 2026-04-27

### Added
- **Per-probe `TFTP Server IP` setting**: Admin can now enter, on each probe's edit form, the IP address that firewalls in that probe's network use to reach the collector. The probe pulls this value via `GET /api/probes/:id/devices` (added alongside the device list as `tftp_server_ip`) and uses it as the destination IP in `execute backup config tftp <file> <ip>`. This replaces the collector's previous attempts to auto-detect the right outbound IP from inside Docker (which is unreliable when `PROBE_LISTEN_ADDR=0.0.0.0`). Field is optional — if left blank, the collector falls back to per-device auto-detection.

### Database
- New `probes.tftp_server_ip TEXT` column. Migration follows the existing AddColumn-if-missing pattern; existing rows get an empty string.

### API
- `Probe` model gains `TFTPServerIP string` (`json:"tftp_server_ip"`).
- `PUT /api/probes/:id` accepts `tftp_server_ip` in the update body (allowlisted).
- `GET /api/probes/:id/devices` response now includes `"tftp_server_ip"` alongside the existing `success` + `data` fields. Backward-compatible with collectors that ignore unknown fields.

## [0.10.185] - 2026-04-27

### Added
- **Server test suite** (Phase 4–5 of test plan):
  - `internal/database/testing.go`: `NewDatabaseForTesting` using in-memory SQLite via `github.com/glebarez/sqlite`; `sqliteDialect` added to `dialect.go` implementing `TimeBucket`/`QuoteIdent`/`IsPostgres` for test compatibility
  - `internal/api/handlers/testhelper_test.go`: shared `setupTestHandler`, `setupProbeAndDevice`, `doTestRequest` helpers
  - `internal/api/handlers/handlers_data_test.go`: 12 handler tests covering `validateProbe` (missing auth, wrong token, pending), `ReceiveConfigRevision` (save, dedup, second checksum, cross-probe 403, oversized 400), `ReceiveSystemStatuses` (save, cross-probe filtering, 100-record truncation, no-auth)
  - Critical security test: cross-probe data injection is rejected at both config revision and system status endpoints

## [0.10.182] - 2026-04-27

### Fixed
- **ConfigText truncation bug**: Server-side warning now logs when received config Length mismatch is detected. Root cause was in Firewall-Collector (Firewall-Mon#repo) where cleanOutput was incorrectly filtering config lines containing `$` character.

### Added
- **TFTP config fetch support**: Server ready to receive configs via TFTP from Firewall-Collector probes.

## [0.10.181] - 2026-04-27

### Fixed
- **admin.html chart CSS**: Updated embedded .chart-card styles to match admin-shared.css (padding:20px, height:340px, canvas max-height:280px)
- **device-detail.html canvas heights**: Updated inline canvas heights from 300px to 340px for consistency
- **connection-detail.html container height**: Updated container div from 300px to 340px

## [0.10.180] - 2026-04-27

### Fixed
- **Chart font sizes**: Increased from 9px to 11px across all charts for better readability
- **Doughnut chart aspect ratio**: Fixed maintainAspectRatio setting that prevented proper container filling

## [0.10.176] - 2026-04-27

### Fixed
- **Network Throughput chart**: Added adjustable time range selector like the public dashboard graphs - previously hardcoded to 24h only
- **Network Connection Map VXLAN detection**: Fixed bug where vxlan-prefixed interfaces (e.g., vxlan700) on FortiGate were not properly detected as overlays - now correctly identifies them as l2vlan (Software Switch) or vxlan (if verified in config)
- **Frontend/backend type consistency**: Moved bridge/Software Switch back to DIRECT_TYPES (same-site local switching) while keeping vxlan/l3ipvlan in OVERLAY_TYPES (IPSec tunnel children)

### Added
- **Standardized time range selectors**: All graph time range selectors now use consistent dropdown style with full options: 15m, 30m, 1h, 6h, 12h, 24h, 1w, 1m, 3m, 1y
- **Professional dropdown CSS**: New `.chart-range-select` class with custom dropdown arrow, hover states, and focus styles for enterprise look
- **FortiGate config text parsing**: Added ParseFortiGateVxlanConfig() to parse VXLAN definitions from FortiGate configuration text
- **SSH poll validation**: Added client-side validation to prevent enabling SSH polling without SSH credentials
- **Connection Map filter buttons**: Added VXLAN and Bridge filter buttons to Connection Map toolbar
- **Friendly type labels**: Connection Map now shows "Software Switch" instead of "bridge" for bridge-type connections
- **Debug logging**: Added logging when config revisions are received and saved

### Changed
- **All graph pages**: Converted from button groups to compact dropdown selects for time range selection
- **detectOverlayConnections**: Now fetches FortiGate config text to distinguish true VXLAN tunnels from Software Switch L2VLAN extensions

## [0.10.171] - 2026-04-23

### Fixed
- **FlowRollup SamplingRateAvg type**: Changed from uint32 to float64 to handle AVG() and weighted calculation results that return decimal values (e.g., "1024.0000000000000000")

## [0.10.170] - 2026-04-23

### Added
- **Verbose debug logging for sensor data**: Added per-sensor logging in ReceiveSensorDetails to debug why sensors aren't being saved

## [0.10.169] - 2026-04-22

### Added
- **Debug logging for sensor details**: Added logging to ReceiveSensorDetails handler to debug sensor data flow

## [0.10.168] - 2026-04-22

### Added
- **Config History: View in modal**: Added "View" button to configuration history table to display configuration in a popup modal with syntax formatting
- **Config History: Diff view**: Added "Compare" button to show diff between two configurations in a popup modal with color-coded additions/removals
- **Config History: Delete revision**: Added "Delete" button to remove individual configuration revisions from the UI

### Fixed
- **Config History: Download broken**: Fixed download button that was failing because the endpoint returns raw text but JS was expecting JSON. Now correctly fetches raw text directly.

### Changed
- **Config History table**: Now shows View, Download, Compare, and Delete action buttons for each revision

## [0.10.167] - 2026-04-22

### Fixed
- **Database: IRC migration transactional**: Wrapped IRC table recreation in transaction to prevent partial schema on failure
- **Database: GetLatestVPNStatuses nil slice**: Changed to return empty slice `[]models.VPNStatus{}` instead of nil on no records, prevents JSON `null` being sent to frontend
- **Chart: Triple API fetch optimization**: Refactored loadStatusHistoryChart/loadNetworkThroughputChart/loadCPUBreakdownChart to share a single fetch promise instead of 3 separate requests for identical data
- **Chart: Stale canvas text**: Added `clearRect()` before drawing "Not enough history data" text to prevent ghost rendering
- **JS cleanup: Duplicate connStyleLookup removed**: Removed local copy from admin-connection-detail.js; now uses canonical `connStyle()` from admin-common.js

## [0.10.166] - 2026-04-22

### Fixed
- **Database migration for new columns**: Added HasColumn/AddColumn migration helpers for SystemStatus (network throughput, CPU breakdown, memory breakdown fields) and VPNStatus (InterfaceName, Mode) fields. Existing databases will now automatically get the new columns on upgrade.

## [0.10.165] - 2026-04-22

### Added
- **Network Throughput Chart**: Added new chart section on device detail page showing network throughput (in/out kbps) from SSH performance data. Automatically hidden when no data available.
- **CPU Breakdown Chart**: Added new chart section on device detail page showing CPU breakdown (user/system/nice/idle/iowait/irq/softirq) as stacked area chart. Automatically hidden when no data available.
- **Enhanced SystemStatus Model**: Added network throughput fields (NetworkInKbps, NetworkOutKbps), CPU breakdown fields (CPUUser, CPUSystem, CPUNice, CPUIdle, CPUIowait, CPUIrq, CPUSoftirq), and memory breakdown fields (MemoryFree, MemoryFreeable).
- **Enhanced VPNStatus Model**: Added InterfaceName and Mode fields from SSH phase1 configuration.
- **VPN Tab Enhancement**: Added Interface and Mode columns to the VPN tunnels table on device detail page.
- **Connection Map Enhancement**: Added Interface and Mode columns to VPN tunnel detail panel in the connection map popup.

### Changed
- **Device Detail Page**: Network throughput and CPU breakdown charts are now displayed below the standard System Status History chart.


## [0.10.164] - 2026-04-21

### Fixed
- **Syslog DeviceID resolution**: Probe now relays syslog messages to API, and API resolves DeviceID from SourceIP using ResolveDeviceByIP (same logic as flow samples). Added SetHandler callback to TCP/UDP syslog receivers.

## [0.10.163] - 2026-04-21

## [0.10.162] - 2026-04-21

### Fixed
- **Admin sidebar**: Fixed `AdminCommon is not defined` error by wrapping `AdminCommon.renderSidebar()` in `DOMContentLoaded` to ensure admin-common.js is fully loaded before calling. Applied to all 8 admin pages.
- **Probe health popup**: Fixed modal width alignment in admin.html (520px) with admin-shared.css (1000px) to prevent small popup.

## [0.10.161] - 2026-04-21

### Added
- **Public dashboard chart modal**: Added click-to-expand functionality on CPU/Memory and Bandwidth charts to open a fullscreen modal with zoom/selection capabilities. Features: scroll to zoom, drag to select region, Shift+drag to pan, Reset button, ESC/Close to dismiss.

### Changed
- **Public Dashboard Display settings**: Simplified settings page by removing unused toggles (Show Hostname, Show Uptime, Show CPU Usage, Show Memory Usage, Show Active Sessions, Show Network Interfaces, Show Bandwidth Graphs, VPN Tunnels per Device). Kept only VPN Tunnels, Connection Map, and Refresh Interval settings which are actively used. Unused settings are automatically cleaned from the database on next load.
- **Alert Policies UI**: Redesigned the alert policy modal with improved visual hierarchy - grouped form fields into logical sections (Basic Info, Notification Channels, Alert Rules) with styled section headers, improved stat cards with icons on the policies page, and better compact table styling for alert rules.

### Fixed
- **Public dashboard CPU chart labels**: Fixed CPU chart to use month/day/hour/minute format for time ranges >= 168 hours (1w/1m/1y), matching the bandwidth chart label formatting.

## [0.10.160] - 2026-04-20

### Fixed
- **Network page**: Fixed missing `id="connections-table"` on table causing "Cannot set innerHTML of null" error.
- **Settings page checkbox alignment**: Changed notification, reports, and spike checkboxes from `setting-item` to `toggle-row` for proper label/checkbox alignment.
- **Report settings validation**: Made `report_daily_time` and `report_weekly_day` optional (empty allowed) to avoid validation errors when enabling reports without filling in all fields.
- **Report time/day dropdowns**: Replaced text inputs for `report_daily_time` and `report_weekly_day` with proper select dropdowns (30-minute intervals for time, day-of-week for weekly day) to prevent format errors and improve UX.
- **Report settings save**: Fixed save handler to include select elements so dropdown values are properly saved.
- **Public dashboard 1m/1y range**: Fixed backend switch to use numeric keys ("720", "8760") instead of string keys ("1m", "1y") so the frontend's numeric range values map correctly.

### Changed
- **Settings page CSS**: Added dropdown arrow styling for select elements in settings forms.

## [0.10.159] - 2026-04-19

### Changed
- **Public dashboard time range**: Added 1m and 1y options to match admin flows page time ranges (1h/6h/24h/1w/1m/1y).

## [0.10.158] - 2026-04-19

### Fixed
- **Deploy Probe registration key**: Removed redaction that was masking the registration key in the Deploy Probe modal, allowing the key to be properly displayed and copied.
- **Device detail tabs**: Added missing CSS rules (`.hidden`, `.tab-content`, `.tab-content.active`) that were preventing tab switching on device detail page.
- **Flows time range label**: Added `flow-range-label` span to display the selected time range on the admin flows page.
- **Public dashboard time range**: Consolidated separate bandwidth and CPU time range dropdowns into a single unified time range selector (1h/6h/24h/7d) for simplicity.

## [0.10.157] - 2026-04-18

### Added
- **Tailwind CSS**: Integrated Tailwind CSS v3 with custom GitHub dark theme configuration. Common component classes now use Tailwind utilities for consistent styling.

### Removed
- **SQLite support**: Removed all SQLite-related code and dependencies. PostgreSQL is now the only supported database type.
- **Migration UI**: Removed SQLite to PostgreSQL migration interface and related API endpoints.

### Changed
- **Default database**: Configuration now defaults to PostgreSQL (`DB_TYPE=postgres`) with separate host/port/user/password/name fields instead of SQLite's single file path.
- **Config env example**: Updated `config.env.example` to reflect PostgreSQL configuration.
- **Probe cards CSS**: Fixed overflow/bleed issue by adding `min-width: 0` and `overflow: hidden` to grid items.
- **Responsive design**: Added mobile sidebar with hamburger menu toggle and responsive breakpoints for admin dashboard.

## [0.10.156] - 2026-04-18

### Added
- **Syslog aggregation system**: Informational syslog (severity 6-7) is now aggregated into hourly/daily summaries for long-term storage efficiency. Configurable via `RETENTION_SYSLOG_INFO_DAYS` (default: 7) and `RETENTION_SYSLOG_CRITICAL_DAYS` (default: 0 = forever).
- **SyslogSummary model**: New `syslog_summaries` table stores aggregated syslog data with counts, sample messages, and normalized patterns.
- **PostgreSQL partitioning support**: High-volume tables (`syslog_messages`, `syslog_summaries`, `trap_events`, `flow_samples`) now support monthly range partitions via `EnsurePartitions()` for efficient data management.
- **Aggressive autovacuum**: High-volume tables now have aggressive autovacuum settings (1% trigger, 10ms delay) to reduce bloat.
- **Probe stats API**: `/api/probes/{id}/stats` now returns `last_hour` counts and `hourly_breakdown` (24 hours) for each data type.
- **Probe detail modal**: Click any probe card on the dashboard to see full stats with hourly breakdown.

### Changed
- **Syslog retention**: Critical syslog (severity 0-5) is now retained separately from informational syslog (severity 6-7). Use `RETENTION_SYSLOG_CRITICAL_DAYS=0` to keep critical syslog forever.
- **Syslog aggregation cycle**: Runs every 5 minutes alongside flow rollup. Hourly summaries are promoted to daily summaries after 48 hours.
- **`GetSyslogStats`**: Now combines raw syslog counts with summary counts for complete statistics.
- **Probe summary on probes page**: Probes management page now shows total data counts across all approved probes with last hour activity.
- **Timezone handling**: Public dashboard bandwidth and CPU charts now respect `display_timezone` setting. Backend returns ISO timestamps for proper client-side formatting.
- **Flows display**: Removed misleading "Est. Actual Bytes" calculation. Table now shows only sampled bytes.
- **Settings save**: Fixed bug where "Email Reports" and "Traffic Spike Detection" settings were not being saved.
- **Probe card UI**: Improved CSS styling for probe cards with better layout, hover effects, and formatted numbers.

## [0.10.155] - 2026-04-18

### Added
- **Probe data flow monitoring**: New `PROBE_DATA_LAG` alert fires when a probe has not received any data for `PROBE_DATA_LAG_ALERT_MINUTES` (default: 60). This catches queue-full, network, or misconfiguration issues that heartbeat-based `DEVICE_OFFLINE` alerts miss.
- **Probe data truncation alerts**: New `PROBE_DATA_TRUNCATED` alert fires when a probe sends batches >1200 items (truncated to 1000) multiple times within 5 minutes — indicates possible misconfiguration.
- **`LastDataReceived` timestamp**: Probe model now tracks last data receipt time via `last_data_received` column (indexed). Updated on all data ingestion endpoints.
- **`ProbeID` on alerts**: Alert model now supports `probe_id` field for probe-specific alerts without an associated device.

### Changed
- **Probe data flow check**: `CheckProbeDataFlow()` now runs at end of each poll cycle alongside `CheckEscalations()`.

## [0.10.154] - 2026-04-05

### Fixed
- **Sublane particle flow through cloud**: Cross-site expanded sublane halves (-a/-b) now use forward-only particles like the parent tunnel edges. Previously bidirectional particles on both halves collided at the cloud node.

### Added
- **Phase 2 count in tunnel labels**: Tunnel-bundle edges now show Phase 2 selector count (e.g., "IPSEC (3 P2) +2 DIAL-UP") when a tunnel has multiple Phase 2 entries
- **Per-Phase2 throughput in detail panel**: Phase 2 tab now shows BytesIn, BytesOut, Total, and Uptime per Phase 2 selector match — not just up/down status
- **Phase2Match byte counters**: Backend `Phase2Match` struct now includes `SrcBytesIn/Out`, `DstBytesIn/Out`, `SrcUptime`, `DstUptime` from the per-SA SNMP counters

## [0.10.153] - 2026-04-05

### Changed
- **Flow retention increased to 365 days**: Default `RETENTION_FLOW_DAYS` changed from 90 to 365. Rollups compress old data (5m → 1h → 1d) so storage is manageable. The 1-year time range button now has data to show.

### Added
- **Enterprise sFlow dashboard enhancements**:
  - **Estimated Actual Bytes** stat card: Shows `sampled_bytes × avg_sampling_rate` for true traffic volume
  - **Sampling Rate** stat card: Shows the average sampling ratio (e.g., "1:4096") so users know data is sampled
  - **Total Packets** stat card
  - **Top Ports chart**: Horizontal bar chart showing top 10 destination ports by bytes with well-known port names (HTTPS, SSH, DNS, etc.)
  - **Data Retention info card**: Shows current retention period and rollup tiers
- **Top destination ports query**: `GetFlowStats` now returns `top_ports` with port-to-name mapping for 17 well-known services

## [0.10.152] - 2026-04-05

### Added
- **sFlow v5 parser**: Complete rewrite of the sFlow receiver — now fully decodes sFlow v5 datagrams, flow samples (standard + expanded), and raw packet headers. Extracts IP src/dst, ports, protocol, TCP flags, and frame length from sampled Ethernet/IPv4 packets
- **sFlow relay wiring**: Probe now connects decoded sFlow samples to the relay pipeline via `SetFlowHandler()`. Flow data is queued and synced to the API server alongside SNMP/trap/syslog data

### Fixed
- **Connection flow stats query rollups**: `GetConnectionFlowStats` now supplements raw `flow_samples` with `flow_rollups` for historical periods >1hr (subnet strategy). Previously returned empty for any period after rollup consumption.
- **cidrToLikePattern handles all formats**: Now supports IP ranges (`10.0.1.0 - 10.0.1.255`), bare IPs (exact match), /32 (exact), and /8-/31 CIDR. Previously returned empty for non-CIDR inputs and treated /28-/32 the same as /24.
- **VPN cross-fill by remote IP**: Tunnel subnet cross-fill now matches by remote IP correlation instead of tunnel name (which never matched because names differ on each side of a tunnel)
- **Sampling rate in connection flow stats**: `GetConnectionFlowStats` raw byte/packet totals now apply sampling rate correction

## [0.10.151] - 2026-04-05

### Fixed
- **Empty tunnel traffic charts**: `getConnectionTunnelNames()` now handles `tunnel_indirect` and `wan_inferred` match methods by relaxing IP matching (same logic as `GetConnectionDetail`). Previously these connections returned zero tunnel matches → empty charts.
- **sFlow sampling rate correction**: All flow volume calculations now multiply bytes/packets by `sampling_rate`. Previously all sFlow data was underreported by the sampling ratio (typically 1000-4096x).
- **sFlow rollup preserves sampling correction**: `aggregateFlowsToRollup` now stores `bytes * sampling_rate` in rollup `bytes_sum`.
- **FortiGate CIDR subnets**: Collect subnet mask OIDs (.10/.13) and use `buildCIDR()` (was dead code) to convert Phase 2 selectors to proper CIDR notation (e.g., `10.0.1.0/24` instead of `10.0.1.0 - 10.0.1.255`). Falls back to IP range if mask unavailable.
- **FortiGate SSL-VPN byte counters**: Collect OIDs `.4`/`.5` (InOctets/OutOctets) for SSL-VPN sessions — enables traffic charts for SSL-VPN tunnels.
- **Empty chart placeholder**: Traffic charts now show "No traffic data available" message instead of blank canvas when API returns empty data.

## [0.10.150] - 2026-04-05

### Fixed
- **Saved layout restored correctly**: All node positions (cloud, sites, devices) saved by full ID and restored on reload. Previously cloud/sites collapsed to (0,0) after any drag-save.
- **Parallel edges spaced apart**: Edges sharing the same endpoints automatically get perpendicular offsets via `segments` curve-style (8px spacing). No curves — straight lines offset by a few pixels so each is visible and clickable.
- **DOWN X marker preserves tunnel label**: Uses `source-label` instead of overriding the main edge label. "IPSEC +2" stays visible on down connections.
- **Unsited devices placed below cloud**: No longer randomly overlapping the cloud at center. Spaced horizontally at y=450.
- **Removed waypoint nodes**: Off-net edges now use direct device→cloud edges with `segments` offset applied by `spaceParallelEdges()`. Simpler, no phantom nodes.
- **Site compounds have subtle fill**: 40% opacity dark background makes site boundaries visible behind edges.
- **Tunnel-bundle labels readable**: Dark background pill on edge labels prevents text from being hidden by crossing edges.

## [0.10.149] - 2026-04-05

### Fixed
- **Straight lines**: All edges are now straight (removed bezier curves and multi-edge detection). Expanded sublanes also use straight lines through the cloud
- **Expanded tunnels route through cloud**: Cross-site tunnel expansion creates sublane halves through the Internet cloud (Device→Cloud + Cloud→Device) instead of going direct
- **Cloud icon centered**: Cloud node is now a 64px emoji on a transparent 100px ellipse, properly centered
- **Site spacing**: Increased node repulsion (15000), edge length (350), node separation (200), and reduced gravity (0.15) to prevent sites from overlapping
- **VPN badge real-time updates**: VPN up/down counts on device nodes refresh every 15 seconds via VPN map polling. When a tunnel drops, the badge updates immediately
- **DOWN tunnel X marker**: DOWN edges show the red X marker on straight lines correctly

## [0.10.148] - 2026-04-05

### Removed
- **436 lines of dead code** from database.go (3306→2870 lines):
  - Entire site database subsystem (CreateSiteDatabase, GetSiteDatabase, ListSiteDatabases, DeleteSiteDatabase, SetSiteDatabaseStatus, UpdateSiteDatabaseSync, CreateSiteDatabaseFile, CloseAllSiteDBs, openSiteDB, GetOrCreateSiteDB) — scaffolded but never wired up
  - All SaveSite*/GetSite* sync methods (16 functions for SiteDevice, SiteSystemStatus, SiteInterfaceStats, SiteTrapEvent, SiteAlert, SitePingResult, SitePingStats, SiteSyslogMessage)
  - GetLatestUptime, FindConnectionByDevicePair, GetProbeApproval, GetAllProbeApprovals, GetLatestPingStats, GetSyslogMessagesByDevice — zero external callers
  - Unexported ProtoNames → protoNames (only used internally)
  - Removed unused `sync` import

## [0.10.147] - 2026-04-05

### Fixed
- **IRC bot security**: `isAdmin()` no longer returns true for all users. Only the bot's own nick is treated as admin, preventing external users from executing admin-only IRC commands
- **O(n^2) bubble sorts**: Replaced 4 manual bubble sorts in database.go with `sort.Slice` for proper O(n log n) performance on protocol distributions, merged KeyCounts, time series, and connection events

## [0.10.146] - 2026-04-05

### Changed
- **Consolidate shared utilities into admin-common.js**: `escapeHtml` (now includes `'` escaping), `formatBytes`, `formatNum`, `connStyle`, `matchMethodBadge`, `typeBadgeHtml` moved to admin-common.js. Removed 4x duplicate `escapeHtml`, 4x duplicate `formatBytes`, 3x duplicate `connStyle`, 2x duplicate `matchMethodBadge` from individual files

### Fixed
- **Device edit modal**: Added `Enabled` and `Public Visible` checkboxes. Previously `enabled` was hardcoded to `true` on every save, and `public_visible` was not included — editing a device could silently reset visibility
- **Dead settings save code**: Removed leftover `public_bandwidth_interfaces` and `public_vpn_tunnels` save logic from settings submit (the select elements were already removed from the HTML)
- **Debug log leak**: Removed `console.log('Saved:', publicInterfaces)` from admin-device-detail.js

## [0.10.145] - 2026-04-04

### Fixed
- **Cross-site tunnels route through Internet**: IPSec/SSL connections between devices in different sites now draw as two edges through the Internet cloud node (Device→Cloud→Device) instead of a direct line. Particles flow through the cloud correctly. Same-site tunnels remain as direct edges.
- **Cross-site expansion**: Clicking a cross-site tunnel expands sublanes spanning the full device-to-device path. Both half-edges (src and dst) are hidden during expansion and restored on collapse.
- **Cross-site status updates**: Polling updates both halves of a split tunnel edge when status changes

## [0.10.144] - 2026-04-04

### Fixed
- **Overlay duplication**: Overlays (vxlan, l3ipvlan) assigned to first tunnel carrier only, not duplicated across all tunnels for a device pair
- **Escape key handler leak**: Keydown listener now stored and removed on cleanup, preventing accumulation across re-renders
- **Overlay status polling**: `updateStatuses()` now searches tunnel-bundle `childConns` when overlay edges aren't found as direct edges, preventing silent status loss
- **Sublane filter inheritance**: Expanded sublanes and pipe-bg edges now hidden when parent tunnel type is filtered out
- **Flash animation crash**: `animateFlash()` guards against removed edges mid-animation chain
- **Particle count overflow**: `addParticlePair()` now checks `particleEls.length` directly instead of caller-tracked count, preventing MAX_PARTICLES overflow
- **VXLAN/L3IPVLAN filter buttons removed**: These overlay types are now bundled inside tunnel edges, so standalone filter buttons were inert. Removed from toolbar.
- **Dead code cleanup**: Deleted `diagram-tunnel-zoom.js` (289 lines) and SVG compatibility shims (`getSVG`, `getDimensions`, `createEl`, `svgPoint`, `NS` constant) that were only used by the removed tunnel zoom overlay

## [0.10.143] - 2026-04-04

### Changed
- **Tunnel-bundled connection map**: Overlay networks (l3ipvlan, vxlan) no longer shown as separate edges. They ride inside their tunnel carrier (IPSec/SSL) as colored dots on the tunnel edge. Each dot color represents the network type inside the tunnel
- **Inline tunnel expansion**: Click a tunnel edge with overlays to expand it into a "pipe" with sub-lanes — each overlay network gets its own labeled lane with directional particles. Click again or press Escape to collapse
- **Directional particle flow**: Forward particles (source→target) are larger and brighter, return particles are smaller and dimmer with the same color. No more reverse-direction collisions. Off-net edges flow device→cloud only
- **Same-site connections unchanged**: Ethernet, LAG, L2VLAN, and bridge connections remain as independent direct edges (they don't travel through tunnels)

### Removed
- **diagram-tunnel-zoom.js**: Old overlay zoom replaced by inline expansion. "Zoom In" button removed from connection detail panel

## [0.10.142] - 2026-04-04

### Fixed
- **Settings page sync**: Remove dead settings (`public_bandwidth_layout`, `public_bandwidth_height`) that the Gridstack dashboard no longer uses. Fix bandwidth interface selector bug (was querying `input` instead of `select`). Update Public Dashboard description to reflect widget-based layout

### Added
- **Email Reports settings card**: UI for configuring daily/weekly report scheduling (enable, time, day, recipients, timezone)
- **Traffic Spike Detection settings card**: UI for enabling spike alerts and configuring the standard deviation threshold

## [0.10.141] - 2026-04-04

### Changed
- **Public dashboard rebuilt with Gridstack.js**: Full rewrite using Gridstack.js v10 widget grid. All sections (devices, CPU/memory, bandwidth, VPN, connections) are draggable and resizable widgets. Layout fits viewport height with no scrolling — designed for NOC wall displays
- **Widget persistence**: Layout (position, size) saved to localStorage automatically on drag/resize. Hidden widgets remembered across sessions. "Reset Layout" button restores defaults
- **Widget visibility**: "Widgets" dropdown menu with checkboxes lets users show/hide any widget. Close button (×) on each widget header for quick hiding

### Fixed
- **Bandwidth "Transfer" chart**: Was showing cumulative growth (monotonically increasing line). Now shows per-interval byte deltas as bar chart — each bar represents bytes transferred in that measurement period
- **Bandwidth "Combined" (Mix) chart**: Was rendering 4 overlapping lines. Now uses Chart.js mixed chart — rate as lines on left axis (Mbps) + transfer deltas as bars on right axis (Bytes)

## [0.10.140] - 2026-04-04

### Added
- **Public dashboard CPU/Memory charts**: Per-device historical CPU and memory usage charts with time range selector (1h, 6h, 24h, 7d) on the public dashboard. Uses new `GET /api/public/status-history` endpoint
- **Per-device public visibility toggle**: New `public_visible` field on Device model (defaults to true). Checkbox in admin devices table lets you hide specific firewalls from the public dashboard without disabling polling. `GetPublicDevices` now filters by both `enabled` and `public_visible`

## [0.10.139] - 2026-04-04

### Changed
- **Bundle all JS dependencies locally**: Chart.js, Cytoscape.js, and cytoscape-fcose are now embedded in `cmd/api/static/js/` instead of loaded from CDNs. Eliminates all external script dependencies, removes CDN URLs from CSP, and ensures the app works fully offline

## [0.10.138] - 2026-04-04

### Added
- **Real-time connection map**: Diagram auto-refreshes every 15 seconds via lightweight `/api/connections/status-summary` endpoint. Status changes trigger animated transitions — red flash for DOWN, green flash for recovery
- **Visual X marker on DOWN links**: DOWN edges now display a prominent red X icon with background badge, visible by default (showDown defaults to true)
- **Events tab in connection panel**: Click any connection to see correlated alerts, traps, and syslog from both endpoint devices. DOWN connections auto-open the Events tab. Time range selector: 1h, 6h, 24h, 7d
- **Standard linkUp/linkDown trap support**: SNMP trap receiver now handles IETF standard linkDown (`.1.3.6.1.6.3.1.1.5.3`) and linkUp (`.1.3.6.1.6.3.1.1.5.4`) traps for both SNMPv1 and v2c/v3 formats. Extracts interface index and description from varbinds
- **LINK_UP recovery alerts**: When a LINK_UP trap arrives, any active LINK_DOWN alert for the same device is automatically resolved
- **Connection events API**: New `GET /api/connections/:id/events` endpoint returns unified timeline of alerts, traps, and syslog for a connection's endpoint devices

## [0.10.137] - 2026-04-04

### Fixed
- **Connections page not loading**: Non-critical API calls (`/sites`, `/vpn-map`) in `loadConnections()` now have individual `.catch()` fallbacks so a failure in either doesn't prevent the connections table from rendering
- **Stale cleanup wiping all connections**: Connection detection cycle now tracks whether any detector found connections; stale cleanup is skipped when all detectors return zero results, preventing mass deletion on transient failures
- **Discovery badges**: Unified to consistent Direct/Indirect taxonomy across all views (connections table, network page, diagram panels). Removed stale methods (`vxlan_name`, `tunnel_name`) and added missing ones (`wan_inferred`, `subnet_match`). Indirect styling now applies to all indirect match methods on the connection diagram
- **Renamed `overlay_name` → `name_match`**: Internal match method for interface-name-based detection now uses clear terminology. Legacy `overlay_name` values still render correctly

## [0.10.136] - 2026-03-19

### Changed
- **Connection Map**: Replaced custom SVG rendering engine (4 files, ~90KB) with Cytoscape.js graph library
  - Native compound nodes for site grouping with automatic layout
  - Native multi-edge support — parallel connections between same device pair shown as bezier curves
  - Built-in zoom/pan with mouse wheel and drag
  - fcose force-directed layout with compound node support (falls back to cose)
- **Toolbar**: Added layer filter buttons (per connection type with color indicators), Show DOWN toggle, Fit, and Reset controls
- **DOWN connections**: Now included in graph data but hidden by default; "Show DOWN" button reveals them as dashed/dimmed edges

### Fixed
- **Missing `/sites` API call**: `loadConnections()` now fetches sites, fixing site grouping that was silently broken
- **Event listener accumulation**: Previous cy instance is destroyed on re-render, preventing sluggishness on tab switches
- **0-device edge case**: Early return with message instead of crash when no devices exist

### Removed
- `diagram-core.js`, `diagram-layout.js`, `diagram-connections.js`, `diagram-particles.js` — replaced by `diagram-cytoscape.js`

### Added
- `diagram-cytoscape.js` — single Cytoscape.js module with data transformation, styling, layout, filtering, particle animation, and SVG overlay shim for tunnel-zoom compatibility
- CDN dependencies: Cytoscape.js v3.30.4, cytoscape-fcose v2.2.0

## [0.10.135] - 2026-03-18

### Fixed
- **ParseHours** max raised from 168 → 8760: 1-month and 1-year time range buttons now work correctly instead of silently falling back to 24h
- **sFlow charts**: Port-0 internal/local traffic (IPv6 link-local) filtered from Top Sources, Top Destinations, and Top Conversations to prevent one address from dominating all charts
- **Bar chart scaling**: With local traffic separated, bar charts show balanced application traffic instead of 1.0B/2.0B scale

### Added
- Local traffic info bar on Flows page showing filtered port-0 bytes, flows, and packets
- `LocalTraffic` field in `FlowStatsResult` API response

## [0.10.134] - 2026-03-18

### Fixed
- **Critical**: `GetFlowStats` now queries both raw `flow_samples` and `flow_rollups` — dashboard no longer goes blank after rollup cycle
- **Critical**: Rollup INSERT+DELETE wrapped in transactions to prevent data loss and duplicate entries on crash
- **High**: BPS bandwidth chart now uses server-provided `bucket_seconds` instead of inaccurate client-side interval estimation
- **High**: Added `DstPort` to `FlowRollup` model — conversation-level port detail preserved through rollup tiers
- **High**: Combined 4 separate aggregate queries (COUNT, SUM, DISTINCT src, DISTINCT dst) into single query
- **High**: Extracted duplicate `protoNames` map to package-level `ProtoNames` var with `protoName()` helper — fixes inconsistency where connection flow stats was missing 7 protocol names
- **Medium**: Added `idx_rollup_interval_ts` composite index on `(interval_type, timestamp)` — rollup promotion queries no longer force full table scan
- **Medium**: Rollup aggregation now paginated (50k groups per batch) to prevent OOM on high-cardinality networks
- **Medium**: `formatBps()` now handles values < 1 and negative/NaN inputs without producing "undefined"
- **Medium**: Added error checks on GORM queries in `GetFlowStats` — DB errors now propagate instead of silently showing zeros
- **Low**: Replaced inline 6-column grid style with responsive `.stat-grid-6` CSS class (3-col at <1100px, 2-col at <600px)
- **Low**: Rollup engine logs heartbeat when no data to aggregate
- **Low**: Used weighted average `SUM(rate * count) / SUM(count)` for `sampling_rate_avg` when promoting rollups
- **Low**: Extracted shared `horizBarOpts` function — eliminated duplicate horizontal bar chart config
- **Low**: Extracted shared `topAddrsByBytes` helper — eliminated duplicate top src/dst query patterns
- **Low**: Reduced rollup batch size from 1000 to 500 for better SQLite compatibility
- Added `data-dport` attribute to conversation rows for future port-level drill-down

## [0.10.133] - 2026-03-18

### Added
- Enterprise sFlow dashboard: 6 stat cards (Total Flows, Total Bytes, Avg Throughput, Unique Sources, Unique Dests, Protocol Count)
- Bandwidth Over Time chart with adaptive bucketing (minute/hour/day based on time range)
- Top Destinations horizontal bar chart (green, complements Top Sources)
- Top Conversations table with % of total column and click-to-filter drill-down
- `FlowRollup` model for scalable flow data aggregation
- Rollup engine: auto-aggregates raw flows → 5m → 1h → 1d rollups every 5 minutes
- `formatBps()` helper for human-readable bits/sec formatting (Kbps, Mbps, Gbps)
- Est. Bytes column in flow samples table (bytes × sampling_rate)
- 5-minute time bucket support in SQLite and PostgreSQL dialects

### Changed
- Flow time range buttons expanded: 1h, 6h, 24h, 1w, 1m, 1y (was: Today, 1 Week, 1 Month, 1 Year)
- Bandwidth chart now shows bits/sec throughput instead of raw bytes
- Flows API (`/api/flows/stats`) returns `bits_per_second`, `protocol_count`, `top_destinations`, `top_conversations`

## [0.10.132] - 2026-03-18

### Added
- Per-device alert configuration modal accessible via "Alerts" button on each device row
- Toggle switch for enabling/disabling alerts per device
- Alert policy assignment dropdown (inherits from site/global when unset)
- Threshold override fields for CPU, Memory, Disk, Sessions, and Cooldown
- "Reset to Defaults" button to remove all device-level overrides
- Visual indicators on device table: red dot for muted alerts, yellow dot for custom config

## [0.10.131] - 2026-03-18

### Fixed
- Maintenance window device dropdown was empty when navigating directly to page (fetched from `currentDevices` which required visiting Devices page first) — now fetches from `/api/devices` API
- Maintenance table scope column showed "Device #3" instead of actual device/site names — now resolves names via API
- Scope toggle in edit mode now correctly restores the saved scope selection

### Improved
- Maintenance modal: replaced scope dropdown with segmented radio toggle for better UX
- Maintenance modal: pre-fills start time (now) and end time (now + 2 hours) for new windows
- Maintenance modal: device select shows IP address, site select shows region
- Maintenance modal: widened to 600px with better form spacing and placeholder text
- Stat cards: added colored left border accents (red=active, blue=scheduled, gray=total)
- Table: improved empty state with icon, hover-reveal action buttons
- Notes textarea enlarged with placeholder guidance

## [0.10.130] - 2026-03-18

### Fixed
- Remove dead code: unused `checkThreshold` method left over from refactor
- Add composite index `idx_alert_unack(acknowledged, suppressed, timestamp)` for efficient escalation queries
- Add index on `policy_id` for alert policy lookups
- Escape `formatDate()` output in ACK badge title attribute for defense-in-depth XSS prevention
- Add input length validation on alert policy name (200 chars) and description (1000 chars)

### Changed
- Refactor `CheckEscalations` to use `BuildNotifyConfigFromResolved` instead of manually constructing NotifyConfig, reducing code duplication
- Separate escalation notification sending from DB updates — all updates happen after notifications complete

## [0.10.129] - 2026-03-18

### Fixed
- **Critical: Escalation query inverted** — `GetUnacknowledgedAlerts` used `timestamp < cutoff` instead of `timestamp > cutoff`, causing escalation checks to query alerts older than 24h instead of newer
- **Critical: Missing PolicyActive flag** — `BuildNotifyConfigFromResolved` did not set `PolicyActive: true`, so policy-based channel routing was silently ignored and all channels fired via legacy path
- **Critical: Route conflict** — `GET /api/maintenance-windows/active` registered after `/:id` param route, causing Gin to match "active" as an ID; moved specific route before parameterized routes
- **Race condition in RefreshPolicyCache** — `policyCache` struct was assigned without holding `am.mu`, allowing torn reads during concurrent alert checks; now properly locks before assignment
- **Upsert error masking** — `UpsertDeviceAlertConfig` and `UpsertSiteAlertConfig` treated all DB errors as "not found" and retried with Create; now explicitly checks for `gorm.ErrRecordNotFound`
- **Recovery during maintenance** — Recovery notifications were sent even when the original alert was suppressed by a maintenance window; now skips recovery if `InMaintenance` is true
- **EnsureDefaultPolicy race** — Check-then-create pattern could create duplicate default policies under concurrent startup; replaced with GORM `FirstOrCreate`
- **UpdateMaintenanceWindow missing existence check** — Blindly updated by ID without verifying record exists; now returns 404 if not found
- **DeleteAlertPolicy error leak** — Exposed raw database error messages to API response; now returns generic error for non-business errors
- **Notes length unbounded** — `UpdateAlertNotes` accepted arbitrarily long notes; now validates max 4000 characters

### Changed
- **Performance: O(n) → O(1) policy lookup** — Added `policyByID` map to `PolicyCache` for constant-time policy resolution instead of linear scan
- **Performance: Batch recovery lock** — Recovery checks in `CheckSystemStatus` now resolve all 4 alert types under a single lock acquisition instead of 4 separate lock/unlock cycles
- **Code quality: Deduplicate `firedEntry`** — Extracted `firedEntry` struct to package-level type instead of 4 identical inline definitions
- **Code quality: Consolidate threshold overrides** — Merged `overrideThresholdFloat` and `overrideSiteThreshold` into single `overrideThreshold` function accepting raw field values
- **Code quality: Simplify SendAlert** — Replaced duplicated policy/legacy channel-check branches with unified boolean eligibility computation

## [0.10.128] - 2026-03-18

### Added
- **Per-device alert policies**: Reusable `AlertPolicy` bundles with per-alert-type rules, notification channel routing, cooldown overrides, and escalation settings
- **Alert rules**: Per-alert-type configuration within policies — enable/disable, severity override, threshold override, per-channel notification toggles (tri-state: inherit/on/off)
- **Device alert config**: Per-device policy assignment, threshold overrides (CPU/memory/disk/sessions), cooldown override, and master alerts-enabled toggle
- **Site alert config**: Per-site default policy and threshold overrides inherited by all site devices unless overridden at device level
- **Maintenance windows**: Time-based notification suppression per device, site, or fleet-wide — alerts still saved with `suppressed=true` for audit trail
- **Escalation**: Re-sends notifications for unacknowledged alerts after configurable interval, up to configurable repeat limit
- **Policy resolution engine** (`internal/alerts/policy.go`): Inheritance chain Device → Site → Policy Rule → Policy → Global defaults, computed per (device, alertType) with in-memory cache refreshed each poll cycle
- **Enhanced Alert model**: New fields `acknowledged_at`, `resolved_at`, `notes`, `policy_id`, `escalation_count`, `suppressed`
- **Alert acknowledgment with notes**: Acknowledge modal with optional notes textarea, `acknowledged_at` timestamp
- **15 new API endpoints**: Full CRUD for alert policies, alert rules (batch upsert), device/site alert configs, maintenance windows, alert notes
- **Admin UI**: New "Alert Policies" tab with policy list, create/edit/clone/delete, inline alert rules editor with tri-state channel toggles
- **Admin UI**: New "Maintenance" tab with maintenance window list, create/edit with scope picker (all/device/site), datetime pickers, alert type filter
- **Default policy auto-seeded**: `EnsureDefaultPolicy()` creates a "Default" policy on first boot — system works identically to pre-change with zero configuration

### Changed
- All alert check methods (`CheckSystemStatus`, `CheckInterfaceStatus`, `CheckVPNStatus`, `CheckInterfaceErrors`, `ProcessTrap`, `ProcessSyslog`) now accept `siteID` parameter and resolve per-device/policy configuration
- `canAlertWithCooldown()` uses resolved cooldown duration instead of global default
- `sendRecovery()` sets `resolved_at` on original alert records
- `SendAlert()` in notifier respects per-channel enable flags from policy resolution (backward compatible: legacy behaviour when no policy active)
- `RefreshThresholds()` now also refreshes the policy cache
- `pollAllDevices()` calls `CheckEscalations()` at end of each cycle

## [0.10.127] - 2026-03-18

### Added
- **Scheduled HTML email reports**: Daily and weekly reports with embedded PNG charts (traffic, CPU/memory, uptime meter, alert trend) sent as MIME multipart/related emails
- **Per-device 30-day uptime tracking**: Derived from `system_status` poll density — displayed as 99.99% format with visual uptime meter (green/red/grey)
- **Traffic spike detection**: Rolling-window standard deviation analysis for both real-time alerts (`TRAFFIC_SPIKE`) and report annotations
- **Enhanced critical alert emails**: Device-offline, VPN-down, and disk-critical alerts now include HTML formatting with recent CPU/memory charts
- **Report scheduler** (`internal/report/`): New package with chart rendering via `go-chart/v2`, HTML templates with inline CSS, MIME email builder, data aggregation, and scheduling
- **8 new settings**: `report_daily_enabled`, `report_daily_time`, `report_weekly_enabled`, `report_weekly_day`, `report_recipients`, `report_timezone`, `spike_stddev_threshold`, `spike_alert_enabled` — configurable via admin UI
- **4 new database queries**: `GetAlertsByDeviceAndHours`, `GetTopInterfacesByTraffic`, `GetDevicePollCount`, `GetDeviceFirstPoll`
- **MIME multipart email support**: `SendHTMLEmail()` in notifier with inline base64-encoded PNG images via Content-ID references

## [0.10.126] - 2026-03-17

### Fixed
- **Full PostgreSQL compatibility audit**: Fix all remaining SQLite-specific SQL across the codebase
- Fix backtick-quoted `index` column in interface history/chart queries (handlers_devices.go, handlers_dashboard.go) — use double quotes for PG compatibility
- Fix backtick-quoted `key` column in RefreshThresholds, getNotificationSetting, GetPublicDisplaySettings — use double quotes
- Fix `SavePingStats` using GORM `.Save()` on new records (ID=0) which fails on PG — use `.Create()` for new, `.Save()` for existing
- Fix `groupByString` not quoting column names — use `dialect.QuoteIdent()` for PG reserved word safety
- Fix migration PK clash: advance PG sequence to source MAX(id) before copying rows so concurrent probe inserts don't collide

## [0.10.125] - 2026-03-17

### Changed
- **Embedded PostgreSQL in Docker image**: PostgreSQL 16 is now installed inside the container and starts automatically — no external database needed
- Entrypoint initializes PG data directory on first run, creates database/user, and sets `DB_TYPE=postgres` for all services
- PG data persists in `/data/pgdata` alongside existing volume mount
- Existing SQLite data at `/data/firewall-mon.db` is auto-migrated on first startup, then renamed to `.migrated`
- Graceful shutdown stops app services first, then PostgreSQL
- PG tuned for embedded use: 128MB shared buffers, 30 max connections, unix socket only (no TCP)

## [0.10.124] - 2026-03-17

### Changed
- **Auto-migration on startup**: When `DB_TYPE=postgres` and the old SQLite file exists on disk, migration starts automatically — no manual action needed
- After successful migration, the SQLite file is renamed to `.migrated` (plus WAL/SHM) so it won't re-trigger on next restart
- Settings page shows live migration progress if one is running; manual start form available as fallback

## [0.10.123] - 2026-03-17

### Added
- **Admin database migration tool**: New SQLite-to-PostgreSQL data migration in the Settings page for users switching from SQLite to PostgreSQL
- Migration engine (`internal/database/migrate_data.go`) copies all tables in FK-safe order with configurable batch sizes (1000 for high-volume tables, 500 for others)
- Per-table progress tracking with real-time status updates (pending, running, done, skipped, error)
- Idempotent migration — tables that already contain data in PostgreSQL are automatically skipped
- PostgreSQL sequences automatically reset to `MAX(id)` after each table migration
- 3 new admin API endpoints: `GET /admin/api/migrate/precheck`, `POST /admin/api/migrate/start`, `GET /admin/api/migrate/status`
- Migration UI card on Settings page with overall progress bar, per-table status table, and 2-second polling
- `Database.IsPostgres()` accessor method for dialect detection

## [0.10.122] - 2026-03-17

### Fixed
- Fix PostgreSQL DSN breaking when password/user/dbname contain spaces or special characters (now properly quoted)
- Fix VPN chart queries using unaliased subqueries that fail on PostgreSQL (`FROM (...) AS deltas`)

## [0.10.121] - 2026-03-17

### Added
- **PostgreSQL support**: Add PostgreSQL as primary database backend (`DB_TYPE=postgres`) with connection pooling (25 open / 10 idle), while keeping SQLite as default for small deployments
- **Batch inserts**: High-volume data (syslog, traps, pings) now buffered and flushed in batches — syslog: 500 items / 2s, traps/pings: 100 items / 5s
- **Batch save API methods**: `SaveSyslogMessages`, `SaveTrapEvents`, `SavePingResults` for single-transaction bulk inserts from probe handlers
- **Configurable retention periods**: Per-data-type retention via env vars (`RETENTION_SYSLOG_DAYS`, `RETENTION_FLOW_DAYS`, `RETENTION_TRAP_DAYS`, `RETENTION_STATUS_DAYS`, `RETENTION_PING_DAYS`, `RETENTION_ALERT_DAYS`, `RETENTION_DEFAULT_DAYS`), default 90 days
- **DB SSL mode**: `DB_SSL_MODE` env var for PostgreSQL connections (default: `disable`)

### Changed
- **SQL dialect abstraction**: All 15 `strftime()` calls and 3 backtick-quoted identifiers replaced with dialect-aware helpers supporting both SQLite and PostgreSQL
- **Probe data handlers**: `ReceiveSyslogMessages`, `ReceiveTrapEvents`, `ReceivePingResults` now use single batch inserts instead of per-row saves
- **CleanupOldData**: Now accepts `RetentionConfig` with per-table retention periods instead of a single `days` parameter
- **Database Close**: Flushes all batch inserters before closing the connection

## [0.10.120] - 2026-03-15

### Fixed
- Fix IRC handlers returning encrypted ciphertext to API clients on create/update (all 4 endpoints now decrypt before responding)
- Fix `GetIRCChannels` endpoint not decrypting channel secrets
- Fix `UpdateIRCChannel` returning stale pre-update data (now re-fetches from DB)
- Fix double-encryption risk: `encryptField` now skips values already prefixed with `{enc}`
- Fix decryption failure returning empty string (reverted to returning ciphertext so auth fails loudly instead of silently)
- Fix nil pointer dereference in IRC bot `onQuit` when `b.Conn` is nil (now checks under mutex)
- Fix `PingCollector.Start()` being a no-op after `Stop()` (re-creates `stopCh` channel)
- Fix potential panic when admin password is shorter than 6 characters during masking
- Fix admin password file using hardcoded `/data/` path; now uses database directory
- Fix CORS middleware returning 204 for OPTIONS from disallowed origins (moved inside allowed block)
- Improve ENCRYPTION_KEY warning to guide safe migration from JWT-derived key

## [0.10.119] - 2026-03-15

### Security
- Add CORS middleware with configurable `CORS_ALLOWED_ORIGINS` (defaults to same-origin only)
- Move rate limiter from global to per-group so authenticated admin users don't share buckets with unauthenticated requests
- Encrypt SMTP password in system_settings using AES-256-GCM
- Redact auto-generated admin password from stderr; write full password to secure file `/data/.admin-password` instead
- Escape remaining unescaped `ch.status` in IRC admin JS to prevent XSS

### Performance
- Optimize GetDeviceDetail: reduce 12 sequential queries to 6 using subquery pattern (`WHERE timestamp = (SELECT MAX...)`)
- Add composite database indexes: Alert.Acknowledged, UptimeRecord(device_id,timestamp), ProbeHeartbeat(probe_id,timestamp), Probe.ApprovalStatus, SyslogMessage.Severity, TrapEvent.Severity

### Fixed
- Fix PingCollector goroutine leak: Stop() now sets running=false before close(stopCh) and waits outside lock
- Add error logging to ~30 swallowed database query errors across handlers (devices, dashboard, analytics, settings, sites, probes)

## [0.10.118] - 2026-03-15

### Security
- Encrypt IRC passwords (ServerPassword, NickServPassword, SASLPassword, ChanServPass, ChanOperPass, ChannelKey) with AES-256-GCM — same encryption used for SNMP credentials
- Separate database encryption key from JWT secret via new `ENCRYPTION_KEY` env var (falls back to JWT secret with warning for backwards compatibility)
- Fix decryption failure returning raw ciphertext — now returns empty string and logs warning
- Tighten Content-Security-Policy: remove `unsafe-inline` and `unsafe-eval` from `script-src`
- Convert all inline event handlers in IRC admin page to `addEventListener` for CSP compliance
- Add startup configuration validation: port ranges, SNMP version, TLS cert paths, bcrypt cost bounds, missing secret warnings
- Fix raw database error message exposure in IRC server update endpoint

### Fixed
- Add mutex to poller's `prevIfaceStats` map — prevents concurrent map write panic under load
- Sanitize IRC server update error response (no longer leaks internal DB errors)

## [0.10.117] - 2026-03-15

### Fixed
- IRC bot nick collision infinite loop: 433 handler now appends underscore to current nick instead of always trying the same static alternate nick
- Removed NICK event echo loop that caused cascading rename storms when multiple bot instances connected
- Reconnect loop now checks connection state under proper lock and spawns reconnects in goroutines to prevent duplicate connections
- onQuit handler now ignores other users' QUIT messages instead of clearing bot connection state
- Added DISCONNECTED callback for reliable TCP drop detection
- Start() now checks quit channel to prevent reconnecting a stopped bot
- RestartBot only starts new bot if server is enabled

## [0.10.116] - 2026-03-09

### Added
- Palo Alto Networks vendor profile with PAN-COMMON-MIB support (system status, sessions, GlobalProtect stats, AV/threat versions)
- Palo Alto VPN tunnel detection via IF-MIB tunnel.* interface patterns with 64-bit counter support
- Palo Alto hardware sensors via ENTITY-SENSOR-MIB (temperature, fan, voltage, power)
- Palo Alto per-CPU stats via HOST-RESOURCES-MIB (management plane, data plane)
- Palo Alto SNMP trap definitions (VPN, HA, hardware, GlobalProtect, threat events)
- SonicWall vendor profile with SNWL-COMMON-MIB and SONICWALL-FIREWALL-IP-STATISTICS-MIB
- SonicWall system status (CPU, RAM, session count from enterprise OIDs)
- SonicWall IPSec VPN tunnel monitoring via sonicSAStatTable (peer gateway, subnets, byte counters)
- SonicWall hardware sensor monitoring via sonicwallSensorsTable
- SonicWall SNMP trap definitions (IPSec, HA, IPS, security services, WAN failover)
- SonicWall added to valid vendors list and admin dropdown

## [0.10.115] - 2026-03-09

### Added
- Firewalla VPN tunnel detection via IF-MIB interface name patterns (WireGuard wg*, OpenVPN tun*/tap*, IPSec vti*)
- Linux-specific VPN helper (`vendor_linux_vpn.go`) with ifType-based disambiguation for ambiguous tun* interfaces
- `linuxGetAllVPNTunnels()` function with 64-bit counter support via ifXTable

## [0.10.114] - 2026-03-09

### Added
- **VPN tunnel detection for pfSense & OPNsense**: Discover VPN tunnels from IF-MIB interface name patterns (OpenVPN `ovpns*/ovpnc*`, WireGuard `wg*/tun_wg*`, IPSec VTI `ipsec*`) with status and traffic counters
- Shared BSD VPN helper (`vendor_bsd_vpn.go`) with IF-MIB walk + ifXTable 64-bit counter support

## [0.10.113] - 2026-03-09

### Added
- **pfSense vendor support**: SNMP vendor profile using UCD-SNMP-MIB + BEGEMOT-PF-MIB for CPU, memory, PF state count, and per-CPU load
- **OPNsense vendor support**: SNMP vendor profile with same FreeBSD/PF MIB stack and OPNsense-specific version parsing
- pfSense and OPNsense options in admin UI device vendor dropdown
- Vendor validation updated for pfsense and opnsense

## [0.10.112] - 2026-03-09

### Added
- **Firewalla vendor support**: New SNMP vendor profile for Firewalla devices using standard Linux MIBs (UCD-SNMP-MIB, HOST-RESOURCES-MIB, SNMPv2-MIB)
- Firewalla option in admin UI device vendor dropdown
- Firewalla added to valid vendor list for device create/update API validation

## [0.10.111] - 2026-03-07

### Added
- Configurable display timezone for all admin and public dashboard pages
- Timezone selector in Settings page with full list of world timezones (defaults to America/New_York / Eastern)
- `display_timezone` system setting persisted in DB and synced to localStorage
- Centralized `formatDate()` / `formatDateShort()` helpers in admin-common.js
- Public dashboard also respects the configured timezone via display-settings API
- All date/time displays across admin pages (syslog, flows, alerts, traps, devices, probes, network map) now use the configured timezone

## [0.10.110] - 2026-03-07

### Added
- IRC auto-status: periodic automatic status messages posted to channels on a configurable interval
- New `statusLoop` goroutine in IRC Manager ticks every 30s and sends status to channels with `SendStatus` enabled
- Channel modal: interval input (in minutes) shown when "Auto-Post Status" is checked
- Interval stored in seconds in DB, displayed as minutes in the UI

### Fixed
- IRC !status: removed bold formatting from device name in header
- IRC !status: removed extra space before closing `-+` in header to fix alignment

## [0.10.109] - 2026-03-07

### Fixed
- IRC !status: uptime was 100x too high — fgSysUpTime returns centiseconds (hundredths of a second), not seconds

## [0.10.108] - 2026-03-07

### Fixed
- IRC !status: switch to pure ASCII characters for mIRC Fixedsys compatibility (Unicode box-drawing chars cause font-linking misalignment)
- IRC !status: use colored spaces for progress bars instead of block chars (works with any font)
- IRC !status: bold device name in header, cleaner layout with grey borders
- IRC !status: all text/labels use only ASCII 0-127 characters

## [0.10.107] - 2026-03-07

### Fixed
- IRC !status: restore explicit white color after bar reset so bracket/percentage text renders consistently

## [0.10.105] - 2026-03-07

### Fixed
- IRC !status: restored Unicode box-drawing characters (│─┌┐└┘█●) — ASCII looked worse

## [0.10.104] - 2026-03-07

### Changed
- IRC !status: widened device boxes from 30 to 38 chars (supports longer firewall names up to ~17 chars)
- IRC !status: widened progress bars from 16 to 22 chars for better visual resolution

## [0.10.103] - 2026-03-07

### Fixed
- IRC !status: fixed box misalignment caused by \x0F resets killing monospace mid-line
- IRC !status: fixed padding errors from using byte length instead of rune count (Unicode chars like ● counted as 3 bytes)
- IRC !status: replaced per-element color+reset wrapping with inline color-set approach (single \x0F at end of each line)
- IRC !status: switched from Unicode box-drawing chars to ASCII for maximum client compatibility
- IRC !status: removed unreliable \x11 monospace toggle that was inconsistently applied

## [0.10.102] - 2026-03-07

### Changed
- IRC !status: per-device side-by-side boxes with individual CPU/MEM/VPN/alerts/sessions
- Progress bars use color thresholds: green (≤60%), yellow (60-85%), red (>85%) on black background
- Wider 16-char bars for better visual resolution
- Device uptime shown in header: ┌─ NAME ──── (Up: 45d 3h) ─┐
- Status provider now returns per-device data instead of aggregates
- Monospace toggle (\x11) wrapping for proper alignment across IRC clients

## [0.10.101] - 2026-03-07

### Fixed
- IRC: seed default commands (!status, !stats, !help) on startup so they work without manual creation
- IRC: added !help command type that lists all available commands

## [0.10.100] - 2026-03-07

### Fixed
- IRC disconnect panic: Bot.Stop() no longer panics on double-close of quit channel

## [0.10.99] - 2026-03-07

### Added
- IRC !status command now shows a 6-line visual ASCII health dashboard with:
  - Device counts (online/offline/total) with color indicators
  - CPU and memory usage with visual progress bars
  - VPN tunnel status (up/total), active alerts, and session count
  - IRC color codes for green (healthy), red (alerts/down), orange (bars)
- Status provider now includes CPU/memory averages, session totals, and VPN tunnel counts

## [0.10.98] - 2026-03-07

### Fixed
- Standardized navigation sidebar across all admin pages (consistent order, icons, sections)
- Added "System" section with Settings and IRC links to all admin pages
- Fixed Connections/Interfaces order in device-detail and connection-detail pages
- IRC: renamed model field `Password` to `ServerPassword` with explicit gorm column tags
- IRC: fixed frontend sending wrong JSON key (`password` instead of `server_password`)
- IRC: fixed server card not showing channels (was using empty global array instead of preloaded data)
- IRC: removed broken manual column migration code, replaced with one-time schema fix
- IRC: fixed update handler returning stale data after save
- IRC page sidebar now matches all other admin pages
- IRC page logout link now uses standard data-action="logout" pattern

## [0.10.97] - 2026-03-07

### Fixed
- Fixed OID index extraction for VPN tunnels (getIndexFromOID now correctly extracts multi-part indices)
- Device VPN page now cross-fills Phase 2 subnets from peer devices

## [0.10.96] - 2026-03-07

### Fixed
- Device VPN page now cross-fills Phase 2 subnets from peer devices when local device doesn't expose them (HUB limitation)

## [0.10.88] - 2026-03-04

### Added
- WAN link speed setting per device (for usage percentage calculations)
- Bandwidth charts now show usage percentage based on configured WAN speed

### Fixed
- Fixed bandwidth chart ranges (now uses proper time-bucketed aggregation)
- Removed 1-minute range option (minimum is now 5 minutes)
- Fixed negative Mbps values in aggregated bandwidth charts
- Fixed API response format for bandwidth charts

### Added (0.10.87)
- Public dashboard bandwidth layout options (grid/full width)
- Public dashboard chart height configuration
- Admin controls on public page to customize bandwidth layout
- Admin detection middleware for public API

## [0.10.86] - 2026-03-04

### Fixed
- Removed orphaned duplicate code in public-dashboard.js that caused syntax error

## [0.10.85] - 2026-03-04

### Fixed
- Critical: Race condition - settings now load before fetching data
- Fixed toFixed() crash on undefined bandwidth data
- Added missing null checks for DOM elements
- Added 90d range support for bandwidth charts

## [0.10.84] - 2026-03-04

### Fixed
- Public interface checkbox now saves properly (added missing switch case in backend)
- Fixed race condition in public dashboard loading (now waits for devices before loading data)
- Fixed duplicate device fetch in bandwidth section

### Changed
- Public dashboard shows all device data together without waiting for dropdown

## [0.10.83] - 2026-03-04

### Changed
- Public dashboard now shows ALL devices in combined table view (no dropdown)
- Combined CPU/Memory/Uptime/Sessions table for all firewalls
- All public interfaces from all devices shown in grid
- Fixed bandwidth charts to only show public interfaces

## [0.10.82] - 2026-03-04

### Added
- Fancy interface bandwidth charts on public dashboard with Chart.js
- View types: Throughput (Mbps), Total Transferred, Mix (Both)
- Time ranges: 1m, 5m, 15m, 1h, 6h, 24h, 7d
- Interface selector to switch between public interfaces

## [0.10.81] - 2026-03-04

### Changed
- Simplified public dashboard interface selection - now "Show Public" checkbox directly on device detail page
- Per-device interface selection stored as JSON: {"1":["wan1","wan2"],"2":["dmz"]}
- Removed complex Settings page dropdowns - just check "Public" box on each interface

## [0.10.80] - 2026-03-04

### Added
- Configurable public dashboard modules - pick and choose what to show on stats.technicallabs.org
- New public APIs: `/api/public/vpn` (IPSec tunnel status), `/api/public/connections` (connection map)
- New display settings: bandwidth graphs, VPN tunnels, connection map
- Interface selection now grouped by type (Physical, VLAN, IPSec, VXLAN, Tunnel, etc.)
- Connection map shows animated links between devices (read-only, no private details)

### Admin
- Settings page now allows enabling/disabling individual public dashboard modules
- Multi-select dropdowns to pick specific interfaces and VPN tunnels per module
- Bandwidth graphs show RX/TX as percentage of interface speed

## [0.10.79] - 2026-03-04

### Fixed
- Fix sFlow "Top Conversations" showing ALL device traffic instead of connection-specific VPN traffic
- Primary filtering now uses VPN subnet pairs (local_subnet/remote_subnet → SQL LIKE patterns) instead of unreliable interface index matching
- Improved fallback: include Phase1Names in interface name matching when subnets unavailable
- Removed overly broad Strategy 2 that grabbed all tunnel-type interfaces from both devices

## [0.10.78] - 2026-03-04

### Fixed
- Fix 500 on VPN chart queries — raw SQL used `vpn_statuses` but actual table name is `vpn_status`

## [0.10.77] - 2026-03-04

### Fixed
- Fix LAG() delta queries: use manual SQL placeholders for IN clauses (GORM Raw doesn't reliably expand slices in subqueries)
- Fix first-row delta bug: LAG() returning NULL on first row was falling through to ELSE branch returning raw cumulative counter instead of NULL — now explicitly returns NULL so first row is properly filtered
- Add error logging to traffic and VPN chart handlers for debugging 500s

## [0.10.76] - 2026-03-04

### Fixed
- Fix CSP violation blocking Chart.js — add `'unsafe-inline'` to script-src directive
- Add inline SVG favicon to prevent 404 on `/favicon.ico`

## [0.10.75] - 2026-03-04

### Added
- Syslog-driven alerts: critical syslog messages (severity 0-2) now auto-generate alerts with notifications
- Recovery/resolved notifications for all alert types: CPU, memory, disk, sessions, VPN tunnels, interfaces, and device offline
- Interface error/discard alerting: detects new errors between poll cycles and fires warning alerts
- API endpoints for security stats, SD-WAN health, and HA status per device (`GET /api/devices/:id/security-stats`, `/sdwan-health`, `/ha-status`)
- Dashboard enrichment includes HA mode/member count and SD-WAN alive/total per device
- Database query functions: `GetLatestSecurityStats`, `GetSecurityStatsHistory`, `GetLatestSDWANHealth`, `GetLatestHAStatus`
- Cross-fill VPN tunnel uptime from paired tunnels in connection detail (same pattern as subnet backfill)

### Fixed
- Fix 500 error on connection traffic chart — GORM `IN ?` placeholder was double-parenthesized in raw SQL
- Fix CSP `script-src` to allow Chart.js internal eval (`'unsafe-eval'`)

## [0.10.74] - 2026-03-04

### Fixed
- Fix VPN traffic charts showing meaningless cumulative counter sums — now uses LAG() window function to compute actual per-interval byte/packet deltas from SNMP counters
- Fix per-tunnel chart data (GetVPNChartData) using AVG of cumulative counters — same LAG() delta fix
- Fix throughput gauges showing wrong values with no real units — now displays server-computed Mbps with % of 1 Gbps capacity
- Tighten sFlow filtering in connection detail to only show flows matching this connection's specific tunnels, not all tunnels from both devices

### Added
- Server-side throughput computation (bytes/sec) in connection detail API from latest VPN status samples

## [0.10.73] - 2026-03-04

### Fixed
- Fix doubled total bytes/packets in connection detail — was summing both source and dest tunnels but they represent the same traffic from opposite perspectives

## [0.10.72] - 2026-03-04

### Fixed
- Cross-fill empty Phase 2 subnets from paired tunnel in connection detail — hub-side ADVPN tunnels (e.g. NUDAY_LAN) now show local/remote subnet inferred from the spoke side's data

## [0.10.71] - 2026-03-04

### Fixed
- Fix connection detail page showing empty dest tunnels for NAT'd hub-spoke VPNs (tunnel_indirect/wan_inferred matches)
  - Infers source device WAN IPs from dest tunnel remote IPs for indirectly matched connections
  - Example: NUDAY-FW's `dialup-76.64.79.217` tunnel now correctly appears as dest tunnel for DC2-FW1 ↔ NUDAY-FW
- Fix overlay detector assigning wrong connection type ("ipsec") to vxlan-named interfaces with empty/non-overlay TypeName
  - Interfaces accepted by name prefix (e.g., vxlan500) now get effective type "vxlan" if their SNMP TypeName isn't an overlay type

## [0.10.70] - 2026-03-04

### Fixed
- Fix SQLite "readonly database" error caused by non-root container user unable to write to bind-mounted data volume
- Entrypoint now starts as root, fixes `/data` and `/config` ownership, then drops to `fwmon` user via `su-exec`
- Removed `USER fwmon` from Dockerfile — privilege drop happens at runtime in entrypoint instead

## [0.10.69] - 2026-03-04

### Fixed
- Add server-side error logging for all probe data ingestion handlers (security stats, flow samples, interface stats, VPN statuses, etc.) — previously DB errors returned 500 without logging the cause

## [0.10.68] - 2026-03-03

### Added
- Physical (Ethernet/LAG) connection auto-detection via shared IP subnet matching
  - Detects same-site devices with Ethernet (ifType 6) or LAG (ifType 161) interfaces on the same subnet
  - Skips /30, /31, /32 point-to-point WAN links — only matches LAN segments
  - Accumulates interface names per device pair (e.g., "port1, port2")
  - Uses `subnet_match` discovery method badge
- `ethernet` connection type styling in all frontend style maps (gray #6e7681, solid, width 2)
- `subnet_match` discovery badge in connection tables and network diagram

## [0.10.67] - 2026-03-03

### Fixed
- L2VLAN connections now accumulate ALL matching interface names (was stopping after first match)
- buildCIDR now preserves wildcard subnets (0.0.0.0/0) for Phase 2 selectors
- Connection detail panel now shows dest tunnels for NAT'd VPN scenarios via WAN IP cross-referencing

### Added
- WAN IP inference phase in VPN auto-detection — catches NAT'd hub-spoke tunnels (e.g., dialup-x.x.x.x)
- Site grouping in connection diagram — dashed rounded rectangles around same-site device clusters
- Straight lines for same-site connections with parallel offsets for multiple connections
- Tunnels column in connections table with count badge and abbreviated names
- Multi-line tunnel list in connection detail panel
- Discovery badges for `wan_inferred` and `overlay_name` match methods

## [0.10.66] - 2026-03-03

### Security
- **Remove CSP `unsafe-inline` for scripts**: Removed `'unsafe-inline'` from CSP `script-src` directive, hardening XSS protection. All scripts are now external with `defer`.

### Refactor
- **Extract all inline JS to external files**: Created 10 new external JS files, eliminating every inline `<script>` block across 9 HTML pages:
  - `admin-common.js` — shared utilities (escapeHtml, apiFetch, CSRF, delegateEvent)
  - `admin-login.js`, `public-dashboard.js` (standalone pages)
  - `admin-sites.js`, `admin-probe-pending.js`, `admin-probes.js`, `admin-network.js` (admin pages)
  - `admin-connection-detail.js`, `admin-device-detail.js`, `admin-main.js` (detail/dashboard pages)
- **Convert ~114 inline event handlers to data-action delegation**: Replaced every `onclick`, `onchange`, `onsubmit` across all HTML files and dynamically-generated JS strings with `data-action` + `data-*` attributes.
- **Update diagram JS files**: Converted ~30 inline handlers in `diagram-panels.js`, 4 in `diagram-core.js`, and 1 in `diagram-tunnel-zoom.js` to data-action delegation.

## [0.10.65] - 2026-03-03

### Security (P1 — High)
- **H3: SNMP credentials encrypted at rest**: Added AES-256-GCM encryption for `SNMPCommunity`, `SNMPV3AuthPass`, and `SNMPV3PrivPass` in the database. Encryption key is derived from `JWT_SECRET_KEY` via SHA-256. Existing plaintext values are automatically migrated on startup. Encrypted values use a `{enc}` prefix for backward-compatible detection.
- **H4: Remove insecure SNMP defaults**: Removed `default:public` from SNMP community GORM tags. `TestDeviceConnection` now requires an explicit community string for SNMPv1/v2c instead of defaulting to "public". SNMP trap community default changed from "public" to empty string.
- **H7: Cookie Secure flag auto-detection**: `COOKIE_SECURE` now defaults to match `SERVER_ENABLE_TLS` instead of always defaulting to `false`. When TLS is enabled, cookies are automatically marked Secure without explicit configuration.
- **H10: SNMP error detail redaction**: `TestDeviceConnection` now returns generic error messages ("unable to reach device", "device did not respond to SNMP query") instead of leaking internal SNMP error details. Detailed errors are still logged server-side.

## [0.10.64] - 2026-03-03

### Security (P2 — Medium)
- **M2+M3: JWT token revocation**: Added `token_version` field to Admin model and JWT claims. Tokens are now server-side invalidated on password change and logout by incrementing the version counter. `ValidateToken` checks the current version against the database, rejecting stale tokens immediately rather than waiting for expiry.
- **M4: Docker non-root user**: Dockerfile now creates a dedicated `fwmon` user/group and runs the container as non-root via `USER fwmon`, reducing the blast radius of container escapes.
- **M5: Remove Docker host networking**: Replaced `network_mode: "host"` in docker-compose.yml with explicit port mappings (8080, 162/udp, 514/tcp+udp, 6343/udp, 8089), providing network isolation between the container and host.
- **M6: Go version bump**: Updated Go directive from 1.21 to 1.22 in both `go.mod` and Dockerfile builder stage. Operators should run `go get -u ./... && go mod tidy` to refresh dependencies.
- **M7: Syslog source IP allowlist**: Both TCP and UDP syslog receivers now support an `AllowedSourceIPs` config field (`SYSLOG_ALLOWED_SOURCES` env var, comma-separated). When set, packets/connections from non-listed IPs are silently dropped.
- **M8: sFlow source IP allowlist**: sFlow receiver now supports an allowed source IP list (`SFLOW_ALLOWED_SOURCES` env var, comma-separated). When set, datagrams from non-listed IPs are silently dropped.

## [0.10.63] - 2026-03-03

### Security (P3 — Low)
- **L1: CSRF fix in connection-detail.html**: Added CSRF token fetching and `X-CSRF-Token` header to all API requests including logout. Upgraded `apiFetch` to match the pattern used in other admin pages.
- **L2: CSRF token parsing fix in device-detail.html**: Changed `d.data?.token` to `d.csrf_token` to match the actual API response format from `/admin/api/csrf-token`.
- **L3: Tightened CSP directives**: Added `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, and `frame-ancestors 'none'` to Content-Security-Policy header. `unsafe-inline` for scripts/styles remains necessary due to inline usage across all admin pages.
- **L4: Per-IP account lockout**: Login lockout is now tracked per `username:IP` composite key instead of per-username only, preventing remote attackers from locking out the admin account from a different IP.
- **L5: config.env in .gitignore**: Added `config.env` to `.gitignore` to prevent accidental commit of production secrets.
- **L6: Text field length validation**: Added maximum length checks on all string fields in CreateDevice, UpdateDevice, CreateSite, and UpdateSite handlers (name: 255, description: 1000, address: 500, etc.).
- **L7: Mass assignment prevention**: `CreateDevice` now zeroes `ID`, `CreatedAt`, `UpdatedAt`, `LastPolled` before insert. `CreateSite` now zeroes `ID` before insert.
- **L8: Rate limiter dead code cleanup**: Removed unused `stop` channel from `ipRateLimiter` struct; simplified cleanup goroutine to use `for range ticker.C`.
- **L9: Composite DB indexes**: Added `(device_id, timestamp)` composite indexes to `PingResult`, `SyslogMessage`, and `FlowSample` models. Added `(device_id, probe_id, target_ip)` composite index to `PingStats` for efficient lookups.

## [0.10.62] - 2026-03-03

### Security (P2 — Medium)
- **SameSite cookie from config**: Login/logout cookies now use the `COOKIE_SAMESITE` env var (default `Strict`) instead of hardcoded `Lax`, strengthening CSRF protection.
- **SMTP SSRF prevention**: `TestEmail` now validates the SMTP host against loopback, private, and link-local addresses before connecting, preventing server-side request forgery to internal services.
- **Private IP SSRF block**: `isValidExternalIP` now rejects RFC 1918 / RFC 4193 private IP ranges (10.x, 172.16-31.x, 192.168.x, fc00::/7) in addition to loopback and link-local, closing the DNS rebinding SSRF bypass.
- **Device ownership validation**: All 14 probe data-ingestion handlers now verify submitted `device_id` values against the probe's assigned device list, preventing a compromised probe from injecting data into unrelated devices. Unauthorized records are silently filtered before database writes.
- **Site circular reference detection**: `UpdateSite` now walks up the parent chain (max depth 50) to detect circular parent references, preventing infinite loops in site hierarchy.
- **TCP syslog WaitGroup**: `SyslogReceiver.Stop()` now waits for all active TCP connections to finish via `sync.WaitGroup`, ensuring clean shutdown without orphaned goroutines.

### Fixed (Collector)
- **Relay batch re-queue**: Failed data batches (traps, pings, syslog, flows) are now re-queued for the next sync cycle instead of being silently dropped after 3 retries, improving data delivery reliability.

## [0.10.61] - 2026-03-03

### Security (P0 — Critical)
- **Probe endpoint authentication**: All 14 probe data-ingestion endpoints (`/api/probes/:id/syslog`, `/traps`, `/flows`, etc.), the heartbeat endpoint, and the device-list endpoint now require `Authorization: Bearer <registration_key>` — previously these were completely unauthenticated, allowing anyone who guessed a probe ID to inject fake monitoring data or read SNMP credentials. The collector already sends this header, so no collector changes are needed.
- **Probe heartbeat validation**: `ProbeHeartbeat` now authenticates the caller by Bearer token, validates probe_id matches the authenticated probe, and restricts status to `online`/`offline`/`degraded`.
- **Mass assignment prevention in CreateProbe**: Forces `ApprovalStatus = "pending"`, `ID = 0`, and clears all server-controlled fields before database insert — previously an attacker could POST `{"approval_status":"approved"}` to bypass the admin approval workflow.

### Security (P1 — High)
- **Hardcoded credentials removed**: Removed `changeme123!` default password from `entrypoint.sh`; cleared `JWT_SECRET_KEY`, `ADMIN_SECRET_KEY`, and `ADMIN_PASSWORD` values from `config.env.example`. Dockerfile now copies the example file as `config.env.example` (not `config.env`), so auto-generated secrets are used by default.
- **TLS minimum version enforced**: Added `MinVersion: tls.VersionTLS12` to TLS configs in syslog receiver and relay client — previously TLS 1.0 (vulnerable to BEAST/POODLE) was accepted.
- **Data race fix (AlertManager/Notifier)**: `Notifier.SendAlert()` now receives a `NotifyConfig` value snapshot taken under the AlertManager's lock, instead of reading shared `config.Alerts.*` fields without synchronization. Eliminates a race between `RefreshThresholds()` writes and notification reads.
- **LIKE wildcard injection fix**: Syslog search now escapes `%` and `_` metacharacters before constructing LIKE patterns, preventing query manipulation and DoS via expensive full-table scans.

## [0.10.60] - 2026-03-03

### Fixed
- **CSP data: URI images**: Added `img-src 'self' data:` to Content-Security-Policy so Chart.js inline data-URI images are not blocked
- **Panel traffic chart crash**: All `window.apiFetch()` calls in `diagram-panels.js` and `diagram-tunnel-zoom.js` now unwrap the `{success, data}` response envelope — fixes `data.map is not a function` errors on traffic, detail, flows, and tunnel chart panels

## [0.10.59] - 2026-03-03

### Fixed
- **CSP source map block**: Added `connect-src 'self' https://cdn.jsdelivr.net` to Content-Security-Policy header so Chart.js can fetch its `.js.map` source map without being blocked by the `default-src 'self'` fallback

## [0.10.58] - 2026-03-03

### Fixed
- **Static JS 404 fix**: Embedded `static/js/` diagram modules into the Go binary via `go:embed`, eliminating 404 errors when running from Docker or from a different working directory. Moved JS files from `static/js/` to `cmd/api/static/js/` so they are included by the existing `COPY cmd ./cmd` in the Dockerfile.

## [0.10.57] - 2026-03-03

### Added
- **Modular diagram library**: Extracted ~900 lines of connection diagram JavaScript from admin.html into 6 library files under `static/js/`: `diagram-core.js` (SVG setup, zoom/pan), `diagram-layout.js` (circular layout, drag-and-drop), `diagram-connections.js` (path rendering, UP-only filter), `diagram-particles.js` (traffic-proportional rAF animation), `diagram-panels.js` (rich detail panels), `diagram-tunnel-zoom.js` (per-tunnel SVG overlay)
- **Scroll-wheel zoom**: Zoom into diagram around cursor point (0.3x–3x range), +/- buttons and 1:1 reset in top-right overlay
- **Ctrl+drag pan**: Pan the diagram viewport with Ctrl+click-drag
- **Drag-and-drop device nodes**: Drag devices to rearrange the diagram; positions persist in localStorage. "Reset Layout" button restores circular default
- **UP-only connection lines**: Only connections with `status === 'up'` are drawn as paths, decluttering the diagram for NOC operators. DOWN tunnels remain visible via VPN badge counts and detail panels
- **Outward same-site arcs**: Direct connections between same-site devices bulge away from center, clearly bypassing the cloud node
- **Cross-site angular fan spread**: Cross-site paths fan across a 60-degree arc through unique cloud transit points, providing 15–30px minimum separation between paths
- **Traffic-proportional particles**: Particle count (1–6) and speed scale with `log10(bytesIn + bytesOut)` using `requestAnimationFrame` + `getPointAtLength()` instead of `<animateMotion>` elements
- **Tunnel zoom overlay**: "Zoom In" button in connection detail panel opens an SVG overlay with source/dest nodes and each tunnel drawn as a separate labeled horizontal path with UP animation and DOWN dashed gray. Click any tunnel for details tooltip
- **VPN map bytes**: `bytes_in`/`bytes_out` fields added to `/api/connections/vpn-map` tunnelInfo response

### Changed
- admin.html reduced from 2,980 to ~2,115 lines (net -865 lines) via modular library extraction
- Panel onclick handlers now route through `FWDiagram.Panels` namespace with global bridge functions for inline HTML compatibility

## [0.10.56] - 2026-03-03

### Added
- **Cross-site VPN routing**: Connections between devices in different sites now route through the Internet cloud node with two-segment bezier paths (Source→Cloud + Cloud→Dest), each with unique offsets to avoid overlap. Same-site connections remain direct curves.
- **Rich connection detail panel**: Clicking any connection line opens a full diagnostic panel inline with bridge SVG animation, KPI cards (bytes in/out, tunnel count, status), and four tabs: Overview (traffic chart with 1h/24h/7d/30d range pills), Tunnels (two-column expandable table with per-tunnel bandwidth charts), Phase 2 (IPSec selector match SVG diagrams), and Flows (protocol doughnut, traffic timeline, top sources/destinations bar charts, conversations table)
- **Rich VPN badge panel**: Clicking a device VPN badge shows tunnels grouped into Matched (linked to known devices) and Off-Net sections, each with expandable rows containing inline Chart.js bandwidth charts with range pills
- **Chart lifecycle management**: All panel charts tracked in `panelChartInstances` with proper cleanup on panel open/close/switch to prevent memory leaks
- **Cloud node scaling**: Cloud node width now scales based on the number of cross-site connections and off-net tunnels

### Changed
- Off-net tunnel dashed lines now use `2,4,8,4` dot-dash pattern to visually distinguish from cross-site connection paths
- Old `showConnDetailPanel` and `showVPNDetailPanel` replaced entirely by rich panel versions
- Diagram re-render preserves open panel when `currentPanelConnId` is set

## [0.10.55] - 2026-03-03

### Added
- New API endpoint `GET /api/connections/vpn-map` returning per-device VPN tunnel summaries with remote IP matching
- VPN badge on each device node in connection map showing up/total tunnel counts (green/amber/red)
- Internet cloud node at center of connection map when any device has off-net (unmatched) VPN tunnels
- Dashed green/gray lines from devices to cloud node for off-net tunnel visualization with particle animation
- VPN detail panel (table) opened by clicking device VPN badge — shows tunnel name, type, status, remote IP, destination, and uptime
- Off-net filter mode when clicking cloud connection lines to show only unmatched tunnels

## [0.10.54] - 2026-03-03

### Fixed
- **False tunnel connections from name-matching**: Renamed `detectTunnelConnections` → `detectOverlayConnections` and restricted it to only L2VLAN, L3IPVLAN, and VXLAN types. Tunnel/IPSec/GRE connections are now handled exclusively by `detectVPNConnections` which uses actual VPN tunnel data (IPs, status) rather than error-prone interface name matching. This eliminates false connections from generic names like "Remote Access" appearing on unrelated devices.
- **Down tunnels indistinguishable from up tunnels on network map**: DOWN connections in `network.html` now render with dimmed gray (#484f58) stroke at 50% opacity instead of full type color. In `admin.html`, DOWN connection paths also use dimmed gray instead of the type color (opacity pulse animation was already correct).

## [0.10.53] - 2026-03-03

### Added
- **Indirect VPN detection for NAT'd tunnels**: When VPN tunnel remote IPs don't match any known device (common with NAT'd IPSec), the poller now tries matching the VPN tunnel name against device names (e.g., tunnel "NUDAY_LAN" on DC2-FW1 matches device "NUDAY-FW"). Creates connections with match method `tunnel_indirect`.
- **Database-backed `hasDirectLink` fallback**: The overlay validation check now also queries the database for existing tunnel/ipsec connections, not just in-memory VPN status data. This allows overlays (l3ipvlan/vxlan) to be detected once the underlying IPSec tunnel is established by any method (IP match, tunnel_indirect, or manual).

## [0.10.52] - 2026-03-03

### Fixed
- **Tunnel connections (HUB↔SPOKES) not detected**: v0.10.51 was too aggressive — requiring `hasDirectLink()` for ALL non-l2vlan types blocked legitimate tunnel detection since tunnel/ipsec/gre interfaces ARE the tunnels themselves. Restored three-category validation: l2vlan requires sameSite, overlays (l3ipvlan/vxlan) require hasDirectLink, tunnels (ipsec/gre/tunnel) use name-match only. The `isSystemIface` filter (*.root/*.vdom) already prevents false matches from system interfaces.

## [0.10.51] - 2026-03-03

### Fixed
- **False triangle from FortiGate system interfaces (naf.root, l2t.root, ssl.root)**: Added pattern-based `isSystemIface` filter that skips all `*.root` and `*.vdom` suffixed interfaces — these are generic system interfaces present on every FortiGate and created false connections between all devices
- **Unified validation for all non-local types**: All connection types except l2vlan now require `hasDirectLink()` (a verified VPN tunnel between endpoints). Previously only overlay types (l3ipvlan/vxlan) required this check, allowing generic "tunnel" type interfaces like `naf.root` to bypass validation
- **Expanded startup cleanup**: Added `naf.root` and `l2t.root` to the list of stale connection names cleaned up on poller startup

## [0.10.50] - 2026-03-03

### Fixed
- **False triangle connections between all firewalls**: Overlay types (l3ipvlan, vxlan) now require a direct VPN tunnel link (`hasDirectLink`) between the device pair. Previously, devices sharing a VLAN name got l3ipvlan connections even without a tunnel between them (e.g., FW1↔FW3 got a false l3ipvlan when only FW1↔FW2 had an IPSec tunnel). Now: l2vlan requires same-site, l3ipvlan/vxlan requires a direct tunnel, preventing false cross-site overlay connections.

## [0.10.49] - 2026-03-03

### Fixed
- **Stale cleanup deleting VPN connections**: The `CleanupStaleAutoConnectionsBefore` call was inside `detectTunnelConnections` with a `cycleStart` timestamp set AFTER `detectVPNConnections` had already run — causing it to delete the VPN-detected connections every cycle. Moved the cycle timestamp and cleanup to the parent `pollAllDevices` function so both detectors' connections survive.

## [0.10.48] - 2026-03-03

### Improved
- **Robust connection auto-detection overhaul**:
  - **Name normalization**: Interface names are stripped of separators (spaces, dots, dashes, underscores) before matching — `vlan500`, `vlan 500`, `vlan.500`, `vlan-500`, `VLAN_500` all match correctly
  - **Per-pair type determination**: Connection type is now determined from each pair's own interface types instead of the whole group, so FW2↔FW3 (both l2vlan) get "l2vlan" while FW1↔FW2 (l3ipvlan + l2vlan) get "l3ipvlan"
  - **Multi-type per pair**: Database upsert key changed from device-pair to device-pair+type, allowing the same pair to have both an ipsec AND l2vlan connection
  - **Stale cleanup**: Auto-detected connections not refreshed in the current poll cycle are automatically deleted — connections disappear when interfaces are removed
  - **Same-site scoping**: L2VLAN connections only created between devices assigned to the same site

## [0.10.47] - 2026-03-03

### Fixed
- **L2VLAN auto-detection scoped to same-site devices**: L2VLAN connections are now only auto-detected between devices assigned to the same site. Devices at different sites sharing a VLAN name are skipped, preventing false cross-site L2 connections. L3IPVLAN and other tunnel types remain unrestricted.

## [0.10.46] - 2026-03-02

### Fixed
- **Remove L2VLAN from tunnel auto-detection**: L2VLAN is a local segment, not a tunnel — auto-detecting it by interface name created false connections between devices that share a VLAN name but aren't on the same physical segment. L3IPVLAN (overlay extending L2 through IPSec/GRE) remains auto-detected.

## [0.10.45] - 2026-03-02

### Added
- **Network type-aware connection visualization**: Connection map now renders distinct colors, dash patterns, and line widths for each network layer type (IPSec, SSL VPN, VXLAN, L2VLAN, L3IPVLAN, GRE, LAG, Tunnel, WAN)
- **Poller auto-detection for L2VLAN/L3IPVLAN**: `detectTunnelConnections` now recognizes `l2vlan` and `l3ipvlan` interface types with priority-based type determination (l3ipvlan > vxlan > l2vlan > gre > ipsec > tunnel)
- **Connection type legend/filter expansion**: All connection type dropdowns and legends across network.html, admin.html, and connection-detail.html include the new types
- **Type-specific bridge rendering**: Connection detail page bridge SVG uses per-type colors, dash patterns, and particle colors instead of hardcoded vxlan/default logic

## [0.10.44] - 2026-03-02

### Fixed
- **Auto-cleanup stale `ssl.root` connections**: Poller now deletes auto-detected connections with generic tunnel names (`ssl.root`, `ssl.vdom`) on startup via `CleanupStaleAutoConnections()`

## [0.10.43] - 2026-03-02

### Fixed
- **Browser autofill ignoring `autocomplete="off"`**: Replaced all `autocomplete="off"` with `autocomplete="one-time-code"` across all HTML pages — Chrome/Edge ignore `off` but respect `one-time-code`, preventing email/credential autofill into IP address, search, and name fields

## [0.10.42] - 2026-03-02

### Fixed
- **False tunnel connections from `ssl.root`**: Added FortiGate default SSL VPN interfaces (`ssl.root`, `ssl.vdom`) to the tunnel auto-detection skip list — these exist on every FortiGate and were causing spurious pairwise connections between all devices

## [0.10.41] - 2026-03-02

### Added
- **Indirect tunnel connection detection**: `detectTunnelConnections` now cross-checks name-matched device pairs against VPN tunnel remote IPs; pairs with no direct IP evidence are marked as "tunnel_indirect" instead of "tunnel_name"
- **Indirect connection rendering**: Indirect connections show as amber/orange dotted lines (#f0883e) with slower, smaller amber particles — visually distinct from direct connections (green) and VXLAN (purple)
- **"Indirect" match method badge**: Orange badge displayed across admin, network, and connection detail pages for tunnel-name-only connections without direct IP verification
- **Phase 2 selector inverse matching**: `GetConnectionDetail` now matches Phase 2 selectors between connected devices — if source's `local_subnet` equals destination's `remote_subnet` (and vice versa), a `Phase2Match` is created confirming end-to-end IPSec SA alignment
- **Phase 2 Selectors tab**: New tab on the connection detail page showing matched Phase 2 pairs with animated SVG diagrams — green particles flow between matching subnets when both tunnels are up, with bidirectional TX/RX animation
- **`Phase2Match` struct**: Backend data structure for matched Phase 2 selector pairs (source/dest tunnel names, Phase 1 names, local/remote subnets, status)

### Fixed
- **False VXLAN connections**: Previously, two devices with the same VXLAN interface name (e.g., "vxlan1") were auto-connected even if they communicated through an intermediate hub device; now correctly detected as indirect

## [0.10.40] - 2026-03-02

### Added
- **IPSec Phase 2 selector support**: VPNStatus model now includes `phase1_name`, `local_subnet`, `remote_subnet`, and `tunnel_uptime` fields collected via FortiGate SNMP OIDs (.2, .5-.8, .21)
- **Phase 2 subnet display**: Connection detail and device detail VPN tables now show Phase 1 name, Phase 2 name, local/remote subnets in CIDR notation, and tunnel uptime
- **Bidirectional traffic animation**: SVG connection diagram and connection detail bridge now show particles flowing both directions — TX (connection color, source→dest) and RX (blue, dest→source)
- **Expanded tunnel auto-detection**: Renamed `detectVXLANConnections` → `detectTunnelConnections` to support IPSec, GRE, L2TP, WireGuard, and hub/spoke topologies — creates pairwise connections for multi-device tunnel groups
- **Tunnel Name match method badge**: Auto-detected tunnel connections display "Tunnel Name" discovery badge in orange across admin, network, and connection detail pages
- **`buildCIDR()` helper**: Combines IP address and subnet mask from SNMP into CIDR notation (e.g., "10.0.0.0/24")

### Fixed
- **sFlow tunnel interface matching**: Broadened matching strategy with three fallback layers — name/description/alias match, VPN-type interface match, and tunnel remote IP fallback — so "no traffic samples match" message is far less likely when sFlow is enabled
- **Broken build**: Fixed dangling call to removed `detectVXLANConnections` function (renamed to `detectTunnelConnections`)

## [0.10.39] - 2026-03-02

### Fixed
- **Connection detail page showing zero data**: Fixed broken GORM `Group("ip_address")` query on InterfaceAddress table that returned empty results; replaced with `Distinct().Pluck()` for correct IP collection
- **Tunnel matching fallback**: Connection detail and traffic queries now also match tunnels by name from the auto-discovered `TunnelNames` field, not just by IP address
- **Browser autofill populating search fields**: Added `autocomplete="off"` to all text inputs across admin.html, network.html, probes.html, sites.html, and dynamic settings forms to prevent browser from filling search/form fields with saved login credentials
- **Server-side sFlow device resolution**: Flow samples arriving with `device_id=0` are now resolved server-side by matching `sampler_address` against device management IPs and interface addresses

### Added
- **sFlow per-device filtering**: Device dropdown filter on the Flows page filters both the flow samples table and all stats charts (protocol distribution, top talkers, bytes over time) by selected device
- **`GetFlowStats` device filter**: Flow stats aggregation query now accepts optional `device_id` parameter (`?device_id=X`)
- **`ResolveDeviceByIP()` database function**: Resolves IP address to device ID by checking management IP and interface addresses table
- **`collectDeviceIPs()` helper**: Centralized function for collecting all known IPs for a device (management + interface addresses)

## [0.10.38] - 2026-03-02

### Added
- **NOC-style animated SVG connection diagram**: Replaced CSS DIV-based connection map with full SVG canvas featuring bezier curves, glow filters, device status indicators, and click-to-detail panels
- **Animated traffic particles**: "Up" connections show flowing particle animations along paths using SVG `animateMotion`; down connections pulse red
- **VXLAN visual distinction**: VXLAN connections render in purple with dashed stroke pattern
- **Connection detail page** (`/admin/connections/:id`): Full standalone page with animated bridge header, aggregate bandwidth charts, live throughput gauges, tunnel tabs, and sFlow traffic analysis
- **Per-tunnel bandwidth charts**: Expandable tunnel rows with lazy-loaded Chart.js charts and time range selectors (1h/24h/7d/30d)
- **sFlow traffic analysis tab**: Protocol distribution doughnut, top sources/destinations horizontal bars, top conversations table, bytes-over-time chart — conditionally shown when sFlow data exists
- **VPN chart data API** (`GET /admin/api/devices/:id/vpn/:tunnel/chart`): Time-bucketed VPN tunnel bandwidth data
- **Connection detail API** (`GET /admin/api/connections/:id/detail`): Full connection info with matching source/dest tunnels, aggregate stats, and sFlow availability flag
- **Connection traffic API** (`GET /admin/api/connections/:id/traffic`): Aggregate bandwidth chart data across all matching tunnels
- **Connection flows API** (`GET /admin/api/connections/:id/flows`): sFlow traffic analysis filtered to connection tunnel interfaces with protocol breakdown, top talkers, conversations, and time series
- **View Details links**: Added connection detail navigation from connections table, SVG diagram click panel, and network page detail sidebar

## [0.10.37] - 2026-03-02

### Added
- **Enhanced VPN auto-discovery via interface IP collection**: Walks standard IP-MIB `ipAddrTable` on every device to collect all interface IP addresses, enabling VPN connection matching even when a device's WAN IP differs from its configured management/SNMP IP
- **New `InterfaceAddress` model**: Stores per-device interface IPs with ifIndex, IP address, and netmask; auto-migrated, cleaned up with other time-series data
- **Bidirectional VPN detection**: When both sides of a VPN pair have tunnels pointing at each other, the connection is upgraded to "bidirectional" match method for higher confidence
- **VXLAN connection auto-discovery**: New `detectVXLANConnections()` finds VXLAN/tunnel interfaces with matching names across exactly 2 devices and creates auto-detected connections with type "vxlan"
- **`MatchMethod` field on `DeviceConnection`**: Tracks how each connection was discovered — `ip_match` (management IP), `interface_ip` (WAN/interface IP), `bidirectional` (both sides confirmed), `vxlan_name` (matching interface names), or `manual`
- **Connection type inference from VPN tunnel type**: IPSec tunnels set `connection_type = "ipsec"`, SSL-VPN tunnels set `connection_type = "ssl"`
- **Discovery column in connections UI**: Both admin.html and network.html connections tables show color-coded badges for match method (gray=IP Match, blue=WAN IP, green=Bidirectional, purple=VXLAN)
- **VXLAN visual differentiation**: VXLAN connections render purple in admin.html diagram and with dashed purple lines in network.html SVG map
- **Connection detail tooltips**: Admin diagram tooltips and network.html detail panel now show discovery method and tunnel names
- **Probe endpoint**: `POST /api/probes/:id/interface-addresses` for remote probe interface address ingestion
- **Database methods**: `SaveInterfaceAddresses`, `GetLatestInterfaceAddresses`, `GetAllLatestInterfaces`

### Changed
- `UpsertAutoConnection()` now accepts `connType` and `matchMethod` parameters instead of hardcoding `"ipsec"`, enabling proper type/method tracking for all auto-detected connections

## [0.10.36] - 2026-03-02

### Added
- **Device detail UI**: 4 new data tabs — HA Cluster, Security, SD-WAN, Licenses
  - **HA Cluster tab**: Shows cluster mode, member table with serial, hostname, CPU/memory %, network usage, sessions, sync status, and primary/secondary role
  - **Security tab**: Stat-grid layout for AV (detected/blocked, HTTP/SMTP), IPS (detected/blocked + severity breakdown), and WebFilter (HTTP/HTTPS/URL blocked)
  - **SD-WAN tab**: Per-link table with name, interface, state badges (alive/dead), latency, packet loss, sent/received counters
  - **Licenses tab**: Description and expiry date with color-coded expiry (expired=red, <30d=yellow, ok=green)
- **VPN tab**: Added "Type" column with color-coded badges for `ipsec` (blue), `ipsec-dialup` (yellow), `sslvpn` (green)
- **Extended system status cards**: Conditionally shows Session Rate (1m/10m/30m/60m), IPv6 Sessions, SSL-VPN (users/tunnels), AV Signature version, IPS Signature version when data is present
- **API**: `GetDeviceDetail()` now returns `ha_status`, `security_stats`, `sdwan_health`, `license_info` alongside existing data

## [0.10.35] - 2026-03-02

### Added
- **Comprehensive FortiGate SNMP monitoring expansion** across 6 areas:
  - **Extended SystemStatus**: Session setup rates (1/10/30/60 min averages), IPv6 session count, low memory utilization, AV/IPS signature versions, SSL-VPN aggregate user/tunnel counts
  - **SSL-VPN tunnels**: SSL-VPN client sessions now appear in VPN status with `tunnel_type: "sslvpn"` alongside IPSec tunnels (`ipsec`, `ipsec-dialup`)
  - **HA cluster monitoring**: Redesigned `HAStatus` model with per-member rows — CPU, memory, network, sessions, packets, bytes, sync status, master serial per HA member
  - **Security stats**: New `SecurityStats` model tracking AV detected/blocked (total, HTTP, SMTP), IPS detected/blocked by severity, and WebFilter HTTP/HTTPS/URL blocked counts
  - **SD-WAN health checks**: New `SDWANHealth` model with per-link name, interface, state (alive/dead), latency, packet loss, send/recv counters
  - **License/contract tracking**: New `LicenseInfo` model with contract description and expiry date
- `TunnelType` field on `VPNStatus` model to distinguish IPSec site-to-site, IPSec dialup, and SSL-VPN tunnels
- 4 new probe data ingestion endpoints: `POST /api/probes/:id/ha-status`, `/security-stats`, `/sdwan-health`, `/license-info`
- Database save methods: `SaveHAStatuses`, `SaveSecurityStats`, `SaveSDWANHealth`, `SaveLicenseInfo`
- Auto-migration for new tables: `security_stats`, `sdwan_health`, `license_info`

## [0.10.34] - 2026-03-02

### Added
- **Ping latency in Status History chart**: Device detail status history chart now includes ICMP latency (ms) as a 4th dataset on a secondary Y-axis, combining CPU/Memory/Disk percentages with ping response times in one view
- `GetPingResultHistory()` database method for time-series ping result queries

### Changed
- `GET /api/devices/:id/status-history` now returns `{ system_status: [...], ping_history: [...] }` instead of a flat array (breaking change for API consumers)

## [0.10.33] - 2026-03-02

### Fixed
- **Disk usage percentage calculation**: FortiGate `fgSysDiskUsage`/`fgSysDiskCapacity` OIDs return values in MB, not percentage — now correctly computes `usage/capacity * 100` instead of storing raw MB as percentage
- **SNMP PDU type guard**: Added `isValidPDU()` check to skip `NoSuchObject`/`NoSuchInstance`/`EndOfMibView` responses instead of silently treating unsupported OIDs as zero values

## [0.10.32] - 2026-03-02

### Fixed
- **Probe-assigned devices stay "online" forever**: Server poller now checks for stale probe-assigned devices each poll cycle and marks them "offline" if no data received for 3× the poll interval (minimum 5 minutes)

## [0.10.31] - 2026-03-02

### Added
- `POST /api/probes/:id/processor-stats` endpoint for receiving per-core processor stats from probes
- Probe-polled devices now display processor usage data (previously only worked for server-polled devices)

## [0.10.30] - 2026-03-02

### Added
- Diagnostic endpoint `/admin/api/dashboard/diag` showing per-device system_status row counts and latest values
- `status_rows` count in device enrichment API response for data availability visibility
- Enhanced logging in `ReceiveSystemStatuses` showing probe ID, saved count, and device IDs per batch
- Device table CPU/Memory/Sessions tooltips now show record count and last polled time

### Fixed
- Improved "No data" tooltip to include device_id for easier cross-referencing with collector logs

## [0.10.29] - 2026-03-02

### Fixed
- CPU/memory/session data showing "-" for devices with valid polling data due to `> 0` check filtering out 0% values
- Added `has_status` flag to device enrichment so frontend can distinguish "no data" from "0% CPU"
- Devices without polling data now show "No data" with diagnostic tooltip instead of ambiguous "-"
- Added `status_time` to enrichment for last-polled timestamp visibility on hover

## [0.10.28] - 2026-03-02

### Added
- Auto-detect IPsec VPN connections between devices by matching tunnel remote IPs to known device addresses
- New `AutoDetected` and `TunnelNames` fields on DeviceConnection model
- Database methods: `GetAllLatestVPNStatuses`, `FindConnectionByDevicePair`, `UpsertAutoConnection`
- Poller `detectVPNConnections()` runs after each poll cycle to upsert auto-detected connections
- Connections table: new "Tunnels" column, AUTO badge for auto-detected entries, "Auto-managed" label instead of delete button
- Network diagram: dashed lines for auto-detected connections, tunnel name tooltips on hover

## [0.10.27] - 2026-03-02

### Fixed
- **CPU/Disk detection on 2/3 firewalls**: Added required `.0` instance suffix to all 9 FortiGate scalar OIDs — SNMP GET responses include `.0` in PDU names, so switch cases in `ParseSystemStatus()` were never matching
- **Flows page loads empty**: Added `autocomplete="off"` to Src/Dst IP filter inputs to prevent browser autofill from injecting email addresses into query params

### Added
- **Hardware sensor collection in server poller**: Locally-polled devices (no probe assigned) now collect hardware sensor data via SNMP, matching what the collector/probe already does
- **Processor/SPU monitoring**: New `ProcessorStats` model and full pipeline — walks FortiGate `fgProcessorTable` to collect per-core CPU and NP/SPU ASIC usage; new Processors tab on device detail page with visual bar charts
- **VPN diagnostic logging**: Poller now logs "VPN: 0 tunnels" vs "VPN walk error" to help distinguish no-tunnels-configured from SNMP failures

### Changed
- **Data cleanup**: `CleanupOldData()` now also prunes old `processor_stats` and `hardware_sensors` records (>90 days)
- **Device deletion**: Cascade delete now includes `processor_stats` table

## [0.10.26] - 2026-03-02

### Added
- **Multi-vendor SNMP architecture**: New `VendorProfile` interface and registry (`internal/snmp/vendor.go`) enabling vendor-specific SNMP OID handling; FortiGate profile (`vendor_fortigate.go`) is the first implementation
- **Vendor field on devices**: `Device` model now has a `vendor` field (default: `fortigate`); existing devices are backfilled on startup; API validates vendor on create/update (fortigate, paloalto, cisco_asa, generic)
- **Vendor dropdown in admin UI**: Device add/edit modal now includes a vendor selector
- **Flow time range selector**: Flows page now has Today/1 Week/1 Month/1 Year buttons for stats and charts
- **Expanded protocol names**: Frontend and backend now recognize 22 protocols (added HOPOPT, IGMP, IPv4, EGP, IPv6, IPv6-Route, IPv6-Frag, ICMPv6, IPv6-NoNxt, IPv6-Opts, EIGRP, PIM, VRRP, SCTP, MPLS-in-IP)
- **More flow filter options**: Protocol dropdown now includes ICMPv6, GRE, ESP, OSPF

### Fixed
- **Dashboard syslog/trap counts**: Now uses `/api/syslog/stats` and `/api/traps/stats` for real totals instead of capped `?limit=10` array length
- **Top talkers chart unreadable**: Y-axis and tooltips now format bytes as human-readable (KB/MB/GB)
- **Disk gauge 0/0 confusion**: Device detail page shows "N/A" with dimmed gauge when device reports 0 usage and 0 total

### Removed
- **Recent Activity section**: Redundant dashboard section removed (syslog/traps pages provide better detail)

### Changed
- **SNMP refactoring**: FortiGate-specific OIDs moved from `snmp.go` to `vendor_fortigate.go`; `GetSystemStatus()`, `GetVPNStatus()`, `GetHardwareSensors()` now accept optional vendor parameter
- **Trap receiver**: Uses vendor profile registry to look up trap OIDs instead of hardcoded switch statements

## [0.10.25] - 2026-03-02

### Fixed
- **Interfaces nav item missing on standalone pages**: Added "Interfaces" link to sidebar navigation on probes, sites, network, and probe-pending pages
- **Alerts show DEV-{id} instead of device name**: `renderAlertsTable` now resolves device names from `currentDevices` cache via `getDeviceName()` helper
- **Debug console.log statements**: Removed all `console.log('[Sites]...')` (11 occurrences) and `console.log('[Pending]...')` (5 occurrences) from sites.html and probe-pending.html

## [0.10.24] - 2026-03-02

### Improved
- **Composite database indexes**: Added `(device_id, timestamp)` composite indexes to `system_status`, `vpn_status`, `hardware_sensors`, `trap_events`, and `alerts` tables for faster time-range queries; GORM AutoMigrate creates indexes on startup

## [0.10.23] - 2026-03-02

### Fixed
- **GetAllInterfaces pagination bug**: `ParsePagination` returns `(limit, offset)` but code treated them as `(page, pageSize)`; response now returns `limit`/`offset`/`total` instead of `page`/`page_size`
- **SSRF on TestWebhook**: User-supplied webhook URL now validated (scheme + hostname) via `isValidExternalIP` before making outbound HTTP request
- **SSRF on TestProbeConnection**: `ListenAddress` now validated via `isValidExternalIP` before `net.DialTimeout` to prevent internal port scanning
- **RegistrationKey leaked in probe responses**: `RedactProbe` now masks `RegistrationKey` with `********`
- **RedactDevice inconsistency**: SNMPv3 auth/priv passwords now masked with `********` instead of empty string
- **CSRF token values logged**: Middleware no longer logs full token values on mismatch, only lengths
- **Debug log statements in main.go**: Removed `DEBUG: Serving sites.html` and `DEBUG: Serving probe-pending.html` log lines
- **Poller full-row overwrite**: `updateDeviceStatus` now uses targeted `UpdateDeviceStatus(id, status, lastPolled)` instead of `db.Save(device)` which overwrote all columns
- **Dead VPN dashboard code**: Removed VPN summary block that wrote to `#trap-count` only to be immediately overwritten by trap count
- **CSRF token path mismatch in device-detail.html**: `loadStatusHistoryChart` no longer fetches/parses CSRF token redundantly for a GET request
- **Implicit `event` variable**: `testDeviceConnection` now receives `event` parameter explicitly; onclick passes `event`
- **TestEmail missing smtpFrom validation**: Now requires sender address in addition to host and recipient
- **Unbounded queries**: Added `Limit(2000)` to `GetSystemStatusHistory` and `Limit(100)` to device detail ping stats query

## [0.10.22] - 2026-03-02

### Added
- **Interface charts with downsampling**: Replaced tiny sparklines with full Chart.js charts (200px height) on device detail interface expand panel, with 24h/7d/30d/90d range selector buttons; backend uses AVG() aggregation with time-bucketed downsampling (per-minute, per-hour, per-day)
- **Admin "All Interfaces" page**: New cross-device interface overview at `/admin/interfaces` with device name column, device/status/type dropdown filters, and pagination; accessible from sidebar under Monitoring
- **Public multi-device support**: Device selector dropdown on public dashboard; new `/api/public/devices` endpoint returns enabled devices (id, name, status only); `GetPublicDashboard` and `GetPublicInterfaces` accept `?device_id=X` query param
- **SMTP settings in admin UI**: New SMTP Configuration card in Settings page with host, port, username, password, from address, and to address fields; settings stored in `system_settings` DB table
- **Email test button**: "Send Test Email" button in Settings sends a real SMTP test message using DB settings (falling back to env vars)
- **Webhook test buttons**: "Test Slack", "Test Discord", and "Test Webhook" buttons send test payloads to configured webhook URLs
- **Webhook URL field in settings**: Added `webhook_url` to notification settings UI (was previously env-var only)

### Improved
- **Composite database indexes**: Added `idx_iface_device_ts` on `(device_id, timestamp)` and `idx_iface_device_idx_ts` on `(device_id, index, timestamp)` to `interface_stats` table, eliminating full table scans for device detail and chart queries
- **Notification settings from DB**: `RefreshThresholds` in alerts.go now reads all notification keys (`email_enabled`, `smtp_*`, `slack_webhook`, `discord_webhook`, `webhook_url`) from DB, so admin UI changes take effect without server restart

## [0.10.21] - 2026-03-02

### Fixed
- **Interface names missing**: SNMP ifXTable walk now reads `ifName` (`.1.3.6.1.2.1.31.1.1.1.1`) and uses it to override the generic `ifDescr` value; on FortiGate devices, `ifDescr` returns generic descriptions while `ifName` returns the actual interface names (`port1`, `wan1`, etc.)

## [0.10.20] - 2026-03-01

### Fixed
- **PingStats not populated from probe data**: `ReceivePingResults` now aggregates each incoming ping result into `PingStats` (min/max/avg latency, packet loss, sample count), so the Ping tab on device detail shows actual data instead of "Awaiting ping data from probe..."
- **VLAN interface filter broken**: Changed VLAN filter from `vlan_id > 0` (Q-BRIDGE-MIB, unsupported on FortiGate) to matching `type_name === 'l2vlan' || type_name === 'l3ipvlan'`

### Added
- **Hardware sensor receive endpoint**: `POST /api/probes/:id/hardware-sensors` accepts sensor data from probes and saves to database, completing the hardware sensor pipeline so the Hardware tab shows actual sensor readings
- **Dynamic interface type filters**: Interface filter buttons are now generated dynamically from actual interface types present in the data (with counts), instead of hardcoded ethernet/tunnel/vxlan/lag/vlan buttons

## [0.10.19] - 2026-03-01

### Fixed
- **Password change error not shown**: Changed HTTP status from 401 to 403 when the current password is wrong during password change, preventing the frontend's session-expiry interceptor from silently redirecting to login instead of displaying the error message

## [0.10.18] - 2026-03-01

### Fixed
- **Chart.js blocked by CSP**: Added `https://cdn.jsdelivr.net` to Content-Security-Policy `script-src` directive so Chart.js CDN scripts load correctly on admin and device-detail pages

## [0.10.17] - 2026-03-01

### Fixed
- **Critical bug**: `UDPSyslogReceiver.Stop()` now correctly calls `running.Store(false)` instead of `running.Load()`, which caused the UDP read loop to continue indefinitely after stop
- **Thread safety**: `SFlowReceiver` changed from plain `bool` to `atomic.Bool` for the `running` field, preventing data races between Start/Stop/readLoop goroutines; added `sync.WaitGroup` for clean shutdown

### Refactored
- **Split `handlers.go`** (2,716 lines) into 10 domain-specific files: `handlers_auth.go`, `handlers_dashboard.go`, `handlers_devices.go`, `handlers_sites.go`, `handlers_connections.go`, `handlers_probes.go`, `handlers_settings.go`, `handlers_data.go`, `handlers_analytics.go`, plus the trimmed core `handlers.go`
- **New `internal/httputil/` package**: Shared handler helpers (`ParsePagination`, `ParseID`, `ParseHours`, `RequireDB`, `FilterAllowedFields`) and credential redaction (`RedactDevice`, `RedactDevices`, `RedactProbe`, `RedactProbes`) — eliminates ~200 lines of copy-paste across handlers
- **Notifier dedup**: Extracted `postJSON` helper in `internal/notifier/notifier.go`, replacing identical JSON POST logic in `sendSlack`, `sendDiscord`, and `sendWebhook`
- **Alerts dedup**: Extracted `checkThreshold` helper in `internal/alerts/alerts.go`, reducing 4 near-identical threshold check blocks in `CheckSystemStatus`
- **Database dedup**: Extracted `timeSeriesCount` and `groupByString` helpers in `internal/database/database.go`, deduplicating `GetAlertStats`, `GetTrapStats`, `GetSyslogStats`, and `GetDashboardTimeSeries`

## [0.10.16] - 2026-03-01

### Added
- **Chart.js integration**: All major pages now include interactive charts and graphs via Chart.js 4.4.7 CDN
- **Dashboard charts**: Activity trend line chart (syslog + traps + alerts per hour) and device status doughnut chart
- **Flows analytics**: Summary stat cards (total flows, bytes, unique sources/destinations), protocol distribution doughnut, top talkers bar chart, bytes-over-time line chart
- **Alerts overhaul**: Stat cards, alert trend line chart, alert type distribution doughnut, severity/acknowledged filters, per-alert acknowledge button, pagination
- **Traps overhaul**: Stat cards, trap frequency bar chart, severity distribution doughnut, severity/type filters, pagination
- **Syslog charts**: Stat cards, message trend bar chart, severity distribution doughnut
- **Device status history**: 24-hour CPU/memory/disk line chart on device detail page below gauge cards
- **VLAN interface filter**: New VLAN filter button on device detail interfaces tab (filters by vlan_id > 0)
- **6 new API stats endpoints**: `/api/flows/stats`, `/api/alerts/stats`, `/api/traps/stats`, `/api/syslog/stats`, `/api/dashboard/stats`, `/api/devices/:id/status-history`
- **Alert acknowledge endpoint**: `POST /api/alerts/:id/acknowledge`
- **Offset/pagination support**: Added offset query parameter to alerts, traps, syslog, and flows endpoints
- **Filtering**: Device ID and severity filters on alerts; severity and trap type filters on traps; device ID filter on flows

### Improved
- **Database layer**: 6 new aggregation methods for time-series stats (GetSystemStatusHistory, GetFlowStats, GetAlertStats, GetTrapStats, GetSyslogStats, GetDashboardTimeSeries)

## [0.10.15] - 2026-03-01

### Fixed
- **Test Device for probe-managed devices**: Test connection no longer fails with "Failed to poll device" for devices managed by a remote probe; instead returns an informational message explaining the probe polls the device automatically
- **Test Device error detail**: Connect and poll errors now include the actual error message instead of generic "Failed to connect/poll" text

### Improved
- **Device detail empty states**: System status, interfaces, VPN, sensors, and ping tabs now show "Awaiting data from probe…" when no data has arrived yet, instead of silent dashes
- **Alerts empty state**: Shows "No recent alerts — device is healthy" when alert list is empty

## [0.10.14] - 2026-03-02

### Fixed
- **Database migration crash on upgrade**: GORM AutoMigrate with SQLite fails with "table already exists" when adding new columns to existing tables; migration now runs per-model and logs warnings instead of crashing, so existing databases upgrade cleanly

## [0.10.13] - 2026-03-01

### Fixed
- **Docker compose**: Added `build: .` directive so `docker-compose up -d --build` rebuilds the image and detects changes without needing a separate `docker build` step

## [0.10.12] - 2026-03-01

### Added
- **Per-device SNMPv3 support**: Devices can now be configured with SNMPv3 credentials (username, auth protocol/password, privacy protocol/password) stored per-device rather than globally
- **SNMPv3 UI**: Device modal now includes SNMP version selector with conditional v3 fields (username, auth type, auth password, privacy type, privacy password)
- **Enhanced interface data collection**: Collects ifXTable data (ifAlias, ifHighSpeed, ifHCInOctets, ifHCOutOctets), ifMtu, ifPhysAddress (MAC), and Q-BRIDGE VLAN IDs from SNMP
- **Interface type names**: Maps IANA ifType values to human-readable names (ethernet, tunnel, vxlan, lag, loopback, etc.)
- **IPSec VPN tunnel polling**: New `GetVPNStatus()` SNMP method walks FortiGate VPN tunnel MIB for tunnel name, remote gateway, status, and byte counters
- **VPN data pipeline**: VPN statuses flow through poller, probe, relay, and API (`POST /api/probes/:id/vpn-status`)
- **Device detail page**: New `/admin/devices/:id` page with system status gauges (CPU/memory/disk), tabbed interface for interfaces, VPN tunnels, hardware sensors, alerts, and ping stats
- **Interface detail expansion**: Clicking an interface row expands to show full counters, VLAN ID, high speed, and a 24-hour sparkline chart
- **Interface history API**: `GET /admin/api/devices/:id/interfaces/:ifIndex/history?hours=24` returns time-series interface data
- **Device detail API**: `GET /admin/api/devices/:id/detail` returns comprehensive device info with latest system status, interfaces, VPN, sensors, alerts, and ping stats
- **Dashboard enrichment**: Dashboard API now returns per-device CPU, memory, sessions, interface up/down counts, and VPN tunnel summary
- **Device table columns**: Devices table now shows CPU, Memory, and Sessions columns with color-coded values
- **Alert persistence**: All alerts (CPU, memory, disk, session, interface down, VPN down, device offline) are now saved to the database
- **VPN down alert**: `VPN_TUNNEL_DOWN` critical alert fires when a VPN tunnel is detected as down
- **Device offline alert**: `DEVICE_OFFLINE` critical alert fires when the poller marks a device offline
- **Device name links**: Device names in the admin table are now clickable links to the device detail page

### Fixed
- **Probe-assigned devices marked offline**: Server poller no longer polls devices that have a `ProbeID` set — those are polled by the remote probe instead
- **Probe data doesn't update device status**: `ReceiveSystemStatuses` and `ReceiveInterfaceStats` handlers now mark devices as online with updated `last_polled` timestamp when probe data arrives
- **Alerts missing DeviceID**: All alert checks now set `DeviceID` on generated alerts and use per-device cooldown keys to avoid cross-device cooldown conflicts
- **Alerts not persisted**: `AlertManager` now accepts a database reference and calls `SaveAlert()` for every generated alert

### Changed
- **AlertManager constructor**: `NewAlertManager()` now takes a `*database.Database` parameter (nil-safe for trap-receiver)
- **Dashboard API format**: `GetDashboardAll` response now includes `enrichments` map alongside `dashboard` data

## [0.10.11] - 2026-03-01

### Changed
- **Admin UI consistency**: Unified sidebar design across all standalone pages (sites, network, probes, probe-pending) to match admin.html's GitHub-dark theme — 240px flex sidebar with section headers, icons, and grouped navigation
- **CSS class unification**: Replaced `.status-badge` with `.badge` and `.btn.small` with `.btn.sm` across all standalone pages for consistent styling with admin.html
- **Color palette alignment**: Changed body text from `#fff` to `#c9d1d9`, header accent from `#00d4ff` to `#58a6ff`, and active nav style to use `rgba(56,139,253,0.15)` across all admin pages
- **network.html legacy rename**: Renamed `.firewall-node`/`.firewall-name`/`.firewall-ip` CSS classes to `.device-node`/`.device-name`/`.device-ip`, changed "Firewall Details" → "Device Details" and "Firewalls:" → "Devices:"

### Fixed
- **Login redirect**: Changed post-login redirect from `/admin/dashboard` to `/admin` for cleaner URL

## [0.10.10] - 2026-03-01

### Fixed
- **Ping destination unreachable**: `Ping()` now returns `fmt.Errorf("destination unreachable")` instead of stale nil error, which caused unreachable hosts to be reported as successful

## [0.10.9] - 2026-03-01

### Fixed
- **Syslog TCP read deadline**: Moved `SetReadDeadline` inside read loop so it resets per-read instead of expiring 60s after connection start
- **Syslog TCP IPv6 source IP**: Use `net.SplitHostPort()` instead of `strings.LastIndex(":")` which breaks on IPv6 addresses

## [0.10.8] - 2026-03-01

### Fixed
- **Site DB race condition**: Added `sync.RWMutex` to protect `siteDBConnections` map — concurrent access would crash with map corruption
- **Site DB connection leak**: `GetOrCreateSiteDB` now properly closes the connection if `db.DB()` fails after `gorm.Open` succeeds
- **Site DB deletion leak**: `DeleteSiteDatabase` now closes cached DB connection before removing the file
- **GetProbeStats error handling**: All four `Count()` queries now check for errors instead of silently returning zeros

## [0.10.7] - 2026-03-01

### Fixed
- **Syslog ParsePriority**: Rewrote to parse full `<NNN>` priority format (e.g. `<134>` → facility 16, severity 6) instead of only single-digit priorities 0–9
- **Relay sendBatch body leak**: Changed `defer resp.Body.Close()` inside retry loop to direct close, preventing response body accumulation on retries
- **Heartbeat endpoint security**: Added probe existence check — unknown probe IDs now return 404 instead of silently updating
- **GetProbeDevices security**: Added `validateProbe()` call so unapproved or nonexistent probes cannot enumerate devices

## [0.10.6] - 2026-03-01

### Changed
- **Full vendor-agnostic rebrand**: Renamed all "FortiGate" references to generic "Device" terminology throughout models, API routes, handlers, database, config, UI, and deployment files
- **Go module rename**: `fortiGate-Mon` → `firewall-mon`
- **Model renames**: `FortiGate` → `Device`, `FortiGateTunnel` → `DeviceTunnel`, `FortiGateConnection` → `DeviceConnection`, `SiteFortiGate` → `SiteDevice`
- **DB table renames**: `fortigates` → `devices`, `fortigate_tunnels` → `device_tunnels`, `fortigate_connections` → `device_connections`, `site_fortigates` → `site_devices`
- **API route renames**: `/api/fortigates` → `/api/devices`
- **JSON field renames**: `fortigate_id` → `device_id`, `source_fg_id` → `source_device_id`, `dest_fg_id` → `dest_device_id`, `fortigates` → `devices`
- **Config field renames**: `FortiGateHost`/`FortiGatePort` → `SNMPHost`/`SNMPPort`, env vars `FORTIGATE_HOST` → `SNMP_HOST`, `FORTIGATE_SNMP_PORT` → `SNMP_PORT`
- **Binary renames**: `fortigate-api` → `fwmon-api`, `fortigate-poller` → `fwmon-poller`, `fortigate-trap` → `fwmon-trap`, `fortigate-probe` → `fwmon-probe`
- **Docker renames**: service/image/container `fortigate-mon` → `firewall-mon`
- **Default paths**: `/data/fortigate.db` → `/data/firewall-mon.db`, `/etc/fortigate-mon/` → `/etc/firewall-mon/`, `/var/lib/fortigate-mon/` → `/var/lib/firewall-mon/`
- **SNMP OIDs**: FortiGate-specific OID constants and vendor-specific trap logic remain unchanged with clarifying comments added
- **Note**: Pre-production DB migration — GORM AutoMigrate creates new tables but won't rename old ones; users should reinitialize

## [0.10.5] - 2026-03-01

### Added
- **Probe data ingestion endpoints**: Server now accepts data from probes via `POST /api/probes/:id/{syslog,traps,flows,pings,system-status,interface-stats}` — probes no longer get 404 when relaying data
- **FlowSample model & DB methods**: Full GORM model for sFlow data with `SaveFlowSamples()`, `GetFlowSamples()`, AutoMigrate, and cleanup
- **FortiGate-to-Probe assignment**: `ProbeID` field on FortiGate model allows assigning devices to specific probes for SNMP polling
- **TrapEvent ProbeID**: Trap events now track which probe sent them
- **Probe device endpoint**: `GET /api/probes/:id/devices` lets probes fetch their assigned FortiGates with SNMP credentials
- **Probe SNMP polling**: Probe now fetches assigned devices every 5 minutes and polls each via SNMP every 60 seconds, relaying SystemStatus and InterfaceStats back to server
- **Admin syslog page**: New `/admin/syslog` page with filters (probe, device, severity, text search), expandable messages, pagination, and auto-refresh toggle
- **Admin flows page**: New `/admin/flows` page with filters (probe, protocol, src/dst IP) and pagination
- **Admin probe stats endpoint**: `GET /admin/api/probes/:id/stats` returns syslog/trap/flow/ping counts per probe
- **Admin syslog/flows API endpoints**: `GET /admin/api/syslog` and `GET /admin/api/flows` with query filtering
- **Dashboard probe health cards**: Each probe shows name, site, status (animated pulse dot), last seen, and data counts
- **Dashboard recent activity feed**: Combined syslog + trap events sorted by timestamp
- **Device form probe/site dropdowns**: Add/edit device modal now includes Probe and Site selection
- **Device table columns**: Probe and Site columns shown in device list with preloaded data

### Changed
- **Admin UI overhaul**: Redesigned sidebar with sectioned navigation (Monitoring, Data, Infrastructure), stat cards on dashboard, improved typography and spacing
- **Body size limit**: Increased from 1MB to 5MB to handle syslog/sFlow batch submissions
- **GetAllFortiGates/GetFortiGate**: Now preload Site and Probe associations
- **UpdateFortiGate**: Allowed fields now include `probe_id` and `site_id`
- **Styling**: Animated pulsing status dots, color-coded severity badges, monospace font for IPs, sticky table headers, page transition animations, expandable syslog messages

## [0.10.4] - 2026-02-28

### Fixed
- **404 on /admin/devices**: Added missing route so navigating directly to `/admin/devices` works
- **URL-based tab activation**: Navigating to `/admin/devices`, `/admin/connections`, or `/admin/settings` now activates the correct tab in the SPA instead of always showing dashboard

## [0.10.3] - 2026-02-28

### Fixed
- **Broken probe registration flow**: `CreateProbe` now creates the `SystemSetting` entry that `RegisterProbe` expects, so remote probes can actually register
- **Duplicate probe on registration**: `RegisterProbe` now links to the existing admin-created probe instead of creating a duplicate with an auto-generated name
- **Probe auto-approval**: When a remote probe registers with an admin-created key, it is automatically approved and set online

### Added
- **Regenerate registration key**: New endpoint `POST /api/probes/:id/regenerate-key` lets admins regenerate a lost key (old key is immediately invalidated)
- **Deploy Instructions modal**: After creating a probe, shows copy-paste-ready environment variables (`PROBE_NAME`, `PROBE_SITE_ID`, `PROBE_REGISTRATION_KEY`, `PROBE_SERVER_URL`) for the remote machine
- **Deploy Info button**: Each probe in the table has a "Deploy Info" button to retrieve deployment instructions at any time

### Changed
- **Simplified Add Probe form**: Removed technical deployment fields (Listen Address, Listen Port, Server URL) that belong on the remote machine, not in admin config
- **Cleaner probe table**: Replaced Listen Address and Registration Key columns with Approval status column; shows description inline under probe name
- **Filter tabs**: Now filter by approval status (pending/approved/rejected) instead of connection status

## [0.10.2] - 2026-02-28

### Fixed
- **CSRF token reliability**: Replaced fragile cookie-based CSRF token reading with server-side `/admin/api/csrf-token` endpoint across all admin pages (admin, sites, probes, network, probe-pending)
- **Logout button broken on sites and probe-pending pages**: Changed from dead `<a href="/admin/logout">` link (GET to non-existent route) to proper JS-driven POST to `/admin/api/logout`
- **CSRF debug logging**: Added server-side logging when CSRF validation fails showing token lengths and values for diagnosis

### Improved
- **Full world coverage for sites**: Expanded country dropdown from 11 to 140+ countries organized by geographic region (Americas, Europe, Middle East, Africa, Asia, Oceania)
- **Comprehensive region list**: Expanded from 7 to 24 regions covering all continents
- **Complete timezone coverage**: Expanded from 16 to 100+ IANA timezones covering every UTC offset worldwide

## [0.10.0] - 2026-02-28

### Added
- **Probe Approval System**: Approve/reject workflow for probes before they can send data
- **Probe Registration**: Unique registration key for probe authentication
- **Probe Relay Client**: Client that collects all data and forwards to central server
- **Probe Command**: New `cmd/probe` for running probe collectors at remote sites
- **Per-Site Databases**: Database-per-site architecture for easier device cleanup
- **Probe Heartbeat**: Track probe online/offline status
- **Server URL**: Default set to stats.technicallabs.org

### Admin UI
- **Probes Page**: Full CRUD, approval actions, registration key management
- **Sites Page**: Tree view of hierarchical sites with firewall/probe listing
- **Network Diagram**: Visual SVG-based network topology
- **Pending Approvals Page**: Dedicated page for approving/rejecting probes

### Configuration
- PROBE_NAME, PROBE_SITE_ID, PROBE_REGISTRATION_KEY (required for probe)
- PROBE_SERVER_URL (default: https://stats.technicallabs.org)

## [0.9.0] - 2026-02-28

### Added
- **Site Model**: Hierarchical location support with parent-child relationships (Region > Data Center > Rack)
- **Probe Model**: Distributed collector architecture for multi-location monitoring
- **Probe API Endpoints**: Full CRUD operations for probe management
- **Site API Endpoints**: Full CRUD operations for site management
- **FortiGate-Site Linking**: FortiGate model now supports SiteID for organization
- **TLS/mTLS Support**: Configuration for secure probe-to-server communication
- **ICMP Ping Collector**: Active ping monitoring with latency tracking and statistics
- **Syslog Receiver**: RFC 5424 compliant syslog collection (UDP/TCP/TLS)
- **sFlow Receiver**: Basic sFlow v5 skeleton for flow sampling
- **Network Diagram Support**: Connection tracking between firewalls enhanced

### Configuration
- New `ProbeConfig` section with:
  - `PROBE_SERVER_ENABLED` - Enable probe mode
  - `PROBE_LISTEN_ADDRESS/PORT` - Local listener config
  - `PROBE_SERVER_URL` - Central server URL
  - `PROBE_TLS_ENABLED` / `PROBE_MTLS_ENABLED` - TLS options
  - `PROBE_ICMP_ENABLED` - ICMP ping toggle
  - `PROBE_SYSLOG_ENABLED` / `PROBE_SYSLOG_PORT` - Syslog config
  - `PROBE_SFLOW_ENABLED` / `PROBE_SFLOW_PORT` - sFlow config

## [0.8.8] - 2026-02-28

### Added
- **SNMPv3 support**: Full USM security with auth (MD5/SHA/SHA224-512) and privacy (DES/AES/AES192/AES256) protocols via `SNMP_V3_*` env vars

### Security
- Stored XSS fix: settings values escaped with `escapeHtml()` in admin UI form inputs
- SNMP community string redacted in `CreateFortiGate` and `UpdateFortiGate` responses
- `GetSettings` masks `IsSecret=true` values as `"********"`
- `UpdateSettings` validates value types: numeric ranges for thresholds, booleans for toggles, minimum 5 for refresh interval
- Rate limiter bypass fixed: `SetTrustedProxies(nil)` prevents `X-Forwarded-For` spoofing
- `ChangePassword` no longer triggers login rate-limiter lockout (uses `CheckPassword` directly)
- `CurrentPassword` length capped at 1024 bytes in `ChangePassword`
- Username length capped at 255 characters in login to prevent map/DB bloat
- User-Agent truncated to 512 characters before storage
- `Referrer-Policy: strict-origin-when-cross-origin` header added
- `Cache-Control: no-store` header added to prevent caching of authenticated responses
- Password form fields have proper `autocomplete` attributes

### Fixed
- `ProcessTrap` now uses cooldown to prevent notification floods from trap storms
- Alert notification failure no longer aborts remaining alerts in the same cycle (logs error, continues)
- Trap OID loop breaks on first match instead of silently overwriting with last varbind
- `parseTrap` returns nil when no FortiGate trap OID matches (prevents empty trap objects)
- Bare type assertions in `UpdateFortiGateConnection` replaced with safe two-value form

## [0.8.7] - 2026-02-28

### Security
- Logout endpoint moved inside CSRF-protected admin group (`POST /admin/api/logout`)
- Request body size limit middleware (1MB) prevents memory exhaustion via oversized JSON
- `MaxHeaderBytes` (64KB) set on HTTP server to limit header-based DoS
- Login attempts map periodically pruned (10-minute ticker) to prevent unbounded memory growth

### Fixed
- **Admin settings now applied at runtime**: `AlertManager.RefreshThresholds()` reads threshold settings from DB before each poll cycle, making admin UI changes effective without restart
- Trap OID prefix includes leading dot (`.1.3.6.1.4.1.12356.101.2.0`) to match gosnmp output format
- `GetHardwareSensors` now parses sensor name, value, and alarm status from FortiGate HW sensor sub-OIDs instead of returning empty structs
- Admin HTML logout button uses `apiFetch` with CSRF token instead of plain `fetch`

## [0.8.6] - 2026-02-28

### Security
- Login-specific rate limiter (1 req/s, burst 5) added to `/api/auth/login` endpoint
- Email subject headers sanitized to prevent header injection via alert fields
- Module-level `defaultPassword` variable cleared after config load
- Auth cookie `MaxAge` synced with JWT `TokenExpiry` config (was hardcoded 86400s)

### Fixed
- OID prefix collision: `HasPrefix` checks now use OID+`"."` to prevent `.2` matching `.20`
- Type assertions in `ChangePassword` use two-value form (prevents panic on invalid session data)
- `DeleteFortiGateConnection` checks `RowsAffected` and returns 404 when connection not found
- `UpdateFortiGateConnection` validates source and dest won't be the same device after update
- SNMP port range validated in `NewSNMPClient` (rejects port < 1 or > 65535)

### Removed
- Unused `GetRealIP` middleware (blindly trusted `X-Real-IP`/`X-Forwarded-For` headers)
- Unused `CORSMiddleware` function
- Unused `AlertManager` and `Notifier` creation in API server (alerts are handled by poller)

### Changed
- Alert cooldown map pruning now runs periodically in poller cleanup ticker

## [0.8.5] - 2026-02-28

### Security
- Login handler rejects passwords >1024 chars to prevent bcrypt CPU exhaustion DoS
- SSRF fix: `isValidExternalIP` now resolves hostnames and validates all resolved IPs (blocks DNS rebinding)
- SNMP community strings redacted in `GetDashboardAll` response (was only redacted in `GetFortiGates`)
- Logout requires valid `auth_token` cookie before clearing session (prevents cross-origin logout)
- Removed untrusted `GetRealIP` middleware that blindly trusted `X-Real-IP`/`X-Forwarded-For` headers
- Rate limiter cleanup goroutine now stoppable via channel (prevents goroutine leak)
- Login attempts map entries deleted when empty (prevents unbounded memory growth from username spraying)

### Fixed
- SNMP OIDs for ifOutUcastPkts/NUcastPkts/Discards/Errors corrected (were off by one, producing wrong interface stats)
- `getIndexFromOID` returns -1 on parse failure instead of 0 (no longer collides with valid index 0)
- `formatNumber(0)` now displays `0` instead of `--` on public dashboard
- Double refresh timer eliminated on public dashboard (settings timer replaces default)
- `UpdateSettings` reports errors to client instead of silently continuing with "Settings updated"
- `CreateFortiGate` defaults SNMP port to 161 when 0 (prevents invalid port 0 in database)
- `CreateFortiGateConnection` validates SourceFGID/DestFGID exist and are different
- `UpdateFortiGateConnection` validates FK references when source/dest IDs are changed
- `DeleteFortiGate` cascades delete to all related records (SystemStatus, InterfaceStats, VPN, HA, sensors, alerts, uptime, traps)
- `GenerateSecureToken` computes correct random byte count for any output length (prevents potential panic)
- Uptime baseline directory created with 0700 permissions (was 0755)
- Trap receiver stores `addr.IP.String()` instead of `addr.String()` (removes port from stored IP)
- `SystemStatus.ToJSON()` returns `{}` on marshal error instead of empty string
- Alert cooldown map pruning added to prevent unbounded growth

### Added
- AlertManager integrated into poller: threshold alerts and interface-down alerts now fire on each poll
- Concurrent device polling with semaphore (max 5 simultaneous SNMP connections)

## [0.8.4] - 2026-02-28

### Security
- SSRF prevention: IP validation blocks loopback, unspecified, and link-local addresses in TestDevice and CreateFortiGate
- Input validation for `UpdateFortiGate`: validates `snmp_port` range, `ip_address` format, and `enabled` boolean type
- Required field validation for `CreateFortiGate` (name and IP address)
- SNMP community string validated on incoming traps (rejects mismatched community)
- HSTS header only sent over TLS connections (prevents issues with plain HTTP setups)
- Database directory created with 0700 permissions instead of 0755
- 72-character max password length enforced (bcrypt limit)
- `SameSite=Strict` on auth and CSRF cookies via `http.SetCookie`
- SNMP community strings redacted in `GetFortiGates` API response
- Status enum validation for connection updates (only `unknown`, `up`, `down` allowed)
- Plaintext admin password cleared from config memory after hashing

### Fixed
- Database initialization is now fatal in both API server and poller (prevents nil pointer panics)
- Login handler nil-deref guard when database unavailable for admin lookup
- `generateRandomPassword` exits on `crypto/rand` failure instead of nil pointer panic
- `CalculateFiveNines` target downtime corrected from 3.1536 to 315.576 seconds/year
- `updateDeviceStatus` errors now logged in poller
- Admin initialization logs when admin already exists instead of silently skipping
- Env file parser strips surrounding quotes from values (single and double)

### Added
- Periodic data cleanup in poller (removes data older than 90 days, runs daily)

## [0.8.3] - 2026-02-28

### Security
- CSRF tokens are now HMAC-signed and tied to auth session (replaces double-submit cookie)
- `GetAdminByUsername` now queries by username parameter instead of returning first admin
- Admin password no longer logged in plaintext at startup (printed once to stderr only)
- Error messages from SNMP test connections are sanitized (no internal error leaks)
- Port range validation added for SNMP test device endpoint

### Fixed
- `ChangePassword` uses actual admin ID from JWT claims instead of hardcoded ID=1
- `Login` uses actual admin ID from database for JWT token generation
- SQLite `MaxOpenConns` set to 1 with WAL mode to prevent "database is locked" errors
- SNMP `Close()` guards against nil `Conn` to prevent panic
- `AdminAuth` middleware returns 401 JSON for API routes instead of HTML redirect
- `UpdateFortiGate` and `UpdateFortiGateConnection` return fresh data after update
- `snmp_version` added to allowed fields for FortiGate updates
- Alert cooldown keys no longer include metric values (cooldown now works correctly)
- Email notifications include proper MIME headers (From, To, Content-Type)
- `FormatUptime` uses `uint64` arithmetic to prevent int overflow on 32-bit systems
- Uptime percentage capped at 100% and guarded against uint64 underflow
- `HashPassword` error is now fatal at startup instead of silently ignored
- Poller polls immediately on startup instead of waiting for first interval
- `loadEnvFile` errors are now logged to stderr
- Removed duplicate `saveBaseline` method in uptime tracker

## [0.8.2] - 2026-02-28

### Security
- Removed hardcoded JWT fallback secret key; JWT now fails without configured secret
- Removed hardcoded CSRF fallback token; CSRF generation now fails safely on error
- Removed all debug log lines that leaked usernames, JWT secrets, and config state
- Password change now validates current password before allowing update
- Added minimum 8-character password requirement server-side
- Sanitized error messages to avoid leaking internal DB errors
- Removed panic recovery blocks that silently swallowed errors
- Login lockout now properly expires after configured duration (default 15 min)
- Uses bcrypt cost from config instead of hardcoded default
- JWT token validation now checks signing method
- Default admin password is now randomly generated on first startup (logged to console)
- Per-IP rate limiting replaces global rate limiter to prevent single-IP abuse

### Fixed
- Public dashboard falls back to database when SNMP is unavailable (no more 503)
- Public interfaces endpoint falls back to database when SNMP is unavailable
- Admin dashboard falls back to database when SNMP is unavailable
- FortiGate deletion is now transactional (tunnels, connections, device)
- Connection update now accepts `connection_type`, `notes`, and `status` fields
- FortiGateConnection model now has proper SourceFG/DestFG relation fields for Preload
- Poller now saves SystemStatus and InterfaceStats to database on each poll
- Fixed self-assignment bug in SNMP interface stats
- Fixed admin checkbox settings using `input.checked` instead of `input.value`
- Fixed settings loading for checkbox display (checked attribute)
- Fixed footer year to use dynamic `new Date().getFullYear()`
- Admin sidebar title changed from "FortiGate Admin" to "Firewall Monitor"
- Removed incorrect "restart container" message from password change
- Admin dashboard auto-refreshes every 30 seconds

### Added
- Admin-configurable public display settings (show/hide hostname, uptime, CPU, memory, sessions, interfaces)
- Configurable public dashboard refresh interval
- `GET /api/public/display-settings` endpoint for public display config
- `GET /admin/api/display-settings` endpoint for admin display config management
- `GetLatestSystemStatus()` and `GetLatestInterfaceStats()` database helpers
- Error handling with 401 redirect for failed admin API calls

### Changed
- Moved `glebarez/sqlite` and `gorm.io/gorm` from indirect to direct dependencies
- Removed unused `mattn/go-sqlite3` and `gorm.io/driver/sqlite` dependencies

## [0.8.1] - 2026-02-25

### Fixed
- Login 500 error: Improved password validation logic in auth.go
- CSRF validation failed: Changed csrf_token cookie to be accessible by JavaScript (HttpOnly: false)
- CookieSecure default: Changed default from true to false to allow HTTP login

## [0.8.0] - 2026-02-25

### Added
- Public dashboard with system status
- Admin panel with authentication
- FortiGate device management
- Connection tracking
- Alert management
- Uptime tracking with 99.9% calculation
- SNMP monitoring
- Email/Slack/Discord notifications
