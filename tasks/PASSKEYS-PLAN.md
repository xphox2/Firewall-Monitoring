# Passkey (WebAuthn) Login — Plan

Status: **v3 — decisions made 2026-09-30**, revised after two adversarial reviews (lockout,
wrong-user). No code written. Implementation starts only on explicit go-ahead.

## Goals and hard constraints

1. **No lockout.** No sequence of user, admin, config or deploy actions may leave an account —
   or the whole install — without a working way in.
2. **No wrong-user access.** A passkey assertion must only ever produce a session for the one
   account that registered that credential, only while that account is enabled, and only with the
   role that account holds at that moment.
3. Passkey login is an *additional* way in. Password (+TOTP if enabled) always keeps working.

## Current system (facts this plan depends on)

- Sessions: stateless HS256 JWTs (`internal/auth/auth.go:352`), no `jti`; revocation via per-user
  `admins.token_version`, checked every request, fail-closed (`auth.go:426-431`). Bumping it kills
  **every** session of that user, including the current one and any pending-TOTP token.
- Password login `Login` (`internal/api/handlers/handlers_auth.go:30`) → optional TOTP stage
  (`pending_2fa`, Stage=totp) rejected everywhere except `/api/auth/totp` (`middleware.go:312,337`).
- Users in `admins` (uint IDs, unique username, hard delete → usernames reusable, no rename).
- `/admin` chain: AdminAuth (JWT cookie **or** `Bearer fwm_` API token) → CSRF (skipped for API
  tokens) → audit → RequirePasswordChanged (skipped for API tokens) → RequireRole
  (`selfServiceRoutes` bypass role checks; POSTs default to operator) (`middleware.go:262-396`).
- `ChangePassword` requires `current_password` (`handlers_auth.go:231,271-339`).
- TOTP replay guard is in-memory, keyed by purpose (`auth.go:207-226`); login uses `"login"`.
- Login lockout: in-memory per `username:IP`; `SetTrustedProxies(nil)` → behind a proxy every client
  shares the proxy IP.
- Migrations: versioned, latest v69, **not transactional** (run then record, `migrations.go:159-169`);
  failure is fatal at startup (`database.go:330`) and the entrypoint then stops the stack.
- No FKs/cascades anywhere; test SQLite runs without `foreign_keys=ON`.
- Image: binary `./fwmon-api` (Dockerfile:22,39), builder `golang:1.25-alpine`, `go 1.25.13`.
  Postgres listens on the unix socket only; DB env (`DB_HOST=/run/postgresql`, `DB_PASSWORD`,
  `CONFIG_FILE`) is exported only inside `entrypoint.sh`, so a plain `docker exec` does not have it.
- Single API instance (advisory lock, `main.go:195-237`).

## Pre-existing defects fixed first (PR 1)

- **D1 (critical): user-1 admin fallback** (`handlers_auth.go:99-115`) — lookup failure after the
  password check mints an admin session for user 1 and skips TOTP. → 500, no session.
- **D5: empty role → admin** in `auth.go:54-59`, `handlers_auth.go:103,111` **and**
  `handlers_totp.go:~124-129`. → fail closed (v20 guarantees a non-null role, so this is safe).
- **D7: `DeleteAdmin` leaves recovery codes** (`sites_probes.go:276-283`) → delete in the same tx.
- **TOTP replay guard:** one shared purpose for every TOTP consumption (login, re-auth, disable),
  so a code used once cannot be replayed through a different endpoint.
- Extract `completeLogin(adminID, method)` used by password, TOTP and (later) passkey login.
  Tests prove password/TOTP behaviour is unchanged, and that a `completeLogin` failure after a
  recovery code is consumed is handled deliberately (test decides: accept loss vs. roll back).

## Chosen design: Option A — passkey as a full, usernameless login

Discoverable credential, user verification **required**, password(+TOTP) always retained.
(B = passkey only as second factor; C = passkey-only accounts. C is out of scope.)

### Library and toolchain
`github.com/go-webauthn/webauthn` — pre-1.0, minor versions break API; pin an exact version and
review MIGRATION.md on every bump. v0.18.1+ requires `go 1.26`; v0.18.0 is the newest on 1.25.
→ **Open decision D-LIB.**
Config must set `AuthenticatorSelection.UserVerification=required`,
`ResidentKey=required`, `AttestationPreference=none`, and `Timeouts.{Login,Registration}.Enforce=true`
with 5-minute timeouts (the library only enforces UV/expiry when these are set).

### Configuration and feature gate
- Env: `WEBAUTHN_ENABLED` (default `false`), `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS` (exact
  `https://host[:port]` list). RP ID defaults to the `PUBLIC_BASE_URL` host; recommend RP ID = the
  exact host (not a parent domain).
- Validation lives in a **separate non-fatal step**, not in `cfg.Validate()` (which `log.Fatalf`s).
  RP ID must be a DNS name (not an IP); origins https (or `http://localhost`) and within the RP ID.
  Invalid → passkeys disabled, loud log, server and password login start normally.
- `WEBAUTHN_ENABLED=false` = kill switch: UI hidden, passkey endpoints 404, stored credentials kept.
- RP ID/origins never derived from `Host` / `X-Forwarded-*`.
- Login page shows the passkey button only if `location.origin` is in the configured list.

### Ceremony state — in API memory, not the DB
Single API instance is enforced, so ceremonies live in a mutex-guarded in-process map:
TTL 5 min, hard cap (e.g. 1000 entries; oldest evicted), lazy expiry on every access. Consumed by
delete-under-lock → strictly single-use, including concurrent finishes. Restart just means "try
again". No DB growth from unauthenticated `begin`, no dependency on the poller's 24h sweep.
- **Login:** ceremony id (32 random bytes) in cookie `webauthn_login`, HttpOnly, SameSite=Strict,
  Secure per config, Path=`/api/auth/passkey`, Max-Age 300. Cleared on every finish outcome.
- **Registration:** keyed by the session's `admin_id` (at most one outstanding per user); no cookie
  needed. `finish` rejects unless a ceremony exists for the caller's `admin_id`.

### Schema (migration v70) — every statement idempotent
`IF NOT EXISTS` / guarded DDL (pattern of v19/v20, `migrate.go:2507,2531`), plus SQLite AutoMigrate
branch, plus a test that re-runs v70 against a partially-applied schema.
- `admins.webauthn_user_handle BYTEA UNIQUE NULL` — 64 bytes `crypto/rand`, set on first
  registration, never reused, never derived from username/ID.
- `webauthn_credentials`: `id`, `admin_id` (FK ON DELETE CASCADE as backstop), `credential_id BYTEA
  UNIQUE NOT NULL`, `public_key`, `attestation_type`, `aaguid`, `sign_count`, `backup_eligible`,
  `backup_state`, `transports`, `name`, `created_at`, `last_used_at`. Max 10 per user.
- `login_attempts.method` column (password|totp|passkey).
- `DeleteAdmin` deletes the user's credentials **explicitly in its transaction** (SQLite tests have
  no FK enforcement; the FK is only a backstop).

### Login (public: `/api/auth/passkey/login/{begin,finish}`, own `LoginRateLimiter()` instance)
1. `begin`: `BeginDiscoverableLogin` → store ceremony → set cookie. No username → no enumeration.
2. `finish`: consume ceremony by cookie id (missing/expired/wrong kind → generic failure).
3. `DiscoverableUserHandler(rawID, userHandle)`: credential by `rawID` → owner by `admin_id` →
   constant-time `stored_handle == userHandle` → owner disabled/missing → fail. The returned user's
   `WebAuthnID()` is the **stored** handle (the library re-checks it and credential membership,
   `login.go:337-358`).
4. Require UV on **this** assertion's flags. `CloneWarning` is not an error in the library → our code
   rejects, audits, and does not update the counter. Otherwise persist `sign_count`,
   `backup_state`, `last_used_at`.
5. `completeLogin(adminID, "passkey")`: re-read admin by ID (fresh `disabled`, `role`,
   `token_version`), error → 500, disabled/unknown role → generic failure, no TOTP stage (UV passkey
   = MFA), new JWT + CSRF cookie, clear `pending_2fa`, `login_attempts` row. `must_change_password`
   still enforced by middleware.

### Registration and management (session-only, CSRF-protected)
- All passkey routes return **403 unless `auth_method == "session"`** — API tokens can never
  register, list, rename or delete passkeys.
- Identity only from the session's `user_id`; account loaded **by ID**, never by username.
- Self-service routes (`/admin/api/passkeys/...`) go in `selfServiceRoutes` so every role can manage
  **their own** passkeys; every query is scoped `WHERE id=? AND admin_id=<session user>`.
- Admin action "remove all passkeys for user X" goes in `adminOnlyRoutes`. Role-matrix test extended.
- **Fresh re-auth** on register-begin, delete: current password via `CheckPassword` (not
  `ValidateCredentials`, so failures don't touch the login lockout) **+ TOTP code if enabled**
  (shared replay purpose), with a dedicated per-user limiter.
- Register-finish: reject duplicate `credential_id` (unique index is the backstop), UV=0, >10 keys;
  `excludeCredentials` = user's existing keys.
- Delete a passkey: bump `token_version` (kills every other session in case that key was
  compromised) **and re-issue the caller's session in the same response** so they stay logged in.
- After any new passkey registration: audit row + a visible notice on the next password login and
  on the profile page ("A passkey named X was added on <date>").

### Resets remove passkeys (closes the "rogue passkey outlives recovery" hole)
→ See **Open decision D-RESET.** Proposed: admin password reset, admin 2FA reset and `reset-auth`
always delete all passkeys; self-service password change offers "also remove all passkeys"
(default on).

### Break-glass: `fwmon-reset-auth` (works with no web UI)
- Shipped as a wrapper script in the image that sources the same DB env as `entrypoint.sh`
  (`/config/pg-credentials`, socket `DB_HOST=/run/postgresql`) and runs `./fwmon-api reset-auth`
  as the `fwmon` user.
- Documented command: `docker exec -it <container> fwmon-reset-auth --user <name>`.
- Default action: new random temporary password (printed once, `must_change_password=true`),
  clear 2FA and recovery codes, delete all passkeys, bump `token_version`, audit. Flags to keep 2FA or
  passkeys exist but are off by default.
- Prints: "restart the API container to clear in-memory login lockouts" (lockout is per process).
- **Tested inside the real container image in CI/staging**, not only against SQLite.

## Lockout analysis (v2)
| Scenario | Outcome |
|---|---|
| Lost passkey device | Password(+TOTP) still works; delete old passkey |
| Forgot password, still has passkey | Can log in, but **cannot** change password without it (by design). Admin reset or `fwmon-reset-auth` |
| Forgot password + lost passkey | Admin reset or `fwmon-reset-auth` |
| Sole admin locked out | `fwmon-reset-auth` via docker exec (tested in the real image) |
| Admin set must_change_password | User logs in with the temp password they were given, then changes it |
| Hostname/RP ID changes, IP access | Passkey button hidden / no match; password login unaffected |
| Bad WebAuthn config | Passkeys disabled + log; server starts normally |
| Library regression | `WEBAUTHN_ENABLED=false`, no data loss |
| v70 migration fails half-way | Idempotent statements → next boot completes it (tested) |
| API restart mid-ceremony | "Try again" |
| Deleting a passkey | Other sessions end; caller's session re-issued |
| Lockout-bucket DoS behind proxy (pre-existing D3) | Fixed in PR 1 via `TRUSTED_PROXIES`; restart API still clears buckets |
| Library needs newer Go | PR 0 upgrades Go 1.26 first; image must build in CI before merge |

## Wrong-user analysis (v2)
| Attack | Mitigation |
|---|---|
| Replay assertion/challenge | In-memory single-use ceremony, cookie-bound, 5-min server expiry; constant-time challenge compare (library) |
| Assertion mapped to wrong account | Credential id → owner by ID → constant-time stored-handle match; library re-checks |
| Deleted user / username reuse | Credentials deleted in `DeleteAdmin` tx; new account gets a new random handle |
| Register key onto victim account | Session-only, CSRF, fresh password+TOTP, identity from session `user_id`, ceremony keyed by `admin_id` |
| API token used to register/manage | 403 unless `auth_method == session` |
| Operator deletes another user's key | Owner-scoped queries; admin-only bulk removal route |
| Phisher registers a rogue key with a stolen session | Needs password+TOTP again (single-use TOTP); new-key notice + audit; every reset deletes all passkeys |
| TOTP code replayed across endpoints | Shared replay purpose |
| Disabled / role-changed user mid-ceremony | `completeLogin` re-reads the row by ID; role/disable bump token_version |
| Cloned authenticator | Explicit `CloneWarning` reject + audit |
| Origin spoof | Static allow-list |
| Presence-only authenticator | UV required in config and checked per assertion |
| D1 user-1 fallback | Removed in PR 1 before any passkey code |

## Delivery plan
0. **PR 0 — toolchain:** Go 1.26 bump (go.mod, Dockerfile builder image, CI) on its own; full
   build/test/image build; no functional change.
1. **PR 1 — hardening:** D1, D5, D7, D3 (`TRUSTED_PROXIES`), shared TOTP replay purpose,
   `completeLogin` extraction, tests.
2. **PR 2 — backend:** v70 (idempotent), config + kill switch, in-memory ceremonies, login,
   registration, management, reset changes, `fwmon-reset-auth` + wrapper, audit. Default off.
3. **PR 3 — UI + docs:** login button, profile management + new-key notice, admin action,
   OPERATIONS.md (replace manual SQL), CHANGELOG.
4. **Rollout:** deploy with `WEBAUTHN_ENABLED=false`; run `fwmon-reset-auth` against a throwaway
   user in production to prove break-glass; enable; register from a second browser while an existing
   session stays open; verify login, delete, kill switch.
Each PR: CHANGELOG entry, `go build ./...`, `go test ./...`, image build, user-approved push.

## Tests (each must fail on revert — in-place revert/restore)
- D1 lookup failure → 500, no cookie. Empty role on password, TOTP and passkey paths → failure.
- TOTP code accepted at login is rejected at re-auth within the window.
- Discoverable handler: handle mismatch, A's credential + B's handle, disabled owner, deleted owner → fail.
- Ceremony: reuse, expiry, wrong kind, missing cookie, concurrent double-finish (exactly one wins), cap eviction.
- Registration: API token → 403; no/wrong re-auth → fail; ceremony for other admin_id → fail;
  duplicate credential id, UV=0, >10 → fail.
- Management: operator/viewer cannot touch another user's key; admin bulk removal is admin-only.
- Delete passkey: token_version bumped, caller still logged in.
- Resets delete passkeys (admin password reset, 2FA reset, reset-auth, self change with box ticked).
- Config: IP RP ID / bad origin → disabled, server starts, password login works; kill switch → 404.
- v70 re-run on partially-applied schema succeeds.
- `DeleteAdmin` removes credentials and recovery codes (SQLite and Postgres).
- `fwmon-reset-auth` in the real container image.
- Clone warning → reject + audit.

## Decisions (2026-09-30)
- **Approach:** Option A — full usernameless passkey login, UV required, password(+TOTP) retained.
- **D-LIB:** upgrade to **Go 1.26 first (PR 0)**, then pin go-webauthn **v0.18.2** exactly.
- **D-RESET:** admin password reset, admin 2FA reset and `fwmon-reset-auth` **always** delete all
  passkeys; self-service password change offers "also remove all passkeys", **ticked by default**.
- **D-D3:** fix trusted-proxy client IP **in PR 1**:
  - New `TRUSTED_PROXIES` (comma list of IPs/CIDRs), default empty = current behaviour
    (`SetTrustedProxies(nil)`), so nothing changes until the operator opts in.
  - When set: `SetTrustedProxies(list)`, `RemoteIPHeaders = ["X-Forwarded-For"]`; gin takes the
    right-most address not in the trusted list, so a client-supplied `X-Forwarded-For` from an
    untrusted peer is ignored.
  - Startup validation: unparseable entries → log and ignore that entry (never fatal).
  - Tests: spoofed XFF from an untrusted peer is ignored; XFF via trusted proxy yields the client
    IP; lockout buckets are per real client behind the proxy; empty setting = identical to today.
  - Document for nginx-proxy-manager in OPERATIONS.md (proxy's Docker network CIDR).

## Out of scope (tracked in tasks/todo.md)
D2 TOTP budget reset on password success, D4 re-auth rate limits on existing endpoints, D6
cookie Secure/HSTS behind proxy, D8 username-keyed lookups, D9 unauthenticated /metrics,
passkey-only accounts, attestation allow-lists, related origins.
