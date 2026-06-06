# Firewall-Mon Audit-Resolution Handoff

**Written:** 2026-06-03 (end of a multi-session audit-resolution effort)
**Source of truth:** `docs/AUDIT.md` (the original audit document, which has been
updated in lockstep with each resolved finding).

## Executive summary

The public-release audit at v0.10.239 produced **170 bug findings** (AUDIT-001
through AUDIT-170) and **89 feature recommendations** (AUDIT-F01 through F89).
After the audit-resolution effort through v0.10.319, **86 of the 170 bug
findings are resolved** and **0 are still in CRITICAL status**. (Session 15
reached 88, but v0.10.320 reverted AUDIT-066/067 → **86**.) Three production
hotfixes (v0.10.322–324, 2026-06-04) shipped outside the audit cadence — see the
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
> Audit work still resumes at **Session 16 (security-adjacent: AUDIT-017, 020,
> 018, 085, 042)**.

**Remaining scope:**

| Bucket | Count | Notes |
|---|---|---|
| **Resolved bug audits** | **86** | per the `docs/AUDIT.md` resolved table (`grep -c '^\| AUDIT-'`); 0 remain CRITICAL |
| **Open bug audits** | **84** | 170 total − 86 resolved |
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

## Remaining HIGH-priority bug audits (by session)

Sorted by recommended execution order. The "Defer reason" column is for
audits where a future commit can defer cleanly without an in-progress fix.

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

### Session 16: HIGH security-adjacent quick wins (S) — 5 audits

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-017 | Probe registration key stored in plaintext | M | Encrypt at rest using the existing `crypto.go` AES-256-GCM pattern. Big jump in security value. |
| AUDIT-020 | SSRF allowlist has DNS-rebinding TOCTOU | M | Resolve once, dial the captured IP. The fix is a 30-line refactor. |
| AUDIT-018 | Stale dependencies | M | `go get -u gin@1.10.x golang-jwt@5.2.2+ gosnmp@1.40+`. Run `govulncheck` in CI. Migrate off `thoj/go-ircevent`. |
| AUDIT-085 | Probe auth handler not transactional | S | Wrap in a single transaction. |
| AUDIT-042 | Relay client has no idempotency key | M | Add `X-Probe-Batch-ID` UUID. ~50 LOC. |

### Session 17: HIGH DB performance quick wins (S–M) — 8 audits

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

### Session 18: HIGH critical-feature quick wins (S–M) — 5 audits

| Audit | Title | Effort | Notes |
|---|---|---|---|
| AUDIT-040 | Two `cmd/api` instances → 2 IRC bots, 2× login lockout, 2× rate limit | L | Short-term: advisory-lock startup check. Long-term: move state to Postgres. |
| AUDIT-028 | `interface_stats` and `system_status` are not partitioned | L | Monthly partitions for both tables. Requires migration path. |
| AUDIT-006 | Batcher is not crash-durable and has a shutdown race | L | WAL+fsync+spill-to-disk. Already half-done (v0.10.257). |
| AUDIT-004 | No git tags, no CI, no release flow | L | Already half-done (v0.10.255: Makefile, ci.yml). Deferred: release.yml, goreleaser. |
| AUDIT-032 | `c.Request.Context()` is never passed to DB calls | L | **188 sites** to touch. The right approach is a middleware-injection wrapper, not a hand-edit. |

### Session 19: HIGH frontend polish (S) — 10 audits

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

### Session 20: HIGH docs (S) — 10 audits

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

### Session 21: HIGH test/CI (S–M) — 7 audits

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

### Session 22: HIGH testing — 5 audits (XS–S)

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

### Session 23: HIGH docs (S) — already done mostly

- AUDIT-111: No RUNBOOK.md / OPERATIONS.md (S)
- AUDIT-112: No `.well-known/security.txt` route (S)
- AUDIT-113: No "How to add a vendor" doc (S)
- AUDIT-114: README "Build" instructions may not work on fresh Ubuntu (M)
- AUDIT-115: `lessons.md` and `tasks/` should not be public (already done v0.10.275)
- AUDIT-117: covered above
- AUDIT-118: covered above

## 13 remaining MEDIUM-priority bug audits

Section starts at `docs/AUDIT.md:742`. Most are JS / frontend / accessibility.

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

## 12 remaining LOW-priority bug audits

Section starts at `docs/AUDIT.md:874`. Mostly cosmetic.

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
- `grep -c "^| AUDIT-" docs/AUDIT.md` — count of resolved audits in the table
  (currently **86**; should grow as the next session commits)
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
