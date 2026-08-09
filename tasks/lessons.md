# Lessons

## When a bug report describes two visual states, the user is telling you which one they want (2026-07-09)

**Mistake:** user reported "switch to day mode, you will have a border on the graphs. Once it refreshes the border on the graph is lost." I diagnosed the inconsistency correctly (doughnut borders baked at chart build time, not repainted on theme toggle) but resolved it toward the state I judged design-consistent (invisible card-bg border) — the exact opposite of what they wanted. Shipped v0.11.64, got "you made it worse," shipped v0.11.65 to invert it.

**Rules:** (a) when a user describes a before/after visual change as a bug, the state they mention with detail or approval ("you will have a border") is almost always the DESIRED state, and the transition away from it is the complaint — fix toward it; (b) if both end states are plausible and the fix direction is a design judgment call, state the two options in one sentence and pick the user-described one as default, don't pick against the report; (c) "make it consistent" answers HOW but not WHICH — consistency toward the wrong state is still a regression in the user's eyes.

## A test session's deliverable includes the user's own post-publish checklist (2026-07-03)

**Mistake:** ran a thorough local walkthrough of Tranche 2, reported the results, and stopped. User: "you failed to outline all the changes I need to test once I publish." The verification I can do locally (synthetic feeds, no real PD/Opsgenie/SMTP, SSRF-blocked webhooks) is not the verification that matters to the operator — the deploy-and-confirm pass on prod is theirs, and they need the list.

**Rules:** (a) whenever a batch of features ships or gets validated, END with a concrete post-deploy checklist in `tasks/todo.md`: per feature, what to click/curl and what to expect; (b) explicitly flag the items local testing could NOT close (live channel deliveries, success-path side effects, real-data reports) — those are the prod checklist's priority items; (c) include the upgrade pre-flight (backup, key continuity, migration expectations) whenever prod lags by multiple migrations.

## Local functional testing runs against PostgreSQL, never SQLite (2026-07-03)

**Mistake:** planned a local feature walkthrough "with SQLite" because the unit tests use it. User: "why do you keep testing with SQLite instead of Postgres that we use?" The runtime binary is PG-only anyway (`database.NewDatabase` opens only `gorm.io/driver/postgres`, database.go:143; SQLite exists solely as the `!production` in-memory test helper in `internal/database/testing.go`) — and SQLite-green has lied before (FK enforcement, `to_char`, partitioning are PG-only).

**Rules:** (a) any local run of fwmon-api/poller/harness uses a real PostgreSQL 16 (prod's major version) — quickest recipe: `initdb` into a scratch dir, `pg_ctl -o "-p 5544 -c unix_socket_directories=''"` (TCP-only; macOS 103-byte socket-path limit trips on long dirs), `createdb`, then `fwmon-api migrate`; (b) SQLite is for `go test` only — never present it as "testing the server"; (c) two live-test constraints discovered 2026-07-03: the AUDIT-020 SSRF guard blocks webhook deliveries to loopback/private IPs with NO bypass (by design — live webhook tests need a public receiver or the on-the-wire unit tests), and `psql -c "STMT1; STMT2"` is one implicit transaction — an error in STMT2 silently rolls back STMT1 (a "committed" test fixture wasn't; verify with a separate `-c` SELECT). — `gh run watch --exit-status | tail` reported green on a RED run (2026-07-03)

**Mistake:** every CI watch used `gh run watch "$ID" --exit-status … | tail -3 && echo CI_GREEN`. The pipeline's status is tail's (always 0), so `CI_GREEN` printed even when the run FAILED. Master was red for two pushes (v0.10.568, v0.11.0 — Tailwind freshness gate) while I reported green, and Docker Hub publishing silently skipped both. Same failure family as the benchmark workflow's `go test | tee` mask fixed earlier the same day — the lesson didn't transfer to my own tooling.

**Rules:** (a) any command whose exit code matters must not end in a bare pipe — use `set -o pipefail` first, or capture the status explicitly; (b) after "CI green", verify the OUTCOME too when something depends on it (the publish run + Hub tags, not just the CI check); (c) when a gate exists for generated artifacts (tailwind.css freshness), regenerate after ANY edit to files it scans — login.html/admin.html class changes require `npm run tailwind`.

## Plan mode per feature — an approved program plan is not blanket execution authority (2026-07-03)

**Mistake:** after the v0.11 Tranche 1 plan was approved, I shipped Phase A, rolled straight into Phase B, and began Phase C without re-entering plan mode. User: "please make sure you are going into plan mode to plan each one do not just execute it live."

**Rules:** (a) every feature/phase of a multi-part program starts with its own plan-mode session and ExitPlanMode approval, even when the umbrella plan already sketched it; (b) the per-unit plan should be a short delta — what changed since the umbrella design, exact files, verification — not a re-derivation; (c) momentum after a green CI run is the trigger to watch for: finish the unit, report, then PLAN the next one.

## Answer the user's "why X vs Y" question before re-asking for the decision (2026-07-02)

**Mistake:** user asked "why ghcr vs. docker hub?"; I gave a generic trade-off list and immediately re-presented the same choice still recommending ghcr. User: "I asked this question and you ignored me."

**Rules:** (a) when the user questions a recommendation, answer that question anchored to THEIR existing setup, not a neutral comparison; (b) re-weigh the recommendation against infrastructure they already run — a working pipeline/registry/library is a strong prior that usually beats marginal generic advantages; (c) the wording of an old note ("ghcr publish" in a deferred-items list) is not a user decision — don't inherit requirements from phrasing.

## Inspect external PR commits for AI-attribution trailers BEFORE merging (2026-07-01)

**Mistake:** merged community PR #50 as a merge commit without reading the commit message body. The contributor's commit carried `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` (their Claude Code default), which put "Claude" back on the repo's contributors graph — something the maintainer had deliberately removed before. The only way to undo a contributor entry is a history rewrite + force push (done as a one-time maintainer-authorized exception, preserving the contributor's authorship).

**Rules:** (a) before merging any external PR, run `git log --format=%B <base>..<head> | grep -i 'co-authored\|claude\|generated with'` on the PR commits; (b) if a trailer is present, use **squash merge and hand-edit the squash message** to strip it (GitHub pre-fills co-author trailers into the squash body — they must be deleted manually) — never a merge/rebase merge, which preserves the original message verbatim; (c) this repo's no-AI-attribution policy applies to the full history, not just commits we author.

## Never round-trip a UTF-8 source file through PowerShell 5.1 Get-Content/Set-Content (2026-07-01)

**Mistake:** bumped the collector version with `(Get-Content -Raw) -replace ... | Set-Content -Encoding utf8`. PS 5.1 reads a BOM-less UTF-8 file as ANSI, so every non-ASCII character (comment arrows `→`, em-dashes) was double-encoded into mojibake — 38 corrupted lines were committed and pushed before `git show --stat` caught the oversized diff (build stayed green because only comments were hit).

**Rules:** (a) single-line edits in Go/source files use the Edit tool, never a PowerShell re-write of the whole file; (b) after any scripted file rewrite, run `git diff --stat` and treat a larger-than-expected line count as corruption until proven otherwise; (c) if PowerShell must write a file other tools read, remember `-Encoding utf8` writes a BOM in 5.1 (Go tolerates it, gofmt/gitignore diffs don't love it) — prefer `[System.IO.File]::WriteAllText` with explicit `UTF8Encoding($false)`.

## A "flaky" test that never goes green on rerun is a real bug — re-diagnose, don't keep rerunning (2026-06-23)

**Context:** `TestPostgresIntegration/PopulatedTableSkipped` was documented as an intermittent flake with the remedy "do a full `gh run rerun`, it usually goes green." By 2026-06-23 that remedy was stale: master had been red on the PG lane for 8+ consecutive runs and reruns never cleared it. The "flake" was a real, persistent **shared-database race** — `go test ./pkgA/... ./pkgB/...` runs the two package binaries concurrently, and both `NewIntegrationDB`s did an unsynchronized `DROP SCHEMA public CASCADE` on the same `TEST_PG_DSN`, so one process reset the other's in-flight migration. Nondeterministic *which* relation was reported missing (`schema_migrations` vs `system_status`) — the tell of a concurrency bug, not container timing.

**Rule:** the moment a "flake" stops being cleared by a rerun (say, 3+ consecutive failures of the same subtest), STOP rerunning and re-root-cause it. Treat "rerun fixes it" as a hypothesis with an expiry, not a standing instruction. A check that's red on master for days is a broken signal, not noise.

**Tells of a shared-resource test race (vs. timing flake):** (a) the *identity* of the missing/failing object changes run to run; (b) the failure tracks to a globally shared resource (one DB/file/port) touched by >1 concurrently-run test binary; (c) `go test` was given multiple packages in one invocation (it parallelizes package binaries by default). Fix with `-p 1` to serialize, or give each binary its own isolated resource. Don't reach for per-DB locks alone — the destructive reset often runs OUTSIDE the lock.

**Also:** when CI has a lane that's red on master yet PRs keep merging (as here, #30–#34), that lane is not a merge gate. Confirm which checks actually gate merges before treating a red X as blocking.

## ALWAYS verify CI on BOTH repos after every push (2026-06-11)

**Rule:** After every `git push` to either repo (Firewall-Mon or Firewall-Collector), I MUST verify the CI run for that push goes green, and if it fails, fix it before considering the task done. Don't push-and-forget.

How:
```
# after pushing, watch the run for the repo you pushed:
RUN_ID=$(gh run list --limit 1 --json databaseId -q '.[0].databaseId')
gh run watch "$RUN_ID" --exit-status --interval 15
# if it fails:  gh run view "$RUN_ID" --log-failed | grep -iE "FAIL|panic|error|\.go:[0-9]+:"
# Collector:    gh run list -R xphox2/Firewall-Collector --limit 3
```

**Why:** CI was silently red for ~5 commits (2026-06-09 → 2026-06-11) and nobody caught it. Two separate root causes bit us in one session — see below.

## "Docs-only" / CHANGELOG changes CAN break the build — run the FULL `go test ./...` before pushing (2026-06-11)

**Mistake:** I reformatted CHANGELOG.md, assumed "docs-only ⇒ tests can't break," ran only `gofmt`+`go build`, and pushed. CI went red.

**Root cause:** `internal/shell/` contains *static-file* tests that validate non-Go files. `TestChangelog_KeepAChangelogHeader_AUDIT110` parses CHANGELOG.md and FAILS if `## [Unreleased]` is not the first `## [...]` section. My per-version reformat moved version headers above `[Unreleased]` → red.

**Rule:** Before EVERY push, run `go test ./...` (not just build). The `internal/shell` package has ~25 static checks over CHANGELOG.md, entrypoint.sh, docker-compose, CODEOWNERS, etc. A change to ANY of those files — even "just docs" — can fail a test. There is no such thing as a push that's exempt from `go test ./...`.

## The local `go test ./...` does NOT run the Postgres integration lane — CI does (2026-06-11)

**Mistake:** `go test ./...` passed locally, so I assumed CI would pass. CI's `Integration (PostgreSQL)` job was red.

**Root cause:** Integration tests are behind `//go:build integration` and skip unless `TEST_PG_DSN` is set; the dev sandbox has no Postgres/docker. The specific failure: `setupProbeAndDevice` created a probe with `site_id=0`, violating the `fk_sites_probes` FK — **Postgres enforces FKs, the local SQLite default does not**. So FK / ON-CONFLICT / partition / `to_char` bugs are invisible locally and only surface in CI.

**Rule:** A green local `go test ./...` is necessary but NOT sufficient. After pushing, always confirm the CI `Integration (PostgreSQL)` job specifically. When writing/seeding test data that crosses a FK (probe→site, device→probe, etc.), set the FK to a real seeded row even if SQLite would tolerate `0`/NULL.

## Cross-repo CHANGELOG formats now match — both use per-version sections at top (2026-06-22)

- **Both repos**: per-version sections at the top, newest first. **No `[Unreleased]` accumulator.**
- **Server**: `## [X.Y.Z] - DATE` format. `TestChangelog_KeepAChangelogHeader_AUDIT110` (`internal/shell/changelog_audit110_test.go:24-25`) enforces the FIRST `## [...]` section must be a concrete version, NOT `## [Unreleased]`.
- **Collector**: `## X.Y.Z - DATE` format (no brackets). No static guard exists; convention only.

**The maintainer removed the original Keep-A-Changelog `[Unreleased]` convention on 2026-06-11** because it had drifted into a catch-all blob and diverged from the collector's format (see `CHANGELOG.md:277`). The earlier lessons.md entry that said "`[Unreleased]` MUST be the first section" was **wrong as of that date** and is replaced by this rule.

When bumping a version: open a new `## [X.Y.Z] - DATE` (or `## X.Y.Z - DATE`) section at the top. The server's AUDIT-110 test will fail if you (a) put `[Unreleased]` first, or (b) put a non-version `## [...]` section first.

## `TestPostgresIntegration/PopulatedTableSkipped` is flaky; do NOT panic on transient failure (2026-06-22)

**Context:** the audit follow-up (2026-06-22 session) shipped 5 PRs to the server repo. The Postgres `Integration (PostgreSQL)` CI lane flaked on `TestPostgresIntegration/PopulatedTableSkipped` 3 times during that session:

- Phase 3 (PR #1, v0.10.471, sampling_rate scaling): failed once, passed on retry with identical code.
- Phase 5 (PR #3, v0.10.473, drops field): failed on pre-merge (after gofmt amend) retry, then failed post-merge on master.

**The failure is unrelated to PR code.** It's the `runMigrationList([v1])` call inside `PopulatedTableSkipped`'s `DROP SCHEMA public CASCADE; CREATE SCHEMA public;` block failing with "relation schema_migrations does not exist" at the INSERT step — but the CREATE TABLE IF NOT EXISTS runs in the same function before the INSERT. The most likely cause is connection-pool staleness on the throwaway GORM connection that survives the DROP+CREATE.

**The rule for future runs:**

1. **Do not panic on a single PopulatedTableSkipped failure.** Treat the first failure as a flake candidate; retry before bisecting code.
2. **Pre-merge CI green = ship.** If the pre-merge CI is green for the PR's actual code, the post-merge master failure (when it's PopulatedTableSkipped) is almost certainly the same flake. The PR was correctly validated.
3. **Capture the flake in a lesson if it hits 3+ times in one session.** (This entry is itself the lesson.)
4. **If the post-merge master CI fails on the same flake, push an empty retrigger commit; if that passes, the PR is good.** Revert the empty commit before moving on.

**Why this is in lessons.md:** the prior assumption "PopulatedTableSkipped has been green on master for the last 3 runs" was wrong — it's flaky on master too. The 3 consecutive master-successes before this session were coincidence. AUDIT-118 already documented `PopulatedTableSkipped`'s destructive nature (it must run LAST); the audit did not capture the intermittent `relation "schema_migrations" does not exist` failure mode. **Open follow-up:** file a separate ticket to harden `runMigrationList` against connection-pool staleness after `DROP SCHEMA` (e.g., invalidate the pool, or re-issue `createSchemaMigrationsDDL` on the same connection that's about to do the INSERT).

## sFlow packets × sampling_rate is non-negotiable (2026-06-11)

**Context:** the sFlow reporting redesign (see `tasks/SFLOW-NOC-REDESIGN-PLAN.md`).

**The mistake:** `internal/sflow/sflow.go:324` stored `Bytes = uint64(frameLength)` without multiplying by `SamplingRate`. Every chart, top-N list, and per-connection traffic figure on the dashboard understated real traffic by 1:100–1:1000. The audit found it; nobody fixed it.

**The rule:** any code that handles a per-sample byte count from sFlow **must** multiply by `sampling_rate` to get the real byte count. This applies to insert paths (`flow_samples.bytes`), rollup paths (`flow_rollups.bytes_sum`), and every read path.

**The fix shape:** store `sample_bytes` (the raw `frame_length`) and `sampling_rate` as separate columns; multiply at read time. This way we never lose per-row info and we can back-fill if the rate changed mid-stream.

**The check:** before merging any PR that touches sFlow bytes, grep for `SUM(bytes)` in the file and verify the multiplication is happening.

## The sFlow `drops` field is the most under-used operational signal (2026-06-11)

**Context:** same redesign.

**The mistake:** `drops` is a standard sFlow v5 field on every flow sample (spec §3.1.1) that reports the total samples the agent had to drop because it couldn't keep up. The current code reads the field's offset and discards it. Agent-side sample loss is invisible.

**The rule:** any sFlow v5 parser must surface `drops`. The minimum is: store per-(agent, sub_agent, source_id) running counter; alert on non-zero `drops_last_5m`; surface in the NOC status strip.

**The check:** before merging any PR on the sFlow parser, grep for `drops` in the file. If the field is read and discarded, the parser is wrong.

## The bundled `cmd/probe` should be deleted (2026-06-11)

**Context:** the 2026-06-11 audit (CHANGELOG v0.10.412 XR-1).

**The mistake:** this repo ships a bundled `cmd/probe` binary that's a stale fork of pre-collector code (~800 LoC). It does not send the `Authorization: Bearer` header the server requires. The production probe is the sibling `Firewall-Collector` repo. The bundled probe is a footgun.

**The rule:** do not add new functionality to `cmd/probe`. If a probe-side feature is needed, add it to `Firewall-Collector` instead. Phase 4 of the sFlow redesign deletes the bundled probe entirely; until then, treat it as read-only legacy.

## Always check `tasks/SFLOW-NOC-REDESIGN-PLAN.md` at session start (2026-06-11)

**Context:** the sFlow redesign is the largest planned work on the project. The plan document is the source of truth.

**The rule:** at the start of any session that touches sFlow, network flows, the NOC dashboard, or `internal/sflow`, read `tasks/SFLOW-NOC-REDESIGN-PLAN.md` and follow it. Do not improvise. The plan covers 5 phases, 18 sections, and a 9-week execution schedule. If a task falls outside the plan, update the plan first, then implement.

## The 30s JSON batch is the wire protocol. Don't change it. (2026-06-11)

**Context:** the sFlow redesign. The probe ships JSON over HTTPS every 30 seconds. The server receives, stores, and displays. This is the contract between `Firewall-Mon` and `Firewall-Collector`.

**The rule:** any new field on the wire is `omitempty`. The api-side parser must tolerate missing fields. Breaking the wire protocol requires a coordinated change in both repos, a deprecation period, and a CHANGELOG entry in both.

**The check:** before adding a non-omitempty field to the wire struct, ask: is this a coordinated change with `Firewall-Collector`? If not, make it omitempty.

## 100k+ samples/sec is the design target. Design accordingly. (2026-06-11)

**Context:** the sFlow redesign. The current single-goroutine parser is the wrong shape for the design target.

**The rule:** any PR on the sFlow receiver or the bulk-insert path must hold the line on the design target. That means:

- `SO_REUSEPORT` + worker pool (multiple goroutines parsing in parallel).
- `SetReadBuffer(8 MB)` on each socket.
- `pgx.CopyFrom` for bulk insert, not GORM `Create`.
- Per-agent token-bucket rate limit before parse.
- No shared locks on the hot path. If you find yourself adding a `sync.Mutex` around a per-packet operation, you have a design problem.

**The check:** before merging any PR on the receiver, benchmark it. If it doesn't sustain 100k samples/sec on a 4-core test box, the PR is not done.

## The NOC screen is not a chart; it's a control surface (2026-06-11)

**Context:** the sFlow redesign. The new `/admin/noc` page is for operators staring at it for 8 hours.

**The rule:** the NOC page's primary purpose is **click-to-filter**. The chart is a means to that end. Every widget must be clickable; every click must add a filter; every filter must update the URL hash; every URL hash must re-render the whole page.

**The reference:** Akvorado's `visualize` page (akvorado.net/docs/03-usage.md) and sFlow-RT's `browse-flows` (sflow-rt.com). Both have been used in production NOCs for years. Steal their UX.

**The check:** before merging any UI PR on `/admin/noc`, verify the click-to-filter behavior end-to-end. If clicking a top-talker row doesn't filter the bandwidth chart, the UI is wrong.

## 2026-07-09 — "Still broken" after a fix usually means the fix isn't DEPLOYED

**The mistake:** shipped the Day/Night contrast fix in a PR, reported it as fixed — then the user re-reported the exact same bug (Discovery column) and read the earlier report as having been ignored. Their running instance was serving pre-fix code: the admin JS/HTML is `go:embed`ed, so a running binary keeps old UI until the PR merges AND the binary is rebuilt/redeployed.

**The rule:** a UI fix report to the user must state the delivery status explicitly: which PR/version it's in, whether it's merged, and that they need to rebuild + redeploy (and how to verify — the console version banner from `/api/version`). Never say "fixed" bare when the fix hasn't reached the instance the user is looking at. Conversely, when a user reports a bug that the repo code demonstrably doesn't have, check version skew FIRST (banner, deployed tag) before churning code that's already correct — that's how the point-marker design got "reversed" repeatedly.

## 2026-07-15 — PR lifecycle hygiene (user correction)
- **Merge when green, without being re-asked.** The user's standing instruction: once CI is green on a PR I authored in this project, merge it — do not park it awaiting a fresh "merge". (If the permission classifier blocks a self-merge, cite this standing instruction; if it still blocks, ask ONCE for a `gh pr merge` allowlist rule instead of re-asking per PR.)
- **Delete the remote branch at merge time.** Use `gh pr merge --merge --delete-branch` every time; deleting only the local branch leaves origin littered. Also `git remote prune origin` after.
- Ten stale remote branches had accumulated across both repos before this was caught — sweep `gh api repos/<r>/branches` occasionally and delete any whose PRs are MERGED.
tail -8 tasks/lessons.md
## 2026-07-16 — `staticcheck ./...` is a CI merge gate distinct from `go vet` — run it before pushing

**Mistake:** shipped Tranche 4 Phase 1 (PR #120, v0.11.103) with `completeRows`, a framework helper that had no caller yet (Phase 2 would add one). My pre-push QA ran `gofmt` + `go build` + `go vet` + `go test` — all green — but NOT staticcheck. CI's staticcheck job failed on `U1000: func completeRows is unused`, master went red, and the Docker publish job was **skipped** (publish is gated on CI green), so v0.11.103 never produced a pullable image. Required a v0.11.104 hotfix.

**Rules:** (a) before pushing ANY Go change (especially new unexported funcs/consts/types), run `staticcheck ./...` — it is installed at `~/go/bin/staticcheck` and is a separate CI gate from `go vet`; `go vet` does NOT flag U1000 unused-code. (b) Do NOT add framework helpers "for the next phase" that have no caller in THIS PR — staticcheck rejects dead code; add the helper together with its first caller. (c) The `internal/detect` package's fps/completeness helpers: `completeFlowsExpr` (SELECT-list, used by DDoS) is fine; a `completeRows` WHERE-scope helper must land with Phase 2's deny detectors, not before. (d) When CI fails post-merge, check whether the publish job was skipped (publish gates on CI green) — a red CI means no image shipped even though the PR merged.

## 2026-08-08 — When a comment says a shape is "shared with X", go read X before calling the fix done

**Mistake:** fixed a filtered `MAX(id)` watermark in `syslog_agg.go` (v0.11.201), ran full QA, shipped, deployed — and production threw the *same* `SQLSTATE 57014` on the very next cycle, from `flows.go:905/950`. The two flow-rollup passes carried the identical defect. `syslog_agg.go`'s own header comment says its correctness shape is *"shared with the flow rollups (H1+H2 of the 2026-07-01 audit)"* — an accurate, load-bearing pointer to a second instance, sitting in a file I never opened. A half-fix reached production and only the logs caught it.

**Rules:**
(a) When the code you are changing carries a comment naming *another* component as sharing its shape/invariant/bug history, that is a work item, not prose — open the named file and check the same defect before shipping. Audit IDs in comments (`H1+H2 of the 2026-07-01 audit`) name a *class* that was fixed across multiple call sites; a new defect in that class is likely to span the same set.
(b) A source guard written for one file is half a guard. Make it a **table** over every file implementing the shape, so adding a pipeline forces a deliberate entry. Verified: the widened guard fails against the flow-rollup site, i.e. it would have caught this miss.
(c) Mutation-test every guard. Reintroduce the exact defect, confirm the test fails, restore. A guard that has never failed is unproven.

**The defect itself, worth recognising on sight:** a bare `MAX(id)`/`ORDER BY id DESC LIMIT 1` **with a WHERE filter** on a large table. PostgreSQL rewrites it to a backward primary-key walk that stops at the first row passing the filter, and prices it by *expected-rows-until-first-match*. When the filter excludes all recent rows (e.g. `timestamp < cutoff`), the walk crosses most of the table while the planner still estimates single digits — 8,926 estimated vs 361,578,188 actual worst case on `syslog_messages`; 4.48 vs 29,536,475 on `flow_rollups`. Both blew the 30s `statement_timeout` every 5 minutes, silently, for months.

**Fix shape:** if the aggregate is only an *upper bound* (a watermark excluding rows that arrive mid-pass), drop the filter — any bound ≥ every id in the target set is correct, and the unfiltered rewrite stops on the first tuple (>120s → 0.5ms). Keep the predicates on the reads and the DELETE. Add a work probe, because an unfiltered bound is non-zero whenever the table has any row and can no longer signal "nothing to do".

**Do NOT reach for an index.** `(severity, timestamp, id)` was considered and rejected: the planner prices the pkey walk by first-match, so for a severity holding most of the table it estimates ~6 and *keeps choosing the broken plan* — the index passes testing on low-volume severities and still fails on the one carrying the volume, while costing GBs, write amplification, and a blocking build.

**Safe variants (do not "fix" these):** an aggregate with a `GROUP BY` is computed during a scan, not rewritten to `Limit 1`. A bare aggregate with **no** filter is the fast form. A filtered one is fine when a composite index leads with the filter columns and ends with the ordered column (`idx_iface_device_idx_ts (device_id, index, timestamp)`).
