# Lessons

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
