# Lessons

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

## Cross-repo changelog formats differ — know which repo you're in (2026-06-11)

- **Firewall-Collector**: clean `## X.Y.Z - date` per-version headers, newest first, NO `[Unreleased]`, NO changelog test.
- **Firewall-Mon (server)**: Keep-A-Changelog — `## [Unreleased]` MUST be the first section (enforced by `TestChangelog_KeepAChangelogHeader_AUDIT110`), released versions as `## [x.y.z] - date` below. New entries accumulate under `[Unreleased]` grouped by `### Added/Changed/Fixed` with the version tagged inline `(vX.Y.Z)`.

Do not apply the collector's format to the server (or vice-versa) without also changing the server's AUDIT-110 test.

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

**Context:** the 2026-06-11 CTO-loop audit (CHANGELOG v0.10.412 XR-1).

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
