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
