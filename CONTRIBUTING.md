# Contributing to Firewall-Mon

Thanks for considering a contribution. This document covers the dev environment, testing requirements, and PR conventions. The audit doc (`docs/AUDIT.md`) is the canonical source for known issues and roadmap items.

## Dev environment

- **Go**: 1.24+ (check `go.mod` for the exact module-level Go version).
- **Postgres**: 14+ (production target). Tests use the in-memory SQLite shim — `:memory:` from `modernc.org/sqlite` — so you can `go test ./...` without a live database.
- **Node**: 20+ only if you need to rebuild `cmd/api/static/css/tailwind.css` via `npm run tailwind`. Most contributors will not touch CSS.
- **OS**: Linux / macOS / WSL2. Native Windows builds work but a few helper scripts (`deploy.sh`, `entrypoint.sh`) assume bash + `su-exec`.

Clone and bootstrap:

```bash
git clone https://github.com/xphox2/Firewall-Monitoring.git firewall-mon
cd firewall-mon
go build ./...
go test ./...
```

## What is in scope

- Bug fixes (point to the AUDIT-NNN ID from `docs/AUDIT.md` in the PR title when applicable).
- Test coverage for previously-untested packages (`internal/auth`, `internal/relay`, `internal/uptime`, `internal/sflow`, `internal/syslog` are good candidates — see AUDIT-117).
- Vendor profile additions (`internal/snmp/vendor_*.go` + `internal/configdiff/vendor_*.go` — see AUDIT-113 for the "how").
- Documentation, especially `docs/OPERATIONS.md` (currently missing — see AUDIT-111).

## What is out of scope (for now)

- Multi-tenant features (see AUDIT-F86; ~XL effort, single-tenant is the v0 scope).
- Replacing GORM with sqlc / Bun / something else (the cost of touching every query exceeds the win).
- Adding new vendored JS libraries without a strong story for why local-only + no CDN is unacceptable (the project has zero CDN deps by design — see `tasks/lessons.md`'s CSP rule).

If unsure, open a [discussion](https://github.com/xphox2/Firewall-Monitoring/discussions) before writing code.

## Workflow

1. **Branch** from `master`:
   ```bash
   git checkout -b fix/audit-NNN-short-description
   ```
2. **Make focused changes**. One PR = one logical change. If an unrelated cleanup tempts you, do it in a separate PR.
3. **Run QA locally** *before* pushing:
   ```bash
   gofmt -l . | (! grep .)        # must produce no output
   go vet ./...                    # must be clean
   go build ./...                  # must succeed
   go test -count=1 ./...          # must pass
   # Optional but encouraged:
   CGO_ENABLED=1 go test -race -count=1 ./...
   ```
4. **Update `CHANGELOG.md`** with a new entry **at the top of the file** describing the change. Use the version pattern `[0.10.N+1] - YYYY-MM-DD`. Include the AUDIT-NNN ID if applicable.
5. **Bump `ServerVersion`** in `cmd/api/main.go:34` and the matching `org.opencontainers.image.version` label in `Dockerfile:48` to the version your CHANGELOG entry uses.
6. **For resolved audit items**, append a row to the "Resolved findings" table in `docs/AUDIT.md` and a line to the "Progress log" at the bottom — both with the version and commit SHA. (You can leave SHA `(pending)` in the PR; a maintainer will update on merge.)
7. **Open the PR**. Title format: `vX.Y.Z: AUDIT-NNN - short description` or `vX.Y.Z: <area> - short description` for non-audit work.
8. **CI** runs `go build`, `go test -race`, `gofmt -l`, `go vet`, `govulncheck` on every PR — must be green before merge.
9. **Squash-merge** is the default; the merge commit message becomes the canonical changelog entry on `master`.

## Commit message style

Imperative mood, ≤ 72 char subject. Body explains *why* the change is being made; the diff already shows *what*. Reference the AUDIT-NNN ID and any related v0.10.N CHANGELOG entries when the change is part of a larger thread.

Example:

```
v0.10.246: AUDIT-016 - probe key constant-time compare

validateProbe used Go != string compare which short-circuits at the first
mismatching byte. A network attacker could time the rejection to reduce
the key search space.

Replaced with subtle.ConstantTimeCompare. 9-case regression test in
handlers_probes_audit016_test.go covers all variants a naive == would
short-circuit on.

QA: go build, go test -count=1 ./..., go vet, gofmt -l all clean.
Server-repo only.
```

## Code style

- **Go**: follow `gofmt`. CI rejects unformatted code. No `gci` / `goimports` reordering beyond `gofmt` defaults.
- **Comments**: add comments explaining *why* (especially for security-sensitive code). Avoid restating what the code does — the reader can read it.
- **No new global state**. Prefer dependency injection (see how `database.Database`, `notifier.Notifier`, `alerts.AlertManager` are constructed in `cmd/api/main.go` for the established pattern).
- **No new third-party Go dependencies** without a clear justification in the PR description. The dependency surface is intentionally small.
- **No new vendored browser libraries** without the same justification + a `THIRD-PARTY-NOTICES.md` update.
- **Tests**: prefer table-driven tests. Use `t.TempDir()` for filesystem fixtures. Mark `t.Parallel()` on safe tests.

## Security-sensitive contributions

If your change touches authentication, encryption, secret management, the trap listener, or any of the SSRF-gated `Test*` endpoints, please:

1. Reference the specific audit findings the change addresses (`docs/AUDIT.md`).
2. Add a regression test that *fails* without your fix (or document why a test is infeasible).
3. Update `SECURITY.md` if the change affects the threat model.

Do NOT submit a public PR for an undisclosed vulnerability. See `SECURITY.md` for the private disclosure path.

## Code of conduct

This project adopts the Contributor Covenant; see `CODE_OF_CONDUCT.md`.

## Maintainers

See `git log --format='%an' | sort -u` and `.github/CODEOWNERS` (once added — see AUDIT-163).
