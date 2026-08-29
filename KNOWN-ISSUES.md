# Known Issues

This document tracks known issues, limitations, and known-bad-configurations
in the current Firewall-Mon release. The intent is two-fold:

1. **Operator awareness** — so a deployer doesn't lose an hour debugging
   something we already know about.
2. **Tracking** — every entry here should also be a tracked item in
   `docs/AUDIT.md` (search for the AUDIT-NNN ID), so a fix automatically
   removes both the doc entry and the audit doc row.

## Active limitations

### Single-binary deployment on ports 8080 / 162

The Docker image runs api + poller + trap-receiver in a single process
group inside one container, all binding to the host's network
namespace. Operators who want to scale out the API behind a load
balancer need to disable the trap-receiver in some instances
(AUDIT-040 has more). The native systemd path is one service per
binary, so the issue is Docker-only.

### Embedded Postgres uses a randomly-generated password (AUDIT-093)

The Dockerfile's embedded Postgres auto-generates a 32-char random
password on first init, stored at `/config/pg-credentials` (chmod
0600, owned by `fwmon`). The audit's concern was a hardcoded literal
in the public repo; the random password fixes that. The trade-off
is that operators who want to attach `psql` from the host need
to `docker exec cat /config/pg-credentials` to discover it.

### Default username `admin` triggers a startup warning (AUDIT-105)

If the operator keeps the default `ADMIN_USERNAME=admin`, a
multi-line warning is logged at startup. The warning is informational,
not fatal. SSO-portal / VPN-fronted deployments are a legitimate
reason to keep the default. Operators who want a clean startup
log should set `ADMIN_USERNAME=` to a unique value.

### The four "previously-unbounded" tables (AUDIT-029) still grow
until the cleanup tick runs

`interface_errors`, `processor_stats`, `process_stats`, and
`irc_message_logs` are cleaned up by the `CleanupOldData` cron
(once a day by default). Between ticks, the tables grow. On a
fresh deployment with 50 devices polling every 15s, the IRC
message log table can accumulate ~1M rows before the first tick
deletes anything older than 7 days. Operators with limited disk
space may want to increase the cleanup frequency (would require
an `entrypoint.sh` change; not currently configurable).

## Reporting a new issue

1. Search `docs/AUDIT.md` for the symptom — many common issues
   already have an entry.
2. If not present, open a GitHub issue with the symptom + a
   minimal repro (config snippet, log line, expected vs actual).
3. Critical-severity issues (security, data loss, crash) follow
   the disclosure policy in `SECURITY.md`.

## Removing an entry

When an issue is fixed:
1. The fix's commit message should reference the AUDIT-NNN ID.
2. The fix's commit should also remove the entry from this file
   (in the same commit, ideally in the same diff as the fix).
3. The fix's commit should update `docs/AUDIT.md` to mark the
   entry resolved (per the AUDIT doc's own progress log).

A "this file" gate isn't currently automated; the existing
AUDIT-tracking discipline is the closest thing.
