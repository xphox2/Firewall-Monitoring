# Operations Runbook

Operator-facing procedures for running Firewall-Mon in production (AUDIT-111).
Pairs with [`KNOWN-ISSUES.md`](../KNOWN-ISSUES.md) (current limitations) and
[`SECURITY.md`](../SECURITY.md) (hardening + disclosure).

> **Deployment assumed:** the single-container Docker image (API + poller +
> trap-receiver + embedded PostgreSQL 16), with `/data` and `/config`
> bind-mounted to the host. Native (systemd) installs differ only in paths
> (`/opt/firewall-mon`, `/etc/firewall-mon`, `/var/lib/firewall-mon`).

---

## First-24h checklist

1. **Change the admin credentials.** Set a non-default `ADMIN_USERNAME` (not
   `admin` — see AUDIT-105) and a strong `ADMIN_PASSWORD` on first boot.
2. **Confirm secret persistence.** After first start, `<SECRETS_DIR>/.jwt-secret`
   (default `/data/.jwt-secret`, mode 0600) must exist. If it's regenerated on
   every restart, every login is invalidated **and every encrypted device/IRC/
   SMTP secret becomes unreadable** (the AES-256 key is derived from it — AUDIT-008).
3. **Verify health.** `curl -fsS http://localhost:8080/api/health` must return
   200 (it pings the DB with a 1 s timeout; 503 means the DB is unreachable —
   AUDIT-091/045).
4. **Confirm TLS.** Either terminate TLS in-process (`SERVER_ENABLE_TLS=true`
   + cert/key) or front it with the reverse proxy in [`nginx.conf`](nginx.conf).
   Logins over plain HTTP fail silently if `COOKIE_SECURE` is on (AUDIT-024).
5. **Set retention.** Confirm `RETENTION_SYSLOG_CRITICAL_DAYS` (and the other
   `RETENTION_*` vars) are set — an unset critical-syslog retention lets
   `syslog_messages` grow without bound (the #1 DB-bloat cause).
6. **Take a first backup** (see Backup & restore) once devices/probes are added.
7. **Watch the logs** for one full poll cycle (default 60 s) and confirm
   devices report online and no repeated errors.

---

## Health & monitoring

- **Liveness/readiness:** `GET /api/health` (DB ping, 503 on failure). The
  Docker `HEALTHCHECK` already hits it every 30 s.
- **Version:** `GET /api/version` returns the running `ServerVersion` — use it
  to confirm a redeploy actually shipped (embedded JS/HTML is compiled into the
  binary, so a browser refresh alone won't update the UI).
- **Container:** `docker ps` health column, and `docker logs <container>` for
  the three daemons' stdout + PostgreSQL (see Debug logging).

---

## Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| All API calls 503; `/api/health` 503 | PostgreSQL down / recovering | `docker logs` → look for the PG startup/crash lines in `/data/pgdata/postgresql.log`; ensure `/data` is writable and not full. |
| A device shows **offline** with no alert/email | probe-monitored device (polled by the remote collector, not the central poller) | Fixed in v0.10.323 — confirm you're on ≥ that build; check the probe is sending data. |
| A device went dark after an edit, community looks like `********` | redacted-secret write-back (pre-v0.10.324) | Re-enter the real SNMP community (the mask overwrote it; unrecoverable from the DB). Confirm you're on ≥ v0.10.324. |
| Disk filling up | `syslog_messages` bloat | Check severity distribution first; set `RETENTION_SYSLOG_CRITICAL_DAYS`. The retention cleanup runs every 24 h in the poller. |
| Duplicate IRC bots / double login-lockout | two `cmd/api` instances sharing one DB | Known limitation (AUDIT-040, see KNOWN-ISSUES). Run a single API instance until resolved. |
| Logins all fail right after a restart | `.jwt-secret` was regenerated (not persisted) | Restore `/data/.jwt-secret` from backup, or accept that all sessions + encrypted secrets are lost and re-enter device/IRC/SMTP secrets. |
| `/interface-addresses` 500s (SQLSTATE 42P10) | legacy duplicate rows blocked the unique index | Fixed in v0.10.322 (self-healing on restart) — confirm you're on ≥ that build. |
| Rate-limiter memory growth under IP-spray | bounded LRU cap (AUDIT-083) | Confirm ≥ the AUDIT-083 build; front with the proxy to shed abusive traffic. |
| Webhook/Slack/Discord alerts not firing | SSRF block-list rejects the target, or bad URL | Check the target isn't a private/loopback/CGNAT IP (AUDIT-020); test the URL. |

---

## Debug logging

- **Database:** set `DB_LOG_LEVEL=info` (valid: `silent`/`error`/`warn`/`info`,
  default `warn` — AUDIT-149) to log slow queries and statements. Restart to apply.
- **PostgreSQL:** lower `log_min_messages` in `/data/pgdata/postgresql.conf`
  (e.g. to `info`) and restart PG; logs land in `/data/pgdata/postgresql.log`
  (retained on the bind mount even with `logging_collector = off` — AUDIT-095).
- **HTTP:** the API runs gin in **release mode** (hardcoded) — there is no
  `GIN_MODE=debug` toggle. Per-request method/path/status/latency is logged by
  the `RequestLogger` middleware. (Per-request IDs are AUDIT-135, not yet shipped.)

---

## Admin password reset

`InitAdmin` only **creates** the admin when none exists — it does **not**
overwrite an existing admin, so changing `ADMIN_PASSWORD` and restarting has no
effect on an already-initialized install. To reset:

1. Stop the API (or the whole container).
2. Connect to the DB and remove the admin row:
   ```sql
   DELETE FROM admins;
   ```
   (In the single container: `docker exec -it <c> su-exec postgres psql -h /run/postgresql -d firewall_mon -c "DELETE FROM admins;"`)
3. Start with `ADMIN_USERNAME` + `ADMIN_PASSWORD` set — `InitAdmin` recreates
   the admin from those env values on boot.

---

## JWT secret rotation

> ⚠ **Destructive.** The JWT secret doubles as the seed for the AES-256 key
> that encrypts SNMP/IRC/SMTP secrets at rest (AUDIT-008). Rotating it
> **invalidates every login session AND makes every stored encrypted secret
> unreadable.** This is a credentials-rotation event, not a routine task.

1. Back up the current `/data/.jwt-secret` (in case you need to roll back).
2. **Record every device/IRC/SMTP secret** out-of-band — you will re-enter them.
3. Stop the app, replace `/data/.jwt-secret` with a new 32-byte base64 value
   (or delete it to auto-generate a fresh one on next boot), restart.
4. Re-enter all SNMP communities / v3 creds, IRC passwords, and SMTP passwords
   (the old ciphertext can no longer be decrypted; `decryptField` fails closed
   to empty — AUDIT-027).

---

## Backup & restore

**Back up (all four):**
1. **Database** — `pg_dump`:
   `docker exec <c> su-exec postgres pg_dump -h /run/postgresql firewall_mon | gzip > fwmon-$(date +%F).sql.gz`
2. **Secrets** — `/data/.jwt-secret` and `/data/.admin-password` (0600).
   Without `.jwt-secret`, a DB restore cannot decrypt any stored secret.
3. **Config** — `/config/config.env`.
4. **Probe registration keys** — these authenticate each remote probe; they're
   stored hashed (AUDIT-017), so a probe that loses its key must be
   re-registered (regenerate the key, update the collector).

**Restore:** stop the app → restore `.jwt-secret`/`.admin-password`/`config.env`
→ `gunzip -c fwmon-….sql.gz | psql … firewall_mon` into a fresh DB → start.

---

## Upgrade

1. **Read the [CHANGELOG](../CHANGELOG.md)** for the target version — look for
   `### Security` / breaking-change callouts since your current `GET /api/version`.
2. Pull/rebuild the image (`docker compose pull && docker compose up -d`, or
   `make docker`).
3. The entrypoint runs `AutoMigrate` + idempotent index/partition repair on
   boot — no manual migration step today (golang-migrate adoption is AUDIT-044).
4. Confirm `GET /api/version` shows the new version and `/api/health` is 200.
5. **Roll back** by redeploying the previous image tag; the DB is
   forward-compatible within a minor series (AutoMigrate only adds).

---

## Scale & HA

- **Single API instance only** (enforced — see below). A second `cmd/api`
  against the same DB would spawn a second IRC bot, double login-lockout/
  rate-limit state, and diverge on uptime (AUDIT-040).
- The **poller** is multi-instance-safe via a Postgres advisory lock
  (`pg_try_advisory_lock`, AUDIT-007) — only one poller does the migration/
  cleanup work at a time.
- **Remote sites** scale horizontally via probes (each relays SNMP/syslog/
  sFlow/ICMP back to the central server); this is the supported scale-out path.

## Running a single API instance (AUDIT-040)

The API process keeps four pieces of state **in memory**, not in the database:

- IRC bots (one TCP connection + nick per configured server)
- login-lockout counters (`internal/auth`)
- rate-limit buckets (`internal/api/middleware`)
- uptime baseline (`internal/uptime`)

Running **two** API processes against the same database double-runs all four:
two bots fight over the same IRC nick (the loser gets `_` suffixes), lockout and
rate-limit counters split across instances (a brute-forcer effectively gets ~2×
the attempts; rate limits ~2× looser), and the two report different uptimes.

**Guard:** on startup the API takes a session-scoped Postgres advisory lock. If
another API already holds it, the new process **refuses to start** with an
actionable error. This is the default and recommended behavior.

- **Graceful shutdown (SIGTERM) releases the lock** before the process exits, so
  a normal restart re-acquires it instantly. Docker/systemd send SIGTERM on
  restart, so the common case is seamless.
- **SIGKILL / OOM-kill does NOT run the release.** The lock then lingers until
  the killed process's Postgres session is reaped (TCP keepalive / server-side
  idle timeout). A restart within that window retries for
  `API_SINGLETON_LOCK_WAIT` (default `10s`) and then, if still blocked, refuses.
  Tuning Postgres `tcp_keepalives_*` / `idle_session_timeout` shortens the
  lingering window (this guard does not change those).

**`ALLOW_MULTI_API=true`** — follower mode (advanced / not recommended):

- The extra instance serves HTTP but does **not** start the IRC bots.
- Login-lockout, rate-limit, and uptime remain **per-instance and will diverge**.
  Moving them to shared storage is the long-term fix and is deliberately **not**
  done here — a Postgres round-trip per request at dashboard-polling rates is the
  wrong tool for rate-limiting.
- Edge case: a follower's admin **Connect** action on an IRC server can still
  start a single bot for that server (best-effort; the background reconnect/
  status loops don't run on a follower). Don't connect IRC servers from a
  follower instance.

---

## Disaster recovery

**Target RTO: < 1 hour** from the most recent backup.

1. Provision a fresh host + the Firewall-Mon image with `/data` and `/config`
   volumes.
2. Restore `.jwt-secret`, `.admin-password`, `config.env`, then the `pg_dump`
   (see Restore). The JWT secret **must** be the one paired with that dump, or
   all encrypted secrets are lost.
3. Start; confirm `/api/health` 200 and devices report online within one poll
   cycle.
4. Re-point remote probes if the server hostname/URL changed (update
   `PROBE_SERVER_URL` on each collector).

**RPO** is your `pg_dump` cadence — schedule it (e.g. hourly) for low data loss.
