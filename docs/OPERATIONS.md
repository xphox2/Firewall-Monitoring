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

- **Liveness/readiness:** `GET /api/health` (also aliased at `GET /api/readyz`).
  Returns 503 on a DB ping failure **or** when the `ENCRYPTION_KEY` can't decrypt
  the database's stored secrets (M8); the JSON includes an `"encryption"` boolean.
  The Docker `HEALTHCHECK` already hits it every 30 s.
- **Version:** `GET /api/version` returns the running `ServerVersion` — use it
  to confirm a redeploy actually shipped (embedded JS/HTML is compiled into the
  binary, so a browser refresh alone won't update the UI).
- **Container:** `docker ps` health column, and `docker logs <container>` for
  the three daemons' stdout + PostgreSQL (see Debug logging).
- **Poller / trap-receiver:** both now expose `/healthz`, `/readyz`, and
  Prometheus `/metrics` on their own listeners (`POLLER_METRICS_ADDR` default
  `:9101`, `TRAP_METRICS_ADDR` default `:9102`; set either to `off` to disable).
- **Encryption-key fail-fast (M8):** unlike the API (which stays up and reports
  unhealthy), the poller and trap-receiver **exit immediately** (`log.Fatal`) at
  startup if the configured `ENCRYPTION_KEY` can't decrypt stored secrets — they
  are useless without device credentials, so they crash-loop loudly rather than
  poll with empty secrets. Fix by restoring the original `ENCRYPTION_KEY` (or
  adding the old key to `ENCRYPTION_KEY_HISTORY`); see the **Upgrade** section's
  `ENCRYPTION_KEY` continuity note below.

---

## Verifying signed webhooks

When a **Webhook Signing Secret** is set (Settings → Notification Settings, or
`WEBHOOK_SECRET`), every generic-webhook delivery — including the test button —
carries two headers:

```
X-FirewallMon-Timestamp: 1719990000                  (unix seconds)
X-FirewallMon-Signature: sha256=<hex hmac digest>
```

The signature is `HMAC-SHA256(secret, timestamp + "." + raw_body)`. Verify and
reject replays older than your tolerance:

```python
import hmac, hashlib, time
def verify(headers, body: bytes, secret: str, tolerance=300) -> bool:
    ts = headers["X-FirewallMon-Timestamp"]
    if abs(time.time() - int(ts)) > tolerance:
        return False
    want = "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body,
                                hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-FirewallMon-Signature"])
```

Slack/Discord deliveries are unaffected (they use their own schemes). No secret
configured = unsigned requests, exactly as before.

---

## Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| All API calls 503; `/api/health` 503 | PostgreSQL down / recovering | `docker logs` → look for the PG startup/crash lines in `/data/pgdata/postgresql.log`; ensure `/data` is writable and not full. |
| A device shows **offline** with no alert/email | probe-monitored device (polled by the remote collector, not the central poller) | Fixed in v0.10.323 — confirm you're on ≥ that build; check the probe is sending data. |
| A device went dark after an edit, community looks like `********` | redacted-secret write-back (pre-v0.10.324) | Re-enter the real SNMP community (the mask overwrote it; unrecoverable from the DB). Confirm you're on ≥ v0.10.324. |
| Disk filling up | `syslog_messages` bloat | Check severity distribution first; set `RETENTION_SYSLOG_CRITICAL_DAYS`. The retention cleanup runs every 24 h in the poller. |
| Disk filling up, but the **database volume** is fine | Docker build cache + orphaned images on the **root** filesystem | Different disk, different fix — see [Host disk housekeeping](#host-disk-housekeeping). `df -h /` vs `df -h` on the data volume tells you which one. |
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
  the `RequestLogger` middleware. Per-request IDs (`X-Request-ID` propagation,
  AUDIT-135) **are** shipped — the correlation ID appears in each request's
  structured log line and in the `X-Request-ID` response header.

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

Note: with multiple users (v0.11 RBAC), `DELETE FROM admins WHERE username='<name>';`
targets one account; deleting all rows removes every user and re-bootstraps only
the env-configured admin.

---

## Two-factor authentication lockout (last admin)

If a user loses both their authenticator and recovery codes, any **admin** can
clear their 2FA from Settings → Users → *Reset 2FA*. If the **last admin** is
the one locked out, clear the flag directly in the database:

```sql
UPDATE admins SET totp_enabled = false, totp_secret = '' WHERE username = '<name>';
DELETE FROM admin_recovery_codes WHERE admin_id = (SELECT id FROM admins WHERE username = '<name>');
```

(In the single container: wrap in the same `docker exec … psql` as above.) The
user then logs in with password only and can re-enroll.

Two design notes worth knowing during an incident: **API tokens bypass TOTP by
design** (they are their own credential class — revoke them from Settings → API
Tokens if an account is suspect), and TOTP secrets are encrypted with the same
field-encryption key chain as device credentials — if `ENCRYPTION_KEY` is lost,
TOTP validation fails closed (codes stop working) and the startup canary flags
the key problem loudly (see “Failure modes”).

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

> ⚠ **Key continuity — the #1 upgrade hazard.** Two secrets MUST survive every
> upgrade, host move, or repo-directory relocation **unchanged**:
>
> - **`ENCRYPTION_KEY`** — derives the AES-256 key (`sha256(value)`) for every
>   secret stored at rest (SNMP communities, SMTP/IRC passwords). If it changes,
>   `decryptField` fails closed (AUDIT-027) and **every stored secret becomes
>   unreadable** — devices stop polling and email/IRC alerts fail (`535`) until
>   you re-enter them all by hand. There is no recovery without the original value.
> - **`JWT_SECRET_KEY`** — signs login sessions; if it changes everyone is logged
>   out (annoying, not destructive).
>
> **The trap (2026-06-07 prod incident):** deploying from a *fresh checkout in a
> new directory* (e.g. `/home/xphox/firewall-mon` → `/opt/Firewall-Monitoring`)
> makes the entrypoint generate a **brand-new** `config.env` with a **random**
> `JWT_SECRET_KEY`. If `ENCRYPTION_KEY` was never set explicitly (so encryption
> was silently derived from the JWT secret — the AUDIT-008/009 fallback), the
> derived key changes and every stored secret breaks. **Always set
> `ENCRYPTION_KEY` explicitly** (in `docker-compose.yml` `environment:` or the
> container env) — this decouples encryption from JWT churn — **record it in your
> secret store, and carry the exact same value forward on every deploy.**
>
> Verify it is unchanged across the upgrade (run **before and after** — the value
> must match):
> ```bash
> grep ENCRYPTION_KEY docker-compose.yml
> docker exec <c> env | grep -E 'ENCRYPTION_KEY|JWT_SECRET_KEY'
> ```

1. **Read the [CHANGELOG](../CHANGELOG.md)** for the target version — look for
   `### Security` / breaking-change callouts since your current `GET /api/version`.
2. Pull/rebuild the image (`docker compose pull && docker compose up -d`, or
   `make docker`).
3. The entrypoint runs `AutoMigrate` + idempotent index/partition repair on
   boot — no manual migration step is required. Versioned, recorded migrations
   (the `schema_migrations` table + advisory-lock-gated runner, AUDIT-044) are
   shipped; `fwmon-api migrate` / `migrate-status` expose the runner for manual
   inspection.
4. Confirm `GET /api/version` shows the new version and `/api/health` is 200.
5. **Roll back** by redeploying the previous image tag; the DB is
   forward-compatible within a minor series (AutoMigrate only adds).

---

## Retiring, restoring and recovering devices

Since v0.11.239 a device is never hard-deleted from the console. **Retire**
(the trash action on the Devices page, `DELETE /admin/api/devices/:id` or
`POST /admin/api/devices/:id/retire`, operator-level) is a soft delete that
mirrors probe decommissioning:

- the row is kept with `retired_at` set and `enabled=false`; status is left
  as it was (no separate "retired" status bucket);
- the collector stops polling it at its next device-list refresh
  (`PROBE_DEVICE_REFRESH_INTERVAL`, default 300 s) and the server's ingest
  allow-list drops any late or spooled rows for that device only;
- its open alerts are acknowledged and resolved (so the escalation engine
  stops re-notifying), its open incidents are resolved with a
  `(device retired)` reason, and its user-drawn connection-map links are
  removed;
- **every** telemetry, alert, incident, config-history and ping row is
  preserved. Dashboards, NOC, reports, the IRC status and fleet counts exclude
  retired devices; the alerts page and the device detail page still name it.

**Restore** (`POST /admin/api/devices/:id/restore`, optional JSON body of
device settings in the `PUT` shape) clears the marker, re-enables the device,
resets its status to `unknown` and applies the settings through the same
validation and secret handling as an edit (`enabled` is ignored; blank or
masked secrets keep the stored values). The history was never moved, so it is
back on the charts immediately. Editing a retired device with `PUT` returns
`409 device is retired; restore it first`.

**Names are unique among active devices only** (v0.11.241, migration v63:
the global unique index on `devices.name` is replaced by the partial index
`idx_devices_name_active … WHERE retired_at IS NULL`). A retired device keeps
its name, and a replacement — a rebuilt VM, or a different vendor at the same
location — may reuse it as a **new** device with its own id and history.

**Same-name re-add.** Creating a device whose name matches a retired one
returns `409` with `retired_device_id` (the most recently retired one),
`retired_at` and `retired_count`; the Devices page then asks whether to
**restore** that device with the form's settings, or to **create a new
device** with the name (the create is re-sent with `"reuse_name": true`, which
skips the advisory check). When several retired devices share the name,
Restore applies to the most recently retired one. A name that collides with
an *active* device is `409 device name already in use` in every case,
including `reuse_name` — and even when a retired device shares the name: the
active-name check runs before the retired-name advisory, so the advisory
(and its `retired_device_id`) only ever appears for a name no active device
holds.

**Restore is refused while an active device holds the name** (`409 device
name already in use`, the device stays retired). Restore it under a new name
instead: the Devices page prompts for one and re-sends the restore with
`{"name": …}`; the rename and the restore are one statement, so a rejected
name leaves the row retired and unchanged.

**IPSec identity.** Every device carries an immutable UUID (`uuid` on the
device API, shown on the device page and in the edit dialog; migration v64
backfills devices created before v0.11.242). The IPSec wizard defaults a
*new* tunnel's IKE local identity to `fwm-<uuid>` rather than the device
name, so a replacement device that reuses a retired device's name presents a
different identity automatically — a shared peer never sees two phase1s
with the same identity. Existing tunnels keep the identity stored in their
intent (changing a deployed identity would break phase 1); the wizard's edit
path shows that stored value, and an operator-entered identity still wins
over the default.

**Probes and sites.** A retired device does not block deleting or
decommissioning its probe (delete detaches it: `probe_id` becomes NULL). A
site cannot be deleted while any device — active or retired — or probe still
references it (`409`); move or purge the devices and decommission the probes
first.

**Recovering devices removed before v0.11.239.** The old delete removed only
the `devices` row and left every child table keyed by the vanished
`device_id` (alerts rendered as `DEV-<id>` with a dead link). Migration v61
(`materialize_orphaned_devices`) runs once at startup, finds such ids in
`alerts`, `device_config_revisions`, `device_alert_configs`, `uptime_records`
and `vpn_status`, and recreates each as a **retired** device under its
original id — name and IP recovered from the newest `Device <name> (<ip>) is
offline/back online` alert, otherwise `Removed device #<id>` / `0.0.0.0` (also
used when the recovered name is already taken). Each row is logged as
`migrate v61: materialized retired device ...`. Rename or restore it from the
Devices page (Retired tab) like any other retired device. The migration is
idempotent and never scans the partitioned telemetry parents.

### Permanently deleting a retired device (purge)

Since v0.11.243 a **retired** device can be purged — every row keyed to it
removed and the device row deleted — from the Devices page (Retired tab,
"Delete permanently") or `POST /admin/api/devices/:id/purge`. It is the
only destructive path and it is deliberately heavy:

- **Admin-only and re-authenticated.** All five purge routes are admin-only.
  The POST requires the device name typed back (`confirm_name`), the
  caller's own password and — when the account has 2FA — a fresh
  authenticator code (single-use; the same step-up as reveal-secret). Every
  accepted request writes an audit row `purge_device` naming the device id,
  UUID, name and job id; a cancel writes `purge_device_cancel`.
- **Retired only.** An active device returns `409 device must be retired
  first` — retire it, check nothing else needs its history, then purge.
- **Refused while an IPSec tunnel on the device is deploying, verifying or
  rolling back** (`409` naming the tunnels). The purge deletes the tunnel
  *intent* rows that reference the device — a tunnel intent is one shared
  row, so the intent disappears for the **peer device too**; the confirm
  dialog lists those tunnels with their peer. Roll a deployed tunnel back
  first if you need its device objects removed; the purge removes the
  server-side intent only, never the config on the peer.
- **Background, batched, one at a time.** The request returns `202` with a
  job; the API primary's worker picks it up within 5 s and deletes in
  transactions of at most 10,000 rows (2,000 on the widest tables), ordered
  along each table's `(device_id, timestamp)` index, with a 5 s lock
  timeout and a 120 s statement timeout per batch, so ingestion and the
  poller are never blocked for long. Partitioned tables are processed per
  partition. Progress (`current_table`, `rows_deleted`, `tables_done` of
  `tables_total`) is visible on the Devices row, the device page banner,
  `GET /admin/api/devices/:id/purge` and `GET /admin/api/purge-jobs`. A
  device with tens of millions of syslog rows takes hours; that is expected.
  The confirm dialog's row estimate counts at most 100,000 rows per table
  ("100,000+"); a table that cannot be counted is flagged, not fatal.
- **Resumable.** The job row is the checkpoint: a restart flips a running
  job back to `pending` and the next primary resumes it; a worker that dies
  without a clean shutdown is detected by the heartbeat (`running` with
  `updated_at` older than two minutes) and requeued. Every delete is
  idempotent, so a resumed job simply continues with whatever rows remain.
- **Cancellable.** Cancel on the row (or `POST .../purge/cancel`) stops the
  job between batches. **A cancelled or failed purge leaves the device
  retired with partial data** — tables are processed largest first, so what
  remains depends on where it stopped (`current_table` on the job says
  where) — and the device can be restored (whatever history remains comes
  back) or purged again later, resuming from where it stopped. The device row itself is deleted
  only as the very last step, so a device is never left half-deleted. A
  restore is refused (`409`, naming the job) while a purge job is pending,
  running or cancelling — cancel it first; the worker also re-checks that
  the device is still retired before it starts and before the final step,
  so a restore can never have its data deleted underneath it.
- **What is removed.** All telemetry (`syslog_messages`, `interface_stats`,
  status/sensor/processor/ping/flow/trap/denied-event rows and their
  summaries), **alerts and incidents**, **configuration history**
  (`device_config_revisions`), tunnel and interface-address inventory, the
  device's alert configuration, device-scoped event rules and maintenance
  windows, probe commands addressed to it, its user-drawn connection-map
  links, the shared IPSec tunnel intents noted above, and finally the device
  row (its UUID is never reused). Rows carrying `device_id = 0`
  (agent-level detections, probe-level commands, probe alerts) are never
  touched. Terminal job rows are kept 30 days as an audit trail.
- **Disk space comes back later, not immediately.** Postgres leaves the
  deleted rows as dead tuples for autovacuum to reclaim; the tables shrink
  in place (the space is reused by new ingest) rather than returning it to
  the filesystem. After a very large purge, `VACUUM (VERBOSE)
  interface_stats` (and the same for `syslog_messages`) shows the dead
  tuples being removed and lets you confirm the reclaim without waiting for
  the autovacuum threshold. On the SQLite test backend deletes are
  immediate.

**Restore vs. purge:** restore is reversible and free; purge is neither.
When a device has been replaced under the same name, the usual sequence is
retire → confirm the replacement works → purge the old one.

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

## Resource footprint & DB sizing

The three Go daemons themselves are light (tens of MB RSS each); **PostgreSQL
disk is what grows**, and it is driven almost entirely by the high-volume
time-series tables, not the binaries. Rather than a single "it needs N GB"
figure (which depends entirely on your fleet size, traffic, and retention),
estimate from the drivers:

- **Dominant tables** (all monthly range-partitioned): `syslog_messages`,
  `flow_samples` (sFlow), `interface_stats`, `system_status`, `trap_events`,
  `syslog_summaries`. `syslog_messages` is the usual #1 — an unset
  `RETENTION_SYSLOG_CRITICAL_DAYS` lets it grow unbounded (see Failure modes).
- **Rough model:** `rows_retained ≈ ingest_rate × retention_window`, and disk ≈
  `rows_retained × bytes_per_row` (order 100–300 B/row for syslog/stats after
  index overhead). So the levers are entirely the `RETENTION_*` env vars and how
  much syslog/sFlow your devices emit — halve the retention window, roughly
  halve the steady-state size for that table.
- **Bounding it:** set every `RETENTION_*` var (see `docs/DATA-RETENTION.md`),
  and prefer `RETENTION_SYSLOG_INFORMATIONAL_DAYS` low (informational syslog is
  the bulk) while keeping critical longer. The 24 h retention cleanup runs in
  the poller.
- **Measure, don't guess:** once running, size it from your own data —
  `SELECT pg_size_pretty(pg_total_relation_size('syslog_messages'));` and
  `SELECT date_trunc('day',timestamp), count(*) FROM syslog_messages GROUP BY 1
  ORDER BY 1;` give you the real per-day growth to project from.

CPU is dominated by SNMP poll fan-out (poller) and sFlow parsing (ingest); both
scale with fleet size and sampling rate rather than a fixed baseline.

### Measured ingest throughput

From the ingestion benchmark suite (`make bench-ingest`, run 2026-07-03 via the
manual Benchmark workflow on a 4-vCPU GitHub runner with a postgres:16 sidecar —
shared-VM numbers, so treat them as order-of-magnitude, and relative comparisons
as the reliable part):

| Write path (flow_samples)             | batch 100 | batch 500 | batch 1000 |
|---------------------------------------|-----------|-----------|------------|
| pgx COPY (production Postgres path)   | 60k rows/s| 111k rows/s| 121k rows/s|
| One multi-row INSERT (M26 fallback)   | 47k rows/s| 55k rows/s | 60k rows/s |
| Per-row INSERTs                       | 1.8k rows/s| 1.7k rows/s| —         |

Syslog (`syslog_messages`, one multi-row INSERT): ~81k rows/s at batch 500.

Takeaways: COPY beats per-row INSERTs by ~30–70x (the old "5–10x" comment was a
large understatement) and the multi-row-INSERT fallback by ~2x; COPY at batch
1000 clears the 100k samples/sec sFlow design target on modest hardware; and
batch size matters — the collector's 500–1000-row batches sit in the right
range, so don't shrink them to "smooth" load.

## Host disk housekeeping

The section above is about the **database volume**. This one is about the **root filesystem**, which
holds Docker. They fill for unrelated reasons and the fix for one does nothing for the other — that
confusion is the single most common wrong turn here.

| Mount | Holds | Fills because |
|---|---|---|
| the data volume (a bind mount) | PGDATA | telemetry ingest — see *Resource footprint & DB sizing* |
| `/` | Docker images, build cache, volumes | build cache and orphaned images, below |

The server already **detects** both: the poller probes root and the PGDATA volume every 5 minutes and
raises `DISK_HIGH` against `server_disk_threshold` (default 85%) and `server_disk_free_floor_gb`
(default 5). It does not remediate, which is what this section is for.

### Three traps, in the order people hit them

**`du` on `/var/lib/docker` will convince you Docker is innocent.** With the containerd image store,
layers live under `/var/lib/containerd`. On the reference deployment `du` reported ~17 GB for
`/var/lib/docker` while `/var/lib/containerd` held 37 GB.

**`docker system df` under-reports too.** A builder using the `docker-container` driver keeps its
cache inside its own volume. It once reported `Build Cache 3.846MB` while that builder held
gigabytes. The honest number is per builder:

```bash
docker buildx ls                              # note: there is usually more than one
docker buildx du --builder <name>
```

**There is more than one builder, and the one you care about may not be the default.** On the
reference deployment `docker compose build` runs on a builder created by an unrelated project,
because that is the one selected in `~/.docker/buildx/current`. `docker builder prune` with no
`--builder` only touches `default`, so it can appear to do nothing.

### The real control is BuildKit's GC policy, not a cleanup job

BuildKit garbage-collects on its own. The reason a host still fills is that the **upstream defaults
are sized for a large CI machine**:

| Setting | Upstream default | Meaning on a 77 GB disk |
|---|---|---|
| `Max Used Space` | 42.84 GiB | per builder — two builders may exceed the disk |
| `Min Free Space` | 11.18 GiB | eviction only begins at ~85.5% used |

That `Min Free Space` is why such a host climbs to ~88% and then sits there instead of filling
completely: it is the configured floor, and it happens to sit just above the app's own 85%
`DISK_HIGH` line. Check the live policy with `docker buildx inspect <name>`.

Set it to something the disk can actually hold. For the `docker` driver, `/etc/docker/daemon.json`:

```json
{
  "builder": { "gc": { "enabled": true, "defaultKeepStorage": "8GB" } },
  "log-opts": { "max-size": "50m", "max-file": "3" }
}
```

**Validate the file before you go anywhere near a restart.** The daemon can check a config without
touching the running instance, so a typo never costs an outage:

```bash
sudo dockerd --validate --config-file=/etc/docker/daemon.json   # prints "configuration OK"
```

Then try `systemctl reload docker` and re-inspect with `docker buildx inspect`; a full restart bounces
every container on the host. For a `docker-container` driver builder, recreate it with
`docker buildx create --buildkitd-config`, which discards its cache — usually the intent.

A finer-grained policy is accepted too, if one number is not enough:

```json
{ "builder": { "gc": { "enabled": true, "policy": [
  { "keepStorage": "8GB", "filter": ["unused-for=168h"] },
  { "keepStorage": "8GB", "all": true }
] } } }
```

Note `unused-for` takes a Go duration, so `168h` — **not** `7d`. There is no `d` unit and the value is
rejected outright.

The `log-opts` above are worth setting at the same time: containers created without a logging limit
write unbounded json-file logs. It only affects containers created afterwards.

### Orphaned images are a separate problem

**BuildKit's GC never touches them** — they are image-store objects, not build cache, so no policy
will ever reclaim them. Every `docker compose build` replaces the `:latest` tag and leaves the
previous image untagged; they accumulate one per rebuild, forever.

Prune them **as part of the deploy**, where it is known exactly what was just orphaned:

```bash
git pull && docker compose build && docker compose up -d
docker image prune -f      # removes the image the rebuild just orphaned
```

`docker image prune` without `-a` cannot remove an image any container references, running **or**
stopped — so this is safe even mid-deploy. It is worth knowing that the live container is sometimes
itself on an untagged image (a build that ran without a recreate); prune correctly leaves it alone.

Note `until` compares the image **record's** creation time, which is set when the image is orphaned —
not the config's `Created`, which a cache-hit rebuild leaves at its old value. So `until=24h` means
"orphaned more than 24h ago" even though `docker images` may print a much older CREATED column.

### When the disk is full right now

`tasks/docker-disk-gc.sh` reports and reclaims. It removes untagged images and caps each builder's
cache, and it will never run a system prune, touch volumes, or stop a container.

```bash
./tasks/docker-disk-gc.sh report      # what is using the space
./tasks/docker-disk-gc.sh --dry-run   # what it would remove
./tasks/docker-disk-gc.sh             # do it
```

It exits non-zero if the disk is still above 85% afterwards, which means Docker was **not** the
cause. Look at `sudo du -xhd1 /var /home /opt | sort -h | tail` next — journald, apt, snap revisions
and container logs are the usual suspects, and none of them are this script's business.

---

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
- The **TOTP replay guard** (a valid 2FA code is single-use for its full ~90s
  validity window — the guard remembers each accepted code, hashed, until it can
  no longer pass validation) is also per-instance: each API process keeps its own
  used-code set, so an intercepted still-fresh code could be replayed **once per
  extra instance**. With followers serving logins this weakens the single-use
  property accordingly — one more reason follower mode is not recommended.
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

---

## Pre-release / deployment security checklist

A sign-off checklist for a hardened production deployment. The implemented
controls below ship in the current release; the "verify in production" items are
operator actions.

### Implemented controls (shipped)

**Authentication & authorization**
- JWT-based authentication with secure cookies.
- Account lockout after 5 failed attempts (configurable).
- Password hashing with bcrypt (cost 12).
- Session tokens with 24h expiry.
- Admin-only routes protected by middleware.

**Input validation & protection**
- CSRF protection with token validation on admin mutations.
- Rate limiting (per-IP LRU cap; separate login/public/probe buckets — the
  thresholds are configurable, not fixed literals; see `config.env.example`).
- Request body size limits.
- SQL-injection prevention via parameterized queries (GORM).

**Network security**
- Secure HTTP headers (HSTS, CSP nonce, X-Frame-Options, X-Content-Type-Options).
- TLS support (in-process or via reverse proxy — see [`nginx.conf`](nginx.conf)).
- CORS configuration (`CORS_ALLOWED_ORIGINS`).
- Client-IP tracking for the audit log.

**Data protection**
- Secure cookie settings (HttpOnly, Secure, SameSite).
- JWT secret auto-generated and persisted if not set explicitly.
- No sensitive data in logs (`httputil.InternalError` never leaks the underlying error).
- Environment-based configuration for secrets; encrypted-at-rest stored secrets
  (AES-256-GCM).

**Deployment security**
- Rootless hardened container (dedicated `fwmon` user).
- File permissions set correctly (0600 on secret files).
- systemd service isolation (`NoNewPrivileges`, `ProtectSystem=strict`, …).

**Audit trail**
- Login-attempt logging.
- Append-only, route-template-labelled admin-action audit log.
- Trap-event logging.

### Verify in production (operator actions)

1. Change the default admin password and set a non-default `ADMIN_USERNAME`.
2. Set a strong `JWT_SECRET_KEY` (and an explicit `ENCRYPTION_KEY` — see Upgrade).
3. Enable TLS/SSL (in-process or via the reverse proxy).
4. Configure host firewall rules (expose only the ports you enable).
5. Set up log monitoring.
6. Schedule regular security reviews.
7. Keep dependencies updated (CI runs `govulncheck` on every PR).

### Smoke tests

```bash
# Rate limiting (expect 429s once the bucket is exhausted)
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/auth/login; done

# Authentication (expect 401 on bad credentials)
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'

# Admin protection (expect 401/redirect without a session)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/admin/api/dashboard

# CSRF (expect rejection without a CSRF token)
curl -s -X POST http://localhost:8080/admin/api/logout \
  -H "Content-Type: application/json"
```
