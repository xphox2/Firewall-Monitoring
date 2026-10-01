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
effect on an already-initialized install.

- **Another admin can still log in:** Settings → Users → *Reset password*
  (issues a temporary password) or *Reset 2FA*. Both also delete all of that
  user's passkeys.
- **Nobody can log in (break-glass):** run the reset tool inside the container.
  It needs no web UI and no working login:

  ```sh
  docker exec -it <container> fwmon-reset-auth --user <name>
  ```

  In one transaction it sets a new random **temporary password (printed
  once)**, flags the account to choose a new password at its next login, clears
  its TOTP 2FA and recovery codes, deletes all of its passkeys, ends every
  session of the account, and writes an audit-log row (`reset_auth`).
  `--keep-2fa` keeps the 2FA enrolment and `--keep-passkeys` keeps the
  passkeys; both are off by default. It does not re-enable a disabled account.

  Login lockouts (too many failed attempts) are kept in the API's memory, not
  the database: if the account is currently locked out, restart the container
  (`docker restart <container>`) after the reset. The tool prints this
  reminder too.

  `fwmon-reset-auth` is a wrapper installed in the image: it loads the same
  database environment `entrypoint.sh` exports (`/config/pg-credentials`, the
  Postgres socket in `/run/postgresql`, `CONFIG_FILE=/config/config.env`) and
  runs `./fwmon-api reset-auth` as the `fwmon` user. A plain
  `docker exec … ./fwmon-api reset-auth` would not have that environment.

- **The container is crash-looping (or will not stay up):** `docker exec`
  needs a running container, and the entrypoint tears the whole container down
  (Postgres included) whenever the API exits. Run the reset in a one-off
  container from the **same image** against the **same volumes** instead.
  **Stop the crash-looping container first** — two Postgres servers must never
  run on the same data directory at once:

  ```sh
  docker stop <container>
  docker run --rm -it --network none --volumes-from <container> \
    --entrypoint bash "$(docker inspect -f '{{.Config.Image}}' <container>)" -c '
      mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql &&
      su-exec postgres pg_ctl -D /data/pgdata -l /data/pgdata/postgresql.log -w start &&
      fwmon-reset-auth --user <name>; rc=$?
      su-exec postgres pg_ctl -D /data/pgdata -m fast stop; exit $rc'
  docker start <container>
  ```

  With Docker Compose the same thing is
  `docker compose stop firewall-mon` followed by
  `docker compose run --rm --no-deps --entrypoint bash firewall-mon -c '…'`
  (same quoted script as above), then `docker compose start firewall-mon`.
  The reset tool connects without running migrations, so it also works on a
  database an upgrade left half-migrated.

---

## Two-factor authentication lockout (last admin)

If a user loses both their authenticator and recovery codes, any **admin** can
clear their 2FA from Settings → Users → *Reset 2FA*. If the **last admin** is
the one locked out, use the break-glass reset above
(`docker exec -it <container> fwmon-reset-auth --user <name>`): it clears 2FA
and issues a temporary password; the user then logs in, sets a new password
and can re-enroll.

Two design notes worth knowing during an incident: **API tokens bypass TOTP by
design** (they are their own credential class — revoke them from Settings → API
Tokens if an account is suspect), and TOTP secrets are encrypted with the same
field-encryption key chain as device credentials — if `ENCRYPTION_KEY` is lost,
TOTP validation fails closed (codes stop working) and the startup canary flags
the key problem loudly (see “Failure modes”).

---

## Passkeys (WebAuthn)

Passkey login is an **additional** way in: password (+TOTP) login always keeps
working. It ships **disabled**.

- `WEBAUTHN_ENABLED=true` turns it on. Setting it back to `false` is the kill
  switch: every passkey endpoint returns 404 and the login page stops offering
  passkeys; stored passkeys are kept and work again when re-enabled.
- `WEBAUTHN_RP_ID` is the relying-party ID — a DNS name, never an IP address.
  Default: the host of `PUBLIC_BASE_URL`. Prefer the exact host users browse to.
- `WEBAUTHN_ORIGINS` is the comma-separated list of exact origins passkeys may
  be used from (`https://host[:port]`; plain `http` only for `localhost`), each
  equal to or within the RP ID. Default: the `PUBLIC_BASE_URL` origin.
- Neither value is ever derived from the request's `Host` or `X-Forwarded-*`
  headers. A value that fails validation disables passkeys with a loud
  `ERROR: passkeys DISABLED` block in the API log; the API still starts.
- Passkeys require user verification (PIN/biometric), so a passkey login is a
  full session without the TOTP step.
- Every reset path removes a user's passkeys: admin *Reset password*, admin
  *Reset 2FA*, `fwmon-reset-auth`, and a self-service password change (unless
  the request explicitly keeps them). Deleting a passkey ends the user's other
  sessions.
- Changing the RP ID orphans existing passkeys (browsers bind them to the RP
  ID); users then sign in with their password and register new ones.

### Enabling passkeys

**Requirements.** Browsers only offer passkeys to a page served over **HTTPS
from a real DNS name**. An IP address (`https://192.0.2.10`) never works,
and neither does plain `http` (except `http://localhost` for development).
Users must reach the console at exactly the name you configure.

1. **Pick the name** users type, e.g. `fwmon.example.com`, and make sure it
   resolves and serves a valid certificate (your reverse proxy terminates TLS).
2. **Set the relying-party ID to that exact host**, not a parent domain.
   `WEBAUTHN_RP_ID=fwmon.example.com` binds passkeys to this console only; a
   parent such as `example.com` would also let other sites under that domain
   request them.
3. **List every origin** users browse from, comma-separated, scheme + host
   (+ port when it is not 443): `WEBAUTHN_ORIGINS=https://fwmon.example.com`.
   An origin must be the RP ID or a subdomain of it. If `PUBLIC_BASE_URL` is
   already `https://fwmon.example.com`, both values default from it.
4. **Turn it on:** `WEBAUTHN_ENABLED=true` in `config.env`, then restart the
   API. Check the log: an invalid value prints `ERROR: passkeys DISABLED` and
   the console keeps running with passwords only.
5. **Register a passkey** from Profile → Passkeys (password, plus the 2FA
   code when 2FA is on), sign out, and use *Sign in with a passkey* on the
   login page. Keep an existing session open in a second browser until it
   works.

**Behind nginx-proxy-manager** (or any reverse proxy): the browser-facing
name is what counts, not the container address. Create an NPM proxy host for
`fwmon.example.com` → `firewall-mon:8080` with an SSL certificate and *Force
SSL*, set the RP ID and origins to that name as above, and set
`COOKIE_SECURE=true`. The RP ID and origins are **never** read from `Host` or
`X-Forwarded-*`, so no proxy header changes are needed; `TRUSTED_PROXIES`
(see "Behind a reverse proxy") is still recommended so login lockouts and the
audit log see real client IPs.

**When the button does not appear.** The login page shows *Sign in with a
passkey* only when passkeys are enabled, the browser supports them, the page
is HTTPS (a secure context), and the page's origin is in
`WEBAUTHN_ORIGINS`. Browsing by IP or by another name hides it; password
login is unaffected. `GET /api/auth/passkey/config` shows what the server
has configured.

**Kill switch.** Set `WEBAUTHN_ENABLED=false` (or remove it) and restart:
the passkey UI disappears, every passkey endpoint returns 404, and stored
passkeys are kept for when you turn it back on. Password (+TOTP) login works
throughout.

**Break-glass.** Passkeys never replace the password, so the usual recovery
applies: an admin uses Settings → Users → *Reset password* / *Reset 2FA* /
*Remove passkeys*, and when nobody can sign in,
`docker exec -it <container> fwmon-reset-auth --user <name>` (see "Admin
password reset") resets the password, clears 2FA and deletes all passkeys of
that account.

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
> **The trap:** deploying from a *fresh checkout in a
> new directory* (e.g. `/opt/firewall-mon` → `/srv/firewall-mon`)
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

### PostgreSQL memory and `/dev/shm`

The bundled PostgreSQL starts with conservative memory settings
(`entrypoint.sh` writes them only when PGDATA is first created). On a larger
host, raise them with `ALTER SYSTEM` from inside the container — it writes
`postgresql.auto.conf` and survives restarts. `ALTER SYSTEM` and
`pg_reload_conf()` need the `postgres` superuser (the app role `fwmon` cannot
run them), and `ALTER SYSTEM` cannot run inside a transaction block, so send
the statements over stdin rather than several in one `psql -c` (which runs
them as one transaction):

```sh
docker exec -i firewall-mon psql -h /run/postgresql -v ON_ERROR_STOP=1 -U postgres -d firewall_mon <<'SQL'
ALTER SYSTEM SET work_mem = '32MB';
SELECT pg_reload_conf();
SQL
```

`work_mem`, `maintenance_work_mem` and `autovacuum_work_mem` apply after
`SELECT pg_reload_conf();` (check with `SHOW` from a new session — the reload
is asynchronous); `shared_buffers` needs a container restart.
`ALTER SYSTEM RESET` removes an override, which falls back to the value
`entrypoint.sh` wrote into `postgresql.conf` or, if it wrote none, the built-in
default (`autovacuum_work_mem` = -1, which inherits `maintenance_work_mem`).
For `maintenance_work_mem` that is 64 MB, not a previously tuned value, so to
go back, `SET` the old value instead.

Check the `/dev/shm` ceiling first. Parallel queries keep their shared hash
tables and shared scan bitmaps in `/dev/shm` (`dynamic_shared_memory_type =
posix`); past it a query fails with *could not resize shared memory segment …
No space left on device* instead of completing. One parallel hash join budgets
`work_mem × hash_mem_multiplier (2) × 3 participants`, and PostgreSQL reserves
its shared memory in growing segments, so it maps roughly a third more than
that: about 254 MB at `work_mem = 32MB`. The compose file sets `shm_size: "1g"`
(Docker's default is 64 MB), which covers four concurrent parallel hash joins at
`work_mem = 32MB`; at 64 MB, two at once already reach it. How many parallel
queries run at once is bounded by client concurrency, not by
`max_parallel_workers` — a query whose workers fail to launch still allocates
the same shared memory.

`maintenance_work_mem` has the same ceiling for one case: a manual `VACUUM` is
parallel by default (on a table with at least two indexes above
`min_parallel_index_scan_size`) and reserves its whole dead-row array in
`/dev/shm` up front, sized from `maintenance_work_mem` (up to 1 GB, and never
more than the table's pages × 291 row slots, so small tables reserve less). At 1 GB that alone
fills a 1 GB `shm_size`, and the VACUUM fails at once. Keep
`maintenance_work_mem` under about half of `shm_size` — 256 MB with the
compose file's 1 GB, which leaves room for about three parallel hash joins
while a parallel VACUUM runs — and give autovacuum its own, larger budget with
`autovacuum_work_mem` (e.g. 1 GB): autovacuum never runs in parallel and keeps
its array in private memory. Parallel index builds sort in private memory and
are unaffected, but they do use `maintenance_work_mem`, so a large manual
`CREATE INDEX` should set a bigger session value itself.

For a large manual VACUUM — the Settings page suggests one after a flow
reclassification rewrites `flow_rollups` — run it serially with a 1 GB session
value. Serial VACUUM keeps its dead-row array in private memory, so it cannot
hit `/dev/shm`, and 1 GB covers ~179M dead rows in one pass over the indexes.
Parallelism buys little here anyway: each index goes to one worker, and the
primary key dominates. Run it detached so a dropped SSH session does not leave
the outcome unknown:

```sh
nohup docker exec -e PGOPTIONS='-c maintenance_work_mem=1GB' firewall-mon \
  psql -h /run/postgresql -U fwmon -d firewall_mon -c 'VACUUM (PARALLEL 0, ANALYZE) flow_rollups' \
  > vacuum-flow_rollups.log 2>&1 &
```

Do not write it as `psql -c "SET maintenance_work_mem = '1GB'; VACUUM …"`: a
multi-statement `-c` runs as one transaction, and VACUUM fails with *VACUUM
cannot run inside a transaction block*.

The persistent PostgreSQL log is `/data/pgdata/postgresql.log` inside the
container (on the data volume, so it survives recreates):
`docker exec firewall-mon grep -c 'could not resize shared memory' /data/pgdata/postgresql.log`.
Check the live cap with `docker exec firewall-mon df -h /dev/shm`; a change to
`shm_size` needs `docker compose up -d` (a recreate), not a restart.

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

**`docker system df` will point you at the wrong line.** A builder using the `docker-container`
driver keeps its cache in its own named volume, so those bytes are counted under **Local Volumes**
while the `Build Cache` row shows only the in-daemon builder. It once read `Build Cache 3.846MB`
while a container-driver builder held gigabytes. The honest number is per builder:

```bash
docker buildx ls                              # note: there is usually more than one
docker buildx du --builder <name>
```

**There is more than one builder, and the one you care about may not be the default.** On the
reference deployment `docker compose build` runs on a builder created by an unrelated project,
because that is the one selected in `~/.docker/buildx/current`. `docker builder prune` with no
`--builder` only touches `default`, so it can appear to do nothing.

### The real control is BuildKit's GC policy, not a cleanup job

BuildKit garbage-collects on its own. The reason a host still fills is that its default policy is a
**fraction of the filesystem**, and there is one such allowance *per builder*:

| Setting | Default | Consequence |
|---|---|---|
| reserved space | 10% of the fs (capped 10 GB) | |
| min free space | 20% of the fs | **eviction only begins once free space drops under 20%** |
| max used space | 80% of the fs (capped 100 GB) | **each builder may use 80% of the disk** |

Two builders at 80% each is more than the disk holds, and the min-free floor is why such a host
climbs to ~88% and then *sits* there rather than filling completely. It is not a runaway; it is the
floor doing its job, and it lands just above the app's own 85% `DISK_HIGH` line.

**The numbers in `docker buildx inspect` are computed once, at daemon or builder start, and then
frozen.** So they look arbitrary and they drift: a builder started before a disk was grown keeps
reporting fractions of the *old* size until it is restarted. Do not read them as fixed upstream
constants — read them as "80% of whatever this filesystem was when the daemon came up".

Set it to something the disk can actually hold. For the `docker` driver, `/etc/docker/daemon.json`:

```json
{
  "builder": { "gc": { "enabled": true, "defaultReservedSpace": "8GB" } },
  "log-opts": { "max-size": "50m", "max-file": "3" }
}
```

Use `defaultReservedSpace`, not the older `defaultKeepStorage` — the latter is a deprecated alias
that still works but is the spelling you will find in stale blog posts.

**Check the file's shape before restarting anything.** The daemon can parse a config without
touching the running instance:

```bash
sudo dockerd --validate --config-file=/etc/docker/daemon.json   # prints "configuration OK"
```

Treat that as a syntax check and nothing more. Keys *nested* under `builder.gc` are decoded as plain
JSON, so an unknown one is silently ignored — misspell `maxUsedSpace` and validation still passes
while the setting does nothing. **Always confirm the policy actually took with
`docker buildx inspect <name>` afterwards.** That is the only check that proves anything.

**`systemctl reload docker` cannot apply this.** The daemon's reload path covers debug, labels,
registry config, live-restore and a handful of others — not builder config. A reload will appear to
succeed and change nothing. Applying `builder.gc` needs a genuine `systemctl restart docker`, and
with no `live-restore` set that bounces **every container on the host**, so it wants a window.

For a `docker-container` driver builder, recreate it with `docker buildx create --buildkitd-config`
instead, which discards its cache — usually the intent — and touches nothing else.

A finer-grained policy is accepted too, if one number is not enough:

```json
{ "builder": { "gc": { "enabled": true, "policy": [
  { "reservedSpace": "8GB", "maxUsedSpace": "8GB", "keepDuration": "168h" },
  { "reservedSpace": "8GB", "maxUsedSpace": "8GB", "all": true }
] } } }
```

Durations are Go durations, so `168h` — **not** `7d`. There is no `d` unit and the value is rejected
outright. The same applies to `--filter unused-for=` on the command line.

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

Reclaim Docker's share without touching volumes or running containers:

```bash
docker system df                              # what is using the space
docker image prune -f                         # untagged images only
```

Then cap the build cache of **every** builder. `docker buildx prune` without `--builder` only
touches the selected builder (see the traps above), so loop over all of them:

```bash
for b in $(docker buildx ls --format json | jq -r .Name); do
  docker buildx prune -f --builder "$b" --max-used-space 10gb
done
```

`--max-used-space` is the current spelling. Older buildx releases only have `--keep-storage`, which
newer ones still accept as a deprecated alias; check `docker buildx prune --help` and substitute it if
needed. Without `jq`, run `docker buildx ls`, note each builder name (the unindented rows) and run
the `prune` line once per name.

If the disk is still above 85% afterwards, Docker was **not** the cause. Look at `sudo du -xhd1 /var /home /opt | sort -h | tail` next — journald, apt, snap revisions
and container logs are the usual suspects, and none of them are Docker's.

---

## Behind a reverse proxy (TRUSTED_PROXIES)

By default the API trusts **no** proxy headers: the client IP is the TCP peer.
Behind nginx / nginx-proxy-manager that peer is the proxy, so every user shares
one login-lockout bucket and one rate-limit bucket (one attacker's failed
logins lock everyone out for `LOCKOUT_DURATION`), and audit logs show the
proxy's IP.

Set `TRUSTED_PROXIES` to **the reverse proxy's single IP address**. The API
then reads **only** `X-Forwarded-For` — and only when the TCP peer is that
proxy; it takes the right-most address that is not a trusted proxy, so a
client-supplied `X-Forwarded-For` is ignored. Invalid entries are logged at
startup and skipped (never fatal); empty = the default behaviour.

**Never trust a whole subnet (e.g. a Docker network CIDR).** Port `8080` stays
published because remote collectors post to it directly. On Docker Desktop,
rootless Docker, and for IPv6 clients, connections to a published port reach
the container from the network's **gateway** address — which is inside the
Docker subnet. Trusting the subnet therefore lets any outside client send its
own `X-Forwarded-For` and pick the IP it is attributed to: a free pass around
the per-IP rate limit and the login lockout. Trust exactly one address: the
proxy container's, pinned so it cannot change.

**nginx-proxy-manager (docker-compose.proxy.yml):** NPM already sends
`X-Forwarded-For`. Give NPM a fixed address on a network it shares with
`firewall-mon`, e.g. a user-defined network created once:

```bash
docker network create --subnet 172.30.0.0/24 fwmon-proxy
```

then, in a compose override for NPM (and attach `firewall-mon` to the same
network in its own override):

```yaml
services:
  nginx-proxy-manager:
    networks:
      fwmon-proxy:
        ipv4_address: 172.30.0.10
networks:
  fwmon-proxy:
    external: true
```

Point the NPM proxy host at `firewall-mon:8080`, set
`TRUSTED_PROXIES=172.30.0.10` in `config.env` and restart the API. Check that
the audit log and login attempts now show real client IPs. If NPM runs on the
host network or another machine, use the single IP the API sees it connect from.

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
