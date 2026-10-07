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
   `syslog_messages` grow without bound (the #1 DB-bloat cause). Or set
   `RETENTION_SYSLOG_MONTHS` for a calendar-month window over every severity
   (see [below](#raw-archive-one-calendar-month-of-raw-syslog)).
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
- **API `/metrics` (Prometheus):** on port 8080, which is internet-facing on a
  typical install, so it is not open. `METRICS_TOKEN` unset (default): served
  only to a loopback TCP peer (`127.0.0.1` / `::1` — a scraper in the same
  container, e.g. `docker exec <container> wget -qO- http://127.0.0.1:8080/metrics`;
  a scraper on the Docker host reaches a bridge-networked container from the
  bridge gateway, not loopback, so it needs `METRICS_TOKEN` or host networking) and a plain 404 for everyone else, so the endpoint is not
  advertised. `METRICS_TOKEN` set: every request, loopback included, must send
  `Authorization: Bearer <token>` (Prometheus: `authorization.credentials`),
  anything else is 401 with a `WWW-Authenticate` challenge — a misconfigured
  scraper then shows an auth failure in its target status instead of a vanished
  target. The peer is the socket address, never `X-Forwarded-For`, so a proxy
  cannot turn a remote scrape into a local one; a scraper behind the reverse
  proxy therefore needs the token. See [monitoring/README.md](monitoring/README.md).
- **Poller / trap-receiver:** both now expose `/healthz`, `/readyz`, and
  Prometheus `/metrics` on their own listeners (`POLLER_METRICS_ADDR` default
  `:9101`, `TRAP_METRICS_ADDR` default `:9102`; set either to `off` to disable).
  Those listeners have no token check: they default to loopback, and
  `METRICS_TOKEN` does not apply to them.
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
SSL*, and set the RP ID and origins to that name as above. The session cookies
must be `Secure` for a passkey origin: with `TRUSTED_PROXIES` set to NPM's
address that happens by itself (NPM sends `X-Forwarded-Proto: https`); without
it, set `COOKIE_SECURE=true` explicitly. The RP ID and origins are **never**
read from `Host` or `X-Forwarded-*`, so no proxy header changes are needed;
`TRUSTED_PROXIES` (see "Behind a reverse proxy") is recommended so login lockouts and the
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

## Raw archive: setting it up from the admin panel

From 0.11.310 every `ARCHIVE_*` key can be set on **Settings → Retention →
Raw Archive Settings** (admins only). A value saved there wins over the
environment, and the environment (or `CONFIG_FILE`) stays the default it
falls back to:

- each field shows where its value comes from: **set here**, **environment**
  or **default** (built in);
- **Revert to env default** removes the value saved here, so the
  environment's applies again (for the secret: **Clear**);
- an install that never saves the form behaves exactly as an env-only one;
- the values are checked by the same rules as the environment (a value the
  startup check would refuse is refused on save).

The **secret access key** is write-only: it is stored encrypted with the
server's encryption key (like the SMTP password), never returned by any API
(the form shows "set (key ID ends in …XXXX)": the last four characters of
the key **ID**, never of the secret), and never written to the audit log. If the server's encryption key
changes without the old one kept in `ENCRYPTION_KEY_HISTORY`, the stored
secret can no longer be decrypted: the form says so, an enabled archive stops
(the status card's "Last failures" shows a `config` entry) until it is
entered again.

Saving asks for your password (and 2FA code) and is audit-logged as
`archive_settings_update` with the names of the fields changed, never their
values. The poller applies a save **without a restart**: its archive and
restore workers re-read the configuration every tick (a minute; 15 s for
restores) and rebuild themselves when it changed — with a fresh bucket
preflight — and the retention gate re-reads the two stream switches at most
every 30 seconds.

Step by step, for Backblaze B2 (any S3-compatible service works the same way;
the names below are placeholders):

1. **Bucket with Object Lock.** Create a private bucket with Object Lock
   (file lock) enabled — it can only be turned on at creation in most
   services. With the B2 CLI:
   `b2 bucket create --file-lock-enabled example-bucket allPrivate`. Add the
   lifecycle rules from the security notes (hide after 730 days, delete one
   day after hiding, cancel unfinished large files after 7 days); never
   shorter than the lock.
2. **A restricted application key.** Limited to the bucket and the prefix,
   with only the capabilities the archive needs and **no** `deleteFiles` or
   `bypassGovernance`:
   `b2 key create --bucket example-bucket --name-prefix fwmon/site-a/ fwmon-archive listFiles,readFiles,writeFiles,readFileRetentions,writeFileRetentions,readBucketRetentions`
   (`readBucketRetentions` lets the preflight confirm Object Lock is on).
   Note the key ID and the application key: the latter is shown once.
3. **A staging volume.** The worker writes each chunk to the staging
   directory before it uploads it; it needs at least 2 GiB free (see "the
   staging directory" below for the Docker volume). The directory must exist
   and be writable by the server before a stream can be enabled.
4. **Connection.** Enter the endpoint (`https://s3.<region>.backblazeb2.com`),
   the region (`<region>`), the bucket, the prefix (`fwmon/site-a`), the key ID
   and the secret. Leave path-style on.
5. **Object Lock.** Mode `GOVERNANCE`, days `400` (or your policy; 0 turns
   the per-object retention off).
6. **Test connection.** Runs the bucket preflight with the form's values
   without saving: it lists under the prefix and, with Object Lock days set,
   checks that the bucket has Object Lock enabled; it also checks the saved
   staging directory (a path typed into the form is checked when you save).
   It uses the stored secret unless you typed a new one — but only with the
   saved endpoint and key ID: to test another endpoint or key ID, type the
   secret in too. It uses the **saved** Advanced flags: to test a private or
   `http://` endpoint, save those flags first.
7. **Enable the streams** (syslog, flows) and Save. Enabling runs the same
   preflight and the staging check on the server; a failure refuses the save
   and nothing is stored. The status card above shows the worker's progress
   within a few minutes.

**Switching a stream off** from the form records the start of a "disabled"
interval at once (as the poller's start does): the stream's raw rows are
deleted without waiting for the archive again, and every month the interval
touches is sealed **partial**. The form warns before it saves.

**Endpoint, bucket and prefix are fixed once the archive holds a chunk**: the
manifest in the database names every object by them. The poller records that
location (`system_settings.archive_location`) and logs a WARNING at the
worker's start when the configuration names another one (a change made in
the environment). Changing any of them
from the form is refused (HTTP 409) with a pointer to the next section. The
form judges a change against that **recorded** location (since 0.11.312),
not against the configuration in effect: if the environment was changed
under the archive, saving the recorded endpoint, bucket and prefix on the
form is accepted (it puts the archive back where its chunks are), and any
third location is refused naming the recorded one. Other fields
(credentials, Object Lock days, pacing, the window, the streams) can change
at any time.

**The bucket name may be in either case** (since 0.11.311): enter it as the
storage service's console shows it — Backblaze B2 keeps the case a bucket was
created with ("Firewall-Mon") and resolves its name in any case, through its
S3 API too. A name that changes **only in case** is not a move: the poller's
location check and the form compare bucket names ignoring case (the prefix
is part of every object key, so its case still counts), and the recorded
location keeps the spelling it was first written with. Once the archive holds
chunks, the form saves such a change only after a listing under the prefix
finds the archive's objects under the new spelling — on a service that
matches names exactly (a legacy AWS us-east-1 bucket, MinIO) the re-cased
name is another bucket, and the save is refused with the service's answer.
The listing compares with the recorded spelling: entering the bucket exactly
as recorded needs none. A name that is not a DNS label (upper case, `_`, `.`)
is always sent path-style, whatever `ARCHIVE_S3_PATH_STYLE` says.

**A re-case in the environment is not checked.** The listing runs only for a
save from the form. Changing only the case of `ARCHIVE_S3_BUCKET` in the
environment is taken as the same bucket (the poller's location check ignores
the case, so it logs no WARNING): on a service that matches names exactly
the worker would then fail its preflight or reads with the service's
`NoSuchBucket` (the card's *Last failure* of `preflight`, `upload` or
`verify`). Re-case a bucket from the form, or check it with **Test
connection** first.

**Why a save or Test connection failed** is in the form's message — for a
bucket preflight, the storage service's own error code and message — and in
the server log, as `WARNING: archive settings: save refused (HTTP 422): …`
(or `Test connection refused`); the secret is never in either.

## Raw archive: moving the bucket

There is no in-place move. The manifest in the database (`archive_chunks`,
`archive_objects`, `archive_months`) records every object's key, **version
id** and checksums at its location, and each sealed month pins them in its
`_MONTH.json`. A copy into another bucket gets new version ids, so the
manifest cannot simply be pointed at it. What does not need a move:

- **Rotating the key**: create a new restricted key for the same bucket and
  prefix, enter its ID and secret, Test connection, Save. Allowed at any time.
- **Changing Object Lock days, pacing, the window or the streams**: allowed
  at any time.

The same holds for switching `ARCHIVE_TARGET` between `s3` and `local`, or
changing a local target's directory or prefix from the admin page (moving a
local target's data while keeping its container path needs no fresh start;
see "Raw archive: a local or network-share target").

To change provider, bucket or prefix anyway, the archive starts afresh at the
new location and the old bucket stays the record of what it already holds.
This is a manual procedure and is **not exercised by the test suite**: take a
database backup first (`pg_dump`), and do it in a quiet hour.

1. Wait for no restore to be running or queued (`fwmon-api archive
   --restores`); drop the ones you no longer need.
2. Switch both streams off (form or environment). Their deletes stop waiting
   for the archive and a "disabled" interval opens, so the months from now on
   are sealed partial. Leave the old bucket and its key untouched; its
   Object Lock keeps it.
3. Stop the poller, then clear the manifest in one transaction:
   `BEGIN; TRUNCATE archive_objects, archive_chunks, archive_months, archive_id_marks; DELETE FROM system_settings WHERE "key" = 'archive_worker_state'; COMMIT;`
   The gate events (`archive_gate_events`) are kept: they still mark the
   affected months partial. Do not truncate anything else.
4. Set the new location: in the form (it is no longer refused: the manifest
   is empty), or in the environment. Test connection, then switch the
   streams back on and start the poller. The archive now behaves as on its
   first enable: it archives every raw row still in the database into the
   new location (its deletes wait for that, as on a first enable — plan the
   staging space and time for the backlog, see the staging directory below).
5. The old bucket's sealed months stay checkable from the bucket alone:
   `fwmon-api archive --env-only --verify-month <stream> <YYYY-MM>` with the
   `ARCHIVE_S3_*` environment of that one command pointed at the old bucket
   (`--env-only` ignores the admin page's settings). Restores from the old
   bucket are no longer possible through the manifest.

## Raw archive: a local or network-share target

From 0.11.315 the archive can be written to a **directory** instead of an
S3 bucket: `ARCHIVE_TARGET=local` and `ARCHIVE_LOCAL_DIR`, set in the
environment or on **Settings → Retention → Raw Archive Settings → Target**.
The directory can be a dedicated local partition or a network share (NFS,
SMB). **The host mounts it; the server never mounts anything** and needs no
extra privilege or capability. Everything else is the same as with a bucket:
the same layout below the prefix (`<ARCHIVE_LOCAL_DIR>/<prefix>/<stream>/v<schema>/<YYYY-MM>/…`,
`chunk.json`, `_MONTH.json`), every object read back in full and hashed
before its rows may be deleted, the monthly seal, `--verify-month` and
restores.

### 1. Mount the volume on the host

Pick one directory on the host for everything the archive uses (here
`/srv/fwmon-archive`) and mount the partition or share there. The server
runs as **uid 100, gid 101** inside the published image (check with
`docker exec firewall-mon id fwmon`); the archive's files must be writable by
that uid/gid. Neutral examples for `/etc/fstab`:

```fstab
# A dedicated local partition (ext4 or xfs). nofail: the host still boots
# without it — the archive then waits, see below.
UUID=0000aaaa-bbbb-cccc-dddd-eeeeffff0000  /srv/fwmon-archive  ext4  defaults,noatime,nofail  0 2

# An NFS export. _netdev: mount after the network; x-systemd.automount: mount
# on first access, so a slow NAS does not hold up the boot.
nas.example.com:/export/fwmon  /srv/fwmon-archive  nfs  rw,hard,noatime,vers=4.2,_netdev,nofail,x-systemd.automount  0 0

# An SMB share. uid/gid map every file to the container user; the
# credentials file is root-only (chmod 600) and never in this repository.
//nas.example.com/fwmon  /srv/fwmon-archive  cifs  credentials=/root/.smb-fwmon,uid=100,gid=101,file_mode=0640,dir_mode=0750,_netdev,nofail,x-systemd.automount  0 0
```

Then create the directories and give them to the container user:

```sh
mount /srv/fwmon-archive
mkdir -p /srv/fwmon-archive/archive /srv/fwmon-archive/staging
chown 100:101 /srv/fwmon-archive/archive /srv/fwmon-archive/staging
```

**uid/gid on a share.** NFS maps uids as they are unless the export squashes
them: `root_squash` (the default) only affects root, so either own the
directories by 100:101 on the server, or export with
`all_squash,anonuid=100,anongid=101`. SMB has no Unix owners without the
Unix extensions: `uid=100,gid=101` on the mount makes every file appear as
the container user's. A permission error says this in the preflight, the
Test and the server log (`permission denied: the server runs as uid 100,
gid 101 …`).

**Durability on a share.** The archive counts an object as stored only after
it was fsynced and read back, so the server must really store what it
acknowledges: the **NFS export must be `sync`** (`/export/fwmon
192.0.2.0/24(rw,sync,no_subtree_check)` — with `async` the server acknowledges
writes it has not yet put on disk, and a NAS crash can lose objects the
archive has verified and whose rows retention then deletes), and the **SMB
share must honour flush** (Samba: `strict sync = yes`, the default since
4.7; on a NAS appliance, disable any "async write" / "write cache"
option for the share). The read-back on a network filesystem bypasses this
client's page cache (direct I/O, or dropping the file's cached pages after
the fsync), so it reads what the server returns, not what was just written
into local memory.

### 2. Bind it into the container under the allowed root

`ARCHIVE_ALLOWED_ROOT` (default `/archive`, **environment only**) is the
directory inside the container under which the admin page may choose the
archive directory and the staging directory; its folder picker never leaves
it, and a symbolic link that leads out of it is refused. It must be a bind
mount (the Test and the save refuse a root that is not a mount point: a
directory there would be in the container's writable layer), must not be
`/` and must not overlap the database volume `/data`. In
`docker-compose.override.yml` (next to `docker-compose.yml`, not tracked):

```yaml
services:
  firewall-mon:
    volumes:
      - /srv/fwmon-archive:/archive
```

`docker compose up -d` applies it. With systemd automount on the host, add
`:rslave` (`/srv/fwmon-archive:/archive:rslave`) so a share mounted after
the container started is seen inside it.

### 3. Choose it on the admin page

On **Raw Archive Settings**: Target `local`, then **Browse…** beside
*Archive directory* and pick `/archive/archive`; do the same for the
*Staging directory* (`/archive/staging`). **Test** probes each directory and
lists every check:

- it resolves under the allowed root and is a directory;
- a 1 MiB test file can be written, fsynced, committed under a new name
  (Test names the method: hard link, `RENAME_NOREPLACE`, or a checked
  rename that is not atomic), a second commit onto that name is refused, and
  the file is read back and removed (with the write and read times);
- free space, the filesystem type (`nfs`, `cifs`, `ext4`, `xfs`, `zfs`, …),
  whether read-only files and directory fsync work there;
- a **warning** when the archive, the staging directory or the database
  volume share a filesystem (an archive on the database's disk is no separate
  copy and fills the disk the retention protects).

Saving with a stream enabled runs the same probe after your password, then
the archive worker initialises the directory on its first pass: it creates
`<dir>/<prefix>/` and the marker file `.fwmon-archive-target` in it, which
carries this install's id (`system_settings.archive_install_id`, random). A
directory whose marker carries another install's id is refused by the
preflight and every write: **two servers must not share one archive
directory** (give each its own directory or prefix). The worker's preflight
also refuses, however the configuration was set (environment or admin
page), a directory on the container's `overlay` or `tmpfs`, and one where
neither `ARCHIVE_LOCAL_DIR` nor a directory above it up to
`ARCHIVE_ALLOWED_ROOT` is a mount point. That applies to a bare-metal
install too: there `ARCHIVE_ALLOWED_ROOT` (or `ARCHIVE_LOCAL_DIR`) must be
the mount point of the archive partition or share itself, not a directory on
the system disk.

**The archive tree must be one filesystem.** Nothing may be mounted below
`<ARCHIVE_LOCAL_DIR>/<prefix>`: an NFSv4 export with `crossmnt` children, a
ZFS dataset or a btrfs subvolume created under it puts objects on another
device than the marker, and every write there fails with "… a nested mount
below the archive directory …". Mount the share or dataset at
`ARCHIVE_LOCAL_DIR` (or above it), never inside the archive.

### How it writes

- **Crash-safe**: each object is written to a temporary file in its own
  directory, fsynced, given its final name without replacing an existing
  file, and the directory and those above it up to the prefix are fsynced.
  A crash leaves a temporary file (removed by the next write there), never a
  partial object. The final name is given by a hard link, which the kernel
  (or the NFS server) refuses atomically if the name exists; where there are
  no hard links (SMB without the Unix extensions) by `renameat2` with
  `RENAME_NOREPLACE`, also refused atomically; and only where neither works
  by a rename after checking that the name is free. That last one is **not
  atomic**: it relies on the check and on a single writer per archive
  directory (one archive worker per database, and the install id in the
  marker). Test says which one the directory uses and warns about the last.
- **The volume must stay the same during a write**: the device of the marker
  is recorded when a write starts and checked again after it; a share
  unmounted or replaced meanwhile fails the write, and the chunk is not
  verified. Writes never create the `<dir>/<prefix>` directory itself and
  never follow a symbolic link inside it.
- **Never overwritten**: a second write of a key with other bytes (a chunk
  re-exported after a mismatch) keeps the first file and writes
  `<name>.v2`, `<name>.v3`, …; the version id the manifest records is that
  number, so every verify reads exactly the bytes it wrote. A retry with the
  same bytes reuses the stored file (after hashing it in full).
- **Metadata** (the S3 headers' equivalent) is a sidecar `<name>.fwmeta`;
  copy it with the object. An object without one still reads. A sidecar that
  exists but cannot be parsed is a **mismatch**: the chunk error names the
  file, the chunk is exported again as a new version with a fresh sidecar,
  and three in a row park it in `needs_attention`. If the object itself is
  intact (its sha256 is the manifest's `sha256_object`), the broken sidecar
  may be removed; a `_MONTH.json`'s sidecar records the seal's sha256 and
  must be restored from a copy instead.
- **Read-only**: finished objects are `chmod 0444`. That only stops
  accidents: whoever owns the files (or root on the NAS) can change them.
  **Object Lock does not exist for a directory** — `ARCHIVE_OBJECT_LOCK_*`
  must be empty with a local target. For real immutability use the storage:
  ZFS snapshots on a schedule (`zfs snapshot` with a retention, or
  sanoid/zrepl), a NAS share with WORM / immutable snapshots, or a periodic
  copy to object storage with Object Lock. `--verify-month` detects any
  change to a sealed month either way.

### When the share is not there

If the share is unmounted, unreachable or stale, the container sees the
empty mount point (or I/O errors). The archive never writes there: every
write needs the marker file, and once the archive holds chunks the worker
**does not create the marker again** — its preflight fails with "… has no
.fwmon-archive-target … the archive holds chunks …", the status card shows
the failed preflight, and nothing is exported. A missing object is not
counted as lost while the marker is missing. **The retention gate holds**:
raw rows are deleted only up to what was verified, so nothing unarchived is
deleted while the share is away; the database grows meanwhile
(`RETENTION_HELD` warns). A share that goes away while the worker runs
fails its writes and read-backs the same way (retried with the bucket
backoff: 1, 5, 30 minutes, then 2 hours; never counted as a mismatch). When
the share is back the worker retries its preflight every minute and catches
up. A stale NFS handle (`ESTALE`) needs a remount on the host and
a container restart.

**Monitoring**: the same as for a bucket — the status card and
`fwmon-api archive --status`, `fwmon_archive_lag_seconds`, the
`ARCHIVE_LAG`, `ARCHIVE_NEEDS_ATTENTION` and `RETENTION_HELD` alerts. Watch
the share's free space on the host; the staging directory's floor is
checked by the worker (2 GiB).

### Moving or switching

Once the archive holds chunks the target type, the directory and the
prefix are fixed on the admin page (409), like a bucket's endpoint. To move
the data to another disk or NAS, keep the **container path**: copy the tree
with the file names unchanged (`rsync -a`, sidecars included — the version
ids are the file names, so the manifest stays valid), remount the new
volume at the same host path or change the bind mount's host side, and run
`fwmon-api archive --verify-month` on a sealed month. Switching between S3
and a local target is refused with chunks present; it is the fresh start of
"Raw archive: moving the bucket" below.

## Raw archive: the staging directory

When `ARCHIVE_SYSLOG_ENABLED` or `ARCHIVE_FLOWS_ENABLED` is on (v0.11.302+;
in the environment or, since 0.11.310, on the admin panel),
the poller's archive worker writes each chunk's compressed objects to
`ARCHIVE_STAGING_DIR` between the export and the upload (a day of syslog is
roughly 0.3–0.7 GB compressed), and deletes them once the chunk is uploaded.
The key is **required** — there is no default: a temp directory inside the
container would land in its writable layer, usually on the same disk as the
PostgreSQL data. A chunk is not exported while the directory has less than
2 GiB free, or when its free space cannot be read.

Mount a dedicated volume, ideally on a different disk from `/data`, and point
the key at it. With the bundled `docker-compose.yml`, add to the
`firewall-mon` service:

```yaml
    environment:
      - ARCHIVE_STAGING_DIR=/archive-staging
    volumes:
      - ${ARCHIVE_STAGING_HOST_DIR:-./archive-staging}:/archive-staging
```

From 0.11.315 a staging directory chosen on the admin page (with
**Browse…**) must be under `ARCHIVE_ALLOWED_ROOT` (default `/archive`); one
set before outside it, like `/archive-staging` above, keeps working while it
is not changed. To keep staging on another disk than the archive, bind-mount
that disk *inside* the root as well, e.g.
`- ${ARCHIVE_STAGING_HOST_DIR}:/archive/staging` below the archive volume's
line — Test then shows the two on different filesystems.

The worker only ever removes `chunk-<n>` entries from that directory (left
over by an interrupted run, on the next start), so a shared directory is safe,
but a dedicated one is easier to watch. `ARCHIVE_WINDOW` (`HH:MM-HH:MM`,
**UTC**) confines syslog exports to a time of day, e.g. a first backlog to the
night; flows always run.

A chunk whose read-back or count check fails three times is parked with
status `needs_attention` and no longer retried (every retry writes another
Object Lock-retained copy). Watch `fwmon_archive_chunks{status="needs_attention"}`
and `fwmon_archive_needs_attention_total` on the poller's `/metrics` (since
0.11.308 the `ARCHIVE_NEEDS_ATTENTION` alert fires on it); the chunk's
`error` column in `archive_chunks` says what differed.

## Raw archive: the retention gate

From 0.11.304, while `ARCHIVE_SYSLOG_ENABLED` (or `ARCHIVE_FLOWS_ENABLED`) is
on, a raw row of that stream is deleted only after the archive has verified
it. For each table the poller derives **V**, the `id_hi` of the last chunk in
the run of `verified` chunks that starts at seq 1 with no gap
(`fwmon_archive_verified_through_id{table}`); every delete path takes only
rows with `id <= V`:

| path | gated as |
|---|---|
| `syslog_messages` retention (daily batched DELETE) | `AND id <= V` |
| `syslog_messages` / `flow_samples` monthly partition DROP | only when the leaf's `max(id) <= V` (checked again inside the DROP's lock); a held leaf is kept and its archived rows are row-deleted |
| severity 6/7 aggregation (every 5 min) | watermark capped at V: held rows are neither summarised nor deleted |
| flow rollup (every 5 min) | watermark capped at V: held raw flows are neither rolled up nor deleted (flow pages union raw rows and rollups, so they stay counted) |
| `flow_samples` / `flow_if_counters` retention | `AND id <= V` |
| device purge | **not gated** |

On PostgreSQL the gated statements also carry the newest message time of the
verified chunks (`timestamp <= …`), which every row at or below V satisfies
anyway; it lets the planner skip the held rows instead of walking them.

**Partition maintenance.** When the daily partition pass finds rows of a
month (or day) still in a table's DEFAULT child, it moves them into a new leaf
that stays a standalone table until the move is done — and until the next
pass if the attach fails. Rows in it cannot be seen through the parent, so
while any unattached `<table>_YYYYMM[DD]` table exists the archive worker does
not cut, export or count that table
(`fwmon_archive_unsettled{reason="unattached_leaf"}`), an export or a count
during which a move started is discarded and simply retried later (never a
mismatch, so it cannot park a chunk), and the gate deletes nothing of the
table. A
leftover standalone table with such a name (a manual rescue, say) holds the
table the same way until it is attached or renamed.

A chunk that is pending, exporting, uploading, verifying, failed or
`needs_attention` stops V, and so does a gap. Normally V trails ingest by
about a day for syslog and counters and by 10–20 minutes for flows, far less
than the windows, so nothing is held. When the archive lags (bucket down,
credentials revoked, a parked chunk) the tables grow past their window
instead: syslog by its daily volume, raw flows by about 160 000 rows an hour.
The poller logs at startup which tables are gated, and warns when a stream is
disabled although `archive_chunks` has chunks of it (its deletes are then
ungated again, exactly as before the archive). There is **no automatic
bypass** when the disk fills: `SERVER_DISK_HIGH` pages at the free-space floor.

### Releasing the gate (time-limited override)

If the archive cannot catch up before the disk runs out, an admin can release
one stream's gate (`syslog`, `flows` or `all`) for at most 24 hours. Rows
deleted while it is released may never reach the archive, so the reason is
required and recorded:

```
docker exec <container> fwmon-api archive --override flows --for 6h --reason "bucket outage, disk at 92%"
docker exec <container> fwmon-api archive --override flows --clear          # re-engage now
docker exec <container> fwmon-api archive --gate-status                     # overrides + parked chunks
docker exec <container> fwmon-api archive --status                          # the whole archive (0.11.308)
```

or `POST /admin/api/archive/override` (`{stream, hours: 1..24, reason,
password, totp_code}`; admin-only, re-authenticated like the purge;
`hours: 0` re-engages without a password) and `GET /admin/api/archive/override`.
The override is the system setting `archive_gate_override_until_<stream>`, an
end time: it expires on its own (a value more than 24 h ahead is ignored), the
settings page cannot write it, every change is an `audit_logs` row
(`archive_gate_override`, actor `cli` for the command line), and the poller
logs a WARNING (at most once a minute per table) while deletes run ungated
under it. The gate is re-read before every retention batch and every partition
drop, so an override that ends or is cleared mid-pass stops the ungated
deletes at the next batch. The CLI needs the
server's database credentials (like `reset-auth`), which is its
authentication; the API route re-verifies the operator's password and TOTP.

### A chunk stuck in `needs_attention`

A chunk whose read-back or count check failed three times is parked in
`needs_attention` and never retried on its own — and it stops V, so its
table's deletes stay held until someone acts. Find out why from its `error`
(`fwmon-api archive --gate-status` lists the parked chunks), fix the cause
(bucket policy, Object Lock settings, a proxy rewriting bodies, …), then put
it back in the queue:

```
docker exec <container> fwmon-api archive --reset-chunk <id> --reason "bucket policy fixed"
```

or `POST /admin/api/archive/chunks/:id/reset` (`{reason, password,
totp_code}`; admin-only, re-authenticated). The chunk returns to `pending`
with its mismatch and verify counters cleared; the worker exports, uploads and
verifies it again on its next pass (up to three more mismatches before it is
parked again; each attempt writes another Object Lock-retained copy). Only a
`needs_attention` chunk can be reset, and every reset is an `audit_logs` row
(`archive_chunk_reset`).

## Backfilling the normalized tables (one-time, 30 days)

The normalized tables (`net_events`, `sec_events`, `fw_rules`,
`device_field_observed`; v0.11.295) are written by the syslog ingest from the
moment v0.11.296 started (the `normalize_ingest_started_at` setting, written
once and never moved). The raw rows received before that can be normalized
after the fact, **once**, by the backfill job (v0.11.297):

```
docker exec <container> fwmon-api normalize-backfill --since 30d        # queue
docker exec <container> fwmon-api normalize-backfill --status           # progress
docker exec <container> fwmon-api normalize-backfill --cancel | --resume
```

or `POST /admin/api/normalize/backfill` (`{since_days, device_id?,
rate_rows_per_sec?, window?, password, totp_code}`; admin-only and
re-authenticated like the purge). What to expect:

- **Window.** `since` is at most 30 days back from now and never before the
  oldest `net_events` day leaf (a row older than the retention lookback would
  land in `net_events_default`); `until` is always the ingest watermark. A
  device-scoped job (`--device`) walks only that device's rows.
- **Load.** The poller runs it (within 15 s of queueing), one job at a time,
  under its own advisory lock, in batches of 5 000 raw rows read oldest-first
  from each `syslog_messages` leaf through its `(timestamp)` index (an index
  scan under an incremental sort that only orders rows sharing a timestamp by
  id — never a sequential scan), and held to `--rate` rows per second
  (default 2 000: about 90 M rows in 12.5 h). A leaf with no usable
  `(timestamp)` index (for a `--device` job, `(device_id, timestamp)` also
  serves) is never seq-scanned: the job stops `failed` with a WARNING in the
  log, the reason in its `error` and its cursor parked at the start of that
  leaf — create the index, then `--resume` (or the API's resume) and it
  continues from there. `--status` and the status API name that next step
  for a failed or cancelled job. Writes are one
  COPY per batch into the day leaves. A cancel lands within about a second,
  even mid-sleep at a low rate. Set `--window 22:00-06:00` (server local time; or the
  `normalize_backfill_window` setting as the default) to run at night: outside
  the window the job shows `paused` and waits.
- **Disk.** The job is refused when the data volume's free space is under
  twice the estimated write (received rows in the window × 0.5 KB; see the
  Retention page for the measured per-row cost once a few days have landed).
  `--resume` re-runs the check over the part of the window still to go. Only
  a `server_metrics` sample from the last 15 minutes counts; with none, free
  space is unknown and the check does not block.
  Plan on ~35 % of the raw syslog volume of the window.
- **Exactly once.** A raw row is in scope only when both its message time and
  its arrival (`created_at`) precede the watermark, and every batch checks the
  typed tables for rows the live ingest already wrote; each batch's rows, its
  `fw_rules` catalog rows and the cursor commit in one transaction. Re-running a finished backfill writes
  nothing (`rows_skipped` counts the rows it found already normalized), a
  crash or restart resumes from the committed cursor, and cancel keeps the
  cursor so `--resume` continues where it stopped.
- **Rollups.** When a job that wrote rows ends, the rollup cycle rewinds its
  closed-day cursor to the day before the window and recomputes the
  backfilled days exactly over the following ticks (two days per 5-minute
  tick); `distinct_src` is a lower bound for a day until its recompute lands.
- **Not touched.** `denied_events` and the alert rules (live-stream
  consumers), raw syslog, and anything the live ingest has normalized — in
  `fw_rules` an older sighting only fills columns still empty, so a rule
  renamed since keeps the name the live ingest saw.
  `device_field_observed.last_seen` takes the event time, so the capability
  matrix does not report a field "observed in the last 24 h" because of a
  month-old row.
- **Rollback.** Cancel the job. Backfilled rows live in the day leaves of
  their event time; a leaf before the watermark's day holds backfilled rows
  plus whatever the live ingest wrote there late (a replayed collector
  spool), so `DROP TABLE net_events_YYYYMMDD` removes both — acceptable when
  the backfill must be undone, and the retention pass drops the leaf on
  schedule anyway (the partition pass recreates an empty leaf inside the
  lookback). Nothing outside the normalized tables is touched.

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
  and prefer `RETENTION_SYSLOG_INFO_DAYS` low (informational syslog is
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

## Raw archive: one calendar month of raw syslog

`RETENTION_SYSLOG_MONTHS=N` (0.11.306; 0-120, default 0 = off) keeps raw
syslog of every severity for N calendar months. The cutoff is the same UTC
time N months earlier, clamped to that month's last day, so one month is 28-31
days (31 March keeps back to 28 or 29 February; Go's plain month arithmetic
would have kept only to 3 March). It replaces `RETENTION_SYSLOG_CRITICAL_DAYS`,
`RETENTION_SYSLOG_INFO_DAYS` and `RETENTION_SYSLOG_DAYS`, which are ignored
while it is set; the API and the poller log a startup NOTICE naming them with their
values. A malformed or out-of-range value refuses to start. Windows set on the
Retention page (per severity or the default) still take precedence; while one
does, every daily cleanup logs a WARNING naming the severity and its window
(`severity 5 uses Retention-page 7d, not RETENTION_SYSLOG_MONTHS=1 …`) — clear
the page setting to follow the months.

- The daily cleanup and the 5-minute severity 6/7 aggregation use the month
  cutoff; severities 6-7 stay raw for the month and are then summarised.
- On a partitioned `syslog_messages` (fresh installs) a monthly leaf is dropped
  once its whole month is older than the cutoff (October's leaf on 1 December);
  the leaf the cutoff falls in is trimmed by the row DELETE.
- With `ARCHIVE_SYSLOG_ENABLED` every one of those deletes still takes only
  rows at or below V (see [the retention gate](#raw-archive-the-retention-gate)):
  a leaf is dropped only when its `max(id) <= V`.
- Setting it back to 0 restores the day windows exactly.

**Production with the archive.** A compose or env file that sets
`RETENTION_SYSLOG_CRITICAL_DAYS=30` (as the example
[`docker-compose.yml`](../docker-compose.yml) does) keeps 30 days. To keep a
rolling month instead, set `RETENTION_SYSLOG_MONTHS=1` and remove
`RETENTION_SYSLOG_CRITICAL_DAYS` **in the same deploy that enables
`ARCHIVE_SYSLOG_ENABLED`**, not before: until the archive runs, the 30-day
window stays as it is. Leaving the old key in place is harmless (it is
ignored and named in the NOTICE) but misleading to the next reader. One month
against 30 days is at most one extra day of raw syslog at peak.

## Raw archive: the monthly seal

From 0.11.307 the archive worker closes each stream's month folder
(`<prefix>/<stream>/v<schema>/<YYYY-MM>/`) once the month is over: at the
first pass at or after the 1st of the next month, 00:00 UTC, plus
`ARCHIVE_SEAL_GRACE_HOURS` (default 48, 6–168). Months seal oldest first, per
stream (`syslog`, `sflow`, `netflow`, `sflow-counters`):

1. **Completeness** (database): every chunk cut for the month is `verified`;
   their seq, id ranges and periods are gapless; the last one ends exactly at
   the 1st of the next month; the first continues the previous month's last
   chunk, and that month is sealed with that id as its `last_id`.
2. **Re-verification** (bucket): every object of the month is HEADed (size,
   ETag, Object Lock) — `ARCHIVE_SEAL_REVERIFY=full` also reads each one back
   and re-hashes it — and every `chunk.json` must be byte for byte the one the
   database describes.
3. **`_MONTH.json`**: the chunk list with every object's key, version id,
   `sha256_object`, `sha256_content` and row count, each `chunk.json`'s
   version and hash, the totals, the message-day histogram and the month
   digest (how it is computed is written into the file). It is uploaded with
   Object Lock, read back, and only then is the month recorded `sealed` in
   `archive_months`. After that the worker refuses any write into the folder
   (a chunk of a sealed month being worked again — only possible by editing
   the database — is parked `needs_attention`, and
   `fwmon_archive_sealed_write_refused_total` counts it; see the recovery
   steps below).

**An incomplete month is never sealed.** It is recorded `seal_failed` with
the reason in `archive_months.error`, `fwmon_archive_seal_blocked{stream,reason}`
says which (`incomplete`, `needs_attention`, `gap`, `objects`, `reverify`,
`conflict`, `bucket`), the later months of the stream wait behind it, and the
stream is tried again after a backoff (1, 5, 30 minutes, then every 2 hours —
a refusal that persists is not re-verified, or with `full` re-downloaded,
every pass). A `_MONTH.json` the archive did not write is found before any
object is re-checked and never overwritten (`conflict`).
`fwmon_archive_months_sealed_total{stream}` counts the seals.

**Alert on `fwmon_archive_month_unsealed_days{stream}`**, the days the
stream's oldest closed month that is not sealed is past its seal time (the 1st
+ the grace); 0 when every due month is sealed. A refusal for a day or two
after the grace is normal (a syslog backlog still being verified), so
`seal_blocked` alone is noisy. Since 0.11.308 the built-in
`ARCHIVE_SEAL_OVERDUE` alert does this (default: more than 3 days; see
[status and alerts](#raw-archive-status-and-alerts)).

**The first archived month is PARTIAL.** The month the archive of a table
began in (its first chunk starts at id 0) is sealed with `"partial": true`,
`first_row_id` (the first archived row) and a note: rows ingested before the
archive began were deleted by retention first, and the archive cannot list
them. On production that is September 2026 for syslog (its first chunk is the
oldest ingest day still on the server) and the enabling month for the flow
streams (raw flows live about an hour).

**A month the gate did not fully protect is PARTIAL too.** Rows deleted while
a stream's gate was released (an override) or its archiving was disabled
never reach the archive and vanish from both sides of the chunk's count
check, so nothing else could tell. Every override (`archive --override`, the
API route) and every poller start with a disabled stream that already has
chunks is recorded in `archive_gate_events` (migration v77; an enabled start
ends the open `disabled` interval). A month whose archiving — from its first
day to the verification of its last chunk — overlaps such an interval is
sealed with `"partial": true` and the intervals in `"degraded"`
(`{kind, from, to}`, clamped to that window). If an interval cannot be
recorded at the poller's start, that disabled stream's deletes stay **gated**
(logged as an ERROR) until the record succeeds — retried every minute, from
the start time — so nothing is deleted ungated without the seal knowing.

Two more kinds are conservative, because the past cannot be reconstructed:

- `before_archive`: from the month's start to when the table's archive began
  (its first chunk verified). Before that nothing waited for the archive —
  retention, and the severity 6/7 aggregation after 7 days, may have removed
  rows of the month. So the month the archive is enabled in is partial
  whatever day it is enabled on; on production, if it is enabled in October,
  **November is the first full month** (and October is partial even if its
  backlog is complete — its first days' severity 6/7 rows may already have
  been summarised).
- `unrecorded`: if the archive began before migration v77 was applied, a
  disabled period before v77 would not have been recorded, so the time from
  the archive's start (or the month's start) to v77 is listed. v77 rebuilds
  the overrides made before it from their `archive_gate_override` audit rows;
  disabled periods have no such record. On an install that enables the
  archive with this release, v77 comes first and nothing is listed.

The seal is the month-level completeness proof, **not a delete gate**: raw
rows are deleted as soon as their chunk is verified (the retention gate
above).

**Checking a sealed month** — from the bucket alone, no database needed:

```
docker exec <container> fwmon-api archive --verify-month syslog 2026-09
```

It downloads `_MONTH.json` (its ETag and the sha256 recorded at the seal),
re-derives the chain, the totals and the month digest, downloads every
`chunk.json` and every object by the version the manifest pins, and checks the
stored bytes, the decompressed content hash, the row counts and that every
line is JSON with an id inside its chunk. It only reads (GET requests) and
prints one line per chunk and a summary; the exit code is 0 only when every
check passed. Expect it to read the whole month (about 9–21 GB of syslog);
on Backblaze B2 downloads up to three times the stored volume a month are
free. It also fails when `_MONTH.json` has more than one stored version (the
seal writes it once), when the month does not join the sealed months beside
it (the previous one's `last_id` is this one's `first_id`, and it must exist
unless this is the archive's first month), or when `partial` does not match
(true exactly for the first month — from id 0, seq 1 — or a degraded one).

### Recovering a month that cannot be sealed

A month that stays refused holds back every later seal of its stream (each
month proves it joins the previous one) — the deletes are not affected,
they follow the verified chunks.

- **`conflict`: a `_MONTH.json` the archive did not write.** Download it and
  find out where it came from (another install writing to the same
  `ARCHIVE_S3_PREFIX` is the usual cause — give each install its own prefix).
  The archive's key cannot delete, by design. With Object Lock GOVERNANCE, an
  administrator key with `deleteFiles` and `bypassGovernance` (B2) or
  `s3:BypassGovernanceRetention` (AWS) can delete that file's versions; the
  next pass after the backoff seals the month. Under COMPLIANCE nobody can
  remove it before its retain-until date: the month stays unsealed (its
  chunks are still archived and verified individually) and, until then, so
  do the stream's later months — `month_unsealed_days` keeps rising and its
  alert should be acknowledged with that reason.
- **`reverify`: a stored object or `chunk.json` changed.** Objects are
  checked by the version the archive wrote (`archive_objects.version_id`),
  which Object Lock keeps; a `chunk.json` is checked by its latest version.
  Something else wrote into the prefix: find and stop it, then make the
  archive's version the latest again (copy that version over the key with an
  administrator key); the next pass after the backoff seals the month. If the
  archive's own version is gone (only possible with a key that bypasses the
  lock, or on a bucket without versioning), the month cannot be proven and
  stays unsealed — re-exporting a verified chunk is not supported.
- **A parked chunk of a SEALED month** (`fwmon_archive_sealed_write_refused_total`
  rose; only possible after the database was edited). It does not hold the
  retention gate when its id range lies inside the `(first_id, last_id]`
  recorded for that month (for every stream of its table; otherwise it does):
  the month was sealed only after every one of its chunks was
  verified and re-checked, `_MONTH.json` pins those objects under Object
  Lock, and the worker refuses the chunk before it changes anything. The A-5
  reset refuses it (`fwmon-api archive --reset-chunk` and the API answer that
  the chunk belongs to a sealed month). Confirm the month with
  `archive --verify-month <stream> <YYYY-MM>`, then put the row back:
  `UPDATE archive_chunks SET status = 'verified', error = '' WHERE id = <id>;`
  (its objects were left verified).

## Raw archive: status and alerts

From 0.11.308 the archive's whole state is in one place:

- **Settings → Retention → Raw Archive** (admins), refreshed every 15 s while
  the page is open (paused while the browser tab is hidden), top to bottom:
  - banners for whatever needs you: a stream's gate released by an override
    (with **Re-engage now**), a retention gate that cannot read the stream
    switches, chunks parked in `needs_attention` or waiting for a retry, a
    stale worker, a bucket preflight that has not passed, a staging
    directory below its floor;
  - **Now**: the chunk the worker is working (table, period, stage —
    exporting with the rows read and the share of its id range, uploading /
    reading back with objects and bytes — and how long the stage and the
    chunk have run), or a settling chunk's countdown, or *Idle*; and when the
    last pass ran and the next one is due;
  - **Tables**: per table the planned chunks verified of the total (a bar),
    the chunks left and the oldest period among them, an upper bound of their
    rows (their id span), the rate (rows per second of work over the last ten
    verified chunks) and the work left at that rate, *caught up* / *up to
    date* (one chunk left: the newest) / *catching up*, the lag, why the next
    chunk waits, how far past its window the gate holds unarchived rows. Only
    planned chunks count: a long backlog of hourly flow chunks is planned 64
    at a time, so its total grows while it catches up;
  - **Recently verified**: the last ten chunks with rows, objects, size and
    how long each took;
  - **Waiting for a retry** (failed chunks, with the error and the retry time)
    and **Needs attention** (parked chunks, each with a **Reset**: reason +
    password + 2FA code, like the purge);
  - **Streams and months**: per stream the verified rows and bytes in the
    bucket (a sealed month's from its seal, the others' from their verified
    objects), the next month to seal and when it is due, and the month
    folders (pending, due, sealed, `seal_failed`, partial, gate events) with
    their archived rows and bytes;
  - the worker's last failure per stage (collapsed).

  Banners are polite status regions, and a refresh rewrites only the
  sections that changed, so a focused button keeps its focus. Every read
  behind the card is bounded by what it shows, not by the archive's age
  (migration v79 adds two partial indexes on `archive_chunks`; the totals
  read only the months not sealed yet).
- `docker exec <container> fwmon-api archive --status` prints the same
  (`--status --json` the API's JSON), and `GET /admin/api/archive/status`
  serves it (admin-only). The configuration shows the key id's last four
  characters only; the secret never appears.

The worker's own state (why a chunk waits, last failures, staging space,
preflight, the current chunk's progress, the last and next pass) is written
by the poller to the system setting `archive_worker_state` about once a
minute while it holds the archive lock, and every 15 s while a chunk makes
progress. "Stale" means it has not written for 15 minutes: no poller is
running the archive worker (down, wedged, or archiving disabled in its
environment).

**Settling.** Every cut waits out a settle window (`DB_STATEMENT_TIMEOUT` +
5 s, at least a minute) before its chunk is exported. The worker checks a
settling chunk again on the first tick (a minute) after the window ends, and
a chunk held by an open writing transaction on every tick, instead of
waiting for its next 10-minute pass; the card counts the window down.

**Long passes.** A pass works chunks for as long as any table has work — a
first syslog backlog of 30 days at about 20 minutes a day is one pass of
about ten hours. Between two chunks it plans again, at most once a minute,
every table it had run out of work for (nothing planned yet, its next
chunk settling or held by a writer, a failed chunk past its backoff, a
bucket failure's cooldown over), flows first, so each hourly flow chunk
and daily counter chunk is verified within one syslog chunk of becoming
due and flow lag stays near an hour. (Before 0.11.313 a pass planned each
table only at its start: through a long backlog the flow tables got no new
chunk, their raw rows were held by the retention gate and the flows'
`ARCHIVE_LAG` (3 h) could fire.) A syslog chunk is not interrupted, so a
syslog day that takes more than about two hours to export still delays
flows past that alert: raise `ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC` or confine
syslog to `ARCHIVE_WINDOW`. A table whose settle check or database read
failed, or that cannot be cut, waits for the next pass, as before. While a pass
runs the card shows *Pass running since …* (and *Planning the next chunk*
between two chunks) and `--status` prints `pass running since …`.

**Alerts.** The poller evaluates six alerts on its 5-minute server-health
tick, device-less like `SERVER_DISK_HIGH` (they show as *Firewall-Mon
server*). Each has a seeded event rule (*Default: Archive …*, *Default:
Retention held …*) with a 6 h re-notify cooldown, recovers with a recovery
notification, and is tuned on the **Alerting** page (global defaults; 0 turns
one off, blank uses the default):

| alert | per | fires when | default |
|---|---|---|---|
| `ARCHIVE_LAG` | table (sflow and netflow share `flow_samples`: one alert names both) | the table's verified data is further behind than the threshold. **Daily tables (syslog, sflow-counters) must stay above it for an hour**: their day is cut 2 h after midnight UTC and then exported, so their lag passes 26 h briefly every day. An enabled table that has cut **no chunk at all** (typically a bucket that never passes the preflight) fires once that has lasted longer than the threshold — the gate holds every raw row of its table meanwhile | syslog 26 h, sflow/netflow 3 h, sflow-counters 26 h |
| `ARCHIVE_NEEDS_ATTENTION` | table | a chunk is parked in `needs_attention` | always on |
| `ARCHIVE_SEAL_OVERDUE` | stream | the oldest closed month is still not sealed this many days after its seal time (`fwmon_archive_month_unsealed_days`) | 3 days |
| `RETENTION_HELD` (critical) | table | the gate is on and holds unarchived rows more than this far past the table's window (syslog: its shortest severity window; raw flows: the rollup's 1 h; counters: `RETENTION_FLOW_DAYS`) **and** the database volume is growing (free space below the sample 1–3 h earlier; counted as growing when the volume cannot be measured). The growth only fires it: once active it stays until the hold clears, whatever the free space does meanwhile | 6 h |
| `ARCHIVE_UNSETTLED_LONG` | table | the next chunk has waited this long for an open writing transaction, an unattached partition leaf, or a `statement_timeout` (needs a fresh worker state; a stale one leaves the alert as it is) | 6 h |
| `ARCHIVE_GATE_UNREADABLE` | (one) | the poller's retention gate has failed to read the archive's stream switches (`system_settings`) for longer than 15 minutes. Evaluated from the gate itself, even where the archive was never enabled, and even when the rest of the status cannot be read. Field `holding`: `all` — no read has succeeded since the poller started, so every archived table's deletes are held; `last` — the gate keeps the switches it read last, so a stream switched on or off on the admin page is not applied | 15 min (fixed) |

Settings keys: `archive_lag_alert_hours_syslog`, `archive_lag_alert_hours_flows`,
`archive_lag_alert_hours_counters`, `archive_seal_overdue_alert_days`,
`retention_held_alert_hours`, `archive_unsettled_alert_hours` (0–720).
While the status cannot be read whole (a database error, including the gate
override settings), no archive alert fires or resolves.

### Runbook

- **`ARCHIVE_LAG`** — open the Raw Archive card. *Last failures* names the
  stage: `preflight` / `upload` / `verify` / `manifest` (the bucket: endpoint,
  key, bucket policy, Object Lock settings, a proxy), `read` / `db` (the
  database), `stage` (the staging directory: below its 2 GiB floor, or not
  writable). A *Waiting* entry points at `ARCHIVE_UNSETTLED_LONG` below; a
  parked chunk at `ARCHIVE_NEEDS_ATTENTION`. A stale worker: check the poller
  is running and logs `archive: worker started` (`docker logs`). Nothing is lost while the archive lags; raw rows are kept
  instead (watch `RETENTION_HELD`). For flows, held raw rows are not rolled up
  until archived, so flow pages get slower, not wrong.
- **`ARCHIVE_NEEDS_ATTENTION`** — the chunk's error says what differed (see
  [A chunk stuck in `needs_attention`](#a-chunk-stuck-in-needs_attention));
  fix the cause, then **Reset** it on the card or
  `fwmon-api archive --reset-chunk <id> --reason "…"`. *holds deletes* means
  its table's raw deletes wait for it. A parked chunk of a sealed month cannot
  be reset (see [Recovering a month that cannot be sealed](#recovering-a-month-that-cannot-be-sealed)).
- **`ARCHIVE_SEAL_OVERDUE`** — the month's error (card, `--status`, or
  `archive_months.error`) and `fwmon_archive_seal_blocked{reason}` say why; see
  [Recovering a month that cannot be sealed](#recovering-a-month-that-cannot-be-sealed).
  `incomplete` usually clears by itself once the month's last chunks verify.
  Deletes are not affected.
- **`RETENTION_HELD`** — the database is growing because the archive is
  behind. Fix the archive first (`ARCHIVE_LAG`). If the disk will not last
  until it catches up, release the stream's gate for a few hours — rows
  deleted meanwhile may never reach the archive, and the months they belong
  to are sealed PARTIAL:
  `fwmon-api archive --override syslog --for 6h --reason "disk at 90%, bucket outage"`.
  `SERVER_DISK_HIGH` still pages at the free-space floor.
- **`ARCHIVE_UNSETTLED_LONG`** — by reason: `open_writer`: a transaction
  older than the chunk's cut is still open; the detail names its session (pid,
  application, state, start) when visible — end it (`SELECT
  pg_terminate_backend(<pid>)` after checking what it is), commonly an
  `idle in transaction` client. `unattached_leaf`: a partition leaf is being
  moved (see [the retention gate](#raw-archive-the-retention-gate)); if it
  persists, the next partition pass failed to attach it — check the poller log.
  `no_statement_timeout`: set `DB_STATEMENT_TIMEOUT` (the archive cannot
  settle a cut without one).
- **`ARCHIVE_GATE_UNREADABLE`** — the message carries the database error.
  The gate retries every few seconds and the alert recovers on the first
  read that succeeds. Check the poller's database connection and that
  `system_settings` is readable by its role. With `holding=all` raw rows
  accumulate meanwhile (watch `SERVER_DISK_HIGH`); nothing is deleted
  ungated.

## Raw archive: restore to a staging table

From 0.11.309 archived rows can be brought back — **into a staging table of
their own, never into `syslog_messages`, `flow_samples` or
`flow_if_counters`** (restoring there would collide with retention, the gate
and the rollups). A restore covers one stream and a range of **message-time**
UTC days (up to 31), optionally one device:

```
docker exec <container> fwmon-api archive --restore syslog --from 2026-10-04 --to 2026-10-04 [--device 7]
docker exec <container> fwmon-api archive --restores                 # progress, staging tables and sizes
docker exec <container> fwmon-api archive --cancel-restore <id>      # stops between batches, cursors kept
docker exec <container> fwmon-api archive --resume-restore <id>      # a failed / cancelled restore continues
docker exec <container> fwmon-api archive --drop-restore <id>        # drop the staging table now
```

or `POST /admin/api/archive/restores` (`{stream, from, to, device_id?,
renormalize?, replace?, from_bucket?, rate_rows_per_sec?, ttl_days?,
password, totp_code}`), `GET /admin/api/archive/restores`,
`POST /admin/api/archive/restores/:id/cancel`, `…/:id/resume` and
`DELETE /admin/api/archive/restores/:id` — admin-only; queue, resume and drop
re-verify the password (+ 2FA code) and every action is audit-logged. The
poller runs the restores (within 15 s, one at a time, under its own advisory
lock); it needs `ARCHIVE_S3_*` and `ARCHIVE_STAGING_DIR`, not an enabled
stream.

What happens:

- **Selection.** Each archived object records how many of its rows fall on
  each message day, so the restore takes exactly the objects that hold rows
  of the requested days — usually that day's and the next day's (a row is
  filed under the day it was *received*), plus any a device with a skewed
  clock spread further. It reads the database manifest (every verified
  object, sealed month or not). `--from-bucket` selects from the bucket's
  sealed months instead (`_MONTH.json` of the month before through the month
  after the range, each checked against its ETag and the sha256 recorded at
  the seal) for a database that lost its manifest; the job's note lists the
  months it could not search. The note also says when the archive is not yet
  verified past the requested days (later-received rows of them are then
  still only in the live table).
- **Disk.** Refused when the rows to stage (syslog ~1.3 KB, flows ~0.4 KB
  per row with the indexes; with `--renormalize` plus ~0.5 KB per row for the
  normalized rows) would take half the database volume's free space or more —
  and **also when that free space is unknown** (no `server_metrics` sample in
  the last 15 minutes: the poller measures it). `--force` (`"force": true`,
  re-authenticated like every queue, and recorded in the audit row) queues it
  anyway. The worker re-checks before it loads (a bucket restore, which has
  no rows to size until it has selected its objects, is checked only there),
  honouring the force. Each object is downloaded
  to `ARCHIVE_STAGING_DIR/restore-<id>/` (object size + 512 MiB free
  required) and deleted once loaded.
- **Verification — nothing unverified is loaded.** Every object is fetched
  by its recorded version id and checked while it downloads: the stored bytes
  against `sha256_object`, the decompressed bytes against `sha256_content`,
  the byte and row counts, and every line JSON with an id inside its chunk's
  range, in order. Only then is it decoded, and each line must re-encode to
  exactly itself (the row format of its schema version: syslog v1 has no
  `format`, v2 has it) — every line of the object is decoded once **before
  its first batch is loaded**, so a line the decoder refuses (the row format
  drifted from what the archive wrote) refuses the whole object with nothing
  of it staged. A mismatch **REFUSES** the object: the job fails with
  `REFUSED …` in its error, nothing of that object is staged, and
  `fwmon_archive_restore_refused_total{stream}` counts it. Treat it like a
  corrupt archive: run `fwmon-api archive --verify-month` on the month. A
  bucket outage fails the job without `REFUSED`; resume it.
- **Staging table.** `restore_<id>_<table>`: the live table's columns, the
  **original ids** as primary key, indexes on `(timestamp)` and
  `(device_id, timestamp)`. Query it with SQL, e.g.
  `SELECT * FROM restore_12_syslog_messages WHERE device_id = 7 ORDER BY timestamp`.
  Rows of the requested days (and device) only.
- **Exactly once, resumable.** Rows load in batches of 5 000 lines at the
  job's rate (default 5 000 rows/s); each batch commits with the object's
  cursor, so a crash or restart resumes after the last committed line (the
  job is requeued once its heartbeat is two minutes stale).
- **Lifetime.** The staging table is dropped `--ttl-days` (default 7, max 90)
  after the job was queued, or by `--drop-restore` — never while a
  normalized-event backfill over it is active (a drop and the queueing of that
  backfill take the job row's lock, so neither can slip past the other), and
  the TTL never drops a `loaded` restore whose re-normalize has not been
  queued yet. Retention, the archive gate,
  partition maintenance, the device purge and the archive itself never touch
  a staging table.
- **Flows** (`sflow`, `netflow`, `sflow-counters`) are staged only:
  re-rolling them up would count them twice against `flow_rollups`. Query the
  staging table, or point DuckDB at the bucket.

`fwmon_archive_restore_jobs{status}` and `fwmon_archive_restore_rows_total{table}`
are on the poller's `/metrics`.

### Re-normalizing restored syslog

`--renormalize` (syslog only) queues the [normalized-event
backfill](#backfilling-the-normalized-tables-one-time-30-days) over the
staging table once it is loaded (`backfill_job_id` on the restore; a restore
waits as `loaded` while another backfill runs). Over a staging table the
backfill takes every row of the requested days whenever it was received (no
ingest watermark, no 30-day limit), skips rows of devices that no longer
exist, and writes only rows inside their target table's retention: network
rows only for days that still have a `net_events` leaf, `sec_events` rows
only within `RETENTION_SEC_EVENT_DAYS` (config changes within
`RETENTION_SEC_CONFIG_CHANGE_DAYS`, forever by default); the rest are counted
`rows_out_of_retention`. Follow it with `fwmon-api normalize-backfill
--status`; cancel / resume it there.

The normalized rows keep the raw row's original id in `raw_id`. Once the
staging table is dropped those ids point at nothing (the live row of that id
is gone too, unless the day is still in `syslog_messages`): the normalized
rows stay, their raw line does not. Restore the day again to read it.

A `--from-bucket --renormalize` restore may be running against a database
that is not the one the archive was written from (rebuilt, its id sequence
restarted). Before queueing the backfill the worker compares the first live
`syslog_messages` row in the staged id range with the staged row of that id;
when they differ the re-normalize is **refused** (the restore fails, the
staged rows are kept for queries) — re-normalizing would mix the restored
rows' normalized rows with the live rows' under the same ids. It is a sample,
not a proof: on a rebuilt database prefer staging only.

Without `--replace` a raw row that already has a normalized row is skipped
(a second run writes nothing). With `--replace` the rows a raw row already has
in `net_events` / `sec_events` are **deleted and rewritten** in the same
batch transaction as the new ones (`rows_replaced`), so every raw row ends
with exactly the current parser's rows, once — however often it runs or
crashes. A raw row whose re-parse writes nothing (unparsed now, or outside
the target table's retention) **keeps** its earlier rows (`rows_kept`) rather
than losing them. The net_event rollups of those days are recomputed
afterwards.

### Restore a parser-fixed day

A parser bug wrote wrong normalized rows for 4 October; the fix is deployed.

1. Check the day is archived: `fwmon-api archive --status` (the syslog table
   verified past 5 October) — or `--verify-month syslog 2026-10` for a
   sealed month.
2. `fwmon-api archive --restore syslog --from 2026-10-04 --to 2026-10-04 --renormalize --replace`
   (add `--device <id>` if only one device was affected).
3. `fwmon-api archive --restores` until the restore is `done` with a
   `backfill job`, then `fwmon-api normalize-backfill --status` until that is
   `done`: `rows_replaced` is the raw rows whose earlier normalized rows were
   replaced.
4. Spot-check a few events on the dashboards, then
   `fwmon-api archive --drop-restore <id>` (or let its TTL drop it).

The live `syslog_messages` rows of that day, if still there, are not touched;
the normalized rows are keyed by the raw row's id, which the restore keeps.

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

### Optional: behind Cloudflare (or another CDN) as well

Skip this unless your hostname is proxied by Cloudflare (orange-cloud DNS). In
that case every request passes **two** proxies — Cloudflare, then your reverse
proxy — and with only the reverse proxy trusted, the API attributes each request
to the **Cloudflare edge server** that forwarded it, not the visitor. Users who
reach the same edge share one lockout and rate-limit bucket, and the audit log
shows Cloudflare addresses.

Append Cloudflare's published ranges to the reverse proxy's address:

```bash
CF=$(curl -fsS https://www.cloudflare.com/ips-v4; echo; curl -fsS https://www.cloudflare.com/ips-v6)
echo "TRUSTED_PROXIES=192.0.2.10,$(echo "$CF" | grep / | paste -sd, -)"
```

Put the printed line in `config.env` and restart the API.

- This is per installation. The default stays empty, and these entries change
  nothing for traffic that does not arrive from a Cloudflare address, so a
  deployment that is not behind Cloudflare should simply not add them.
- It cannot be spoofed: a visitor's own `X-Forwarded-For` entries end up to the
  left of the address Cloudflare appends, and the API stops at the right-most
  untrusted address.
- Cloudflare rarely changes these ranges; re-run the command if it announces a
  change. A stale list only degrades attribution back to the edge address — it
  never blocks requests.

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
