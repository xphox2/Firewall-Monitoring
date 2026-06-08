# Production Upgrade Runbook — June 2026

Upgrades the live deployment from **Server v0.10.324 / Collector v1.2.73** to
**Server v0.10.386 / Collector v1.2.108**.

This runbook was written after a cross-repo compatibility audit. The key
validated facts that make this upgrade safe:

- **Your data is preserved.** The new server's startup migration runner applies
  `v1 baseline` (gorm `AutoMigrate` — additive only, never drops) and
  `v2 partition_high_volume`, which **SKIPS any table that already has rows**
  (your populated prod tables) and logs a warning. No high-volume table is
  rewritten at startup. (See `internal/database/migrate.go`.)
- **Your HTTPS is untouched.** The app defaults to plain HTTP on `:8080`
  (`SERVER_ENABLE_TLS=false`); the built-in TLS path is opt-in and inert. nginx
  keeps terminating Let's Encrypt in front. Do **not** set `SERVER_ENABLE_TLS`
  or `COOKIE_SECURE=true` on this deployment.
- **Mixed-version safe, either order.** The `schema_version` handshake (added
  this cycle) is backward/forward compatible: an old probe omits the field and
  is treated as v1; a new probe's field is ignored by an old server. Both repos
  are at schema v1. Server-first is the documented order but is not required.

> Topology assumed (rust-01): a single Docker container with **PostgreSQL
> running inside it**, `PGDATA` bind-mounted to
> `/home/xphox/firewall-mon/data/pgdata`, behind an **nginx reverse proxy** that
> terminates HTTPS. Adjust paths to match your host.

---

## 0. Pre-flight (do not skip)

1. **Record current state** so you can confirm the upgrade and roll back:
   ```bash
   curl -s http://localhost:8080/api/version          # expect 0.10.324
   docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
   ```
2. **Back up the database — this is the safety net.** Postgres is inside the
   container, so dump through it:
   ```bash
   docker exec firewall-mon pg_dump -U <pguser> -Fc firewall_mon \
     > ~/firewall-mon-backup-pre-0.10.386-$(date +%Y%m%d-%H%M).dump
   ls -lh ~/firewall-mon-backup-pre-0.10.386-*.dump   # confirm non-zero size
   ```
   (Substitute your DB user/name. If you also snapshot the bind-mount, stop the
   container first for a consistent copy.)
3. **Keep the current image for rollback** — do not prune it:
   ```bash
   docker tag firewall-mon:latest firewall-mon:0.10.324-rollback
   ```
4. **Check free space** on the `pgdata` partition (migrations + normal growth):
   ```bash
   df -h /home/xphox/firewall-mon/data
   ```
5. **Confirm the env does NOT force TLS** (it must stay plain-HTTP behind nginx):
   ```bash
   docker exec firewall-mon env | grep -E 'SERVER_ENABLE_TLS|COOKIE_SECURE' || echo "neither set — good"
   ```
   Expect no output (or `false`). If either is `true`, leave it out / set false.
6. **Do not touch the nginx config.** It already terminates HTTPS correctly.
7. **Record the encryption/JWT keys and carry them forward** (see the **Key
   continuity** warning in [OPERATIONS.md](OPERATIONS.md#upgrade)). If you deploy
   into a *new directory*, the entrypoint generates a fresh `config.env` with a
   new random `JWT_SECRET_KEY` — copy `ENCRYPTION_KEY` (and `JWT_SECRET_KEY`)
   from the current deployment so stored secrets stay decryptable:
   ```bash
   docker exec firewall-mon env | grep -E 'ENCRYPTION_KEY|JWT_SECRET_KEY'
   grep -E 'ENCRYPTION_KEY|JWT_SECRET_KEY' /home/xphox/firewall-mon/config/config.env
   ```
   Save these, and set the **same** `ENCRYPTION_KEY` in the new
   `docker-compose.yml` before `up -d`. **A changed `ENCRYPTION_KEY` makes every
   stored SNMP/SMTP/IRC secret unrecoverable** (the 2026-06-07 incident).

---

## 1. Deploy the server (rust-01)

1. Fetch the new code:
   ```bash
   cd /home/xphox/firewall-mon          # or wherever the repo/compose lives
   git fetch origin && git checkout master && git pull   # HEAD = v0.10.386
   ```
2. Rebuild and recreate the container:
   ```bash
   docker compose build
   docker compose up -d
   ```
3. **Watch the startup logs and confirm the expected migration behavior:**
   ```bash
   docker compose logs -f firewall-mon
   ```
   You **want** to see, for the high-volume tables:
   ```
   migrate: applying v1 "baseline"
   migrate: applied v1 "baseline"
   migrate: applying v2 "partition_high_volume"
   WARNING: AUDIT-028 partition migration: "interface_stats" has existing rows;
            NOT auto-converting ... Convert it in a maintenance window per
            docs/partition-migration.md ...
   ... (same warning for system_status, syslog_messages, syslog_summaries,
        trap_events, flow_samples)
   migrate: applied v2 "partition_high_volume"
   ```
   **Those warnings are correct and expected** — they confirm your data was left
   in place and partitioning was *not* applied to populated tables. (On a fresh
   empty DB the same migration would convert the tables instead; that path is
   what the CI integration suite covers.)
   You should also see the API singleton lock acquired and the server listening
   on `:8080`. You must **not** see a fatal migration error or a `2BP01` /
   `cannot drop table` error.

4. **Health checks (local, plain HTTP):**
   ```bash
   curl -s http://localhost:8080/api/health     # expect ok
   curl -s http://localhost:8080/api/version    # expect 0.10.386
   ```
5. **Through nginx (confirms the proxy still works end-to-end over HTTPS):**
   ```bash
   curl -s https://<your-domain>/api/version    # expect 0.10.386
   ```
6. **Log in to the admin UI over HTTPS.** Confirm the session cookie works
   (it is intentionally *not* `Secure`-flagged so it survives the nginx→app
   plain-HTTP hop; the browser↔nginx leg is still HTTPS).

---

## 2. Deploy the collector (remote site)

Upgrade the collector to **v1.2.108** using the site's existing deploy method
(systemd unit / Docker as configured). Then:

1. **Watch the collector logs** for a clean register + data flow:
   ```
   registered with server ... schema_version negotiated: 1
   heartbeat ok ... pushing system-status / interface-stats / syslog / ...
   ```
   A `426 Upgrade Required` would indicate a schema mismatch — it will **not**
   happen here (both sides are schema v1), but it is the signal to watch for on
   future upgrades.
2. **On the server**, confirm the probe is back online and devices are polling:
   - Admin UI → Probes: probe shows **online**, last-seen recent.
   - Admin UI → Devices: devices online, fresh interface/CPU data.

---

## 3. Smoke tests

- Dashboard loads; device/tunnel/connection data is current.
- Recent syslog / traps / flows arriving (Admin → relevant pages).
- Trigger or wait for a **config-backup**; confirm a new config-revision is
  ingested (config-revision endpoint).
- `GET /metrics` returns Prometheus output; Admin → Audit log records your login.
- Confirm the **poller** is alerting (it owns probe-device offline detection).

---

## 4. Rollback (if needed)

The upgrade makes **no destructive schema change** to your data (baseline
`AutoMigrate` is additive; the partition migration skips populated tables), so
rollback risk is low. If something is wrong:

1. ```bash
   docker compose down
   ```
2. Restore the pre-upgrade image and DB:
   ```bash
   docker tag firewall-mon:0.10.324-rollback firewall-mon:latest
   # if the DB must be restored:
   docker compose up -d        # start just Postgres-in-container, or a temp pg
   docker exec -i firewall-mon pg_restore -U <pguser> -d firewall_mon --clean \
     < ~/firewall-mon-backup-pre-0.10.386-*.dump
   ```
3. Bring the old version back up and verify `GET /api/version` → `0.10.324`.
4. Roll the collector back to v1.2.73 if it was already upgraded (optional — a
   new collector also works against the old server).

---

## 5. Post-upgrade (optional, not required)

- **Partitioning of the populated tables stays deferred.** The high-volume
  tables remain plain and are pruned by batched DELETE — fully functional. If
  you later want them partitioned, do it in a maintenance window per
  `docs/partition-migration.md` (create-copy-swap). Not urgent.
- **Collector AUDIT-064 note (performance only):** the per-queue-mutex
  optimization was inadvertently reverted on collector master by a later merge,
  so v1.2.108 uses a single queue mutex. This is *neutral* versus your live
  v1.2.73 (which predated the optimization) — no regression for you — but it is
  worth re-applying later for collector throughput under load.
