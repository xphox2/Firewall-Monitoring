#!/usr/bin/env bash
#
# replica-setup.sh — pull a full production Firewall-Mon Postgres dump to this
# Mac, restore it into a local PG16 database, and scrub secret/PII columns so
# the replica is safe for analysis (alert-template design, bug repro, benchmarks).
#
# DESIGN NOTES / SAFETY:
#   * Prod is only ever READ. pg_dump takes ACCESS SHARE locks and will not
#     block the running app, and it self-sets statement_timeout=0 so the 30s
#     prod default won't kill a long COPY. Still, run it OFF-HOURS: it holds one
#     long snapshot that pauses autovacuum and adds I/O for the dump's duration.
#   * The dump streams straight to this Mac — nothing 35GB is staged on rust-01.
#   * SSH here uses password auth, so run this in a REAL terminal (it prompts for
#     the rust-01 password). It cannot run through the Claude Code inline shell,
#     which has no TTY for the prompt.
#   * The dump file contains EVERY prod secret. It is written 0600 (umask 077)
#     and is NOT auto-deleted — remove it yourself once the replica is scrubbed.
#   * Secrets are NULLed/deleted on the LOCAL replica in step 4, atomically
#     (single transaction) and then VERIFIED — the script aborts if any remain.
#
# USAGE:
#   1. Fill in the five CONFIG values below.
#   2. chmod +x tasks/replica-setup.sh
#   3. ./tasks/replica-setup.sh            # full run (dump -> restore -> scrub)
#      ./tasks/replica-setup.sh dump       # just dump+transfer
#      ./tasks/replica-setup.sh restore    # just restore the newest dump file
#      ./tasks/replica-setup.sh introspect # list real secret columns present
#      ./tasks/replica-setup.sh scrub      # just re-run the secret sweep+verify
#      ./tasks/replica-setup.sh profile    # run the phase-1 profiling queries
#
set -euo pipefail
umask 077   # any file we create (esp. the secret-laden dump) is owner-only

# ============================ CONFIG — FILL THESE IN ============================
SSH_HOST="66.179.9.149"           # rust-01
SSH_USER="xphox"               # your SSH login on rust-01
PG_CONTAINER="firewall-mon"           # from: docker ps --format '{{.Names}}'
DB_NAME="firewall_mon"                # from container env POSTGRES_DB
DB_USER="fwmon"                # from container env POSTGRES_USER
# ==============================================================================

# --- Pin to the local Homebrew PG16 instance (keg-only: not on PATH by default).
export PATH="/opt/homebrew/opt/postgresql@16/bin:${PATH}"
export PGHOST="127.0.0.1"         # never let an ambient PGHOST point us at a remote/prod cluster
export PGPORT="5432"
unset PGSERVICE PGDATABASE 2>/dev/null || true

# Local target
LOCAL_DB="fwmon_replica"
DUMP_FILE="${HOME}/fwmon_prod_$(date +%Y%m%d).dump"
DUMP_GLOB="${HOME}/fwmon_prod_*.dump"
# -X ignores ~/.psqlrc (e.g. AUTOCOMMIT off would silently roll back the scrub).
PSQL=(psql -X -v ON_ERROR_STOP=1 -d "${LOCAL_DB}")

die() { echo "ERROR: $*" >&2; exit 1; }

# Loud banner on ANY abort: if a run dies after restore but before a verified
# scrub, the local replica may still hold live secrets.
trap 'st=$?; [ $st -ne 0 ] && echo >&2 "
!! ABORTED (exit $st). If the restore had completed, the replica \"${LOCAL_DB}\"
!! and the dump file may still contain UNSCRUBBED production secrets.
!! Re-run:  $0 scrub   (and delete the dump file when done)"' EXIT

check_config() {
  local v
  for v in SSH_USER PG_CONTAINER DB_NAME DB_USER; do
    if [ "${!v}" = "CHANGEME" ]; then
      die "Set $v at the top of this script first."
    fi
    # These get interpolated into a remote shell command — reject anything that
    # could break out of the intended docker/pg_dump invocation on rust-01.
    if ! [[ "${!v}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
      die "$v contains unsafe characters ('${!v}'); allowed: A-Z a-z 0-9 _ . -"
    fi
  done
  return 0
}

newest_dump() { ls -t ${DUMP_GLOB} 2>/dev/null | head -1; }

# ------------------------------------------------------------------------------
# STEP 1 — dump prod + stream to this Mac (compressed custom format)
# Write to .partial, mv on success so an interrupted dump can't be restored.
# ------------------------------------------------------------------------------
do_dump() {
  check_config
  echo ">> Dumping ${DB_NAME} from ${PG_CONTAINER} on ${SSH_HOST} -> ${DUMP_FILE}"
  echo ">> (streams the container's own pg_dump; expect ~5-12GB, 20-60 min)"
  ssh "${SSH_USER}@${SSH_HOST}" \
    "docker exec -i ${PG_CONTAINER} pg_dump -U ${DB_USER} -d ${DB_NAME} -Fc -Z6" \
    > "${DUMP_FILE}.partial"
  mv "${DUMP_FILE}.partial" "${DUMP_FILE}"
  echo ">> Dump complete: ${DUMP_FILE} ($(du -h "${DUMP_FILE}" | cut -f1))"
  echo ">> NOTE: this file contains live prod secrets — delete it once scrubbed."
}

# ------------------------------------------------------------------------------
# STEP 2 — restore into a fresh local PG16 database
# pg_restore may exit non-zero on ignorable warnings (missing extension/role);
# capture the status, warn, and CONTINUE so the scrub still runs.
# ------------------------------------------------------------------------------
do_restore() {
  command -v pg_restore >/dev/null || die "pg_restore not found (brew install postgresql@16)."
  case "$(pg_restore --version)" in
    *\ 16.*) : ;;
    *) die "pg_restore is not v16 ($(pg_restore --version)); check PATH." ;;
  esac
  local f; f="$(newest_dump)"
  [ -n "${f}" ] && [ -f "${f}" ] || die "No dump file matching ${DUMP_GLOB}. Run 'dump' first."

  echo ">> Ensuring local PG16 is running..."
  brew services start postgresql@16 >/dev/null 2>&1 || true
  local i=0
  until pg_isready -q; do
    i=$((i+1)); [ "${i}" -gt 30 ] && die "Local Postgres not accepting connections after 30s."
    sleep 1
  done

  echo ">> (Re)creating ${LOCAL_DB}"
  dropdb --if-exists "${LOCAL_DB}"
  createdb "${LOCAL_DB}"

  echo ">> Restoring ${f} (parallel, no owner/privs)..."
  if pg_restore -j4 --no-owner --no-privileges --no-tablespaces -d "${LOCAL_DB}" "${f}"; then
    echo ">> Restore complete."
  else
    echo ">> WARNING: pg_restore exited non-zero (likely ignorable extension/role"
    echo ">>          warnings). Data is probably fine; the scrub will still run."
  fi
}

# ------------------------------------------------------------------------------
# STEP 3 — show the REAL secret/PII column names on the replica (verification)
# ------------------------------------------------------------------------------
do_introspect() {
  echo ">> Candidate secret/PII columns actually present in the replica:"
  "${PSQL[@]}" -c "
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_name IN ('devices','alert_policies','irc_servers','irc_channels',
                         'admins','admin_recovery_codes','api_tokens')
      AND (column_name ~* 'pass|secret|community|webhook|token|key|recipient|nick|sasl|totp|hash|email|prefix')
    ORDER BY table_name, column_name;"
}

# ------------------------------------------------------------------------------
# STEP 4 — NULL/DELETE the secrets on the LOCAL replica, atomically + verified.
#   * -1 (single transaction): all-or-nothing, no partial scrub.
#   * to_regclass guards: tolerant of a table absent in this deployment.
#   * hash tables (api_tokens, admin_recovery_codes) are DELETEd — they're
#     useless on a replica and have NOT NULL hash columns that block UPDATE NULL.
#   * final DO block RAISEs (aborts, non-zero exit) if ANY secret remains.
# ------------------------------------------------------------------------------
do_scrub() {
  echo ">> Scrubbing + verifying secret/PII columns on ${LOCAL_DB} (single transaction)..."
  "${PSQL[@]}" -1 <<'SQL'
-- Scrub to '' (empty), not NULL: several of these columns are NOT NULL DEFAULT ''
-- (e.g. admins.totp_secret, migration v22), and '' is safe for nullable ones too.
DO $$
BEGIN
  IF to_regclass('public.devices') IS NOT NULL THEN
    UPDATE devices SET
      snmp_community='', snmpv3_username='', snmpv3_auth_pass='',
      snmpv3_priv_pass='', ssh_username='', ssh_password='', ssh_host_key='';
  END IF;
  IF to_regclass('public.alert_policies') IS NOT NULL THEN
    UPDATE alert_policies SET
      email_recipients='', slack_webhook_url='',
      discord_webhook_url='', webhook_url='';
  END IF;
  IF to_regclass('public.irc_servers') IS NOT NULL THEN
    UPDATE irc_servers SET
      nickserv_password='', server_password='',
      sasl_username='', sasl_password='';
  END IF;
  IF to_regclass('public.irc_channels') IS NOT NULL THEN
    UPDATE irc_channels SET
      channel_key='', chanserv_password='', chan_oper_pass='', admin_nicks='';
  END IF;
  IF to_regclass('public.admins') IS NOT NULL THEN
    UPDATE admins SET totp_secret='', email='';  -- keep password hash for local UI login
  END IF;
  IF to_regclass('public.admin_recovery_codes') IS NOT NULL THEN
    DELETE FROM admin_recovery_codes;                -- NOT NULL hash; useless on replica
  END IF;
  IF to_regclass('public.api_tokens') IS NOT NULL THEN
    DELETE FROM api_tokens;                           -- NOT NULL hash; useless on replica
  END IF;
END $$;

-- Verify: abort the whole transaction if any secret survived.
DO $$
DECLARE n bigint := 0; c bigint;
BEGIN
  -- Leaked = column holds a non-empty value (coalesce handles nullable columns).
  IF to_regclass('public.devices') IS NOT NULL THEN
    SELECT count(*) INTO c FROM devices WHERE
      coalesce(snmp_community,'')<>'' OR coalesce(snmpv3_username,'')<>'' OR coalesce(snmpv3_auth_pass,'')<>''
      OR coalesce(snmpv3_priv_pass,'')<>'' OR coalesce(ssh_username,'')<>'' OR coalesce(ssh_password,'')<>''
      OR coalesce(ssh_host_key,'')<>'';
    n := n + c;
  END IF;
  IF to_regclass('public.alert_policies') IS NOT NULL THEN
    SELECT count(*) INTO c FROM alert_policies WHERE
      coalesce(email_recipients,'')<>'' OR coalesce(slack_webhook_url,'')<>''
      OR coalesce(discord_webhook_url,'')<>'' OR coalesce(webhook_url,'')<>'';
    n := n + c;
  END IF;
  IF to_regclass('public.irc_servers') IS NOT NULL THEN
    SELECT count(*) INTO c FROM irc_servers WHERE
      coalesce(nickserv_password,'')<>'' OR coalesce(server_password,'')<>''
      OR coalesce(sasl_username,'')<>'' OR coalesce(sasl_password,'')<>'';
    n := n + c;
  END IF;
  IF to_regclass('public.irc_channels') IS NOT NULL THEN
    SELECT count(*) INTO c FROM irc_channels WHERE
      coalesce(channel_key,'')<>'' OR coalesce(chanserv_password,'')<>''
      OR coalesce(chan_oper_pass,'')<>'' OR coalesce(admin_nicks,'')<>'';
    n := n + c;
  END IF;
  IF to_regclass('public.admins') IS NOT NULL THEN
    SELECT count(*) INTO c FROM admins WHERE coalesce(totp_secret,'')<>'' OR coalesce(email,'')<>'';
    n := n + c;
  END IF;
  IF to_regclass('public.admin_recovery_codes') IS NOT NULL THEN
    SELECT count(*) INTO c FROM admin_recovery_codes; n := n + c;
  END IF;
  IF to_regclass('public.api_tokens') IS NOT NULL THEN
    SELECT count(*) INTO c FROM api_tokens; n := n + c;
  END IF;

  IF n > 0 THEN
    RAISE EXCEPTION 'scrub verification FAILED: % secret value(s) still present', n;
  END IF;
  RAISE NOTICE 'scrub verification OK: no secrets remain';
END $$;
SQL
  echo ">> Scrub verified: no secrets remain."
}

# ------------------------------------------------------------------------------
# STEP 5 — phase-1 profiling (what the alert-template design is built from)
# ------------------------------------------------------------------------------
do_profile() {
  echo "==================== ALERTS: date range & volume ===================="
  "${PSQL[@]}" -c "SELECT min(timestamp) AS earliest, max(timestamp) AS latest, count(*) AS total FROM alerts;"
  echo "==================== ALERTS: by type & severity ===================="
  "${PSQL[@]}" -c "
    SELECT alert_type, severity, count(*) AS n FROM alerts
    WHERE timestamp >= now() - interval '90 days'
    GROUP BY alert_type, severity ORDER BY n DESC LIMIT 40;"
  echo "==================== SYSLOG: retention window actually present ===================="
  "${PSQL[@]}" -c "SELECT min(timestamp) AS earliest, max(timestamp) AS latest, count(*) AS total FROM syslog_messages;"
  echo "==================== SYSLOG: by severity ===================="
  "${PSQL[@]}" -c "SELECT severity, count(*) AS n FROM syslog_messages GROUP BY severity ORDER BY severity;"
  echo "==================== SYSLOG: top facilities ===================="
  "${PSQL[@]}" -c "SELECT facility, count(*) AS n FROM syslog_messages GROUP BY facility ORDER BY n DESC LIMIT 20;"
  echo "==================== SYSLOG: noisiest normalized patterns (from summaries) ===================="
  "${PSQL[@]}" -c "
    SELECT severity, message_pattern, sum(count) AS occurrences FROM syslog_summaries
    GROUP BY severity, message_pattern ORDER BY occurrences DESC LIMIT 30;"
  echo "==================== FLOW DETECTIONS: by detector/category/severity ===================="
  "${PSQL[@]}" -c "
    SELECT detector, category, severity, count(*) AS n FROM flow_detections
    GROUP BY detector, category, severity ORDER BY n DESC LIMIT 30;"
  echo "==================== ALERTS: noisiest devices ===================="
  "${PSQL[@]}" -c "
    SELECT device_id, count(*) AS n FROM alerts
    WHERE timestamp >= now() - interval '90 days'
    GROUP BY device_id ORDER BY n DESC LIMIT 20;"
}

main() {
  case "${1:-all}" in
    dump)       do_dump ;;
    restore)    do_restore ;;
    introspect) do_introspect ;;
    scrub)      do_scrub ;;
    profile)    do_profile ;;
    all)
      do_dump
      do_restore
      do_introspect
      do_scrub
      echo
      echo ">> Replica ready: ${LOCAL_DB}. Run '$0 profile' for the alert profile."
      ;;
    *) die "Unknown mode '$1' (use: all|dump|restore|introspect|scrub|profile)" ;;
  esac
}
main "${@:-all}"
