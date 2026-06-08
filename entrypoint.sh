#!/bin/bash
set -e

echo "=== Firewall Monitor Starting ==="

PGDATA="/data/pgdata"
PGRUN="/run/postgresql"
PG_DB="firewall_mon"
PG_USER="fwmon"
PG_CRED_FILE="/config/pg-credentials"

# AUDIT-093: PostgreSQL password hygiene. The pre-fix script hardcoded
# PASSWORD 'fwmon' for the fwmon DB user, and exported DB_PASSWORD=fwmon
# for the app. With the embedded Postgres configured to listen only on
# the unix socket AND initdb's --auth=trust setting, the password isn't
# actually checked — but it IS still baked into the repo, and a future
# operator who flips `listen_addresses = 'localhost'` to enable a
# remote connection (a common production change for running the API
# outside the container, or for adding pgAdmin access) would silently
# ship a publicly-known credential.
#
# Fix: generate a random 32-character password on first init, persist
# it to /config/pg-credentials mode 0600, and source it on every
# subsequent boot. The init flow becomes:
#   1. First ever boot: no /config/pg-credentials -> generate, persist,
#      then CREATE USER with the random password.
#   2. Subsequent boots: source /config/pg-credentials, CREATE USER
#      is a no-op (the user already exists from the first boot).
#   3. Upgrades from a pre-AUDIT-093 image: the user already exists
#      with the old hardcoded password. We ALTER it to the new random
#      password on the first post-upgrade boot (idempotent re-ALTER).
#
# We don't try to detect the "user already has old password" case
# separately — the ALTER is a no-op if the new password matches, and
# always succeeds because we have superuser access via the trust-auth
# local socket.
if [ ! -f "$PG_CRED_FILE" ]; then
    echo "Generating new PostgreSQL credentials..."
    mkdir -p /config
    # 24 random bytes -> base64 -> strip non-alphanumeric -> first 32
    # chars. The trim handles the case where base64 padding would
    # otherwise leak '=' into a password and into shell variables.
    # /dev/urandom is the right entropy source for a one-shot secret
    # in a fresh container.
    local_random=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
    cat > "$PG_CRED_FILE" <<CREDEOF
# Firewall Monitor PostgreSQL credentials
# AUDIT-093: auto-generated on first init. Do not edit by hand.
# Delete this file to force regeneration on next boot (the existing
# Postgres user keeps the OLD password until you also run:
#   su-exec postgres psql -c "ALTER USER fwmon WITH PASSWORD '\$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)';"
# under the entrypoint before deleting this file).
PG_USER=$PG_USER
PG_PASSWORD=$local_random
CREDEOF
    chmod 0600 "$PG_CRED_FILE"
    chown fwmon:fwmon "$PG_CRED_FILE" 2>/dev/null || true
fi
# shellcheck disable=SC1090
. "$PG_CRED_FILE"
export PG_USER PG_PASSWORD

# ---- PostgreSQL Setup ----
echo "Initializing PostgreSQL..."

mkdir -p "$PGRUN"
chown postgres:postgres "$PGRUN"

# Initialize PG data directory if empty
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "Creating new PostgreSQL database cluster..."
    mkdir -p "$PGDATA"
    chown postgres:postgres "$PGDATA"
    chmod 700 "$PGDATA"
    su-exec postgres initdb -D "$PGDATA" --auth=trust --no-locale --encoding=UTF8 > /dev/null

    # Listen only on unix socket (localhost), no TCP needed
    sed -i "s|#listen_addresses = 'localhost'|listen_addresses = ''|" "$PGDATA/postgresql.conf"
    sed -i "s|#unix_socket_directories.*|unix_socket_directories = '$PGRUN'|" "$PGDATA/postgresql.conf"

    # Tune for embedded use (low memory footprint)
    cat >> "$PGDATA/postgresql.conf" <<PGCONF
shared_buffers = 128MB
work_mem = 4MB
maintenance_work_mem = 64MB
effective_cache_size = 256MB
wal_buffers = 4MB
max_connections = 30
# AUDIT-095: crash forensics are NOT lost despite logging_collector = off.
# The audit assumed "off" meant Postgres logs vanished; in this embedded
# single-container setup Postgres is started below with
#   pg_ctl ... -l "\$PGDATA/postgresql.log"
# so its stderr (startup, crash, FATAL/PANIC, slow-query warnings) is
# redirected to that file, which lives in the bind-mounted /data/pgdata
# and therefore survives container restarts. The collector is deliberately
# kept OFF so we do not run Postgres's own log-rotation subprocess inside a
# container whose lifecycle is already managed by Docker (one log writer,
# captured on the persistent volume). To instead surface PG logs in
# 'docker logs' alongside the app, set 'log_destination = stderr' here and
# drop the pg_ctl -l redirect; we keep the file form so PG diagnostics are
# not interleaved with the three fwmon daemons' stdout.
logging_collector = off
log_min_messages = warning
PGCONF
else
    echo "Existing PostgreSQL data found."
    chown -R postgres:postgres "$PGDATA"
fi

# Start PostgreSQL
echo "Starting PostgreSQL..."
su-exec postgres pg_ctl -D "$PGDATA" -l "$PGDATA/postgresql.log" -w start > /dev/null

# Create database and user if they don't exist
su-exec postgres psql -h "$PGRUN" -c "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" | grep -q 1 || \
    su-exec postgres psql -h "$PGRUN" -c "CREATE USER $PG_USER WITH PASSWORD '$PG_PASSWORD';" > /dev/null
# AUDIT-093: always ALTER the password to the current /config/pg-credentials
# value. This is a no-op on steady-state (the password already matches) and
# the migration path for upgrades from a pre-AUDIT-093 image (the user
# already existed with the hardcoded 'fwmon' password; ALTER swaps it).
# Idempotent and safe under trust-auth local-socket access.
su-exec postgres psql -h "$PGRUN" -c "ALTER USER $PG_USER WITH PASSWORD '$PG_PASSWORD';" > /dev/null
su-exec postgres psql -h "$PGRUN" -tc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" | grep -q 1 || \
    su-exec postgres psql -h "$PGRUN" -c "CREATE DATABASE $PG_DB OWNER $PG_USER;" > /dev/null

echo "PostgreSQL ready."

# ---- Set DB environment for all fwmon services ----
export DB_TYPE=postgres
export DB_HOST="$PGRUN"
export DB_PORT=5432
export DB_NAME="$PG_DB"
export DB_USER="$PG_USER"
export DB_PASSWORD="$PG_PASSWORD"

# Create config from environment or use default
if [ ! -f /config/config.env ]; then
    echo "Creating config from environment..."
    cat > /config/config.env << EOF
SNMP_HOST=${SNMP_HOST:-192.168.1.1}
SNMP_PORT=${SNMP_PORT:-161}
SNMP_COMMUNITY=${SNMP_COMMUNITY:-public}
SNMP_VERSION=${SNMP_VERSION:-2c}
SNMP_POLL_INTERVAL=${SNMP_POLL_INTERVAL:-60s}
SERVER_HOST=${SERVER_HOST:-0.0.0.0}
SERVER_PORT=${SERVER_PORT:-8080}
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
JWT_SECRET_KEY=${JWT_SECRET_KEY:-$(head -c 32 /dev/urandom | base64)}
CPU_THRESHOLD=${CPU_THRESHOLD:-80}
MEMORY_THRESHOLD=${MEMORY_THRESHOLD:-80}
DISK_THRESHOLD=${DISK_THRESHOLD:-90}
SESSION_THRESHOLD=${SESSION_THRESHOLD:-100000}
EMAIL_ENABLED=${EMAIL_ENABLED:-false}
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USERNAME=${SMTP_USERNAME:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_FROM=${SMTP_FROM:-firewall-mon@example.com}
SMTP_TO=${SMTP_TO:-admin@example.com}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}
DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL:-}
EOF
    echo "Config created at /config/config.env"
fi

# Create data directories and fix ownership (runs as root)
mkdir -p /data /config
chown -R fwmon:fwmon /data/firewall-mon.db* /config 2>/dev/null || true

# Export config file path
export CONFIG_FILE=/config/config.env

echo "Starting Firewall Monitor services..."

# Start all services as fwmon user
echo "Starting API server..."
su-exec fwmon ./fwmon-api &
API_PID=$!

echo "Starting SNMP poller..."
su-exec fwmon ./fwmon-poller &
POLLER_PID=$!

echo "Starting trap receiver..."
su-exec fwmon ./fwmon-trap &
TRAP_PID=$!

echo "All services started!"
echo "  API:      $API_PID"
echo "  Poller:   $POLLER_PID"
echo "  Trap:     $TRAP_PID"

# Stop the app daemons, then PostgreSQL. Does NOT exit — the caller decides the
# exit code (0 for a clean signal-driven stop, non-zero for a crash).
teardown() {
    echo "Stopping fwmon services..."
    # `|| true` so a non-zero kill/wait (e.g. the daemon that already crashed)
    # can't trip the script-level `set -e` before the caller's explicit exit,
    # which would otherwise leak 143 into a clean `docker stop` (want exit 0).
    kill $API_PID $POLLER_PID $TRAP_PID 2>/dev/null || true
    wait $API_PID $POLLER_PID $TRAP_PID 2>/dev/null || true
    echo "Stopping PostgreSQL..."
    su-exec postgres pg_ctl -D "$PGDATA" -m fast stop > /dev/null 2>&1 || true
}

# Graceful shutdown on SIGINT/SIGTERM (e.g. `docker stop`) — clean exit 0.
shutdown() {
    echo "Received shutdown signal..."
    teardown
    exit 0
}
trap shutdown INT TERM

# AUDIT-094: fail-fast supervision. A bare `wait $API_PID $POLLER_PID $TRAP_PID`
# blocks until ALL THREE exit, so a single crashed daemon left the container up
# running a silently-degraded stack — the dead process was neither restarted nor
# surfaced. Instead, wait for the FIRST daemon to exit, report which one and its
# status, tear the whole stack down cleanly, and exit non-zero. Docker's
# `restart: unless-stopped` then brings back a fresh, COMPLETE stack (PostgreSQL
# included) rather than limping along missing a daemon. `set +e` keeps the
# script-level `set -e` from aborting before we can log/teardown when the
# crashed child returns a non-zero status.
set +e
wait -n
first_status=$?
set -e

dead="a service"
for entry in "API:$API_PID" "Poller:$POLLER_PID" "Trap:$TRAP_PID"; do
    name=${entry%%:*}
    pid=${entry##*:}
    if ! kill -0 "$pid" 2>/dev/null; then
        dead="$name (pid $pid)"
        break
    fi
done

echo "!!! $dead exited (status $first_status) — tearing down the stack for a clean restart"
teardown
exit 1
