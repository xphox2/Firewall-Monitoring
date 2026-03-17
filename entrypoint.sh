#!/bin/bash
set -e

echo "=== Firewall Monitor Starting ==="

PGDATA="/data/pgdata"
PGRUN="/run/postgresql"
PG_DB="firewall_mon"
PG_USER="fwmon"

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
    su-exec postgres psql -h "$PGRUN" -c "CREATE USER $PG_USER WITH PASSWORD 'fwmon';" > /dev/null
su-exec postgres psql -h "$PGRUN" -tc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" | grep -q 1 || \
    su-exec postgres psql -h "$PGRUN" -c "CREATE DATABASE $PG_DB OWNER $PG_USER;" > /dev/null

echo "PostgreSQL ready."

# ---- Set DB environment for all fwmon services ----
export DB_TYPE=postgres
export DB_HOST="$PGRUN"
export DB_PORT=5432
export DB_NAME="$PG_DB"
export DB_USER="$PG_USER"
export DB_PASSWORD="fwmon"

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

# Graceful shutdown — stop app first, then PostgreSQL
shutdown() {
    echo "Shutting down..."
    kill $API_PID $POLLER_PID $TRAP_PID 2>/dev/null
    wait $API_PID $POLLER_PID $TRAP_PID 2>/dev/null
    echo "Stopping PostgreSQL..."
    su-exec postgres pg_ctl -D "$PGDATA" -m fast stop > /dev/null 2>&1
    exit 0
}
trap shutdown INT TERM

# Wait for all processes
wait $API_PID $POLLER_PID $TRAP_PID
