#!/bin/sh
set -e

echo "=== Firewall Monitor Starting ==="

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
ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme123!}
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

# Create data directories
mkdir -p /data /config

# Export config file path
export CONFIG_FILE=/config/config.env

echo "Starting Firewall Monitor services..."

# Start all services in background
echo "Starting API server..."
export CONFIG_FILE=/config/config.env
./fwmon-api &
API_PID=$!

echo "Starting SNMP poller..."
./fwmon-poller &
POLLER_PID=$!

echo "Starting trap receiver..."
./fwmon-trap &
TRAP_PID=$!

echo "All services started!"
echo "  API:      $API_PID"
echo "  Poller:   $POLLER_PID"
echo "  Trap:     $TRAP_PID"

# Graceful shutdown
trap "echo 'Shutting down...'; kill $API_PID $POLLER_PID $TRAP_PID 2>/dev/null; exit 0" INT TERM

# Wait for all processes
wait $API_PID $POLLER_PID $TRAP_PID
