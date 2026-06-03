#!/bin/bash

set -e

APP_NAME="firewall-mon"
INSTALL_DIR="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
SYSTEMD_DIR="/etc/systemd/system"
SVC_USER="fwmon"
SVC_GROUP="fwmon"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build          Build the application binaries"
    echo "  deploy         Deploy to remote server via SSH"
    echo "  install        Install on local Linux system"
    echo "  start          Start the services"
    echo "  stop           Stop the services"
    echo "  restart        Restart the services"
    echo "  status         Check service status"
    echo ""
    echo "Deploy options:"
    echo "  -h, --host     Remote server hostname/IP"
    echo "  -u, --user     SSH username"
    echo "  -p, --port     SSH port (default: 22)"
    echo "  -k, --key      SSH private key file"
    exit 1
}

build() {
    log_info "Building Firewall Monitor..."

    if [ ! -f "go.mod" ]; then
        log_info "Initializing Go module..."
        go mod init firewall-mon
    fi

    log_info "Downloading dependencies..."
    go mod tidy

    log_info "Building API server..."
    go build -o bin/fwmon-api ./cmd/api

    log_info "Building SNMP poller..."
    go build -o bin/fwmon-poller ./cmd/poller

    log_info "Building trap receiver..."
    go build -o bin/fwmon-trap ./cmd/trap-receiver

    log_info "Build complete!"
    ls -la bin/
}

deploy_remote() {
    HOST=""
    USER=""
    PORT=22
    KEY=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--host) HOST="$2"; shift 2 ;;
            -u|--user) USER="$2"; shift 2 ;;
            -p|--port) PORT="$2"; shift 2 ;;
            -k|--key) KEY="$2"; shift 2 ;;
            *) usage ;;
        esac
    done

    if [ -z "$HOST" ] || [ -z "$USER" ]; then
        log_error "Host and user are required for deploy"
        usage
    fi

    log_info "Building locally first..."
    build

    REMOTE_DIR="/opt/${APP_NAME}"
    SSH_OPTS="-p ${PORT}"
    if [ -n "$KEY" ]; then
        SSH_OPTS="${SSH_OPTS} -i ${KEY}"
    fi

    log_info "Creating remote directory..."
    ssh ${SSH_OPTS} ${USER}@${HOST} "sudo mkdir -p ${REMOTE_DIR} /etc/${APP_NAME} /var/lib/${APP_NAME}"

    log_info "Transferring files..."
    ssh ${SSH_OPTS} ${USER}@${HOST} "sudo rm -rf ${REMOTE_DIR}/*"
    
    rsync -avz -e "ssh ${SSH_OPTS}" --progress bin/ ${USER}@${HOST}:${REMOTE_DIR}/
    rsync -avz -e "ssh ${SSH_OPTS}" --progress web/ ${USER}@${HOST}:/tmp/web/
    rsync -avz -e "ssh ${SSH_OPTS}" --progress config.env.example ${USER}@${HOST}:/tmp/config.env.example

    log_info "Installing files on remote..."
    ssh ${SSH_OPTS} ${USER}@${HOST} << 'EOF'
        sudo cp /tmp/web/* /opt/firewall-mon/ -r
        sudo cp /tmp/config.env.example /etc/firewall-mon/config.env
        sudo chmod +x /opt/firewall-mon/fwmon-*
        sudo cp /etc/systemd/system/fwmon-*.service /tmp/ 2>/dev/null || true
EOF

    log_info "Deployment complete!"
    log_info "Connect to server and run: sudo /opt/firewall-mon/scripts/install.sh"
}

install_local() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    log_info "Installing Firewall Monitor..."

    # AUDIT-021: create the dedicated system user the systemd unit will run
    # as. Previously the unit ran as root, which is the worst-case blast
    # radius for any future RCE — the binary would land on a public-facing
    # network port (8080, 162/udp, 6343/udp), and a single memory-corruption
    # bug would give the attacker root. The Docker path already runs as the
    # non-root `fwmon` user (Dockerfile USER); the native systemd path now
    # matches.
    create_service_user

    mkdir -p ${INSTALL_DIR}
    mkdir -p ${DATA_DIR}
    mkdir -p ${CONFIG_DIR}

    if [ -d "bin" ]; then
        cp bin/* ${INSTALL_DIR}/
        chmod +x ${INSTALL_DIR}/*
    fi

    if [ -d "web" ]; then
        cp -r web/* ${INSTALL_DIR}/
    fi

    if [ ! -f "${CONFIG_DIR}/config.env" ]; then
        cp config.env.example ${CONFIG_DIR}/config.env
        log_warn "Please edit ${CONFIG_DIR}/config.env with your settings"
    fi

    if [ -d "scripts" ]; then
        cp scripts/*.sh ${INSTALL_DIR}/
        chmod +x ${INSTALL_DIR}/*.sh
    fi

    # AUDIT-021: fix ownership after copy so the fwmon user can read its
    # own binaries / web assets / scripts. The data dir must also be
    # writable so the AUDIT-008 secrets flow (which writes
    # /var/lib/firewall-mon/.jwt-secret) and the SQLite database can
    # live there. Config files are 0640 fwmon:fwmon — fwmon must read
    # JWT_SECRET_KEY, ENCRYPTION_KEY, etc., but other system users
    # should not.
    chown -R ${SVC_USER}:${SVC_GROUP} ${INSTALL_DIR}
    chown -R ${SVC_USER}:${SVC_GROUP} ${DATA_DIR}
    chown -R ${SVC_USER}:${SVC_GROUP} ${CONFIG_DIR}
    chmod 0750 ${CONFIG_DIR}
    find ${CONFIG_DIR} -type f -exec chmod 0640 {} \;
    if [ -f ${CONFIG_DIR}/config.env ]; then
        chmod 0640 ${CONFIG_DIR}/config.env
    fi

    log_info "Creating systemd services..."
    create_systemd_service "api" "${INSTALL_DIR}/fwmon-api" "Firewall Monitor API Server"
    create_systemd_service "poller" "${INSTALL_DIR}/fwmon-poller" "Firewall Monitor SNMP Poller"
    create_systemd_service "trap" "${INSTALL_DIR}/fwmon-trap" "Firewall Monitor Trap Receiver"

    systemctl daemon-reload
    log_info "Installation complete!"
}

create_systemd_service() {
    local name=$1
    local binary=$2
    local desc=$3

    cat > ${SYSTEMD_DIR}/fwmon-${name}.service << EOF
[Unit]
Description=${desc}
After=network.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_DIR}/config.env
ExecStart=${binary}
Restart=always
RestartSec=10

# AUDIT-021: systemd hardening directives. These match what the Docker
# path already gets for free from the container runtime (seccomp, dropped
# caps, read-only rootfs when applicable) and bring the native deploy
# path up to parity. Each line is sourced from the systemd.exec(5) man
# page; see the rationale next to each directive.
#
# NoNewPrivileges=yes - prevents SUID/SGID bit acquisition. A future
#   bug that drops a binary in /tmp and chmods it 4755 will not get the
#   root it expected.
# ProtectSystem=strict - mounts /, /usr, /boot, /etc read-only. The
#   binary can only write to /var/lib/firewall-mon (and an explicit
#   /tmp via PrivateTmp; see below).
# ReadWritePaths=/var/lib/firewall-mon - the explicit write allow-list
#   for the data directory (secrets file, SQLite, WAL, IRC logs).
# PrivateTmp=yes - dedicated /tmp namespace; no surprises from other
#   services' temp files and no /tmp-confusion attacks.
# ProtectHome=yes - /home, /root, /run/user are inaccessible.
# ProtectKernelTunables=yes - /proc and /sys are protected from writes
#   (e.g. the binary cannot disable ASLR by writing to /proc/self/maps).
# ProtectKernelModules=yes - cannot load kernel modules.
# ProtectControlGroups=yes - cannot manipulate cgroups.
# RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 - only the socket
#   families the binary actually needs. No AF_NETLINK (no routing
#   socket), no AF_PACKET (no raw packet), no AF_KEY (no IPsec).
# RestrictNamespaces=yes - cannot unshare / clone namespaces.
# RestrictRealtime=yes - no SCHED_RR/SCHED_FIFO scheduling.
# RestrictSUIDSGID=yes - no SUID/SGID bit flips.
# LockPersonality=yes - no personality(2) syscalls.
# MemoryDenyWriteExecute=yes - mmap / mprotect cannot create WX pages
#   (defense-in-depth against JIT-based shellcode in a future XSS
#   chain that gains local code execution).
# SystemCallArchitectures=native - no i386 / x32 syscalls.
# SystemCallFilter=@system-service ~@privileged @resources - explicit
#   allow-list, not a deny-list. Denies @privileged (mount, kexec,
#   reboot, swapon, etc.) and @resources (ioperm, iopl, etc.).
#   The trailing ~ prefix subtracts the listed sets from @system-service.
#   Edit the allow-list after the first prod deploy by running:
#     systemd-analyze syscall-filter ${binary}
#   and adding any syscalls the binary legitimately needs that aren't
#   in @system-service.
# CapabilityBoundingSet= - drop ALL Linux capabilities. The binary
#   needs no caps — it talks UDP/TCP via standard sockets, reads files,
#   writes to its data dir, and that's it.
# AmbientCapabilities= - none. (Empty by default; explicit for clarity.)
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service ~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF

    log_info "Created fwmon-${name}.service"
}

create_service_user() {
    if id -u ${SVC_USER} >/dev/null 2>&1; then
        log_info "Service user ${SVC_USER} already exists"
        return 0
    fi
    log_info "Creating service user ${SVC_USER}..."
    # --system: uid from SYS_UID_MAX range (no login, no expiry)
    # --no-create-home: we use /var/lib/firewall-mon, not /home/fwmon
    # --shell /usr/sbin/nologin: cannot log in interactively even if
    #   some future misconfiguration sets a password
    useradd --system \
            --home-dir ${DATA_DIR} \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Firewall Monitor service account" \
            ${SVC_USER}
    log_info "Service user ${SVC_USER} created (uid=$(id -u ${SVC_USER}))"
}

start_services() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    log_info "Starting services..."
    systemctl start fwmon-api
    systemctl start fwmon-poller
    systemctl start fwmon-trap
    log_info "Services started!"
}

stop_services() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    log_info "Stopping services..."
    systemctl stop fwmon-api 2>/dev/null || true
    systemctl stop fwmon-poller 2>/dev/null || true
    systemctl stop fwmon-trap 2>/dev/null || true
    log_info "Services stopped!"
}

restart_services() {
    stop_services
    start_services
}

status_services() {
    systemctl status fwmon-api --no-pager || true
    systemctl status fwmon-poller --no-pager || true
    systemctl status fwmon-trap --no-pager || true
}

COMMAND=${1:-}
shift || true

case $COMMAND in
    build) build ;;
    deploy) deploy_remote "$@" ;;
    install) install_local ;;
    start) start_services ;;
    stop) stop_services ;;
    restart) restart_services ;;
    status) status_services ;;
    *) usage ;;
esac
