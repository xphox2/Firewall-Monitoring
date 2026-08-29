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
    echo "      --dry-run  Print what deploy would do without making any"
    echo "                 remote changes (AUDIT-098). Run this first."
    exit 1
}

build() {
    log_info "Building Firewall Monitor..."

    log_info "Compiling Tailwind CSS..."
    if command -v npm &> /dev/null; then
        if [ ! -d "node_modules" ]; then
            log_info "Installing npm dependencies..."
            npm install
        fi
        npm run build
    else
        log_warn "npm not found; skipping Tailwind CSS compilation. Existing tailwind.css will be used."
    fi

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
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--host) HOST="$2"; shift 2 ;;
            -u|--user) USER="$2"; shift 2 ;;
            -p|--port) PORT="$2"; shift 2 ;;
            -k|--key) KEY="$2"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
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

    # AUDIT-098: the pre-fix deploy wiped the install directory
    # unconditionally with no backup and no rollback. A typo in --host, a
    # half-built bin/, or an aborted transfer could leave a wiped or
    # partial install with no way back. Two safeguards now precede the
    # destructive step:
    #   1. --dry-run: print exactly what would happen and make NO remote
    #      changes (no rm, no rsync, no install). Always run this first
    #      against a new target.
    #   2. A timestamped backup tarball of the existing install, written to
    #      ${REMOTE_DIR}-backups/ on the remote BEFORE the rm, so a bad
    #      deploy can be rolled back by extracting the latest archive.
    BACKUP_DIR="${REMOTE_DIR}-backups"
    STAMP="$(date +%Y%m%d-%H%M%S)"
    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN — no remote changes will be made."
        log_info "[dry-run] Would back up ${REMOTE_DIR} to ${BACKUP_DIR}/${APP_NAME}-${STAMP}.tar.gz"
        log_info "[dry-run] Would clear and re-populate ${REMOTE_DIR} with bin/ and web/"
        log_info "[dry-run] Would seed /etc/${APP_NAME}/config.env only if absent (AUDIT-099)"
        log_info "[dry-run] Local build artifacts:"
        ls -la bin/ 2>/dev/null || true
        log_info "Dry run complete. Re-run without --dry-run to apply."
        return 0
    fi

    log_info "Backing up existing install on remote (pre-deploy safety)..."
    ssh ${SSH_OPTS} ${USER}@${HOST} "sudo mkdir -p ${BACKUP_DIR}; if [ -n \"\$(ls -A ${REMOTE_DIR} 2>/dev/null)\" ]; then sudo tar czf ${BACKUP_DIR}/${APP_NAME}-${STAMP}.tar.gz -C ${REMOTE_DIR} . && echo 'Backup: ${BACKUP_DIR}/${APP_NAME}-${STAMP}.tar.gz'; else echo 'No existing install to back up (first deploy)'; fi"

    log_info "Transferring files..."
    # AUDIT B5: never let an empty/short REMOTE_DIR turn `rm -rf ${REMOTE_DIR}/*`
    # into `rm -rf /*`. REMOTE_DIR is /opt/${APP_NAME} today, but guard the
    # destructive expansion so a future refactor can't wipe the remote root.
    # Require exactly /opt/<single-component> — a bare `/opt/*` glob would also
    # match /opt/.. (→ rm -rf /*) or /opt/ (→ rm -rf /opt/*), so validate the
    # basename too (AUDIT — Fable).
    base="${REMOTE_DIR#/opt/}"
    case "${REMOTE_DIR}" in
        /opt/"$base") : ;;
        *) log_error "REMOTE_DIR='${REMOTE_DIR}' is not under /opt — refusing to rm -rf"; exit 1 ;;
    esac
    case "$base" in
        ""|.|..|*/*) log_error "REMOTE_DIR='${REMOTE_DIR}' is not a safe single dir under /opt — refusing to rm -rf"; exit 1 ;;
    esac
    ssh ${SSH_OPTS} ${USER}@${HOST} "sudo rm -rf ${REMOTE_DIR}/*"

    rsync -avz -e "ssh ${SSH_OPTS}" --progress bin/ ${USER}@${HOST}:${REMOTE_DIR}/
    rsync -avz -e "ssh ${SSH_OPTS}" --progress web/ ${USER}@${HOST}:/tmp/web/
    rsync -avz -e "ssh ${SSH_OPTS}" --progress config.env.example ${USER}@${HOST}:/tmp/config.env.example

    log_info "Installing files on remote..."
    ssh ${SSH_OPTS} ${USER}@${HOST} << 'EOF'
        # AUDIT-171: install web/ WITH its directory prefix — the API binary
        # resolves ./web/**/*.html against WorkingDirectory=/opt/firewall-mon
        # and panics (crash-loops) when the glob matches nothing.
        sudo rm -rf /opt/firewall-mon/web
        sudo cp -r /tmp/web /opt/firewall-mon/web
        # AUDIT-099: never clobber the operator's live config. The pre-fix
        # deploy unconditionally copied config.env.example over
        # /etc/firewall-mon/config.env on EVERY deploy, wiping the
        # operator's real SNMP community, JWT secret, SMTP creds, etc. and
        # silently reverting the service to placeholder defaults on restart.
        # Only seed the example config when no config exists yet (first
        # install); on every subsequent deploy the existing file is kept.
        # The example is still staged at /tmp/config.env.example for manual
        # diffing of new keys.
        if [ ! -f /etc/firewall-mon/config.env ]; then
            sudo cp /tmp/config.env.example /etc/firewall-mon/config.env
            echo "Seeded /etc/firewall-mon/config.env from the example (first install)"
        else
            echo "Preserving existing /etc/firewall-mon/config.env (AUDIT-099); example at /tmp/config.env.example"
        fi
        sudo chmod +x /opt/firewall-mon/fwmon-*
        sudo cp /etc/systemd/system/fwmon-*.service /tmp/ 2>/dev/null || true
EOF

    log_info "Deployment complete!"
    # AUDIT-171 (adjacent): the old instruction pointed at
    # /opt/firewall-mon/scripts/install.sh, which was never shipped.
    log_info "Upgrade: restart services with: sudo systemctl restart fwmon-api fwmon-poller fwmon-trap"
    log_info "First install: run 'sudo ./deploy.sh install' from a repo checkout on the server to create the systemd units"
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
    # network port (8080, 162/udp), and a single memory-corruption
    # bug would give the attacker root. In the Docker path the long-running
    # daemons drop to the non-root `fwmon` user via su-exec, though the
    # container's init/PID1 still runs as root (there is NO `USER` directive in
    # the Dockerfile — AUDIT B1, a tracked follow-up). This native systemd path
    # runs the service as a dedicated non-root user throughout.
    create_service_user

    mkdir -p ${INSTALL_DIR}
    mkdir -p ${DATA_DIR}
    mkdir -p ${CONFIG_DIR}

    if [ -d "bin" ]; then
        cp bin/* ${INSTALL_DIR}/
        chmod +x ${INSTALL_DIR}/*
    fi

    # AUDIT-171: copy web/ WITH its directory prefix. The pre-fix copy
    # flattened web/* into ${INSTALL_DIR}, but the API binary loads HTML
    # templates via LoadHTMLGlob("./web/**/*.html") relative to the unit's
    # WorkingDirectory=${INSTALL_DIR}; a zero-match glob panics at startup
    # and Restart=always turns that into a permanent crash loop. The
    # rm -rf guard prevents `cp -r web dir/web` nesting web/web on
    # re-install.
    if [ -d "web" ]; then
        rm -rf ${INSTALL_DIR}/web
        cp -r web ${INSTALL_DIR}/web
    fi

    if [ ! -f "${CONFIG_DIR}/config.env" ]; then
        cp config.env.example ${CONFIG_DIR}/config.env
        log_warn "Please edit ${CONFIG_DIR}/config.env with your settings"
    fi

    # AUDIT-171 (adjacent): the old scripts-copy block is gone. scripts/
    # holds development-time audit helpers (*.py) only — no shell scripts
    # exist there, so under `set -e` the unexpanded shell-script glob made
    # cp fail and aborted the install before the systemd units were ever
    # created.

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
