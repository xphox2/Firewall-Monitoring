#!/bin/bash

set -e

APP_NAME="fortigate-mon"
INSTALL_DIR="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
SYSTEMD_DIR="/etc/systemd/system"

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
    log_info "Building FortiGate Monitor..."

    if [ ! -f "go.mod" ]; then
        log_info "Initializing Go module..."
        go mod init fortiGate-Mon
    fi

    log_info "Downloading dependencies..."
    go mod tidy

    log_info "Building API server..."
    go build -o bin/fortigate-api ./cmd/api

    log_info "Building SNMP poller..."
    go build -o bin/fortigate-poller ./cmd/poller

    log_info "Building trap receiver..."
    go build -o bin/fortigate-trap ./cmd/trap-receiver

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
        sudo cp /tmp/web/* /opt/fortigate-mon/ -r
        sudo cp /tmp/config.env.example /etc/fortigate-mon/config.env
        sudo chmod +x /opt/fortigate-mon/fortigate-*
        sudo cp /etc/systemd/system/fortigate-*.service /tmp/ 2>/dev/null || true
EOF

    log_info "Deployment complete!"
    log_info "Connect to server and run: sudo /opt/fortigate-mon/scripts/install.sh"
}

install_local() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    log_info "Installing FortiGate Monitor..."

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

    log_info "Creating systemd services..."
    create_systemd_service "api" "${INSTALL_DIR}/fortigate-api" "FortiGate API Server"
    create_systemd_service "poller" "${INSTALL_DIR}/fortigate-poller" "FortiGate SNMP Poller"
    create_systemd_service "trap" "${INSTALL_DIR}/fortigate-trap" "FortiGate Trap Receiver"

    systemctl daemon-reload
    log_info "Installation complete!"
}

create_systemd_service() {
    local name=$1
    local binary=$2
    local desc=$3

    cat > ${SYSTEMD_DIR}/fortigate-${name}.service << EOF
[Unit]
Description=${desc}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_DIR}/config.env
ExecStart=${binary}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    log_info "Created fortigate-${name}.service"
}

start_services() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    log_info "Starting services..."
    systemctl start fortigate-api
    systemctl start fortigate-poller
    systemctl start fortigate-trap
    log_info "Services started!"
}

stop_services() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    log_info "Stopping services..."
    systemctl stop fortigate-api 2>/dev/null || true
    systemctl stop fortigate-poller 2>/dev/null || true
    systemctl stop fortigate-trap 2>/dev/null || true
    log_info "Services stopped!"
}

restart_services() {
    stop_services
    start_services
}

status_services() {
    systemctl status fortigate-api --no-pager || true
    systemctl status fortigate-poller --no-pager || true
    systemctl status fortigate-trap --no-pager || true
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
