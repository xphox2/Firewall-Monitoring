#!/bin/bash
# setup-claude-ssh.sh — one-time setup: key-based SSH from this Mac for
# Claude Code debugging sessions (rust-01 prod host + the OPNsense box).
# RUN THIS YOURSELF in a terminal — it prompts for each host's password once.
#
#   bash tasks/setup-claude-ssh.sh
#
# Edit the host/user variables below if they differ.
set -euo pipefail

RUST_HOST="66.179.9.149"   # rust-01
RUST_USER="xphox"
OPN_HOST="192.168.5.107"   # OPNsense (HOME-FW)
OPN_USER="claude"

KEY="$HOME/.ssh/id_ed25519"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"

if [ ! -f "$KEY" ]; then
    ssh-keygen -t ed25519 -f "$KEY" -N "" -C "claude-debug@$(hostname -s)"
    echo ">> Generated $KEY"
else
    echo ">> Using existing $KEY"
fi

CONF="$HOME/.ssh/config"
touch "$CONF"; chmod 600 "$CONF"
if ! grep -q "^Host rust-01\$" "$CONF"; then
    cat >> "$CONF" << EOC

Host rust-01
    HostName $RUST_HOST
    User $RUST_USER
    IdentityFile $KEY

Host opnsense
    HostName $OPN_HOST
    User $OPN_USER
    IdentityFile $KEY
EOC
    echo ">> Added rust-01 + opnsense aliases to ~/.ssh/config"
fi

echo ""
echo ">> Installing key on rust-01 — enter the $RUST_USER password when prompted."
echo "   (Your earlier interactive attempt was ALSO denied on password, so make"
echo "    sure this is the right password for '$RUST_USER' on $RUST_HOST — if the"
echo "    account is different, edit RUST_USER at the top and re-run.)"
ssh-copy-id -i "$KEY.pub" "$RUST_USER@$RUST_HOST"

echo ""
echo ">> Installing key on OPNsense ($OPN_USER) — enter its password when prompted."
ssh-copy-id -i "$KEY.pub" "$OPN_USER@$OPN_HOST" || echo "   (OPNsense copy failed — optional, continuing)"

echo ""
echo ">> Verifying key auth:"
ssh -o BatchMode=yes -o ConnectTimeout=8 rust-01 'echo "   rust-01 KEY AUTH OK on $(hostname)"'
ssh -o BatchMode=yes -o ConnectTimeout=8 opnsense 'echo "   opnsense KEY AUTH OK on $(hostname)"' || true
echo ">> Done. Claude can now use: ssh rust-01 / ssh opnsense"
