#!/usr/bin/env bash
set -euo pipefail

# Prepare temporary SSHD honeypot environment under /tmp
ROOT_DIR="/tmp/sshd_honeypot"
CONFIG_PATH="/tmp/sshd_config_honeypot"
PORT="2222"

mkdir -p "$ROOT_DIR"

# Create privilege separation directory if missing
if [[ ! -d /run/sshd ]]; then
  sudo mkdir -p /run/sshd
  sudo chmod 755 /run/sshd
fi

# Generate host keys if missing
if [[ ! -f "$ROOT_DIR/ssh_host_rsa_key" ]]; then
  ssh-keygen -t rsa -b 2048 -f "$ROOT_DIR/ssh_host_rsa_key" -N "" -q
fi
if command -v ssh-keygen >/dev/null 2>&1; then
  if [[ ! -f "$ROOT_DIR/ssh_host_ecdsa_key" ]]; then
    ssh-keygen -t ecdsa -b 256 -f "$ROOT_DIR/ssh_host_ecdsa_key" -N "" -q || true
  fi
  if [[ ! -f "$ROOT_DIR/ssh_host_ed25519_key" ]]; then
    ssh-keygen -t ed25519 -f "$ROOT_DIR/ssh_host_ed25519_key" -N "" -q || true
  fi
fi

# Create minimal sshd_config
cat > "$CONFIG_PATH" <<EOF
Port ${PORT}
Protocol 2
ListenAddress 0.0.0.0
PidFile ${ROOT_DIR}/sshd.pid
UsePAM no
PasswordAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile none
PermitEmptyPasswords no
UsePrivilegeSeparation no
HostKey ${ROOT_DIR}/ssh_host_rsa_key
HostKey ${ROOT_DIR}/ssh_host_ecdsa_key
HostKey ${ROOT_DIR}/ssh_host_ed25519_key
EOF

chmod 600 "$CONFIG_PATH"
chmod 600 "$ROOT_DIR"/ssh_host_*_key || true

# Echo summary for logs
echo "Prepared SSHD honeypot config at $CONFIG_PATH"
echo "Host keys in $ROOT_DIR"
echo "Run: sudo /usr/sbin/sshd -D -f $CONFIG_PATH -p $PORT (or without sudo for port ${PORT})"
