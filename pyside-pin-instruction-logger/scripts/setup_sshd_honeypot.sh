#!/usr/bin/env bash
set -euo pipefail

# Prepare an SSHD honeypot environment.
# Defaults are project-local to avoid /tmp ownership/permissions issues.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
DEFAULT_ROOT_DIR="$REPO_ROOT/projects/sshd/runtime/sshd_honeypot"
DEFAULT_CONFIG_PATH="$REPO_ROOT/projects/sshd/runtime/sshd_config_honeypot"
LEGACY_CONFIG_PATH="/tmp/sshd_config_honeypot"

ROOT_DIR="$DEFAULT_ROOT_DIR"
CONFIG_PATH="$DEFAULT_CONFIG_PATH"
PORT="2222"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--root DIR] [--config PATH] [--port PORT]

Defaults:
  --root   $DEFAULT_ROOT_DIR
  --config $DEFAULT_CONFIG_PATH
  --port   2222

Notes:
  This script also maintains a legacy config at $LEGACY_CONFIG_PATH for
  backwards compatibility with older runs that still use '-f /tmp/sshd_config_honeypot'.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT_DIR="$2"; shift 2 ;;
    --config)
      CONFIG_PATH="$2"; shift 2 ;;
    --port)
      PORT="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname -- "$CONFIG_PATH")"

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
cfg_payload=$(cat <<EOF
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
)

printf "%s\n" "$cfg_payload" > "$CONFIG_PATH"

# sshd config should be readable; keys should remain strict.
chmod 0644 "$CONFIG_PATH" || true
chmod 0600 "$ROOT_DIR"/ssh_host_*_key || true

# Backwards compatibility: keep /tmp/sshd_config_honeypot updated.
# Prefer a symlink when possible (more obvious/debuggable), else copy.
legacy_target="$LEGACY_CONFIG_PATH"
if [[ "${EUID}" -eq 0 ]]; then
  # If running as root (e.g., pre-run executed under sudo), create/replace legacy path safely.
  rm -f "$legacy_target" || true
  ln -sf "$CONFIG_PATH" "$legacy_target" 2>/dev/null || cp -f "$CONFIG_PATH" "$legacy_target"
  chmod 0644 "$legacy_target" || true
  if [[ -n "${SUDO_USER:-}" ]]; then
    chown "${SUDO_USER}:${SUDO_USER}" "$CONFIG_PATH" "$legacy_target" 2>/dev/null || true
    chown -R "${SUDO_USER}:${SUDO_USER}" "$ROOT_DIR" 2>/dev/null || true
  fi
else
  rm -f "$legacy_target" 2>/dev/null || true
  ln -sf "$CONFIG_PATH" "$legacy_target" 2>/dev/null || cp -f "$CONFIG_PATH" "$legacy_target" 2>/dev/null || true
  chmod 0644 "$legacy_target" 2>/dev/null || true
fi

# Echo summary for logs
echo "Prepared SSHD honeypot config at $CONFIG_PATH"
echo "Host keys in $ROOT_DIR"
echo "Run: sudo /usr/sbin/sshd -D -f $CONFIG_PATH (or without sudo for port ${PORT})"
