#!/usr/bin/env bash
#
# Remove the awg-endpoints service.
#
# The vault and your sing-box config are NEVER touched without --purge-vault,
# because the vault is the only copy of every client private key.

set -euo pipefail

SERVICE_NAME=awg-endpoints
PREFIX=/opt/awg-endpoints
CONF_DIR=/etc/awg-endpoints
SVC_USER=awg-endpoints
SB_VAULT=/var/lib/awg-endpoints/vault.json
PURGE_VAULT=""
REMOVE_USER=""

usage() {
  cat <<EOF
Usage: sudo ./uninstall.sh [options]

  --service-user NAME  system user to remove (default: $SVC_USER)
  --vault PATH         vault location (default: $SB_VAULT)
  --remove-user        also delete the system user
  --purge-vault        also delete the vault — every client private key goes
                       with it and cannot be recovered
  --help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --service-user) SVC_USER="$2"; shift 2 ;;
    --vault)        SB_VAULT="$2"; shift 2 ;;
    --remove-user)  REMOVE_USER=yes; shift ;;
    --purge-vault)  PURGE_VAULT=yes; shift ;;
    --help|-h)      usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

if systemctl list-unit-files | grep -q "^$SERVICE_NAME.service"; then
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  say "stopped and disabled $SERVICE_NAME"
fi
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
rm -f "/etc/sudoers.d/$SERVICE_NAME"
rm -rf "$PREFIX"
rm -rf "$CONF_DIR"
say "removed unit, sudoers rule, $PREFIX and $CONF_DIR"

if [ "$PURGE_VAULT" = yes ]; then
  rm -f "$SB_VAULT"
  say "DELETED $SB_VAULT — those client keys are gone"
else
  say "kept $SB_VAULT (use --purge-vault to delete it)"
fi

if [ "$REMOVE_USER" = yes ] && id -u "$SVC_USER" >/dev/null 2>&1; then
  userdel "$SVC_USER" 2>/dev/null || true
  say "removed system user $SVC_USER"
fi

cat <<EOF

Left alone on purpose:
  - your sing-box config and its backups
  - the group permissions on /etc/sing-box (harmless; chgrp root to revert)
  - any route rules you added to sing-box
EOF
