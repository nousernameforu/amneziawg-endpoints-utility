#!/usr/bin/env bash
#
# Install the AmneziaWG endpoints editor as a systemd service.
#
# Runs as a dedicated system user, not root: the app holds every client private
# key and rewrites a file the daemon loads, so it gets its own identity and a
# systemd sandbox rather than the run of the machine.
#
# Re-running is safe — it updates the files and the unit in place.

set -euo pipefail

SERVICE_NAME=awg-endpoints
PREFIX=/opt/awg-endpoints
CONF_DIR=/etc/awg-endpoints
SVC_USER=awg-endpoints
SB_CONFIG=/etc/sing-box/config.json
STATE_DIR=/var/lib/awg-endpoints
SB_VAULT=$STATE_DIR/vault.json
SB_SERVICE=sing-box.service
HOST=127.0.0.1
PORT=8787
ADMIN_USER=admin
PASSWORD=""
WITH_RESTART=""
ASSUME_YES=""

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: sudo ./install.sh [options]

  --host ADDR         bind address (default: $HOST)
  --port N            bind port (default: $PORT)
  --user NAME         admin login for the web UI (default: $ADMIN_USER)
  --password PASS     admin password (default: prompt; use - to read stdin)
  --config PATH       sing-box config (default: $SB_CONFIG)
  --vault PATH        key sidecar (default: $SB_VAULT)
  --service-user NAME system user to run as (default: $SVC_USER)
  --sing-box-unit U   sing-box unit name (default: $SB_SERVICE)
  --with-restart      allow the app to restart sing-box (installs a sudoers rule)
  --no-restart        do not (default)
  --yes               do not ask anything; fail instead of prompting
  --help

Examples:
  sudo ./install.sh
  sudo ./install.sh --port 8080 --with-restart
  printf 'my-password\\n' | sudo ./install.sh --password - --yes
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host)          HOST="$2"; shift 2 ;;
    --port)          PORT="$2"; shift 2 ;;
    --user)          ADMIN_USER="$2"; shift 2 ;;
    --password)      PASSWORD="$2"; shift 2 ;;
    --config)        SB_CONFIG="$2"; shift 2 ;;
    --vault)         SB_VAULT="$2"; shift 2 ;;
    --service-user)  SVC_USER="$2"; shift 2 ;;
    --sing-box-unit) SB_SERVICE="$2"; shift 2 ;;
    --with-restart)  WITH_RESTART=yes; shift ;;
    --no-restart)    WITH_RESTART=no; shift ;;
    --yes)           ASSUME_YES=yes; shift ;;
    --help|-h)       usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || die "run this with sudo"
command -v systemctl >/dev/null || die "systemd is required"
command -v python3   >/dev/null || die "python3 is required"
python3 - <<'PY' || die "python 3.8 or newer is required"
import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY
[ -f "$SRC_DIR/server.py" ] || die "run this from the source directory"

# ---------------------------------------------------------------- interactive

if [ "$PASSWORD" = "-" ]; then
  IFS= read -r PASSWORD || die "no password on stdin"
elif [ -z "$PASSWORD" ]; then
  [ -n "$ASSUME_YES" ] && die "--yes given but no --password"
  [ -t 0 ] || die "no terminal to prompt on; pass --password"
  printf 'Admin password for the web UI (user "%s"): ' "$ADMIN_USER" >&2
  read -rs PASSWORD; echo >&2
  printf 'Again: ' >&2
  read -rs PASSWORD2; echo >&2
  [ "$PASSWORD" = "$PASSWORD2" ] || die "passwords do not match"
fi
[ -n "$PASSWORD" ] || die "empty password"

if [ -z "$WITH_RESTART" ]; then
  if [ -n "$ASSUME_YES" ] || [ ! -t 0 ]; then
    WITH_RESTART=no
  else
    printf 'Allow the app to restart %s? Needs a sudoers rule and weakens\n' "$SB_SERVICE" >&2
    printf 'the sandbox (NoNewPrivileges off). [y/N]: ' >&2
    read -r reply
    case "$reply" in [yY]*) WITH_RESTART=yes ;; *) WITH_RESTART=no ;; esac
  fi
fi

# --------------------------------------------------------------------- install

echo
echo "Installing $SERVICE_NAME"

if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home \
          --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
  say "created system user $SVC_USER"
else
  say "system user $SVC_USER already exists"
fi
SVC_GROUP="$(id -gn "$SVC_USER")"

install -d -m 0755 "$PREFIX"
install -m 0644 "$SRC_DIR/server.py"  "$PREFIX/server.py"
install -m 0644 "$SRC_DIR/README.md"  "$PREFIX/README.md" 2>/dev/null || true
rm -rf "$PREFIX/static"
install -d -m 0755 "$PREFIX/static"
install -m 0644 "$SRC_DIR"/static/* "$PREFIX/static/"
say "installed to $PREFIX"

# --- credentials -------------------------------------------------------------

# --- optional restart hook (decided before the config file is written) -------

SUDOERS=/etc/sudoers.d/$SERVICE_NAME
RESTART_CMD=""
NNP=yes
RESTRICT_SUID=yes
if [ "$WITH_RESTART" = yes ]; then
  SYSTEMCTL="$(command -v systemctl)"
  printf '%s ALL=(root) NOPASSWD: %s restart %s\n' \
         "$SVC_USER" "$SYSTEMCTL" "$SB_SERVICE" > "$SUDOERS"
  chmod 0440 "$SUDOERS"
  if command -v visudo >/dev/null && ! visudo -cqf "$SUDOERS"; then
    rm -f "$SUDOERS"
    die "generated sudoers rule failed validation; nothing installed"
  fi
  RESTART_CMD="sudo -n $SYSTEMCTL restart $SB_SERVICE"
  NNP=no
  RESTRICT_SUID=no
  say "installed $SUDOERS (restart of $SB_SERVICE only)"
else
  rm -f "$SUDOERS"
  say "restart hook disabled"
fi

# --- config file -------------------------------------------------------------

install -d -m 0750 -o root -g "$SVC_GROUP" "$CONF_DIR"
CONF_FILE="$CONF_DIR/config.json"
HASH="$(printf '%s\n' "$PASSWORD" | python3 "$PREFIX/server.py" --hash-password)"
unset PASSWORD

# Start from the shipped template, then fill in this install's answers. Keeping
# the template as the source means the comments survive.
umask 077
python3 - "$SRC_DIR/packaging/config.json" "$CONF_FILE" <<PY
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()

def setval(text, key, value):
    return re.sub(r'("%s"\s*:\s*)("[^"]*"|true|false|\d+)' % key,
                  lambda m: m.group(1) + value, text, count=1)

text = setval(text, "sing_box_config", '"$SB_CONFIG"')
text = setval(text, "vault",           '"$SB_VAULT"')
text = setval(text, "host",            '"$HOST"')
text = setval(text, "port",            "$PORT")
text = setval(text, "user",            '"$ADMIN_USER"')
text = setval(text, "password",        '"$HASH"')
text = setval(text, "restart_cmd",     '"$RESTART_CMD"')
open(dst, "w", encoding="utf-8").write(text)
PY
chown root:"$SVC_GROUP" "$CONF_FILE"
chmod 0640 "$CONF_FILE"
say "wrote $CONF_FILE (password stored hashed)"

# Fail now rather than at first boot if the generated file is malformed.
python3 "$PREFIX/server.py" --config "$CONF_FILE" --check >/dev/null \
  || die "generated $CONF_FILE is not valid — nothing enabled"

# --- access to the sing-box files -------------------------------------------

SB_DIR="$(dirname "$SB_CONFIG")"
VAULT_DIR="$(dirname "$SB_VAULT")"
[ -d "$SB_DIR" ] || die "$SB_DIR does not exist — is sing-box installed?"

# sing-box is frequently run as `sing-box run -C /etc/sing-box`, which loads
# EVERY *.json in that directory. A vault in there gets parsed as configuration
# and puts the daemon in a crash loop, so refuse outright.
if [ "$VAULT_DIR" = "$SB_DIR" ]; then
  die "refusing to put the vault in $SB_DIR.

If sing-box is started with -C on that directory it loads every *.json in it,
would try to parse the vault as configuration, and would fail to start.
Pass --vault $STATE_DIR/vault.json (the default) or another directory."
fi

# The app replaces config.json atomically, which means creating a temp file in
# the directory and renaming over the target. That needs write on the DIRECTORY,
# not on the file. setgid keeps new files in the service group.
chgrp "$SVC_GROUP" "$SB_DIR"
chmod 2770 "$SB_DIR"
if [ -f "$SB_CONFIG" ]; then
  chgrp "$SVC_GROUP" "$SB_CONFIG"
  chmod 0640 "$SB_CONFIG"
fi
say "granted $SVC_GROUP write access to $SB_DIR"

# 2770 drops world access to the directory. Harmless when sing-box runs as root,
# but it would lock out a sing-box that runs as some other unprivileged user.
SB_RUNS_AS="$(systemctl show -p User --value "$SB_SERVICE" 2>/dev/null || true)"
[ -n "$SB_RUNS_AS" ] || SB_RUNS_AS=root
if [ "$SB_RUNS_AS" != root ] &&
   ! id -nG "$SB_RUNS_AS" 2>/dev/null | tr ' ' '\n' | grep -qx "$SVC_GROUP"; then
  echo
  echo "  WARNING: $SB_SERVICE runs as '$SB_RUNS_AS', which is not in group" >&2
  echo "  '$SVC_GROUP' and can no longer read $SB_DIR. Fix with:" >&2
  echo "      sudo usermod -aG $SVC_GROUP $SB_RUNS_AS && sudo systemctl restart $SB_SERVICE" >&2
  echo
fi

install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$VAULT_DIR"
if [ ! -f "$SB_VAULT" ]; then
  install -m 0600 -o "$SVC_USER" -g "$SVC_GROUP" /dev/null "$SB_VAULT"
  printf '{\n  "version": 1,\n  "endpoints": {}\n}\n' > "$SB_VAULT"
  chown "$SVC_USER:$SVC_GROUP" "$SB_VAULT"
  chmod 0600 "$SB_VAULT"
  say "created empty vault at $SB_VAULT"
else
  chown "$SVC_USER:$SVC_GROUP" "$SB_VAULT"
  chmod 0600 "$SB_VAULT"
  say "vault already present at $SB_VAULT"
fi

# --- capabilities ------------------------------------------------------------

CAPS=""
if [ "$PORT" -lt 1024 ]; then
  CAPS="CAP_NET_BIND_SERVICE"
  say "port $PORT is privileged; granting CAP_NET_BIND_SERVICE"
fi

# --- unit --------------------------------------------------------------------

RW_PATHS="$SB_DIR $VAULT_DIR"

UNIT=/etc/systemd/system/$SERVICE_NAME.service
sed -e "s|__PREFIX__|$PREFIX|g" \
    -e "s|__USER__|$SVC_USER|g" \
    -e "s|__GROUP__|$SVC_GROUP|g" \
    -e "s|__CONFIGFILE__|$CONF_FILE|g" \
    -e "s|__NNP__|$NNP|g" \
    -e "s|__RESTRICT_SUID__|$RESTRICT_SUID|g" \
    -e "s|__RW_PATHS__|$RW_PATHS|g" \
    -e "s|__CAPS__|$CAPS|g" \
    "$SRC_DIR/packaging/awg-endpoints.service" > "$UNIT"
chmod 0644 "$UNIT"
say "wrote $UNIT"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME" >/dev/null
sleep 1

# --- report ------------------------------------------------------------------

echo
if systemctl is-active --quiet "$SERVICE_NAME"; then
  echo "$SERVICE_NAME is running on http://$HOST:$PORT (user: $ADMIN_USER)"
else
  echo "$SERVICE_NAME failed to start:" >&2
  systemctl status "$SERVICE_NAME" --no-pager --lines=20 >&2 || true
  exit 1
fi

cat <<EOF

Check it:
  curl -si -u $ADMIN_USER:<password> http://$HOST:$PORT/api/state | head -1
  journalctl -u $SERVICE_NAME -f

EOF

if [ "$HOST" = "127.0.0.1" ] || [ "$HOST" = "::1" ]; then
  cat <<EOF
It is on loopback, so nothing off-box can reach it yet. Add a sing-box route
rule that redirects tunnel traffic to $HOST:$PORT — see examples/ and the
"Reaching it only through sing-box" section of the README.
EOF
fi
