#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo 'Run this installer as root.' >&2
    exit 1
fi

REPOSITORY=${SNC_REPOSITORY:-https://github.com/DgekStr/SmallnGinxControl.git}
RELEASE_TAG=${SNC_RELEASE_TAG:-v1.0.2}
INSTALL_DIR=${SNC_INSTALL_DIR:-/opt/smallnginxcontrol}
ENV_FILE=/etc/smallnginxcontrol.env
SERVICE_FILE=/etc/systemd/system/smallnginxcontrol.service
CLEANUP_SERVICE_FILE=/etc/systemd/system/smallnginxcontrol-log-cleanup.service
CLEANUP_TIMER_FILE=/etc/systemd/system/smallnginxcontrol-log-cleanup.timer
STATE_DIR=/var/lib/smallnginxcontrol

if [[ ! $INSTALL_DIR =~ ^/[A-Za-z0-9_./-]+$ || $INSTALL_DIR == / || $INSTALL_DIR == *..* ]]; then
    echo 'SNC_INSTALL_DIR must be a simple absolute path without spaces or parent references.' >&2
    exit 1
fi
if [[ -e $ENV_FILE || -e $SERVICE_FILE || -e $CLEANUP_SERVICE_FILE || -e $CLEANUP_TIMER_FILE ]]; then
    echo 'Service configuration already exists; refusing to overwrite it.' >&2
    exit 1
fi
for command in git python3 systemctl; do
    command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

INSTALL_STARTED=0
cleanup_failed_install() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 && INSTALL_STARTED )); then
        echo 'Installation failed; removing generated service configuration. State data was preserved.' >&2
        systemctl disable --now smallnginxcontrol >/dev/null 2>&1 || true
        systemctl disable --now smallnginxcontrol-log-cleanup.timer >/dev/null 2>&1 || true
        rm -f "$SERVICE_FILE" "$CLEANUP_SERVICE_FILE" "$CLEANUP_TIMER_FILE" "$ENV_FILE"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}
trap cleanup_failed_install EXIT

if [[ -e $INSTALL_DIR || -L $INSTALL_DIR ]]; then
    checkout_ref=$(git -C "$INSTALL_DIR" symbolic-ref --quiet --short HEAD 2>/dev/null || git -C "$INSTALL_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)
    checkout_origin=$(git -C "$INSTALL_DIR" config --get remote.origin.url 2>/dev/null || true)
    if [[ $checkout_ref != "$RELEASE_TAG" || $checkout_origin != "$REPOSITORY" ]]; then
        echo 'Install path exists but is not the requested release checkout; refusing to overwrite it.' >&2
        exit 1
    fi
else
    git clone --depth 1 --branch "$RELEASE_TAG" "$REPOSITORY" "$INSTALL_DIR"
fi

while true; do
    if ! read -r -p 'IP address or DNS name used to open the panel: ' PANEL_HOST; then
        echo 'Could not read the panel address.' >&2
        exit 1
    fi
    PANEL_HOST=${PANEL_HOST%$'\r'}
    if [[ $PANEL_HOST =~ ^[A-Za-z0-9.-]+$ ]]; then
        break
    fi
    echo 'Enter a plain IPv4 address or DNS name, without scheme or port.' >&2
done

if ! python3 -m venv "$INSTALL_DIR/.venv"; then
    rm -rf "$INSTALL_DIR/.venv"
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    venv_package="python${python_version}-venv"
    if ! command -v apt-get >/dev/null || ! apt-get update || ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$venv_package"; then
        printf 'Could not install %s automatically. Install it manually and rerun.\n' "$venv_package" >&2
        exit 1
    fi
    if ! python3 -m venv "$INSTALL_DIR/.venv"; then
        rm -rf "$INSTALL_DIR/.venv"
        printf 'Could not create the virtual environment after installing %s.\n' "$venv_package" >&2
        exit 1
    fi
    printf 'Installed %s and created the virtual environment.\n' "$venv_package"
fi
"$INSTALL_DIR/.venv/bin/python" -m pip install --disable-pip-version-check --no-input -r "$INSTALL_DIR/requirements.txt"

install -d -o root -g root -m 0700 "$STATE_DIR"
INSTALL_STARTED=1
umask 077
cat > "$ENV_FILE" <<ENV
SNC_MODE=local
SNC_STATE_DIR=$STATE_DIR
SNC_NGINX_ROOT=/etc/nginx
SNC_LOG_ROOT=/var/log/nginx
SNC_LOG_EXTRA_ROOTS=/var/http
SNC_MAINTENANCE_ROOT=/var/www/html
SNC_ACME_WEBROOT=/var/www/html
SNC_CERTBOT_BIN=/usr/bin/certbot
SNC_CERTBOT_LIVE_ROOT=/etc/letsencrypt/live
SNC_NGINX_BIN=/usr/sbin/nginx
SNC_SERVER=$PANEL_HOST
SNC_BIND=127.0.0.1
SNC_PORT=7444
SNC_ALLOWED_HOSTS=127.0.0.1,localhost,$PANEL_HOST
SNC_INTERFACE=
SNC_CSRF_ORIGINS=
SNC_TRUST_PROXY=0
SNC_SECURE_COOKIES=0
ENV
chmod 0600 "$ENV_FILE"

service_temp=$(mktemp)
sed "s|/opt/smallnginxcontrol|$INSTALL_DIR|g" "$INSTALL_DIR/deploy/smallnginxcontrol.service" > "$service_temp"
install -o root -g root -m 0644 "$service_temp" "$SERVICE_FILE"
rm -f "$service_temp"
cleanup_service_temp=$(mktemp)
sed "s|/opt/smallnginxcontrol|$INSTALL_DIR|g" "$INSTALL_DIR/deploy/smallnginxcontrol-log-cleanup.service" > "$cleanup_service_temp"
install -o root -g root -m 0644 "$cleanup_service_temp" "$CLEANUP_SERVICE_FILE"
rm -f "$cleanup_service_temp"
install -o root -g root -m 0644 "$INSTALL_DIR/deploy/smallnginxcontrol-log-cleanup.timer" "$CLEANUP_TIMER_FILE"

set -a
. "$ENV_FILE"
set +a
while true; do
    if ! read -r -s -p 'Initial administrator password (10+ characters, not numeric-only): ' SNC_INITIAL_PASSWORD; then
        printf '\n' >&2
        echo 'Could not read the administrator password.' >&2
        exit 1
    fi
    printf '\n'
    export SNC_INITIAL_PASSWORD
    if "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/manage.py" shell -c '
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
import os
validate_password(os.environ["SNC_INITIAL_PASSWORD"], user=get_user_model()(username="admin"))
' >/dev/null 2>&1; then
        break
    fi
    unset SNC_INITIAL_PASSWORD
    echo 'Password was rejected by Django. Choose a longer, uncommon password and retry.' >&2
done
"$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/bootstrap.py"
unset SNC_INITIAL_PASSWORD
"$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/manage.py" collectstatic --noinput
"$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/manage.py" check

systemctl daemon-reload
systemctl enable --now smallnginxcontrol
systemctl enable --now smallnginxcontrol-log-cleanup.timer
systemctl --no-pager --full status smallnginxcontrol

printf '\nInstalled %s (%s).\n' "$INSTALL_DIR" "$RELEASE_TAG"
printf 'Open a local SSH tunnel with: ssh -N -L 7444:127.0.0.1:7444 root@%s\n' "$PANEL_HOST"
printf 'Then visit http://127.0.0.1:7444. Do not expose the loopback HTTP upstream directly.\n'