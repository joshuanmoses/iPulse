#!/usr/bin/env bash
#
# Remove iPulse from a systemd Linux host.
#
#   sudo scripts/uninstall.sh            keep the database and logs
#   sudo scripts/uninstall.sh --purge    delete everything
#
# Historical data is kept by default: an uninstall is often a reinstall, and months of
# measurements are not something to discard without being asked.

set -euo pipefail

SERVICE_USER="${IPULSE_USER:-ipulse}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="/etc/ipulse"
DATA_DIR="/var/lib/ipulse"
LOG_DIR="/var/log/ipulse"
PURGE=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    *) echo "usage: $0 [--purge]" >&2; exit 2 ;;
  esac
done

say()  { printf '  %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "this uninstaller must run as root (try: sudo $0)"

echo "Removing iPulse"

if command -v ipulse >/dev/null 2>&1 || [ -x "${PREFIX}/bin/ipulse" ]; then
  BIN="${PREFIX}/bin/ipulse"
  [ -x "$BIN" ] || BIN="$(command -v ipulse)"
  say "stopping and removing the service"
  if [ "$PURGE" = "1" ]; then
    "$BIN" service uninstall --purge || true
  else
    "$BIN" service uninstall --keep-data || true
  fi
fi

say "removing ${PREFIX}/bin/ipulse"
rm -f "${PREFIX}/bin/ipulse"
rm -f /etc/logrotate.d/ipulse

if [ "$PURGE" = "1" ]; then
  say "deleting configuration, data and logs"
  rm -rf "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    say "removing the ${SERVICE_USER} account"
    userdel "$SERVICE_USER" 2>/dev/null || true
  fi
  echo
  echo "iPulse and all of its data have been removed."
else
  echo
  echo "iPulse has been removed. Historical data was kept:"
  echo "  configuration  ${CONFIG_DIR}"
  echo "  data           ${DATA_DIR}"
  echo "  logs           ${LOG_DIR}"
  echo
  echo "Re-run with --purge to delete these as well."
fi
