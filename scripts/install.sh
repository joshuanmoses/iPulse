#!/usr/bin/env bash
#
# Install iPulse on a systemd Linux host.
#
#   sudo scripts/install.sh
#
# What it does, in order: create a dedicated unprivileged account, install the binary,
# create the configuration, data and log directories with tight permissions, register
# the systemd unit, and start the service.
#
# The service does not run as root. It is given exactly two capabilities: CAP_NET_RAW
# for ICMP and path measurement, and CAP_DAC_READ_SEARCH so connections can be attributed
# to the processes that own them. See docs/security.md for what each one buys.

set -euo pipefail

SERVICE_USER="${IPULSE_USER:-ipulse}"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
CONFIG_DIR="/etc/ipulse"
DATA_DIR="/var/lib/ipulse"
LOG_DIR="/var/log/ipulse"
BINARY="${IPULSE_BINARY:-}"

say()  { printf '  %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "this installer must run as root (try: sudo $0)"

# Locate the binary: an explicit path, a cross-compiled artifact, or a local build.
if [ -z "$BINARY" ]; then
  for candidate in \
      "$(dirname "$0")/../bin/ipulse" \
      "$(dirname "$0")/../dist/linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')/ipulse" \
      "./ipulse"; do
    if [ -x "$candidate" ]; then BINARY="$candidate"; break; fi
  done
fi
[ -n "$BINARY" ] && [ -x "$BINARY" ] || fail "no iPulse binary found; run scripts/build.sh first"

echo "Installing iPulse"

if ! [ -d /run/systemd/system ]; then
  say "warning: systemd is not running; the binary will be installed but no service registered"
  SKIP_SERVICE=1
fi

# 1. Service account. A system account with no shell and no home: it exists only to own
#    the agent's files and its process.
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  say "creating system account ${SERVICE_USER}"
  useradd --system --no-create-home --shell /usr/sbin/nologin \
          --comment "iPulse monitoring agent" "$SERVICE_USER" 2>/dev/null \
    || useradd --system --no-create-home --shell /sbin/nologin \
               --comment "iPulse monitoring agent" "$SERVICE_USER"
else
  say "using existing account ${SERVICE_USER}"
fi

# 2. Binary.
say "installing ${BIN_DIR}/ipulse"
install -d -m 0755 "$BIN_DIR"
install -m 0755 "$BINARY" "${BIN_DIR}/ipulse"

# 3. Directories. The data directory holds connection metadata, so it is not
#    world-readable.
say "creating ${CONFIG_DIR}, ${DATA_DIR} and ${LOG_DIR}"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"

# 4. Configuration, only if absent: an upgrade must never overwrite local settings.
if [ -f "${CONFIG_DIR}/ipulse.yaml" ]; then
  say "keeping existing ${CONFIG_DIR}/ipulse.yaml"
else
  say "writing default ${CONFIG_DIR}/ipulse.yaml"
  if [ -f "$(dirname "$0")/../configs/ipulse.yaml" ]; then
    install -m 0640 -o root -g "$SERVICE_USER" \
      "$(dirname "$0")/../configs/ipulse.yaml" "${CONFIG_DIR}/ipulse.yaml"
  else
    "${BIN_DIR}/ipulse" config init --config "${CONFIG_DIR}/ipulse.yaml"
    chown root:"$SERVICE_USER" "${CONFIG_DIR}/ipulse.yaml"
    chmod 0640 "${CONFIG_DIR}/ipulse.yaml"
  fi
fi

# 5. Validate before starting: a service that fails at boot because of a typo is a
#    worse outcome than a refusal here.
say "validating configuration"
"${BIN_DIR}/ipulse" config validate --config "${CONFIG_DIR}/ipulse.yaml" || \
  fail "the configuration is not valid; fix it and re-run"

# 6. Log rotation is built in, but a logrotate drop-in is provided for sites that
#    prefer to manage rotation centrally. It is disabled by default.
if [ -d /etc/logrotate.d ]; then
  cat > /etc/logrotate.d/ipulse <<'LOGROTATE'
# iPulse rotates its own logs (see the logging section of ipulse.yaml).
# This file is provided for sites that prefer logrotate to own rotation instead:
# set logging.max_file_mb very high and logging.rotate_daily false, then uncomment.
#
#/var/log/ipulse/*.log /var/log/ipulse/*.jsonl {
#    daily
#    rotate 30
#    compress
#    delaycompress
#    missingok
#    notifempty
#    create 0640 ipulse ipulse
#    copytruncate
#}
LOGROTATE
  say "installed /etc/logrotate.d/ipulse (commented out by default)"
fi

if [ "${SKIP_SERVICE:-0}" = "1" ]; then
  echo
  echo "iPulse installed. Run it in the foreground with:"
  echo "  ${BIN_DIR}/ipulse run"
  exit 0
fi

# 7. Register and start the service.
say "registering the systemd service"
"${BIN_DIR}/ipulse" service install --user "$SERVICE_USER" --config "${CONFIG_DIR}/ipulse.yaml"

echo
echo "iPulse installed."
"${BIN_DIR}/ipulse" service status || true
echo
echo "  configuration  ${CONFIG_DIR}/ipulse.yaml"
echo "  data           ${DATA_DIR}"
echo "  logs           ${LOG_DIR}"
echo "  dashboard      http://127.0.0.1:8750"
echo
echo "Next steps:"
echo "  1. Set your ISP plan in ${CONFIG_DIR}/ipulse.yaml (speed_test.expected_*_mbps)"
echo "  2. sudo systemctl restart ipulse"
echo "  3. ipulse status"
