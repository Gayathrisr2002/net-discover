#!/usr/bin/env bash
# Install marlinspike-capd as a systemd service.
#
# Run as root. Idempotent — safe to re-run.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (use sudo)" >&2
  exit 1
fi

UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/marlinspike-capd.service"
UNIT_DST="/etc/systemd/system/marlinspike-capd.service"

if ! id marlinspike-capd >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin marlinspike-capd
fi

# dumpcap (Wireshark) is installed non-setuid on Debian/Ubuntu — only root
# and members of the `wireshark` group may execute it (mode is typically
# rwxr-x---+, i.e. no execute bit for "other"). Without this, capd's own
# CAP_NET_RAW/CAP_NET_ADMIN grant (below) is irrelevant: the dumpcap exec
# itself fails before those capabilities ever matter, surfacing as a
# confusing "dumpcap not found on PATH" even though `which dumpcap` finds
# it fine as root.
if getent group wireshark >/dev/null; then
  usermod -aG wireshark marlinspike-capd
fi

# If marlinspike-agent is already on this host, it needs group access to
# read rotated PCAPs (StateDirectoryMode=0750 — deliberately restricted,
# unlike the RPC socket's own directory) and a spot on the socket's
# allow-list (see below) — mirrors the .deb postinst's cross-package
# wiring for whichever install order this happens to be.
if id marlinspike-agent >/dev/null 2>&1; then
  usermod -aG marlinspike-capd marlinspike-agent
fi

install -m 0644 "$UNIT_SRC" "$UNIT_DST"

# The socket only trusts root by default (capd/cli.py) — the shipped
# unit's ExecStart already points --allow-uid-file at this file, which
# capd re-reads on every connection attempt (no restart needed to pick
# up a change). If marlinspike-agent already exists, add its uid now so
# a fresh install needs no manual step; a uid discovered later (e.g. the
# web app's own container uid, or marlinspike-agent installed
# afterward) can just be appended the same way — plain text, one uid
# per line, '#' comments and blank lines ignored.
mkdir -p /etc/marlinspike-capd
touch /etc/marlinspike-capd/allowed-uids
if id marlinspike-agent >/dev/null 2>&1; then
  agent_uid="$(id -u marlinspike-agent)"
  grep -qxF "$agent_uid" /etc/marlinspike-capd/allowed-uids 2>/dev/null || \
    echo "$agent_uid" >> /etc/marlinspike-capd/allowed-uids
fi

systemctl daemon-reload
systemctl enable --now marlinspike-capd.service

echo
echo "marlinspike-capd installed."
echo "  systemctl status marlinspike-capd"
echo "  journalctl -u marlinspike-capd -f"
echo
echo "Set in the MarlinSpike web app environment:"
echo "  LIVE_CAPTURE_ENABLED=true"
echo "  LIVE_CAPTURE_SOCKET=/var/run/marlinspike-capd/marlinspike-capd.sock"
echo
echo "The socket only trusts root and uids listed in"
echo "/etc/marlinspike-capd/allowed-uids by default. marlinspike-agent's"
echo "uid was added automatically if it was already installed; for any"
echo "other uid that needs to connect (e.g. the web app's own container"
echo "uid), just append it — no systemd edit or restart needed:"
echo "  echo <uid> | sudo tee -a /etc/marlinspike-capd/allowed-uids"
if id marlinspike-agent >/dev/null 2>&1 && systemctl is-active --quiet marlinspike-agent 2>/dev/null; then
  echo
  echo "marlinspike-agent is already running — it was just added to the"
  echo "marlinspike-capd group, but an already-running process won't see"
  echo "that until restarted: sudo systemctl restart marlinspike-agent"
fi
