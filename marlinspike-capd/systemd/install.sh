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

install -m 0644 "$UNIT_SRC" "$UNIT_DST"
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
echo "The socket only trusts root by default — the web app (or a remote"
echo "marlinspike-agent) connects as some other uid, which must be"
echo "explicitly allowed or every request fails as unauthorized. Add"
echo "--allow-uid=<uid> to ExecStart in $UNIT_DST for each uid that"
echo "needs to connect (the web app's container uid, or marlinspike-agent's"
echo "uid on a remote sensor host — check with 'id marlinspike-agent'),"
echo "then 'systemctl daemon-reload && systemctl restart marlinspike-capd'."
