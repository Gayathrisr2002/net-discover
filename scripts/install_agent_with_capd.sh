#!/usr/bin/env bash
# Build and install marlinspike-agent for this host.
#
# marlinspike-capd comes bundled inside the agent .deb's own payload and
# is installed automatically by its postinst (see
# marlinspike-agent/debian/postinst and scripts/build_agent_deb.sh) — so
# installing this one package is enough to set up a fully working sensor
# host, live capture included.
#
# Must be run as the user who can sudo, from an actual terminal (sudo
# needs a real TTY to prompt for a password — this fails non-interactively,
# e.g. piped through a chat tool's shell). Rebuilds unconditionally so a
# fresh checkout is always what gets installed.
#
# Usage: scripts/install_agent_with_capd.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/dist"

echo "Building marlinspike-agent (bundling marlinspike-capd)..."
bash "$REPO_ROOT/scripts/build_agent_deb.sh" "$OUT_DIR"

AGENT_DEB="$(ls -t "$OUT_DIR"/marlinspike-agent_*_all.deb | head -1)"

echo
echo "Installing $AGENT_DEB (sudo will prompt)..."
sudo apt install -y "$AGENT_DEB"

if systemctl is-active --quiet marlinspike-agent 2>/dev/null; then
  echo "Restarting marlinspike-agent to pick up its new capd/wireshark group membership..."
  sudo systemctl restart marlinspike-agent
fi

echo
echo "Done. Verify with:"
echo "  systemctl status marlinspike-capd"
echo "  systemctl status marlinspike-agent"
