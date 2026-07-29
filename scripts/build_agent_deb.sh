#!/usr/bin/env bash
# Build a .deb package for marlinspike-agent — a real, install-by-double-
# click alternative to `pip install -e .` for Debian/Ubuntu hosts.
#
# Pure-Python, zero third-party dependencies for the agent's own transport
# layer (see marlinspike-agent's own docstrings), so this deliberately
# doesn't use dh_python3/debhelper — it assembles the package tree directly
# and calls dpkg-deb, matching how many simple non-Debian-native tools
# ship their .deb.
#
# Also bundles the marlinspike analysis engine itself (marlinspike/ +
# plugins/ + rules/ + presets/ + oui.json) under
# /usr/lib/marlinspike-agent/engine — agent/consumer.py's run_scan needs
# this importable to actually run a scan on each rotated capture, and
# without it bundled here there is no supported way to get it onto a bare
# remote sensor host at all. engine.py has zero Flask/SQLAlchemy/DB
# imports (marlinspike/__init__.py lazy-loads those via __getattr__, only
# on first access) — confirmed directly: `python3 -c "import
# marlinspike.engine"` succeeds with none of requirements.txt installed.
# tshark is a Depends (debian/control) since it's a system package, not
# something to vendor.
#
# Usage: scripts/build_agent_deb.sh [output-dir]
#   Writes <output-dir>/marlinspike-agent_<version>_all.deb
#   (output-dir defaults to ./dist)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_SRC="$REPO_ROOT/marlinspike-agent"
OUT_DIR="${1:-$REPO_ROOT/dist}"
mkdir -p "$OUT_DIR"

VERSION="$(python3 -c "
import tomllib
with open('$AGENT_SRC/pyproject.toml', 'rb') as f:
    print(tomllib.load(f)['project']['version'])
" 2>/dev/null || python3 -c "
import re
print(re.search(r'version\s*=\s*\"([^\"]+)\"', open('$AGENT_SRC/pyproject.toml').read()).group(1))
")"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
PKG_ROOT="$BUILD_DIR/marlinspike-agent_${VERSION}_all"

mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/usr/lib/marlinspike-agent"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/lib/systemd/system"
mkdir -p "$PKG_ROOT/usr/share/doc/marlinspike-agent"

# ── Control files ─────────────────────────────────────────────
sed "s/__VERSION__/${VERSION}/" "$AGENT_SRC/debian/control" > "$PKG_ROOT/DEBIAN/control"
install -m 0755 "$AGENT_SRC/debian/postinst" "$PKG_ROOT/DEBIAN/postinst"
install -m 0755 "$AGENT_SRC/debian/prerm" "$PKG_ROOT/DEBIAN/prerm"
install -m 0755 "$AGENT_SRC/debian/postrm" "$PKG_ROOT/DEBIAN/postrm"

# ── Payload: the agent/ package tree, source only ────────────
cp -r "$AGENT_SRC/agent" "$PKG_ROOT/usr/lib/marlinspike-agent/agent"

# ── Payload: the bundled analysis engine (agent/consumer.py's
# _BUNDLED_ENGINE_DIR) — same layout PYTHONPATH needs: marlinspike/,
# plugins/, rules/, presets/, oui.json all as direct siblings.
ENGINE_DST="$PKG_ROOT/usr/lib/marlinspike-agent/engine"
mkdir -p "$ENGINE_DST"
cp -r "$REPO_ROOT/marlinspike" "$ENGINE_DST/marlinspike"
cp -r "$REPO_ROOT/plugins" "$ENGINE_DST/plugins"
cp -r "$REPO_ROOT/rules" "$ENGINE_DST/rules"
cp -r "$REPO_ROOT/presets" "$ENGINE_DST/presets"
# oui.json: dev checkout layout has it at data/oui.json; inside the
# Docker image (this script also runs there, building the .deb the
# Fleet page serves) the Dockerfile already flattens it to ./oui.json
# directly, and data/ itself is never copied in wholesale — try both.
if [[ -f "$REPO_ROOT/data/oui.json" ]]; then
  cp "$REPO_ROOT/data/oui.json" "$ENGINE_DST/oui.json"
else
  cp "$REPO_ROOT/oui.json" "$ENGINE_DST/oui.json"
fi

find "$PKG_ROOT/usr/lib/marlinspike-agent" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$PKG_ROOT/usr/lib/marlinspike-agent" -name "*.pyc" -delete 2>/dev/null || true

# ── Wrapper entry point ──────────────────────────────────────
cat > "$PKG_ROOT/usr/bin/marlinspike-agent" <<'WRAPPER'
#!/bin/sh
exec python3 -c "import sys; sys.path.insert(0, '/usr/lib/marlinspike-agent'); from agent.cli import main; sys.exit(main())" "$@"
WRAPPER
chmod 0755 "$PKG_ROOT/usr/bin/marlinspike-agent"

# ── systemd unit (ExecStart adjusted for the packaged binary path) ──
sed 's#/usr/local/bin/marlinspike-agent#/usr/bin/marlinspike-agent#' \
    "$AGENT_SRC/systemd/marlinspike-agent.service" \
    > "$PKG_ROOT/lib/systemd/system/marlinspike-agent.service"

# ── Docs ──────────────────────────────────────────────────────
cp "$AGENT_SRC/README.md" "$PKG_ROOT/usr/share/doc/marlinspike-agent/README.md"
cp "$AGENT_SRC/debian/copyright" "$PKG_ROOT/usr/share/doc/marlinspike-agent/copyright"
cp "$REPO_ROOT/LICENSE" "$PKG_ROOT/usr/share/doc/marlinspike-agent/LICENSE"

# ── Build ─────────────────────────────────────────────────────
DEB_PATH="$OUT_DIR/marlinspike-agent_${VERSION}_all.deb"
fakeroot dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_PATH"

echo "Wrote $DEB_PATH"
