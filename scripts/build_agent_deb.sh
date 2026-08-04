#!/usr/bin/env bash
# Build a .deb package for marlinspike-agent — a real, install-by-double-
# click alternative to `pip install -e .` for Debian/Ubuntu hosts.
#
# Pure-Python, zero third-party dependencies (see marlinspike-agent's own
# docstrings), so this deliberately doesn't use dh_python3/debhelper — it
# assembles the package tree directly and calls dpkg-deb, matching how
# many simple non-Debian-native tools ship their .deb.
#
# No analysis engine is bundled here — the agent only captures and
# forwards raw pcap bytes; the central fleet-gateway runs the actual
# engine and produces the report. Nothing beyond the agent/ package tree
# itself needs to ship in this .deb.
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
mkdir -p "$PKG_ROOT/usr/share/marlinspike-agent"

# ── Bundle marlinspike-capd's own .deb inside this package's payload ──
# postinst installs it automatically (see debian/postinst) so a plain
# `dpkg -i`/single-file `apt install` of just this .deb sets up a fully
# working sensor host, not just the relay half — Recommends alone can't
# guarantee that without a real apt repo serving both packages.
CAPD_BUILD_DIR="$(mktemp -d)"
bash "$REPO_ROOT/scripts/build_capd_deb.sh" "$CAPD_BUILD_DIR" >&2
cp "$CAPD_BUILD_DIR"/marlinspike-capd_*_all.deb "$PKG_ROOT/usr/share/marlinspike-agent/marlinspike-capd.deb"
rm -rf "$CAPD_BUILD_DIR"

# ── Control files ─────────────────────────────────────────────
sed "s/__VERSION__/${VERSION}/" "$AGENT_SRC/debian/control" > "$PKG_ROOT/DEBIAN/control"
install -m 0755 "$AGENT_SRC/debian/postinst" "$PKG_ROOT/DEBIAN/postinst"
install -m 0755 "$AGENT_SRC/debian/prerm" "$PKG_ROOT/DEBIAN/prerm"
install -m 0755 "$AGENT_SRC/debian/postrm" "$PKG_ROOT/DEBIAN/postrm"

# ── Payload: the agent/ package tree, source only ────────────
cp -r "$AGENT_SRC/agent" "$PKG_ROOT/usr/lib/marlinspike-agent/agent"

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
# --root-owner-group already forces root:root ownership in the archive
# metadata without needing an actual root/fakeroot process — that's the
# flag's whole purpose (dpkg >= 1.19), so no fakeroot dependency here.
DEB_PATH="$OUT_DIR/marlinspike-agent_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_PATH"

echo "Wrote $DEB_PATH"
