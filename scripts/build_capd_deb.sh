#!/usr/bin/env bash
# Build a .deb package for marlinspike-capd — a real, install-by-double-
# click alternative to `pip install ./marlinspike-capd` for Debian/Ubuntu
# hosts, matching build_agent_deb.sh's approach for the sibling agent
# package.
#
# Unlike the agent, capd has one third-party dependency (psutil, a C
# extension) — rather than vendor a wheel per architecture, this depends
# on the Debian python3-psutil package instead, alongside wireshark-common
# (dumpcap) and libpcap0.8, matching normal Debian packaging convention.
#
# Usage: scripts/build_capd_deb.sh [output-dir]
#   Writes <output-dir>/marlinspike-capd_<version>_all.deb
#   (output-dir defaults to ./dist)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPD_SRC="$REPO_ROOT/marlinspike-capd"
OUT_DIR="${1:-$REPO_ROOT/dist}"
mkdir -p "$OUT_DIR"

VERSION="$(python3 -c "
import tomllib
with open('$CAPD_SRC/pyproject.toml', 'rb') as f:
    print(tomllib.load(f)['project']['version'])
" 2>/dev/null || python3 -c "
import re
print(re.search(r'version\s*=\s*\"([^\"]+)\"', open('$CAPD_SRC/pyproject.toml').read()).group(1))
")"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
PKG_ROOT="$BUILD_DIR/marlinspike-capd_${VERSION}_all"

mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/usr/lib/marlinspike-capd"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/lib/systemd/system"
mkdir -p "$PKG_ROOT/usr/share/doc/marlinspike-capd"

# ── Control files ─────────────────────────────────────────────
sed "s/__VERSION__/${VERSION}/" "$CAPD_SRC/debian/control" > "$PKG_ROOT/DEBIAN/control"
install -m 0755 "$CAPD_SRC/debian/postinst" "$PKG_ROOT/DEBIAN/postinst"
install -m 0755 "$CAPD_SRC/debian/prerm" "$PKG_ROOT/DEBIAN/prerm"
install -m 0755 "$CAPD_SRC/debian/postrm" "$PKG_ROOT/DEBIAN/postrm"

# ── Payload: the capd/ package tree, source only ─────────────
cp -r "$CAPD_SRC/capd" "$PKG_ROOT/usr/lib/marlinspike-capd/capd"
find "$PKG_ROOT/usr/lib/marlinspike-capd" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$PKG_ROOT/usr/lib/marlinspike-capd" -name "*.pyc" -delete 2>/dev/null || true

# ── Wrapper entry point ──────────────────────────────────────
cat > "$PKG_ROOT/usr/bin/marlinspike-capd" <<'WRAPPER'
#!/bin/sh
exec python3 -c "import sys; sys.path.insert(0, '/usr/lib/marlinspike-capd'); from capd.cli import main; sys.exit(main())" "$@"
WRAPPER
chmod 0755 "$PKG_ROOT/usr/bin/marlinspike-capd"

# ── systemd unit (ExecStart adjusted for the packaged binary path) ──
sed 's#/usr/local/bin/marlinspike-capd#/usr/bin/marlinspike-capd#' \
    "$CAPD_SRC/systemd/marlinspike-capd.service" \
    > "$PKG_ROOT/lib/systemd/system/marlinspike-capd.service"

# ── Docs ──────────────────────────────────────────────────────
cp "$CAPD_SRC/README.md" "$PKG_ROOT/usr/share/doc/marlinspike-capd/README.md"
cp "$CAPD_SRC/debian/copyright" "$PKG_ROOT/usr/share/doc/marlinspike-capd/copyright"
cp "$REPO_ROOT/LICENSE" "$PKG_ROOT/usr/share/doc/marlinspike-capd/LICENSE"

# ── Build ─────────────────────────────────────────────────────
# --root-owner-group already forces root:root ownership in the archive
# metadata without needing an actual root/fakeroot process — that's the
# flag's whole purpose (dpkg >= 1.19), so no fakeroot dependency here.
DEB_PATH="$OUT_DIR/marlinspike-capd_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_PATH"

echo "Wrote $DEB_PATH"
