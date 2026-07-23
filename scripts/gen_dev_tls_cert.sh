#!/usr/bin/env bash
# Generate a self-signed TLS cert+key for the fleet gateway — LOCAL/DEV
# TESTING ONLY. A real deployment should use a cert from a real CA (or an
# internal CA you operate) instead of this script's output.
#
# Usage: scripts/gen_dev_tls_cert.sh [extra-hostname-or-ip ...]
#   scripts/gen_dev_tls_cert.sh
#   scripts/gen_dev_tls_cert.sh fleet.example.com 203.0.113.10
#
# Writes ./certs/gateway.crt and ./certs/gateway.key (0600), which is
# exactly what docker-compose.yml's fleet-gateway service mounts at /certs.

set -euo pipefail

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
mkdir -p "$OUT_DIR"

SAN="DNS:localhost,IP:127.0.0.1"
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="${SAN},IP:${extra}"
  else
    SAN="${SAN},DNS:${extra}"
  fi
done

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/gateway.key" \
  -out "$OUT_DIR/gateway.crt" \
  -days 365 \
  -subj "/CN=marlinspike-fleet-gateway" \
  -addext "subjectAltName=${SAN}"

# 644 rather than the usual 600: this file is bind-mounted read-only into
# the fleet-gateway container, which reads it as uid 1000 (not root, since
# it's the same non-root image as the main app) — a stricter mode would
# hit the exact same host-root-vs-container-uid mismatch already fixed
# for capd's socket and capture files. Fine for a throwaway dev cert; a
# real deployment's cert/key should be chowned to the runtime uid instead
# of loosened this way.
chmod 644 "$OUT_DIR/gateway.key"
chmod 644 "$OUT_DIR/gateway.crt"

echo "Wrote $OUT_DIR/gateway.crt and $OUT_DIR/gateway.key (SAN: ${SAN})"
echo "Point agents at this with: marlinspike-agent enroll --ca-cert $OUT_DIR/gateway.crt ..."
