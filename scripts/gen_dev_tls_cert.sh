#!/usr/bin/env bash
# Generate a dev fleet CA + gateway TLS cert, signed by that CA —
# LOCAL/DEV TESTING ONLY. A real deployment should use its own internal CA
# (or a real public CA for the gateway cert) instead of this script's output.
#
# Usage: scripts/gen_dev_tls_cert.sh [extra-hostname-or-ip ...]
#   scripts/gen_dev_tls_cert.sh
#   scripts/gen_dev_tls_cert.sh fleet.example.com 203.0.113.10
#
# Writes (idempotent — reuses an existing CA rather than regenerating it,
# so previously-issued agent client certs stay valid across re-runs):
#   ./certs/fleet-ca.crt, ./certs/fleet-ca.key   — signs both the gateway's
#     own server cert below AND every agent client cert minted at
#     enrollment (marlinspike/fleet/gateway/db.py:_sign_csr). The gateway
#     verifies incoming client certs against fleet-ca.crt
#     (build_ssl_context's ca_cert_path) — this file is what makes mTLS
#     agent auth work at all, so it never leaves the gateway container.
#   ./certs/gateway.crt, ./certs/gateway.key    — the gateway's own server
#     cert, now CA-signed instead of self-signed (agents already verify
#     this via --ca-cert, so nothing changes on that side of the contract).
#
# This is exactly what docker-compose.yml's fleet-gateway service mounts
# at /certs.

set -euo pipefail

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
mkdir -p "$OUT_DIR"

if [[ ! -f "$OUT_DIR/fleet-ca.crt" || ! -f "$OUT_DIR/fleet-ca.key" ]]; then
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$OUT_DIR/fleet-ca.key" \
    -out "$OUT_DIR/fleet-ca.crt" \
    -days 3650 \
    -subj "/CN=marlinspike-fleet-ca"
  echo "Generated new fleet CA: $OUT_DIR/fleet-ca.crt"
else
  echo "Reusing existing fleet CA: $OUT_DIR/fleet-ca.crt"
fi

SAN="DNS:localhost,IP:127.0.0.1"
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="${SAN},IP:${extra}"
  else
    SAN="${SAN},DNS:${extra}"
  fi
done

GW_CSR="$(mktemp)"
trap 'rm -f "$GW_CSR"' EXIT

openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/gateway.key" \
  -out "$GW_CSR" \
  -subj "/CN=marlinspike-fleet-gateway"

openssl x509 -req \
  -in "$GW_CSR" \
  -CA "$OUT_DIR/fleet-ca.crt" -CAkey "$OUT_DIR/fleet-ca.key" -CAcreateserial \
  -out "$OUT_DIR/gateway.crt" \
  -days 365 \
  -copy_extensions none \
  -extfile <(echo "subjectAltName=${SAN}")

# 644 rather than the usual 600: these files are bind-mounted read-only
# into the fleet-gateway container, which reads them as uid 1000 (not
# root, since it's the same non-root image as the main app) — a stricter
# mode would hit the exact same host-root-vs-container-uid mismatch
# already fixed for capd's socket and capture files. Fine for a throwaway
# dev CA/cert; a real deployment's CA key especially should be chowned to
# the runtime uid and never made world-readable this way.
chmod 644 "$OUT_DIR"/fleet-ca.key "$OUT_DIR"/fleet-ca.crt
chmod 644 "$OUT_DIR"/gateway.key "$OUT_DIR"/gateway.crt

echo "Wrote $OUT_DIR/gateway.crt and $OUT_DIR/gateway.key (SAN: ${SAN}), signed by fleet-ca"
echo "Point agents at this with: marlinspike-agent enroll --ca-cert $OUT_DIR/fleet-ca.crt ..."
