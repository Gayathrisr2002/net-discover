#!/usr/bin/env bash
# Ensures ./certs/gateway.crt covers this deployment's actual reachable
# address, regenerating just the leaf cert (never the CA — that would
# invalidate every already-enrolled agent's client cert, see
# gen_dev_tls_cert.sh) whenever it doesn't. Runs on every `docker compose
# up` via certs-init (see docker-compose.yml): a genuinely fresh clone
# gets a first-time CA + leaf generation, and an existing deployment
# whose host address changed (moved to a different network, DHCP lease
# renewed, etc.) gets its leaf cert refreshed automatically the next time
# the stack starts — no manual "set FLEET_GATEWAY_PUBLIC_HOST, delete
# ./certs, restart" dance required, which is exactly the operational trap
# that repeatedly bit real live testing before this script existed (see
# docs/fleet-agent-poc.md §6, "a stale gateway TLS cert misses a later
# FLEET_GATEWAY_PUBLIC_HOST").
#
# Auto-detection needs the HOST's real network interfaces/routes, which a
# container on its own Docker bridge network cannot see at all — it would
# only ever discover its own internal bridge IP. The caller
# (docker-compose.yml) must run this container with `network_mode: host`
# for the detection below to reflect anything real. Linux-only, same as
# every other assumption this project already makes about its deployment
# target (SO_PEERCRED elsewhere in this codebase has the identical
# constraint).
#
# Usage: scripts/refresh_gateway_cert.sh [explicit-host-override]
#   With no argument: auto-detects the host's outbound-facing IP (the
#   source address the kernel would pick to reach the public internet —
#   the standard trick for "what's my real LAN IP", which correctly
#   ignores Docker's own internal bridge/veth addresses even though this
#   container can see every interface on the host, since none of those
#   are ever the kernel's chosen route to the outside world).
#   With an argument (FLEET_GATEWAY_PUBLIC_HOST, if set in .env): that
#   value is used verbatim instead of auto-detection — lets an operator
#   pin a DNS hostname, or override a multi-homed/NATed host where
#   auto-detection would guess wrong.

set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
GEN_SCRIPT="$(dirname "${BASH_SOURCE[0]}")/gen_dev_tls_cert.sh"

EXPLICIT_HOST="${1:-}"

detect_host() {
  # A UDP "connect" never actually sends a packet — connect() on
  # SOCK_DGRAM just asks the kernel to resolve which local address/route
  # it would use, which is exactly the fact we want and works even
  # without real internet access, as long as some default route exists.
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
except OSError:
    pass
finally:
    s.close()
PY
}

if [[ -n "$EXPLICIT_HOST" ]]; then
  TARGET_HOST="$EXPLICIT_HOST"
  echo "using explicitly configured FLEET_GATEWAY_PUBLIC_HOST=$TARGET_HOST"
else
  TARGET_HOST="$(detect_host || true)"
  if [[ -n "$TARGET_HOST" ]]; then
    echo "auto-detected host address: $TARGET_HOST"
  else
    echo "could not auto-detect a host address (no default route?) — cert will only cover localhost/127.0.0.1/marlinspike-fleet-gateway"
  fi
fi

NEEDS_REGEN=1
if [[ -f "$CERTS_DIR/fleet-ca.crt" && -f "$CERTS_DIR/gateway.crt" && -f "$CERTS_DIR/gateway.key" ]]; then
  if [[ -z "$TARGET_HOST" ]]; then
    NEEDS_REGEN=0  # nothing to add, and a cert already exists — leave it alone
  elif openssl x509 -in "$CERTS_DIR/gateway.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "$TARGET_HOST"; then
    NEEDS_REGEN=0
  fi
fi

if [[ "$NEEDS_REGEN" == "1" ]]; then
  echo "gateway cert missing or doesn't cover ${TARGET_HOST:-<none>} — (re)generating (reuses the existing CA if present)"
  bash "$GEN_SCRIPT" marlinspike-fleet-gateway ${TARGET_HOST:+"$TARGET_HOST"}
else
  echo "gateway cert already covers ${TARGET_HOST:-<none>} — nothing to do"
fi
