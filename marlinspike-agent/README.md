# marlinspike-agent

Remote sensor agent for MarlinSpike fleet management. Deployed at a site,
it holds a persistent, authenticated TLS connection to the central fleet
gateway (`marlinspike/fleet/gateway/`) so the site can be managed from one
console instead of running a separate MarlinSpike instance per location.

**Phase 2 scope** (this package, as it stands today): enroll once with a
one-time token, then heartbeat forever, reconnecting automatically if the
link drops. No capture control or report shipping yet — those are Phase 3
(relay start/stop to the local `capd` sidecar) and Phase 4 (run the
analysis engine locally, ship only the resulting JSON report), added as
new methods on this same connection, not a new protocol.

## Why a separate process from capd

`marlinspike-capd` already does the actual privileged capture work
(`CAP_NET_RAW`/`CAP_NET_ADMIN`, supervises `dumpcap`) and is reached over a
local unix socket. This agent holds no such capabilities — it only speaks
TLS to the gateway and, from Phase 3, relays capture commands to the local
capd over its existing unix-socket protocol, exactly the way the central
web app does today. The privilege boundary that already exists between the
web app and capd is preserved end-to-end, just with a remote hop added in
front of it.

## Install

```bash
pip install -e ./marlinspike-agent
```

Zero third-party dependencies — stdlib `ssl`/`asyncio` only.

## Usage

```bash
# One-time enrollment: redeem a token issued from the central console
# (Fleet page -> site -> "Issue Enrollment Token").
marlinspike-agent enroll \
    --gateway fleet.example.com:8765 \
    --token <token-from-console> \
    --name "plant-3-east-substation" \
    --ca-cert /etc/marlinspike-agent/gateway-ca.crt

# Writes /etc/marlinspike-agent/credential.json (mode 0600) and prints
# the assigned agent_uuid. This file is this agent's identity — treat it
# like a private key.

# Run (foreground, or via the bundled systemd unit):
marlinspike-agent run
```

For local/dev testing against a self-signed gateway cert without a real
CA, pass `--insecure-skip-verify` instead of `--ca-cert` — logs a loud
warning and must never be used for a real deployment.

## systemd

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin marlinspike-agent
sudo mkdir -p /etc/marlinspike-agent
sudo marlinspike-agent enroll --gateway ... --token ... --credential-file /etc/marlinspike-agent/credential.json
sudo chown -R marlinspike-agent:marlinspike-agent /etc/marlinspike-agent
sudo cp systemd/marlinspike-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now marlinspike-agent
```

## Protocol

Length-prefixed JSON over TLS (4-byte big-endian length, then UTF-8 JSON
body) — the same framing idea as `capd`'s uds protocol, evolved into a
bidirectional envelope since both sides need to initiate here (the agent
pushes heartbeat/report frames; the gateway pushes capture commands from
Phase 3 on):

```
{"type": "req", "id": <int>, "method": <str>, "params": {...}}
{"type": "res", "id": <int>, "ok": bool, "result": {...} | "error": <str>}
```

See `marlinspike/fleet/gateway/server.py` for the canonical schema and
`agent/client.py` for this side of it.

## License

AGPL-3.0-or-later. See repo root `LICENSE`.
