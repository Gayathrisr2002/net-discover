# marlinspike-agent

Remote sensor agent for MarlinSpike fleet management. Deployed at a site,
it holds a persistent, authenticated TLS connection to the central fleet
gateway (`marlinspike/fleet/gateway/`) so the site can be managed from one
console instead of running a separate MarlinSpike instance per location.

**Phase 2 scope** (this package, as it stands today): enroll once with your
site's standing enrollment token (reusable for enrolling any number of
agents, from the Fleet page), then heartbeat forever, reconnecting
automatically if the link drops. No capture control or report shipping yet — those are Phase 3
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
    --ca-cert /etc/marlinspike-agent/fleet-ca.crt

# Writes /etc/marlinspike-agent/credential.json (mode 0600) and prints
# the assigned agent_uuid. This file is this agent's identity — treat it
# like a private key. If the gateway has a fleet CA configured (Phase 6),
# enrollment also generates a local keypair (never transmitted) and gets
# back a signed mTLS client cert, both stored in the same credential file;
# every reconnect then presents that cert automatically. Pass --no-mtls to
# skip this and stay on bearer-credential-only auth.

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

### Allowing this agent's uid on the local capd

capd only ever trusts its own effective uid (root) unless told otherwise
— it has no idea the `marlinspike-agent` system user above even exists.
Without this, every remote-capture-control request (list interfaces,
start/stop) fails with a capd `"unauthorized"` error, since this agent
relays those commands to capd over the *local* unix socket, not the
central gateway.

If both packages were installed via their `.deb`s (either order), this
is already wired up automatically — each package's `postinst` adds this
agent's uid to the other's allow-list/group. **The only manual step
left**: if `marlinspike-agent` was already running when `capd` got
installed afterward, restart it once so it picks up its new group
membership (`sudo systemctl restart marlinspike-agent`) — a
`postinst`-time group change never applies to an already-running
process.

For a source install with no `.deb` involved at all, append the uid
yourself — capd re-reads this file on every connection attempt, no
systemd edit or restart needed:

```bash
id -u marlinspike-agent   # note this uid
echo <uid-from-above> | sudo tee -a /etc/marlinspike-capd/allowed-uids
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
