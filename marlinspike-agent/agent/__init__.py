"""marlinspike-agent — remote sensor agent.

Deployed at a remote site, this process holds a persistent, authenticated
TLS connection to the central fleet gateway (marlinspike/fleet/gateway/),
relays live-capture control to a local capd sidecar, runs the analysis
engine locally on each rotated capture, and ships the resulting report
upward.

This package's own transport layer (client.py/certs.py/credential_store.py)
has zero third-party dependencies (stdlib ssl/socket/asyncio only) — this
mirrors marlinspike-capd's own minimal-dependency posture. Running actual
scans (agent/consumer.py) needs the marlinspike analysis engine + tshark
present too; the .deb (scripts/build_agent_deb.sh) bundles the former and
depends on the latter via apt, so nothing beyond `apt install` is needed.
"""

__version__ = "0.3.5"
