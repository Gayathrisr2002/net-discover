"""marlinspike-agent — remote sensor agent.

Deployed at a remote site, this process holds a persistent, authenticated
TLS connection to the central fleet gateway (marlinspike/fleet/gateway/),
relays live-capture control to a local capd sidecar, and forwards each
rotated capture's raw pcap bytes upward over that same connection. No
analysis happens on this host — the fleet-gateway runs the actual engine
and produces the report.

This package has zero third-party dependencies (stdlib ssl/socket/asyncio
only) and is installable standalone on a bare remote box — this mirrors
marlinspike-capd's own minimal-dependency posture.
"""

__version__ = "0.4.0"
