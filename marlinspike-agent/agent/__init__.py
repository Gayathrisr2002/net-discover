"""marlinspike-agent — remote sensor agent (Phase 2: transport + auth + heartbeat only).

Deployed at a remote site, this process holds a persistent, authenticated
TLS connection to the central fleet gateway (marlinspike/fleet/gateway/).
Phase 2 scope is deliberately narrow: enroll once, then heartbeat forever.
No capture control (Phase 3) or report shipping (Phase 4) yet — those add
methods to the same connection, not a new one.

Zero third-party dependencies (stdlib ssl/socket/asyncio only) — this
mirrors marlinspike-capd's own minimal-dependency posture, and this
package must be installable on a bare remote box with nothing else from
the MarlinSpike suite present.
"""

__version__ = "0.1.0"
