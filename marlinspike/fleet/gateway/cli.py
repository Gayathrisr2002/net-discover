"""CLI entry point for the fleet gateway.

Usage:
    python -m marlinspike.fleet.gateway serve --tls-cert=... --tls-key=...
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from .server import DEFAULT_HEARTBEAT_TIMEOUT_S, GatewayServer, build_ssl_context

DEFAULT_ADMIN_SOCKET = "/var/run/marlinspike-fleet-gateway/admin.sock"


async def _run(args: argparse.Namespace) -> None:
    ssl_context = build_ssl_context(args.tls_cert, args.tls_key)
    server = GatewayServer(heartbeat_timeout_s=args.heartbeat_timeout_s)

    allowed_uids = {int(u) for u in args.admin_allow_uid} if args.admin_allow_uid else set()
    allowed_uids.add(os.geteuid())

    await asyncio.gather(
        server.serve(args.host, args.port, ssl_context),
        server.serve_admin(args.admin_socket, allowed_uids),
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    parser = argparse.ArgumentParser(prog="marlinspike-fleet-gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="Run the fleet gateway.")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--tls-cert", required=True)
    p_serve.add_argument("--tls-key", required=True)
    p_serve.add_argument("--heartbeat-timeout-s", type=float, default=DEFAULT_HEARTBEAT_TIMEOUT_S)
    p_serve.add_argument("--admin-socket", default=DEFAULT_ADMIN_SOCKET,
                          help="Local unix socket the Flask app uses to push capture commands")
    p_serve.add_argument("--admin-allow-uid", action="append",
                          help="uid allowed on the admin socket (repeatable); "
                               "defaults to this process's own uid")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        try:
            asyncio.run(_run(args))
        except KeyboardInterrupt:
            pass
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
