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
    ssl_context = build_ssl_context(args.tls_cert, args.tls_key, ca_cert_path=args.ca_cert)
    server = GatewayServer(
        heartbeat_timeout_s=args.heartbeat_timeout_s,
        instance_id=args.instance_id,
        admin_host=args.admin_tcp_advertise_host or args.admin_tcp_host,
        admin_port=args.admin_tcp_port,
    )

    allowed_uids = {int(u) for u in args.admin_allow_uid} if args.admin_allow_uid else set()
    allowed_uids.add(os.geteuid())

    tasks = [
        server.serve(args.host, args.port, ssl_context),
        server.serve_admin(args.admin_socket, allowed_uids),
    ]
    # Phase 6.5: only start the cross-host admin listener when a token is
    # actually configured — an unconfigured/default single-instance
    # deployment never exposes a network-reachable admin surface at all.
    if args.admin_tcp_port and args.admin_token:
        tasks.append(server.serve_admin_tcp(args.admin_tcp_host, args.admin_tcp_port, args.admin_token))
    elif args.admin_tcp_port or args.admin_token:
        raise SystemExit("--admin-tcp-port and --admin-token must be set together")

    await asyncio.gather(*tasks)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    parser = argparse.ArgumentParser(prog="marlinspike-fleet-gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="Run the fleet gateway.")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--tls-cert", required=True)
    p_serve.add_argument("--tls-key", required=True)
    p_serve.add_argument("--ca-cert", default=None,
                          help="Fleet CA cert (Phase 6 mTLS) — verifies agent client certs "
                               "presented during the TLS handshake. Omit to accept connections "
                               "with no client cert at all (bearer-credential-only auth).")
    p_serve.add_argument("--heartbeat-timeout-s", type=float, default=DEFAULT_HEARTBEAT_TIMEOUT_S)
    p_serve.add_argument("--admin-socket", default=DEFAULT_ADMIN_SOCKET,
                          help="Local unix socket the Flask app uses to push capture commands")
    p_serve.add_argument("--admin-allow-uid", action="append",
                          help="uid allowed on the admin socket (repeatable); "
                               "defaults to this process's own uid")

    # Phase 6.5: horizontal scaling. All optional — a single-instance
    # deployment (the docker-compose default) sets none of these and gets
    # exactly the pre-6.5 behavior: local unix socket only, no registry
    # writes (GatewayServer only publishes when admin_host/admin_port are
    # both set — see server.py's _handle_connection).
    p_serve.add_argument("--instance-id", default=os.environ.get("FLEET_GATEWAY_INSTANCE_ID", ""),
                          help="Identifies this gateway process in the shared Redis registry "
                               "(env: FLEET_GATEWAY_INSTANCE_ID). Auto-generated if unset.")
    p_serve.add_argument("--admin-tcp-host", default=os.environ.get("FLEET_GATEWAY_ADMIN_HOST", ""),
                          help="Bind host for the cross-host admin TCP listener.")
    p_serve.add_argument("--admin-tcp-advertise-host", default="",
                          help="Host other components should use to reach this instance's admin "
                               "TCP listener, if different from --admin-tcp-host (e.g. binding "
                               "0.0.0.0 but advertising a container/service DNS name). Defaults "
                               "to --admin-tcp-host.")
    p_serve.add_argument("--admin-tcp-port", type=int,
                          default=int(os.environ.get("FLEET_GATEWAY_ADMIN_PORT", "0") or 0),
                          help="Port for the cross-host admin TCP listener. Requires --admin-token.")
    p_serve.add_argument("--admin-token", default=os.environ.get("FLEET_GATEWAY_ADMIN_TOKEN", ""),
                          help="Shared secret required on every admin TCP request (no SO_PEERCRED "
                               "equivalent over TCP). Requires --admin-tcp-port.")

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
