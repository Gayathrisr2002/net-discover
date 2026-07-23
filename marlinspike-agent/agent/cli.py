"""marlinspike-agent CLI.

Usage:
    marlinspike-agent enroll --gateway HOST:PORT --token TOKEN \\
        [--name NAME] [--ca-cert PATH | --insecure-skip-verify] \\
        [--credential-file PATH]

    marlinspike-agent run [--credential-file PATH] \\
        [--heartbeat-interval-s N]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import platform
import sys

from . import __version__
from .client import (
    DEFAULT_HEARTBEAT_INTERVAL_S,
    DEFAULT_STATS_INTERVAL_S,
    AgentClient,
    AgentError,
    build_ssl_context,
    enroll as _enroll,
)
from .credential_store import DEFAULT_CREDENTIAL_PATH, AgentCredentials

DEFAULT_CAPD_SOCKET = "/var/run/marlinspike-capd/marlinspike-capd.sock"

log = logging.getLogger("marlinspike-agent")


def _split_host_port(hostport: str) -> tuple[str, int]:
    if ":" not in hostport:
        raise SystemExit(f"--gateway must be HOST:PORT, got {hostport!r}")
    host, _, port = hostport.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        raise SystemExit(f"--gateway must be HOST:PORT, got {hostport!r}")


def _cmd_enroll(args: argparse.Namespace) -> int:
    host, port = _split_host_port(args.gateway)
    ssl_context = build_ssl_context(ca_cert=args.ca_cert, insecure_skip_verify=args.insecure_skip_verify)
    os_info = f"{platform.system()} {platform.release()}"

    try:
        result = asyncio.run(_enroll(
            gateway_host=host, gateway_port=port, ssl_context=ssl_context,
            token=args.token, name=args.name, agent_version=__version__, os_info=os_info,
        ))
    except AgentError as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        return 1

    creds = AgentCredentials(
        gateway_host=host, gateway_port=port,
        ca_cert=args.ca_cert, insecure_skip_verify=args.insecure_skip_verify,
        agent_uuid=result["agent_uuid"], credential=result["credential"],
    )
    creds.save(args.credential_file)
    print(f"Enrolled as agent {result['agent_uuid']}")
    print(f"Credentials written to {args.credential_file} (mode 0600)")
    print("Start the agent with: marlinspike-agent run")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        creds = AgentCredentials.load(args.credential_file)
    except FileNotFoundError:
        print(
            f"No credentials at {args.credential_file} — run "
            f"'marlinspike-agent enroll' first.",
            file=sys.stderr,
        )
        return 1

    ssl_context = build_ssl_context(ca_cert=creds.ca_cert, insecure_skip_verify=creds.insecure_skip_verify)
    client = AgentClient(
        gateway_host=creds.gateway_host, gateway_port=creds.gateway_port, ssl_context=ssl_context,
        agent_uuid=creds.agent_uuid, credential=creds.credential,
        capd_socket_path=args.capd_socket,
        heartbeat_interval_s=args.heartbeat_interval_s,
        stats_interval_s=args.stats_interval_s,
    )
    log.info("starting agent %s -> %s:%d", creds.agent_uuid, creds.gateway_host, creds.gateway_port)
    try:
        asyncio.run(client.run_forever())
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    parser = argparse.ArgumentParser(prog="marlinspike-agent")
    parser.add_argument("--version", action="version", version=f"marlinspike-agent {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enroll = sub.add_parser("enroll", help="Redeem a one-time enrollment token.")
    p_enroll.add_argument("--gateway", required=True, help="Fleet gateway HOST:PORT")
    p_enroll.add_argument("--token", required=True, help="One-time enrollment token")
    p_enroll.add_argument("--name", default=None, help="Display name for this agent")
    p_enroll.add_argument("--ca-cert", default=None, help="Path to the gateway's CA/server cert")
    p_enroll.add_argument("--insecure-skip-verify", action="store_true",
                           help="Skip TLS certificate verification (testing only)")
    p_enroll.add_argument("--credential-file", default=DEFAULT_CREDENTIAL_PATH)
    p_enroll.set_defaults(func=_cmd_enroll)

    p_run = sub.add_parser("run", help="Connect and heartbeat using saved credentials.")
    p_run.add_argument("--credential-file", default=DEFAULT_CREDENTIAL_PATH)
    p_run.add_argument("--heartbeat-interval-s", type=float, default=DEFAULT_HEARTBEAT_INTERVAL_S)
    p_run.add_argument("--stats-interval-s", type=float, default=DEFAULT_STATS_INTERVAL_S,
                        help="How often to relay progress for an active capture session")
    p_run.add_argument("--capd-socket", default=DEFAULT_CAPD_SOCKET,
                        help="Path to the local marlinspike-capd unix socket "
                             "(capture commands from the gateway are relayed here)")
    p_run.set_defaults(func=_cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
