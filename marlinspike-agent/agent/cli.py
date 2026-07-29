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
import json
import logging
import platform
import re
import sys

from . import __version__
from .certs import CertError, generate_key_and_csr
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
    # Users instinctively type a URL here (http://host:port) — that's the
    # muscle-memory format for nearly every other network address they
    # ever type, even though this flag wants a bare HOST:PORT pair (it's
    # a raw TLS socket, not an HTTP endpoint). Silently strip a scheme
    # prefix rather than let it flow into rpartition(":") below, which
    # otherwise "successfully" splits "http://localhost:8765" into
    # host="http://localhost", port=8765 — a value that passes int(port)
    # but sends asyncio.open_connection() a hostname getaddrinfo can
    # never resolve, surfacing as a confusing socket.gaierror deep in a
    # traceback instead of a clear, immediate error here.
    original = hostport
    hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", hostport)
    if ":" not in hostport:
        raise SystemExit(f"--gateway must be HOST:PORT, got {original!r}")
    host, _, port = hostport.rpartition(":")
    try:
        port_int = int(port)
    except ValueError:
        raise SystemExit(f"--gateway must be HOST:PORT, got {original!r}")
    if not host:
        raise SystemExit(f"--gateway must be HOST:PORT, got {original!r}")
    return host, port_int


def _cmd_enroll(args: argparse.Namespace) -> int:
    host, port = _split_host_port(args.gateway)
    # Read the CA cert's content now, at enroll time, and carry it as PEM
    # from here on — not a path. A path gets persisted into
    # credential.json and read back later by `run`, which under systemd
    # (marlinspike-agent.service) starts from a different, sandboxed
    # working directory than wherever the operator happened to type
    # `enroll` from (typically ~/Downloads): ProtectHome=true hides /home
    # entirely and ReadOnlyPaths only allow-lists /etc/marlinspike-agent,
    # so no path outside that one directory would ever be readable by
    # `run` regardless of being relative or absolute.
    ca_cert_pem = None
    if args.ca_cert:
        try:
            with open(args.ca_cert, "r", encoding="utf-8") as f:
                ca_cert_pem = f.read()
        except OSError as exc:
            raise SystemExit(f"--ca-cert {args.ca_cert!r}: {exc}")
    ssl_context = build_ssl_context(ca_cert_pem=ca_cert_pem, insecure_skip_verify=args.insecure_skip_verify)
    os_info = f"{platform.system()} {platform.release()}"

    # Always generate a local keypair + CSR and offer it — cheap (one
    # openssl invocation), and the gateway simply won't sign it (omitting
    # client_cert_pem from the result) if no fleet CA is configured there,
    # so this is a no-op against an older/unconfigured gateway.
    client_key_pem = None
    csr_pem = None
    if not args.no_mtls:
        try:
            client_key_pem, csr_pem = generate_key_and_csr(cn="pending-enrollment")
        except CertError as exc:
            print(f"Warning: couldn't generate mTLS keypair ({exc}) — "
                  f"falling back to bearer-credential-only enrollment.", file=sys.stderr)

    try:
        result = asyncio.run(_enroll(
            gateway_host=host, gateway_port=port, ssl_context=ssl_context,
            token=args.token, name=args.name, agent_version=__version__, os_info=os_info,
            csr_pem=csr_pem,
        ))
    except AgentError as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        return 1

    client_cert_pem = result.get("client_cert_pem")
    creds = AgentCredentials(
        gateway_host=host, gateway_port=port,
        ca_cert_pem=ca_cert_pem, insecure_skip_verify=args.insecure_skip_verify,
        agent_uuid=result["agent_uuid"], credential=result["credential"],
        client_cert_pem=client_cert_pem,
        client_key_pem=client_key_pem if client_cert_pem else None,
    )
    try:
        creds.save(args.credential_file)
    except OSError as exc:
        # By this point the enroll RPC has ALREADY succeeded server-side —
        # a real credential has been minted for this agent. A save failure
        # here (e.g. /etc/marlinspike-agent not
        # created yet — see README's systemd setup) used to just lose that
        # credential silently, leaving a "phantom" enrolled-but-unusable
        # agent recoverable only via an admin rotate-credential action.
        # Print it so the operator can save it by hand instead.
        print(f"WARNING: enrollment succeeded but failed to write {args.credential_file}: {exc}",
              file=sys.stderr)
        print("Save this now — it will not be shown again:", file=sys.stderr)
        print(json.dumps({
            "gateway_host": creds.gateway_host, "gateway_port": creds.gateway_port,
            "ca_cert_pem": creds.ca_cert_pem, "insecure_skip_verify": creds.insecure_skip_verify,
            "agent_uuid": creds.agent_uuid, "credential": creds.credential,
            "client_cert_pem": creds.client_cert_pem, "client_key_pem": creds.client_key_pem,
        }, indent=2))
        return 1
    print(f"Enrolled as agent {result['agent_uuid']}")
    print(f"Credentials written to {args.credential_file} (mode 0600)")
    if client_cert_pem:
        print("mTLS client cert issued — future reconnects will present it automatically.")
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

    ssl_context = build_ssl_context(
        ca_cert_pem=creds.ca_cert_pem, insecure_skip_verify=creds.insecure_skip_verify,
        client_cert_pem=creds.client_cert_pem, client_key_pem=creds.client_key_pem,
    )
    client = AgentClient(
        gateway_host=creds.gateway_host, gateway_port=creds.gateway_port, ssl_context=ssl_context,
        agent_uuid=creds.agent_uuid, credential=creds.credential,
        capd_socket_path=args.capd_socket,
        heartbeat_interval_s=args.heartbeat_interval_s,
        stats_interval_s=args.stats_interval_s,
        staging_dir=args.staging_dir,
        spool_dir=args.spool_dir,
        scan_profile=args.scan_profile,
        dpi_engine=args.dpi_engine,
        dpi_binary=args.dpi_binary,
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
    p_enroll.add_argument("--no-mtls", action="store_true",
                           help="Skip local key/CSR generation — enroll with the bearer "
                                "credential only, even if the gateway has a fleet CA configured")
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
    p_run.add_argument("--staging-dir", default=None,
                        help="Local scratch dir for engine output before it ships "
                             "upward (default: a marlinspike-agent-reports dir under tmp)")
    p_run.add_argument("--spool-dir", default=None,
                        help="Durable local queue for reports that couldn't ship "
                             "immediately (default: a marlinspike-agent-spool dir under tmp)")
    p_run.add_argument("--scan-profile", default="fast", choices=["fast", "full"],
                        help="Passed through to the engine chain (--fast when 'fast')")
    p_run.add_argument("--dpi-engine", default=None,
                        help="Passed through to the engine chain's --dpi-engine")
    p_run.add_argument("--dpi-binary", default=None,
                        help="Passed through to the engine chain's --dpi-binary "
                             "(requires the real marlinspike package + engine "
                             "dependencies installed on this host — see README.md)")
    p_run.set_defaults(func=_cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
