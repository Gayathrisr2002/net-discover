"""Client for the fleet gateway's admin interface (local unix socket, or a
specific remote instance's admin TCP listener — Phase 6.5).

Lets the Flask app push a capture command (start/stop/list_interfaces) to
a specific connected remote agent and get back the result, synchronously,
from an ordinary Flask request handler. Mirrors marlinspike/capture/
client.py's CapdClient shape (same method names/signatures, same
CapdError/CapdUnavailable exceptions) so capture/api.py can pick whichever
client to use with minimal branching — see capture/api.py's `_client_for`.

Wire format: length-prefixed JSON, one call:

    {"method": "push_command", "id": 1, "params": {
        "agent_uuid": ..., "command_method": "start"/"stop"/"list_interfaces",
        "command_params": {...}, "timeout_s": ...
    }}

matching marlinspike/fleet/gateway/server.py's admin dispatch (shared by
both its unix-socket and TCP listeners).

Routing (Phase 6.5): a fleet with more than one gateway instance needs to
reach whichever *specific* instance currently holds the target agent's
live connection, not just "the" gateway — see
marlinspike/fleet/gateway/db.py's Redis-backed registry. Every call here
looks up that registry first; a hit routes over TCP (with the shared
admin_token) to that instance, a miss (registry empty/not configured, or
the agent isn't tracked in it) falls back to the local unix socket
unchanged — which is exactly today's single-instance behavior, since a
single-instance deployment never populates the registry in the first
place (GatewayServer only registers when admin_host/admin_port are
configured — see server.py's _handle_connection).
"""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import struct

from marlinspike import config
from marlinspike.capture.client import CapdError, CapdUnavailable, Interface

log = logging.getLogger(__name__)

_LEN_PREFIX = 4
_MAX_MESSAGE_BYTES = 1 << 20


class GatewayAdminClient:
    def __init__(self, socket_path: str, agent_uuid: str, timeout: float = 15.0):
        self.socket_path = socket_path
        self.agent_uuid = agent_uuid
        self.timeout = timeout

    def list_interfaces(self, include_virtual: bool = False) -> list[Interface]:
        resp = self._push("list_interfaces", {"include_virtual": include_virtual})
        return [Interface.from_dict(d) for d in resp.get("interfaces", [])]

    def start(self, *, session_id: str, interface: str, bpf_filter: str = "",
              ring_filesize_kb: int = 200_000, ring_files: int = 10,
              max_duration_s: int = 0) -> dict:
        return self._push("start", {
            "session_id": session_id,
            "interface": interface,
            "bpf": bpf_filter,
            "ring_filesize_kb": ring_filesize_kb,
            "ring_files": ring_files,
            "max_duration_s": max_duration_s,
        })

    def stop(self, session_id: str) -> dict:
        # Stop can take a few seconds on the agent side (dumpcap SIGINT + flush).
        return self._push("stop", {"session_id": session_id}, timeout_s=20.0)

    def disconnect_agent(self) -> bool:
        """Force-drop this agent's live gateway connection right now, rather
        than waiting for its next heartbeat-interval revocation check
        (Phase 6.2). Unlike start/stop/list_interfaces this isn't relayed
        to the agent at all — it's a direct gateway-local admin method, not
        wrapped in the push_command envelope. Best-effort by design: the
        caller (revoke_agent / rotate_credential) has already committed the
        DB-side revocation regardless of whether this succeeds."""
        sock, extra_params = self._connect(self.timeout + 5.0)
        try:
            _send_json(sock, {"method": "disconnect_agent", "id": 1,
                               "params": {"agent_uuid": self.agent_uuid, **extra_params}})
            resp = _recv_json(sock)
            if resp is None or not resp.get("ok"):
                return False
            return bool((resp.get("result") or {}).get("disconnected"))
        except (TimeoutError, OSError):
            # A connected-but-hung peer (partial admin-connection race,
            # gateway overload) raises here same as an unreachable one —
            # this call is already documented best-effort, so treat it the
            # same way rather than letting a raw socket error escape.
            return False
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def _push(self, command_method: str, command_params: dict, timeout_s: float | None = None) -> dict:
        effective_timeout = timeout_s or self.timeout
        sock, extra_params = self._connect(effective_timeout + 5.0)
        try:
            _send_json(sock, {"method": "push_command", "id": 1, "params": {
                "agent_uuid": self.agent_uuid,
                "command_method": command_method,
                "command_params": command_params,
                "timeout_s": effective_timeout,
                **extra_params,
            }})
            resp = _recv_json(sock)
            if resp is None:
                raise CapdError("fleet gateway closed connection")
            if not resp.get("ok"):
                raise CapdError(resp.get("error") or f"{command_method} failed")
            return resp.get("result") or {}
        except (TimeoutError, OSError) as exc:
            # A connect that succeeded but then hung (unlike an outright
            # connection failure, already wrapped into CapdUnavailable by
            # _connect_tcp/_connect_unix) previously escaped as a raw
            # socket.timeout/OSError — callers in capture/api.py only catch
            # CapdUnavailable/CapdError, so this used to surface as an
            # unhandled 500 and leave the CaptureSession row stuck in
            # "pending"/"stopping" forever instead of being marked failed.
            raise CapdUnavailable(f"gateway connection hung during {command_method}: {exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def _connect(self, timeout: float) -> tuple[socket.socket, dict]:
        """Returns (connected socket, extra params to merge into the
        request — {"admin_token": ...} for a routed TCP connection, {}
        for the local unix socket)."""
        instance = self._lookup_instance()
        if instance is not None:
            return self._connect_tcp(instance, timeout), {"admin_token": config.FLEET_GATEWAY_ADMIN_TOKEN}
        return self._connect_unix(timeout), {}

    def _lookup_instance(self) -> dict | None:
        try:
            from marlinspike.fleet.gateway.db import lookup_agent_instance
            return lookup_agent_instance(self.agent_uuid)
        except Exception:
            log.exception("instance registry lookup failed for agent %s — using local admin socket",
                          self.agent_uuid)
            return None

    def _connect_tcp(self, instance: dict, timeout: float) -> socket.socket:
        host, port = instance.get("admin_host"), instance.get("admin_port")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, int(port)))
        except (ConnectionRefusedError, OSError, TypeError, ValueError) as exc:
            sock.close()
            raise CapdUnavailable(f"gateway instance {instance.get('instance_id')} "
                                  f"unreachable at {host}:{port}: {exc}") from exc
        return sock

    def _connect_unix(self, timeout: float) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(self.socket_path)
        except (FileNotFoundError, ConnectionRefusedError, PermissionError, OSError) as exc:
            sock.close()
            raise CapdUnavailable(f"fleet gateway unreachable at {self.socket_path}: {exc}") from exc
        return sock


# ── wire helpers ──────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _recv_json(sock: socket.socket) -> dict | None:
    header = _recv_exact(sock, _LEN_PREFIX)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > _MAX_MESSAGE_BYTES:
        raise CapdError(f"gateway sent oversized frame: {length} bytes")
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def _send_json(sock: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body)
