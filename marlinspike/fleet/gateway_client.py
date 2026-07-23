"""Client for the fleet gateway's local admin socket.

Lets the Flask app push a capture command (start/stop/list_interfaces) to
a specific connected remote agent and get back the result, synchronously,
from an ordinary Flask request handler. Mirrors marlinspike/capture/
client.py's CapdClient shape (same method names/signatures, same
CapdError/CapdUnavailable exceptions) so capture/api.py can pick whichever
client to use with minimal branching — see capture/api.py's `_client_for`.

Wire format: length-prefixed JSON over a unix socket, one call:

    {"method": "push_command", "id": 1, "params": {
        "agent_uuid": ..., "command_method": "start"/"stop"/"list_interfaces",
        "command_params": {...}, "timeout_s": ...
    }}

matching marlinspike/fleet/gateway/server.py's admin-socket handler.
"""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import struct

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

    def _push(self, command_method: str, command_params: dict, timeout_s: float | None = None) -> dict:
        effective_timeout = timeout_s or self.timeout
        sock = self._connect(effective_timeout + 5.0)
        try:
            _send_json(sock, {"method": "push_command", "id": 1, "params": {
                "agent_uuid": self.agent_uuid,
                "command_method": command_method,
                "command_params": command_params,
                "timeout_s": effective_timeout,
            }})
            resp = _recv_json(sock)
            if resp is None:
                raise CapdError("fleet gateway closed connection")
            if not resp.get("ok"):
                raise CapdError(resp.get("error") or f"{command_method} failed")
            return resp.get("result") or {}
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def _connect(self, timeout: float) -> socket.socket:
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
