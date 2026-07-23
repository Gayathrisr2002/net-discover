"""Fleet gateway — TLS listener for remote agent connections, plus a local
admin socket the Flask app uses to push capture commands to a specific
connected agent.

Runs as a separate always-on asyncio process (not inside gunicorn/Flask
workers — see capture/sessions.py's own documented limitation that its
per-process CaptureSessionManager singleton doesn't survive multi-worker
deployments even for one local capd; a fleet of persistent remote agent
sockets makes that structural rather than a documented shortcut).

Wire format on the agent-facing TLS listener: the same length-prefixed-
JSON idea as capd/server.py (4-byte big-endian length + UTF-8 JSON body,
capped at 1 MiB), evolved into a bidirectional envelope since, unlike capd
(only the local web app calls in), both sides need to initiate here:

    {"type": "req", "id": <int>, "method": <str>, "params": {...}}
    {"type": "res", "id": <int>, "ok": bool, "result": {...} | "error": <str>}
    {"type": "event", "method": <str>, "params": {...}}   # no response expected

Agent-initiated: heartbeat (req), session_stats (event, Phase 3).
Gateway-initiated: start / stop / list_interfaces (req, Phase 3) — pushed
down a specific agent's connection on demand by the local admin socket
below, which speaks the *same* framing but is reached only via a unix
socket shared with the Flask app container (capd-style, not internet-
facing) rather than TLS.

capd's server uses raw ``loop.sock_*`` calls on a plain socket; the TLS
listener here uses asyncio's Streams API instead (``asyncio.start_server``
/ StreamReader / StreamWriter), because that's what actually supports TLS.
The admin listener uses the same Streams API for consistency, over
``asyncio.start_unix_server``.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import ssl
import struct
import sys

from . import db

log = logging.getLogger("fleet.gateway")

_LEN_PREFIX = 4
_MAX_MESSAGE_BYTES = 1 << 20  # 1 MiB — matches capd's cap; reports ship in Phase 4.

# An agent that hasn't sent anything (heartbeat included) in this long is
# presumed dead — the connection is dropped and the agent marked offline.
# Set well above the agent's own heartbeat interval so ordinary network
# jitter never trips it.
DEFAULT_HEARTBEAT_TIMEOUT_S = 90.0

# How long the admin socket waits for a pushed command's response before
# giving up on a connected-but-unresponsive agent.
DEFAULT_COMMAND_TIMEOUT_S = 15.0


class GatewayCommandError(RuntimeError):
    """Raised by push_command — safe to surface to the admin-socket caller."""


# ── wire framing (shared by both listeners) ─────────────────────

async def _recv_frame(reader: asyncio.StreamReader) -> dict | None:
    try:
        header = await reader.readexactly(_LEN_PREFIX)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > _MAX_MESSAGE_BYTES:
        raise ValueError(f"bad frame length: {length}")
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.warning("malformed json from peer: %s", exc)
        return {}


async def _send_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > _MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    writer.write(struct.pack(">I", len(body)) + body)
    await writer.drain()


def _res(req_id, *, ok: bool, result: dict | None = None, error: str | None = None) -> dict:
    msg = {"type": "res", "id": req_id, "ok": ok}
    if ok:
        msg["result"] = result or {}
    else:
        msg["error"] = error or "unknown error"
    return msg


class _AgentConnection:
    """Per-connection state for one authenticated agent — lets push_command
    (driven by the admin socket) address a specific live connection and
    await its reply, independent of that agent's own outgoing heartbeat
    requests (separate id namespace, separate pending-futures dict)."""

    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        self.pending: dict[int, asyncio.Future] = {}
        self.write_lock = asyncio.Lock()
        self._next_id = 1

    def next_id(self) -> int:
        self._next_id += 1
        return self._next_id


# ── agent-facing TLS listener ────────────────────────────────────

class GatewayServer:
    def __init__(self, heartbeat_timeout_s: float = DEFAULT_HEARTBEAT_TIMEOUT_S):
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self._connections: dict[str, _AgentConnection] = {}
        self._connections_lock = asyncio.Lock()

    async def serve(self, host: str, port: int, ssl_context: ssl.SSLContext) -> None:
        server = await asyncio.start_server(
            self._handle_connection, host, port, ssl=ssl_context
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        log.info("fleet gateway listening on %s", addrs)
        async with server:
            await server.serve_forever()

    async def serve_admin(self, socket_path: str, allowed_uids: set[int]) -> None:
        """Local-only admin socket the Flask app uses to push commands to a
        connected agent. Same auth posture as capd: SO_PEERCRED, not
        filesystem permissions (see capd/server.py's own comment on why
        0o666 + peer-credential check beats a restrictive file mode here)."""
        os.makedirs(os.path.dirname(socket_path), exist_ok=True)
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
        server = await asyncio.start_unix_server(
            functools.partial(self._handle_admin_connection, allowed_uids), path=socket_path
        )
        os.chmod(socket_path, 0o666)
        log.info("fleet gateway admin socket listening on %s (allowed uids: %s)",
                  socket_path, sorted(allowed_uids))
        async with server:
            await server.serve_forever()

    # ── agent connection lifecycle ───────────────────────────────

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        loop = asyncio.get_running_loop()
        agent_uuid: str | None = None
        conn: _AgentConnection | None = None

        try:
            msg = await _recv_frame(reader)
            if msg is None:
                return
            if msg.get("type") != "req" or msg.get("method") not in ("enroll", "auth"):
                await _send_frame(writer, _res(msg.get("id"), ok=False,
                                                error="first frame must be enroll or auth"))
                return

            agent_uuid = await self._authenticate(reader, writer, msg, loop)
            if agent_uuid is None:
                return
            log.info("agent %s authenticated from %s", agent_uuid, peer)

            conn = _AgentConnection(writer)
            async with self._connections_lock:
                self._connections[agent_uuid] = conn

            await self._serve_authenticated(reader, agent_uuid, conn, loop)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, ssl.SSLError):
            pass
        except Exception:
            log.exception("connection handler crashed (peer=%s)", peer)
        finally:
            if agent_uuid is not None:
                async with self._connections_lock:
                    if self._connections.get(agent_uuid) is conn:
                        del self._connections[agent_uuid]
                if conn is not None:
                    for fut in conn.pending.values():
                        if not fut.done():
                            fut.cancel()
                try:
                    await loop.run_in_executor(None, functools.partial(db.mark_offline, agent_uuid=agent_uuid))
                except Exception:
                    log.exception("failed to mark agent %s offline", agent_uuid)
                log.info("agent %s disconnected (%s)", agent_uuid, peer)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _authenticate(self, reader, writer, msg, loop) -> str | None:
        """Handle the connection's first frame (enroll or auth).

        Returns the authenticated agent_uuid, or None if auth failed (the
        error response has already been sent and the caller should return).
        """
        method = msg["method"]
        params = msg.get("params") or {}
        req_id = msg.get("id")

        if method == "enroll":
            try:
                result = await loop.run_in_executor(None, functools.partial(
                    db.enroll_agent,
                    raw_token=str(params.get("token", "")),
                    name=params.get("name"),
                    agent_version=params.get("agent_version"),
                    os_info=params.get("os_info"),
                ))
            except db.GatewayAuthError as exc:
                await _send_frame(writer, _res(req_id, ok=False, error=str(exc)))
                return None
            await _send_frame(writer, _res(req_id, ok=True, result=result))
            return result["agent_uuid"]

        # method == "auth"
        agent_uuid = str(params.get("agent_uuid", ""))
        credential = str(params.get("credential", ""))
        try:
            await loop.run_in_executor(None, functools.partial(
                db.authenticate_agent, agent_uuid=agent_uuid, raw_credential=credential
            ))
        except db.GatewayAuthError as exc:
            await _send_frame(writer, _res(req_id, ok=False, error=str(exc)))
            return None
        await _send_frame(writer, _res(req_id, ok=True, result={"agent_uuid": agent_uuid}))
        return agent_uuid

    async def _serve_authenticated(self, reader, agent_uuid: str, conn: _AgentConnection, loop) -> None:
        """Post-auth read loop for one agent. Demuxes every frame type the
        agent can send: 'req' (heartbeat — the only agent-initiated request),
        'event' (session_stats — fire and forget), and 'res' (a reply to a
        command *we* pushed via push_command, matched against conn.pending)."""
        while True:
            try:
                msg = await asyncio.wait_for(_recv_frame(reader), timeout=self.heartbeat_timeout_s)
            except asyncio.TimeoutError:
                log.warning("agent %s heartbeat timeout (%.0fs) — dropping connection",
                            agent_uuid, self.heartbeat_timeout_s)
                return
            if msg is None:
                return

            msg_type = msg.get("type")

            if msg_type == "res":
                fut = conn.pending.get(msg.get("id"))
                if fut is not None and not fut.done():
                    fut.set_result(msg)
                continue

            if msg_type == "event":
                asyncio.create_task(self._handle_event(agent_uuid, msg, loop))
                continue

            if msg_type != "req":
                continue

            method = msg.get("method")
            req_id = msg.get("id")

            if method == "heartbeat":
                revoked = await loop.run_in_executor(None, functools.partial(
                    db.is_agent_revoked, agent_uuid=agent_uuid
                ))
                if revoked:
                    await _send_frame(conn.writer, _res(req_id, ok=False, error="revoked"))
                    return
                await loop.run_in_executor(None, functools.partial(
                    db.record_heartbeat, agent_uuid=agent_uuid
                ))
                await _send_frame(conn.writer, _res(req_id, ok=True, result={}))
                continue

            await _send_frame(conn.writer, _res(req_id, ok=False, error=f"unknown method: {method}"))

    async def _handle_event(self, agent_uuid: str, msg: dict, loop) -> None:
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "session_stats":
            try:
                await loop.run_in_executor(None, functools.partial(
                    db.record_session_stats,
                    session_uuid=str(params.get("session_id", "")),
                    bytes_captured=int(params.get("bytes_captured") or 0),
                    rotation_count=int(params.get("rotation_count") or 0),
                ))
            except Exception:
                log.exception("failed to record session_stats event from agent %s", agent_uuid)

    # ── command push (called from the admin-socket handler) ──────

    async def push_command(self, agent_uuid: str, method: str, params: dict,
                            timeout_s: float = DEFAULT_COMMAND_TIMEOUT_S) -> dict:
        conn = self._connections.get(agent_uuid)
        if conn is None:
            raise GatewayCommandError(f"agent {agent_uuid} is not connected")

        req_id = conn.next_id()
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        conn.pending[req_id] = fut
        try:
            async with conn.write_lock:
                await _send_frame(conn.writer, {"type": "req", "id": req_id, "method": method, "params": params})
            try:
                resp = await asyncio.wait_for(fut, timeout=timeout_s)
            except asyncio.TimeoutError:
                raise GatewayCommandError(f"agent {agent_uuid} did not respond to {method!r} within {timeout_s}s")
        finally:
            conn.pending.pop(req_id, None)

        if not resp.get("ok"):
            raise GatewayCommandError(resp.get("error") or f"{method} failed")
        return resp.get("result") or {}

    # ── local admin socket (Flask -> gateway) ────────────────────

    async def _handle_admin_connection(self, allowed_uids: set[int],
                                        reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        peer_uid = _peer_uid(sock) if sock is not None else None
        if peer_uid is None or peer_uid not in allowed_uids:
            log.warning("rejecting admin client uid=%s (allowed=%s)", peer_uid, sorted(allowed_uids))
            try:
                await _send_frame(writer, {"ok": False, "error": "unauthorized"})
            finally:
                writer.close()
            return

        try:
            while True:
                msg = await _recv_frame(reader)
                if msg is None:
                    return
                method = msg.get("method")
                params = msg.get("params") or {}
                req_id = msg.get("id")

                if method != "push_command":
                    await _send_frame(writer, _res(req_id, ok=False, error=f"unknown method: {method}"))
                    continue

                try:
                    result = await self.push_command(
                        agent_uuid=str(params.get("agent_uuid", "")),
                        method=str(params.get("command_method", "")),
                        params=params.get("command_params") or {},
                        timeout_s=float(params.get("timeout_s") or DEFAULT_COMMAND_TIMEOUT_S),
                    )
                except GatewayCommandError as exc:
                    await _send_frame(writer, _res(req_id, ok=False, error=str(exc)))
                    continue
                await _send_frame(writer, _res(req_id, ok=True, result=result))
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            log.exception("admin connection handler crashed")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _peer_uid(sock) -> int | None:
    """SO_PEERCRED on Linux — same approach as capd/server.py's _peer_uid."""
    import socket as _socket
    try:
        if sys.platform.startswith("linux"):
            data = sock.getsockopt(_socket.SOL_SOCKET, 17, 12)  # 17 = SO_PEERCRED
            _, uid, _ = struct.unpack("iII", data)
            return uid
    except OSError:
        return None
    return None


def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx
