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

Wire compatibility contract (Phase 6.3 — version-skew tolerance)
------------------------------------------------------------------
Extends the same discipline already documented for the capd<->web JSON-RPC
contract (marlinspike/capture/client.py) to this third stable contract
surface, so an older agent talking to a newer gateway (or vice versa)
degrades gracefully instead of crashing the connection:

* Every ``params`` dict is read with ``.get(key, default)``, never direct
  indexing — an old agent that predates some newer, optional field simply
  never sends it and the default applies; a newer agent sending a field
  this gateway doesn't know about yet is silently ignored.
* An unrecognized ``method`` on an already-authenticated connection gets a
  normal ``{"ok": false, "error": "unknown method: ..."}`` reply, not a
  dropped connection — see the bottom of ``_serve_authenticated`` below.
  The connection keeps working normally afterward (heartbeat etc. are
  unaffected by one rejected/unknown request).
* An unrecognized top-level ``type`` (something other than "req"/"res"/
  "event") is silently ignored rather than raising — see the ``msg_type``
  checks in ``_serve_authenticated`` and the agent's own ``_reader_loop``.
  A hypothetical future envelope type can be introduced without the older
  side crashing on it; it just won't act on it yet.
* ``agent_version`` (sent at enroll/auth, stored on the Agent row, shown in
  the fleet UI) is purely informational — never gates auth or dispatch.
  There is deliberately no hard minimum-version cutover: this is a young,
  single-maintainer protocol, not a public API with a deprecation policy,
  so the simplest correct rule is "never reject on version alone."

None of this is optional scaffolding added defensively — every dispatch
branch in this file (and in marlinspike-agent/agent/client.py) was already
written this way from Phase 2 onward; this section documents that intent
explicitly so future changes preserve it rather than accidentally tightening
a check into a hard failure.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import secrets
import ssl
import struct
import sys
import time
import uuid

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

# ── Phase 6.4: backpressure / rate-limiting against a misbehaving or
# compromised agent ──────────────────────────────────────────────────
#
# A legitimate agent ships report_chunk events sized _REPORT_CHUNK_CHARS
# (client.py) = 512 KiB of *text* each; at ~1.3x JSON-string-escaping
# overhead that's comfortably under _MAX_MESSAGE_BYTES per chunk. Capping
# total_chunks at 4096 still allows a multi-hundred-MB report (a
# pathologically large one for what's normally a small JSON summary) while
# making `"".join(chunks[i] for i in range(total_chunks))` in
# report_complete bounded work instead of a value an attacker fully
# controls — without this cap, a connection claiming total_chunks=10**9
# would iterate a billion times synchronously inside the event loop,
# freezing the *entire* gateway (every other agent's connection too, not
# just this one) for as long as that loop runs. This is a real,
# concrete DoS, not a defensive-programming nicety.
_MAX_REPORT_CHUNKS = 4096
# Total buffered bytes across all of one connection's in-flight (not yet
# report_complete'd) reassembly buffers. Bounds memory from an agent that
# streams report_chunk events forever without ever sending report_complete.
_MAX_REPORT_BYTES_PER_CONN = 200 * 1024 * 1024  # 200 MiB

# Minimum real interval between two DB-writing heartbeats from the same
# agent_uuid. A legitimate agent heartbeats every DEFAULT_HEARTBEAT_INTERVAL_S
# (30s, agent/client.py) — nothing stops a modified/compromised agent from
# heartbeating far faster, and every heartbeat currently does a real
# Postgres UPDATE (db.record_heartbeat). This throttles the DB write
# without breaking the wire contract: every heartbeat still gets a prompt
# {"ok": true} reply (a legitimate agent's reconnect/backoff logic depends
# on that), only the DB round-trip itself gets skipped when too frequent.
_MIN_HEARTBEAT_DB_WRITE_INTERVAL_S = 1.0

# Enroll/auth attempts are the only pre-authentication, DB-querying
# operations reachable by an unauthenticated TCP peer — exactly the
# surface a credential/token brute-force or connection-flood attack would
# hit. Rate-limited per source IP with a simple in-process sliding window
# (the gateway is a single asyncio process; no Redis/shared-state needed
# for this, unlike the Flask app's multi-worker rate limiter).
_AUTH_ATTEMPTS_PER_WINDOW = 20
_AUTH_WINDOW_S = 60.0


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
        # Reassembly buffers for chunked report_chunk/report_complete events
        # (Phase 4) — keyed by filename since one agent could in principle
        # ship more than one report in flight. Each session_uuid produces at
        # most one in-flight report at a time in practice, but keying by
        # filename (unique per run) rather than session_uuid costs nothing
        # and avoids a rare cross-talk edge case if that ever changes.
        self.report_chunks: dict[str, dict[int, str]] = {}
        # Running total of buffered chunk bytes across all filenames on this
        # connection (Phase 6.4) — cheap to maintain incrementally rather
        # than summing report_chunks on every event, and it's what
        # _MAX_REPORT_BYTES_PER_CONN actually bounds.
        self.report_bytes = 0
        # Last time this connection's heartbeat actually triggered a DB
        # write (Phase 6.4) — see _MIN_HEARTBEAT_DB_WRITE_INTERVAL_S. None
        # until the first heartbeat.
        self.last_heartbeat_write: float | None = None

    def next_id(self) -> int:
        self._next_id += 1
        return self._next_id


# ── agent-facing TLS listener ────────────────────────────────────

class GatewayServer:
    def __init__(self, heartbeat_timeout_s: float = DEFAULT_HEARTBEAT_TIMEOUT_S,
                 instance_id: str = "", admin_host: str = "", admin_port: int = 0):
        self.heartbeat_timeout_s = heartbeat_timeout_s
        # Phase 6.5 — identifies this process in the shared Redis registry
        # (db.register_agent_instance) so a Flask worker can find which
        # instance a given agent is connected to when more than one gateway
        # is running. instance_id defaults to a random id per process start
        # if unset — fine even for the single-instance case, since nothing
        # is ever compared against it unless a second instance also
        # publishes into the same registry.
        self.instance_id = instance_id or uuid.uuid4().hex
        self.admin_host = admin_host
        self.admin_port = admin_port
        self._connections: dict[str, _AgentConnection] = {}
        self._connections_lock = asyncio.Lock()
        # Sliding-window enroll/auth attempt counter per source IP (Phase
        # 6.4) — see _AUTH_ATTEMPTS_PER_WINDOW. Plain in-process dict: this
        # is a single asyncio process, not multi-worker, so there's no
        # cross-process state to share (unlike the Flask app's Redis-backed
        # login limiter).
        self._auth_attempts: dict[str, list[float]] = {}

    def _auth_rate_limited(self, peer_ip: str) -> bool:
        now = time.monotonic()
        attempts = [t for t in self._auth_attempts.get(peer_ip, []) if now - t < _AUTH_WINDOW_S]
        attempts.append(now)
        self._auth_attempts[peer_ip] = attempts
        # Opportunistically drop other IPs' expired windows too, so this
        # dict doesn't grow forever across many distinct source IPs over
        # the gateway's lifetime (a long-lived process, unlike a per-request
        # Flask limiter that's naturally bounded by request lifetime).
        if len(self._auth_attempts) > 10_000:
            self._auth_attempts = {
                ip: ts for ip, ts in self._auth_attempts.items()
                if any(now - t < _AUTH_WINDOW_S for t in ts)
            }
        return len(attempts) > _AUTH_ATTEMPTS_PER_WINDOW

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
            functools.partial(self._handle_admin_connection, allowed_uids, None), path=socket_path
        )
        os.chmod(socket_path, 0o666)
        log.info("fleet gateway admin socket listening on %s (allowed uids: %s)",
                  socket_path, sorted(allowed_uids))
        async with server:
            await server.serve_forever()

    async def serve_admin_tcp(self, host: str, port: int, token: str) -> None:
        """Cross-host admin listener (Phase 6.5): the same push_command /
        disconnect_agent dispatch as the local unix socket, but reachable
        over the network so a Flask worker can reach an agent connected to
        a *different* gateway instance — see db.lookup_agent_instance.
        SO_PEERCRED has no TCP equivalent, so auth here is a shared-secret
        token instead of a peer-uid check; every admin request must
        include a matching admin_token or gets rejected before any dispatch.
        Opt-in only: the caller (cli.py) only starts this when a token is
        actually configured, so a default single-instance deployment never
        exposes a network-reachable admin surface at all."""
        server = await asyncio.start_server(
            functools.partial(self._handle_admin_connection, None, token), host, port
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        log.info("fleet gateway admin TCP listener on %s", addrs)
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

            peer_ip = peer[0] if peer else "unknown"
            if self._auth_rate_limited(peer_ip):
                log.warning("rate-limiting enroll/auth attempts from %s", peer_ip)
                await _send_frame(writer, _res(msg.get("id"), ok=False, error="rate limited"))
                return

            agent_uuid = await self._authenticate(reader, writer, msg, loop)
            if agent_uuid is None:
                return
            log.info("agent %s authenticated from %s", agent_uuid, peer)

            conn = _AgentConnection(writer)
            async with self._connections_lock:
                self._connections[agent_uuid] = conn
            if self.admin_host and self.admin_port:
                # Only publish into the shared registry if this instance is
                # actually cross-host reachable (Phase 6.5) — a single-
                # instance deployment with no admin TCP configured has
                # nothing useful to register; Flask's fallback to the local
                # unix socket is already correct for it.
                await loop.run_in_executor(None, functools.partial(
                    db.register_agent_instance, agent_uuid=agent_uuid, instance_id=self.instance_id,
                    admin_host=self.admin_host, admin_port=self.admin_port,
                ))

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
                if self.admin_host and self.admin_port:
                    try:
                        await loop.run_in_executor(None, functools.partial(
                            db.unregister_agent_instance, agent_uuid=agent_uuid
                        ))
                    except Exception:
                        log.exception("failed to unregister instance for agent %s", agent_uuid)
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
                    csr_pem=params.get("csr_pem"),
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
                db.authenticate_agent, agent_uuid=agent_uuid, raw_credential=credential,
                peer_cert_fingerprint=_peer_cert_fingerprint(writer),
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
                asyncio.create_task(self._handle_event(agent_uuid, conn, msg, loop))
                continue

            if msg_type != "req":
                continue

            method = msg.get("method")
            req_id = msg.get("id")

            if method == "heartbeat":
                # Throttle the DB round-trips (revocation check + write),
                # not the reply: a legitimate agent heartbeats every
                # DEFAULT_HEARTBEAT_INTERVAL_S (30s) so this never engages
                # in normal operation, but nothing on the wire stops a
                # modified/compromised agent from heartbeating far faster
                # — see _MIN_HEARTBEAT_DB_WRITE_INTERVAL_S. Revocation is
                # still enforced promptly via _force_disconnect (Phase
                # 6.2); this periodic check is only the backup path for
                # when that push didn't reach this agent (e.g. gateway was
                # down at revoke time), so skipping it for a few seconds
                # under flood conditions costs nothing real.
                now = time.monotonic()
                if conn.last_heartbeat_write is None or now - conn.last_heartbeat_write >= _MIN_HEARTBEAT_DB_WRITE_INTERVAL_S:
                    conn.last_heartbeat_write = now
                    revoked = await loop.run_in_executor(None, functools.partial(
                        db.is_agent_revoked, agent_uuid=agent_uuid
                    ))
                    if revoked:
                        await _send_frame(conn.writer, _res(req_id, ok=False, error="revoked"))
                        return
                    await loop.run_in_executor(None, functools.partial(
                        db.record_heartbeat, agent_uuid=agent_uuid
                    ))
                    if self.admin_host and self.admin_port:
                        # Refresh the registry TTL (Phase 6.5) on the same
                        # throttled cadence as the heartbeat DB write —
                        # keeps a live agent's entry from ever expiring
                        # without adding a separate timer/task per agent.
                        await loop.run_in_executor(None, functools.partial(
                            db.register_agent_instance, agent_uuid=agent_uuid, instance_id=self.instance_id,
                            admin_host=self.admin_host, admin_port=self.admin_port,
                        ))
                await _send_frame(conn.writer, _res(req_id, ok=True, result={}))
                continue

            await _send_frame(conn.writer, _res(req_id, ok=False, error=f"unknown method: {method}"))

    async def _handle_event(self, agent_uuid: str, conn: _AgentConnection, msg: dict, loop) -> None:
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
            return

        if method == "report_chunk":
            filename = str(params.get("filename", ""))
            chunk_index = int(params.get("chunk_index", 0))
            data = str(params.get("data", ""))
            if not (0 <= chunk_index < _MAX_REPORT_CHUNKS):
                log.warning("agent %s sent out-of-range chunk_index=%d for %s — dropping report",
                            agent_uuid, chunk_index, filename)
                conn.report_bytes -= sum(len(v) for v in conn.report_chunks.pop(filename, {}).values())
                return
            if conn.report_bytes + len(data) > _MAX_REPORT_BYTES_PER_CONN:
                log.warning("agent %s exceeded %d bytes of buffered report data — dropping %s",
                            agent_uuid, _MAX_REPORT_BYTES_PER_CONN, filename)
                conn.report_bytes -= sum(len(v) for v in conn.report_chunks.pop(filename, {}).values())
                return
            conn.report_chunks.setdefault(filename, {})[chunk_index] = data
            conn.report_bytes += len(data)
            return

        if method == "report_complete":
            filename = str(params.get("filename", ""))
            total_chunks = int(params.get("total_chunks") or 0)
            chunks = conn.report_chunks.pop(filename, {})
            conn.report_bytes -= sum(len(v) for v in chunks.values())
            if not (0 < total_chunks <= _MAX_REPORT_CHUNKS) or len(chunks) != total_chunks or \
                    any(i not in chunks for i in range(total_chunks)):
                log.warning("agent %s report %s incomplete or invalid (got %d chunks, claimed %d) — dropping",
                            agent_uuid, filename, len(chunks), total_chunks)
                return
            report_text = "".join(chunks[i] for i in range(total_chunks))
            try:
                await loop.run_in_executor(None, functools.partial(
                    db.ingest_report,
                    session_uuid=str(params.get("session_id", "")),
                    filename=filename,
                    report_text=report_text,
                    pcap_filename=params.get("pcap_filename"),
                ))
            except Exception:
                log.exception("failed to ingest report %s from agent %s", filename, agent_uuid)
            return

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

    async def disconnect_agent(self, agent_uuid: str) -> bool:
        """Force-drop a live agent connection immediately (Phase 6.2:
        revoke/rotate-credential admin actions call this so a revoked agent
        can't keep talking until its next heartbeat-interval revocation
        check — see is_agent_revoked). Unlike push_command, this needs no
        reply from the agent: closing its writer alone is enough to make
        _handle_connection's read loop unblock and run its normal cleanup
        (mark_offline, cancel pending futures). Returns False if the agent
        wasn't connected at all — not an error, just nothing to do."""
        conn = self._connections.get(agent_uuid)
        if conn is None:
            return False
        conn.writer.close()
        return True

    # ── local admin socket (Flask -> gateway) ────────────────────

    async def _handle_admin_connection(self, allowed_uids: set[int] | None, admin_token: str | None,
                                        reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Shared dispatch for both admin transports. allowed_uids is set
        (and admin_token is None) for the local unix socket — SO_PEERCRED
        auth, exactly as before Phase 6.5. admin_token is set (and
        allowed_uids is None) for the cross-host TCP listener — every
        request must carry a matching params.admin_token instead, checked
        per-message below (constant-time compare) since there's no
        connection-level credential to check once up front like SO_PEERCRED."""
        if allowed_uids is not None:
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

                if admin_token is not None and not secrets.compare_digest(
                        str(params.get("admin_token", "")), admin_token):
                    await _send_frame(writer, _res(req_id, ok=False, error="unauthorized"))
                    continue

                if method == "disconnect_agent":
                    disconnected = await self.disconnect_agent(str(params.get("agent_uuid", "")))
                    await _send_frame(writer, _res(req_id, ok=True, result={"disconnected": disconnected}))
                    continue

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


def _peer_cert_fingerprint(writer: asyncio.StreamWriter) -> str | None:
    """SHA-256 fingerprint (hex) of the client cert the connecting agent
    presented during the TLS handshake, or None if it presented none (a
    pre-mTLS agent, or a CA isn't configured at all — see build_ssl_context's
    CERT_OPTIONAL below, which accepts a connection with no client cert at
    all so those agents keep working; authenticate_agent is what actually
    decides whether a missing cert is acceptable for *this* agent)."""
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None
    return hashlib.sha256(der).hexdigest()


def build_ssl_context(cert_path: str, key_path: str, ca_cert_path: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    if ca_cert_path and not os.path.isfile(ca_cert_path):
        # Graceful degrade, not a startup crash: a deployment that hasn't
        # (re-)run scripts/gen_dev_tls_cert.sh since the mTLS upgrade simply
        # has no fleet CA yet — agent enrollment/auth then continues on
        # bearer-credential-only auth, exactly as before this upgrade.
        log.warning("--ca-cert %s not found — mTLS agent-cert verification disabled "
                    "(bearer-credential-only auth); run scripts/gen_dev_tls_cert.sh to enable it",
                    ca_cert_path)
        ca_cert_path = None
    if ca_cert_path:
        # CERT_OPTIONAL, not CERT_REQUIRED: the very first `enroll` frame
        # (before any client cert has ever been issued) must still succeed,
        # and bearer-only agents (fingerprint NULL, see db.py) must keep
        # reconnecting without one. Any cert that *is* presented still gets
        # fully chain/expiry-validated against this CA by the ssl module
        # itself — only "no cert at all" is let through at the TLS layer,
        # with per-agent enforcement left to authenticate_agent().
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.load_verify_locations(cafile=ca_cert_path)
    return ctx
