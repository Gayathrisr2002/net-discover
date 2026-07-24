"""Persistent TLS connection to the fleet gateway.

Wire format matches marlinspike/fleet/gateway/server.py exactly (that
module's docstring is the canonical protocol description) — length-
prefixed JSON envelopes:

    {"type": "req", "id": <int>, "method": <str>, "params": {...}}
    {"type": "res", "id": <int>, "ok": bool, "result": {...} | "error": <str>}
    {"type": "event", "method": <str>, "params": {...}}   # no response expected

Deliberately NOT a shared import between this package and the gateway:
this package must stay installable standalone on a bare remote box with
none of the rest of the MarlinSpike suite present, so the ~30 lines of
framing are duplicated rather than pulled in via a dependency — the same
tradeoff marlinspike-capd/capd/server.py and marlinspike/capture/client.py
already make for the same reason (capd_client.py in this package is the
same tradeoff applied to the capd client itself).

Phase 2 scope was strict request/response: agent sends heartbeat, sleeps,
repeats. Phase 3 needs real bidirectionality — the gateway pushes capture
commands (start/stop/list_interfaces) at any time, which must be relayed
to the agent's own local capd and answered, *while* heartbeat keeps going
and *while* an active capture's stats get reported upward. That requires
a proper multiplexer: one reader task demuxing incoming frames (res ->
resolve a pending future for something *we* asked; req -> dispatch to a
command handler and reply), a heartbeat loop using the same pending-
future mechanism, and one stats-reporter task per active capture session.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import random
import ssl
import struct

from . import consumer
from .capd_client import CapdClient, CapdError, CapdUnavailable, Interface

log = logging.getLogger("marlinspike-agent")

_LEN_PREFIX = 4
_MAX_MESSAGE_BYTES = 1 << 20

DEFAULT_HEARTBEAT_INTERVAL_S = 30.0
DEFAULT_STATS_INTERVAL_S = 3.0
_MAX_BACKOFF_S = 60.0
_REQUEST_TIMEOUT_S = 10.0

# Report text is split into chunks well under the 1 MiB frame cap (leaves
# headroom for JSON envelope overhead + string-escaping expansion) rather
# than raising the cap unbounded for a large chain-output report.
_REPORT_CHUNK_CHARS = 512 * 1024


class AgentError(RuntimeError):
    pass


# ── wire framing ────────────────────────────────────────────────

async def _recv_frame(reader: asyncio.StreamReader) -> dict | None:
    try:
        header = await reader.readexactly(_LEN_PREFIX)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > _MAX_MESSAGE_BYTES:
        raise AgentError(f"bad frame length: {length}")
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    return json.loads(body.decode("utf-8"))


async def _send_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    writer.write(struct.pack(">I", len(body)) + body)
    await writer.drain()


def build_ssl_context(*, ca_cert: str | None, insecure_skip_verify: bool,
                      client_cert_pem: str | None = None,
                      client_key_pem: str | None = None) -> ssl.SSLContext:
    if insecure_skip_verify:
        log.warning(
            "TLS certificate verification DISABLED (--insecure-skip-verify) — "
            "only ever use this for local testing, never a real deployment."
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=ca_cert)

    if client_cert_pem and client_key_pem:
        # SSLContext.load_cert_chain needs file paths, not in-memory PEM —
        # write to a private temp dir (0700 by mkdtemp default) just long
        # enough for this eager, synchronous load, then clean up. The
        # durable copy lives only in the 0600 credential file
        # (credential_store.py), never as a standing file on disk here.
        import stat
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "client-cert.pem")
            key_path = os.path.join(tmp, "client-key.pem")
            with open(cert_path, "w", encoding="utf-8") as f:
                f.write(client_cert_pem)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(client_key_pem)
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    return ctx


async def enroll(*, gateway_host: str, gateway_port: int, ssl_context: ssl.SSLContext,
                  token: str, name: str | None, agent_version: str, os_info: str,
                  csr_pem: str | None = None) -> dict:
    """One-shot: redeem an enrollment token, return {"agent_uuid", "credential"}
    (plus "client_cert_pem" when csr_pem was supplied and the gateway has a
    fleet CA configured — see gateway/db.py:enroll_agent)."""
    reader, writer = await asyncio.open_connection(gateway_host, gateway_port, ssl=ssl_context)
    try:
        await _send_frame(writer, {
            "type": "req", "id": 1, "method": "enroll",
            "params": {
                "token": token, "name": name, "agent_version": agent_version, "os_info": os_info,
                "csr_pem": csr_pem,
            },
        })
        resp = await _recv_frame(reader)
        if resp is None:
            raise AgentError("connection closed during enrollment")
        if not resp.get("ok"):
            raise AgentError(resp.get("error") or "enrollment failed")
        return resp["result"]
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


class AgentClient:
    """Maintains the long-lived, authenticated connection: auth once, then
    heartbeat + relay gateway-pushed capture commands to the local capd,
    reconnecting with exponential backoff on any drop."""

    def __init__(self, *, gateway_host: str, gateway_port: int, ssl_context: ssl.SSLContext,
                 agent_uuid: str, credential: str,
                 capd_socket_path: str,
                 heartbeat_interval_s: float = DEFAULT_HEARTBEAT_INTERVAL_S,
                 stats_interval_s: float = DEFAULT_STATS_INTERVAL_S,
                 staging_dir: str | None = None,
                 spool_dir: str | None = None,
                 scan_profile: str = "fast",
                 dpi_engine: str | None = None,
                 dpi_binary: str | None = None):
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.ssl_context = ssl_context
        self.agent_uuid = agent_uuid
        self.credential = credential
        self.capd_socket_path = capd_socket_path
        self.heartbeat_interval_s = heartbeat_interval_s
        self.stats_interval_s = stats_interval_s
        self.staging_dir = staging_dir or consumer.default_staging_dir()
        self.spool_dir = spool_dir or consumer.default_spool_dir()
        self.scan_profile = scan_profile
        self.dpi_engine = dpi_engine
        self.dpi_binary = dpi_binary

        self._next_id_counter = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._write_lock: asyncio.Lock | None = None
        self._active_sessions: dict[str, asyncio.Task] = {}
        self._current_writer: asyncio.StreamWriter | None = None
        # asyncio only holds a *weak* reference to a task created via
        # create_task — several call sites below fire one off without
        # storing it anywhere else (unlike reader_task/heartbeat_task/
        # _active_sessions, which already retain what they need), so
        # nothing stops it from being garbage-collected mid-execution — a
        # documented asyncio gotcha, and a real risk for the longer-running
        # ones (_scan_and_ship runs a real pcap analysis + a multi-chunk
        # network send).
        self._background_tasks: set[asyncio.Task] = set()

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task

    def _capd(self) -> CapdClient:
        return CapdClient(self.capd_socket_path)

    def _next_id(self) -> int:
        self._next_id_counter += 1
        return self._next_id_counter

    async def run_forever(self) -> None:
        backoff = 1.0
        while True:
            try:
                await self._run_once()
                backoff = 1.0  # clean session ended (shouldn't normally happen) — reset backoff
            except (ConnectionError, OSError, ssl.SSLError, asyncio.TimeoutError, AgentError) as exc:
                log.warning("connection lost (%s) — reconnecting shortly", exc)
            except Exception:
                log.exception("agent client crashed — reconnecting shortly")
            # Jittered sleep (±50% of the nominal backoff): a fleet of many
            # agents all dropped by the same event (gateway restart, network
            # blip) would otherwise all retry in lockstep and hit the
            # gateway with a synchronized reconnect spike every backoff
            # interval. The backoff value itself still grows deterministically.
            await asyncio.sleep(random.uniform(backoff * 0.5, backoff * 1.5))
            backoff = min(backoff * 2, _MAX_BACKOFF_S)

    async def _run_once(self) -> None:
        reader, writer = await asyncio.open_connection(
            self.gateway_host, self.gateway_port, ssl=self.ssl_context
        )
        self._pending = {}
        self._write_lock = asyncio.Lock()
        self._active_sessions = {}
        self._current_writer = writer
        try:
            # Auth handshake happens before the reader/heartbeat tasks exist —
            # a plain direct send+recv, same as Phase 2.
            await _send_frame(writer, {
                "type": "req", "id": self._next_id(), "method": "auth",
                "params": {"agent_uuid": self.agent_uuid, "credential": self.credential},
            })
            resp = await _recv_frame(reader)
            if resp is None:
                raise AgentError("connection closed during auth")
            if not resp.get("ok"):
                raise AgentError(resp.get("error") or "auth rejected")
            log.info("authenticated as %s", self.agent_uuid)

            self._spawn(self._flush_spool())

            reader_task = asyncio.create_task(self._reader_loop(reader, writer))
            heartbeat_task = asyncio.create_task(self._heartbeat_loop(writer))
            done, still_running = await asyncio.wait(
                {reader_task, heartbeat_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for t in still_running:
                t.cancel()
            for t in done:
                exc = t.exception()
                if exc is not None:
                    raise exc
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.cancel()
            for task in self._active_sessions.values():
                task.cancel()
            self._active_sessions.clear()
            self._current_writer = None
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ── agent-initiated requests (heartbeat) ────────────────────

    async def _send_request(self, writer: asyncio.StreamWriter, method: str, params: dict) -> dict:
        req_id = self._next_id()
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut
        async with self._write_lock:
            await _send_frame(writer, {"type": "req", "id": req_id, "method": method, "params": params})
        try:
            resp = await asyncio.wait_for(fut, timeout=_REQUEST_TIMEOUT_S)
        finally:
            self._pending.pop(req_id, None)
        if not resp.get("ok"):
            raise AgentError(resp.get("error") or f"{method} rejected")
        return resp.get("result") or {}

    async def _heartbeat_loop(self, writer: asyncio.StreamWriter) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval_s)
            await self._send_request(writer, "heartbeat", {})

    # ── demux incoming frames ────────────────────────────────────

    async def _reader_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            msg = await _recv_frame(reader)
            if msg is None:
                raise AgentError("connection closed by gateway")

            msg_type = msg.get("type")
            if msg_type == "res":
                fut = self._pending.get(msg.get("id"))
                if fut is not None and not fut.done():
                    fut.set_result(msg)
                continue

            if msg_type == "req":
                # A gateway-pushed command (start/stop/list_interfaces). Handle
                # it as its own task so a slow capd round-trip never blocks
                # reading the next frame (heartbeat responses, other commands).
                self._spawn(self._handle_command(writer, msg))
                continue

    async def _handle_command(self, writer: asyncio.StreamWriter, msg: dict) -> None:
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        loop = asyncio.get_running_loop()

        try:
            if method == "list_interfaces":
                ifaces = await loop.run_in_executor(
                    None, functools.partial(self._capd().list_interfaces,
                                             include_virtual=bool(params.get("include_virtual", False)))
                )
                result = {"interfaces": [i.to_dict() for i in ifaces]}
            elif method == "start":
                result = await self._cmd_start(params, loop)
            elif method == "stop":
                result = await self._cmd_stop(params, loop)
            else:
                await _send_frame_locked(self._write_lock, writer,
                                          {"type": "res", "id": req_id, "ok": False,
                                           "error": f"unknown method: {method}"})
                return
        except (CapdError, CapdUnavailable) as exc:
            await _send_frame_locked(self._write_lock, writer,
                                      {"type": "res", "id": req_id, "ok": False, "error": str(exc)})
            return
        except Exception:
            log.exception("command %s crashed", method)
            await _send_frame_locked(self._write_lock, writer,
                                      {"type": "res", "id": req_id, "ok": False, "error": "internal agent error"})
            return

        await _send_frame_locked(self._write_lock, writer,
                                  {"type": "res", "id": req_id, "ok": True, "result": result})

    async def _cmd_start(self, params: dict, loop: asyncio.AbstractEventLoop) -> dict:
        session_id = str(params.get("session_id", ""))
        resp = await loop.run_in_executor(None, functools.partial(
            self._capd().start,
            session_id=session_id,
            interface=str(params.get("interface", "")),
            bpf_filter=str(params.get("bpf", "") or params.get("bpf_filter", "")),
            ring_filesize_kb=int(params.get("ring_filesize_kb") or 200_000),
            ring_files=int(params.get("ring_files") or 10),
            max_duration_s=int(params.get("max_duration_s") or 0),
        ))
        # Kick off a background reporter that relays periodic progress
        # upward as unprompted 'event' frames — decoupled from the
        # request/response channel so a stalled stats poll never blocks
        # heartbeat or other commands.
        task = asyncio.create_task(self._stats_reporter(session_id))
        self._active_sessions[session_id] = task
        return resp

    async def _cmd_stop(self, params: dict, loop: asyncio.AbstractEventLoop) -> dict:
        session_id = str(params.get("session_id", ""))
        resp = await loop.run_in_executor(None, self._capd().stop, session_id)
        task = self._active_sessions.pop(session_id, None)
        if task is not None:
            task.cancel()
        # The stats-reporter task (just cancelled) is what normally notices
        # rotated files — but the *final* file only closes as part of this
        # stop() call itself, after the reporter stopped polling, so it must
        # be picked up here or that last rotation's data never gets analyzed.
        for closed_path in resp.get("files_closed") or []:
            self._spawn(self._scan_and_ship(closed_path, session_id))
        return resp

    async def _stats_reporter(self, session_id: str) -> None:
        """Poll local capd's one-shot session_status and relay a summarized
        snapshot upward — never the raw per-second stream (that would be a
        needless amount of chatter over the WAN for a progress indicator).
        Also the trigger for local analysis: each newly-closed rotation file
        gets scanned and its report shipped upward (Phase 4)."""
        loop = asyncio.get_running_loop()
        try:
            while True:
                await asyncio.sleep(self.stats_interval_s)
                try:
                    status = await loop.run_in_executor(None, self._capd().session_status, session_id)
                except (CapdError, CapdUnavailable):
                    return  # session gone (stopped/crashed) — nothing more to report
                # writer/write_lock belong to the currently-running connection;
                # grabbed fresh each iteration in case of reconnect churn.
                writer = self._current_writer
                if writer is None:
                    return
                for closed_path in status.get("files_closed") or []:
                    self._spawn(self._scan_and_ship(closed_path, session_id))
                still_running = status.get("running", True)
                await _send_frame_locked(self._write_lock, writer, {
                    "type": "event", "method": "session_stats",
                    "params": {
                        "session_id": session_id,
                        "bytes_captured": status.get("bytes_total", 0),
                        "rotation_count": status.get("file_index", 0),
                        # Without this, a session that expires on its own
                        # (max_duration_s reached, or the ring simply fills
                        # under a policy that doesn't loop) never tells the
                        # gateway it's actually done — record_session_stats
                        # only touched bytes/rotation counts, never status,
                        # so the CaptureSession row stayed "running" forever
                        # even after the report had already shipped and
                        # been ingested. Same class of bug as the local
                        # capture path's StatsHub finalizer fixes, on the
                        # remote path instead. Explicit /stop requests are
                        # unaffected — they already finalize synchronously
                        # from the app's own stop_session handler.
                        "running": still_running,
                    },
                })
                if not still_running:
                    return
        except asyncio.CancelledError:
            return

    # ── local analysis + report shipping (Phase 4) ───────────────

    async def _scan_and_ship(self, pcap_path: str, session_id: str) -> None:
        loop = asyncio.get_running_loop()
        report_path = await loop.run_in_executor(None, functools.partial(
            consumer.run_scan,
            pcap_path=pcap_path, session_id=session_id, staging_dir=self.staging_dir,
            scan_profile=self.scan_profile, dpi_engine=self.dpi_engine, dpi_binary=self.dpi_binary,
        ))
        if report_path is None:
            return  # already logged by consumer.run_scan

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report_text = f.read()
        except OSError:
            log.exception("failed to read report %s", report_path)
            return

        try:
            await self._ship_report(session_id, os.path.basename(report_path), report_text,
                                     pcap_filename=os.path.basename(pcap_path))
        finally:
            try:
                os.remove(report_path)
            except OSError:
                pass

    async def _ship_report(self, session_id: str, filename: str, report_text: str,
                            pcap_filename: str) -> None:
        """Send a finished report upward. Never loses it: a link that's
        down (or drops mid-send) gets the report spooled to disk instead
        of dropped, and _flush_spool retries it on the next reconnect."""
        # Capture writer AND lock together, once, and use only these local
        # references for the whole send — never self._write_lock again
        # inside the loop. A reconnect mid-send (large report, many
        # chunks) replaces both self._current_writer and self._write_lock
        # with a fresh pair for the new connection; re-reading
        # self._write_lock on later iterations while still holding the
        # OLD writer would send to an already-closed transport while
        # locking out the NEW connection's legitimate traffic (heartbeat,
        # pushed commands) behind a lock nothing else is using. Pairing
        # them once means a mid-send reconnect instead fails cleanly on
        # the stale writer (caught below, spooled) without ever touching
        # the new connection's lock.
        writer = self._current_writer
        lock = self._write_lock
        if writer is None or lock is None:
            log.warning("session=%s no active connection — spooling report %s", session_id, filename)
            self._spool_report(session_id, filename, report_text, pcap_filename)
            return

        try:
            total_chunks = max(1, -(-len(report_text) // _REPORT_CHUNK_CHARS))  # ceil div
            for i in range(total_chunks):
                chunk = report_text[i * _REPORT_CHUNK_CHARS:(i + 1) * _REPORT_CHUNK_CHARS]
                await _send_frame_locked(lock, writer, {
                    "type": "event", "method": "report_chunk",
                    "params": {
                        "session_id": session_id, "filename": filename,
                        "chunk_index": i, "total_chunks": total_chunks, "data": chunk,
                    },
                })
            await _send_frame_locked(lock, writer, {
                "type": "event", "method": "report_complete",
                "params": {
                    "session_id": session_id, "filename": filename,
                    "total_chunks": total_chunks, "pcap_filename": pcap_filename,
                },
            })
        except (ConnectionError, OSError, asyncio.CancelledError) as exc:
            log.warning("session=%s link dropped mid-send (%s) — spooling report %s",
                        session_id, exc, filename)
            self._spool_report(session_id, filename, report_text, pcap_filename)
            return

        log.info("session=%s shipped report %s (%d bytes, %d chunks)",
                  session_id, filename, len(report_text), total_chunks)

    # ── durable local spool (Phase 5) ────────────────────────────

    def _spool_report(self, session_id: str, filename: str, report_text: str, pcap_filename: str) -> None:
        try:
            os.makedirs(self.spool_dir, exist_ok=True)
            spool_path = os.path.join(self.spool_dir, filename + ".spool.json")
            with open(spool_path, "w", encoding="utf-8") as f:
                json.dump({
                    "session_id": session_id, "filename": filename,
                    "pcap_filename": pcap_filename, "report_text": report_text,
                }, f)
        except OSError:
            log.exception("failed to spool report %s — data lost", filename)

    async def _flush_spool(self) -> None:
        """Called once right after (re)authenticating. Best-effort: any
        report still un-shippable (immediate re-disconnect) just gets
        re-spooled by _ship_report and waits for the next reconnect."""
        if not os.path.isdir(self.spool_dir):
            return
        try:
            entries = sorted(os.listdir(self.spool_dir))
        except OSError:
            return
        spooled = [e for e in entries if e.endswith(".spool.json")]
        if not spooled:
            return
        log.info("flushing %d spooled report(s)", len(spooled))
        for entry in spooled:
            spool_path = os.path.join(self.spool_dir, entry)
            try:
                with open(spool_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError):
                log.exception("failed to read spool entry %s — leaving in place", entry)
                continue
            try:
                os.remove(spool_path)
            except OSError:
                pass
            await self._ship_report(
                data["session_id"], data["filename"], data["report_text"], data["pcap_filename"],
            )


async def _send_frame_locked(lock: asyncio.Lock, writer: asyncio.StreamWriter, obj: dict) -> None:
    async with lock:
        await _send_frame(writer, obj)
