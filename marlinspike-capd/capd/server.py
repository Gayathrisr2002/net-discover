"""uds JSON-RPC server.

Length-prefixed JSON over a unix-domain socket. The web app is the only
client; we authenticate it by SO_PEERCRED and reject any uid not in the
allow-list (defaults to the socket owner's uid + 0). One request → one
response, except `stats` which streams `{type:"stats", ...}` frames
until the supervisor exits or the client disconnects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from . import bpf, interfaces
from .supervisor import CaptureConfig, CaptureSupervisor

log = logging.getLogger("capd.server")

# Length-prefix size. 4 bytes big-endian = max 4GB per message; we cap
# much lower in practice.
_LEN_PREFIX = 4
_MAX_MESSAGE_BYTES = 1 << 20  # 1 MiB; way more than any of our messages need


@dataclass
class ServerConfig:
    socket_path: Path
    capture_root: Path
    allowed_uids: set[int]
    # Additional uids allowed to connect, read from this file on every
    # connection attempt (cheap mtime check, only re-parsed when changed)
    # rather than baked into the command line — lets both the
    # marlinspike-agent and marlinspike-capd .deb postinst scripts wire
    # up cross-package uid access automatically (see debian/postinst in
    # both packages) with no systemd unit edit or capd restart needed.
    # One uid per line; blank lines and '#' comments ignored.
    allow_uid_file: "Path | None" = None


class CapdServer:
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self._sessions: dict[str, CaptureSupervisor] = {}
        self._sessions_lock = asyncio.Lock()
        self._uid_file_cache: "tuple[float, set[int]] | None" = None

    def _effective_allowed_uids(self) -> set[int]:
        if self.cfg.allow_uid_file is None:
            return self.cfg.allowed_uids
        try:
            mtime = self.cfg.allow_uid_file.stat().st_mtime
        except OSError:
            return self.cfg.allowed_uids
        if self._uid_file_cache is not None and self._uid_file_cache[0] == mtime:
            return self.cfg.allowed_uids | self._uid_file_cache[1]
        file_uids: set[int] = set()
        try:
            for line in self.cfg.allow_uid_file.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    file_uids.add(int(line))
                except ValueError:
                    log.warning("ignoring non-numeric line in %s: %r", self.cfg.allow_uid_file, line)
        except OSError:
            file_uids = set()
        self._uid_file_cache = (mtime, file_uids)
        return self.cfg.allowed_uids | file_uids

    # ── public entry ──────────────────────────────────────────

    async def serve(self) -> None:
        sock_path = str(self.cfg.socket_path)
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass
        # Create the socket so we can chmod it before accept(). The web app
        # client runs as a different, non-root uid/gid with no group shared
        # with this (root) process, so 0o660 would block its connect() before
        # our SO_PEERCRED check ever runs. Real authorization happens in
        # _handle_client() via allowed_uids, so the file mode just needs to
        # let any local peer reach that check.
        srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.bind(sock_path)
        os.chmod(sock_path, 0o666)
        srv_sock.listen(16)

        loop = asyncio.get_running_loop()
        srv_sock.setblocking(False)
        log.info("capd listening on %s (allowed uids: %s%s)", sock_path,
                  sorted(self.cfg.allowed_uids),
                  f", plus {self.cfg.allow_uid_file}" if self.cfg.allow_uid_file else "")

        try:
            while True:
                client_sock, _ = await loop.sock_accept(srv_sock)
                asyncio.create_task(self._handle_client(client_sock))
        finally:
            srv_sock.close()
            try:
                os.unlink(sock_path)
            except FileNotFoundError:
                pass

    # ── per-connection handler ────────────────────────────────

    async def _handle_client(self, client_sock: socket.socket) -> None:
        peer_uid = _peer_uid(client_sock)
        allowed = self._effective_allowed_uids()
        if peer_uid is None or peer_uid not in allowed:
            log.warning("rejecting client uid=%s (allowed=%s)", peer_uid, sorted(allowed))
            try:
                await _send_json_async(client_sock, {"ok": False, "error": "unauthorized"})
            finally:
                client_sock.close()
            return

        try:
            while True:
                msg = await _recv_json_async(client_sock)
                if msg is None:
                    return
                resp = await self._dispatch(msg, client_sock)
                # `stats` streams; dispatch handles its own writes.
                if resp is not None:
                    await _send_json_async(client_sock, resp)
        except Exception:
            log.exception("client handler crashed")
        finally:
            client_sock.close()

    # ── dispatch ──────────────────────────────────────────────

    async def _dispatch(self, msg: dict, client_sock: socket.socket) -> dict | None:
        method = (msg or {}).get("method")
        params: dict[str, Any] = (msg or {}).get("params") or {}
        log.debug("dispatch method=%s", method)

        if method == "list_interfaces":
            return {"ok": True, "interfaces": interfaces.list_interfaces(
                include_virtual=bool(params.get("include_virtual", False))
            )}

        if method == "validate_bpf":
            link_type = int(params.get("link_type", bpf.DLT_EN10MB))
            res = bpf.validate(str(params.get("filter", "")), link_type=link_type)
            return {"ok": res.ok, "error": res.error}

        if method == "start":
            return await self._start_session(params)

        if method == "stop":
            return await self._stop_session(str(params.get("session_id", "")))

        if method == "session_status":
            return self._session_status(str(params.get("session_id", "")))

        if method == "stats":
            await self._stream_stats(client_sock, str(params.get("session_id", "")),
                                     float(params.get("interval_s", 1.0)))
            return None

        if method == "version":
            try:
                pcap_version = bpf.libpcap_version()
            except OSError as exc:
                pcap_version = f"unavailable: {exc}"
            return {"ok": True, "capd_version": _capd_version(), "libpcap": pcap_version}

        return {"ok": False, "error": f"unknown method: {method}"}

    async def _start_session(self, params: dict[str, Any]) -> dict:
        session_id = str(params.get("session_id", "")).strip()
        interface = str(params.get("interface", "")).strip()
        bpf_filter = str(params.get("bpf", "") or params.get("bpf_filter", ""))
        # A malformed value here (e.g. a non-numeric string) used to raise
        # ValueError/TypeError uncaught — isolated to this one connection
        # by _handle_client's outer except (it doesn't crash the daemon or
        # affect other sessions), but the socket just closed with no
        # {"ok": false, "error": ...} response, so the caller
        # (marlinspike/capture/client.py) saw a generic "capd closed
        # connection" instead of the actual, specific cause.
        try:
            filesize_kb = int(params.get("ring_filesize_kb") or params.get("filesize_kb") or 200_000)
            files = int(params.get("ring_files") or params.get("files") or 10)
            max_duration_s = int(params.get("max_duration_s") or 0)
        except (TypeError, ValueError):
            return {"ok": False, "error": "ring_filesize_kb, ring_files, and max_duration_s must be integers"}

        if not session_id:
            return {"ok": False, "error": "session_id required"}
        if not interface:
            return {"ok": False, "error": "interface required"}

        # Pre-flight: BPF must compile.
        link_type = bpf.DLT_LINUX_SLL2 if interface == "any" else bpf.DLT_EN10MB
        v = bpf.validate(bpf_filter, link_type=link_type)
        if not v.ok:
            return {"ok": False, "error": f"bpf invalid: {v.error}"}

        # Pre-flight: interface must exist.
        if interface != "any" and interfaces.find_interface(interface) is None:
            return {"ok": False, "error": f"interface not found: {interface}"}

        out_dir = Path(self.cfg.capture_root) / session_id
        cfg = CaptureConfig(
            session_id=session_id,
            interface=interface,
            bpf_filter=bpf_filter,
            output_dir=out_dir,
            filesize_kb=filesize_kb,
            files=files,
            max_duration_s=max_duration_s,
        )

        async with self._sessions_lock:
            if session_id in self._sessions and self._sessions[session_id].is_running():
                return {"ok": False, "error": f"session {session_id} already running"}
            # Interface-level lock (Finding #21), matching docs/live-capture.md:
            #   * a named NIC hosts only one running capture at a time;
            #   * `any` captures every interface, so it conflicts with — and is
            #     blocked by — any other running capture, and vice versa.
            # Checked inside the lock so it's atomic against concurrent starts.
            running = [
                (other_id, other)
                for other_id, other in self._sessions.items()
                if other_id != session_id and other.is_running()
            ]
            for other_id, other in running:
                other_iface = getattr(other.cfg, "interface", None)
                if interface == "any" or other_iface == "any" or other_iface == interface:
                    # Name both interfaces explicitly rather than just
                    # "any" — when interface == "any" and other_iface is a
                    # specific NIC (or vice versa), a message naming only
                    # "any" reads as if some OTHER session is also on
                    # "any", which is confusing when it's actually a named
                    # NIC that's already running (confirmed confusing in
                    # practice: a real operator asked "why does it say any
                    # is captured when I only started enp2s0").
                    return {
                        "ok": False,
                        "error": (
                            f"interface {interface!r} conflicts with session {other_id}, "
                            f"already capturing on {other_iface!r} ('any' captures every "
                            f"interface, so it can't run alongside a capture on any specific NIC)"
                        ),
                    }
            try:
                sup = CaptureSupervisor(cfg)
                sup.start()
            except Exception as exc:
                log.exception("start failed for session=%s", session_id)
                return {"ok": False, "error": str(exc)}
            self._sessions[session_id] = sup

        return {"ok": True, "session_id": session_id, "output_dir": str(out_dir)}

    async def _stop_session(self, session_id: str) -> dict:
        async with self._sessions_lock:
            sup = self._sessions.get(session_id)
            if sup is None:
                return {"ok": False, "error": f"unknown session: {session_id}"}

        # Stop is blocking (it waits up to 5s for SIGINT). Run in
        # default executor so the asyncio loop stays responsive.
        loop = asyncio.get_running_loop()
        stats = await loop.run_in_executor(None, sup.stop)

        async with self._sessions_lock:
            self._sessions.pop(session_id, None)

        return {
            "ok": True,
            "session_id": session_id,
            "packets": sup.final_packets,
            "drops": sup.final_drops,
            "bytes_total": stats.bytes_total,
            "files_closed": stats.files_closed,
            "files_lost_count": stats.files_lost_count,
        }

    def _reap_if_finished(self, session_id: str, stats) -> None:
        """Remove a self-expired session's supervisor once its terminal
        state (running=False) has actually been observed and returned to
        a caller. _stop_session already does this for an explicit stop —
        without this, a session that ends on its own (max_duration_s
        elapsed, or the process just died), the documented, intended way
        to run a bounded capture, left its finished CaptureSupervisor
        permanently in self._sessions for the life of this privileged
        (root) process, growing without bound until it's OOM-killed,
        taking down every other in-progress capture on the host with it.
        Safe to call unlocked from either call site below: both are plain
        synchronous code with no `await` between reading self._sessions
        and this pop, so nothing else on the event loop can interleave.
        """
        if not stats.running:
            self._sessions.pop(session_id, None)

    def _session_status(self, session_id: str) -> dict:
        """One-shot, non-streaming snapshot — for a caller that just wants
        a periodic poll (e.g. a fleet agent relaying summarized progress to
        the central gateway) without holding open a `stats` stream."""
        sup = self._sessions.get(session_id)
        if sup is None:
            return {"ok": False, "error": f"unknown session: {session_id}"}
        stats = sup.poll()
        self._reap_if_finished(session_id, stats)
        return {
            "ok": True,
            "session_id": session_id,
            "bytes_total": stats.bytes_total,
            "file_index": stats.file_index,
            "files_closed": stats.files_closed,
            "running": stats.running,
            "files_lost_count": stats.files_lost_count,
        }

    async def _stream_stats(self, client_sock: socket.socket, session_id: str, interval_s: float) -> None:
        sup = self._sessions.get(session_id)
        if sup is None:
            await _send_json_async(client_sock, {"ok": False, "error": f"unknown session: {session_id}"})
            return

        interval_s = max(0.25, min(10.0, interval_s))
        while True:
            stats = sup.poll()
            frame = {
                "type": "stats",
                "session_id": session_id,
                "ts": stats.ts,
                "bytes_total": stats.bytes_total,
                "bytes_per_sec": stats.bytes_per_sec,
                "current_file": stats.current_file,
                "file_index": stats.file_index,
                "files_closed": stats.files_closed,
                "running": stats.running,
                "files_lost_count": stats.files_lost_count,
            }
            self._reap_if_finished(session_id, stats)
            try:
                await _send_json_async(client_sock, frame)
            except (BrokenPipeError, ConnectionResetError):
                return
            if not stats.running:
                return
            await asyncio.sleep(interval_s)


# ── wire helpers ──────────────────────────────────────────────

def _capd_version() -> str:
    from . import __version__
    return __version__


def _peer_uid(sock: socket.socket) -> int | None:
    """SO_PEERCRED on Linux, LOCAL_PEEREID on macOS/BSD."""
    try:
        if sys.platform.startswith("linux"):
            # struct ucred: pid (i32), uid (u32), gid (u32) = 12 bytes
            data = sock.getsockopt(socket.SOL_SOCKET, 17, 12)  # 17 = SO_PEERCRED
            _, uid, _ = struct.unpack("iII", data)
            return uid
        if sys.platform == "darwin":
            # LOCAL_PEEREID returns euid then egid. Use getsockopt at level
            # SOL_LOCAL (0) opt LOCAL_PEEREID (1) struct xucred — easier:
            # use SO_PEERCRED-ish path via os.getpeername fallback.
            # macOS specific: getpeereid() — but ctypes-free path is to
            # use socket.getsockopt with LOCAL_PEERCRED (1) returning xucred.
            try:
                from socket import SOL_LOCAL  # type: ignore[attr-defined]
            except ImportError:
                SOL_LOCAL = 0
            # xucred: cr_version(u32), cr_uid(u32), cr_ngroups(i16), cr_groups[16](u32) = 4+4+2+4*16 = 74,
            # padded — request a generous buffer and unpack uid.
            buf = sock.getsockopt(SOL_LOCAL, 1, 76)
            # cr_version (u32 LE), cr_uid (u32 LE)
            _, uid = struct.unpack_from("II", buf, 0)
            return uid
    except OSError:
        return None
    return None


async def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    loop = asyncio.get_running_loop()
    out = bytearray()
    while len(out) < n:
        chunk = await loop.sock_recv(sock, n - len(out))
        if not chunk:
            return None
        out.extend(chunk)
    return bytes(out)


async def _recv_json_async(sock: socket.socket) -> dict | None:
    header = await _recv_exact(sock, _LEN_PREFIX)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > _MAX_MESSAGE_BYTES:
        log.warning("bad message length: %d", length)
        return None
    body = await _recv_exact(sock, length)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.warning("malformed json from client: %s", exc)
        return {}


async def _send_json_async(sock: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > _MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(sock, struct.pack(">I", len(body)) + body)
