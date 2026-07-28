"""Regression test: capd never removed a self-expired session's supervisor
from self._sessions.

self._sessions.pop() only ever happened inside _stop_session — a session
that ends on its own (dumpcap's own `-a duration:N` timer elapses, or the
process just dies) never calls stop(), which is the documented, intended
way to run a bounded (max_duration_s) capture. That left the finished
CaptureSupervisor permanently in self._sessions for the life of this
privileged (root) process, growing without bound until it's OOM-killed —
taking down every other in-progress capture on the host with it.

Fix: _session_status and _stream_stats both now reap a session from
self._sessions the moment they observe stats.running == False, the same
terminal-state check _stop_session already used to justify its own pop.
"""

from __future__ import annotations

import asyncio

import pytest

from capd import server as capd_server
from capd.supervisor import CaptureStats


class _FakeSupervisor:
    """Stand-in for CaptureSupervisor whose capture has already self-expired
    (dumpcap's own -a duration:N timer elapsed) — poll() reports
    running=False without stop() ever having been called, exactly like a
    real supervisor would after its process exits on its own."""

    def __init__(self, cfg, dumpcap_path=None):
        self.cfg = cfg

    def is_running(self):
        return False

    def poll(self):
        return CaptureStats(
            ts=0.0, bytes_total=1234, bytes_per_sec=0.0,
            current_file=None, file_index=1, files_closed=["cap_00001.pcapng"],
            running=False,
        )


@pytest.fixture
def server(tmp_path):
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
    )
    return capd_server.CapdServer(cfg)


def test_session_status_reaps_self_expired_session(server):
    sup = _FakeSupervisor(cfg=None)
    server._sessions["s1"] = sup

    result = server._session_status("s1")

    assert result["ok"] is True
    assert result["running"] is False
    assert "s1" not in server._sessions, (
        "a self-expired session observed via session_status must be reaped, "
        "not left in self._sessions forever"
    )


def test_stream_stats_reaps_self_expired_session(server):
    sup = _FakeSupervisor(cfg=None)
    server._sessions["s1"] = sup

    class _FakeSocket:
        def send(self, data):
            return len(data)

        def fileno(self):
            return -1

    import capd.server as capd_server_module

    sent_frames = []

    async def _fake_send_json_async(sock, obj):
        sent_frames.append(obj)

    orig_send = capd_server_module._send_json_async
    capd_server_module._send_json_async = _fake_send_json_async
    try:
        asyncio.run(server._stream_stats(_FakeSocket(), "s1", 1.0))
    finally:
        capd_server_module._send_json_async = orig_send

    assert sent_frames and sent_frames[0]["running"] is False
    assert "s1" not in server._sessions, (
        "a self-expired session observed via the stats stream must be reaped, "
        "not left in self._sessions forever"
    )


def test_session_status_does_not_reap_still_running_session(server):
    class _RunningSupervisor(_FakeSupervisor):
        def poll(self):
            return CaptureStats(
                ts=0.0, bytes_total=100, bytes_per_sec=10.0,
                current_file="cap_00001.pcapng", file_index=1, files_closed=[],
                running=True,
            )

    server._sessions["s1"] = _RunningSupervisor(cfg=None)
    result = server._session_status("s1")

    assert result["running"] is True
    assert "s1" in server._sessions, "a still-running session must not be reaped"
