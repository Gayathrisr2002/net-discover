"""Regression tests for Finding #21 (capd has no interface-level session lock).

``_start_session`` rejected a duplicate *session_id* but never checked whether
the requested *interface* was already being captured by another session. Two
near-simultaneous starts on one NIC (e.g. from two workers) therefore both
launched a dumpcap ring against the same interface — double capture load — and
the docs' claim of one-capture-per-interface was false.

Fix: inside the sessions lock, reject a start when another running session is
already capturing that (named) interface.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from capd import server as capd_server


class _FakeSupervisor:
    """Stand-in for CaptureSupervisor that never spawns dumpcap."""

    def __init__(self, cfg, dumpcap_path=None):
        self.cfg = cfg
        self._running = True

    def start(self):
        pass

    def is_running(self):
        return self._running


class _OkValidation:
    ok = True
    error = None


@pytest.fixture
def server(monkeypatch, tmp_path):
    monkeypatch.setattr(capd_server, "CaptureSupervisor", _FakeSupervisor)
    monkeypatch.setattr(capd_server.bpf, "validate", lambda *a, **k: _OkValidation())
    monkeypatch.setattr(capd_server.interfaces, "find_interface", lambda name: {"name": name})
    cfg = capd_server.ServerConfig(
        socket_path=tmp_path / "capd.sock",
        capture_root=tmp_path / "captures",
        allowed_uids={0},
    )
    return capd_server.CapdServer(cfg)


def test_second_session_on_same_interface_is_rejected(server):
    async def run():
        r1 = await server._start_session({"session_id": "s1", "interface": "eth0"})
        r2 = await server._start_session({"session_id": "s2", "interface": "eth0"})
        return r1, r2

    r1, r2 = asyncio.run(run())
    assert r1["ok"] is True
    assert r2["ok"] is False, "a second capture on the same NIC must be refused"
    assert "eth0" in r2["error"]


def test_different_interfaces_both_allowed(server):
    async def run():
        r1 = await server._start_session({"session_id": "s1", "interface": "eth0"})
        r2 = await server._start_session({"session_id": "s2", "interface": "eth1"})
        return r1, r2

    r1, r2 = asyncio.run(run())
    assert r1["ok"] is True
    assert r2["ok"] is True, "captures on distinct interfaces must both be allowed"


def test_any_blocks_named_interface_start(server):
    async def run():
        r1 = await server._start_session({"session_id": "s1", "interface": "any"})
        r2 = await server._start_session({"session_id": "s2", "interface": "eth0"})
        return r1, r2

    r1, r2 = asyncio.run(run())
    assert r1["ok"] is True
    assert r2["ok"] is False, "a running `any` capture must block a named-interface start"


def test_named_interface_blocks_any_start(server):
    async def run():
        r1 = await server._start_session({"session_id": "s1", "interface": "eth0"})
        r2 = await server._start_session({"session_id": "s2", "interface": "any"})
        return r1, r2

    r1, r2 = asyncio.run(run())
    assert r1["ok"] is True
    assert r2["ok"] is False, "a running named capture must block an `any` start"
