"""Tests for agent/client.py's raw-pcap shipping (_send_pcap/_ship_pcap)
and reference-based spool (_spool_pcap_ref/_flush_spool) — the transport
this session's architecture change introduced to replace agent-side
analysis + JSON report shipping.

Monkeypatches the module-level _send_frame (used by every _send_frame_locked
call) to capture frame dicts directly rather than doing real socket I/O —
the writer object itself is never touched, so a plain sentinel works fine
in its place.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from agent import client as agent_client


def _run(coro):
    return asyncio.run(coro)


def _make_client(spool_dir):
    return agent_client.AgentClient(
        gateway_host="gw", gateway_port=1234, ssl_context=None,
        agent_uuid="agent-1", credential="cred",
        capd_socket_path="/tmp/does-not-matter.sock",
        spool_dir=str(spool_dir),
    )


@pytest.fixture
def captured_frames(monkeypatch):
    frames = []

    async def fake_send_frame(writer, obj):
        frames.append(json.loads(json.dumps(obj)))  # deep-copy via round-trip

    monkeypatch.setattr(agent_client, "_send_frame", fake_send_frame)
    return frames


def test_send_pcap_chunks_reassemble_correctly(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = object()
    client._write_lock = asyncio.Lock()

    raw = os.urandom(agent_client._PCAP_CHUNK_RAW_BYTES * 2 + 137)
    pcap_path = tmp_path / "cap.pcapng"
    pcap_path.write_bytes(raw)

    shipped = _run(client._send_pcap("sess-1", "cap.pcapng", str(pcap_path)))
    assert shipped is True

    chunk_frames = [f for f in captured_frames if f["method"] == "pcap_chunk"]
    complete_frames = [f for f in captured_frames if f["method"] == "pcap_complete"]
    assert len(complete_frames) == 1
    assert len(chunk_frames) == complete_frames[0]["params"]["total_chunks"]

    reassembled = bytearray(len(raw))
    for f in chunk_frames:
        p = f["params"]
        chunk_bytes = base64.b64decode(p["data"])
        offset = p["chunk_index"] * agent_client._PCAP_CHUNK_RAW_BYTES
        reassembled[offset:offset + len(chunk_bytes)] = chunk_bytes
    assert bytes(reassembled) == raw
    assert complete_frames[0]["params"]["total_bytes"] == len(raw)


def test_send_pcap_fixed_chunk_sizing(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = object()
    client._write_lock = asyncio.Lock()

    raw = os.urandom(agent_client._PCAP_CHUNK_RAW_BYTES * 3)
    pcap_path = tmp_path / "cap.pcapng"
    pcap_path.write_bytes(raw)

    _run(client._send_pcap("sess-1", "cap.pcapng", str(pcap_path)))

    chunk_frames = sorted(
        (f for f in captured_frames if f["method"] == "pcap_chunk"),
        key=lambda f: f["params"]["chunk_index"],
    )
    assert len(chunk_frames) == 3
    for f in chunk_frames:
        decoded = base64.b64decode(f["params"]["data"])
        assert len(decoded) == agent_client._PCAP_CHUNK_RAW_BYTES


def test_send_pcap_no_connection_spools(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = None
    client._write_lock = None

    pcap_path = tmp_path / "cap.pcapng"
    pcap_path.write_bytes(b"some bytes")

    shipped = _run(client._send_pcap("sess-1", "cap.pcapng", str(pcap_path)))
    assert shipped is False
    assert captured_frames == []

    spool_file = tmp_path / "spool" / "cap.pcapng.spool.json"
    assert spool_file.is_file()
    data = json.loads(spool_file.read_text())
    assert data == {"session_id": "sess-1", "filename": "cap.pcapng", "pcap_path": str(pcap_path)}


def test_ship_pcap_deletes_file_on_success(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = object()
    client._write_lock = asyncio.Lock()

    pcap_path = tmp_path / "cap.pcapng"
    pcap_path.write_bytes(b"some bytes")

    _run(client._ship_pcap(str(pcap_path), "sess-1"))
    assert not pcap_path.exists()


def test_ship_pcap_keeps_file_on_failure(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = None  # forces _send_pcap to spool instead of send
    client._write_lock = None

    pcap_path = tmp_path / "cap.pcapng"
    pcap_path.write_bytes(b"some bytes")

    _run(client._ship_pcap(str(pcap_path), "sess-1"))
    assert pcap_path.exists()  # never shipped, so never deleted


def test_flush_spool_drops_reference_when_file_gone(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = object()
    client._write_lock = asyncio.Lock()

    spool_dir = tmp_path / "spool"
    spool_dir.mkdir(parents=True)
    pcap_path = tmp_path / "cap.pcapng"  # deliberately never created
    (spool_dir / "cap.pcapng.spool.json").write_text(json.dumps({
        "session_id": "sess-1", "filename": "cap.pcapng", "pcap_path": str(pcap_path),
    }))

    _run(client._flush_spool())

    # The stale reference is consumed either way (removed up front so a
    # bad reference can't loop forever), and nothing gets shipped for a
    # file that no longer exists.
    assert not (spool_dir / "cap.pcapng.spool.json").exists()
    assert captured_frames == []


def test_flush_spool_retries_existing_file(tmp_path, captured_frames):
    client = _make_client(tmp_path / "spool")
    client._current_writer = object()
    client._write_lock = asyncio.Lock()

    spool_dir = tmp_path / "spool"
    spool_dir.mkdir(parents=True)
    pcap_path = tmp_path / "cap.pcapng"
    pcap_path.write_bytes(b"still here")
    (spool_dir / "cap.pcapng.spool.json").write_text(json.dumps({
        "session_id": "sess-1", "filename": "cap.pcapng", "pcap_path": str(pcap_path),
    }))

    _run(client._flush_spool())

    complete_frames = [f for f in captured_frames if f["method"] == "pcap_complete"]
    assert len(complete_frames) == 1
    assert not pcap_path.exists()  # shipped successfully -> deleted
    assert not (spool_dir / "cap.pcapng.spool.json").exists()
