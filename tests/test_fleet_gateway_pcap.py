"""Tests for the fleet gateway's raw-pcap chunk reassembly (server.py's
pcap_chunk/pcap_complete event handlers) — the transport this session's
architecture change introduced to replace agent-side analysis + JSON
report shipping.

Uses the same construct-the-server-object-directly + asyncio.run(...)
pattern already established in marlinspike-capd/tests/test_interface_lock.py
for testing an asyncio server's dispatch methods without a real socket.
"""

from __future__ import annotations

import asyncio
import base64
import os

import pytest

from marlinspike.fleet.gateway import server as gw_server


@pytest.fixture
def server():
    return gw_server.GatewayServer()


@pytest.fixture
def conn():
    return gw_server._AgentConnection(writer=None)


def _event(method: str, params: dict) -> dict:
    return {"type": "event", "method": method, "params": params}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def fake_upload(monkeypatch, tmp_path):
    """Stubs db.begin_pcap_upload to hand out real paths under tmp_path,
    without needing a real Flask app/DB/CaptureSession — this test file is
    about chunk reassembly correctness, not session/ownership validation
    (that's covered separately against the real db.py functions)."""
    calls = {"begin": [], "finish": []}

    def fake_begin(*, session_uuid, filename, agent_uuid):
        calls["begin"].append((session_uuid, filename, agent_uuid))
        final_path = str(tmp_path / filename)
        return final_path + ".partial", final_path

    def fake_finish(*, partial_path, final_path, session_uuid, agent_uuid):
        calls["finish"].append((partial_path, final_path, session_uuid, agent_uuid))
        os.replace(partial_path, final_path)
        return (1, 1, None)

    async def fake_launch_scan(**kwargs):
        calls.setdefault("launch_scan", []).append(kwargs)

    monkeypatch.setattr(gw_server.db, "begin_pcap_upload", fake_begin)
    monkeypatch.setattr(gw_server.db, "finish_pcap_upload", fake_finish)
    monkeypatch.setattr(gw_server.scan, "launch_scan", fake_launch_scan)
    return calls


def _chunk_event(session_id, filename, chunk_index, total_chunks, raw_bytes):
    return _event("pcap_chunk", {
        "session_id": session_id, "filename": filename,
        "chunk_index": chunk_index, "total_chunks": total_chunks,
        "data": base64.b64encode(raw_bytes).decode("ascii"),
    })


def _complete_event(session_id, filename, total_chunks):
    return _event("pcap_complete", {
        "session_id": session_id, "filename": filename, "total_chunks": total_chunks,
    })


def test_chunks_in_order_reassemble_correctly(server, conn, fake_upload, tmp_path):
    raw = os.urandom(gw_server._PCAP_CHUNK_RAW_BYTES * 2 + 100)
    chunks = [
        raw[0:gw_server._PCAP_CHUNK_RAW_BYTES],
        raw[gw_server._PCAP_CHUNK_RAW_BYTES:2 * gw_server._PCAP_CHUNK_RAW_BYTES],
        raw[2 * gw_server._PCAP_CHUNK_RAW_BYTES:],
    ]

    async def run():
        loop = asyncio.get_running_loop()
        for i, c in enumerate(chunks):
            await server._handle_event("agent-1", conn,
                                        _chunk_event("sess-1", "cap.pcapng", i, len(chunks), c), loop)
        await server._handle_event("agent-1", conn,
                                    _complete_event("sess-1", "cap.pcapng", len(chunks)), loop)

    _run(run())
    final_path = tmp_path / "cap.pcapng"
    assert final_path.read_bytes() == raw
    assert len(fake_upload["finish"]) == 1


def test_chunks_out_of_order_reassemble_correctly(server, conn, fake_upload, tmp_path):
    """Positional writes (seek to chunk_index * _PCAP_CHUNK_RAW_BYTES) must
    produce a byte-identical file regardless of arrival order — the whole
    point of not relying on sequential arrival (see _AgentConnection's
    docstring on why _handle_event can't guarantee handler completion
    order matches frame arrival order)."""
    raw = os.urandom(gw_server._PCAP_CHUNK_RAW_BYTES * 3)
    chunks = [raw[i * gw_server._PCAP_CHUNK_RAW_BYTES:(i + 1) * gw_server._PCAP_CHUNK_RAW_BYTES]
              for i in range(3)]

    async def run():
        loop = asyncio.get_running_loop()
        # Reverse order: 2, 0, 1
        for i in (2, 0, 1):
            await server._handle_event("agent-1", conn,
                                        _chunk_event("sess-1", "cap.pcapng", i, 3, chunks[i]), loop)
        await server._handle_event("agent-1", conn,
                                    _complete_event("sess-1", "cap.pcapng", 3), loop)

    _run(run())
    assert (tmp_path / "cap.pcapng").read_bytes() == raw


def test_concurrent_chunk_events_for_new_file_dont_race(server, conn, fake_upload, tmp_path):
    """Regression test for a real bug found via live deployment testing:
    _handle_event dispatches each event as its own task (self._spawn in
    the real reader loop), not a sequential await-one-then-the-next
    pattern. Several pcap_chunk events for a brand-new filename arriving
    back-to-back can each observe "no transfer yet" across the await on
    db.begin_pcap_upload, each independently open a file handle, and
    clobber each other in pcap_transfers. Confirmed for real: a live
    agent shipped 8 chunks, the gateway only ever recorded 3 of them —
    the rest were written to file handles that got overwritten and
    dropped before pcap_complete ever saw them. Every other test in this
    file awaits each event sequentially, which never exercises this race
    at all — this one fires all 8 as concurrent tasks specifically to
    catch it."""
    raw = os.urandom(gw_server._PCAP_CHUNK_RAW_BYTES * 8)
    chunks = [raw[i * gw_server._PCAP_CHUNK_RAW_BYTES:(i + 1) * gw_server._PCAP_CHUNK_RAW_BYTES]
              for i in range(8)]

    async def run():
        loop = asyncio.get_running_loop()
        tasks = [
            asyncio.create_task(server._handle_event(
                "agent-1", conn, _chunk_event("sess-1", "cap.pcapng", i, 8, chunks[i]), loop,
            ))
            for i in range(8)
        ]
        await asyncio.gather(*tasks)
        await server._handle_event("agent-1", conn,
                                    _complete_event("sess-1", "cap.pcapng", 8), loop)

    _run(run())
    assert (tmp_path / "cap.pcapng").read_bytes() == raw
    assert len(fake_upload["finish"]) == 1
    assert len(fake_upload["begin"]) == 1, "must only resolve the upload path once, not once per racing task"


def test_complete_racing_inflight_first_chunk_creation_waits(server, conn, fake_upload, tmp_path, monkeypatch):
    """Regression test for a second real race found via live deployment
    testing (a single-chunk transfer, so the multi-chunk creation race
    above doesn't apply): _reader_loop creates the pcap_complete task only
    after the pcap_chunk frame has been read off the wire, but that says
    nothing about which task's *handler body* runs first once both are
    scheduled. Live symptom: agent logged "shipped pcap ... (1 chunks)",
    gateway logged "sent pcap_complete for unknown transfer ... — dropping"
    — pcap_complete's pop() ran and found nothing while the chunk handler
    was still awaiting db.begin_pcap_upload across a real executor call.
    Widen that window deterministically here by making begin_pcap_upload
    slow, then fire both events as concurrent tasks."""
    import time as _time

    raw = os.urandom(1024)

    def slow_begin(*, session_uuid, filename, agent_uuid):
        _time.sleep(0.05)
        fake_upload["begin"].append((session_uuid, filename, agent_uuid))
        final_path = str(tmp_path / filename)
        return final_path + ".partial", final_path

    monkeypatch.setattr(gw_server.db, "begin_pcap_upload", slow_begin)

    async def run():
        loop = asyncio.get_running_loop()
        chunk_task = asyncio.create_task(server._handle_event(
            "agent-1", conn, _chunk_event("sess-1", "cap.pcapng", 0, 1, raw), loop))
        # Give the chunk task a chance to start and reach its await on
        # begin_pcap_upload before pcap_complete's task is even created —
        # matching real _reader_loop ordering (complete is read/dispatched
        # strictly after chunk) while still landing inside slow_begin's
        # artificially widened window.
        await asyncio.sleep(0)
        complete_task = asyncio.create_task(server._handle_event(
            "agent-1", conn, _complete_event("sess-1", "cap.pcapng", 1), loop))
        await asyncio.gather(chunk_task, complete_task)

    _run(run())
    assert (tmp_path / "cap.pcapng").read_bytes() == raw
    assert len(fake_upload["finish"]) == 1
    assert len(fake_upload["begin"]) == 1


def test_duplicate_chunk_resend_is_idempotent(server, conn, fake_upload, tmp_path):
    raw = os.urandom(gw_server._PCAP_CHUNK_RAW_BYTES)

    async def run():
        loop = asyncio.get_running_loop()
        await server._handle_event("agent-1", conn,
                                    _chunk_event("sess-1", "cap.pcapng", 0, 1, raw), loop)
        # Resend the same chunk (e.g. agent retried after a slow ack)
        await server._handle_event("agent-1", conn,
                                    _chunk_event("sess-1", "cap.pcapng", 0, 1, raw), loop)
        await server._handle_event("agent-1", conn,
                                    _complete_event("sess-1", "cap.pcapng", 1), loop)

    _run(run())
    assert (tmp_path / "cap.pcapng").read_bytes() == raw
    assert len(fake_upload["finish"]) == 1


def test_pcap_complete_with_missing_chunk_is_dropped(server, conn, fake_upload, tmp_path):
    """total_chunks claims 3, only 2 ever arrived — must not finalize, and
    the .partial file must be cleaned up rather than left behind forever."""
    raw = os.urandom(gw_server._PCAP_CHUNK_RAW_BYTES)

    async def run():
        loop = asyncio.get_running_loop()
        await server._handle_event("agent-1", conn,
                                    _chunk_event("sess-1", "cap.pcapng", 0, 3, raw), loop)
        await server._handle_event("agent-1", conn,
                                    _chunk_event("sess-1", "cap.pcapng", 1, 3, raw), loop)
        # chunk 2 never arrives
        await server._handle_event("agent-1", conn,
                                    _complete_event("sess-1", "cap.pcapng", 3), loop)

    _run(run())
    assert len(fake_upload["finish"]) == 0
    assert not (tmp_path / "cap.pcapng").exists()
    assert not (tmp_path / "cap.pcapng.partial").exists()


def test_oversized_total_chunks_rejected(server, conn, fake_upload):
    raw = os.urandom(1024)

    async def run():
        loop = asyncio.get_running_loop()
        await server._handle_event("agent-1", conn, _chunk_event(
            "sess-1", "cap.pcapng", 0, gw_server._MAX_PCAP_CHUNKS + 1, raw,
        ), loop)

    _run(run())
    # Rejected before ever calling begin_pcap_upload for this filename.
    assert conn.pcap_transfers == {}
    assert len(fake_upload["begin"]) == 0


def test_invalid_base64_aborts_transfer(server, conn, fake_upload, tmp_path):
    async def run():
        loop = asyncio.get_running_loop()
        await server._handle_event("agent-1", conn, _event("pcap_chunk", {
            "session_id": "sess-1", "filename": "cap.pcapng",
            "chunk_index": 0, "total_chunks": 1, "data": "not valid base64!!",
        }), loop)

    _run(run())
    assert conn.pcap_transfers == {}
    assert not (tmp_path / "cap.pcapng.partial").exists()


def test_deprecated_report_chunk_warns_once_per_connection(server, conn, fake_upload, caplog):
    """An agent still on the retired report_chunk/report_complete protocol
    must get a diagnostic warning, not silence — but only once per
    connection, not once per event (an old agent sends many report_chunk
    events per report)."""
    async def run():
        loop = asyncio.get_running_loop()
        for _ in range(5):
            await server._handle_event("agent-1", conn, _event("report_chunk", {
                "session_id": "sess-1", "filename": "r.json",
                "chunk_index": 0, "total_chunks": 1, "data": "abc",
            }), loop)
        await server._handle_event("agent-1", conn, _event("report_complete", {
            "session_id": "sess-1", "filename": "r.json", "total_chunks": 1,
        }), loop)

    with caplog.at_level("WARNING"):
        _run(run())

    deprecation_warnings = [r for r in caplog.records if "retired report_chunk" in r.message]
    assert len(deprecation_warnings) == 1, "must warn exactly once per connection, not once per event"
    assert conn.warned_deprecated is True
    # And must never touch the new pcap-upload path at all.
    assert len(fake_upload["begin"]) == 0
    assert len(fake_upload["finish"]) == 0
