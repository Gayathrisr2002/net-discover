"""Regression tests for Finding #17 (--chunk-size ignored under the Rust DPI engine).

``_dissect_with_selected_engine`` passed ``chunk_size`` only to the Python
``OTProtocolDissector`` fallback; the Rust ``marlinspike-dpi`` path (the
recommended default) invoked the binary with no chunk argument, so
``--chunk-size`` was silently a no-op and large captures were processed whole
(OOM risk — the one feature that exists so big engagement captures don't crash
the box).

Fix: ``_run_marlinspike_dpi`` accepts and forwards ``--chunk-size`` to the
binary, and ``_dissect_with_selected_engine`` passes the requested size through.
(In ``auto`` mode a binary that predates the flag falls back to the Python
chunked dissector, which honours it — so memory stays bounded either way.)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse

import marlinspike.engine as engine


class _FakeResult:
    returncode = 0
    stdout = ""
    stderr = ""


def _fake_run_writing_bronze(cmd, **_kw):
    out = cmd[cmd.index("--output") + 1]
    with open(out, "w") as f:
        json.dump({"version": "test", "output": {}}, f)
    return _FakeResult()


def test_run_marlinspike_dpi_forwards_chunk_size(monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _fake_run_writing_bronze(cmd, **kw)

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    monkeypatch.setattr(engine.shutil, "which", lambda b: "/usr/bin/marlinspike-dpi")
    monkeypatch.setattr(engine.os.path, "exists", lambda p: True)

    engine._run_marlinspike_dpi("marlinspike-dpi", "/tmp/x.pcap", "cap", chunk_size=300000)

    assert "--chunk-size" in captured["cmd"], "chunk size not forwarded to marlinspike-dpi"
    assert "300000" in captured["cmd"]


def test_run_marlinspike_dpi_omits_flag_when_zero(monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _fake_run_writing_bronze(cmd, **kw)

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    monkeypatch.setattr(engine.shutil, "which", lambda b: "/usr/bin/marlinspike-dpi")
    monkeypatch.setattr(engine.os.path, "exists", lambda p: True)

    engine._run_marlinspike_dpi("marlinspike-dpi", "/tmp/x.pcap", "cap", chunk_size=0)

    assert "--chunk-size" not in captured["cmd"]


def test_dissect_forwards_requested_chunk_size_to_rust(monkeypatch):
    seen = {}

    def fake_dpi(binary, pcap, capture_id, chunk_size=0):
        seen["chunk_size"] = chunk_size
        return {"version": "test", "output": {}}

    monkeypatch.setattr(engine, "_run_marlinspike_dpi", fake_dpi)
    monkeypatch.setattr(engine, "_build_conversations_from_bronze", lambda o: [])
    monkeypatch.setattr(engine, "_build_port_summary_from_conversations", lambda c: {})
    monkeypatch.setattr(engine, "_build_l2_anomalies_from_bronze", lambda o: [])
    monkeypatch.setattr(engine, "_build_malware_seed_events_from_bronze", lambda o: [])
    monkeypatch.setattr(engine.shutil, "which", lambda b: "/usr/bin/marlinspike-dpi")
    monkeypatch.setattr(engine.os.path, "exists", lambda p: True)

    args = argparse.Namespace(
        dpi_engine="marlinspike-dpi", dpi_binary="marlinspike-dpi",
        chunk_size=300000, collapse_threshold=50,
    )
    engine._dissect_with_selected_engine("/tmp/x.pcap", args, "cap")

    assert seen.get("chunk_size") == 300000, "run_chain's --chunk-size not forwarded to the Rust engine"
