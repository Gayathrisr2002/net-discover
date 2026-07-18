"""Regression tests for Finding #22 (reaper timeout check bypasses PID-liveness
and report-completeness checks).

The reaper marked any run past its ``timeout_at`` deadline as ``failed``
(reaped_abandoned) *before* checking whether the engine was still alive or had
already written a complete report. So a slow-but-healthy scan that overran the
deadline, or one that finished right around the deadline, was discarded and the
user shown a false failure — eroding trust ("it said this failed but the data
was fine").

Fix: the deadline verdict is the last resort. A run past its deadline is only
abandoned if the engine is dead AND no complete report exists; a live engine is
re-attached, and a complete report is ingested as completed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-recovery-timeout")

import pytest

from marlinspike import recovery, run_store
from marlinspike.app import create_app
from marlinspike.models import ScanHistory, User, db


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.drop_all()
        db.create_all()
    yield application


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def user(app_ctx):
    u = User(username="recov_to", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u


def _past_deadline(run_id):
    rec = ScanHistory.query.filter_by(run_id=run_id).first()
    rec.timeout_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db.session.commit()


def test_past_deadline_but_report_complete_is_completed_not_failed(app, app_ctx, user, tmp_path, monkeypatch):
    report = tmp_path / "good.json"
    report.write_text(json.dumps({"topology": {"nodes": [{"id": "n1"}], "edges": []}}))
    monkeypatch.setattr("marlinspike.enrich.run_all", lambda rp: {})

    run_store.record_start(
        "to-complete", user_id=user.id, project_id=None, command="chain",
        scan_profile="full", pcap_source=None, pcap_hash=None,
        pcap_path=str(tmp_path / "x.pcap"), report_path=str(report),
        engine_pid=2_000_090, engine_argv=[sys.executable, "-m", "marlinspike"],
    )
    _past_deadline("to-complete")

    counters = recovery.reap_orphan_runs(app)

    assert counters["reaped_completed"] == 1, "a completed report past the deadline was wrongly failed"
    assert counters["reaped_abandoned"] == 0
    rec = ScanHistory.query.filter_by(run_id="to-complete").first()
    assert rec.status == "completed"


def test_past_deadline_but_engine_alive_is_reattached_not_failed(app, app_ctx, user, tmp_path, monkeypatch):
    distinctive = "marlinspike-timeout-liveness-token"
    code = "import time, sys; print(sys.argv[1]); time.sleep(60)"
    proc = subprocess.Popen([sys.executable, "-c", code, distinctive])
    try:
        run_store.record_start(
            "to-alive", user_id=user.id, project_id=None, command="chain",
            scan_profile="full", pcap_source=None, pcap_hash=None,
            pcap_path=str(tmp_path / "x.pcap"), report_path=str(tmp_path / "r.json"),
            engine_pid=proc.pid, engine_argv=[sys.executable, "-c", code, distinctive],
        )
        _past_deadline("to-alive")

        spawned = []
        monkeypatch.setattr(recovery, "_spawn_watcher",
                            lambda app_, run_id, pid, rp: spawned.append(run_id))

        counters = recovery.reap_orphan_runs(app)

        assert counters["reattached"] == 1, "a live, healthy engine past deadline was wrongly failed"
        assert counters["reaped_abandoned"] == 0
        rec = ScanHistory.query.filter_by(run_id="to-alive").first()
        assert rec.status == "running"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_past_deadline_dead_no_report_still_abandoned(app, app_ctx, user, tmp_path):
    """Guardrail: the genuine abandonment case must still be reaped as abandoned."""
    run_store.record_start(
        "to-abandon", user_id=user.id, project_id=None, command="chain",
        scan_profile="full", pcap_source=None, pcap_hash=None,
        pcap_path=str(tmp_path / "x.pcap"), report_path=str(tmp_path / "missing.json"),
        engine_pid=2_000_091, engine_argv=[sys.executable, "-m", "marlinspike"],
    )
    _past_deadline("to-abandon")

    counters = recovery.reap_orphan_runs(app)

    assert counters["reaped_abandoned"] == 1
    rec = ScanHistory.query.filter_by(run_id="to-abandon").first()
    assert rec.status == "failed"
    assert "abandoned" in (rec.error_tail or "")
