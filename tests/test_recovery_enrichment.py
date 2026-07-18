"""Regression tests for Finding #9 (recovery path skips MITRE/ARP/APT/CISA
enrichment).

When Flask restarts mid-scan, ``recovery.reap_orphan_runs`` reconciles the
orphaned run. If the engine finished its report before/while Flask was down,
``_ingest_completed_report`` pulls node/edge counts and marks the run
``completed`` — but, unlike the normal ``app._finalize_run`` path, it never runs
the enrichment plugins. The recovered report is therefore silently missing all
ATT&CK / ARP / APT / CISA context, with no signal that it is incomplete. Since
Flask restarts (deploys, OOM, host reboot) are routine ops events, this is a
silent engagement-integrity loss on the recovery path.

The fix runs standalone enrichment (``enrich.run_all``, no Flask/DB dependency)
when recovery ingests a completed report — producing the same sidecar artifacts
a normal finalize would — and flags the run degraded if enrichment fails
outright.
"""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-recovery-enrich")

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
    u = User(username="recov_enrich", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u


def _completed_report(tmp_path):
    p = tmp_path / "good.json"
    p.write_text(json.dumps({
        "topology": {"nodes": [{"id": "n1"}, {"id": "n2"}], "edges": [{"src": "n1", "dst": "n2"}]}
    }))
    return str(p)


def test_reap_completed_report_runs_enrichment(app, app_ctx, user, tmp_path, monkeypatch):
    """A recovered, completed report must have enrichment run over it — the same
    plugins a normal finalize would produce, not silently skipped."""
    report_path = _completed_report(tmp_path)

    calls = []
    monkeypatch.setattr("marlinspike.enrich.run_all", lambda rp: calls.append(rp) or {})

    run_store.record_start(
        "rec-enrich",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=report_path,
        engine_pid=2_000_050,  # dead
        engine_argv=[sys.executable, "-m", "marlinspike"],
    )

    counters = recovery.reap_orphan_runs(app)

    assert counters["reaped_completed"] == 1
    assert calls == [report_path], "recovery ingested a completed report without running enrichment"

    rec = ScanHistory.query.filter_by(run_id="rec-enrich").first()
    assert rec.status == "completed"
    assert rec.node_count == 2
    assert rec.edge_count == 1


def test_reap_completed_report_enrichment_failure_marks_degraded(app, app_ctx, user, tmp_path, monkeypatch):
    """If enrichment cannot run at all during recovery, the run must not look
    like a clean, fully-enriched completion."""
    report_path = _completed_report(tmp_path)

    def boom(_rp):
        raise RuntimeError("enrichment toolchain unavailable")

    monkeypatch.setattr("marlinspike.enrich.run_all", boom)

    run_store.record_start(
        "rec-enrich-fail",
        user_id=user.id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=report_path,
        engine_pid=2_000_051,  # dead
        engine_argv=[sys.executable, "-m", "marlinspike"],
    )

    recovery.reap_orphan_runs(app)

    rec = ScanHistory.query.filter_by(run_id="rec-enrich-fail").first()
    # Report is still ingested (data isn't lost) but the degraded reason is durable.
    assert rec.status == "completed"
    assert rec.error_tail and "enrichment" in rec.error_tail.lower()
