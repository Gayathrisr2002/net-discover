"""Regression tests for Finding #25 (reaper races the finalize pipeline
mid-enrichment, dropping enrichment silently).

``app._finalize_run`` runs the enrichment plugins *in the Flask worker* after
the engine subprocess has already exited, then marks the run completed. During
that seconds-to-tens-of-seconds window the ScanHistory row is still ``running``
with a dead ``engine_pid`` and a complete report on disk — indistinguishable, to
a boot-time reaper, from a genuinely orphaned run. So a concurrently-booting
worker's reaper could reconcile the run out from under the live finalize (and,
pre-#9, mark it completed with no enrichment).

The fix has the live finalize claim the run as ``recovery_state='finalizing'``
before enrichment. The reaper then:
  * skips a *fresh* finalizing run (a live worker owns it), and
  * reclaims a *stale* finalizing run (past its deadline → the finalizing worker
    crashed) and reconciles it — which, per #9, re-runs enrichment.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-finalize-race")

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
    u = User(username="recov_race", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u


def _report(tmp_path):
    p = tmp_path / "good.json"
    p.write_text(json.dumps({"topology": {"nodes": [{"id": "n1"}], "edges": []}}))
    return str(p)


def _seed(user_id, tmp_path, run_id, report_path):
    run_store.record_start(
        run_id,
        user_id=user_id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=report_path,
        engine_pid=2_000_070,  # dead: engine already exited before finalize
        engine_argv=[sys.executable, "-m", "marlinspike"],
    )


# ── mark_finalizing primitive ─────────────────────────────────────────────────

def test_mark_finalizing_sets_recovery_state(app, app_ctx, user, tmp_path):
    _seed(user.id, tmp_path, "race-mark", _report(tmp_path))
    run_store.mark_finalizing("race-mark")
    rec = ScanHistory.query.filter_by(run_id="race-mark").first()
    assert rec.recovery_state == "finalizing"
    assert rec.status == "running"


# ── reaper defers to a live finalize ──────────────────────────────────────────

def test_reaper_skips_fresh_finalizing_run(app, app_ctx, user, tmp_path, monkeypatch):
    """A live worker is finalizing (fresh, not past deadline) → reaper leaves it alone."""
    report_path = _report(tmp_path)
    _seed(user.id, tmp_path, "race-fresh", report_path)

    # Live finalize marked it finalizing; deadline is still in the future.
    rec = ScanHistory.query.filter_by(run_id="race-fresh").first()
    rec.recovery_state = "finalizing"
    rec.timeout_at = datetime.now(timezone.utc) + timedelta(hours=1)
    db.session.commit()

    enrich_calls = []
    monkeypatch.setattr("marlinspike.enrich.run_all", lambda rp: enrich_calls.append(rp) or {})

    counters = recovery.reap_orphan_runs(app)

    assert counters["skipped_claimed"] == 1
    assert counters["reaped_completed"] == 0
    assert enrich_calls == [], "reaper must not enrich a run a live worker is finalizing"
    rec = ScanHistory.query.filter_by(run_id="race-fresh").first()
    assert rec.status == "running", "live finalize must be left to finish"


# ── reaper reclaims a crashed finalize ────────────────────────────────────────

def test_reaper_reclaims_stale_finalizing_run_and_enriches(app, app_ctx, user, tmp_path, monkeypatch):
    """The finalizing worker crashed (run past deadline) → reaper reclaims and
    reconciles it, re-running enrichment (per #9) rather than losing it."""
    report_path = _report(tmp_path)
    _seed(user.id, tmp_path, "race-stale", report_path)

    rec = ScanHistory.query.filter_by(run_id="race-stale").first()
    rec.recovery_state = "finalizing"
    rec.timeout_at = datetime.now(timezone.utc) - timedelta(hours=1)  # crashed long ago
    db.session.commit()

    enrich_calls = []
    monkeypatch.setattr("marlinspike.enrich.run_all", lambda rp: enrich_calls.append(rp) or {})

    counters = recovery.reap_orphan_runs(app)

    assert counters["reaped_completed"] == 1, "a crashed mid-finalize with a complete report must complete"
    assert enrich_calls == [report_path], "reclaimed run must have enrichment re-run"
    rec = ScanHistory.query.filter_by(run_id="race-stale").first()
    assert rec.status == "completed"
