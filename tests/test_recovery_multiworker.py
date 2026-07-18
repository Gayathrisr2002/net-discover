"""Regression tests for Finding #24 (reap_orphan_runs ignores RUN_STORE mode →
duplicate finalization in multi-worker deployments).

Under the production-recommended gunicorn ``-w N`` deployment, ``create_app()``
runs once per worker at boot, so ``reap_orphan_runs`` executes N times
concurrently. Each worker calls ``get_active_for_recovery()`` (which returns
*every* row still marked ``running``) and independently reconciles each one:
N redundant watcher threads per live orphan, and N ``record_finish`` calls per
dead orphan — i.e. duplicate finalization on every routine multi-worker restart.

The fix coordinates through the durable run store: each run is claimed by
exactly one worker via a single atomic conditional UPDATE
(``status='running' AND recovery_state IS NULL`` → ``'claimed'``). The worker
whose UPDATE matched owns the reconciliation; the others skip that run.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-recovery-mw")

import pytest

from marlinspike import recovery, run_store
from marlinspike.app import create_app
from marlinspike.models import ScanHistory, User, db


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
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
    u = User(username="recov_mw", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u


def _running_row(user_id, tmp_path, run_id="mw-run"):
    run_store.record_start(
        run_id,
        user_id=user_id,
        project_id=None,
        command="chain",
        scan_profile="full",
        pcap_source="x.pcap",
        pcap_hash="abc",
        pcap_path=str(tmp_path / "x.pcap"),
        report_path=str(tmp_path / "missing.json"),
        engine_pid=2_000_009,  # almost certainly dead
        engine_argv=[sys.executable, "-m", "marlinspike"],
    )


# ── The atomic claim primitive ────────────────────────────────────────────────

def test_claim_for_recovery_grants_exactly_one_owner(app, app_ctx, user, tmp_path):
    """Two workers racing to claim the same running row: first wins, second loses."""
    _running_row(user.id, tmp_path)

    first = run_store.claim_for_recovery("mw-run")
    second = run_store.claim_for_recovery("mw-run")

    assert first is True, "first worker must win the claim"
    assert second is False, "second worker must not also claim the same run"

    rec = ScanHistory.query.filter_by(run_id="mw-run").first()
    assert rec.recovery_state == "claimed"
    assert rec.status == "running"  # claim doesn't finalize, just reserves


def test_claim_for_recovery_missing_run_returns_false(app, app_ctx, user):
    assert run_store.claim_for_recovery("does-not-exist") is False


# ── The reaper honours another worker's claim ─────────────────────────────────

def test_reap_skips_run_already_claimed_by_another_worker(app, app_ctx, user, tmp_path):
    """A run another worker has already claimed must not be re-finalized here."""
    _running_row(user.id, tmp_path)

    # Simulate a peer worker having already claimed this run for recovery.
    rec = ScanHistory.query.filter_by(run_id="mw-run").first()
    rec.recovery_state = "claimed"
    db.session.commit()

    counters = recovery.reap_orphan_runs(app)

    # This worker must NOT finalize a run it didn't win — no reaped_* increment.
    assert counters["reaped_failed"] == 0
    assert counters["reaped_completed"] == 0
    assert counters["reaped_abandoned"] == 0
    assert counters["reattached"] == 0
    assert counters.get("skipped_claimed", 0) == 1

    rec = ScanHistory.query.filter_by(run_id="mw-run").first()
    assert rec.status == "running", "another worker owns this run; it must be left alone"


def test_reap_double_boot_finalizes_once(app, app_ctx, user, tmp_path):
    """Two sequential reaper passes (two worker boots) reap the dead run only once."""
    _running_row(user.id, tmp_path)

    first = recovery.reap_orphan_runs(app)
    second = recovery.reap_orphan_runs(app)

    # First boot reaps it (dead pid, no report → failed); second sees nothing
    # left running to reconcile.
    assert first["reaped_failed"] == 1
    assert second["reaped_failed"] == 0
    assert second["checked"] == 0
