"""Regression test (recovery/concurrency plumbing #54): stale engine_pid.

``run_store.record_finish`` (the recovery path) clears ``engine_pid`` when a run
goes terminal, but the normal live-finalize path (``_finalize_scan_history``)
never did — so every normally-completed scan left its subprocess PID populated
in ``scan_history`` forever. A stale PID on a terminal row is a landmine: any
future "kill stuck scan by PID" tooling, or PID-reuse-sensitive logic, could act
on a PID that now belongs to an unrelated process.

Fix: clear ``engine_pid`` in ``_finalize_scan_history`` when the run is terminal.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-finalize-pid")

import pytest


@pytest.fixture
def app():
    from marlinspike.app import create_app
    from marlinspike.models import db
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.drop_all()
        db.create_all()
    return application


def _seed_running(app, run_id, pid):
    from marlinspike.models import ScanHistory, User, db
    with app.app_context():
        if User.query.get(1) is None:
            db.session.add(User(id=1, username="pid_user", password_hash="x", role="admin"))
        db.session.add(ScanHistory(
            run_id=run_id, user_id=1, command="chain", scan_profile="full",
            status="running", engine_pid=pid, report_path="",
        ))
        db.session.commit()


def _run_state(status):
    return {"status": status, "output": ["done"], "stages": []}


def test_completed_run_clears_engine_pid(app):
    import marlinspike.app as appmod
    from marlinspike.models import ScanHistory

    _seed_running(app, "pid-complete", 987654)
    appmod._finalize_scan_history(app, "pid-complete", _run_state("completed"), "")

    with app.app_context():
        rec = ScanHistory.query.filter_by(run_id="pid-complete").first()
        assert rec.status == "completed"
        assert rec.engine_pid is None, "engine_pid left stale on a terminal run"


def test_failed_run_clears_engine_pid(app):
    import marlinspike.app as appmod
    from marlinspike.models import ScanHistory

    _seed_running(app, "pid-failed", 123456)
    appmod._finalize_scan_history(app, "pid-failed", _run_state("failed"), "")

    with app.app_context():
        rec = ScanHistory.query.filter_by(run_id="pid-failed").first()
        assert rec.engine_pid is None
