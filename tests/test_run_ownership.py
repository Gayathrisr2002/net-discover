"""Regression tests for Finding #3 (IDOR on /api/runs/*): a run started by
one user must not be visible to, or controllable by, another non-admin user.

Covers all six routes reviewed for the finding: GET /api/runs (list),
GET /api/runs/<id>/status (both the in-memory and durable-fallback paths),
GET /api/runs/<id>/output, POST /api/runs/<id>/stop,
GET /api/runs/<id>/topology, and GET /api/runs/<id>/live.
"""

import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-run-ownership")


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from marlinspike.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture(scope="module")
def db(app):
    from marlinspike.models import db as _db
    with app.app_context():
        _db.create_all()
        yield _db


_ORIGIN = "http://localhost"
_H = {"Origin": _ORIGIN}


def _make_user(db, username, password="pw", role="user") -> int:
    from marlinspike.auth import create_user
    from marlinspike.models import User
    try:
        user = create_user(username, password, role=role)
        db.session.commit()
    except Exception:
        db.session.rollback()
        user = User.query.filter_by(username=username).first()
    return user.id


def _client(app, username):
    """Return a test client with an injected session for ``username``."""
    from marlinspike.models import User
    c = app.test_client()
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        ident = (u.username, u.id, u.role, u.session_version or 1)
    with c.session_transaction() as sess:
        sess["user"], sess["user_id"], sess["role"], sess["session_version"] = ident
    return c


def _register_run(user_id, **overrides):
    """Insert a minimal run_state directly into the in-memory registry,
    mirroring the shape built at scan-launch time (app.py ~4150), without
    actually spawning an engine subprocess."""
    from marlinspike.app import _run_registry, _runs_lock

    run_id = overrides.pop("run_id", None) or uuid.uuid4().hex
    run_state = {
        "process": None,
        "output": ["[*] started"],
        "status": "running",
        "stage": 2,
        "stage_name": "Dissect",
        "stages": [],
        "started_at": time.time(),
        "finished_at": None,
        "return_code": None,
        "artifacts_produced": {},
        "project_id": None,
        "user_id": user_id,
        "stop_requested": False,
        "pcap_path": "/tmp/does-not-matter.pcap",
        "pcap_size": 0,
        "command": "chain",
        "scan_profile": "full",
        "report_path": "/tmp/does-not-exist-report.json",
        "report_filename": "does-not-exist-report.json",
    }
    run_state.update(overrides)
    with _runs_lock:
        _run_registry[run_id] = run_state
    return run_id


@pytest.fixture
def cleanup_runs():
    """Runs registered via _register_run are removed after each test so
    _run_registry doesn't leak state (and stale process=None entries)
    across tests in this module."""
    created = []
    yield created
    from marlinspike.app import _run_registry, _runs_lock
    with _runs_lock:
        for run_id in created:
            _run_registry.pop(run_id, None)


# ── GET /api/runs (list) ──────────────────────────────────────────────────────

def test_runs_list_excludes_other_users_runs(app, db, cleanup_runs):
    owner_id = _make_user(db, "runs_list_owner")
    _make_user(db, "runs_list_stranger")
    admin_id = _make_user(db, "runs_list_admin", role="admin")

    run_id = _register_run(owner_id)
    cleanup_runs.append(run_id)

    owner_ids = {e["run_id"] for e in _client(app, "runs_list_owner").get("/api/runs").get_json()["active"]}
    assert run_id in owner_ids

    stranger_ids = {e["run_id"] for e in _client(app, "runs_list_stranger").get("/api/runs").get_json()["active"]}
    assert run_id not in stranger_ids

    admin_ids = {e["run_id"] for e in _client(app, "runs_list_admin").get("/api/runs").get_json()["active"]}
    assert run_id in admin_ids


# ── GET /api/runs/<id>/status (in-memory path) ────────────────────────────────

def test_run_status_denied_for_non_owner(app, db, cleanup_runs):
    owner_id = _make_user(db, "runs_status_owner")
    _make_user(db, "runs_status_stranger")
    admin_id = _make_user(db, "runs_status_admin", role="admin")

    run_id = _register_run(owner_id)
    cleanup_runs.append(run_id)

    assert _client(app, "runs_status_owner").get(f"/api/runs/{run_id}/status").status_code == 200
    assert _client(app, "runs_status_stranger").get(f"/api/runs/{run_id}/status").status_code == 404
    assert _client(app, "runs_status_admin").get(f"/api/runs/{run_id}/status").status_code == 200


# ── GET /api/runs/<id>/output ──────────────────────────────────────────────────

def test_run_output_denied_for_non_owner(app, db, cleanup_runs):
    owner_id = _make_user(db, "runs_output_owner")
    _make_user(db, "runs_output_stranger")

    run_id = _register_run(owner_id)
    cleanup_runs.append(run_id)

    rv_owner = _client(app, "runs_output_owner").get(f"/api/runs/{run_id}/output")
    assert rv_owner.status_code == 200
    assert rv_owner.get_json()["lines"]  # owner actually gets the log lines

    assert _client(app, "runs_output_stranger").get(f"/api/runs/{run_id}/output").status_code == 404


# ── POST /api/runs/<id>/stop ───────────────────────────────────────────────────

def test_run_stop_denied_for_non_owner(app, db, cleanup_runs):
    owner_id = _make_user(db, "runs_stop_owner")
    stranger_id = _make_user(db, "runs_stop_stranger")

    run_id = _register_run(owner_id)
    cleanup_runs.append(run_id)

    rv = _client(app, "runs_stop_stranger").post(f"/api/runs/{run_id}/stop", headers=_H)
    assert rv.status_code == 404

    from marlinspike.app import _run_registry
    assert _run_registry[run_id]["stop_requested"] is False  # stranger's request had no effect

    rv = _client(app, "runs_stop_owner").post(f"/api/runs/{run_id}/stop", headers=_H)
    assert rv.status_code == 200
    assert _run_registry[run_id]["stop_requested"] is True


# ── GET /api/runs/<id>/topology ────────────────────────────────────────────────

def test_run_topology_denied_for_non_owner(app, db, cleanup_runs):
    owner_id = _make_user(db, "runs_topo_owner")
    _make_user(db, "runs_topo_stranger")

    run_id = _register_run(owner_id)
    cleanup_runs.append(run_id)

    assert _client(app, "runs_topo_owner").get(f"/api/runs/{run_id}/topology").status_code == 200
    assert _client(app, "runs_topo_stranger").get(f"/api/runs/{run_id}/topology").status_code == 404


# ── GET /api/runs/<id>/live ────────────────────────────────────────────────────

def test_run_live_denied_for_non_owner(app, db, cleanup_runs):
    owner_id = _make_user(db, "runs_live_owner")
    _make_user(db, "runs_live_stranger")

    run_id = _register_run(owner_id)
    cleanup_runs.append(run_id)

    assert _client(app, "runs_live_owner").get(f"/api/runs/{run_id}/live").status_code == 200
    assert _client(app, "runs_live_stranger").get(f"/api/runs/{run_id}/live").status_code == 404


# ── Durable (run_store) fallback path — status + live after "restart" ────────

@pytest.fixture
def durable_run(app, db):
    """Simulate a run that survived only in ScanHistory (as after a Flask
    restart, per docs/run-store-and-recovery.md) — nothing in _run_registry."""
    from marlinspike import run_store

    run_id = uuid.uuid4().hex

    def _make(owner_id):
        with app.app_context():
            run_store.record_start(
                run_id,
                user_id=owner_id,
                project_id=None,
                command="chain",
                scan_profile="full",
                pcap_source=None,
                pcap_hash=None,
                pcap_path="/tmp/does-not-matter.pcap",
                report_path="/tmp/does-not-exist-report.json",
                engine_pid=None,
                engine_argv=None,
            )
        return run_id

    return _make


def test_run_status_durable_fallback_denied_for_non_owner(app, db, durable_run):
    owner_id = _make_user(db, "runs_durable_owner")
    _make_user(db, "runs_durable_stranger")
    run_id = durable_run(owner_id)

    assert _client(app, "runs_durable_owner").get(f"/api/runs/{run_id}/status").status_code == 200
    assert _client(app, "runs_durable_stranger").get(f"/api/runs/{run_id}/status").status_code == 404


def test_run_live_durable_fallback_denied_for_non_owner(app, db, durable_run):
    owner_id = _make_user(db, "runs_durable_live_owner")
    _make_user(db, "runs_durable_live_stranger")
    run_id = durable_run(owner_id)

    assert _client(app, "runs_durable_live_owner").get(f"/api/runs/{run_id}/live").status_code == 200
    assert _client(app, "runs_durable_live_stranger").get(f"/api/runs/{run_id}/live").status_code == 404
