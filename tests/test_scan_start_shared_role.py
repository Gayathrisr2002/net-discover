"""Regression tests for Finding #7 (/api/scans/start ignores shared-member role).

The scan-start route resolved the target project with
``Project.query.filter_by(id=project_id, user_id=session['user_id'])`` — an
owner-only match. A shared *editor*, who is entitled to run scans in a project
shared with them, was therefore rejected (project "not found"), and the
membership role model was ignored entirely.

Fix: resolve the project via the access-checked ``_get_project_for_user`` with
``min_role='editor'`` — editors and owners may scan; viewers (read-only) may not.

The tests submit no ``pcap_file``, so the request returns at the "PCAP required"
check *after* project authorization without ever spawning an engine subprocess.
An authorized-but-pcap-less request yields 400; an unauthorized one yields 404 —
which cleanly distinguishes the authorization outcome.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-scan-role")

_H = {"Origin": "http://localhost"}


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


def _make_user(db, username):
    from marlinspike.auth import create_user
    from marlinspike.models import User
    try:
        u = create_user(username, "pw")
        db.session.commit()
    except Exception:
        db.session.rollback()
        u = User.query.filter_by(username=username).first()
    return u.id


def _make_project(db, user_id, name):
    from marlinspike.models import Project
    proj = Project(user_id=user_id, name=name)
    db.session.add(proj)
    db.session.commit()
    return proj.id


def _add_member(db, project_id, user_id, role):
    from marlinspike.models import ProjectMember
    db.session.add(ProjectMember(project_id=project_id, user_id=user_id, role=role))
    db.session.commit()


def _client(app, username):
    from marlinspike.models import User
    c = app.test_client()
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        ident = (u.username, u.id, u.role, u.session_version or 1)
    with c.session_transaction() as sess:
        sess["user"], sess["user_id"], sess["role"], sess["session_version"] = ident
    return c


def _start(client, pid):
    return client.post("/api/scans/start", json={"project_id": pid}, headers=_H)


def test_shared_editor_can_target_shared_project(app, db):
    owner = _make_user(db, "scan_owner")
    _make_user(db, "scan_editor")
    editor = _make_user(db, "scan_editor")
    pid = _make_project(db, owner, "EditorShared")
    _add_member(db, pid, editor, "editor")

    rv = _start(_client(app, "scan_editor"), pid)
    # Authorized → passes project resolution, fails later on missing PCAP (400),
    # NOT rejected as project-not-found (404).
    assert rv.status_code != 404, "shared editor was wrongly denied access to the project"
    assert rv.status_code == 400


def test_shared_viewer_cannot_target_shared_project(app, db):
    owner = _make_user(db, "scan_owner2")
    _make_user(db, "scan_viewer")
    viewer = _make_user(db, "scan_viewer")
    pid = _make_project(db, owner, "ViewerShared")
    _add_member(db, pid, viewer, "viewer")

    rv = _start(_client(app, "scan_viewer"), pid)
    assert rv.status_code == 404, "read-only viewer must not be able to start a scan"


def test_owner_can_target_own_project(app, db):
    owner = _make_user(db, "scan_owner3")
    pid = _make_project(db, owner, "OwnProj")
    rv = _start(_client(app, "scan_owner3"), pid)
    assert rv.status_code == 400  # authorized, just no PCAP


def test_non_member_denied(app, db):
    owner = _make_user(db, "scan_owner4")
    _make_user(db, "scan_stranger")
    pid = _make_project(db, owner, "PrivateProj")
    rv = _start(_client(app, "scan_stranger"), pid)
    assert rv.status_code == 404
