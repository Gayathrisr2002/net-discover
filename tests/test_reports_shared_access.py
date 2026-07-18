"""Regression tests for Finding #6 (/api/reports wrong directory + no ownership
check).

``user_reports_dir(project_id)`` built the on-disk path from the *requesting*
user's id (``session['user_id']``), not the project owner's. So a member of a
*shared* project asking for one of its reports looked in
``REPORTS_DIR/<their_own_uid>/<pid>/`` — empty — and got a 404. The sharing
feature was non-functional for reading reports. There was also no explicit
access check on the ``project_id`` query arg (the per-uid path nesting merely
happened to contain it).

Fix: resolve the reports/uploads directory using the project *owner's* uid via
the access-checked ``_get_project_for_user``, and deny (404) when the requester
has no access to that project.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-reports-shared")


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


def _place_report(owner_uid, pid, filename="marlinspike-chain-report.json"):
    from marlinspike import config
    rdir = os.path.join(config.REPORTS_DIR, str(owner_uid), str(pid))
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, filename), "w") as fh:
        json.dump({"topology": {"nodes": [], "edges": []}}, fh)
    return filename


def test_shared_member_can_download_owner_report(app, db):
    owner_uid = _make_user(db, "rep_owner")
    _make_user(db, "rep_member")
    pid = _make_project(db, owner_uid, "OwnerProj")
    member_uid = _make_user(db, "rep_member")
    _add_member(db, pid, member_uid, "viewer")

    fn = _place_report(owner_uid, pid)

    # The shared member must be able to read the owner's report.
    rv = _client(app, "rep_member").get(f"/api/reports/{fn}?project_id={pid}")
    assert rv.status_code == 200, "shared member could not read a report in a project shared with them"


def test_non_member_denied_owner_report(app, db):
    owner_uid = _make_user(db, "rep_owner2")
    _make_user(db, "rep_stranger")
    pid = _make_project(db, owner_uid, "OwnerProj2")
    fn = _place_report(owner_uid, pid)

    rv = _client(app, "rep_stranger").get(f"/api/reports/{fn}?project_id={pid}")
    assert rv.status_code == 404, "a non-member must not read another project's report"


def test_owner_can_still_download_own_report(app, db):
    owner_uid = _make_user(db, "rep_owner3")
    pid = _make_project(db, owner_uid, "OwnerProj3")
    fn = _place_report(owner_uid, pid)

    rv = _client(app, "rep_owner3").get(f"/api/reports/{fn}?project_id={pid}")
    assert rv.status_code == 200
