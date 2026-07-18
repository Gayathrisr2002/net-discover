"""Regression test (project-sharing cluster): orphaned files on project delete.

``api_projects_delete`` built the on-disk upload/report directories from
``session['user_id']`` — the *deleter* — but files are stored under the project
*owner's* uid. A non-creator member with the ``owner`` role can delete a project;
when they do, the rmtree targets the deleter's (empty) directory and the real
files under the creator's uid are orphaned on disk forever.

Fix: build the paths from ``proj.user_id`` (the owner), matching where files live.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-proj-delete")

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


def test_delete_by_owner_role_member_removes_owner_files(app, db):
    from marlinspike import config

    creator = _make_user(db, "del_creator")
    _make_user(db, "del_admin_member")
    member = _make_user(db, "del_admin_member")
    pid = _make_project(db, creator, "ToDelete")
    _add_member(db, pid, member, "owner")  # non-creator member with owner role

    # Files live under the CREATOR's uid.
    up_dir = os.path.join(config.UPLOADS_DIR, str(creator), str(pid))
    rp_dir = os.path.join(config.REPORTS_DIR, str(creator), str(pid))
    os.makedirs(up_dir, exist_ok=True)
    os.makedirs(rp_dir, exist_ok=True)
    with open(os.path.join(up_dir, "cap.pcap"), "w") as fh:
        fh.write("x")
    with open(os.path.join(rp_dir, "report.json"), "w") as fh:
        fh.write("{}")

    # The member (owner role, but not the creator) deletes the project.
    rv = _client(app, "del_admin_member").delete(f"/api/projects/{pid}?confirm=true", headers=_H)
    assert rv.status_code == 200

    assert not os.path.isdir(up_dir), "upload files orphaned on disk after project delete"
    assert not os.path.isdir(rp_dir), "report files orphaned on disk after project delete"
