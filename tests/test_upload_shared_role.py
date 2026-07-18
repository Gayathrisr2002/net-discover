"""Regression test (project-sharing cluster): the generic /api/upload path
resolved the target project owner-only, so a shared editor's upload to a shared
project was rejected as "project not found".

The project-scoped route ``/api/projects/<pid>/upload`` already gates via
``_get_project_for_user(pid, "editor")``; the generic ``/api/upload`` handler
(``_handle_upload`` with ``project_id=None``) still used an owner-only
``Project.query.filter_by(id=pid, user_id=self)``. Fix: honour the shared-member
role model there too (editors/owners may upload; viewers may not).

The test sends a tiny non-PCAP file: an authorized request gets past project
resolution and fails later on the magic-byte check (400 "Not a valid PCAP");
an unauthorized one is rejected at resolution (404). That cleanly separates the
authorization outcome.
"""

import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-upload-role")

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


def _upload(client, pid):
    data = {
        "file": (io.BytesIO(b"not a pcap file"), "sample.pcap"),
        "project_id": str(pid),
    }
    return client.post("/api/upload", data=data, headers=_H, content_type="multipart/form-data")


def test_shared_editor_upload_reaches_project(app, db):
    owner = _make_user(db, "upl_owner")
    _make_user(db, "upl_editor")
    editor = _make_user(db, "upl_editor")
    pid = _make_project(db, owner, "UplShared")
    _add_member(db, pid, editor, "editor")

    rv = _upload(_client(app, "upl_editor"), pid)
    assert rv.status_code != 404, "shared editor was wrongly denied upload to the shared project"


def test_non_member_upload_denied(app, db):
    owner = _make_user(db, "upl_owner2")
    _make_user(db, "upl_stranger")
    pid = _make_project(db, owner, "UplPrivate")

    rv = _upload(_client(app, "upl_stranger"), pid)
    assert rv.status_code == 404, "non-member must not upload into another's project"
