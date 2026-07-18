"""Regression test for Finding #5 (no rate limiting on expensive project endpoints).

The cross-report aggregate, project-wide export (OCSF/STIX/Sigma/Navigator) and
IOC-scan endpoints each read and process every report in a project, yet carried
no rate limit (``default_limits=[]``). One noisy low-privilege user could hammer
them and starve the shared worker pool for every other concurrent engagement.

Fix: apply ``@limiter.limit`` to those endpoints. This test drives the
representative ``/api/projects/<pid>/aggregate`` endpoint past its limit and
asserts the limiter engages (HTTP 429).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-ratelimit")


@pytest.fixture
def app():
    # Function-scoped so the in-memory rate-limit counters don't leak across tests.
    from marlinspike.app import create_app
    from marlinspike.models import db
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.create_all()
    return application


def _make_user_and_project(app):
    from marlinspike.auth import create_user
    from marlinspike.models import Project, User, db
    with app.app_context():
        try:
            u = create_user("rl_user", "pw")
            db.session.commit()
        except Exception:
            db.session.rollback()
            u = User.query.filter_by(username="rl_user").first()
        proj = Project(user_id=u.id, name="RL Project")
        db.session.add(proj)
        db.session.commit()
        return u.username, u.id, u.role, (u.session_version or 1), proj.id


def test_aggregate_endpoint_is_rate_limited(app):
    username, uid, role, sver, pid = _make_user_and_project(app)
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user"], sess["user_id"], sess["role"], sess["session_version"] = username, uid, role, sver

    statuses = []
    for _ in range(40):
        statuses.append(client.get(f"/api/projects/{pid}/aggregate").status_code)

    assert 429 in statuses, (
        "the expensive aggregate endpoint was never rate-limited over 40 rapid requests"
    )
