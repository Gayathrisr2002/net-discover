"""Regression tests for Finding #2 (path traversal in the preset sanitizer):
``_safe_preset_name`` ran ``os.path.basename(name)`` and then validated the
result against ``^[a-zA-Z0-9._-]+$`` — but ``os.path.basename("..")`` is ``".."``,
and ``.`` is an allowed character, so ``".."`` (and ``"."``) passed the filter.

Because every preset route builds a path as ``os.path.join(config.PRESETS_DIR, name)``,
a name of ``".."`` resolves to ``PRESETS_DIR/..`` == ``DATA_DIR``. The
delete-category route then does ``shutil.rmtree(cat_dir)`` — i.e. it would wipe
the entire data directory (reports, uploads, submissions, presets) in one
request. The rename route would move DATA_DIR elsewhere.

These tests assert both the unit-level sanitizer contract and, end-to-end, that
the destructive admin routes refuse a traversal name and leave DATA_DIR intact.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-preset-traversal")


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
    from marlinspike.models import User
    c = app.test_client()
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        ident = (u.username, u.id, u.role, u.session_version or 1)
    with c.session_transaction() as sess:
        sess["user"], sess["user_id"], sess["role"], sess["session_version"] = ident
    return c


# ── Unit: the sanitizer must reject dot-only / traversal names ────────────────

@pytest.mark.parametrize("bad", ["..", ".", "...", "../etc", "..\\..", " .. "])
def test_safe_preset_name_rejects_traversal(app, bad):
    """The sanitizer must never return a name that resolves outside its parent."""
    import marlinspike.app as appmod

    fn = getattr(appmod, "_safe_preset_name", None)
    if fn is None:
        # It's a closure inside create_app in this build; reach it via the route
        # test below instead. Skip the unit assertion but keep the e2e guard.
        pytest.skip("_safe_preset_name is a closure, covered by route tests")

    result = fn(bad)
    assert result not in (".", ".."), f"sanitizer returned traversal name for {bad!r}: {result!r}"


# ── End-to-end: destructive routes must not escape PRESETS_DIR ────────────────

def test_delete_category_traversal_does_not_wipe_data_dir(app, db):
    from marlinspike import config

    admin = "preset_trav_admin"
    _make_user(db, admin, role="admin")
    c = _client(app, admin)

    # A sentinel file directly under DATA_DIR that a rmtree(DATA_DIR) would delete.
    os.makedirs(config.DATA_DIR, exist_ok=True)
    sentinel = os.path.join(config.DATA_DIR, "do-not-delete.sentinel")
    with open(sentinel, "w") as fh:
        fh.write("keep")

    try:
        rv = c.delete("/api/admin/presets/category/..?confirm=true",
                      headers={"Origin": "http://localhost"})
        # Must be rejected (400), and crucially DATA_DIR must still exist intact.
        assert rv.status_code == 400, f"traversal delete was accepted: {rv.status_code}"
        assert os.path.isdir(config.DATA_DIR)
        assert os.path.exists(sentinel), "DATA_DIR sentinel was deleted — traversal reached the data dir"
    finally:
        if os.path.exists(sentinel):
            os.unlink(sentinel)


def test_rename_category_traversal_rejected(app, db):
    from marlinspike import config

    admin = "preset_trav_admin_rename"
    _make_user(db, admin, role="admin")
    c = _client(app, admin)

    os.makedirs(config.DATA_DIR, exist_ok=True)
    rv = c.put("/api/admin/presets/category/..",
               json={"name": "moved_data_dir"},
               headers={"Origin": "http://localhost"})
    assert rv.status_code == 400, f"traversal rename was accepted: {rv.status_code}"
    assert os.path.isdir(config.DATA_DIR)
    assert not os.path.exists(os.path.join(config.PRESETS_DIR, "moved_data_dir"))
