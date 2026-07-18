"""Regression tests for Finding #4 (``deliver_reset_token`` missing entirely).

``app.py``'s ``/api/auth/reset-request`` route imports and calls
``marlinspike.auth.deliver_reset_token`` (and the docs reference a
``set_reset_token_delivery`` hook), but neither exists. So for any delivery mode
other than the default ``disabled`` (i.e. ``file`` or ``log``), the import
raises, the broad ``except`` swallows it, the user gets the generic
"token delivered" message — and no token is ever delivered. Self-service reset
is 100% broken outside the default mode.

The fix implements ``deliver_reset_token`` (file + log modes, with a filesystem-
safe username and 0600 file perms) and the ``set_reset_token_delivery`` override
hook.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-reset-delivery")

import pytest


@pytest.fixture(autouse=True)
def _reset_hook():
    """Ensure the delivery hook global doesn't leak across tests."""
    yield
    from marlinspike import auth
    if hasattr(auth, "set_reset_token_delivery"):
        auth.set_reset_token_delivery(None)


def test_deliver_reset_token_is_importable():
    from marlinspike.auth import deliver_reset_token  # noqa: F401
    assert callable(deliver_reset_token)


def test_file_mode_writes_token_file_0600(tmp_path, monkeypatch):
    from marlinspike import auth, config

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    user = types.SimpleNamespace(username="alice", id=1)

    auth.deliver_reset_token(user, "SECRET-TOKEN-123", "file")

    token_dir = os.path.join(str(tmp_path), "instance", "reset-tokens")
    files = [f for f in os.listdir(token_dir) if f.startswith("alice-")]
    assert files, "file-mode delivery wrote no token file"
    path = os.path.join(token_dir, files[0])
    assert "SECRET-TOKEN-123" in open(path).read()
    assert (os.stat(path).st_mode & 0o777) == 0o600, "token file must be owner-only (0600)"


def test_file_mode_sanitises_username(tmp_path, monkeypatch):
    """A malicious username must not escape the reset-tokens directory."""
    from marlinspike import auth, config

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    user = types.SimpleNamespace(username="../../etc/evil", id=2)

    auth.deliver_reset_token(user, "T", "file")

    token_dir = os.path.join(str(tmp_path), "instance", "reset-tokens")
    # Everything written must stay inside the reset-tokens dir.
    for root, _dirs, files in os.walk(str(tmp_path)):
        for f in files:
            assert os.path.realpath(os.path.join(root, f)).startswith(
                os.path.realpath(token_dir)
            ), f"token file escaped the reset-tokens dir: {os.path.join(root, f)}"


def test_log_mode_emits_token(monkeypatch, caplog):
    from marlinspike import auth
    user = types.SimpleNamespace(username="bob", id=3)
    with caplog.at_level("INFO"):
        auth.deliver_reset_token(user, "LOGGED-TOKEN-xyz", "log")
    assert "LOGGED-TOKEN-xyz" in caplog.text


def test_delivery_hook_overrides_default(tmp_path, monkeypatch):
    from marlinspike import auth, config
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))

    seen = []
    auth.set_reset_token_delivery(lambda u, t, mode: seen.append((u.username, t, mode)))
    user = types.SimpleNamespace(username="carol", id=4)

    auth.deliver_reset_token(user, "HOOK-TOKEN", "file")

    assert seen == [("carol", "HOOK-TOKEN", "file")]
    # The default file path must NOT have been used when a hook is registered.
    assert not os.path.isdir(os.path.join(str(tmp_path), "instance", "reset-tokens"))
