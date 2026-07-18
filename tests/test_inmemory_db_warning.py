"""Regression test (recovery/concurrency plumbing #55): silent in-memory-DB
fallback.

When ``DATABASE_URL`` is unset, ``create_app`` refuses to start — UNLESS
``MARLINSPIKE_ALLOW_NO_DATABASE_URL=true`` (the test escape hatch) is set, in
which case it falls back to ``sqlite:///:memory:``. That fallback was effectively
silent (a single ``log.debug``). A lingering test env var + a real server start
therefore yields an ephemeral, per-worker-inconsistent database with no visible
signal — data vanishes on restart and workers disagree.

Fix: emit a prominent WARNING whenever the in-memory fallback is used.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-inmem-warn")


def test_in_memory_fallback_emits_warning(monkeypatch, caplog):
    from marlinspike import config
    from marlinspike.app import create_app

    # Simulate: no DATABASE_URL, escape hatch left on.
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "ALLOW_NO_DATABASE_URL", True)

    with caplog.at_level("WARNING", logger="marlinspike"):
        app = create_app()

    assert app.config["SQLALCHEMY_DATABASE_URI"] in ("sqlite:///:memory:", "sqlite://")
    text = caplog.text.lower()
    # Distinctive DB phrase (not the unrelated "in-memory rate limits" warning).
    assert "in-memory sqlite" in text, "in-memory DB fallback was not warned about"
    assert "database_url" in text, "warning should name the missing DATABASE_URL"


def test_real_database_url_does_not_warn(monkeypatch, caplog, tmp_path):
    from marlinspike import config
    from marlinspike.app import create_app

    dbfile = tmp_path / "real.db"
    monkeypatch.setattr(config, "DATABASE_URL", f"sqlite:///{dbfile}")
    monkeypatch.setattr(config, "ALLOW_NO_DATABASE_URL", False)

    with caplog.at_level("WARNING", logger="marlinspike"):
        create_app()

    assert "in-memory sqlite" not in caplog.text.lower(), "should not warn about in-memory DB when a real DB URL is configured"
