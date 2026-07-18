"""Regression tests for Finding #19 (audit log write failures silently swallowed).

``audit()`` must never raise (an audit failure must not break login / reset /
password-change). But on a DB write failure it merely logged a WARNING naming
the ``event_type`` — the actual security event (who, what, outcome) was lost,
and nothing let an operator detect that the compliance trail had a hole.

Fix: on failure, emit the FULL event as a structured ERROR-level fallback record
(a last-resort compliance log line, recoverable) and increment an inspectable
failure counter — while still never raising.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-audit-fail")


@pytest.fixture
def app():
    from marlinspike.app import create_app
    from marlinspike.models import db
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with application.app_context():
        db.create_all()
    return application


def _force_write_failure(monkeypatch):
    """Make constructing the AuditLog row raise, exercising the except path."""
    from marlinspike import audit as audit_mod

    def boom(**_kw):
        raise RuntimeError("simulated DB failure")

    monkeypatch.setattr(audit_mod, "AuditLog", boom)


def test_audit_failure_does_not_raise(app, monkeypatch):
    from marlinspike import audit as audit_mod
    _force_write_failure(monkeypatch)
    with app.app_context():
        # Must not raise — audit failures must never break the caller.
        audit_mod.audit("auth.login", actor_username="alice", status="failure")


def test_audit_failure_is_counted(app, monkeypatch):
    from marlinspike import audit as audit_mod
    _force_write_failure(monkeypatch)
    with app.app_context():
        before = audit_mod.get_audit_failure_count()
        audit_mod.audit("auth.login", actor_username="alice", status="failure")
        assert audit_mod.get_audit_failure_count() == before + 1


def test_audit_failure_preserves_full_event_at_error(app, monkeypatch, caplog):
    from marlinspike import audit as audit_mod
    _force_write_failure(monkeypatch)
    with app.app_context():
        with caplog.at_level("ERROR", logger="marlinspike.audit"):
            audit_mod.audit(
                "auth.password_change",
                actor_username="alice",
                target_id="bob",
                status="failure",
            )
    # The dropped event must be recoverable from the log: event type + actor +
    # target + outcome, at ERROR (not a bare WARNING that only names the type).
    assert any(r.levelname == "ERROR" for r in caplog.records), "failure not logged at ERROR"
    text = caplog.text
    assert "auth.password_change" in text
    assert "alice" in text
    assert "bob" in text
