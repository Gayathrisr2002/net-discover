"""Regression tests for Finding #11 (no MAX_CONTENT_LENGTH; size check after
the full body is spooled).

The app set no ``MAX_CONTENT_LENGTH``, so Werkzeug never rejected an oversized
request body at the framework level — the only guard was a per-view streaming
check that still spooled up to the limit to a temp file, and a spoofable
Content-Length hint. A hard app-level cap rejects an oversized (or lying) body
with 413 before any view runs, on every endpoint.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-maxlen")


def test_max_content_length_is_configured():
    from marlinspike import config
    from marlinspike.app import create_app
    app = create_app()
    cap = app.config.get("MAX_CONTENT_LENGTH")
    assert cap is not None, "no framework-level MAX_CONTENT_LENGTH cap is set"
    # Must allow the largest legitimate PCAP upload.
    assert cap >= config.PCAP_MAX_SIZE


def test_oversized_body_rejected_with_413(monkeypatch):
    """With the cap in effect, an oversized body is rejected before the view."""
    from marlinspike import config
    # Shrink the cap so we can exercise enforcement without a huge body.
    monkeypatch.setattr(config, "MAX_CONTENT_LENGTH", 2048)

    from marlinspike.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    # POST to the unauthenticated login form so body parsing happens.
    big = b"x" * 8192
    rv = client.post(
        "/login",
        data=big,
        content_type="application/x-www-form-urlencoded",
        headers={"Origin": "http://localhost"},
    )
    assert rv.status_code == 413, f"oversized body was not rejected (got {rv.status_code})"
