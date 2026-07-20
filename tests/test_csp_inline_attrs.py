"""Regression test: CSP blocks all inline event handlers and style attributes.

The CSP puts a nonce on ``script-src``/``style-src`` AND keeps ``'unsafe-inline'``
— but per CSP3, once a nonce is present ``'unsafe-inline'`` is IGNORED for inline
event handlers (``onclick=``) and inline style attributes (``style=``). The
templates use 177 inline ``onclick`` handlers and 600 inline ``style=`` attrs, so
every such button (e.g. Users → Add user) silently did nothing and layout styles
were dropped.

Fix: emit explicit ``script-src-attr 'unsafe-inline'`` and
``style-src-attr 'unsafe-inline'`` directives (no nonce in them, so
``'unsafe-inline'`` is honored) — re-enabling inline handlers/styles while the
nonce still governs ``<script>``/``<style>`` elements.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-csp-attrs")

import pytest


@pytest.fixture(scope="module")
def client():
    from marlinspike.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_csp_allows_inline_event_handlers(client):
    csp = client.get("/login").headers.get("Content-Security-Policy", "")
    assert "script-src-attr 'unsafe-inline'" in csp, (
        "inline onclick handlers are blocked — no script-src-attr 'unsafe-inline'"
    )


def test_csp_allows_inline_style_attributes(client):
    csp = client.get("/login").headers.get("Content-Security-Policy", "")
    assert "style-src-attr 'unsafe-inline'" in csp, (
        "inline style= attributes are blocked — no style-src-attr 'unsafe-inline'"
    )


def test_csp_still_nonce_protects_script_elements(client):
    """The main script-src must still carry the per-request nonce (defence for
    <script> blocks is unchanged)."""
    csp = client.get("/login").headers.get("Content-Security-Policy", "")
    assert "script-src 'self' 'nonce-" in csp
