"""Regression test: the Capabilities page 500s because of a stale module ref.

``_build_findings_catalog`` did ``__import__("_ms_engine")`` — the OLD root-level
engine module name that no longer exists (the engine is now
``marlinspike.engine``). So loading ``/capabilities`` raised
``ModuleNotFoundError: No module named '_ms_engine'`` → HTTP 500 for every user.

Fix: import the current engine module (``marlinspike.engine``), from which
``RUST_PROTOCOL_DISPLAY_NAMES`` is actually exported.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-capabilities")


def test_findings_catalog_builds_without_ms_engine():
    from marlinspike.app import _build_findings_catalog, create_app

    app = create_app()
    with app.app_context():
        catalog = _build_findings_catalog()  # must not raise ModuleNotFoundError

    assert catalog, "catalog should be non-empty"


def test_catalog_includes_dpi_protocols():
    """The DPI protocol entries (from RUST_PROTOCOL_DISPLAY_NAMES) must be present —
    proving the engine module was actually imported, not silently defaulted to {}."""
    from marlinspike.app import _build_findings_catalog, create_app
    from marlinspike.engine import RUST_PROTOCOL_DISPLAY_NAMES

    app = create_app()
    with app.app_context():
        catalog = _build_findings_catalog()

    blob = str(catalog).lower()
    # A representative protocol display name should appear somewhere in the catalog.
    sample = next(iter(RUST_PROTOCOL_DISPLAY_NAMES.values())).lower()
    assert sample[:4] in blob, f"expected DPI protocol {sample!r} in the capabilities catalog"
