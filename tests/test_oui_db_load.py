"""Regression test: the IEEE OUI database is never loaded (vendor fingerprinting
silently degraded).

``TopologyBuilder._load_oui_db`` searched for ``oui.json`` only relative to the
package dir (``marlinspike/oui.json`` / ``marlinspike/data/oui.json``). But the
file ships at repo-root ``data/oui.json`` (dev) and the Dockerfile copies it to
``/app/oui.json`` (== PROJECT_ROOT) — neither of which the search covered. So in
both layouts the 1.4 MB IEEE database was never loaded and vendor fingerprinting
fell back to only the ~20-entry ICS overlay (every other device → "Unknown").

Fix: search the real locations (PROJECT_ROOT, DATA_DIR, an env override) as well.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-oui-load")


def test_ieee_oui_database_is_loaded():
    from marlinspike.engine import TopologyBuilder

    db = TopologyBuilder._load_oui_db()
    # The IEEE OUI DB has tens of thousands of entries; pre-fix only the ~20
    # hardcoded ICS OUIs loaded because the file path was wrong.
    assert len(db) > 1000, (
        f"IEEE OUI DB not loaded — only {len(db)} entries (vendor fingerprinting degraded)"
    )


def test_non_ics_vendor_resolves():
    from marlinspike.engine import TopologyBuilder
    db = TopologyBuilder._load_oui_db()
    # 00:50:56 = VMware in the IEEE DB (and no longer shadowed by the ICS overlay).
    assert "vmware" in db.get("00:50:56", {}).get("vendor", "").lower()


def test_ics_overlay_still_applied():
    """The ICS-specific entries (with product_lines) must still win over IEEE."""
    from marlinspike.engine import TopologyBuilder, ICS_OUI_DB
    db = TopologyBuilder._load_oui_db()
    sample = next(iter(ICS_OUI_DB))
    assert db.get(sample, {}).get("product_lines") == ICS_OUI_DB[sample]["product_lines"]
