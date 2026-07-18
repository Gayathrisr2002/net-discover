"""Regression test for Finding #15 (VMware OUI 00:50:56 mislabeled as Rockwell).

``ICS_OUI_DB`` mapped ``00:50:56`` — VMware, Inc.'s well-known virtual-NIC OUI —
to "Rockwell Automation / EtherNet/IP", and it is overlaid on top of the IEEE
OUI database, so every VMware-backed VM (extremely common for HMI / engineering
workstation / historian hosts) was fingerprinted as Rockwell OT hardware. That
inflates the attack-priority score for something that isn't OT hardware at all
and misdirects responder attention during triage.

Fix: drop the bogus ICS overlay entry so the correct IEEE mapping
(00:50:56 → VMware, Inc.) surfaces and no OT product lines are attached.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.engine import ICS_OUI_DB, TopologyBuilder


def test_vmware_oui_not_labeled_rockwell_in_ics_db():
    entry = ICS_OUI_DB.get("00:50:56")
    if entry is not None:
        assert "rockwell" not in entry.get("vendor", "").lower(), (
            "VMware's OUI 00:50:56 is still mislabeled as Rockwell in ICS_OUI_DB"
        )


def test_vmware_oui_not_fingerprinted_as_ot_hardware():
    """After the fix, 00:50:56 must not resolve to an OT vendor with OT product
    lines. It either resolves to VMware (when the IEEE db is loadable) or is
    simply unknown — either way it is no longer false OT hardware."""
    db = TopologyBuilder._load_oui_db()
    entry = db.get("00:50:56")
    if entry is not None:
        vendor = entry.get("vendor", "").lower()
        assert "rockwell" not in vendor and "allen-bradley" not in vendor, (
            f"00:50:56 still resolves to an OT vendor: {entry.get('vendor')!r}"
        )
        assert not entry.get("product_lines"), (
            f"00:50:56 carries OT product lines {entry.get('product_lines')!r}"
        )


def test_ieee_oui_source_maps_50_56_to_vmware():
    """The correct source of truth (IEEE oui.json) identifies 00:50:56 as VMware,
    so with a properly-loaded IEEE db the vendor surfaces correctly."""
    import json
    for path in ("data/oui.json", os.path.join("marlinspike", "data", "oui.json")):
        if os.path.isfile(path):
            data = json.load(open(path))
            assert "vmware" in data.get("00:50:56", "").lower()
            return
    import pytest
    pytest.skip("IEEE oui.json not present in this checkout")
