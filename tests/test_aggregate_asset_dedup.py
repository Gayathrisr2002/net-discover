"""Regression test for the project-sharing / aggregate cluster: dedup splitting
one asset into two.

``aggregate_reports`` keys each asset by MAC-if-present, else IP. So the same
physical device appears as a MAC-keyed asset in a report that captured its MAC,
and as a separate IP-keyed asset in another report where the MAC wasn't captured
(same IP) — the Project Overview then shows two assets for one device, inflating
the asset count and splitting its history.

Fix: resolve an IP-only node to the MAC key when that IP is associated with a MAC
anywhere in the project (a two-pass IP→MAC map), so the same device stays one
aggregate asset.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.aggregate import aggregate_reports


def _loader(reports):
    def load(path):
        return reports[path]
    return load


def test_same_device_not_split_when_mac_missing_in_one_report():
    reports = {
        "a.json": {"nodes": [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.5", "role": "PLC"}]},
        # Same device, a report where the MAC wasn't captured — only its IP.
        "b.json": {"nodes": [{"ip": "10.0.0.5", "role": "PLC"}]},
    }
    result = aggregate_reports(["a.json", "b.json"], _loader(reports))

    assert result["totals"]["assets"] == 1, (
        f"same device split into {result['totals']['assets']} assets"
    )
    asset = result["assets"][0]
    assert "aa:bb:cc:dd:ee:ff" in asset["macs"]
    assert "10.0.0.5" in asset["ips"]
    assert asset["report_count"] == 2, "the IP-only sighting should count toward the same asset"


def test_merge_is_order_independent():
    # IP-only report seen BEFORE the MAC report must still merge.
    reports = {
        "b.json": {"nodes": [{"ip": "10.0.0.9", "role": "HMI"}]},
        "a.json": {"nodes": [{"mac": "11:22:33:44:55:66", "ip": "10.0.0.9", "role": "HMI"}]},
    }
    result = aggregate_reports(["b.json", "a.json"], _loader(reports))
    assert result["totals"]["assets"] == 1


def test_distinct_devices_stay_separate():
    reports = {
        "a.json": {"nodes": [
            {"mac": "aa:bb:cc:00:00:01", "ip": "10.0.0.1"},
            {"ip": "10.0.0.2"},  # genuinely MAC-less, different IP, no MAC anywhere
        ]},
    }
    result = aggregate_reports(["a.json"], _loader(reports))
    assert result["totals"]["assets"] == 2, "distinct devices must not be merged"
