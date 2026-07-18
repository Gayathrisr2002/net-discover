"""Regression tests for the emit-format correctness cluster (#43–#46).

Downstream consumers (SIEM, Sigma engine, STIX platform) reject or silently
mis-handle malformed output:

* #43 OCSF — a Detection Finding whose report lacks a parseable timestamp lost
  its required ``time`` field (set to None, then pruned).
* #44 Sigma — findings with no affected_nodes produced detection selectors with
  empty ``|in: []`` lists, which are invalid Sigma.
* #45 Sigma — ATT&CK tags used ``attack.t1071_001`` (underscore) instead of the
  SigmaHQ dotted convention ``attack.t1071.001``.
* #46 STIX — IPv6 nodes were mis-typed: short ones (``fe80::1``) as ``mac-addr``
  (``":" in node and len<=17``), long ones as ``ipv4-addr``; never ``ipv6-addr``.
"""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-emit-fixes")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.emit import ocsf, sigma, stix


# ── #43: OCSF time is always present ─────────────────────────────────────────

def test_ocsf_record_has_time_even_without_report_timestamp():
    report = {
        # No timestamp_start / timestamp_end at all.
        "risk_findings": [
            {"severity": "HIGH", "category": "CROSS_PURDUE", "description": "x",
             "affected_nodes": ["10.0.0.1"], "affected_edges": []},
        ],
    }
    records = ocsf.render_report(report)
    assert records, "expected at least one OCSF record"
    for r in records:
        # After pruning, `time` must still be present and be an int (epoch ms).
        pruned = json.loads(ocsf.render_ndjson(report).splitlines()[0])
        assert "time" in pruned, "OCSF Detection Finding is missing the required `time` field"
        assert isinstance(pruned["time"], int)


# ── #44: Sigma emits no empty selectors ──────────────────────────────────────

def _has_empty_list(obj) -> bool:
    if isinstance(obj, dict):
        return any(_has_empty_list(v) for v in obj.values())
    if isinstance(obj, list):
        return len(obj) == 0 or any(_has_empty_list(v) for v in obj)
    return False


def test_sigma_no_empty_selectors_when_no_nodes():
    report = {
        "risk_findings": [
            {"severity": "HIGH", "category": "CROSS_PURDUE", "description": "x",
             "affected_nodes": [], "affected_edges": []},
            {"severity": "HIGH", "category": "MODBUS_WRITE_ANON", "description": "y",
             "affected_nodes": [], "affected_edges": []},
        ],
    }
    for _slug, rule in sigma.render_rules(report):
        assert not _has_empty_list(rule.get("detection", {})), (
            f"Sigma rule {rule.get('id')} has an empty selector: {rule.get('detection')}"
        )


# ── #45: Sigma ATT&CK tag format ─────────────────────────────────────────────

def test_sigma_attack_tag_uses_dotted_subtechnique():
    tags = sigma._attack_tags({"attack_techniques": ["T1071.001"]})
    assert "attack.t1071.001" in tags, f"expected dotted ATT&CK tag, got {tags}"
    assert "attack.t1071_001" not in tags, "ATT&CK tag still uses the invalid underscore form"


# ── #46: STIX IPv6/MAC/IPv4 classification ───────────────────────────────────

def test_stix_ipv6_node_is_ipv6_addr():
    pat = stix._indicator_pattern_for_finding({"category": "X", "affected_nodes": ["fe80::1"]})
    assert "ipv6-addr:value" in pat, f"short IPv6 misclassified: {pat}"
    assert "mac-addr:value" not in pat


def test_stix_long_ipv6_node_is_ipv6_addr():
    node = "2001:0db8:0000:0000:0000:0000:0000:0001"
    pat = stix._indicator_pattern_for_finding({"category": "X", "affected_nodes": [node]})
    assert "ipv6-addr:value" in pat, f"long IPv6 misclassified: {pat}"
    assert "ipv4-addr:value" not in pat


def test_stix_mac_and_ipv4_still_correct():
    mac = stix._indicator_pattern_for_finding({"category": "X", "affected_nodes": ["aa:bb:cc:dd:ee:ff"]})
    assert "mac-addr:value" in mac, mac
    v4 = stix._indicator_pattern_for_finding({"category": "X", "affected_nodes": ["10.0.0.1"]})
    assert "ipv4-addr:value" in v4, v4
