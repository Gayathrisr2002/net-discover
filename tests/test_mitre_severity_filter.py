"""Regression tests for Finding #20 (MITRE plugin missing `severity` rule filter).

The documented rule shape (docs/extensibility-contracts.md) supports a
``when.severity: ["HIGH", "CRITICAL"]`` gate, but ``_primitive_matches`` never
implemented it — so a rule author following the example verbatim got a filter
that was silently ignored, and the rule fired on every report regardless of
finding severity. That inflates the ATT&CK coverage numbers a client may rely on.

Fix: implement the ``severity`` primitive as a membership check against the
severities actually present in the report's risk findings.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.marlinspike_mitre import plugin


def _match(report, when):
    return plugin._rule_matches({"when": when}, plugin._build_context(report))


def test_severity_filter_matches_when_present():
    report = {"risk_findings": [{"category": "C2_DNS_EXFIL", "severity": "CRITICAL"}]}
    assert _match(report, {"severity": ["HIGH", "CRITICAL"]}) is True


def test_severity_filter_excludes_when_absent():
    report = {"risk_findings": [{"category": "C2_DNS_EXFIL", "severity": "LOW"}]}
    # Pre-fix this returned True (filter ignored → over-match).
    assert _match(report, {"severity": ["HIGH", "CRITICAL"]}) is False


def test_severity_filter_case_insensitive():
    report = {"risk_findings": [{"category": "X", "severity": "high"}]}
    assert _match(report, {"severity": ["HIGH"]}) is True


def test_no_severity_filter_still_matches():
    """Absence of a severity gate must not change behaviour (back-compat)."""
    report = {"risk_findings": [{"category": "X", "severity": "LOW"}]}
    assert _match(report, {"finding_categories": ["X"]}) is True


def test_severity_and_category_both_required():
    report = {"risk_findings": [{"category": "X", "severity": "LOW"}]}
    # Category present but no HIGH/CRITICAL finding → must not match.
    assert _match(report, {"finding_categories": ["X"], "severity": ["HIGH"]}) is False
