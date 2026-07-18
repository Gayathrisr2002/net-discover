"""Regression tests for Finding #18 (wildcard domain IOCs never match).

An analyst adding a ``*.evil.com`` IOC expects it to match any host in that
domain. But ``_scan_report`` normalised the value to the literal string
``"*.evil.com"`` and matched with ``norm in query`` — a real DNS query like
``login.evil.com`` never *contains* the literal ``*.evil.com``, so wildcard
domain IOCs matched nothing, ever. For a threat-hunting feature, a silently
broken match means an analyst trusts a clean result that is actually blind.

The fix interprets a leading ``*.`` as "this base domain and any subdomain",
and matches plain domains as exact-or-subdomain (not loose substring, which
would false-positive on ``notevil.com``).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.iocs import scan_ioc_list_against_reports


def _run(report, entries):
    return scan_ioc_list_against_reports(
        entries=entries, report_paths=["fake.json"], loader=lambda _p: report
    )


def _report(dns_queries):
    return {
        "nodes": [], "c2_indicators": [], "risk_findings": [], "malware_findings": [],
        "conversations": [{"dns_queries": dns_queries}],
    }


def test_wildcard_matches_subdomain():
    result = _run(_report(["login.evil.com"]), [{"ioc_type": "domain", "value": "*.evil.com"}])
    assert result["summary"]["total_hits"] == 1, "wildcard IOC did not match a subdomain"


def test_wildcard_matches_apex():
    result = _run(_report(["evil.com"]), [{"ioc_type": "domain", "value": "*.evil.com"}])
    assert result["summary"]["total_hits"] == 1, "wildcard IOC should also match the apex domain"


def test_wildcard_does_not_false_positive_on_lookalike():
    # "notevil.com" ends with "evil.com" as a substring but is NOT in evil.com.
    result = _run(_report(["notevil.com", "evil.com.attacker.net"]),
                  [{"ioc_type": "domain", "value": "*.evil.com"}])
    assert result["summary"]["total_hits"] == 0, "wildcard IOC matched a lookalike domain"


def test_plain_domain_exact_still_matches():
    result = _run(_report(["evil.example.com"]),
                  [{"ioc_type": "domain", "value": "evil.example.com"}])
    assert result["summary"]["total_hits"] == 1


def test_plain_domain_matches_subdomain():
    result = _run(_report(["api.evil.example.com"]),
                  [{"ioc_type": "domain", "value": "evil.example.com"}])
    assert result["summary"]["total_hits"] == 1
