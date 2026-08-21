"""Tests for MarlinSpike OT Security Compliance & Benchmarking Engine."""

from __future__ import annotations

import unittest
from marlinspike.compliance import evaluate_compliance, COMPLIANCE_CONTROLS


class TestComplianceEngine(unittest.TestCase):
    def test_compliance_evaluation_clean_pass(self):
        """Verify that a clean finding list yields 100% compliance and SL-4 grade."""
        res = evaluate_compliance([], asset_count=10)

        self.assertEqual(res["overall_score"], 100.0)
        self.assertIn("SL-4", res["security_level_grade"])
        self.assertEqual(res["status_summary"]["pass"], len(COMPLIANCE_CONTROLS))
        self.assertEqual(res["status_summary"]["gap"], 0)
        self.assertEqual(len(res["hardening_roadmap"]), 0)
        self.assertEqual(res["breakdown_by_standard"]["IEC 62443"]["score"], 100.0)
        self.assertEqual(res["breakdown_by_standard"]["CISA CPG"]["score"], 100.0)

    def test_compliance_evaluation_with_gaps(self):
        """Verify that findings trigger compliance gaps and generate hardening recommendations."""
        findings = [
            {"category": "CROSS_PURDUE", "title": "Cross-Purdue Communication"},
            {"category": "CROSS_PURDUE", "title": "Cross-Purdue Communication"},
            {"category": "CROSS_PURDUE", "title": "Cross-Purdue Communication"},
            {"category": "CLEARTEXT_REMOTE_ACCESS", "title": "Telnet Observed"},
            {"category": "CLEARTEXT_REMOTE_ACCESS", "title": "FTP Unencrypted"},
            {"category": "CLEARTEXT_REMOTE_ACCESS", "title": "HTTP Cleartext Admin"},
            {"category": "MODBUS_WRITE_ANON", "title": "Anonymous Modbus Write"},
        ]

        res = evaluate_compliance(findings, asset_count=5)

        self.assertLess(res["overall_score"], 100.0)
        self.assertGreater(res["status_summary"]["gap"], 0)
        self.assertGreater(len(res["hardening_roadmap"]), 0)

        # Ensure hardening roadmap contains concrete recommendations
        first_item = res["hardening_roadmap"][0]
        self.assertIn("hardening_recommendation", first_item)
        self.assertGreater(len(first_item["hardening_recommendation"]), 10)


if __name__ == "__main__":
    unittest.main()
