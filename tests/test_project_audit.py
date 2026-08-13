"""Unit tests for Project Historical Vulnerability Audit Engine.
"""

import unittest
from marlinspike.project_audit import generate_project_audit_report


class TestProjectAuditEngine(unittest.TestCase):

    def test_vulnerability_lifecycle_discovery_and_remediation(self):
        # Report 1 (Aug 1, 2026): 2 CVEs on 192.168.1.50
        report_aug1 = {
            "timestamp": "2026-08-01T10:00:00Z",
            "nodes": [
                {
                    "ip": "192.168.1.50",
                    "vendor": "Siemens",
                    "product_line": "S7-1500",
                    "cve_vulnerabilities": [
                        {"cve": "CVE-2022-38465", "title": "S7-1500 Hardcoded Key", "severity": "CRITICAL", "cvss": 9.3},
                        {"cve": "CVE-2020-15782", "title": "S7-1500 Arbitrary Memory Write", "severity": "HIGH", "cvss": 8.1},
                    ],
                }
            ],
        }

        # Report 2 (Aug 4, 2026): CVE-2022-38465 was remediated! Only CVE-2020-15782 remains
        report_aug4 = {
            "timestamp": "2026-08-04T10:00:00Z",
            "nodes": [
                {
                    "ip": "192.168.1.50",
                    "vendor": "Siemens",
                    "product_line": "S7-1500",
                    "cve_vulnerabilities": [
                        {"cve": "CVE-2020-15782", "title": "S7-1500 Arbitrary Memory Write", "severity": "HIGH", "cvss": 8.1},
                    ],
                }
            ],
        }

        audit_res = generate_project_audit_report([report_aug1, report_aug4])
        summary = audit_res["summary"]

        self.assertEqual(summary["total_discovered"], 2)
        self.assertEqual(summary["remediated"], 1)
        self.assertEqual(summary["active"], 1)
        self.assertEqual(summary["remediation_rate"], 50.0)

        # Check timeline events
        events = audit_res["timeline_events"]
        event_types = [e["event_type"] for e in events]
        self.assertIn("DISCOVERED", event_types)
        self.assertIn("REMEDIATED", event_types)

        # Verify exact remediated event detail
        remediated_ev = next(e for e in events if e["event_type"] == "REMEDIATED")
        self.assertEqual(remediated_ev["vulnerability_id"], "CVE-2022-38465")
        self.assertEqual(remediated_ev["ip"], "192.168.1.50")
        self.assertEqual(remediated_ev["date"], "2026-08-04")


if __name__ == "__main__":
    unittest.main()
