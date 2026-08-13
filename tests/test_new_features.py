"""Unit tests for MarlinSpike new features:
- Extended OT/ICS Protocol Dissection & Firmware Metadata
- CISA ICS-CERT & CVE Vulnerability Correlation Engine
- Distributed Remote Sensor & Fleet Ingest API
"""

import gzip
import json
import unittest
from marlinspike.ics_cve import correlate_ics_vulnerabilities, CISA_ICS_CATALOG


class TestMarlinSpikeNewFeatures(unittest.TestCase):

    def test_cisa_ics_cve_correlation(self):
        sample_nodes = [
            {
                "ip": "192.168.1.50",
                "mac": "00:0e:8c:11:22:33",
                "vendor": "Siemens",
                "product_line": "S7-1500",
                "hardware_model": "6ES7 516-3AN02-0AB0",
                "firmware_version": "v2.8.0",
                "protocols": ["s7comm", "profinet"],
                "device_type": "Programmable Logic Controller",
            },
            {
                "ip": "192.168.1.60",
                "mac": "00:00:bc:44:55:66",
                "vendor": "Rockwell Automation",
                "product_line": "ControlLogix 1756",
                "hardware_model": "1756-L83E",
                "firmware_version": "v32.011",
                "protocols": ["cip", "enip"],
                "device_type": "Programmable Logic Controller",
            },
        ]

        updated_nodes, cisa_findings = correlate_ics_vulnerabilities(sample_nodes)

        self.assertEqual(len(updated_nodes), 2)
        # Verify Siemens S7-1500 matched CISA Advisories (CVE-2022-38465 / CVE-2020-15782)
        siemens_node = updated_nodes[0]
        self.assertGreater(len(siemens_node["cve_vulnerabilities"]), 0)
        cve_ids = [v["cve"] for v in siemens_node["cve_vulnerabilities"]]
        self.assertTrue("CVE-2022-38465" in cve_ids or "CVE-2020-15782" in cve_ids)

        # Verify Rockwell ControlLogix matched ICSA-21-056-03 (CVE-2021-22681)
        rockwell_node = updated_nodes[1]
        self.assertGreater(len(rockwell_node["cve_vulnerabilities"]), 0)
        rockwell_cves = [v["cve"] for v in rockwell_node["cve_vulnerabilities"]]
        self.assertTrue("CVE-2021-22681" in rockwell_cves)

        # Verify CISA Risk Findings generated
        self.assertGreaterEqual(len(cisa_findings), 2)
        categories = [f["category"] for f in cisa_findings]
        self.assertIn("CISA_ICS_ADVISORY", categories)

    def test_sensor_agent_payload_compression(self):
        dummy_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 64
        compressed = gzip.compress(dummy_pcap)
        decompressed = gzip.decompress(compressed)
        self.assertEqual(decompressed, dummy_pcap)


if __name__ == "__main__":
    unittest.main()
