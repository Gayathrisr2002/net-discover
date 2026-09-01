import unittest
from marlinspike.emit.sbom import generate_cyclonedx_sbom
from marlinspike.emit.switch_acl import generate_switch_acl


class TestPassiveExporters(unittest.TestCase):
    def setUp(self):
        self.report_data = {
            "project_name": "Test Industrial Substation",
            "nodes": [
                {
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "vendor": "Siemens",
                    "device_type": "PLC",
                    "purdue_level": 1,
                    "protocols": ["S7comm", "Modbus"],
                    "s7_identity": {"module_name": "S7-1200 CPU 1214C", "firmware_version": "V4.2.1"},
                },
                {
                    "ip": "192.168.1.60",
                    "mac": "aa:bb:cc:dd:ee:02",
                    "vendor": "Rockwell Automation",
                    "device_type": "PLC",
                    "purdue_level": 1,
                    "protocols": ["EtherNet/IP"],
                    "cip_identity": {"product_name": "ControlLogix 5580", "revision": "v33.011"},
                },
            ],
            "purdue_violations": [
                {"src": "10.0.0.5", "dst": "192.168.1.50", "protocol": "RDP"},
            ],
        }

    def test_cyclonedx_sbom_generation(self):
        sbom = generate_cyclonedx_sbom(self.report_data)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(len(sbom["components"]), 2)
        comp = sbom["components"][0]
        self.assertEqual(comp["supplier"]["name"], "Siemens")
        self.assertEqual(comp["version"], "V4.2.1")

    def test_switch_acl_cisco(self):
        acl = generate_switch_acl(self.report_data, vendor="cisco_ie")
        self.assertIn("Cisco Industrial Ethernet", acl)
        self.assertIn("deny ip host 10.0.0.5 host 192.168.1.50", acl)
        self.assertIn("switchport port-security mac-address aa:bb:cc:dd:ee:01", acl)

    def test_switch_acl_siemens(self):
        acl = generate_switch_acl(self.report_data, vendor="siemens_scalance")
        self.assertIn("Siemens SCALANCE", acl)
        self.assertIn("mac-address-table static aa:bb:cc:dd:ee:01 vlan 10", acl)

    def test_switch_acl_hirschmann(self):
        acl = generate_switch_acl(self.report_data, vendor="hirschmann_hios")
        self.assertIn("Hirschmann HiOS", acl)
        self.assertIn("port security 1/1 static-mac aa:bb:cc:dd:ee:01", acl)

    def test_snort_rule_exporter(self):
        from marlinspike.emit.snort import export_snort_rules
        rules = export_snort_rules(self.report_data)
        self.assertIn("Snort 3 / Suricata Industrial IDS Rules", rules)
        self.assertIn('alert rdp 10.0.0.5 any -> 192.168.1.50 any', rules)


if __name__ == "__main__":
    unittest.main()
