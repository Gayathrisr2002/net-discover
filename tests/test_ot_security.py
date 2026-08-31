"""Unit tests for MarlinSpike's OT security features:
- Purdue zone violations
- Baseline deviations (HMI program access, PLC pull connections)
- PLC hardware/firmware integrity checks
- OT threat signatures (Industroyer, Triton, Modbus recon)
- EOL/EOS hardware status auditing
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from marlinspike.engine import Conversation, RiskSurface, RiskFinding


class TestOTSecurityEngine(unittest.TestCase):

    def setUp(self):
        # Create standard topology schema helper
        self.nodes = [
            # Engineering workstation
            {
                "ip": "10.10.10.10",
                "mac": "aa:bb:cc:dd:ee:01",
                "role": "Engineering Workstation",
                "purdue_level": 3,
                "_level": 3,
                "protocols": ["s7comm", "cip", "modbus"],
            },
            # HMI in Level 2
            {
                "ip": "10.10.10.20",
                "mac": "aa:bb:cc:dd:ee:02",
                "role": "Human-Machine Interface",
                "purdue_level": 2,
                "_level": 2,
                "protocols": ["s7comm", "modbus"],
            },
            # Siemens S7-300 PLC (EOL) in Level 1
            {
                "ip": "192.168.1.50",
                "mac": "aa:bb:cc:dd:ee:03",
                "role": "Programmable Logic Controller",
                "vendor": "Siemens",
                "product_line": "S7-300",
                "purdue_level": 1,
                "_level": 1,
                "protocols": ["s7comm"],
            },
            # Rockwell PLC in Level 1
            {
                "ip": "192.168.1.60",
                "mac": "aa:bb:cc:dd:ee:04",
                "role": "Programmable Logic Controller",
                "vendor": "Rockwell",
                "product_line": "ControlLogix",
                "purdue_level": 1,
                "_level": 1,
                "protocols": ["cip"],
            },
            # Corporate system in Level 4
            {
                "ip": "172.16.5.5",
                "mac": "aa:bb:cc:dd:ee:05",
                "role": "Workstation",
                "purdue_level": 4,
                "_level": 4,
                "protocols": ["http"],
            }
        ]
        self.edges = []
        self.conversations = []

    def _get_risk_surface(self):
        topology = {"nodes": self.nodes, "edges": self.edges}
        return RiskSurface(topology=topology, conversations=self.conversations)

    def test_purdue_violations_detection(self):
        # Let's add direct communication edge and conversation from Level 4 to Level 1
        self.conversations.append(Conversation(
            src_ip="172.16.5.5",
            dst_ip="192.168.1.50",
            src_mac="aa:bb:cc:dd:ee:05",
            dst_mac="aa:bb:cc:dd:ee:03",
            protocol="S7comm",
            port=102,
            packet_count=10,
            bytes_total=1000,
            first_seen="",
            last_seen="",
        ))
        self.edges.append({
            "src": "172.16.5.5",
            "dst": "192.168.1.50",
            "protocol": "S7comm",
            "conversation_count": 1,
        })
        rs = self._get_risk_surface()
        res = rs.score()

        # Check that purdue_violations list contains this direct leak
        self.assertTrue(len(res["purdue_violations"]) > 0)
        violation = res["purdue_violations"][0]
        self.assertEqual(violation["src"], "172.16.5.5")
        self.assertEqual(violation["dst"], "192.168.1.50")
        self.assertEqual(violation["protocol"], "S7comm")

    def test_baseline_deviations_hmi_writes(self):
        # HMI (10.10.10.20) executing S7 program logic changes on S7-300 PLC (192.168.1.50)
        self.conversations.append(Conversation(
            src_ip="10.10.10.20",
            dst_ip="192.168.1.50",
            src_mac="aa:bb:cc:dd:ee:02",
            dst_mac="aa:bb:cc:dd:ee:03",
            protocol="S7comm",
            port=102,
            packet_count=15,
            bytes_total=2500,
            first_seen="",
            last_seen="",
            s7_program_access=True,
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "BASELINE_DEVIATION"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("HMI", findings[0]["description"])
        self.assertIn("violating role baseline", findings[0]["description"])

    def test_baseline_deviations_plc_reverse_conn(self):
        # PLC (192.168.1.50) initiating connections to HMI (10.10.10.20)
        self.conversations.append(Conversation(
            src_ip="192.168.1.50",
            dst_ip="10.10.10.20",
            src_mac="aa:bb:cc:dd:ee:03",
            dst_mac="aa:bb:cc:dd:ee:02",
            protocol="S7comm",
            port=102,
            packet_count=10,
            bytes_total=1000,
            first_seen="",
            last_seen="",
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "BASELINE_DEVIATION" and "unidirectional" in f["description"].lower()]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_plc_integrity_default_serial(self):
        # Rockwell PLC communicating with CIP identity: serial_number = 0
        self.conversations.append(Conversation(
            src_ip="10.10.10.10",
            dst_ip="192.168.1.60",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:04",
            protocol="CIP",
            port=44818,
            packet_count=5,
            bytes_total=500,
            first_seen="",
            last_seen="",
            cip_identity={"serial_number": 0, "revision": "32.011"},
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "PLC_INTEGRITY"]
        # Should flag default serial number
        default_serial_findings = [f for f in findings if "default" in f["description"] or "serial" in f["description"]]
        self.assertEqual(len(default_serial_findings), 1)
        self.assertEqual(default_serial_findings[0]["severity"], "HIGH")

    def test_plc_integrity_legacy_firmware(self):
        # Rockwell PLC communicating with CIP identity: legacy revision "1.2" or "2.3"
        self.conversations.append(Conversation(
            src_ip="10.10.10.10",
            dst_ip="192.168.1.60",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:04",
            protocol="CIP",
            port=44818,
            packet_count=5,
            bytes_total=500,
            first_seen="",
            last_seen="",
            cip_identity={"serial_number": 1234567, "revision": "1.8.2"},
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "PLC_INTEGRITY" and "legacy" in f["description"]]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_ot_threat_signatures_industroyer(self):
        # S7 CPU Control STOP command
        self.conversations.append(Conversation(
            src_ip="10.10.10.10",
            dst_ip="192.168.1.50",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:03",
            protocol="S7comm",
            port=102,
            packet_count=10,
            bytes_total=1200,
            first_seen="",
            last_seen="",
            s7_functions=["STOP"],
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "OT_THREAT_SIGNATURE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("Industroyer", findings[0]["description"])

    def test_ot_threat_signatures_triton(self):
        # TriStation protocol port 1502
        self.conversations.append(Conversation(
            src_ip="10.10.10.10",
            dst_ip="192.168.1.50",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:03",
            protocol="TCP",
            port=1502,
            packet_count=5,
            bytes_total=400,
            first_seen="",
            last_seen="",
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "OT_THREAT_SIGNATURE" and "TriStation" in f["description"]]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_ot_threat_signatures_modbus_fc8(self):
        # Modbus Function Code 8 (Diagnostic)
        self.conversations.append(Conversation(
            src_ip="10.10.10.10",
            dst_ip="192.168.1.50",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:03",
            protocol="Modbus",
            port=502,
            packet_count=5,
            bytes_total=400,
            first_seen="",
            last_seen="",
            modbus_functions=[8],
        ))
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "OT_THREAT_SIGNATURE" and "Diagnostic" in f["description"]]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_eol_status_detection(self):
        # S7-300 PLC is flagged as EOL
        rs = self._get_risk_surface()
        res = rs.score()

        findings = [f for f in res["findings"] if f["category"] == "ASSET_EOL"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("SIMATIC S7-300", findings[0]["description"])


if __name__ == "__main__":
    unittest.main()
