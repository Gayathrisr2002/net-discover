import unittest
from marlinspike.engine import TopologyBuilder, TopologyNode, normalize_vendor_name

class TestITVendorFingerprinting(unittest.TestCase):

    def test_normalize_vendor_name(self):
        """Test vendor display name normalization map."""
        self.assertEqual(normalize_vendor_name("ASUSTek COMPUTER INC."), "ASUS")
        self.assertEqual(normalize_vendor_name("Hewlett Packard"), "HP")
        self.assertEqual(normalize_vendor_name("HP Inc."), "HP")
        self.assertEqual(normalize_vendor_name("Dell Inc."), "Dell")
        self.assertEqual(normalize_vendor_name("LENOVO(BEIJING)CO., LTD."), "Lenovo")
        self.assertEqual(normalize_vendor_name("Apple, Inc."), "Apple")
        self.assertEqual(normalize_vendor_name("Cisco Systems, Inc"), "Cisco")
        self.assertEqual(normalize_vendor_name("HUAWEI TECHNOLOGIES CO.,LTD"), "Huawei")
        self.assertEqual(normalize_vendor_name("TP-LINK TECHNOLOGIES CO.,LTD."), "TP-Link")
        self.assertEqual(normalize_vendor_name("Unknown"), "Unknown")
        self.assertEqual(normalize_vendor_name("Custom Robotics Corp. "), "Custom Robotics Corp.")

    def test_it_vendor_hostname_fingerprint_hp(self):
        """Test that nodes with HP hostnames override generic chipmakers or Unknown vendor."""
        builder = TopologyBuilder(conversations=[])
        builder._conv_by_dst = {}
        builder._conv_by_src = {}
        node = TopologyNode(ip="192.168.1.50", mac="00:1c:42:00:11:22")
        node.system_name = "DESKTOP-HP-WORKSTATION"
        node.vendor = "Intel Corporate"
        builder.nodes["192.168.1.50"] = node

        builder._fingerprint_vendors()
        self.assertEqual(builder.nodes["192.168.1.50"].vendor, "HP")

    def test_it_vendor_hostname_fingerprint_asus(self):
        """Test that nodes with ASUS hostnames override Unknown vendor."""
        builder = TopologyBuilder(conversations=[])
        builder._conv_by_dst = {}
        builder._conv_by_src = {}
        node = TopologyNode(ip="192.168.1.51", mac="70:85:c2:00:33:44")
        node.system_name = "ASUS-ZENBOOK-PRO"
        node.vendor = "Unknown"
        builder.nodes["192.168.1.51"] = node

        builder._fingerprint_vendors()
        self.assertEqual(builder.nodes["192.168.1.51"].vendor, "ASUS")

    def test_it_vendor_hostname_fingerprint_dell_and_lenovo(self):
        """Test Dell and Lenovo hostname fingerprinting."""
        builder = TopologyBuilder(conversations=[])
        builder._conv_by_dst = {}
        builder._conv_by_src = {}

        dell_node = TopologyNode(ip="192.168.1.52", mac="00:14:22:00:55:66")
        dell_node.system_desc = "DELL-LATITUDE-5520"
        dell_node.vendor = "Realtek Semiconductor"
        builder.nodes["192.168.1.52"] = dell_node

        lenovo_node = TopologyNode(ip="192.168.1.53", mac="00:21:5c:00:77:88")
        lenovo_node.system_name = "THINKPAD-T14-GEN2"
        lenovo_node.vendor = "Unknown"
        builder.nodes["192.168.1.53"] = lenovo_node

        builder._fingerprint_vendors()
        self.assertEqual(builder.nodes["192.168.1.52"].vendor, "Dell")
        self.assertEqual(builder.nodes["192.168.1.53"].vendor, "Lenovo")

    def test_dhcp_and_netbios_hostname_fingerprint(self):
        """Test vendor identification using DHCP option hostnames and NetBIOS names from conversations."""
        from marlinspike.engine import Conversation
        conv = Conversation(
            src_ip="192.168.1.60", dst_ip="192.168.1.1",
            src_mac="00:1c:42:00:99:aa", dst_mac="00:11:22:33:44:55",
            protocol="DHCP", port=67, packet_count=1, bytes_total=300,
            first_seen="", last_seen="", dhcp_hostname="ASUS-ROG-LAPTOP",
            dhcp_vendor_class="MSFT 5.0"
        )
        builder = TopologyBuilder(conversations=[conv])
        builder._conv_by_src = {"192.168.1.60": [conv]}
        builder._conv_by_dst = {}

        node = TopologyNode(ip="192.168.1.60", mac="00:1c:42:00:99:aa")
        node.vendor = "Intel Corporate"
        builder.nodes["192.168.1.60"] = node

        builder._fingerprint_vendors()
        self.assertEqual(builder.nodes["192.168.1.60"].vendor, "ASUS")

if __name__ == "__main__":
    unittest.main()
