"""CycloneDX 1.5 JSON SBOM exporter for MarlinSpike passive PCAP report data."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_cyclonedx_sbom(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a CycloneDX 1.5 JSON SBOM from passive PCAP report metadata."""
    if not isinstance(report_data, dict):
        report_data = {}
    nodes = [n for n in report_data.get("nodes", []) if isinstance(n, dict)]
    project_name = report_data.get("project_name", "MarlinSpike Passive PCAP Analysis")

    bom_ref_prefix = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    components: List[Dict[str, Any]] = []

    for idx, node in enumerate(nodes):
        ip = node.get("ip") or node.get("mac") or f"asset-{idx}"
        vendor = node.get("vendor") or node.get("oui_vendor") or "Unknown Industrial Vendor"
        device_type = node.get("device_type") or node.get("role") or "Industrial Asset"
        purdue_level = node.get("purdue_level", 0)

        # Extract CIP / S7 firmware & identity
        cip_identity = node.get("cip_identity") or {}
        s7_identity = node.get("s7_identity") or {}
        firmware_rev = cip_identity.get("revision") or s7_identity.get("firmware_version") or "1.0.0"
        model_name = cip_identity.get("product_name") or s7_identity.get("module_name") or f"{vendor} {device_type}"
        serial_num = cip_identity.get("serial_number") or s7_identity.get("serial_number") or ""

        component = {
            "type": "firmware" if "PLC" in device_type.upper() or "RTU" in device_type.upper() else "device",
            "bom-ref": f"{bom_ref_prefix}:component:{idx}",
            "name": str(model_name),
            "version": str(firmware_rev),
            "description": f"Passive PCAP Discovered {device_type} (Purdue Level {purdue_level}, IP: {ip})",
            "supplier": {
                "name": str(vendor),
            },
            "properties": [
                {"name": "marlinspike:purdue_level", "value": str(purdue_level)},
                {"name": "marlinspike:ip_address", "value": str(node.get("ip", ""))},
                {"name": "marlinspike:mac_address", "value": str(node.get("mac", ""))},
                {"name": "marlinspike:protocols", "value": ", ".join(node.get("protocols", []))},
            ],
        }

        if serial_num:
            component["properties"].append({"name": "marlinspike:serial_number", "value": str(serial_num)})

        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "MarlinSpike",
                    "name": "Passive OT Security Engine",
                    "version": "3.9.0",
                }
            ],
            "component": {
                "type": "application",
                "name": str(project_name),
                "version": "1.0.0",
                "description": "Passive PCAP Industrial Network Inventory & SBOM",
            },
        },
        "components": components,
    }
