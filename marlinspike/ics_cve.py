"""CISA ICS-CERT & CVE Vulnerability Correlation Engine for MarlinSpike.

Correlates extracted OT asset attributes (Vendor, Product Line, Hardware Model,
Firmware Version, Protocol Services) against a curated catalog of CISA ICS-CERT
advisories, CVE vulnerabilities, and Known Exploited Vulnerabilities (KEV).
"""

from __future__ import annotations
import re
from typing import Any


# ── Curated CISA ICS-CERT Advisory & Vulnerability Catalog ────────────────────

CISA_ICS_CATALOG: list[dict[str, Any]] = [
    # Siemens
    {
        "id": "ICSA-22-258-05",
        "cve": "CVE-2022-38465",
        "vendor": "Siemens",
        "product_keywords": ["s7-1500", "s7 1500", "simatic s7-1500", "6es7 5"],
        "title": "Siemens S7-1500 Global Hardcoded Private Key Extraction",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "description": (
            "Siemens SIMATIC S7-1500 CPU families use a hardcoded global private key "
            "for leg-1 s7comm-plus authentication. An unauthenticated remote attacker "
            "can extract the key and forge cryptographic authentication tokens to gain full "
            "control over the PLC."
        ),
        "remediation": (
            "Upgrade S7-1500 CPU firmware to v3.0.0 or higher. Enable TLS-encrypted "
            "PG/HMI communication and implement strict L2/L3 firewall segmentation."
        ),
    },
    {
        "id": "ICSA-20-343-04",
        "cve": "CVE-2020-15782",
        "vendor": "Siemens",
        "product_keywords": ["s7-1200", "s7-1500", "s7 1200", "s7 1500", "6es7 2", "6es7 5"],
        "title": "Siemens S7-1200/1500 Arbitrary Memory Write and Code Execution",
        "cvss": 8.1,
        "severity": "HIGH",
        "cisa_kev": True,
        "description": (
            "A memory protection bypass flaw in Siemens S7-1200 and S7-1500 CPUs allows "
            "an attacker with network access to write arbitrary memory regions and execute "
            "unauthorized code on the PLC controller."
        ),
        "remediation": (
            "Apply Siemens security patches (S7-1200 v4.5.0+, S7-1500 v2.9.2+). Restrict "
            "engineering access to authorized station IP addresses."
        ),
    },
    {
        "id": "ICSA-21-252-02",
        "cve": "CVE-2021-37185",
        "vendor": "Siemens",
        "product_keywords": ["scalance", "xc200", "xp200", "xr300"],
        "title": "Siemens SCALANCE Industrial Switches Unauthenticated Admin Access",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": False,
        "description": (
            "Siemens SCALANCE industrial Ethernet switches contain an unauthenticated "
            "remote access flaw in the web management interface, allowing full admin takeover."
        ),
        "remediation": (
            "Update SCALANCE switch firmware to v4.2 or later. Disable web management "
            "on untrusted VLANs."
        ),
    },
    # Rockwell Automation
    {
        "id": "ICSA-21-056-03",
        "cve": "CVE-2021-22681",
        "vendor": "Rockwell Automation",
        "product_keywords": ["controllogix", "compactlogix", "1756", "5370", "5380"],
        "title": "Rockwell Allen-Bradley ControlLogix Unauthenticated CIP Code Execution",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "description": (
            "Rockwell Logix5000 controllers accept unauthenticated CIP engineering commands "
            "over port 44818/tcp that allow remote attackers to modify controller logic, "
            "change operating modes, or upload malicious tasks."
        ),
        "remediation": (
            "Enable FactoryTalk Policy Manager, restrict CIP messaging over TCP 44818, "
            "and switch PLC keyswitch mode to RUN position."
        ),
    },
    {
        "id": "ICSA-23-192-01",
        "cve": "CVE-2023-3595",
        "vendor": "Rockwell Automation",
        "product_keywords": ["1756-en2t", "1756-en3t", "1756-en4tr"],
        "title": "Rockwell ControlLogix EtherNet/IP Communication Module Remote Code Execution",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "description": (
            "Out-of-bounds write vulnerability in Rockwell 1756-EN2T and 1756-EN3T EtherNet/IP "
            "communication modules allows unauthenticated remote code execution and Denial of Service."
        ),
        "remediation": (
            "Update 1756-EN2T/EN3T firmware to latest revision. Enforce strict CIP filtering."
        ),
    },
    # Schneider Electric
    {
        "id": "ICSA-23-017-01",
        "cve": "CVE-2022-45788",
        "vendor": "Schneider Electric",
        "product_keywords": ["modicon", "m580", "m340", "bmenoc"],
        "title": "Schneider Electric Modicon M580 Unauthenticated Remote Code Execution",
        "cvss": 7.5,
        "severity": "HIGH",
        "cisa_kev": False,
        "description": (
            "Schneider Electric Modicon M580 PACs accept unauthenticated Modbus/UMAS engineering "
            "commands allowing memory corruption, unauthorized code execution, or denial of service."
        ),
        "remediation": (
            "Apply Schneider Electric firmware updates. Enable Application Change Protection "
            "and restrict IP access lists on BMENOC Ethernet modules."
        ),
    },
    # Moxa
    {
        "id": "ICSA-18-107-02",
        "cve": "CVE-2018-7522",
        "vendor": "Moxa",
        "product_keywords": ["edr-810", "edr", "nport", "iologik"],
        "title": "Moxa Industrial Security Router Command Injection & Hardcoded Credentials",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "description": (
            "Moxa EDR-810 industrial routers contain hardcoded credentials and OS command "
            "injection flaws in the web management portal."
        ),
        "remediation": (
            "Upgrade Moxa EDR router firmware to v5.1 or later. Restrict management access to "
            "a dedicated administrative VLAN."
        ),
    },
    # Phoenix Contact
    {
        "id": "ICSA-21-259-01",
        "cve": "CVE-2021-34583",
        "vendor": "Phoenix Contact",
        "product_keywords": ["inline", "ilc", "axc", "mguard"],
        "title": "Phoenix Contact Inline Controllers Unauthenticated Remote Code Execution",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": False,
        "description": (
            "Phoenix Contact ILC and AXC series PLCs process unauthenticated proConOS "
            "management packets allowing remote attackers to overwrite controller memory."
        ),
        "remediation": (
            "Apply Phoenix Contact firmware update and restrict access to port 1962/tcp."
        ),
    },
    # Hirschmann / Belden
    {
        "id": "ICSA-21-035-01",
        "cve": "CVE-2020-28039",
        "vendor": "Hirschmann",
        "product_keywords": ["hios", "rs20", "rs30", "msp", "eagle"],
        "title": "Hirschmann Industrial Switch Authentication Bypass",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": False,
        "description": (
            "Hirschmann HiOS and Classic Switch OS contain an authentication bypass "
            "vulnerability in the management stack allowing full configuration overwrite."
        ),
        "remediation": (
            "Upgrade Hirschmann switch firmware to HiOS v08.3.00 or higher."
        ),
    },
]


def correlate_ics_vulnerabilities(
    nodes: list[dict[str, Any]],
    conversations: list[Any] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Correlates OT assets against the CISA ICS-CERT & CVE vulnerability catalog.

    Returns:
        (updated_nodes, cisa_risk_findings)
    """
    updated_nodes: list[dict[str, Any]] = []
    cisa_findings: list[dict[str, Any]] = []
    seen_vuln_keys: set[str] = set()

    for node in nodes:
        node_copy = dict(node) if isinstance(node, dict) else node.__dict__.copy()
        vendor = str(node_copy.get("vendor", "")).strip()
        product_line = str(node_copy.get("product_line", "")).strip()
        hardware_model = str(node_copy.get("hardware_model", "")).strip()
        firmware_ver = str(node_copy.get("firmware_version", "")).strip()
        sys_name = str(node_copy.get("system_name", "")).strip()
        sys_desc = str(node_copy.get("system_desc", "")).strip()
        protocols = [str(p).lower() for p in (node_copy.get("protocols") or [])]
        ip = node_copy.get("ip", "unknown")

        combined_text = f"{vendor} {product_line} {hardware_model} {sys_name} {sys_desc} {' '.join(protocols)}".lower()
        node_cves: list[dict[str, Any]] = node_copy.get("cve_vulnerabilities") or []

        for advisory in CISA_ICS_CATALOG:
            adv_vendor = advisory["vendor"].lower()
            # Vendor check
            if adv_vendor in vendor.lower() or adv_vendor in combined_text:
                # Check product keywords
                matched_kw = any(kw in combined_text for kw in advisory["product_keywords"])
                # Also match if protocol matches major industrial families (S7, CIP, Modbus)
                if not matched_kw:
                    if adv_vendor == "siemens" and any(p in ("s7comm", "s7comm-plus", "profinet") for p in protocols):
                        matched_kw = True
                    elif adv_vendor == "rockwell automation" and any(p in ("cip", "enip", "ethernet/ip") for p in protocols):
                        matched_kw = True
                    elif adv_vendor == "schneider electric" and "modbus" in protocols and "plc" in str(node_copy.get("device_type", "")).lower():
                        matched_kw = True

                if matched_kw:
                    vuln_entry = {
                        "id": advisory["id"],
                        "cve": advisory["cve"],
                        "title": advisory["title"],
                        "cvss": advisory["cvss"],
                        "severity": advisory["severity"],
                        "cisa_kev": advisory["cisa_kev"],
                    }
                    if vuln_entry not in node_cves:
                        node_cves.append(vuln_entry)

                    vuln_key = f"{advisory['cve']}|{ip}"
                    if vuln_key not in seen_vuln_keys:
                        seen_vuln_keys.add(vuln_key)
                        cisa_findings.append({
                            "severity": advisory["severity"],
                            "category": "CISA_ICS_ADVISORY",
                            "description": (
                                f"CISA Advisory [{advisory['id']} / {advisory['cve']}]: "
                                f"{advisory['title']} affects asset {ip} ({vendor} {product_line or hardware_model}). "
                                f"{advisory['description']}"
                            ),
                            "affected_nodes": [ip],
                            "affected_edges": [],
                            "cvss_impact": advisory["cvss"],
                            "remediation": advisory["remediation"],
                            "advisory_id": advisory["id"],
                            "cve_id": advisory["cve"],
                            "cisa_kev": advisory["cisa_kev"],
                        })

        node_copy["cve_vulnerabilities"] = node_cves
        updated_nodes.append(node_copy)

    return updated_nodes, cisa_findings
