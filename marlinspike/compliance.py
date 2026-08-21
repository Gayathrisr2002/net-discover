"""OT Security Compliance & Benchmarking Engine for MarlinSpike.

Evaluates passive PCAP findings and topology assets against global OT security frameworks:
- IEC 62443 (Target Security Levels SL 1-4)
- CISA Cross-Sector Cybersecurity Performance Goals (CPGs)
- NIST SP 800-82 Rev 3 (Guide to OT Security)

Calculates compliance scores (0-100%), identifies security gaps, and generates
concrete hardening recommendations required to achieve full compliance.
"""

from __future__ import annotations

from typing import Any

# Core Compliance Control Rules Mapping
COMPLIANCE_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "IEC-62443-SR-1.1",
        "standard": "IEC 62443",
        "section": "SR 1.1",
        "title": "Human User Identification & Authentication",
        "domain": "Access Control & Authentication",
        "weight": 15,
        "trigger_categories": ["CLEARTEXT_REMOTE_ACCESS", "NO_AUTH_OBSERVED"],
        "target_sl": "SL-2",
        "description": "Requires all human users attempting access to control systems to be uniquely identified and authenticated using secure channels.",
        "hardening_recommendation": "Enforce SSH/TLS 1.3 for remote access, disable unencrypted Telnet/HTTP, and mandate multi-factor authentication (MFA) for Level 3 Engineering Workstations.",
    },
    {
        "id": "IEC-62443-SR-3.1",
        "standard": "IEC 62443",
        "section": "SR 3.1",
        "title": "Communication Integrity & Industrial Command Abuse",
        "domain": "System Integrity & Industrial Control",
        "weight": 20,
        "trigger_categories": ["MODBUS_WRITE_ANON", "S7_PROGRAM_ACCESS", "MALWARE_IOC_MATCH"],
        "target_sl": "SL-3",
        "description": "Requires protection against unauthorized modification, program downloads, or command injection over industrial protocol channels.",
        "hardening_recommendation": "Set PLC physical keyswitches to 'RUN' mode (blocking remote program downloads), implement CIP Security / S7comm-plus cryptographic authentication, and deploy DPI firewall inspection on Modbus/S7 write function codes.",
    },
    {
        "id": "IEC-62443-SR-5.1",
        "standard": "IEC 62443",
        "section": "SR 5.1",
        "title": "Network Segmentation & Purdue Zone Isolation",
        "domain": "Boundary Protection & Zoning",
        "weight": 25,
        "trigger_categories": ["CROSS_PURDUE", "ICS_EXTERNAL_COMMS", "EXTERNAL_IPS_OBSERVED"],
        "target_sl": "SL-2",
        "description": "Mandates logical and physical separation between IT (Levels 4-5) and OT (Levels 0-3) networks using conduits and firewalls.",
        "hardening_recommendation": "Implement strict Purdue Model micro-segmentation firewalls between Level 3 and Level 2, restrict direct internet egress from PLCs/HMIs, and block raw cross-zone IP routing.",
    },
    {
        "id": "IEC-62443-SR-7.6",
        "standard": "IEC 62443",
        "section": "SR 7.6",
        "title": "Boundary Protection & Unnecessary Service Restriction",
        "domain": "Asset Hardening & Attack Surface",
        "weight": 15,
        "trigger_categories": ["OPC_NO_SECURITY", "IT_SERVICE_ON_OT_DEVICE", "PORT_SCAN_TARGET", "UNKNOWN_SERVICE_PORT"],
        "target_sl": "SL-2",
        "description": "Requires restricting active network services, protocols, and ports on industrial assets strictly to those necessary for process operation.",
        "hardening_recommendation": "Enable OPC UA Security Policy (Basic256Sha256 with Sign & Encrypt), disable unneeded IT services (FTP, SMB v1, SNMP v1/v2) on PLCs/HMIs, and close unused open ports.",
    },
    {
        "id": "CISA-CPG-1.1",
        "standard": "CISA CPG",
        "section": "CPG 1.1",
        "title": "Account & Credential Security",
        "domain": "Access Control & Authentication",
        "weight": 10,
        "trigger_categories": ["CLEARTEXT_REMOTE_ACCESS", "NO_AUTH_OBSERVED"],
        "hardening_recommendation": "Replace default factory credentials on PLCs and relays, prohibit cleartext administrative sessions, and enforce centralized RADIUS/TACACS+ authentication.",
    },
    {
        "id": "CISA-CPG-2.1",
        "standard": "CISA CPG",
        "section": "CPG 2.1",
        "title": "Separation of IT and OT Networks",
        "domain": "Boundary Protection & Zoning",
        "weight": 20,
        "trigger_categories": ["CROSS_PURDUE", "ICS_EXTERNAL_COMMS", "EXTERNAL_IPS_OBSERVED"],
        "hardening_recommendation": "Establish an explicit Demilitarized Zone (DMZ Level 3.5) between corporate IT and plant OT, ensuring no dual-homed dual-subnet connections bypass the firewall.",
    },
    {
        "id": "CISA-CPG-2.8",
        "standard": "CISA CPG",
        "section": "CPG 2.8",
        "title": "OT Protocol Security & Encryption",
        "domain": "System Integrity & Industrial Control",
        "weight": 15,
        "trigger_categories": ["OPC_NO_SECURITY", "CLEARTEXT_ENG", "MODBUS_WRITE_ANON"],
        "hardening_recommendation": "Transition to secure OT protocol variants (Modbus TCP Security over TLS, Secure DNP3 SA v5, EtherNet/IP CIP Security) and enforce cryptographic node identity verification.",
    },
    {
        "id": "CISA-CPG-3.1",
        "standard": "CISA CPG",
        "section": "CPG 3.1",
        "title": "Incident Containment & C2 Defense",
        "domain": "C2 & Threat Defense",
        "weight": 15,
        "trigger_categories": ["C2_BEACONING", "C2_SUSPECT_CHANNEL", "C2_DATA_EXFIL", "C2_DNS_EXFIL", "C2_DNS_TUNNEL_SUSPECT", "C2_DNS_HIGH_ENTROPY"],
        "hardening_recommendation": "Deploy egress DNS filtering, block high-entropy DNS query anomalies, and isolate compromised endpoints using network access control (802.1X) or Ansible IR playbooks.",
    },
    {
        "id": "NIST-800-82-AC-17",
        "standard": "NIST 800-82",
        "section": "AC-17",
        "title": "Remote Access Protection",
        "domain": "Access Control & Authentication",
        "weight": 10,
        "trigger_categories": ["CLEARTEXT_REMOTE_ACCESS", "NO_AUTH_OBSERVED"],
        "hardening_recommendation": "Terminate all external vendor remote access connections at an authenticated jump host inside the OT DMZ with session logging.",
    },
    {
        "id": "NIST-800-82-SC-7",
        "standard": "NIST 800-82",
        "section": "SC-7",
        "title": "Boundary Protection & Conduit Filtering",
        "domain": "Boundary Protection & Zoning",
        "weight": 15,
        "trigger_categories": ["CROSS_PURDUE", "ICS_EXTERNAL_COMMS", "C2_DNS_EXFIL"],
        "hardening_recommendation": "Configure stateful inspection firewalls to deny all cross-boundary traffic by default, explicitly permitting only documented OT protocols.",
    },
    {
        "id": "NIST-800-82-SI-4",
        "standard": "NIST 800-82",
        "section": "SI-4",
        "title": "Information System Monitoring & Anomaly Detection",
        "domain": "C2 & Threat Defense",
        "weight": 10,
        "trigger_categories": ["MALWARE_IOC_MATCH", "PORT_SCAN_TARGET", "HIGH_PORT_SERVICE"],
        "hardening_recommendation": "Integrate continuous passive PCAP monitoring with SIEM/SOAR platforms via STIX 2.1 or OCSF v1.4.0 telemetry streams.",
    },
]


def evaluate_compliance(findings: list[dict[str, Any]], asset_count: int = 0) -> dict[str, Any]:
    """Evaluate passive findings against OT compliance frameworks (IEC 62443, CISA CPG, NIST 800-82).

    Returns a detailed compliance evaluation object with scores, control matrix, and actionable hardening steps.
    """
    category_counts: dict[str, int] = {}
    category_findings: dict[str, list[dict[str, Any]]] = {}

    for f in findings:
        cat = str(f.get("category") or f.get("type") or "").upper()
        if not cat:
            continue
        category_counts[cat] = category_counts.get(cat, 0) + 1
        if cat not in category_findings:
            category_findings[cat] = []
        category_findings[cat].append(f)

    evaluated_controls: list[dict[str, Any]] = []

    total_possible_weight = 0
    total_earned_weight = 0

    standard_scores: dict[str, dict[str, float]] = {
        "IEC 62443": {"earned": 0.0, "total": 0.0},
        "CISA CPG": {"earned": 0.0, "total": 0.0},
        "NIST 800-82": {"earned": 0.0, "total": 0.0},
    }

    gaps_count = 0
    warning_count = 0
    pass_count = 0

    hardening_roadmap: list[dict[str, Any]] = []

    for ctrl in COMPLIANCE_CONTROLS:
        weight = ctrl["weight"]
        total_possible_weight += weight
        std = ctrl["standard"]
        if std in standard_scores:
            standard_scores[std]["total"] += weight

        matched_categories = []
        matched_findings_list = []
        trigger_count = 0

        for trig in ctrl["trigger_categories"]:
            if trig in category_counts:
                matched_categories.append(trig)
                trigger_count += category_counts[trig]
                matched_findings_list.extend(category_findings.get(trig, []))

        if trigger_count == 0:
            status = "PASS"
            earned = weight
            pass_count += 1
        elif trigger_count <= 2:
            status = "WARNING"
            earned = weight * 0.4
            warning_count += 1
        else:
            status = "GAP"
            earned = 0.0
            gaps_count += 1

        total_earned_weight += earned
        if std in standard_scores:
            standard_scores[std]["earned"] += earned

        ctrl_eval = {
            "id": ctrl["id"],
            "standard": ctrl["standard"],
            "section": ctrl["section"],
            "title": ctrl["title"],
            "domain": ctrl["domain"],
            "weight": weight,
            "status": status,
            "earned_weight": round(earned, 1),
            "findings_count": trigger_count,
            "matched_categories": matched_categories,
            "description": ctrl.get("description", ctrl["title"]),
            "hardening_recommendation": ctrl["hardening_recommendation"],
            "target_sl": ctrl.get("target_sl", "SL-2"),
        }
        evaluated_controls.append(ctrl_eval)

        if status in ("GAP", "WARNING"):
            hardening_roadmap.append({
                "priority": "HIGH" if status == "GAP" else "MEDIUM",
                "control_id": ctrl["id"],
                "standard": ctrl["standard"],
                "title": ctrl["title"],
                "domain": ctrl["domain"],
                "findings_count": trigger_count,
                "hardening_recommendation": ctrl["hardening_recommendation"],
            })

    overall_score = round((total_earned_weight / total_possible_weight * 100.0), 1) if total_possible_weight > 0 else 100.0

    # Determine Target Security Level (SL) Grade
    if overall_score >= 95.0:
        security_level_grade = "SL-4 (Nation-State Grade Resilience)"
    elif overall_score >= 80.0:
        security_level_grade = "SL-3 (Sophisticated Protection)"
    elif overall_score >= 65.0:
        security_level_grade = "SL-2 (Moderate Adversary Protection)"
    elif overall_score >= 45.0:
        security_level_grade = "SL-1 (Basic Perimeter Defense)"
    else:
        security_level_grade = "SL-0 (Unprotected / High Vulnerability Risk)"

    breakdown_by_standard = {}
    for std, val in standard_scores.items():
        pct = round((val["earned"] / val["total"] * 100.0), 1) if val["total"] > 0 else 100.0
        breakdown_by_standard[std] = {
            "score": pct,
            "earned": round(val["earned"], 1),
            "total": round(val["total"], 1),
            "grade": "COMPLIANT" if pct >= 80.0 else ("PARTIAL" if pct >= 60.0 else "NON-COMPLIANT"),
        }

    # Sort hardening roadmap by priority (HIGH first) then findings count
    hardening_roadmap.sort(key=lambda x: (0 if x["priority"] == "HIGH" else 1, -x["findings_count"]))

    return {
        "overall_score": overall_score,
        "security_level_grade": security_level_grade,
        "status_summary": {
            "pass": pass_count,
            "warning": warning_count,
            "gap": gaps_count,
            "total_controls": len(COMPLIANCE_CONTROLS),
        },
        "breakdown_by_standard": breakdown_by_standard,
        "evaluated_controls": evaluated_controls,
        "hardening_roadmap": hardening_roadmap,
        "total_findings_evaluated": len(findings),
        "total_assets_evaluated": asset_count,
    }
