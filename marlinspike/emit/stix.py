"""STIX 2.1 Threat Intelligence Exporter for MarlinSpike.

Generates OASIS STIX 2.1 compliant JSON bundles containing Observed-Data,
Indicator, Malware, Threat-Actor, and Infrastructure objects for OT security findings.
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any


def _stix_id(type_name: str) -> str:
    """Generate a valid STIX 2.1 ID string."""
    return f"{type_name}--{uuid.uuid4()}"


def _iso_now() -> str:
    """Generate ISO 8601 UTC timestamp format for STIX 2.1."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def export_stix_bundle(
    capture_id: str,
    findings: list[dict[str, Any]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a STIX 2.1 Bundle containing OT threat intelligence data."""
    now = _iso_now()
    bundle_id = _stix_id("bundle")
    stix_objects: list[dict[str, Any]] = []

    # Identity object representing MarlinSpike OT Security Engine
    identity_id = _stix_id("identity")
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "MarlinSpike OT Security Platform",
        "identity_class": "system",
        "sectors": ["energy", "critical-infrastructure", "dams", "water"],
    }
    stix_objects.append(identity_obj)

    # Process Findings into STIX Indicators and Infrastructure
    findings_list = findings or []
    for f in findings_list:
        ftype = str(f.get("type") or "OT_ANOMALY").upper()
        severity = str(f.get("severity") or "HIGH").upper()
        src_ip = f.get("src_ip") or f.get("source_ip") or ""
        dst_ip = f.get("dst_ip") or f.get("target_ip") or ""
        technique = f.get("technique_id") or "T0855"
        description = f.get("description") or f.get("title") or f"OT Anomaly detected: {ftype}"

        # Indicator Object
        pattern = f"[ipv4-addr:value = '{src_ip}']" if src_ip else f"[network-traffic:dst_ref.value = '{dst_ip}']"
        indicator_id = _stix_id("indicator")
        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"MarlinSpike OT Threat: {ftype}",
            "description": description,
            "indicator_types": ["malicious-activity", "anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now,
            "created_by_ref": identity_id,
            "external_references": [
                {
                    "source_name": "mitre-attack-ics",
                    "external_id": technique,
                    "url": f"https://attack.mitre.org/techniques/{technique}/",
                }
            ],
            "labels": ["ics-security", "ot-anomaly", severity.lower()],
        }
        stix_objects.append(indicator_obj)

        # Infrastructure Object if target asset is specified
        if dst_ip:
            infra_id = _stix_id("infrastructure")
            infra_obj = {
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": infra_id,
                "created": now,
                "modified": now,
                "name": f"OT Device target ({dst_ip})",
                "infrastructure_types": ["control-system"],
                "created_by_ref": identity_id,
            }
            stix_objects.append(infra_obj)

    # Process explicit IOCs
    iocs_list = iocs or []
    for ioc in iocs_list:
        ioc_val = ioc.get("value") or ioc.get("indicator")
        ioc_type = str(ioc.get("type") or "ip").lower()
        if not ioc_val:
            continue

        if ioc_type in ("ip", "ipv4"):
            pattern = f"[ipv4-addr:value = '{ioc_val}']"
        elif ioc_type in ("mac"):
            pattern = f"[mac-addr:value = '{ioc_val}']"
        else:
            pattern = f"[domain-name:value = '{ioc_val}']"

        ioc_id = _stix_id("indicator")
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ioc_id,
            "created": now,
            "modified": now,
            "name": f"MarlinSpike IOC: {ioc_val}",
            "description": f"Observed OT Indicator of Compromise [{ioc_type.upper()}]",
            "indicator_types": ["compromised"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": identity_id,
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects,
    }


def export_stix_json(
    capture_id: str,
    findings: list[dict[str, Any]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
) -> str:
    """Return serialized STIX 2.1 JSON string."""
    bundle = export_stix_bundle(capture_id, findings=findings, iocs=iocs, assets=assets)
    return json.dumps(bundle, indent=2, ensure_ascii=False)
