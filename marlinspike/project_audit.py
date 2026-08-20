"""Project Vulnerability & Asset Historical Audit Engine for MarlinSpike.

Tracks vulnerability lifecycles (Discovered, Remediated, Persistent, Reopened)
and daily security surface trends across all generated reports within a Project.
"""

from typing import Any


def generate_project_audit_report(reports_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Computes day-by-day vulnerability diffs and lifecycle tracking.

    Args:
        reports_list: List of parsed MarlinSpike report dicts sorted by timestamp/date.

    Returns:
        Audit report object containing:
            - summary: {total_discovered, remediated, active, remediation_rate, total_scans}
            - vulnerability_lifecycle: list of tracked vulnerabilities across time
            - timeline_events: list of chronological DISCOVERED / REMEDIATED events
            - daily_snapshots: list of daily metric snapshots
    """
    if not reports_list:
        return {
            "summary": {
                "total_discovered": 0,
                "remediated": 0,
                "active": 0,
                "remediation_rate": 0.0,
                "total_scans": 0,
            },
            "vulnerability_lifecycle": [],
            "timeline_events": [],
            "daily_snapshots": [],
        }

    # Sort reports chronologically by timestamp
    sorted_reports = sorted(
        reports_list,
        key=lambda r: r.get("timestamp_start") or r.get("timestamp_end") or r.get("timestamp") or "",
    )

    vuln_tracker: dict[str, dict[str, Any]] = {}
    timeline_events: list[dict[str, Any]] = []
    daily_snapshots: list[dict[str, Any]] = []

    for idx, report in enumerate(sorted_reports):
        raw_ts = report.get("timestamp_start") or report.get("timestamp_end") or report.get("timestamp") or ""
        date_str = raw_ts[:10] if len(raw_ts) >= 10 else f"Day {idx + 1}"

        current_report_vulns: set[str] = set()

        # 1. Extract vulnerabilities from report nodes (cve_vulnerabilities)
        nodes = report.get("nodes") or []
        for node in nodes:
            ip = node.get("ip") or node.get("address") or "unknown"
            vendor = node.get("vendor", "")
            product = node.get("product_line") or node.get("hardware_model") or ""
            
            cves = node.get("cve_vulnerabilities") or []
            for v in cves:
                v_id = v.get("cve") or v.get("id") or v.get("title")
                v_key = f"{v_id}|{ip}"
                current_report_vulns.add(v_key)

                if v_key not in vuln_tracker:
                    vuln_tracker[v_key] = {
                        "id": v_id,
                        "cve": v.get("cve", v_id),
                        "title": v.get("title", v_id),
                        "severity": v.get("severity", "HIGH"),
                        "cvss": v.get("cvss", 7.5),
                        "ip": ip,
                        "vendor": vendor,
                        "product": product,
                        "discovered_date": date_str,
                        "discovered_ts": raw_ts,
                        "status": "active",
                        "remediated_date": None,
                        "remediated_ts": None,
                    }
                    timeline_events.append({
                        "date": date_str,
                        "timestamp": raw_ts,
                        "event_type": "DISCOVERED",
                        "vulnerability_id": v_id,
                        "title": v.get("title", v_id),
                        "severity": v.get("severity", "HIGH"),
                        "cvss": v.get("cvss", 7.5),
                        "ip": ip,
                        "vendor": vendor,
                        "product": product,
                        "status": "active",
                        "description": f"Vulnerability {v_id} first discovered on asset {ip} ({vendor} {product}).",
                    })
                elif vuln_tracker[v_key]["status"] == "remediated":
                    # Vulnerability reappeared (REOPENED)
                    vuln_tracker[v_key]["status"] = "active"
                    vuln_tracker[v_key]["remediated_date"] = None
                    timeline_events.append({
                        "date": date_str,
                        "timestamp": raw_ts,
                        "event_type": "REOPENED",
                        "vulnerability_id": v_id,
                        "title": v.get("title", v_id),
                        "severity": v.get("severity", "HIGH"),
                        "cvss": v.get("cvss", 7.5),
                        "ip": ip,
                        "vendor": vendor,
                        "product": product,
                        "status": "active",
                        "description": f"Vulnerability {v_id} REOPENED / RE-DETECTED on asset {ip}.",
                    })

        # 2. Check for risk findings
        risk_findings = report.get("risk_findings") or []
        for rf in risk_findings:
            if rf.get("category") == "CISA_ICS_ADVISORY":
                cve_id = rf.get("cve_id") or rf.get("advisory_id") or "CISA-ADVISORY"
                for affected_ip in (rf.get("affected_nodes") or ["unknown"]):
                    v_key = f"{cve_id}|{affected_ip}"
                    current_report_vulns.add(v_key)
                    if v_key not in vuln_tracker:
                        vuln_tracker[v_key] = {
                            "id": cve_id,
                            "cve": cve_id,
                            "title": rf.get("description", "").split(":")[0] or cve_id,
                            "severity": rf.get("severity", "HIGH"),
                            "cvss": rf.get("cvss_impact", 7.5),
                            "ip": affected_ip,
                            "vendor": "",
                            "product": "",
                            "discovered_date": date_str,
                            "discovered_ts": raw_ts,
                            "status": "active",
                            "remediated_date": None,
                            "remediated_ts": None,
                        }
                        timeline_events.append({
                            "date": date_str,
                            "timestamp": raw_ts,
                            "event_type": "DISCOVERED",
                            "vulnerability_id": cve_id,
                            "title": rf.get("description", "").split(":")[0] or cve_id,
                            "severity": rf.get("severity", "HIGH"),
                            "cvss": rf.get("cvss_impact", 7.5),
                            "ip": affected_ip,
                            "vendor": "",
                            "product": "",
                            "status": "active",
                            "description": f"CISA Advisory {cve_id} discovered on {affected_ip}.",
                        })

        # 3. Detect remediated vulnerabilities (was active before, absent in current report)
        for v_key, info in vuln_tracker.items():
            if info["status"] == "active" and v_key not in current_report_vulns:
                info["status"] = "remediated"
                info["remediated_date"] = date_str
                info["remediated_ts"] = raw_ts
                timeline_events.append({
                    "date": date_str,
                    "timestamp": raw_ts,
                    "event_type": "REMEDIATED",
                    "vulnerability_id": info["id"],
                    "title": info["title"],
                    "severity": info["severity"],
                    "cvss": info["cvss"],
                    "ip": info["ip"],
                    "vendor": info["vendor"],
                    "product": info["product"],
                    "status": "remediated",
                    "description": f"Vulnerability {info['id']} REMEDIATED / RESOLVED on asset {info['ip']}.",
                })

        remediated_so_far = sum(1 for v in vuln_tracker.values() if v["status"] == "remediated")
        total_so_far = len(vuln_tracker)

        daily_snapshots.append({
            "date": date_str,
            "report_name": report.get("report_name") or f"report_{idx+1}",
            "active_vulnerabilities": len(current_report_vulns),
            "remediated_vulnerabilities": remediated_so_far,
            "total_discovered": total_so_far,
            "total_nodes": len(nodes),
        })

    # Summary statistics
    total_discovered = len(vuln_tracker)
    remediated_count = sum(1 for v in vuln_tracker.values() if v["status"] == "remediated")
    active_count = total_discovered - remediated_count
    remediation_rate = round((remediated_count / total_discovered * 100.0), 1) if total_discovered > 0 else 100.0

    # OT Security Standards Metrics (IEC 62443 & CISA CPG)
    conduit_violations_count = 0
    control_writes_count = 0
    for report in sorted_reports:
        for rf in (report.get("risk_findings") or []):
            cat = rf.get("category", "")
            if cat == "IEC62443_CONDUIT_VIOLATION" or cat == "CROSS_PURDUE":
                conduit_violations_count += 1
            elif "WRITE" in cat or cat in ("S7_PROGRAM_ACCESS", "MODBUS_WRITE_COIL"):
                control_writes_count += 1

    cisa_cpg_score = max(50.0, min(100.0, round(100.0 - (conduit_violations_count * 4.0 + control_writes_count * 5.0 + active_count * 1.5), 1)))

    return {
        "summary": {
            "total_discovered": total_discovered,
            "remediated": remediated_count,
            "active": active_count,
            "remediation_rate": remediation_rate,
            "total_scans": len(sorted_reports),
            "conduit_violations_count": conduit_violations_count,
            "control_writes_count": control_writes_count,
            "cisa_cpg_score": cisa_cpg_score,
        },
        "vulnerability_lifecycle": list(vuln_tracker.values()),
        "timeline_events": sorted(timeline_events, key=lambda x: x.get("timestamp") or "", reverse=True),
        "daily_snapshots": daily_snapshots,
    }
