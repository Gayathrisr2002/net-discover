"""Outbound webhook delivery for scan-completion findings.

Fires a single HTTP POST per completed scan at a project's configured
receiver (``Project.webhook_config``), carrying every risk finding at or
above the configured minimum severity — the generic integration point for
pushing vulnerabilities into an external system (ticketing, SIEM, chat).

Called from every real scan-completion path: ``run_store.record_finish``
(covers the fleet-agent and crash-recovery paths), ``app.py``'s
manual-upload finalizer, and ``capture/consumer.py``'s local live-capture
path. None of those callers can afford to block on a slow or unreachable
receiver or have a delivery failure break scan finalization, so every
network call here carries a short timeout and every public entry point
swallows its own exceptions.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from marlinspike import config
from marlinspike.models import Project

log = logging.getLogger("marlinspike.webhook")

ALLOWED_KEYS = frozenset({"enabled", "url", "secret", "min_severity"})
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_TIMEOUT_S = 5
_MAX_FINDINGS_PER_DELIVERY = 200


def parse_config(raw: str | None) -> dict[str, Any]:
    """Return a parsed webhook config dict from the JSON column, or {} if absent/invalid."""
    if not raw:
        return {}
    try:
        cfg = json.loads(raw)
        return cfg if isinstance(cfg, dict) else {}
    except (ValueError, TypeError):
        return {}


def _resolves_to_public_address(url: str) -> bool:
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            ):
                return False
        return True
    except (socket.gaierror, ValueError, UnicodeError):
        return False


def validate_config(body: dict) -> str | None:
    """Validate a webhook PUT body. Returns an error string, or None if valid."""
    unknown = set(body.keys()) - ALLOWED_KEYS
    if unknown:
        return f"unknown keys: {', '.join(sorted(unknown))}"
    if "enabled" in body and not isinstance(body["enabled"], bool):
        return "enabled must be a boolean"
    if "url" in body and body["url"] is not None:
        url = body["url"]
        if not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
            return "url must be an http(s) URL string"
        if not config.MARLINSPIKE_WEBHOOK_ALLOW_PRIVATE_TARGETS and not _resolves_to_public_address(url):
            return (
                "url resolves to a private/loopback/reserved address; set "
                "MARLINSPIKE_WEBHOOK_ALLOW_PRIVATE_TARGETS=true on the server "
                "to allow internal receivers"
            )
    if "secret" in body and body["secret"] is not None and not isinstance(body["secret"], str):
        return "secret must be a string"
    if "min_severity" in body and body["min_severity"] is not None:
        if body["min_severity"] not in SEVERITY_ORDER:
            return f"min_severity must be one of {SEVERITY_ORDER}"
    return None


def finding_dedup_key(project_id: int, finding: dict) -> str:
    basis = json.dumps(
        {
            "project_id": project_id,
            "category": finding.get("category"),
            "description": finding.get("description"),
            "affected_nodes": sorted(finding.get("affected_nodes") or []),
        },
        sort_keys=True,
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _qualifying_findings(report: dict, min_severity: str | None) -> list[dict]:
    findings = report.get("risk_findings") or []
    floor = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 0
    out = []
    for f in findings:
        sev = str(f.get("severity") or "INFO").upper()
        idx = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0
        if idx >= floor:
            out.append(f)
    return out


def _finding_payload(project_id: int, f: dict) -> dict:
    return {
        "dedup_key": finding_dedup_key(project_id, f),
        "severity": f.get("severity"),
        "category": f.get("category"),
        "description": f.get("description"),
        "affected_nodes": f.get("affected_nodes"),
        "affected_edges": f.get("affected_edges"),
        "cvss_impact": f.get("cvss_impact"),
        "remediation": f.get("remediation"),
    }


def _build_payload(project: Project, run_id: str | None, report: dict, findings: list[dict]) -> dict:
    capture_info = report.get("capture_info") or {}
    truncated = len(findings) > _MAX_FINDINGS_PER_DELIVERY
    return {
        "event": "scan.completed",
        "project_id": project.id,
        "project_name": project.name,
        "run_id": run_id,
        "capture_info": {
            "packet_count": capture_info.get("packet_count"),
            "duration_s": capture_info.get("duration_s"),
        },
        "finding_count": len(findings),
        "findings_truncated": truncated,
        "findings": [_finding_payload(project.id, f) for f in findings[:_MAX_FINDINGS_PER_DELIVERY]],
    }


def _post(url: str, secret: str | None, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-MarlinSpike-Event": payload.get("event", "scan.completed"),
    }
    if secret:
        sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-MarlinSpike-Signature"] = f"sha256={sig}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return {"ok": True, "status_code": resp.status, "error": None}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status_code": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "status_code": None, "error": str(exc)}


def deliver_for_scan(project_id: int | None, report_path: str | None, run_id: str | None) -> None:
    """Best-effort webhook delivery for one completed scan. Never raises.

    Safe to call from any scan-completion path regardless of whether that
    project has a webhook configured — returns immediately if not.
    """
    if not project_id or not report_path:
        return
    try:
        project = Project.query.get(project_id)
        if project is None:
            return
        cfg = parse_config(project.webhook_config)
        if not cfg.get("enabled") or not cfg.get("url"):
            return
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        findings = _qualifying_findings(report, cfg.get("min_severity"))
        if not findings:
            return
        payload = _build_payload(project, run_id, report, findings)
        result = _post(cfg["url"], cfg.get("secret"), payload)
        if not result["ok"]:
            log.warning(
                "webhook delivery failed project_id=%s run_id=%s status=%s error=%s",
                project_id, run_id, result["status_code"], result["error"],
            )
    except Exception:
        log.warning(
            "webhook delivery raised for project_id=%s run_id=%s", project_id, run_id, exc_info=True
        )


def send_test(project: Project) -> dict:
    """Synchronously fire a synthetic test payload. Returns a delivery result for the UI."""
    cfg = parse_config(project.webhook_config)
    url = cfg.get("url")
    if not url:
        return {"ok": False, "status_code": None, "error": "no webhook URL configured"}
    payload = {
        "event": "webhook.test",
        "project_id": project.id,
        "project_name": project.name,
        "run_id": None,
        "capture_info": {},
        "finding_count": 1,
        "findings_truncated": False,
        "findings": [
            {
                "dedup_key": "test",
                "severity": "INFO",
                "category": "test",
                "description": "Test delivery from MarlinSpike to verify your webhook receiver.",
                "affected_nodes": [],
                "affected_edges": [],
                "cvss_impact": None,
                "remediation": None,
            }
        ],
    }
    return _post(url, cfg.get("secret"), payload)
