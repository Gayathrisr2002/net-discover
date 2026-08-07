"""Outbound delivery of scan-completion findings to an external system.

Two delivery modes, selected by ``Project.webhook_config["platform"]``:

* ``"generic"`` (default) — a single signed HTTP POST per completed scan,
  containing every risk finding at or above the configured minimum
  severity. Any receiver that can parse JSON and (optionally) verify an
  HMAC signature works.
* ``"zammad"`` — calls Zammad's own ticket-creation REST API directly, one
  ticket per *new* finding (``WebhookTicket`` is the dedup ledger: a
  finding that persists across many scans must not spawn a fresh ticket
  every time it's re-reported).

Called from every real scan-completion path: ``run_store.record_finish``
(covers the fleet-agent and crash-recovery paths), ``app.py``'s
manual-upload finalizer, and ``capture/consumer.py``'s local live-capture
path. None of those callers can afford to block long on a slow/unreachable
receiver or have a delivery failure break scan finalization, so every
network call here carries a short timeout, per-delivery work is capped,
and every public entry point swallows its own exceptions.
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
from marlinspike.models import Project, WebhookTicket, db

log = logging.getLogger("marlinspike.webhook")

ALLOWED_KEYS = frozenset({
    "enabled", "platform", "url", "secret", "min_severity",
    "zammad_group", "zammad_customer",
    "jira_email", "jira_project_key", "jira_issue_type",
})
PLATFORMS = frozenset({"generic", "zammad", "jira"})
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_TIMEOUT_S = 8
_MAX_FINDINGS_PER_DELIVERY = 200
_MAX_TICKETS_PER_DELIVERY = 25
_ZAMMAD_DEFAULT_PRIORITY_IDS = {"low": 1, "normal": 2, "high": 3}
_HEADER_ENCODE_ERROR_HINT = (
    "the configured URL, API token, group, or customer contains a character that "
    "isn't valid in an HTTP header (e.g. a curly quote, em-dash, or a real '…' "
    "character picked up from copy-pasting a truncated display value) — re-save "
    "the webhook settings with the value retyped or copied in full"
)


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


def _header_safe(s: str) -> bool:
    """True if ``s`` can be sent as an HTTP header value.

    http.client encodes header values as latin-1 — a value copy-pasted from
    a web page that truncates long tokens/secrets with a real "…" character
    (or smart quotes, em-dashes, etc. from a rich-text source) fails at
    delivery time with a cryptic UnicodeEncodeError instead of a validation
    error the user can act on. Catching it here, at save time, is much
    clearer than surfacing a raw codec error from deep inside urllib later.
    """
    try:
        s.encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def _strip_header_bound_fields(body: dict) -> None:
    """Strip leading/trailing whitespace from every field that ends up in an
    HTTP header, in place. A trailing newline or space from copy-pasting a
    token/URL/group out of a web page is common and silently corrupts the
    header value without tripping the latin-1 check — the receiver just
    rejects the (subtly wrong) credential with its own generic auth error.
    """
    for key in (
        "url", "secret", "zammad_group", "zammad_customer",
        "jira_email", "jira_project_key", "jira_issue_type",
    ):
        if isinstance(body.get(key), str):
            body[key] = body[key].strip()


def validate_config(body: dict) -> str | None:
    """Validate a webhook PUT body. Returns an error string, or None if valid."""
    _strip_header_bound_fields(body)
    unknown = set(body.keys()) - ALLOWED_KEYS
    if unknown:
        return f"unknown keys: {', '.join(sorted(unknown))}"
    if "enabled" in body and not isinstance(body["enabled"], bool):
        return "enabled must be a boolean"
    if "platform" in body and body["platform"] is not None and body["platform"] not in PLATFORMS:
        return f"platform must be one of {sorted(PLATFORMS)}"
    if "url" in body and body["url"] is not None:
        url = body["url"]
        if not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
            return "url must be an http(s) URL string"
        if not _header_safe(url):
            return (
                "url contains a character that isn't valid in an HTTP request "
                "(e.g. a curly quote, em-dash, or '…' picked up by copy-paste) — retype it"
            )
        if not config.MARLINSPIKE_WEBHOOK_ALLOW_PRIVATE_TARGETS and not _resolves_to_public_address(url):
            return (
                "url resolves to a private/loopback/reserved address; set "
                "MARLINSPIKE_WEBHOOK_ALLOW_PRIVATE_TARGETS=true on the server "
                "to allow internal receivers (e.g. a self-hosted Zammad instance)"
            )
    if "secret" in body and body["secret"] is not None:
        if not isinstance(body["secret"], str):
            return "secret must be a string"
        if not _header_safe(body["secret"]):
            return (
                "secret/API token contains a character that isn't valid in an HTTP header "
                "— if you copy-pasted it from a page that displays it truncated (e.g. "
                "'abc123…xyz789'), that '…' is a real character, not three dots; copy the "
                "full untruncated value instead"
            )
    if "min_severity" in body and body["min_severity"] is not None:
        if body["min_severity"] not in SEVERITY_ORDER:
            return f"min_severity must be one of {SEVERITY_ORDER}"
    if "zammad_group" in body and body["zammad_group"] is not None:
        if not isinstance(body["zammad_group"], str):
            return "zammad_group must be a string"
        if not _header_safe(body["zammad_group"]):
            return "zammad_group contains a character that isn't valid in an HTTP header — retype it"
    if "zammad_customer" in body and body["zammad_customer"] is not None:
        if not isinstance(body["zammad_customer"], str):
            return "zammad_customer must be a string"
        if not _header_safe(body["zammad_customer"]):
            return "zammad_customer contains a character that isn't valid in an HTTP header — retype it"
    for key in ("jira_email", "jira_project_key", "jira_issue_type"):
        if key in body and body[key] is not None:
            if not isinstance(body[key], str):
                return f"{key} must be a string"
            if not _header_safe(body[key]):
                return f"{key} contains a character that isn't valid in an HTTP header — retype it"
    return None


def validate_effective_config(cfg: dict) -> str | None:
    """Validate the merged, saved config for completeness.

    validate_config only sees one PUT's fields, which may be a partial
    update — this checks the config as it will actually be *used*, so an
    enabled Zammad delivery that's missing a required field (most
    concretely: zammad_customer, which Zammad's own ticket API rejects
    with "Missing required value for field 'customer_id'") is caught here
    at save time instead of via a Zammad error page days later.
    """
    if not cfg.get("enabled"):
        return None
    platform = cfg.get("platform") or "generic"
    if platform == "zammad":
        required = {"url": "Zammad base URL", "secret": "Zammad API token",
                    "zammad_group": "Zammad group", "zammad_customer": "Zammad customer email"}
        missing = [label for key, label in required.items() if not cfg.get(key)]
        if missing:
            return f"zammad delivery is enabled but missing: {', '.join(missing)}"
    elif platform == "jira":
        required = {"url": "Jira base URL", "secret": "Jira API token / personal access token",
                    "jira_project_key": "Jira project key"}
        missing = [label for key, label in required.items() if not cfg.get(key)]
        if missing:
            return f"jira delivery is enabled but missing: {', '.join(missing)}"
    else:
        if not cfg.get("url"):
            return "webhook is enabled but no URL is configured"
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
    except UnicodeEncodeError:
        return {"ok": False, "status_code": None, "error": _HEADER_ENCODE_ERROR_HINT}
    except Exception as exc:
        return {"ok": False, "status_code": None, "error": str(exc)}


# ── Zammad ────────────────────────────────────────────────────

def _zammad_request(base_url: str, token: str, path: str, method: str, body: dict | None = None) -> dict:
    url = base_url.rstrip("/") + path
    headers = {"Authorization": f"Token token={token}", "Content-Type": "application/json"}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            raw = resp.read()
            parsed = json.loads(raw) if raw else {}
            return {"ok": True, "status_code": resp.status, "body": parsed, "error": None}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        return {"ok": False, "status_code": exc.code, "body": None, "error": detail}
    except UnicodeEncodeError:
        return {"ok": False, "status_code": None, "body": None, "error": _HEADER_ENCODE_ERROR_HINT}
    except Exception as exc:
        return {"ok": False, "status_code": None, "body": None, "error": str(exc)}


def _zammad_priority_map(base_url: str, token: str) -> dict[str, int]:
    """Look up this Zammad instance's actual priority IDs by name.

    Default installs use 1/2/3 for low/normal/high, but priorities are
    admin-editable — resolving by name instead of hardcoding IDs avoids
    silently filing every ticket at the wrong priority on a customized
    instance. Falls back to the documented defaults if the lookup fails.
    """
    result = _zammad_request(base_url, token, "/api/v1/ticket_priorities", "GET")
    if not result["ok"] or not isinstance(result["body"], list):
        return dict(_ZAMMAD_DEFAULT_PRIORITY_IDS)
    out = {}
    for p in result["body"]:
        name = str(p.get("name") or "").lower()
        for bucket in ("low", "normal", "high"):
            if bucket in name:
                out[bucket] = p.get("id")
    return {**_ZAMMAD_DEFAULT_PRIORITY_IDS, **{k: v for k, v in out.items() if v is not None}}


def _zammad_priority_bucket(severity: str) -> str:
    sev = str(severity or "INFO").upper()
    if sev in ("HIGH", "CRITICAL"):
        return "high"
    if sev == "MEDIUM":
        return "normal"
    return "low"


def _zammad_ticket_body(finding: dict) -> str:
    lines = [finding.get("description") or "(no description)", ""]
    if finding.get("affected_nodes"):
        lines.append("Affected assets: " + ", ".join(str(n) for n in finding["affected_nodes"]))
    if finding.get("affected_edges"):
        lines.append("Affected connections: " + ", ".join(str(e) for e in finding["affected_edges"]))
    if finding.get("cvss_impact") is not None:
        lines.append(f"CVSS impact: {finding['cvss_impact']}")
    if finding.get("remediation"):
        lines.append("")
        lines.append("Remediation: " + finding["remediation"])
    lines.append("")
    lines.append(f"MarlinSpike dedup key: {finding.get('dedup_key', '')}")
    return "\n".join(lines)


def _zammad_create_ticket(
    base_url: str, token: str, group: str, customer: str | None,
    finding: dict, priority_id: int | None,
) -> dict:
    project_name = finding.get("_project_name", "MarlinSpike")
    ticket_body: dict[str, Any] = {
        "title": f"[MarlinSpike] {finding.get('category', 'Finding')} — {finding.get('severity', 'INFO')} ({project_name})",
        "group": group,
        "article": {
            "subject": finding.get("category", "MarlinSpike finding"),
            "body": _zammad_ticket_body(finding),
            "type": "note",
            "internal": False,
        },
    }
    if customer:
        ticket_body["customer"] = customer
    if priority_id is not None:
        ticket_body["priority_id"] = priority_id

    result = _zammad_request(base_url, token, "/api/v1/tickets", "POST", ticket_body)
    if not result["ok"]:
        return {"ok": False, "external_id": None, "error": result["error"]}
    ticket = result["body"] or {}
    external_id = str(ticket.get("number") or ticket.get("id") or "")
    return {"ok": True, "external_id": external_id, "error": None}


def _existing_ticket_dedup_keys(project_id: int, platform: str) -> set[str]:
    rows = WebhookTicket.query.filter_by(project_id=project_id, platform=platform).all()
    return {r.dedup_key for r in rows}


def _record_ticket(project_id: int, dedup_key: str, platform: str, external_id: str | None) -> None:
    try:
        row = WebhookTicket(
            project_id=project_id, dedup_key=dedup_key, platform=platform, external_id=external_id,
        )
        db.session.add(row)
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.warning("failed to record webhook ticket dedup row", exc_info=True)


def deliver_to_zammad(project: Project, cfg: dict, findings: list[dict]) -> dict:
    """Create one Zammad ticket per finding not already ticketed. Returns a summary dict."""
    base_url, token, group = cfg.get("url"), cfg.get("secret"), cfg.get("zammad_group")
    customer = cfg.get("zammad_customer")
    if not base_url or not token or not group or not customer:
        log.warning(
            "zammad delivery skipped project_id=%s: missing url/secret/zammad_group/zammad_customer",
            project.id,
        )
        return {"created": 0, "skipped": 0, "failed": 0}

    already = _existing_ticket_dedup_keys(project.id, "zammad")
    new_findings = [f for f in findings if finding_dedup_key(project.id, f) not in already]
    skipped = len(findings) - len(new_findings)
    if not new_findings:
        return {"created": 0, "skipped": skipped, "failed": 0}

    if len(new_findings) > _MAX_TICKETS_PER_DELIVERY:
        log.warning(
            "zammad delivery project_id=%s: %d new findings exceed the %d-ticket cap; "
            "creating the first %d, the rest will be retried next scan",
            project.id, len(new_findings), _MAX_TICKETS_PER_DELIVERY, _MAX_TICKETS_PER_DELIVERY,
        )
        new_findings = new_findings[:_MAX_TICKETS_PER_DELIVERY]

    priority_map = _zammad_priority_map(base_url, token)
    created = failed = 0
    for f in new_findings:
        dedup_key = finding_dedup_key(project.id, f)
        payload = {**_finding_payload(project.id, f), "_project_name": project.name}
        priority_id = priority_map.get(_zammad_priority_bucket(f.get("severity")))
        result = _zammad_create_ticket(base_url, token, group, cfg.get("zammad_customer"), payload, priority_id)
        if result["ok"]:
            _record_ticket(project.id, dedup_key, "zammad", result["external_id"])
            created += 1
        else:
            failed += 1
            log.warning(
                "zammad ticket creation failed project_id=%s dedup_key=%s error=%s",
                project.id, dedup_key, result["error"],
            )
    return {"created": created, "skipped": skipped, "failed": failed}


# ── Jira ──────────────────────────────────────────────────────

def _jira_auth_header(secret: str, email: str | None) -> str:
    """Jira Cloud uses Basic Auth (email + API token); Jira Server/Data
    Center typically uses a Bearer personal access token with no email.
    Presence of jira_email picks the auth style — no separate mode toggle
    needed. Base64-encoding is done over UTF-8 bytes (not the header's own
    latin-1), so a non-ASCII email/token still produces a valid, entirely
    ASCII header value here — unlike a raw Bearer token or Zammad's
    Authorization header, an ellipsis or smart-quote in the *source* value
    can't corrupt this one.
    """
    if email:
        import base64
        raw = f"{email}:{secret}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")
    return f"Bearer {secret}"


def _jira_request(base_url: str, secret: str, email: str | None, path: str, method: str, body: dict | None = None) -> dict:
    url = base_url.rstrip("/") + path
    headers = {"Authorization": _jira_auth_header(secret, email), "Content-Type": "application/json"}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            raw = resp.read()
            parsed = json.loads(raw) if raw else {}
            return {"ok": True, "status_code": resp.status, "body": parsed, "error": None}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        return {"ok": False, "status_code": exc.code, "body": None, "error": detail}
    except UnicodeEncodeError:
        return {"ok": False, "status_code": None, "body": None, "error": _HEADER_ENCODE_ERROR_HINT}
    except Exception as exc:
        return {"ok": False, "status_code": None, "body": None, "error": str(exc)}


def _jira_priority_names(base_url: str, secret: str, email: str | None) -> dict[str, str]:
    """Look up this Jira instance's actual priority names.

    Priority *schemes* are fully admin-customizable per instance/project,
    so guessing "High"/"Medium"/"Low" outright risks Jira rejecting the
    create call if that exact name doesn't exist. Resolving from
    /rest/api/2/priority and falling back to omitting the field entirely
    (Jira then uses the project's own default) is safer than a hardcoded
    guess.
    """
    result = _jira_request(base_url, secret, email, "/rest/api/2/priority", "GET")
    if not result["ok"] or not isinstance(result["body"], list):
        return {}
    out: dict[str, str] = {}
    for p in result["body"]:
        name = str(p.get("name") or "")
        bucket = None
        low = name.lower()
        if any(w in low for w in ("high", "critical", "highest", "blocker", "urgent")):
            bucket = "high"
        elif any(w in low for w in ("medium", "major", "normal")):
            bucket = "medium"
        elif any(w in low for w in ("low", "lowest", "minor", "trivial")):
            bucket = "low"
        if bucket and bucket not in out:
            out[bucket] = name
    return out


def _jira_priority_bucket(severity: str) -> str:
    sev = str(severity or "INFO").upper()
    if sev in ("HIGH", "CRITICAL"):
        return "high"
    if sev == "MEDIUM":
        return "medium"
    return "low"


def _jira_issue_body(finding: dict) -> str:
    lines = [finding.get("description") or "(no description)", ""]
    if finding.get("affected_nodes"):
        lines.append("Affected assets: " + ", ".join(str(n) for n in finding["affected_nodes"]))
    if finding.get("affected_edges"):
        lines.append("Affected connections: " + ", ".join(str(e) for e in finding["affected_edges"]))
    if finding.get("cvss_impact") is not None:
        lines.append(f"CVSS impact: {finding['cvss_impact']}")
    if finding.get("remediation"):
        lines.append("")
        lines.append("Remediation: " + finding["remediation"])
    lines.append("")
    lines.append(f"MarlinSpike dedup key: {finding.get('dedup_key', '')}")
    return "\n".join(lines)


def _jira_create_issue(
    base_url: str, secret: str, email: str | None, project_key: str, issue_type: str,
    finding: dict, priority_name: str | None,
) -> dict:
    project_name = finding.get("_project_name", "MarlinSpike")
    fields: dict[str, Any] = {
        "project": {"key": project_key},
        "summary": f"[MarlinSpike] {finding.get('category', 'Finding')} — {finding.get('severity', 'INFO')} ({project_name})",
        "description": _jira_issue_body(finding),
        "issuetype": {"name": issue_type or "Task"},
    }
    if priority_name:
        fields["priority"] = {"name": priority_name}

    result = _jira_request(base_url, secret, email, "/rest/api/2/issue", "POST", {"fields": fields})
    if not result["ok"]:
        return {"ok": False, "external_id": None, "error": result["error"]}
    issue = result["body"] or {}
    external_id = str(issue.get("key") or issue.get("id") or "")
    return {"ok": True, "external_id": external_id, "error": None}


def deliver_to_jira(project: Project, cfg: dict, findings: list[dict]) -> dict:
    """Create one Jira issue per finding not already ticketed. Returns a summary dict."""
    base_url, token = cfg.get("url"), cfg.get("secret")
    project_key = cfg.get("jira_project_key")
    if not base_url or not token or not project_key:
        log.warning(
            "jira delivery skipped project_id=%s: missing url/secret/jira_project_key", project.id
        )
        return {"created": 0, "skipped": 0, "failed": 0}
    email = cfg.get("jira_email")
    issue_type = cfg.get("jira_issue_type") or "Task"

    already = _existing_ticket_dedup_keys(project.id, "jira")
    new_findings = [f for f in findings if finding_dedup_key(project.id, f) not in already]
    skipped = len(findings) - len(new_findings)
    if not new_findings:
        return {"created": 0, "skipped": skipped, "failed": 0}

    if len(new_findings) > _MAX_TICKETS_PER_DELIVERY:
        log.warning(
            "jira delivery project_id=%s: %d new findings exceed the %d-ticket cap; "
            "creating the first %d, the rest will be retried next scan",
            project.id, len(new_findings), _MAX_TICKETS_PER_DELIVERY, _MAX_TICKETS_PER_DELIVERY,
        )
        new_findings = new_findings[:_MAX_TICKETS_PER_DELIVERY]

    priority_names = _jira_priority_names(base_url, token, email)
    created = failed = 0
    for f in new_findings:
        dedup_key = finding_dedup_key(project.id, f)
        payload = {**_finding_payload(project.id, f), "_project_name": project.name}
        priority_name = priority_names.get(_jira_priority_bucket(f.get("severity")))
        result = _jira_create_issue(base_url, token, email, project_key, issue_type, payload, priority_name)
        if result["ok"]:
            _record_ticket(project.id, dedup_key, "jira", result["external_id"])
            created += 1
        else:
            failed += 1
            log.warning(
                "jira issue creation failed project_id=%s dedup_key=%s error=%s",
                project.id, dedup_key, result["error"],
            )
    return {"created": created, "skipped": skipped, "failed": failed}


def deliver_for_scan(project_id: int | None, report_path: str | None, run_id: str | None) -> None:
    """Best-effort webhook/ticket delivery for one completed scan. Never raises.

    Safe to call from any scan-completion path regardless of whether that
    project has delivery configured — returns immediately if not.
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

        platform = cfg.get("platform") or "generic"
        if platform == "zammad":
            summary = deliver_to_zammad(project, cfg, findings)
            log.info(
                "zammad delivery project_id=%s run_id=%s created=%d skipped=%d failed=%d",
                project_id, run_id, summary["created"], summary["skipped"], summary["failed"],
            )
        elif platform == "jira":
            summary = deliver_to_jira(project, cfg, findings)
            log.info(
                "jira delivery project_id=%s run_id=%s created=%d skipped=%d failed=%d",
                project_id, run_id, summary["created"], summary["skipped"], summary["failed"],
            )
        else:
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
    """Synchronously fire a synthetic test delivery. Returns a result dict for the UI.

    For Zammad this creates one real, clearly-labeled test ticket (never
    recorded in the dedup ledger, so it never blocks a real future finding
    with the same content from ticketing) — the most convincing proof a
    receiver actually works.
    """
    cfg = parse_config(project.webhook_config)
    url = cfg.get("url")
    if not url:
        return {"ok": False, "status_code": None, "error": "no webhook URL configured"}

    test_finding = {
        "dedup_key": "test",
        "severity": "INFO",
        "category": "MarlinSpike test",
        "description": "Test delivery from MarlinSpike to verify your receiver is reachable and configured correctly.",
        "affected_nodes": [],
        "affected_edges": [],
        "cvss_impact": None,
        "remediation": None,
    }

    if (cfg.get("platform") or "generic") == "zammad":
        token, group, customer = cfg.get("secret"), cfg.get("zammad_group"), cfg.get("zammad_customer")
        if not token or not group or not customer:
            missing = [n for n, v in (("API token", token), ("zammad_group", group), ("zammad_customer", customer)) if not v]
            return {"ok": False, "status_code": None, "error": f"missing required field(s): {', '.join(missing)}"}
        priority_map = _zammad_priority_map(url, token)
        payload = {**test_finding, "_project_name": project.name}
        result = _zammad_create_ticket(
            url, token, group, cfg.get("zammad_customer"), payload, priority_map.get("low")
        )
        if result["ok"]:
            return {"ok": True, "status_code": 201, "error": None, "detail": f"created ticket {result['external_id']}"}
        return {"ok": False, "status_code": None, "error": result["error"]}

    if (cfg.get("platform") or "generic") == "jira":
        token, project_key = cfg.get("secret"), cfg.get("jira_project_key")
        if not token or not project_key:
            missing = [n for n, v in (("API/personal access token", token), ("jira_project_key", project_key)) if not v]
            return {"ok": False, "status_code": None, "error": f"missing required field(s): {', '.join(missing)}"}
        email = cfg.get("jira_email")
        issue_type = cfg.get("jira_issue_type") or "Task"
        priority_names = _jira_priority_names(url, token, email)
        payload = {**test_finding, "_project_name": project.name}
        result = _jira_create_issue(
            url, token, email, project_key, issue_type, payload, priority_names.get("low")
        )
        if result["ok"]:
            return {"ok": True, "status_code": 201, "error": None, "detail": f"created issue {result['external_id']}"}
        return {"ok": False, "status_code": None, "error": result["error"]}

    payload = {
        "event": "webhook.test",
        "project_id": project.id,
        "project_name": project.name,
        "run_id": None,
        "capture_info": {},
        "finding_count": 1,
        "findings_truncated": False,
        "findings": [test_finding],
    }
    return _post(url, cfg.get("secret"), payload)
