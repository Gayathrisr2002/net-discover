"""LLM-generated remediation recommendations for risk findings.

Talks to any OpenAI-compatible Chat Completions endpoint (``POST
{base_url}/chat/completions``) — this covers OpenAI itself, Azure OpenAI,
and virtually every self-hosted/local option (Ollama, vLLM, LM Studio,
llama.cpp's server, OpenRouter, Together, Groq) without needing a
provider-specific branch, the same "pick one common shape and support
that" choice already made for the outbound webhook.

Connectivity is a single system-wide credential (``LlmConfig``, singleton
row) an admin sets on the System page — not per-project, since an API key
is an org-level resource. Generated text is cached per (project, finding)
in ``FindingRecommendation`` so it's produced once and reused, not
re-requested on every page view.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from marlinspike.models import FindingRecommendation, LlmConfig, db

log = logging.getLogger("marlinspike.llm")

ALLOWED_KEYS = frozenset({"enabled", "base_url", "api_key", "model"})
_TIMEOUT_S = 30
_MAX_TOKENS = 1500

_SYSTEM_PROMPT = (
    "You are a Senior Principal OT/IT Cybersecurity Specialist embedded in MarlinSpike, "
    "an enterprise network traffic analysis, threat detection, and ICS/OT security scanning platform. "
    "You are analyzing a detected risk finding from network traffic capture.\n\n"
    "CRITICAL REQUIREMENT: You MUST format EVERY recommendation using the EXACT standardized Markdown template below. "
    "Do NOT alter the section headers, bold bullet labels, or phase structure.\n\n"
    "### 1. Executive Summary & Vulnerability Details\n"
    "- **Finding Name**: <Title or Category>\n"
    "- **Severity & Impact Score**: <Severity Level> (CVSS / Impact Rating)\n"
    "- **Vulnerability Description**: <Detailed technical explanation of the underlying vulnerability, protocol weakness, or misconfiguration>\n"
    "- **Associated Identifiers**: <CVE IDs, CISA Advisories, or CWE IDs if applicable>\n\n"
    "### 2. Technical & Operational Impact\n"
    "- **Exploitation Feasibility**: <Analysis of attack vectors and ease of exploitation>\n"
    "- **Purdue Model Blast Radius**: <Impact across IT enterprise vs Purdue ICS/OT Control Layers (Level 1/2 Control vs Level 3 Operations)>\n"
    "- **Operational & Safety Consequences**: <Potential effect on physical process safety, operational uptime, confidentiality, or system availability>\n\n"
    "### 3. Step-by-Step Mitigation & Remediation Plan\n"
    "- **Immediate Containment (Phase 1)**:\n"
    "  1. <Immediate action 1: Network micro-segmentation, firewall rule, or VLAN isolation>\n"
    "  2. <Immediate action 2: Traffic filtering or compensating control>\n"
    "- **Long-Term Remediation (Phase 2)**:\n"
    "  1. <Permanent fix 1: Vendor firmware update, patch application, or secure protocol migration>\n"
    "  2. <Permanent fix 2: Credential rotation, access control hardening, or secure configuration>\n"
    "- **Technical Configuration & Verification Commands**:\n"
    "  ```bash\n"
    "  # Specific configuration snippet or verification command\n"
    "  ```\n\n"
    "### 4. Official Vendor Advisories & References\n"
    "- **Vendor Advisories**: <Direct references / links to CISA ICS-CERT, Siemens SSA, Rockwell, Schneider, Microsoft, etc.>\n"
    "- **NVD / MITRE ATT&CK Mapping**: <References to NVD CVE entries or MITRE ATT&CK technique IDs>\n\n"
    "For critical infrastructure or operational technology (OT) assets that cannot tolerate downtime, "
    "prioritize non-disruptive compensating controls (such as micro-segmentation and DPI firewalling) "
    "in Phase 1 over immediate host reboots or aggressive patching."
)


def _header_safe(s: str) -> bool:
    try:
        s.encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def get_config() -> LlmConfig:
    """Return the singleton LlmConfig row, creating it (disabled, empty) if absent."""
    cfg = db.session.get(LlmConfig, 1)
    if cfg is None:
        cfg = LlmConfig(id=1, enabled=False)
        db.session.add(cfg)
        db.session.commit()
    return cfg


def to_dict(cfg: LlmConfig, *, mask_key: bool = True) -> dict[str, Any]:
    api_key = cfg.api_key
    if mask_key and api_key:
        api_key = ("*" * max(len(api_key) - 4, 0)) + api_key[-4:] if len(api_key) > 4 else "****"
    return {
        "enabled": bool(cfg.enabled),
        "base_url": cfg.base_url,
        "api_key": api_key,
        "model": cfg.model,
        "configured": bool(cfg.base_url and cfg.api_key and cfg.model),
    }


def validate(body: dict) -> str | None:
    """Validate a PUT body for the LLM config. Returns an error string, or None if valid."""
    strip_fields(body)
    unknown = set(body.keys()) - ALLOWED_KEYS
    if unknown:
        return f"unknown keys: {', '.join(sorted(unknown))}"
    if "enabled" in body and not isinstance(body["enabled"], bool):
        return "enabled must be a boolean"
    if "base_url" in body and body["base_url"] is not None:
        url = body["base_url"]
        if not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
            return "base_url must be an http(s) URL string"
        if not _header_safe(url):
            return "base_url contains a character that isn't valid in an HTTP request — retype it"
    if "api_key" in body and body["api_key"] is not None:
        if not isinstance(body["api_key"], str):
            return "api_key must be a string"
        if not _header_safe(body["api_key"]):
            return (
                "api_key contains a character that isn't valid in an HTTP header "
                "— if copy-pasted from a page that displays it truncated, that "
                "may be a real '…' character, not three dots; paste the full value"
            )
    if "model" in body and body["model"] is not None and not isinstance(body["model"], str):
        return "model must be a string"
    return None


def validate_effective(cfg_dict: dict) -> str | None:
    """Validate the merged, saved config for completeness (mirrors webhook's
    validate_effective_config) — enabled with a field missing is caught at
    save time instead of on the first recommendation-generation attempt."""
    if not cfg_dict.get("enabled"):
        return None
    required = {"base_url": "Base URL", "api_key": "API key", "model": "Model"}
    missing = [label for key, label in required.items() if not cfg_dict.get(key)]
    if missing:
        return f"LLM connectivity is enabled but missing: {', '.join(missing)}"
    return None


def strip_fields(body: dict) -> None:
    """Strip whitespace from every header-bound field, in place. A trailing
    newline/space from copy-pasting a base URL or API key is a common,
    otherwise-silent way to corrupt it — see webhook.py's identical fix."""
    for key in ("base_url", "api_key", "model"):
        if isinstance(body.get(key), str):
            body[key] = body[key].strip()


def _chat_completion(base_url: str, api_key: str, model: str, user_message: str) -> dict:
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "max_tokens": _MAX_TOKENS,
        "temperature": 0.2,
    }
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            parsed = json.loads(resp.read())
            text = parsed["choices"][0]["message"]["content"].strip()
            return {"ok": True, "text": text, "error": None}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        return {"ok": False, "text": None, "error": detail}
    except UnicodeEncodeError:
        return {
            "ok": False, "text": None,
            "error": (
                "the configured base URL or API key contains a character that isn't "
                "valid in an HTTP header — re-save the LLM settings with the value retyped"
            ),
        }
    except (KeyError, IndexError, json.JSONDecodeError):
        return {"ok": False, "text": None, "error": "unexpected response shape from the LLM endpoint"}
    except Exception as exc:
        return {"ok": False, "text": None, "error": str(exc)}


def _finding_prompt(finding: dict) -> str:
    lines = [
        "=== MARLINSPIKE RISK FINDING DATA ===",
        f"Category: {finding.get('category', 'UNKNOWN')}",
        f"Severity Level: {finding.get('severity', 'UNKNOWN')}",
        f"Engine Description: {finding.get('description', '(none)')}",
    ]

    cvss = finding.get("max_cvss_impact") if finding.get("max_cvss_impact") is not None else finding.get("cvss_impact")
    if cvss is not None:
        lines.append(f"CVSS Score / Impact: {cvss} / 10.0")

    if finding.get("affected_nodes"):
        lines.append(f"Affected Host Assets (IPs/MACs): {', '.join(str(n) for n in finding['affected_nodes'])}")

    if finding.get("affected_edges"):
        lines.append(f"Affected Communication Paths / Flows: {', '.join(str(e) for e in finding['affected_edges'])}")

    if finding.get("attack_ids"):
        lines.append(f"MITRE ATT&CK Techniques: {', '.join(str(t) for t in finding['attack_ids'])}")

    if finding.get("remediation"):
        lines.append(f"Engine Baseline Guidance: {finding['remediation']}")

    if finding.get("source"):
        lines.append(f"Detection Source / DPI Engine: {finding['source']}")

    if finding.get("occurrences"):
        lines.append(f"Historical Occurrences in Project: {finding['occurrences']} scan(s)")

    if finding.get("first_seen_modified") or finding.get("last_seen_modified"):
        lines.append(f"First Observed: {finding.get('first_seen_modified', 'N/A')} | Last Observed: {finding.get('last_seen_modified', 'N/A')}")

    lines.append("\nPlease generate the comprehensive 4-section Security Advisory based on this finding.")
    return "\n".join(lines)


def get_cached(project_id: int, dedup_key: str) -> FindingRecommendation | None:
    return FindingRecommendation.query.filter_by(project_id=project_id, dedup_key=dedup_key).first()


def generate_for_finding(project_id: int, dedup_key: str, finding: dict) -> dict:
    """Generate (or regenerate) a recommendation for one finding and cache it.

    Returns {"ok", "text", "error"}. Never raises — a bad/unreachable LLM
    endpoint must not break the recommendations page for findings that
    already have a cached result.
    """
    cfg = get_config()
    if not cfg.enabled or not cfg.base_url or not cfg.api_key or not cfg.model:
        return {"ok": False, "text": None, "error": "LLM connectivity is not configured"}

    result = _chat_completion(cfg.base_url, cfg.api_key, cfg.model, _finding_prompt(finding))
    if not result["ok"]:
        log.warning(
            "recommendation generation failed project_id=%s dedup_key=%s error=%s",
            project_id, dedup_key, result["error"],
        )
        return result

    try:
        row = get_cached(project_id, dedup_key)
        if row is None:
            row = FindingRecommendation(project_id=project_id, dedup_key=dedup_key)
            db.session.add(row)
        row.recommendation = result["text"]
        row.model = cfg.model
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.warning("failed to cache recommendation project_id=%s dedup_key=%s", project_id, dedup_key, exc_info=True)

    return result


def send_test(cfg: LlmConfig) -> dict:
    """Synchronously fire a trivial prompt to verify connectivity. Returns a UI-facing result dict."""
    if not cfg.base_url or not cfg.api_key or not cfg.model:
        return {"ok": False, "error": "base_url, api_key, and model are all required"}
    result = _chat_completion(
        cfg.base_url, cfg.api_key, cfg.model,
        "Reply with exactly one word: OK.",
    )
    if result["ok"]:
        return {"ok": True, "error": None, "detail": result["text"][:120]}
    return {"ok": False, "error": result["error"]}
