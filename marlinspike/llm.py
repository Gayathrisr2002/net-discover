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
_MAX_TOKENS = 1000

_SYSTEM_PROMPT = (
    "You are a network security analyst embedded in MarlinSpike, a network "
    "traffic analysis and OT/IT security scanning tool. You will be given "
    "one risk finding detected on a monitored network. Provide a comprehensive "
    "remediation analysis including:\n"
    "1. Full details of the vulnerability.\n"
    "2. How the vulnerability affects the system and network (potential impact and consequences).\n"
    "3. Relevant support article links, vendor advisories, or official documentation references.\n"
    "4. Step-by-step resolution instructions for a network/security engineer.\n\n"
    "If the finding involves industrial control system (ICS/OT) protocols or Purdue-level context, "
    "factor that into the recommendation (e.g. segmentation, not simply 'patch it', for "
    "assets that cannot tolerate downtime)."
)


def _header_safe(s: str) -> bool:
    try:
        s.encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def get_config() -> LlmConfig:
    """Return the singleton LlmConfig row, creating it (disabled, empty) if absent."""
    cfg = LlmConfig.query.get(1)
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
        f"Category: {finding.get('category', 'unknown')}",
        f"Severity: {finding.get('severity', 'unknown')}",
        f"Description: {finding.get('description', '(none)')}",
    ]
    if finding.get("affected_nodes"):
        lines.append("Affected assets: " + ", ".join(str(n) for n in finding["affected_nodes"]))
    if finding.get("cvss_impact") is not None:
        lines.append(f"CVSS impact: {finding['cvss_impact']}")
    if finding.get("attack_ids"):
        lines.append("MITRE ATT&CK techniques: " + ", ".join(str(t) for t in finding["attack_ids"]))
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
