"""DB access for the fleet gateway — a plain asyncio process, not Flask.

The gateway needs the same models/tables the web app uses (Site, Agent,
AgentEnrollmentToken, AgentCredential) but doesn't run inside a Flask
request. Flask-SQLAlchemy's ``db.session`` needs an app context to work,
so we build a minimal Flask app here purely to get that context — the
exact pattern marlinspike/db_cli.py already uses to give Flask-Migrate a
db/app context outside of create_app()'s full bootstrap.

Every function here is synchronous (ordinary SQLAlchemy calls) — the
asyncio server calls these via ``loop.run_in_executor(None, fn, ...)`` so
a DB round-trip never blocks the event loop.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone

from marlinspike import config
from marlinspike.models import (
    Agent,
    AgentCredential,
    AgentEnrollmentToken,
    CaptureSession,
    Project,
    ScanHistory,
    db,
)

log = logging.getLogger("fleet.gateway.db")

_app = None
_redis_client = None


def _get_redis():
    """Lazily build (once) a synchronous redis-py client for status
    publishing. Returns None if no Redis URL is configured — status
    publishing is a nice-to-have (Flask falls back to plain DB polling
    without it), never a hard requirement to enroll/auth/heartbeat."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not config.FLEET_STATUS_REDIS_URL:
        return None
    import redis
    _redis_client = redis.from_url(config.FLEET_STATUS_REDIS_URL)
    return _redis_client


def _publish_agent_status(*, agent_uuid: str, site_id: int, status: str) -> None:
    """Best-effort: publish a status change for live fleet-page updates
    (fleet/api.py's SSE endpoint). Never raises — a Redis hiccup should
    never take down enroll/auth/heartbeat handling."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.publish(config.FLEET_STATUS_REDIS_CHANNEL, json.dumps({
            "agent_uuid": agent_uuid, "site_id": site_id, "status": status,
        }))
    except Exception:
        log.exception("failed to publish agent status for %s", agent_uuid)


def get_app():
    """Build (once) and return a minimal Flask app bound to the real DB.

    Mirrors db_cli.py's _build minimal app_ pattern — no routes, no
    bootstrap, just enough for db.session to work under app_context().
    """
    global _app
    if _app is not None:
        return _app

    from flask import Flask

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.secret_key = config.SECRET_KEY or "fleet-gateway-placeholder"
    db.init_app(app)
    _app = app
    return app


def _hash_token(raw: str) -> str:
    """SHA-256 hash a token/credential for storage. Mirrors fleet/api.py's
    _hash_token (and auth.py's _hash_token) — never store raw secrets."""
    return hashlib.sha256(raw.encode()).hexdigest()


class GatewayAuthError(Exception):
    """Raised for any enroll/auth failure. Message is safe to send to the client."""


def enroll_agent(*, raw_token: str, name: str | None, agent_version: str | None,
                  os_info: str | None) -> dict:
    """Redeem a one-time enrollment token, create the Agent row, mint a
    long-lived credential. Returns {"agent_uuid": ..., "credential": ...}
    (the raw credential — shown once, never recoverable after this call).
    """
    app = get_app()
    with app.app_context():
        token_hash = _hash_token(raw_token)
        token = AgentEnrollmentToken.query.filter_by(token_hash=token_hash).first()
        if token is None:
            raise GatewayAuthError("invalid enrollment token")
        if token.used_at is not None:
            raise GatewayAuthError("enrollment token already used")
        now = datetime.now(timezone.utc)
        if token.expires_at is not None and token.expires_at.replace(tzinfo=timezone.utc) < now:
            raise GatewayAuthError("enrollment token expired")

        token.used_at = now

        agent = Agent(
            agent_uuid=str(uuid.uuid4()),
            site_id=token.site_id,
            name=(name or f"agent-{secrets.token_hex(4)}")[:200],
            status="enrolled",
            agent_version=agent_version,
            os_info=os_info,
            last_seen_at=now,
        )
        db.session.add(agent)
        db.session.flush()  # populate agent.id for the credential FK

        raw_credential = secrets.token_urlsafe(32)
        cred = AgentCredential(agent_id=agent.id, key_hash=_hash_token(raw_credential))
        db.session.add(cred)
        db.session.commit()

        from marlinspike.audit import audit
        audit("fleet.agent_enrolled", target_type="agent", target_id=str(agent.id),
              detail=f"site_id={token.site_id} name={agent.name!r}")
        _publish_agent_status(agent_uuid=agent.agent_uuid, site_id=agent.site_id, status=agent.status)

        return {"agent_uuid": agent.agent_uuid, "credential": raw_credential}


def authenticate_agent(*, agent_uuid: str, raw_credential: str) -> dict:
    """Verify a returning agent's long-lived credential. Returns
    {"agent_id": int} on success. Raises GatewayAuthError on any failure —
    deliberately the same message for "no such agent", "revoked", and "bad
    credential" so a failed attempt can't be used to enumerate agent_uuids.
    """
    app = get_app()
    with app.app_context():
        agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
        if agent is None or agent.status == "revoked":
            raise GatewayAuthError("unauthorized")

        cred_hash = _hash_token(raw_credential)
        cred = AgentCredential.query.filter_by(
            agent_id=agent.id, key_hash=cred_hash, revoked_at=None
        ).first()
        if cred is None:
            raise GatewayAuthError("unauthorized")

        agent.status = "online"
        agent.last_seen_at = datetime.now(timezone.utc)
        db.session.commit()
        _publish_agent_status(agent_uuid=agent.agent_uuid, site_id=agent.site_id, status=agent.status)
        return {"agent_id": agent.id}


def record_heartbeat(*, agent_uuid: str) -> None:
    """Update last_seen_at (and flip back to online if it had lapsed).
    Best-effort — a missing/revoked agent here just means a stale
    connection is about to be dropped; nothing to raise for the caller."""
    app = get_app()
    with app.app_context():
        agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
        if agent is None or agent.status == "revoked":
            return
        agent.last_seen_at = datetime.now(timezone.utc)
        was_online = agent.status == "online"
        agent.status = "online"
        db.session.commit()
        # Only publish on an actual transition — every heartbeat publishing
        # would just be noise the SSE endpoint filters right back out, and
        # the fleet UI shows last-seen via its own periodic agent-list poll.
        if not was_online:
            _publish_agent_status(agent_uuid=agent.agent_uuid, site_id=agent.site_id, status=agent.status)


def mark_offline(*, agent_uuid: str) -> None:
    """Best-effort: flip status to offline when a connection drops."""
    app = get_app()
    with app.app_context():
        agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
        if agent is None or agent.status == "revoked":
            return
        agent.status = "offline"
        db.session.commit()
        _publish_agent_status(agent_uuid=agent.agent_uuid, site_id=agent.site_id, status=agent.status)


def record_session_stats(*, session_uuid: str, bytes_captured: int, rotation_count: int) -> None:
    """Persist a periodic progress snapshot an agent relayed for one of its
    active capture sessions. Writes straight into the same CaptureSession
    columns the local capture path already uses (capture/api.py's
    stop_session sets these from capd's own response) — this is what lets
    GET /api/capture/sessions/<id> show live-ish progress for a remote
    session with zero changes to the report-reading side, matching the
    plan's 'same endpoints serve both local and remote captures' principle.
    Best-effort: an unknown/already-stopped session_uuid is not an error,
    just a stats event that arrived too late to matter."""
    app = get_app()
    with app.app_context():
        cs = CaptureSession.query.filter_by(session_uuid=session_uuid).first()
        if cs is None or cs.status not in ("pending", "running"):
            return
        cs.bytes_captured = bytes_captured
        cs.rotation_count = max(cs.rotation_count, rotation_count)
        db.session.commit()


def ingest_report(*, session_uuid: str, filename: str, report_text: str,
                   pcap_filename: str | None) -> None:
    """Write a report an agent finished analyzing locally to the *same*
    REPORTS_DIR/<owner_user_id>/<project_id>/<filename> path the local
    upload-and-scan flow already uses, and create a ScanHistory row for
    it — this is what makes it show up in the existing report-browsing
    UI indistinguishable from a locally-produced report, with zero UI
    changes. engine_pid/engine_argv stay NULL (no local PID to reap —
    see recovery.py's agent_id-aware reaper scoping).

    Best-effort: an unknown/deleted session_uuid or malformed report text
    is logged and dropped, not raised — a stray late-arriving report from
    a since-cleaned-up session shouldn't crash the gateway's event loop.
    """
    try:
        json.loads(report_text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.warning("session=%s dropping malformed report %s (%d bytes)",
                     session_uuid, filename, len(report_text))
        return

    app = get_app()
    with app.app_context():
        cs = CaptureSession.query.filter_by(session_uuid=session_uuid).first()
        if cs is None or cs.project_id is None:
            log.warning("session=%s unknown or project-less — dropping report %s",
                         session_uuid, filename)
            return
        project = db.session.get(Project, cs.project_id)
        if project is None:
            log.warning("session=%s project %s gone — dropping report %s",
                         session_uuid, cs.project_id, filename)
            return

        owner_uid = project.user_id
        out_dir = os.path.join(config.REPORTS_DIR, str(owner_uid), str(project.id))
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        node_count = edge_count = 0
        try:
            parsed = json.loads(report_text)
            topology = parsed.get("topology") or parsed
            node_count = len(topology.get("nodes") or [])
            edge_count = len(topology.get("edges") or [])
        except Exception:
            pass  # cosmetic counts only — never worth failing ingestion over

        now = datetime.now(timezone.utc)
        sh = ScanHistory(
            run_id=str(uuid.uuid4()),
            user_id=owner_uid,
            project_id=project.id,
            agent_id=cs.agent_id,
            command="chain",
            scan_profile="fast",
            pcap_source=pcap_filename,
            status="completed",
            started_at=cs.started_at or now,
            completed_at=now,
            report_path=report_path,
            node_count=node_count,
            edge_count=edge_count,
        )
        db.session.add(sh)
        db.session.commit()
        log.info("session=%s ingested report -> %s (ScanHistory id=%s)", session_uuid, report_path, sh.id)


def is_agent_revoked(*, agent_uuid: str) -> bool:
    """Checked periodically on already-authenticated connections so a
    revoke-while-connected admin action actually disconnects the agent
    (Phase 2 heartbeat-interval granularity; not instant push — that's
    the Phase 3 command channel's job)."""
    app = get_app()
    with app.app_context():
        agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
        return agent is None or agent.status == "revoked"
