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
import secrets
import uuid
from datetime import datetime, timezone

from marlinspike import config
from marlinspike.models import Agent, AgentCredential, AgentEnrollmentToken, CaptureSession, db

_app = None


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
        if agent.status != "online":
            agent.status = "online"
        db.session.commit()


def mark_offline(*, agent_uuid: str) -> None:
    """Best-effort: flip status to offline when a connection drops."""
    app = get_app()
    with app.app_context():
        agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
        if agent is None or agent.status == "revoked":
            return
        agent.status = "offline"
        db.session.commit()


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


def is_agent_revoked(*, agent_uuid: str) -> bool:
    """Checked periodically on already-authenticated connections so a
    revoke-while-connected admin action actually disconnects the agent
    (Phase 2 heartbeat-interval granularity; not instant push — that's
    the Phase 3 command channel's job)."""
    app = get_app()
    with app.app_context():
        agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
        return agent is None or agent.status == "revoked"
