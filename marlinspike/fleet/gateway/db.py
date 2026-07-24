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
import subprocess
import tempfile
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


_INSTANCE_KEY_PREFIX = "fleet:agent_instance:"
_INSTANCE_TTL_S = 120  # a bit above the agent heartbeat timeout (90s, server.py)


def register_agent_instance(*, agent_uuid: str, instance_id: str,
                             admin_host: str, admin_port: int) -> None:
    """Record which gateway instance currently holds this agent's live
    connection (Phase 6.5: horizontal scaling). Best-effort, like every
    other Redis write here — a Flask worker that can't find an instance
    for an agent just falls back to the local admin socket (the
    single-instance default), so a Redis hiccup degrades gracefully rather
    than breaking anything. TTL'd rather than held forever: if this
    instance crashes without a clean disconnect, the entry expires on its
    own instead of permanently misdirecting admin commands at a dead
    process — refreshed on every throttled heartbeat DB write
    (server.py), so a live connection's entry never actually expires."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.set(
            _INSTANCE_KEY_PREFIX + agent_uuid,
            json.dumps({"instance_id": instance_id, "admin_host": admin_host, "admin_port": admin_port}),
            ex=_INSTANCE_TTL_S,
        )
    except Exception:
        log.exception("failed to register instance for agent %s", agent_uuid)


def unregister_agent_instance(*, agent_uuid: str) -> None:
    """Best-effort: clear the registry entry immediately on a clean
    disconnect, rather than waiting out the TTL."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.delete(_INSTANCE_KEY_PREFIX + agent_uuid)
    except Exception:
        log.exception("failed to unregister instance for agent %s", agent_uuid)


def lookup_agent_instance(agent_uuid: str) -> dict | None:
    """Flask-side lookup: which gateway instance (if any, if Redis is even
    configured) currently holds this agent's connection. Returns None on
    any failure or cache miss — the caller's fallback is always "use the
    local admin socket", which is correct for the common single-instance
    deployment where this registry is never even populated meaningfully
    beyond one instance_id."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_INSTANCE_KEY_PREFIX + agent_uuid)
    except Exception:
        log.exception("failed to look up instance for agent %s", agent_uuid)
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


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


def _fleet_ca_configured() -> bool:
    return bool(config.FLEET_CA_CERT and config.FLEET_CA_KEY
                and os.path.isfile(config.FLEET_CA_CERT) and os.path.isfile(config.FLEET_CA_KEY))


def _sign_csr(csr_pem: str, cn: str) -> tuple[str, str] | None:
    """Sign an agent's CSR with the fleet CA, forcing the subject CN to the
    server-issued agent_uuid (never trusting whatever CN the agent's own
    CSR happened to carry). Returns (cert_pem, sha256_fingerprint_hex), or
    None if no fleet CA is configured — enrollment then falls back to
    bearer-credential-only auth, exactly as it worked before this upgrade.

    Shells out to the openssl CLI rather than adding a cryptography
    dependency — consistent with this project's existing dev-cert tooling
    (scripts/gen_dev_tls_cert.sh) and capd/gateway's stdlib-first posture.
    The agent's private key never reaches the gateway; only the CSR
    (public key + a throwaway self-chosen CN) is sent over the wire.
    """
    if not _fleet_ca_configured():
        return None

    with tempfile.TemporaryDirectory() as tmp:
        csr_path = os.path.join(tmp, "agent.csr")
        cert_path = os.path.join(tmp, "agent.crt")
        with open(csr_path, "w", encoding="utf-8") as f:
            f.write(csr_pem)

        # -set_serial with a random 128-bit value rather than -CAcreateserial:
        # the latter reads/writes a .srl tracking file next to the CA cert,
        # which is normally bind-mounted read-only into the gateway
        # container (../certs:/certs:ro in docker-compose.yml — deliberately
        # not writable, same posture as capd's captures mount) and wouldn't
        # be concurrency-safe across simultaneous enrollments anyway. A
        # random serial needs no shared mutable state at all.
        serial = f"0x{secrets.token_hex(16)}"
        try:
            subprocess.run(
                [
                    "openssl", "x509", "-req",
                    "-in", csr_path,
                    "-CA", config.FLEET_CA_CERT, "-CAkey", config.FLEET_CA_KEY,
                    "-set_serial", serial,
                    "-out", cert_path,
                    "-days", "825",
                    "-copy_extensions", "none",
                    "-subj", f"/CN={cn}",
                ],
                check=True, capture_output=True, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            log.exception("failed to sign agent CSR for cn=%s", cn)
            return None

        with open(cert_path, "r", encoding="utf-8") as f:
            cert_pem = f.read()

        der = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-outform", "der"],
            check=True, capture_output=True, timeout=10,
        ).stdout
        fingerprint = hashlib.sha256(der).hexdigest()
        return cert_pem, fingerprint


def enroll_agent(*, raw_token: str, name: str | None, agent_version: str | None,
                  os_info: str | None, csr_pem: str | None = None) -> dict:
    """Redeem a one-time enrollment token, create (or, for a rotation token
    — see AgentEnrollmentToken.agent_id — reuse) the Agent row, mint a
    long-lived credential. Returns {"agent_uuid": ..., "credential": ...}
    (the raw credential — shown once, never recoverable after this call),
    plus {"client_cert_pem": ...} when the agent sent a CSR and a fleet CA
    is configured (Phase 6 mTLS) — omitted entirely otherwise, so an agent
    that didn't send a CSR (or a gateway with no CA set up) enrolls exactly
    as it did before this upgrade.
    """
    app = get_app()
    with app.app_context():
        token_hash = _hash_token(raw_token)
        # with_for_update(): without a row lock here, two concurrent
        # redemptions of the same raw token (e.g. a replayed/intercepted
        # token racing the legitimate one) could both read used_at=None
        # before either commits, both pass the check below, and both mint
        # a live credential from one supposedly single-use token. The lock
        # makes the second request block until the first's commit, after
        # which it correctly sees used_at already set.
        token = AgentEnrollmentToken.query.filter_by(token_hash=token_hash).with_for_update().first()
        if token is None:
            raise GatewayAuthError("invalid enrollment token")
        if token.used_at is not None:
            raise GatewayAuthError("enrollment token already used")
        now = datetime.now(timezone.utc)
        if token.expires_at is not None and token.expires_at.replace(tzinfo=timezone.utc) < now:
            raise GatewayAuthError("enrollment token expired")

        token.used_at = now

        if token.agent_id is not None:
            # Credential rotation, not a new enrollment: same agent_uuid,
            # same history (ScanHistory/CaptureSession rows keep pointing at
            # this agent_id) — only the credential/cert actually changes.
            agent = db.session.get(Agent, token.agent_id)
            if agent is None:
                raise GatewayAuthError("agent no longer exists")
            if name:
                agent.name = name[:200]
            agent.agent_version = agent_version
            agent.os_info = os_info
            agent.last_seen_at = now
            if agent.status == "revoked":
                agent.status = "enrolled"
        else:
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

        result = {"agent_uuid": agent.agent_uuid, "credential": raw_credential}
        if csr_pem:
            signed = _sign_csr(csr_pem, cn=agent.agent_uuid)
            if signed is not None:
                cert_pem, fingerprint = signed
                cred.cert_fingerprint_sha256 = fingerprint
                result["client_cert_pem"] = cert_pem

        db.session.add(cred)
        db.session.commit()

        from marlinspike import __version__ as gateway_version
        from marlinspike.audit import audit
        audit("fleet.agent_enrolled", target_type="agent", target_id=str(agent.id),
              detail=f"site_id={token.site_id} name={agent.name!r}")
        # Purely informational (see server.py's wire compatibility contract
        # docstring) — a version mismatch is never itself a reason to
        # reject an agent, just something worth an operator noticing.
        if agent_version and agent_version != gateway_version:
            log.info("agent %s enrolled with agent_version=%s (gateway is %s)",
                      agent.agent_uuid, agent_version, gateway_version)
        _publish_agent_status(agent_uuid=agent.agent_uuid, site_id=agent.site_id, status=agent.status)

        return result


def authenticate_agent(*, agent_uuid: str, raw_credential: str,
                        peer_cert_fingerprint: str | None = None) -> dict:
    """Verify a returning agent's long-lived credential. Returns
    {"agent_id": int} on success. Raises GatewayAuthError on any failure —
    deliberately the same message for "no such agent", "revoked", "bad
    credential", and "cert mismatch" so a failed attempt can't be used to
    enumerate agent_uuids or probe which check tripped.

    When this agent's credential has a cert_fingerprint_sha256 on file
    (Phase 6: it was issued a client cert at enrollment), the connection's
    peer_cert_fingerprint must match it — a stolen bearer credential alone
    is no longer sufficient once an agent has been upgraded to mTLS.
    Agents enrolled before the mTLS upgrade (fingerprint NULL) are
    unaffected — this is intentionally opt-in per-agent, not a hard cutover.
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

        if cred.cert_fingerprint_sha256 and cred.cert_fingerprint_sha256 != peer_cert_fingerprint:
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


def _session_owned_by_agent(cs: CaptureSession, agent_uuid: str) -> bool:
    """True iff `cs` is a remote-agent session actually owned by the agent
    claiming to report on it. Without this check, any authenticated agent
    could inject stats/reports for a session_uuid belonging to a
    *different* tenant's agent — session_uuid is a UUID4 (unguessable in
    practice), but this is real defense-in-depth, not redundant: an agent
    is only ever supposed to know the session_uuids the gateway itself
    pushed to it via `start`, and this closes off any other path
    (log scraping, a bug elsewhere) from being usable cross-tenant."""
    if cs.agent_id is None:
        return False  # a local (non-agent) session — no agent should ever report on it
    agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
    return agent is not None and agent.id == cs.agent_id


def record_session_stats(*, session_uuid: str, bytes_captured: int, rotation_count: int,
                          agent_uuid: str) -> None:
    """Persist a periodic progress snapshot an agent relayed for one of its
    active capture sessions. Writes straight into the same CaptureSession
    columns the local capture path already uses (capture/api.py's
    stop_session sets these from capd's own response) — this is what lets
    GET /api/capture/sessions/<id> show live-ish progress for a remote
    session with zero changes to the report-reading side, matching the
    plan's 'same endpoints serve both local and remote captures' principle.
    Best-effort: an unknown/already-stopped session_uuid, or one this
    agent doesn't actually own, is not an error, just an event dropped
    silently — either arrived too late to matter or is worth logging as
    a possible cross-tenant probe, never worth crashing the connection over."""
    app = get_app()
    with app.app_context():
        cs = CaptureSession.query.filter_by(session_uuid=session_uuid).first()
        if cs is None or cs.status not in ("pending", "running"):
            return
        if not _session_owned_by_agent(cs, agent_uuid):
            log.warning("agent %s sent session_stats for session %s it doesn't own — dropping",
                        agent_uuid, session_uuid)
            return
        cs.bytes_captured = bytes_captured
        cs.rotation_count = max(cs.rotation_count, rotation_count)
        db.session.commit()


def ingest_report(*, session_uuid: str, filename: str, report_text: str,
                   pcap_filename: str | None, agent_uuid: str) -> None:
    """Write a report an agent finished analyzing locally to the *same*
    REPORTS_DIR/<owner_user_id>/<project_id>/<filename> path the local
    upload-and-scan flow already uses, and create a ScanHistory row for
    it — this is what makes it show up in the existing report-browsing
    UI indistinguishable from a locally-produced report, with zero UI
    changes. engine_pid/engine_argv stay NULL (no local PID to reap —
    see recovery.py's agent_id-aware reaper scoping).

    Best-effort: an unknown/deleted session_uuid, a session this agent
    doesn't own, or malformed report text is logged and dropped, not
    raised — a stray late-arriving report from a since-cleaned-up session
    shouldn't crash the gateway's event loop.
    """
    try:
        json.loads(report_text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.warning("session=%s dropping malformed report %s (%d bytes)",
                     session_uuid, filename, len(report_text))
        return

    # `filename` and `pcap_filename` arrive from an authenticated-but-not-
    # trusted agent (the whole point of mTLS/credential auth in Phase 6 is
    # to raise the bar on a stolen-credential attacker, not to make every
    # field they send safe to use verbatim). Without this, a compromised
    # agent could send filename="../../../../etc/cron.d/x" or an absolute
    # path — os.path.join silently discards out_dir for an absolute
    # second argument — and write arbitrary content to any path this
    # process can write. Collapse to a bare basename and reject anything
    # that isn't a plain, safe filename outright.
    safe_filename = os.path.basename(filename or "")
    if not safe_filename or safe_filename in (".", "..") or not safe_filename.endswith(".json"):
        log.warning("session=%s rejecting unsafe report filename %r from agent %s",
                     session_uuid, filename, agent_uuid)
        return
    if pcap_filename:
        pcap_filename = os.path.basename(pcap_filename)

    app = get_app()
    with app.app_context():
        cs = CaptureSession.query.filter_by(session_uuid=session_uuid).first()
        if cs is None or cs.project_id is None:
            log.warning("session=%s unknown or project-less — dropping report %s",
                         session_uuid, safe_filename)
            return
        if not _session_owned_by_agent(cs, agent_uuid):
            log.warning("agent %s sent report_complete for session %s it doesn't own — dropping",
                        agent_uuid, session_uuid)
            return
        project = db.session.get(Project, cs.project_id)
        if project is None:
            log.warning("session=%s project %s gone — dropping report %s",
                         session_uuid, cs.project_id, safe_filename)
            return

        owner_uid = project.user_id
        out_dir = os.path.join(config.REPORTS_DIR, str(owner_uid), str(project.id))
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, safe_filename)
        # Belt-and-suspenders: confirm the resolved path is still actually
        # inside out_dir even after basename-only normalization (defends
        # against any future change to the sanitization above regressing
        # this) before ever opening it for write.
        if os.path.commonpath([os.path.realpath(out_dir), os.path.realpath(report_path)]) != os.path.realpath(out_dir):
            log.warning("session=%s report path %r escaped out_dir — dropping", session_uuid, report_path)
            return
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
