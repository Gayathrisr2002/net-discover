"""Flask blueprint mounted at /api/fleet/*.

Phase 1 of the distributed-agent architecture: pure schema + admin UI for
managing sites and enrolling remote sensor agents. No live transport exists
yet — nothing here dials out or accepts agent connections. See
/root/.claude/plans/bright-jumping-tower.md for the full phased plan.

Mirrors marlinspike/capture/api.py's structure (blueprint-per-concern,
local ACL check to avoid importing from app.py and creating a circular
import — app.py registers this blueprint).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

from marlinspike import config
from marlinspike.audit import audit
from marlinspike.auth import login_required
from marlinspike.capture.api import _parse_policy, _resolve_interface_allowlist, _validate_policy_body
from marlinspike.models import (
    Agent,
    AgentCredential,
    AgentEnrollmentToken,
    Project,
    Site,
    SiteMember,
    User,
    db,
)

bp = Blueprint("fleet", __name__, url_prefix="/api/fleet")

ENROLLMENT_TOKEN_TTL_MINUTES = 60

# Mirrors app.py's _MEMBER_ROLE_RANK / _VALID_MEMBER_ROLES exactly (kept as a
# local copy, not an import, for the same reason capture/api.py doesn't
# import _get_project_for_user from app.py: app.py registers this blueprint,
# so importing back from app.py would be circular).
_MEMBER_ROLE_RANK: dict[str, int] = {"viewer": 1, "editor": 2, "owner": 3}
_VALID_MEMBER_ROLES = frozenset(_MEMBER_ROLE_RANK)


def _get_site_for_user(site_id: int, min_role: str = "viewer") -> "Site | None":
    """Return the site if the current session user can access it.

    Mirrors app.py's _get_project_for_user: access is granted when the user
    created the site (always owner) OR has a SiteMember row whose role rank
    >= min_role. Returns None when the site doesn't exist or access denied.
    """
    uid = session.get("user_id")
    if not uid:
        return None
    site = db.session.get(Site, site_id)
    if site is None:
        return None
    if site.created_by == uid:
        return site
    member = SiteMember.query.filter_by(site_id=site_id, user_id=uid).first()
    if member and _MEMBER_ROLE_RANK.get(member.role, 0) >= _MEMBER_ROLE_RANK.get(min_role, 1):
        return site
    return None


def _get_project_for_user(pid: int, min_role: str = "viewer") -> "Project | None":
    """Local copy of app.py's project ACL check — a site must bind to a
    project the caller can at least edit, and this blueprint can't import
    app.py's version without a circular import."""
    from marlinspike.models import ProjectMember

    uid = session.get("user_id")
    if not uid:
        return None
    proj = db.session.get(Project, pid)
    if proj is None:
        return None
    if proj.user_id == uid:
        return proj
    member = ProjectMember.query.filter_by(project_id=pid, user_id=uid).first()
    if member and _MEMBER_ROLE_RANK.get(member.role, 0) >= _MEMBER_ROLE_RANK.get(min_role, 1):
        return proj
    return None


def _hash_token(raw: str) -> str:
    """SHA-256 hash a token for storage. Never store raw tokens (mirrors auth.py:_hash_token)."""
    return hashlib.sha256(raw.encode()).hexdigest()


def _force_disconnect(agent_uuid: str) -> None:
    """Best-effort: drop this agent's live gateway connection right now
    (Phase 6.2), instead of leaving a revoked/rotated agent connected
    until its next heartbeat-interval revocation check. Never raises —
    the caller's DB-side revocation has already committed regardless of
    whether the gateway is even reachable (e.g. the `fleet` profile isn't
    running in this deployment at all)."""
    from marlinspike.capture.client import CapdUnavailable
    from marlinspike.fleet.gateway_client import GatewayAdminClient

    try:
        GatewayAdminClient(
            config.FLEET_GATEWAY_ADMIN_SOCKET, agent_uuid,
            timeout=config.FLEET_GATEWAY_ADMIN_TIMEOUT_S,
        ).disconnect_agent()
    except CapdUnavailable:
        pass  # gateway not running — agent was never connected here anyway
    except Exception:
        import logging
        logging.getLogger(__name__).exception("failed to force-disconnect agent %s", agent_uuid)


def _serialize_site(site: Site, *, agent_count: int | None = None) -> dict:
    return {
        "id": site.id,
        "name": site.name,
        "project_id": site.project_id,
        "created_by": site.created_by,
        "created_at": site.created_at.isoformat() if site.created_at else None,
        "agent_count": agent_count,
    }


def _serialize_agent(agent: Agent) -> dict:
    return {
        "id": agent.id,
        "agent_uuid": agent.agent_uuid,
        "site_id": agent.site_id,
        "name": agent.name,
        "status": agent.status,
        "agent_version": agent.agent_version,
        "os_info": agent.os_info,
        "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "revoked_at": agent.revoked_at.isoformat() if agent.revoked_at else None,
    }


# ── Sites ─────────────────────────────────────────────────────────

@bp.route("/sites", methods=["GET"])
@login_required
def list_sites():
    from sqlalchemy import or_

    uid = session["user_id"]
    shared_site_ids = db.session.query(SiteMember.site_id).filter_by(user_id=uid)
    sites = Site.query.filter(
        or_(Site.created_by == uid, Site.id.in_(shared_site_ids))
    ).order_by(Site.created_at).all()
    result = []
    for s in sites:
        agent_count = Agent.query.filter_by(site_id=s.id).filter(Agent.status != "revoked").count()
        result.append(_serialize_site(s, agent_count=agent_count))
    return jsonify({"ok": True, "sites": result})


@bp.route("/sites", methods=["POST"])
@login_required
def create_site():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    project_id = body.get("project_id")
    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    try:
        project_id = int(project_id)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "project_id is required"}), 400

    proj = _get_project_for_user(project_id, "editor")
    if not proj:
        return jsonify({"ok": False, "error": "Project not found"}), 404

    site = Site(name=name, project_id=project_id, created_by=session["user_id"])
    db.session.add(site)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"ok": False, "error": "A site with that name already exists in this project"}), 409

    audit("fleet.site_created", target_type="site", target_id=str(site.id),
          detail=f"project_id={project_id} name={name!r}")
    return jsonify({"ok": True, "site": _serialize_site(site, agent_count=0)}), 201


@bp.route("/sites/<int:site_id>", methods=["GET"])
@login_required
def get_site(site_id):
    site = _get_site_for_user(site_id)
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    agent_count = Agent.query.filter_by(site_id=site.id).filter(Agent.status != "revoked").count()
    return jsonify({"ok": True, "site": _serialize_site(site, agent_count=agent_count)})


# ── Site members ─────────────────────────────────────────────────
# Mirrors app.py's /api/projects/<pid>/members routes exactly — same
# shape, same rules (creator is an implicit, unremovable, unchangeable
# owner; SiteMember only holds invited members). Exercises the ACL
# helper that's existed since Phase 1 with no UI to actually add anyone.

@bp.route("/sites/<int:site_id>/members", methods=["GET"])
@login_required
def list_site_members(site_id):
    site = _get_site_for_user(site_id)
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    creator = db.session.get(User, site.created_by)
    members = [{
        "user_id": site.created_by,
        "username": creator.username if creator else "unknown",
        "role": "owner",
        "is_creator": True,
        "invited_by": None,
        "created_at": None,
    }]
    for m in SiteMember.query.filter_by(site_id=site_id).all():
        u = db.session.get(User, m.user_id)
        members.append({
            "user_id": m.user_id,
            "username": u.username if u else "unknown",
            "role": m.role,
            "is_creator": False,
            "invited_by": m.invited_by,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        })
    return jsonify({"ok": True, "members": members})


@bp.route("/sites/<int:site_id>/members", methods=["POST"])
@login_required
def add_site_member(site_id):
    site = _get_site_for_user(site_id, "owner")
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    role = body.get("role", "viewer")
    if role not in _VALID_MEMBER_ROLES:
        return jsonify({"ok": False, "error": f"role must be one of: {sorted(_VALID_MEMBER_ROLES)}"}), 400
    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if target.id == site.created_by:
        return jsonify({"ok": False, "error": "Site creator is already an owner"}), 409
    existing = SiteMember.query.filter_by(site_id=site_id, user_id=target.id).first()
    if existing:
        existing.role = role
    else:
        existing = SiteMember(site_id=site_id, user_id=target.id, role=role, invited_by=session["user_id"])
        db.session.add(existing)
    db.session.commit()

    audit("fleet.site_member_added", target_type="site", target_id=str(site_id),
          detail=f"user_id={target.id} username={target.username!r} role={role}")
    return jsonify({"ok": True, "user_id": target.id, "username": target.username, "role": role})


@bp.route("/sites/<int:site_id>/members/<int:uid>", methods=["PUT"])
@login_required
def update_site_member(site_id, uid):
    site = _get_site_for_user(site_id, "owner")
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    if uid == site.created_by:
        return jsonify({"ok": False, "error": "Cannot change the site creator's role"}), 400
    body = request.get_json(silent=True) or {}
    role = body.get("role")
    if role not in _VALID_MEMBER_ROLES:
        return jsonify({"ok": False, "error": f"role must be one of: {sorted(_VALID_MEMBER_ROLES)}"}), 400
    member = SiteMember.query.filter_by(site_id=site_id, user_id=uid).first()
    if not member:
        return jsonify({"ok": False, "error": "Member not found"}), 404
    member.role = role
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/sites/<int:site_id>/members/<int:uid>", methods=["DELETE"])
@login_required
def remove_site_member(site_id, uid):
    site = _get_site_for_user(site_id, "owner")
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    if uid == site.created_by:
        return jsonify({"ok": False, "error": "Cannot remove the site creator"}), 400
    member = SiteMember.query.filter_by(site_id=site_id, user_id=uid).first()
    if member:
        db.session.delete(member)
        db.session.commit()
    return jsonify({"ok": True})


# ── Site capture policy ──────────────────────────────────────────
# Mirrors capture/api.py's GET/PUT /api/capture/policy/<pid> exactly —
# reuses that module's parse/validate helpers rather than duplicating them
# (both live in the same deployable package, unlike the agent's
# deliberately-duplicated wire framing).

@bp.route("/sites/<int:site_id>/policy", methods=["GET"])
@login_required
def get_site_policy(site_id):
    site = _get_site_for_user(site_id, "owner")
    if site is None:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    policy = _parse_policy(site.capture_policy)
    return jsonify({
        "ok": True,
        "site_id": site_id,
        "policy": policy,
        "effective_allowed_interfaces": _resolve_interface_allowlist(policy),
    })


@bp.route("/sites/<int:site_id>/policy", methods=["PUT"])
@login_required
def set_site_policy(site_id):
    site = _get_site_for_user(site_id, "owner")
    if site is None:
        return jsonify({"ok": False, "error": "Site not found"}), 404

    body = request.get_json(silent=True)
    if body is None or not isinstance(body, dict):
        return jsonify({"ok": False, "error": "JSON body required"}), 400

    err = _validate_policy_body(body)
    if err:
        return jsonify({"ok": False, "error": f"invalid policy: {err}"}), 400

    old_raw = site.capture_policy
    site.capture_policy = json.dumps(body) if body else None
    db.session.commit()

    audit("fleet.site_policy_set", target_type="site", target_id=str(site_id),
          detail=json.dumps({
              "site_id": site_id,
              "old_policy": json.loads(old_raw) if old_raw else None,
              "new_policy": body,
          }))
    return jsonify({"ok": True, "policy": body})


# ── Enrollment tokens ────────────────────────────────────────────

@bp.route("/sites/<int:site_id>/enrollment-tokens", methods=["POST"])
@login_required
def issue_enrollment_token(site_id):
    """Issue a one-time enrollment token for a new agent at this site.

    The raw token is returned exactly once, to the authenticated, already-
    authorized caller who requested it — unlike auth.py's password-reset
    token (deliberately never returned in a response, since an unauthenticated
    party can trigger that flow for someone else's account), this token is
    minted on-demand by a site editor/owner for their own use, so returning
    it directly here is the correct and intended UX (same shape as e.g. a
    personal access token shown once at creation).
    """
    site = _get_site_for_user(site_id, "editor")
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404

    raw_token = secrets.token_urlsafe(32)
    token = AgentEnrollmentToken(
        site_id=site_id,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=ENROLLMENT_TOKEN_TTL_MINUTES),
        created_by=session["user_id"],
    )
    db.session.add(token)
    db.session.commit()

    audit("fleet.enrollment_token_issued", target_type="site", target_id=str(site_id))
    return jsonify({
        "ok": True,
        "token": raw_token,
        "expires_at": token.expires_at.isoformat(),
    }), 201


# ── Agents ────────────────────────────────────────────────────────

@bp.route("/sites/<int:site_id>/agents", methods=["GET"])
@login_required
def list_agents(site_id):
    site = _get_site_for_user(site_id)
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    agents = Agent.query.filter_by(site_id=site_id).order_by(Agent.created_at).all()
    return jsonify({"ok": True, "agents": [_serialize_agent(a) for a in agents]})


@bp.route("/sites/<int:site_id>/stream", methods=["GET"])
@login_required
def stream_site_status(site_id):
    """Live agent status updates for one site (Phase 5).

    Agent status changes happen in the fleet gateway — a separate process
    from every Flask/gunicorn worker — so there's no in-process signal to
    push from the way capture/api.py's local StatsHub can. Redis pub/sub
    is the cross-process/cross-worker bridge (gateway publishes, every
    subscribed worker's SSE connection gets a copy — the same reason
    RATELIMIT_STORAGE_URI already needs to be shared, not per-worker).
    Falls back to nothing (no live updates, just the periodic poll the
    fleet page already does) if no Redis URL is configured.
    """
    site = _get_site_for_user(site_id)
    if site is None:
        return jsonify({"ok": False, "error": "Site not found"}), 404

    if not config.FLEET_STATUS_REDIS_URL:
        def _unavailable():
            yield ": fleet status streaming unavailable (no Redis configured)\n\n"
        return Response(stream_with_context(_unavailable()), mimetype="text/event-stream")

    import redis

    @stream_with_context
    def _gen():
        r = redis.from_url(config.FLEET_STATUS_REDIS_URL)
        pubsub = r.pubsub()
        pubsub.subscribe(config.FLEET_STATUS_REDIS_CHANNEL)
        yield ": connected\n\n"
        try:
            for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    data = json.loads(message["data"])
                except (ValueError, TypeError):
                    continue
                if data.get("site_id") != site_id:
                    continue  # this channel carries every site's events
                yield f"data: {json.dumps(data)}\n\n"
        except GeneratorExit:
            return
        finally:
            pubsub.close()

    resp = Response(_gen(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-store"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@bp.route("/agents/<int:agent_id>/revoke", methods=["POST"])
@login_required
def revoke_agent(agent_id):
    agent = db.session.get(Agent, agent_id)
    if not agent:
        return jsonify({"ok": False, "error": "Agent not found"}), 404
    site = _get_site_for_user(agent.site_id, "editor")
    if not site:
        return jsonify({"ok": False, "error": "Agent not found"}), 404

    agent.status = "revoked"
    agent.revoked_at = datetime.now(timezone.utc)
    AgentCredential.query.filter_by(agent_id=agent.id, revoked_at=None).update(
        {"revoked_at": datetime.now(timezone.utc)}
    )
    db.session.commit()
    _force_disconnect(agent.agent_uuid)

    audit("fleet.agent_revoked", target_type="agent", target_id=str(agent_id),
          detail=f"site_id={agent.site_id}")
    return jsonify({"ok": True, "agent": _serialize_agent(agent)})


@bp.route("/agents/<int:agent_id>/rotate-credential", methods=["POST"])
@login_required
def rotate_agent_credential(agent_id):
    """Replace a (possibly compromised) agent's credential/cert without
    losing its identity or history: revoke every existing AgentCredential
    for this agent, force-disconnect it if currently connected, and mint a
    one-time rotation token (returned once, like enrollment tokens) that
    the operator redeems via ``marlinspike-agent enroll --token ...`` on
    the same host — see AgentEnrollmentToken.agent_id and gateway/db.py's
    enroll_agent, which reuses this exact Agent row instead of creating a
    new one when a rotation token is redeemed.
    """
    agent = db.session.get(Agent, agent_id)
    if not agent:
        return jsonify({"ok": False, "error": "Agent not found"}), 404
    site = _get_site_for_user(agent.site_id, "editor")
    if not site:
        return jsonify({"ok": False, "error": "Agent not found"}), 404
    if agent.status == "revoked":
        return jsonify({"ok": False, "error": "Agent is revoked — cannot rotate its credential"}), 409

    AgentCredential.query.filter_by(agent_id=agent.id, revoked_at=None).update(
        {"revoked_at": datetime.now(timezone.utc)}
    )
    raw_token = secrets.token_urlsafe(32)
    token = AgentEnrollmentToken(
        site_id=agent.site_id,
        agent_id=agent.id,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=ENROLLMENT_TOKEN_TTL_MINUTES),
        created_by=session["user_id"],
    )
    db.session.add(token)
    db.session.commit()
    _force_disconnect(agent.agent_uuid)

    audit("fleet.agent_credential_rotated", target_type="agent", target_id=str(agent_id),
          detail=f"site_id={agent.site_id}")
    return jsonify({
        "ok": True,
        "token": raw_token,
        "expires_at": token.expires_at.isoformat(),
    }), 201
