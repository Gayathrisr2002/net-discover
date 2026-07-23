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
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session

from marlinspike.audit import audit
from marlinspike.auth import login_required
from marlinspike.models import (
    Agent,
    AgentCredential,
    AgentEnrollmentToken,
    Project,
    Site,
    SiteMember,
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

    audit("fleet.agent_revoked", target_type="agent", target_id=str(agent_id),
          detail=f"site_id={agent.site_id}")
    return jsonify({"ok": True, "agent": _serialize_agent(agent)})
