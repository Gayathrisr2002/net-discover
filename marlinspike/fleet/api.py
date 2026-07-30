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

import glob
import hashlib
import io
import json
import os
import re
import secrets
import tarfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import Blueprint, Response, jsonify, request, send_file, session, stream_with_context

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


def _mint_standing_token(site_id: int, created_by: int) -> str:
    """Mint a fresh standing (reusable, non-expiring) enrollment token for a
    site, revoking any previously active standing token first — a site has
    at most one live standing token at a time, so "rotate" means "replace",
    not "add another". Returns the raw token (shown once, hashed at rest).
    """
    AgentEnrollmentToken.query.filter_by(
        site_id=site_id, is_standing=True, revoked_at=None
    ).update({"revoked_at": datetime.now(timezone.utc)})

    raw_token = secrets.token_urlsafe(32)
    token = AgentEnrollmentToken(
        site_id=site_id,
        token_hash=_hash_token(raw_token),
        is_standing=True,
        created_by=created_by,
    )
    db.session.add(token)
    db.session.commit()
    return raw_token


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


# Health-badge thresholds against the resource percentages in a heartbeat
# — deliberately conservative (a small remote OT box legitimately runs hot
# sometimes) so the badge only flags something actually worth a look.
_RESOURCE_WARN_PCT = 75.0
_RESOURCE_CRIT_PCT = 90.0


def _compute_health(agent: Agent) -> str | None:
    """Derived, not stored: a one-word verdict for the Fleet UI's health
    badge, computed fresh from the same snapshot _serialize_agent already
    exposes field-by-field. None means "nothing to assess yet" (an agent
    that's revoked, or has never connected) — the UI must not render that
    as healthy.
    """
    if agent.status in ("revoked", "pending"):
        return None
    if agent.status != "online":
        return "offline"
    if agent.last_error or agent.capd_reachable is False:
        return "critical"
    resource_values = [v for v in (agent.cpu_percent, agent.memory_percent, agent.disk_percent)
                        if v is not None]
    if any(v >= _RESOURCE_CRIT_PCT for v in resource_values):
        return "critical"
    if any(v >= _RESOURCE_WARN_PCT for v in resource_values):
        return "warning"
    return "healthy"


def _serialize_agent(agent: Agent) -> dict:
    now = datetime.now(timezone.utc)
    seconds_since_heartbeat = None
    if agent.last_seen_at is not None:
        last_seen = agent.last_seen_at
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        seconds_since_heartbeat = (now - last_seen).total_seconds()

    current_agent_version = config.current_agent_version()

    return {
        "id": agent.id,
        "agent_uuid": agent.agent_uuid,
        "site_id": agent.site_id,
        "name": agent.name,
        "status": agent.status,
        "agent_version": agent.agent_version,
        "version_mismatch": (
            bool(agent.agent_version) and current_agent_version is not None
            and agent.agent_version != current_agent_version
        ),
        "os_info": agent.os_info,
        "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "seconds_since_heartbeat": seconds_since_heartbeat,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "revoked_at": agent.revoked_at.isoformat() if agent.revoked_at else None,
        "health": _compute_health(agent),
        "cpu_percent": agent.cpu_percent,
        "memory_percent": agent.memory_percent,
        "disk_percent": agent.disk_percent,
        "uptime_s": agent.uptime_s,
        "capd_reachable": agent.capd_reachable,
        "capture_active": agent.capture_active,
        "last_error": agent.last_error,
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

    raw_token = _mint_standing_token(site.id, session["user_id"])

    audit("fleet.site_created", target_type="site", target_id=str(site.id),
          detail=f"project_id={project_id} name={name!r}")
    return jsonify({
        "ok": True,
        "site": _serialize_site(site, agent_count=0),
        "enrollment_token": raw_token,
    }), 201


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


# ── Site automated capture schedule ──────────────────────────────
# See marlinspike/scheduler.py — a schedule set here drives a background
# thread that automatically starts a capture on every online agent at
# this site when a configured times_utc slot is due, reusing the exact
# same policy-gated _start_capture_session core logic a manual click uses.

_SCHEDULE_ALLOWED_KEYS = frozenset({"enabled", "times_utc", "duration_s", "interface", "bpf_filter"})
_TIME_UTC_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _validate_schedule_body(body: dict) -> str | None:
    unknown = set(body.keys()) - _SCHEDULE_ALLOWED_KEYS
    if unknown:
        return f"unknown key(s): {', '.join(sorted(unknown))}"

    if "enabled" in body and not isinstance(body["enabled"], bool):
        return "enabled must be a boolean"

    if "times_utc" in body:
        times = body["times_utc"]
        if not isinstance(times, list) or not times:
            return "times_utc must be a non-empty list of HH:MM strings"
        for t in times:
            if not isinstance(t, str) or not _TIME_UTC_RE.match(t):
                return f"times_utc entry {t!r} is not a valid HH:MM (24h) time"

    if "duration_s" in body:
        duration_s = body["duration_s"]
        if isinstance(duration_s, bool) or not isinstance(duration_s, int) or duration_s <= 0:
            return "duration_s must be a positive integer"

    if "interface" in body and not isinstance(body["interface"], str):
        return "interface must be a string"
    if "bpf_filter" in body and not isinstance(body["bpf_filter"], str):
        return "bpf_filter must be a string"

    if body.get("enabled"):
        if not body.get("interface"):
            return "enabled schedules require interface"
        if not body.get("times_utc"):
            return "enabled schedules require times_utc"

    return None


@bp.route("/sites/<int:site_id>/capture-schedule", methods=["GET"])
@login_required
def get_capture_schedule(site_id):
    site = _get_site_for_user(site_id, "owner")
    if site is None:
        return jsonify({"ok": False, "error": "Site not found"}), 404
    schedule = json.loads(site.capture_schedule) if site.capture_schedule else None
    return jsonify({
        "ok": True, "site_id": site_id, "schedule": schedule,
        "last_triggered_at": (
            site.capture_schedule_last_triggered_at.isoformat()
            if site.capture_schedule_last_triggered_at else None
        ),
    })


@bp.route("/sites/<int:site_id>/capture-schedule", methods=["PUT"])
@login_required
def set_capture_schedule(site_id):
    site = _get_site_for_user(site_id, "owner")
    if site is None:
        return jsonify({"ok": False, "error": "Site not found"}), 404

    body = request.get_json(silent=True)
    if body is None or not isinstance(body, dict):
        return jsonify({"ok": False, "error": "JSON body required"}), 400

    err = _validate_schedule_body(body)
    if err:
        return jsonify({"ok": False, "error": f"invalid schedule: {err}"}), 400

    old_raw = site.capture_schedule
    site.capture_schedule = json.dumps(body) if body else None
    db.session.commit()

    audit("fleet.site_capture_schedule_set", target_type="site", target_id=str(site_id),
          detail=json.dumps({
              "site_id": site_id,
              "old_schedule": json.loads(old_raw) if old_raw else None,
              "new_schedule": body,
          }))
    return jsonify({"ok": True, "schedule": body})


# ── Agent package download ───────────────────────────────────────

@bp.route("/agent-package", methods=["GET"])
@login_required
def download_agent_package():
    """Serve the marlinspike-agent source as a .tar.gz — the operator's
    only way to actually get the agent onto a remote host before this
    route existed was to separately clone the whole repo. Built fresh
    from config.MARLINSPIKE_AGENT_SOURCE_DIR on every request (small,
    source-only, no compiled artifacts) rather than a cached/prebuilt
    file, so it can never drift from whatever agent code this exact
    running deployment actually ships. Not site- or project-scoped — the
    package itself is generic; only the enrollment token (issued
    separately, per-site) ties a specific install to a specific site.
    """
    source_dir = config.MARLINSPIKE_AGENT_SOURCE_DIR
    if not os.path.isdir(source_dir):
        return jsonify({"ok": False, "error": "agent package not available on this deployment"}), 404

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(source_dir, arcname="marlinspike-agent", filter=_agent_tar_filter)
    buf.seek(0)

    audit("fleet.agent_package_downloaded", target_type="site", target_id=None)
    return send_file(
        buf, mimetype="application/gzip", as_attachment=True,
        download_name="marlinspike-agent.tar.gz",
    )


def _agent_tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    """Excludes __pycache__/.pyc/.egg-info cruft and normalizes ownership
    (uid/gid 0) so the downloaded tarball doesn't carry this container's
    internal uid/gid — matches how e.g. `git archive` behaves."""
    name = info.name
    if "__pycache__" in name.split("/") or name.endswith((".pyc", ".pyo")) or ".egg-info" in name:
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


@bp.route("/agent-package.deb", methods=["GET"])
@login_required
def download_agent_package_deb():
    """Serve the pre-built marlinspike-agent .deb — install-by-double-click
    (or `apt install ./file.deb`) for Debian/Ubuntu hosts, an alternative
    to the pip-installable tarball above for operators who'd rather not
    deal with a Python toolchain at all. Unlike the tarball, this is built
    ONCE at image-build time (scripts/build_agent_deb.sh, invoked from the
    Dockerfile) rather than per-request — building a .deb needs
    fakeroot/dpkg-deb and never changes between requests against the same
    image, so there's no reason to redo it on every download.
    """
    deb_dir = config.MARLINSPIKE_AGENT_DEB_DIR
    matches = sorted(glob.glob(os.path.join(deb_dir, "marlinspike-agent_*_all.deb"))) if os.path.isdir(deb_dir) else []
    if not matches:
        return jsonify({"ok": False, "error": "agent .deb not available on this deployment"}), 404

    audit("fleet.agent_package_deb_downloaded", target_type="site", target_id=None)
    return send_file(matches[-1], mimetype="application/vnd.debian.binary-package", as_attachment=True,
                      download_name=os.path.basename(matches[-1]))


@bp.route("/capd-package.deb", methods=["GET"])
@login_required
def download_capd_package_deb():
    """Serve the pre-built marlinspike-capd .deb — the privileged capture
    sidecar an operator installs alongside marlinspike-agent on a remote
    sensor host (or alongside the web app itself) to actually enable live
    capture. Same build-once-at-image-build-time posture as
    download_agent_package_deb above (scripts/build_capd_deb.sh, invoked
    from the Dockerfile).
    """
    deb_dir = config.MARLINSPIKE_CAPD_DEB_DIR
    matches = sorted(glob.glob(os.path.join(deb_dir, "marlinspike-capd_*_all.deb"))) if os.path.isdir(deb_dir) else []
    if not matches:
        return jsonify({"ok": False, "error": "capd .deb not available on this deployment"}), 404

    audit("fleet.capd_package_deb_downloaded", target_type="site", target_id=None)
    return send_file(matches[-1], mimetype="application/vnd.debian.binary-package", as_attachment=True,
                      download_name=os.path.basename(matches[-1]))


@bp.route("/ca-cert", methods=["GET"])
@login_required
def download_ca_cert():
    """Serve the fleet CA's public certificate (fleet-ca.crt) — what a
    remote agent needs to pass as ``--ca-cert`` to verify the gateway's
    TLS listener. Not a secret (it's a CA certificate, never the private
    key — see config.FLEET_CA_CERT's docstring), just previously only
    reachable by copying the file off the server by hand. 404s (rather
    than erroring) when no CA is configured for this deployment — the
    same graceful-degradation posture as mTLS being entirely optional.
    """
    ca_cert_path = config.FLEET_CA_CERT
    if not ca_cert_path or not os.path.isfile(ca_cert_path):
        return jsonify({"ok": False, "error": "fleet CA certificate not available on this deployment"}), 404

    audit("fleet.ca_cert_downloaded", target_type="site", target_id=None)
    return send_file(ca_cert_path, mimetype="application/x-x509-ca-cert", as_attachment=True,
                      download_name="fleet-ca.crt")


# Hostnames auto-detection must never guess from — a remote agent
# reaching the gateway via these would almost always be wrong (loopback
# is only "correct" if the agent happens to run on this exact box), and
# a confidently-wrong auto-filled value is worse than the honest
# bracket-placeholder fallback: the placeholder visibly says "fill this
# in", a wrong-but-plausible-looking IP does not.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@bp.route("/gateway-info", methods=["GET"])
@login_required
def gateway_info():
    """Deployment-wide, non-secret settings the Fleet page needs to render
    a ready-to-copy enroll command instead of a bracket-placeholder one:
    where the gateway is actually reachable from a remote agent, and
    whether a CA cert is available to download.

    config.FLEET_GATEWAY_PUBLIC_HOST (operator-configured) always wins
    when set. Otherwise, fall back to the host this very request came in
    on (request.host) — in the overwhelmingly common case, an operator
    browsing the Fleet page and a remote agent both reach this deployment
    at the same address, just on different ports (5001 vs the gateway's).
    This is a best-effort guess, not a guarantee: an operator who reaches
    this page over a tunnel/VPN/port-forward with a different externally-
    reachable address will still need FLEET_GATEWAY_PUBLIC_HOST set
    explicitly — gateway_host_auto_detected tells the UI to soften its
    wording accordingly rather than presenting a guess as gospel.
    """
    auto_detected = False
    gateway_host = config.FLEET_GATEWAY_PUBLIC_HOST or None
    if not gateway_host:
        detected = urlsplit(f"//{request.host}").hostname
        if detected and detected not in _LOOPBACK_HOSTS:
            gateway_host = detected
            auto_detected = True

    return jsonify({
        "ok": True,
        "gateway_host": gateway_host,
        "gateway_host_auto_detected": auto_detected,
        "gateway_port": config.FLEET_GATEWAY_PUBLIC_PORT,
        "ca_cert_available": bool(config.FLEET_CA_CERT and os.path.isfile(config.FLEET_CA_CERT)),
    })


# ── Enrollment tokens ────────────────────────────────────────────

@bp.route("/sites/<int:site_id>/enrollment-tokens", methods=["POST"])
@login_required
def issue_enrollment_token(site_id):
    """Rotate this site's standing enrollment token: revoke whichever one is
    currently active and mint a fresh one, returned exactly once to the
    authenticated, already-authorized caller who requested it — unlike
    auth.py's password-reset token (deliberately never returned in a
    response, since an unauthenticated party can trigger that flow for
    someone else's account), this token is minted on-demand by a site
    editor/owner for their own use, so returning it directly here is the
    correct and intended UX (same shape as e.g. a personal access token
    shown once at creation). The token is reusable — every existing
    enrolled agent keeps working; only *future* enrollments need the new
    value.
    """
    site = _get_site_for_user(site_id, "editor")
    if not site:
        return jsonify({"ok": False, "error": "Site not found"}), 404

    raw_token = _mint_standing_token(site_id, session["user_id"])

    audit("fleet.enrollment_token_issued", target_type="site", target_id=str(site_id))
    return jsonify({"ok": True, "token": raw_token}), 201


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
