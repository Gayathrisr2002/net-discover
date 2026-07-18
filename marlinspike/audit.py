"""MarlinSpike standalone — immutable audit logging."""

import json
import logging

from flask import request, session

from marlinspike.models import AuditLog, db

log = logging.getLogger("marlinspike.audit")

# Count of audit writes that failed to persist. A dropped audit event is a hole
# in the compliance trail, so failures are observable (this counter) rather than
# silently swallowed (Finding #19). Inspect via ``get_audit_failure_count``.
_audit_write_failures = 0


def get_audit_failure_count():
    """Return the number of audit writes that failed to persist this process."""
    return _audit_write_failures


def audit(event_type, *, target_type=None, target_id=None, status="success",
          detail=None, actor_user_id=None, actor_username=None,
          actor_role=None, ip_address=None):
    """Write an immutable audit log entry.

    Auto-populates actor from flask.session and IP from flask.request
    when not explicitly provided.  Never raises — rolls back on failure so
    audit calls never break normal operations. On failure the full event is
    preserved as a structured ERROR-level fallback record (a last-resort
    compliance log line) and counted, never silently dropped (Finding #19).
    """
    global _audit_write_failures
    try:
        if actor_user_id is None:
            try:
                actor_user_id = session.get("user_id")
            except RuntimeError:
                pass
        if actor_username is None:
            try:
                actor_username = session.get("user")
            except RuntimeError:
                pass
        if actor_role is None:
            try:
                actor_role = session.get("role")
            except RuntimeError:
                pass
        if ip_address is None:
            try:
                ip_address = request.remote_addr
            except RuntimeError:
                pass

        category = event_type.split(".")[0] if "." in event_type else event_type
        detail_json = json.dumps(detail, default=str) if detail is not None else None

        entry = AuditLog(
            event_type=event_type,
            category=category,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_role=actor_role,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            status=status,
            ip_address=ip_address,
            detail=detail_json,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        _audit_write_failures += 1
        # Preserve the full event so the dropped security record is recoverable
        # from the application log — never silently lost (Finding #19).
        try:
            fallback = json.dumps({
                "audit_write_failed": True,
                "event_type": event_type,
                "category": event_type.split(".")[0] if "." in event_type else event_type,
                "actor_user_id": actor_user_id,
                "actor_username": actor_username,
                "actor_role": actor_role,
                "target_type": target_type,
                "target_id": str(target_id) if target_id is not None else None,
                "status": status,
                "ip_address": ip_address,
                "detail": detail,
            }, default=str)
        except Exception:
            fallback = event_type
        log.error("AUDIT WRITE FAILED — event preserved: %s", fallback, exc_info=True)
