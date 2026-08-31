"""MarlinSpike standalone — authentication helpers."""

import hashlib
import logging
import os
import re
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from marlinspike import config
from marlinspike.models import PasswordResetToken, User, db

log = logging.getLogger("marlinspike.auth")

# Lazy import to avoid circular dependency at module load time
_audit_fn = None


def _get_audit():
    global _audit_fn
    if _audit_fn is None:
        from marlinspike.audit import audit as _a
        _audit_fn = _a
    return _audit_fn


# ── Decorators ──


def _session_invalidated() -> bool:
    """True if the signed cookie's session_version no longer matches the
    DB — i.e. the password was changed/reset (or another session-fixation
    event happened) *after* this particular session was issued elsewhere,
    and it should be force-logged-out. Shared by login_required and
    admin_required so both actually enforce it identically."""
    if "session_version" in session and "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user is None:
            # Account was deleted out from under this live session (e.g.
            # an admin removing a compromised user) — `if user and ...`
            # used to short-circuit to False here, treating a deleted
            # user's session as NOT invalidated, so it lingered until some
            # other request happened to dereference the (now-gone) row and
            # crashed instead of cleanly logging out.
            return True
        if getattr(user, "session_version", 1) != session["session_version"]:
            return True
    return False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        if _session_invalidated():
            session.clear()
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def csrf_exempt(view_func):
    """Mark a view function as exempt from the global CSRF / origin check.

    Use sparingly — intended for endpoints that legitimately receive POSTs
    from third parties (e.g. payment-provider webhooks, OAuth callbacks)
    where ``Origin`` and ``Referer`` won't match the application host.

    Example:
        @app.route("/billing/webhook", methods=["POST"])
        @csrf_exempt
        def stripe_webhook(): ...
    """
    view_func._csrf_exempt = True
    return view_func


def admin_required(f):
    """Require admin role.

    For ``/api/*`` paths, returns JSON 401/403. For everything else,
    redirects to login (when unauthenticated) or returns a plain 403
    body (when not admin). Detected via ``request.path.startswith('/api/')``.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import jsonify, request
        is_api = (request.path or "").startswith("/api/")
        if "user" not in session:
            if is_api:
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("login_page"))
        if _session_invalidated():
            # Without this, a stolen admin session cookie stayed fully
            # valid on every admin-only route indefinitely, even after the
            # admin changed their own password specifically to invalidate
            # it elsewhere — login_required's routes correctly rejected
            # the stolen cookie, but admin_required's never re-checked the
            # DB at all. Confirmed real: this decorator guards user
            # management, the audit log, and admin presets.
            session.clear()
            if is_api:
                return jsonify({"error": "Session expired"}), 401
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            if is_api:
                return jsonify({"error": "Admin role required"}), 403
            return "Forbidden", 403
        return f(*args, **kwargs)
    return decorated


# ── User CRUD ──


def create_user(username, password, role="user", upload_limit_mb=None):
    if upload_limit_mb is None:
        upload_limit_mb = config.DEFAULT_UPLOAD_LIMIT_MB
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        upload_limit_mb=upload_limit_mb,
    )
    db.session.add(user)
    db.session.commit()
    return user


# Precomputed once at import time (never matches any real password) so a
# nonexistent username still pays the same check_password_hash cost as a
# real one below — otherwise a nonexistent username short-circuits after
# only a fast indexed lookup while an existing one additionally pays the
# full (deliberately slow) hash-verification cost, and that timing gap is
# enough to enumerate valid usernames via /login response timing.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


_MAX_FAILED_LOGIN_ATTEMPTS = 5
_LOCKOUT_DURATION_MINUTES = 15


def verify_user(username, password):
    """Returns the User on success, None on any failure — wrong password,
    nonexistent username, OR a currently-locked account all return None
    identically, so the caller's generic "invalid credentials" message
    can never be used to distinguish "no such user" from "this real
    account is locked out" (the same anti-enumeration principle
    _DUMMY_PASSWORD_HASH already applies to the password-hash timing).

    Per-username lockout: the login rate limiter is keyed by source IP
    only (app.py's limiter), so a distributed attacker could otherwise
    throw unlimited guesses at one specific username, each individual IP
    staying under the per-IP limit. After _MAX_FAILED_LOGIN_ATTEMPTS
    consecutive failures, the account is locked for
    _LOCKOUT_DURATION_MINUTES; a successful login (once the lockout
    window elapses) resets the counter.
    """
    user = User.query.filter_by(username=username).first()
    now = datetime.now(timezone.utc)

    if user is not None and user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if now < locked_until:
            # Still locked — pay the same hash-verification cost as the
            # normal path anyway (timing consistency with the "wrong
            # password" and "no such user" cases below) but never let a
            # correct password succeed while locked.
            check_password_hash(_DUMMY_PASSWORD_HASH, password)
            return None

    password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_ok = check_password_hash(password_hash, password)

    if user is None:
        return None

    if password_ok:
        if user.failed_login_attempts or user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
        return user

    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    newly_locked = user.failed_login_attempts >= _MAX_FAILED_LOGIN_ATTEMPTS
    if newly_locked:
        user.locked_until = now + timedelta(minutes=_LOCKOUT_DURATION_MINUTES)
    db.session.commit()
    if newly_locked:
        _get_audit()("auth.account_locked", status="failure",
                      target_type="user", target_id=user.username,
                      detail={"failed_attempts": user.failed_login_attempts,
                              "locked_until": user.locked_until.isoformat()})
    return None


def change_password(user, new_password):
    user.password_hash = generate_password_hash(new_password)
    user.session_version = (user.session_version or 1) + 1
    db.session.commit()
    # Session-fixation hygiene (csrf.py's own documented contract: "call
    # this on any session-fixation event — login, password change,
    # privilege escalation"). Previously only called at login. Harmless
    # for the admin-changes-another-user's-password call site (rotates
    # the acting admin's own token; their next page load mints a fresh
    # one same as always) and closes the gap for the self-service path.
    from marlinspike.csrf import rotate_csrf
    rotate_csrf()


def generate_random_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── Password Reset ──

RESET_TOKEN_TTL_MINUTES = 30


def _hash_token(token: str) -> str:
    """SHA-256 hash a reset token for storage. Never store raw tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


def dummy_reset_request_work(delivery: str) -> None:
    """Equalizes /api/auth/reset-request's response cost between an
    existing and a nonexistent username, so response timing can't be
    used to enumerate accounts — the same bug class _DUMMY_PASSWORD_HASH
    already closes for /login, reintroduced here since that fix wasn't
    extended to this sibling endpoint. Mirrors the real path's DB read +
    delivery I/O cost without persisting anything for a user that
    doesn't exist.
    """
    # Touches the same table/index create_reset_token's delete() would
    # scan, without matching against any real user_id.
    PasswordResetToken.query.filter_by(user_id=-1, used_at=None).first()
    if delivery == "file":
        token_dir = os.path.join(config.DATA_DIR, "instance", "reset-tokens")
        os.makedirs(token_dir, mode=0o700, exist_ok=True)
        dummy_path = os.path.join(token_dir, f".dummy-{secrets.token_hex(8)}")
        try:
            fd = os.open(dummy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(secrets.token_urlsafe(32) + "\n")
        finally:
            try:
                os.unlink(dummy_path)
            except OSError:
                pass


def create_reset_token(user, ip_address=None):
    """Generate a single-use password reset token. Returns the raw token."""
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).delete()

    raw_token = secrets.token_urlsafe(32)
    token = PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        ip_address=ip_address,
    )
    db.session.add(token)
    db.session.commit()

    log.info("Reset token issued for user=%s ip=%s", user.username, ip_address or "?")
    _get_audit()("auth.reset_token_issued",
                  target_type="user", target_id=user.username,
                  actor_user_id=user.id, actor_username=user.username,
                  ip_address=ip_address)
    return raw_token


# ── Reset token delivery ──────────────────────────────────────────────────────
#
# The reset token is never returned in the HTTP response (that was an
# unauthenticated account takeover, fixed in v3.5.2). Instead it is delivered
# via a configured side channel. Wrappers (cloudmarlin, etc.) may register an
# alternate delivery via ``set_reset_token_delivery``.

_reset_token_delivery_hook = None


def set_reset_token_delivery(func):
    """Register a custom delivery callable ``(user, token, mode) -> None``.

    Pass ``None`` to clear the override and fall back to the built-in
    file / log delivery.
    """
    global _reset_token_delivery_hook
    _reset_token_delivery_hook = func


def deliver_reset_token(user, token, delivery):
    """Deliver ``token`` for ``user`` via the configured side channel.

    ``delivery`` is ``MARLINSPIKE_RESET_TOKEN_DELIVERY``:
      * ``"file"`` — written to ``${DATA_DIR}/instance/reset-tokens/<user>-<ts>.txt``
        (0600, owner-only); the operator delivers it out-of-band.
      * ``"log"``  — emitted to the server log only.
    A registered override hook (``set_reset_token_delivery``) takes precedence.
    Never returns the token to the caller.
    """
    if _reset_token_delivery_hook is not None:
        _reset_token_delivery_hook(user, token, delivery)
        return

    if delivery == "file":
        from marlinspike import config

        token_dir = os.path.join(config.DATA_DIR, "instance", "reset-tokens")
        os.makedirs(token_dir, mode=0o700, exist_ok=True)
        # Sanitise the username so it can never traverse out of token_dir.
        safe_user = re.sub(r"[^A-Za-z0-9._-]", "_", user.username) or "user"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        path = os.path.join(token_dir, f"{safe_user}-{ts}.txt")
        # O_EXCL so we never clobber, 0600 so only the owner can read it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token + "\n")
        log.info("Reset token for %s written to %s (deliver out-of-band)", user.username, path)
    elif delivery == "log":
        log.warning("Password reset token for user=%s: %s", user.username, token)
    else:
        raise ValueError(f"Unknown reset token delivery mode: {delivery!r}")


def validate_reset_token(raw_token):
    """Validate a reset token. Returns the token row if valid, None otherwise."""
    token_hash = _hash_token(raw_token)
    token = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not token:
        _get_audit()("auth.reset_token_rejected", status="failure",
                      detail={"reason": "not_found"})
        return None
    if token.used_at is not None:
        _get_audit()("auth.reset_token_rejected", status="failure",
                      target_type="user", target_id=str(token.user_id),
                      detail={"reason": "already_used"})
        return None
    expires = token.expires_at.replace(tzinfo=timezone.utc) if token.expires_at.tzinfo is None else token.expires_at
    if datetime.now(timezone.utc) > expires:
        _get_audit()("auth.reset_token_rejected", status="failure",
                      target_type="user", target_id=str(token.user_id),
                      detail={"reason": "expired"})
        return None

    return token


def use_reset_token(token, new_password):
    """Consume a reset token and change the user's password.

    Returns the user, or None if the token was already redeemed by a
    concurrent request in the window between validate_reset_token's
    check and this call — a real, if narrow, race: two simultaneous
    reset-confirm requests with the same still-valid token could
    otherwise both pass validation before either committed its own
    used_at write, redeeming the token twice. Re-fetches the row with a
    row lock and re-checks used_at atomically here rather than trusting
    the caller's earlier (by now possibly stale) check.
    """
    locked = PasswordResetToken.query.filter_by(id=token.id).with_for_update().first()
    if locked is None or locked.used_at is not None:
        return None
    user = db.session.get(User, locked.user_id)
    user.password_hash = generate_password_hash(new_password)
    user.session_version = (user.session_version or 1) + 1
    locked.used_at = datetime.now(timezone.utc)
    db.session.commit()
    from marlinspike.csrf import rotate_csrf
    rotate_csrf()

    log.info("Reset token used for user=%s", user.username)
    _get_audit()("auth.reset_token_used",
                  target_type="user", target_id=user.username,
                  actor_user_id=user.id, actor_username=user.username)
    return user


def cleanup_expired_tokens():
    """Delete expired or used tokens older than 24h."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    deleted = PasswordResetToken.query.filter(
        (PasswordResetToken.expires_at < cutoff)
        | (PasswordResetToken.used_at.isnot(None) & (PasswordResetToken.used_at < cutoff))
    ).delete(synchronize_session=False)
    db.session.commit()
    return deleted


# ── Bootstrap ──


def bootstrap_admin(app):
    """Create admin user on first run if users table is empty.

    Security note (v3.5.2): when ``ADMIN_PASSWORD`` is empty, the
    generated password is written to a file with mode 0600 instead of
    printed to stdout. The previous stdout-print approach leaked the
    credential into container/journald logs that frequently outlive
    the credential itself. The file is at:

        ${DATA_DIR}/instance/admin-bootstrap-password.txt

    It's overwritten on each empty-table bootstrap and is intended to
    be deleted by the operator after the first login.
    """
    import os
    from marlinspike.config import ADMIN_PASSWORD, DATA_DIR

    with app.app_context():
        if User.query.count() > 0:
            return

        password = ADMIN_PASSWORD or generate_random_password()
        create_user("admin", password, role="admin")

        if not ADMIN_PASSWORD:
            instance_dir = os.path.join(DATA_DIR, "instance")
            os.makedirs(instance_dir, mode=0o700, exist_ok=True)
            try:
                os.chmod(instance_dir, 0o700)
            except OSError:
                pass
            cred_path = os.path.join(instance_dir, "admin-bootstrap-password.txt")
            try:
                # Write with restrictive perms before any content lands.
                fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(
                        f"username: admin\n"
                        f"password: {password}\n"
                        f"created_at: {datetime.now(timezone.utc).isoformat()}\n"
                        f"# Change this immediately. Delete this file after first login.\n"
                    )
                # Best-effort log line — does NOT leak the password itself,
                # just points the operator at the file.
                log.warning(
                    "FIRST RUN — admin account created. Bootstrap credential "
                    "written to %s (mode 0600). Read, log in, change password, "
                    "delete the file.",
                    cred_path,
                )
            except OSError as exc:
                # Last-ditch: log to stderr so the operator can recover.
                # Still don't print the password to stdout (container logs).
                log.error(
                    "Failed to write admin bootstrap credential file (%s); "
                    "the password is in the database hashed but the plaintext "
                    "is now lost. Manually reset via 'marlinspike-cli reset-admin' "
                    "or by clearing the users table.",
                    exc,
                )
