"""MarlinSpike standalone — SQLAlchemy models."""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

from marlinspike import config

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user")  # 'admin' or 'user'
    email = db.Column(db.String(256), unique=True, nullable=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # Per-username lockout (see auth.py:verify_user) — the global login
    # rate limit is keyed by source IP only, so a botnet/proxy pool could
    # otherwise throw unlimited password guesses at one specific username,
    # each IP individually staying under the per-IP limit. Reset to
    # 0/None on a successful login.
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Profile fields
    full_name = db.Column(db.String(120), nullable=True)
    company = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    birthday = db.Column(db.Date, nullable=True)
    address = db.Column(db.Text, nullable=True)
    upload_limit_mb = db.Column(
        db.Integer, nullable=False, default=lambda: config.DEFAULT_UPLOAD_LIMIT_MB
    )

    scans = db.relationship("ScanHistory", backref="user", cascade="all, delete-orphan")
    projects = db.relationship("Project", backref="user", cascade="all, delete-orphan")


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    # JSON-encoded per-project capture policy. NULL = use system defaults.
    # Shape: {"enabled": bool, "allowed_interfaces": [str, ...],
    #         "max_session_duration_s": int|null,
    #         "max_total_bytes": int|null,  # retained ring-buffer bytes on disk
    #         "operator_warning": str|null}
    capture_policy = db.Column(db.Text, nullable=True)
    # JSON-encoded automated-capture schedule: {"enabled": bool,
    # "times_utc": ["06:00", "18:00"], "duration_s": int, "interface": str,
    # "bpf_filter": str}. NULL = no schedule configured. Applies to every
    # online fleet agent enrolled under this project when a slot fires —
    # see marlinspike/scheduler.py and fleet/api.py's capture-schedule
    # endpoints.
    capture_schedule = db.Column(db.Text, nullable=True)
    # Dedup guard against double-firing the same slot — survives an app
    # restart near a scheduled time (a fresh in-memory "already fired
    # today" set would not). See scheduler.py's _due_slot_today.
    capture_schedule_last_triggered_at = db.Column(db.DateTime, nullable=True)
    # JSON-encoded outbound webhook config, delivered once per completed
    # scan to push risk findings into an external system (e.g. a ticketing
    # platform). Shape: {"enabled": bool, "url": str, "secret": str|null,
    # "min_severity": "INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL"|null}.
    # NULL = no webhook configured. See marlinspike/webhook.py.
    webhook_config = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_project_user_name"),
    )


class ProjectMember(db.Model):
    """Additional members of a project beyond the creator.

    The project creator (projects.user_id) is implicitly owner and is not
    stored here.  This table only holds invited members.
    """

    __tablename__ = "project_members"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role = db.Column(db.String(20), nullable=False, default="viewer")  # viewer | editor | owner
    invited_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("project_id", "user_id", name="uq_project_member"),
    )


class WebhookTicket(db.Model):
    """Dedup ledger for platform-integrated webhook deliveries (e.g. Zammad).

    A finding that persists across many scans must not spawn a new external
    ticket on every single completion — this table remembers "finding X in
    project Y already has ticket Z" so redelivery is a no-op until the
    dedup_key changes (the underlying finding actually changed) or the row
    is removed. Not used by the generic/unsigned webhook mode, which has no
    concept of a durable remote object to avoid re-creating.
    """

    __tablename__ = "webhook_tickets"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dedup_key = db.Column(db.String(64), nullable=False)
    platform = db.Column(db.String(20), nullable=False)
    external_id = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint(
            "project_id", "dedup_key", "platform", name="uq_webhook_ticket_project_dedup_platform"
        ),
    )


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    command = db.Column(db.String(20), nullable=False)
    scan_profile = db.Column(db.String(12), nullable=False, default="full")
    pcap_source = db.Column(db.Text)
    pcap_hash = db.Column(db.String(64))
    status = db.Column(db.String(20), nullable=False)  # running/completed/failed/stopped
    started_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    completed_at = db.Column(db.DateTime)
    report_path = db.Column(db.Text)
    node_count = db.Column(db.Integer, default=0)
    edge_count = db.Column(db.Integer, default=0)
    error_tail = db.Column(db.Text)  # last ~10 output lines on failure

    # Recovery essentials — populated at scan launch, consulted by
    # marlinspike.recovery on every boot to reconcile in-flight scans
    # whose Flask parent died.
    pcap_path = db.Column(db.Text)               # absolute path (re-launch on retry)
    engine_pid = db.Column(db.Integer)           # subprocess PID; cleared on terminal
    engine_argv = db.Column(db.Text)             # JSON-encoded argv (PID-reuse defense)
    timeout_at = db.Column(db.DateTime)          # hard deadline for abandonment reaping
    recovery_state = db.Column(db.String(20))   # NULL / reattached / reaped_*

    # Set when this scan was launched by the fleet gateway from an agent-
    # forwarded pcap rather than as a local subprocess. engine_pid IS
    # populated for these rows (fleet/gateway/scan.py records the real
    # subprocess PID), but it's scoped to the fleet-gateway container's own
    # PID namespace — a separate container from this app (no `pid:`
    # sharing in docker-compose.yml), so it's meaningless to *this*
    # process's own pid_alive() check. The main app's reaper
    # (run_store.get_active_for_recovery) still excludes these rows for
    # exactly that reason; a separate reaper scoped to them runs inside
    # the fleet-gateway process itself (run_store
    # .get_active_agent_scans_for_recovery, wired up in fleet/gateway/cli.py).
    agent_id = db.Column(
        db.Integer, db.ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Composite index on (status, user_id): the recovery reaper queries
    # status="running" on every boot and the db-mode concurrency check queries
    # (status, user_id) on every scan-start. The leading status column also
    # serves the status-only reaper query. See migration 0003 (#68).
    __table_args__ = (
        db.Index("ix_scan_history_status_user", "status", "user_id"),
    )

    project = db.relationship("Project", backref="scans")


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


class AssetTag(db.Model):
    __tablename__ = "asset_tags"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    asset_key = db.Column(db.String(64), nullable=False, index=True)  # MAC first, IP fallback
    owner = db.Column(db.String(120))
    criticality = db.Column(db.String(20))   # 'low'|'medium'|'high'|'critical'|None
    zone = db.Column(db.String(80))
    business_function = db.Column(db.String(120))
    free_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    __table_args__ = (db.UniqueConstraint("project_id", "asset_key", name="uq_asset_tag"),)


class FindingNote(db.Model):
    __tablename__ = "finding_notes"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    report_filename = db.Column(db.String(255), nullable=False, index=True)
    finding_signature = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(20), default="open", nullable=False)
    body = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    actor_user_id = db.Column(db.Integer, nullable=True)
    actor_username = db.Column(db.String(80), nullable=True)
    actor_role = db.Column(db.String(20), nullable=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="success")
    ip_address = db.Column(db.String(45), nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


# ── IOC Threat Hunting ──────────────────────────────────────────

class IocList(db.Model):
    __tablename__ = "ioc_lists"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    source = db.Column(db.String(64))  # 'manual' | 'csv' | 'misp' | 'stix'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    entries = db.relationship("IocEntry", backref="ioc_list", cascade="all, delete-orphan")

    __table_args__ = (db.UniqueConstraint("project_id", "name", name="uq_ioc_list_name"),)


class IocEntry(db.Model):
    __tablename__ = "ioc_entries"

    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey("ioc_lists.id"), nullable=False, index=True)
    ioc_type = db.Column(db.String(16), nullable=False, index=True)  # 'ip'|'mac'|'oui'|'domain'|'sha256'|'md5'
    value = db.Column(db.String(255), nullable=False, index=True)
    label = db.Column(db.String(120))
    severity = db.Column(db.String(20))

    __table_args__ = (db.UniqueConstraint("list_id", "ioc_type", "value", name="uq_ioc_entry"),)


# ── Live Capture (capd-driven) ──────────────────────────────────

class CaptureSession(db.Model):
    __tablename__ = "capture_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)

    interface = db.Column(db.String(64), nullable=False, index=True)
    bpf_filter = db.Column(db.Text, default="", nullable=False)
    ring_filesize_kb = db.Column(db.Integer, default=200_000, nullable=False)
    ring_files = db.Column(db.Integer, default=10, nullable=False)
    max_duration_s = db.Column(db.Integer, default=0, nullable=False)

    # 'pending' | 'running' | 'stopping' | 'stopped' | 'failed'
    status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    started_at = db.Column(db.DateTime)
    stopped_at = db.Column(db.DateTime)

    capture_dir = db.Column(db.Text)
    bytes_captured = db.Column(db.BigInteger, default=0, nullable=False)
    packets_captured = db.Column(db.BigInteger, default=0, nullable=False)
    drop_count = db.Column(db.BigInteger, default=0, nullable=False)
    rotation_count = db.Column(db.Integer, default=0, nullable=False)
    error_tail = db.Column(db.Text)

    # Set when this capture ran on a remote fleet agent rather than the local
    # capd sidecar. NULL (the default) is the untouched, existing local path.
    agent_id = db.Column(
        db.Integer, db.ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    user = db.relationship("User", backref="capture_sessions")
    project = db.relationship("Project", backref="capture_sessions")


class SavedFilter(db.Model):
    """Per-project named BPF filter library."""

    __tablename__ = "saved_filters"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    name = db.Column(db.String(80), nullable=False)
    expression = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("project_id", "name", name="uq_saved_filter_project_name"),
    )


# ── Fleet (remote sensor agents) ─────────────────────────────────

class Agent(db.Model):
    """A remote sensor agent enrolled under a project."""

    __tablename__ = "agents"

    id = db.Column(db.Integer, primary_key=True)
    agent_uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name = db.Column(db.String(200), nullable=False)
    # 'pending' (token issued, never connected) | 'enrolled' (connected once,
    # currently offline) | 'online' | 'offline' | 'revoked'
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    agent_version = db.Column(db.String(40), nullable=True)
    os_info = db.Column(db.Text, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at = db.Column(db.DateTime, nullable=True)

    # Health snapshot — all populated from the agent's own heartbeat params
    # (gateway/db.py:record_heartbeat) and simply overwritten each time, not
    # historized: this is "what does this agent look like right now", not a
    # metrics timeseries. NULL for every one of these means either the
    # agent hasn't heartbeated yet or it predates this feature (an older
    # agent_version that sends bare {} heartbeat params) — the UI must
    # render that as "unknown", not zero.
    cpu_percent = db.Column(db.Float, nullable=True)
    memory_percent = db.Column(db.Float, nullable=True)
    disk_percent = db.Column(db.Float, nullable=True)
    uptime_s = db.Column(db.Integer, nullable=True)
    capd_reachable = db.Column(db.Boolean, nullable=True)
    capture_active = db.Column(db.Boolean, nullable=True)
    last_error = db.Column(db.Text, nullable=True)

    project = db.relationship("Project", backref="agents")


class AgentEnrollmentToken(db.Model):
    """Token used to enroll a new agent under a project, or (via
    ``agent_id``) to rotate an existing agent's credential.

    Two lifecycles share this table:
    - Standing project-enrollment token (``is_standing=True``): long-lived,
      reusable across any number of agents under the project. Never expires
      and is never marked used_at — only ``revoked_at`` ends its life, set
      when an owner/editor rotates it (see api.py:_mint_standing_token).
      This is the one an operator gets from the Fleet page and pastes into
      ``marlinspike-agent enroll``.
    - One-time rotation token (``agent_id`` set, ``is_standing=False``):
      mirrors PasswordResetToken's hash-at-rest / expire / single-use shape
      — reuse auth.py's token hashing helpers rather than re-deriving them.
      Used only to recover one specific already-enrolled agent's
      credential (api.py:rotate_agent_credential), not for general
      enrollment.
    """

    __tablename__ = "agent_enrollment_tokens"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Set only for a credential-rotation token (Phase 6.2): redeeming it
    # reuses this existing Agent row (same agent_uuid, name, history) and
    # just replaces its credential/cert, rather than enrolling a brand new
    # agent — see gateway/db.py:enroll_agent. NULL for an ordinary
    # first-time enrollment token (standing or one-time).
    agent_id = db.Column(
        db.Integer, db.ForeignKey("agents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    # NULL for a standing token (it never expires by time).
    expires_at = db.Column(db.DateTime, nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    is_standing = db.Column(db.Boolean, nullable=False, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AgentCredential(db.Model):
    """Long-lived post-enrollment credential for an agent.

    Kept separate from AgentEnrollmentToken (the one-time token) so
    rotation/revocation has a clean history distinct from enrollment.
    """

    __tablename__ = "agent_credentials"

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(
        db.Integer, db.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    issued_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at = db.Column(db.DateTime, nullable=True)
    # SHA-256 fingerprint (hex) of the mTLS client cert issued alongside this
    # credential at enrollment (Phase 6), when a fleet CA is configured. NULL
    # for agents enrolled before the mTLS upgrade or when no CA is set up —
    # authenticate_agent() only enforces a client-cert match when this is
    # non-NULL, so bearer-only agents keep working. Revoking this credential
    # (revoked_at) implicitly revokes the cert too, since both checks gate on
    # the same non-revoked row — no separate CRL/OCSP infrastructure needed.
    cert_fingerprint_sha256 = db.Column(db.String(64), nullable=True, index=True)


class LlmConfig(db.Model):
    """System-wide LLM connectivity config — singleton (always id=1).

    A single shared credential/endpoint for the whole deployment, set by an
    admin on the System page, rather than per-project like webhook_config —
    an LLM API key is an org-level resource, not something each project
    owner should separately provision. See marlinspike/llm.py.
    """

    __tablename__ = "llm_config"

    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    base_url = db.Column(db.String(500), nullable=True)
    api_key = db.Column(db.Text, nullable=True)
    model = db.Column(db.String(200), nullable=True)
    updated_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class FindingRecommendation(db.Model):
    """Cached LLM-generated remediation text for one deduplicated finding.

    Keyed by (project_id, dedup_key) — the same dedup_key scheme
    webhook.finding_dedup_key uses — so a finding that recurs across many
    scans gets one recommendation, generated once and reused, rather than
    a fresh (costly, slow) LLM call every time a report is viewed.
    """

    __tablename__ = "finding_recommendations"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dedup_key = db.Column(db.String(64), nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    model = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.UniqueConstraint("project_id", "dedup_key", name="uq_finding_recommendation_project_dedup"),
    )
