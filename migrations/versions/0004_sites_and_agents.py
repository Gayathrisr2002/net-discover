"""sites and agents — fleet of remote sensor agents

Adds the schema for Phase 1 of the distributed-agent architecture: a Site
(bound to a Project, so its reports land in that project's existing
REPORTS_DIR with no report-viewer changes needed), SiteMember (viewer |
editor | owner sharing, mirroring project_members), Agent (a remote sensor
enrolled at a site), AgentEnrollmentToken (one-time token used to enroll a
new agent, mirroring password_reset_tokens' hash-at-rest/expire/single-use
shape), and AgentCredential (the long-lived post-enrollment secret, kept
separate from the enrollment token for clean rotation/revocation history).

No live transport exists yet — this is pure schema + admin UI scaffolding.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0004
Revises:     0003
Create Date: 2026-07-23

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name", name="uq_site_project_name"),
    )
    op.create_index("ix_sites_project_id", "sites", ["project_id"])

    op.create_table(
        "site_members",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("invited_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("site_id", "user_id", name="uq_site_member"),
    )
    op.create_index("ix_site_members_site_id", "site_members", ["site_id"])
    op.create_index("ix_site_members_user_id", "site_members", ["user_id"])

    op.create_table(
        "agents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_uuid", sa.String(length=64), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("agent_version", sa.String(length=40), nullable=True),
        sa.Column("os_info", sa.Text(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_uuid", name="uq_agent_uuid"),
    )
    op.create_index("ix_agents_agent_uuid", "agents", ["agent_uuid"])
    op.create_index("ix_agents_site_id", "agents", ["site_id"])
    op.create_index("ix_agents_status", "agents", ["status"])

    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_agent_enrollment_token_hash"),
    )
    op.create_index("ix_agent_enrollment_tokens_site_id", "agent_enrollment_tokens", ["site_id"])

    op.create_table(
        "agent_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash", name="uq_agent_credential_key_hash"),
    )
    op.create_index("ix_agent_credentials_agent_id", "agent_credentials", ["agent_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_credentials_agent_id", table_name="agent_credentials")
    op.drop_table("agent_credentials")

    op.drop_index("ix_agent_enrollment_tokens_site_id", table_name="agent_enrollment_tokens")
    op.drop_table("agent_enrollment_tokens")

    op.drop_index("ix_agents_status", table_name="agents")
    op.drop_index("ix_agents_site_id", table_name="agents")
    op.drop_index("ix_agents_agent_uuid", table_name="agents")
    op.drop_table("agents")

    op.drop_index("ix_site_members_user_id", table_name="site_members")
    op.drop_index("ix_site_members_site_id", table_name="site_members")
    op.drop_table("site_members")

    op.drop_index("ix_sites_project_id", table_name="sites")
    op.drop_table("sites")
