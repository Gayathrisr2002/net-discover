"""flatten sites into projects — agents belong directly to a project

Removes the Site/SiteMember indirection between Project and Agent. Agents
(and their enrollment tokens) now carry project_id directly instead of
site_id, and the automated-capture-schedule fields move from Site onto
Project (Project.capture_policy already existed and is now the only
capture-policy layer — there is no more site-level policy to merge in).

Data migration (best-effort, since this collapses a two-level hierarchy
into one level):
  - agents.project_id / agent_enrollment_tokens.project_id are backfilled
    from their site's project_id.
  - projects.capture_schedule / capture_schedule_last_triggered_at are
    backfilled from whichever of that project's sites had a non-NULL
    capture_schedule most recently (highest site id) — last-write-wins.
    A project that had more than one site with different schedules
    configured will only keep one of them; this is a real, accepted loss
    given sites no longer exist as a grouping concept.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0012
Revises:     0011
Create Date: 2026-08-03

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as batch_op:
        batch_op.add_column(sa.Column("capture_schedule", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("capture_schedule_last_triggered_at", sa.DateTime(), nullable=True))

    op.execute(
        """
        UPDATE projects SET
            capture_schedule = (
                SELECT s.capture_schedule FROM sites s
                WHERE s.project_id = projects.id AND s.capture_schedule IS NOT NULL
                ORDER BY s.id DESC LIMIT 1
            ),
            capture_schedule_last_triggered_at = (
                SELECT s.capture_schedule_last_triggered_at FROM sites s
                WHERE s.project_id = projects.id AND s.capture_schedule IS NOT NULL
                ORDER BY s.id DESC LIMIT 1
            )
        WHERE EXISTS (
            SELECT 1 FROM sites s
            WHERE s.project_id = projects.id AND s.capture_schedule IS NOT NULL
        )
        """
    )

    with op.batch_alter_table("agents") as batch_op:
        batch_op.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE agents SET project_id = (
            SELECT sites.project_id FROM sites WHERE sites.id = agents.site_id
        )
        """
    )
    op.drop_index("ix_agents_site_id", table_name="agents")
    with op.batch_alter_table("agents") as batch_op:
        batch_op.alter_column("project_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_agents_project_id", "projects", ["project_id"], ["id"], ondelete="CASCADE"
        )
        batch_op.drop_column("site_id")
    op.create_index("ix_agents_project_id", "agents", ["project_id"])

    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE agent_enrollment_tokens SET project_id = (
            SELECT sites.project_id FROM sites WHERE sites.id = agent_enrollment_tokens.site_id
        )
        """
    )
    op.drop_index("ix_agent_enrollment_tokens_site_id", table_name="agent_enrollment_tokens")
    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.alter_column("project_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_agent_enrollment_tokens_project_id", "projects", ["project_id"], ["id"], ondelete="CASCADE"
        )
        batch_op.drop_column("site_id")
    op.create_index("ix_agent_enrollment_tokens_project_id", "agent_enrollment_tokens", ["project_id"])

    op.drop_index("ix_site_members_user_id", table_name="site_members")
    op.drop_index("ix_site_members_site_id", table_name="site_members")
    op.drop_table("site_members")

    op.drop_index("ix_sites_project_id", table_name="sites")
    op.drop_table("sites")


def downgrade() -> None:
    """Lossy reconstruction: synthesizes exactly one Site per Project that
    has any agents, named "Site 1", and reattaches every one of that
    project's agents/tokens to it. Original site names/boundaries (if a
    project previously had more than one site) are NOT recoverable — this
    matches the accepted data loss already noted in upgrade()'s docstring.
    """
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("capture_policy", sa.Text(), nullable=True),
        sa.Column("capture_schedule", sa.Text(), nullable=True),
        sa.Column("capture_schedule_last_triggered_at", sa.DateTime(), nullable=True),
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

    # One synthetic site per project that owns at least one agent OR
    # enrollment token (a standing token can exist on a project before any
    # agent has ever enrolled against it — see fleet/api.py's
    # issue_enrollment_token), carrying over that project's (flattened)
    # capture_schedule. Missing the token half of this guard left any
    # project with an unredeemed standing token but zero agents with no
    # synthesized site, so agent_enrollment_tokens.site_id below backfills
    # to NULL and the following NOT NULL alter hard-crashes the downgrade.
    op.execute(
        """
        INSERT INTO sites (name, project_id, capture_schedule, capture_schedule_last_triggered_at)
        SELECT 'Site 1', p.id, p.capture_schedule, p.capture_schedule_last_triggered_at
        FROM projects p
        WHERE EXISTS (SELECT 1 FROM agents a WHERE a.project_id = p.id)
           OR EXISTS (SELECT 1 FROM agent_enrollment_tokens t WHERE t.project_id = p.id)
        """
    )

    with op.batch_alter_table("agents") as batch_op:
        batch_op.add_column(sa.Column("site_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE agents SET site_id = (
            SELECT sites.id FROM sites WHERE sites.project_id = agents.project_id
        )
        """
    )
    op.drop_index("ix_agents_project_id", table_name="agents")
    with op.batch_alter_table("agents") as batch_op:
        batch_op.alter_column("site_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_agents_site_id", "sites", ["site_id"], ["id"], ondelete="CASCADE"
        )
        batch_op.drop_constraint("fk_agents_project_id", type_="foreignkey")
        batch_op.drop_column("project_id")
    op.create_index("ix_agents_site_id", "agents", ["site_id"])

    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.add_column(sa.Column("site_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE agent_enrollment_tokens SET site_id = (
            SELECT sites.id FROM sites WHERE sites.project_id = agent_enrollment_tokens.project_id
        )
        """
    )
    op.drop_index("ix_agent_enrollment_tokens_project_id", table_name="agent_enrollment_tokens")
    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.alter_column("site_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_agent_enrollment_tokens_site_id", "sites", ["site_id"], ["id"], ondelete="CASCADE"
        )
        batch_op.drop_constraint("fk_agent_enrollment_tokens_project_id", type_="foreignkey")
        batch_op.drop_column("project_id")
    op.create_index("ix_agent_enrollment_tokens_site_id", "agent_enrollment_tokens", ["site_id"])

    with op.batch_alter_table("projects") as batch_op:
        batch_op.drop_column("capture_schedule_last_triggered_at")
        batch_op.drop_column("capture_schedule")
