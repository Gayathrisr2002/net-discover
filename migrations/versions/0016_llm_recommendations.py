"""llm_config, finding_recommendations — LLM-generated remediation recommendations

Adds llm_config (a singleton row holding the system-wide LLM connectivity
settings an admin sets on the System page) and finding_recommendations (a
dedup ledger, keyed like webhook_tickets, caching one generated
recommendation per deduplicated finding so it's generated once and reused
rather than re-calling the LLM on every view). Both new, empty tables;
nothing to backfill.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0016
Revises:     0015
Create Date: 2026-08-07

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "llm_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("base_url", sa.String(length=500), nullable=True),
        sa.Column("api_key", sa.Text(), nullable=True),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "finding_recommendations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "project_id", sa.Integer(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "project_id", "dedup_key", name="uq_finding_recommendation_project_dedup"
        ),
    )
    op.create_index(
        "ix_finding_recommendations_project_id", "finding_recommendations", ["project_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_finding_recommendations_project_id", table_name="finding_recommendations")
    op.drop_table("finding_recommendations")
    op.drop_table("llm_config")
