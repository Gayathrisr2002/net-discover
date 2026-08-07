"""webhook_tickets — dedup ledger for platform-integrated webhook delivery

Adds the webhook_tickets table so a ticketing-platform delivery mode (e.g.
Zammad) can remember which finding already has an external ticket and
avoid creating a duplicate one every time a scan re-reports the same
persisting finding. New, empty table; nothing to backfill.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0015
Revises:     0014
Create Date: 2026-08-07

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "webhook_tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "project_id", sa.Integer(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("platform", sa.String(length=20), nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "project_id", "dedup_key", "platform", name="uq_webhook_ticket_project_dedup_platform"
        ),
    )
    op.create_index(
        "ix_webhook_tickets_project_id", "webhook_tickets", ["project_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_webhook_tickets_project_id", table_name="webhook_tickets")
    op.drop_table("webhook_tickets")
