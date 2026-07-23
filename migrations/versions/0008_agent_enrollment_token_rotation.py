"""agent_enrollment_tokens.agent_id — credential rotation tokens (Phase 6.2)

Adds a nullable agent_id FK to agent_enrollment_tokens. Set only for a
rotation token (minted by POST /api/fleet/agents/<id>/rotate-credential):
redeeming it reuses the existing Agent row instead of enrolling a new one.
NULL (the default) is an ordinary first-time enrollment token — purely
additive, existing tokens/flows are unaffected.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0008
Revises:     0007
Create Date: 2026-07-23

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.add_column(sa.Column("agent_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_agent_enrollment_tokens_agent_id", "agents", ["agent_id"], ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_agent_enrollment_tokens_agent_id", ["agent_id"])


def downgrade() -> None:
    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.drop_index("ix_agent_enrollment_tokens_agent_id")
        batch_op.drop_constraint("fk_agent_enrollment_tokens_agent_id", type_="foreignkey")
        batch_op.drop_column("agent_id")
