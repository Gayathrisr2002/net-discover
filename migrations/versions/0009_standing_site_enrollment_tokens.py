"""agent_enrollment_tokens — standing per-site enrollment tokens

Adds is_standing (bool) and revoked_at (nullable datetime) to
agent_enrollment_tokens, and relaxes expires_at to nullable — a standing
token never expires by time, only by explicit revocation (rotation).
Existing one-time tokens are unaffected: is_standing defaults to False and
their expires_at/used_at behavior is unchanged.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0009
Revises:     0008
Create Date: 2026-07-27

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.add_column(
            sa.Column("is_standing", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch_op.add_column(sa.Column("revoked_at", sa.DateTime(), nullable=True))
        batch_op.alter_column("expires_at", existing_type=sa.DateTime(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("agent_enrollment_tokens") as batch_op:
        batch_op.alter_column("expires_at", existing_type=sa.DateTime(), nullable=False)
        batch_op.drop_column("revoked_at")
        batch_op.drop_column("is_standing")
