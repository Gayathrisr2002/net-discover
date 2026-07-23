"""sites.capture_policy — per-site capture policy

Adds a nullable capture_policy Text column to sites, mirroring
projects.capture_policy exactly (same JSON shape: enabled,
allowed_interfaces, max_session_duration_s, max_total_bytes,
operator_warning). NULL (the default) means no site-level restriction —
purely additive, existing sites are unaffected.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0006
Revises:     0005
Create Date: 2026-07-23

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("sites") as batch_op:
        batch_op.add_column(sa.Column("capture_policy", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sites") as batch_op:
        batch_op.drop_column("capture_policy")
