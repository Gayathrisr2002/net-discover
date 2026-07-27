"""agents — health snapshot columns

Adds cpu_percent, memory_percent, disk_percent, uptime_s, capd_reachable,
capture_active, last_error to agents. All nullable, populated from the
agent's own heartbeat params (gateway/db.py:record_heartbeat) — purely
additive, existing agents/rows are unaffected until their next heartbeat.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0010
Revises:     0009
Create Date: 2026-07-27

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as batch_op:
        batch_op.add_column(sa.Column("cpu_percent", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("memory_percent", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("disk_percent", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("uptime_s", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("capd_reachable", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("capture_active", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("last_error", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents") as batch_op:
        batch_op.drop_column("last_error")
        batch_op.drop_column("capture_active")
        batch_op.drop_column("capd_reachable")
        batch_op.drop_column("uptime_s")
        batch_op.drop_column("disk_percent")
        batch_op.drop_column("memory_percent")
        batch_op.drop_column("cpu_percent")
