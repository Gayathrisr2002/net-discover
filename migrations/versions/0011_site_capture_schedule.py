"""sites — automated capture schedule columns

Adds capture_schedule (JSON text) and capture_schedule_last_triggered_at
to sites. Both nullable, purely additive — existing sites are unaffected
until an operator configures a schedule via PUT
/api/fleet/sites/<id>/capture-schedule. See marlinspike/scheduler.py.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0011
Revises:     0010
Create Date: 2026-07-30

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("sites") as batch_op:
        batch_op.add_column(sa.Column("capture_schedule", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("capture_schedule_last_triggered_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sites") as batch_op:
        batch_op.drop_column("capture_schedule_last_triggered_at")
        batch_op.drop_column("capture_schedule")
