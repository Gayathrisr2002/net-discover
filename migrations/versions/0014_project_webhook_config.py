"""projects — outbound webhook config

Adds webhook_config (nullable JSON-encoded text) to projects, following
the same per-project JSON-text-column pattern as capture_policy/
capture_schedule. Lets an owner point completed scans at an external
receiver (e.g. a ticketing platform) — see marlinspike/webhook.py.
Purely additive; existing projects start with no webhook configured.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0014
Revises:     0013
Create Date: 2026-08-07

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as batch_op:
        batch_op.add_column(sa.Column("webhook_config", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("projects") as batch_op:
        batch_op.drop_column("webhook_config")
