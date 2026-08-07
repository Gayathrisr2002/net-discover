"""users — per-username login lockout columns

Adds failed_login_attempts (default 0) and locked_until (nullable) to
users, so auth.py:verify_user can lock out a specific account after too
many failed attempts — closing a gap where the existing login rate limit
is keyed by source IP only (a distributed attacker could otherwise throw
unlimited guesses at one username, each IP individually staying under
the per-IP limit). Purely additive; existing users start unlocked with
zero failed attempts.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0013
Revises:     0012
Create Date: 2026-08-06

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("locked_until", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("locked_until")
        batch_op.drop_column("failed_login_attempts")
