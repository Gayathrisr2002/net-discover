"""capture_sessions / scan_history agent_id — fleet attribution

Adds a nullable agent_id FK to capture_sessions and scan_history. NULL (the
default for every existing row and every locally-run scan/capture) is the
untouched, existing local path — this is purely additive. When set, the
capture/scan ran on a remote fleet agent rather than local capd/local
subprocess (see Phase 3/4 of the distributed-agent architecture: engine_pid/
engine_argv stay NULL for agent-attributed scan_history rows since there is
no local PID to reap — marlinspike.recovery's reaper must skip them).

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0005
Revises:     0004
Create Date: 2026-07-23

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("capture_sessions") as batch_op:
        batch_op.add_column(sa.Column("agent_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_capture_sessions_agent_id", "agents", ["agent_id"], ["id"], ondelete="SET NULL"
        )
    op.create_index("ix_capture_sessions_agent_id", "capture_sessions", ["agent_id"])

    with op.batch_alter_table("scan_history") as batch_op:
        batch_op.add_column(sa.Column("agent_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_scan_history_agent_id", "agents", ["agent_id"], ["id"], ondelete="SET NULL"
        )
    op.create_index("ix_scan_history_agent_id", "scan_history", ["agent_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_history_agent_id", table_name="scan_history")
    with op.batch_alter_table("scan_history") as batch_op:
        batch_op.drop_constraint("fk_scan_history_agent_id", type_="foreignkey")
        batch_op.drop_column("agent_id")

    op.drop_index("ix_capture_sessions_agent_id", table_name="capture_sessions")
    with op.batch_alter_table("capture_sessions") as batch_op:
        batch_op.drop_constraint("fk_capture_sessions_agent_id", type_="foreignkey")
        batch_op.drop_column("agent_id")
