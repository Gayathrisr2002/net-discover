"""scan_history (status, user_id) index

Adds a composite index on scan_history(status, user_id). The recovery reaper
queries status="running" on every boot, and the MARLINSPIKE_RUN_STORE=db
concurrency check queries (status, user_id) on every scan-start; without an
index these were full table scans that slow down as history grows (#68).

Existing deployments: run ``python -m marlinspike.db upgrade head`` to apply.

Revision ID: 0003
Revises:     0002
Create Date: 2026-07-18

"""

from __future__ import annotations

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_index(
        "ix_scan_history_status_user", "scan_history", ["status", "user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_scan_history_status_user", table_name="scan_history")
