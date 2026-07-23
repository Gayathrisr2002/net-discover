"""agent_credentials.cert_fingerprint_sha256 — mTLS client cert binding

Adds a nullable cert_fingerprint_sha256 column to agent_credentials (Phase
6: mTLS). NULL for credentials issued before this upgrade or when no fleet
CA is configured — purely additive, existing agents keep working via
bearer-credential-only auth.

Existing deployments: run ``python -m marlinspike.db upgrade head`` to
apply this migration.

Revision ID: 0007
Revises:     0006
Create Date: 2026-07-23

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("agent_credentials") as batch_op:
        batch_op.add_column(sa.Column("cert_fingerprint_sha256", sa.String(length=64), nullable=True))
        batch_op.create_index(
            "ix_agent_credentials_cert_fingerprint_sha256", ["cert_fingerprint_sha256"]
        )


def downgrade() -> None:
    with op.batch_alter_table("agent_credentials") as batch_op:
        batch_op.drop_index("ix_agent_credentials_cert_fingerprint_sha256")
        batch_op.drop_column("cert_fingerprint_sha256")
