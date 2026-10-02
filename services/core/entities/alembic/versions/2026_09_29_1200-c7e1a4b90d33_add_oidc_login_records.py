# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""add oidc login records

Revision ID: c7e1a4b90d33
Revises: b4c8d19f6a2e
Create Date: 2026-09-29 12:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c7e1a4b90d33"
down_revision: Union[str, Sequence[str], None] = "b4c8d19f6a2e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "oidc_login_records",
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("record_hash"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("oidc_login_records")
