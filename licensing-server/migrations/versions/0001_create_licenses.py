"""Create the licensing records table.

Revision ID: 0001_create_licenses
Revises:
Create Date: 2026-10-24
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_create_licenses"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "licenses",
        sa.Column("license_id", sa.String(length=36), nullable=False),
        sa.Column("customer_name", sa.String(length=200), nullable=False),
        sa.Column("activation_code_hash", sa.String(length=64), nullable=False),
        sa.Column("registered_device_id", sa.String(length=256), nullable=True),
        sa.Column("license_type", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activation_status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "license_type IN ('lifetime', 'annual')", name="ck_license_type"
        ),
        sa.CheckConstraint(
            "activation_status IN ('pending', 'active', 'revoked')",
            name="ck_activation_status",
        ),
        sa.PrimaryKeyConstraint("license_id"),
        sa.UniqueConstraint("activation_code_hash", name="uq_activation_code_hash"),
    )
    op.create_index(
        "ix_licenses_activation_status", "licenses", ["activation_status"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_licenses_activation_status", table_name="licenses")
    op.drop_table("licenses")
