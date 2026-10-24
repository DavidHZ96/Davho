from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class License(Base):
    __tablename__ = "licenses"
    __table_args__ = (
        CheckConstraint("license_type IN ('lifetime', 'annual')", name="ck_license_type"),
        CheckConstraint(
            "activation_status IN ('pending', 'active', 'revoked')",
            name="ck_activation_status",
        ),
        UniqueConstraint("activation_code_hash", name="uq_activation_code_hash"),
        Index("ix_licenses_activation_status", "activation_status"),
    )

    license_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    activation_code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    registered_device_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    license_type: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
