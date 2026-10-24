from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LicenseType(str, Enum):
    lifetime = "lifetime"
    annual = "annual"


class CreateLicenseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_name: Annotated[str, Field(min_length=1, max_length=200)]
    license_type: LicenseType
    expires_at: datetime | None = None

    @field_validator("customer_name")
    @classmethod
    def normalize_customer_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("customer_name cannot be blank")
        return value

    @model_validator(mode="after")
    def validate_expiration(self) -> "CreateLicenseRequest":
        if self.license_type == LicenseType.lifetime and self.expires_at is not None:
            raise ValueError("lifetime licenses cannot have an expiration date")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise ValueError("expires_at must include a timezone")
            if self.expires_at.astimezone(timezone.utc) <= datetime.now(timezone.utc):
                raise ValueError("expires_at must be in the future")
        return self


class ActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activation_code: Annotated[str, Field(min_length=16, max_length=100)]
    device_id: Annotated[str, Field(min_length=8, max_length=256)]

    @field_validator("activation_code")
    @classmethod
    def validate_activation_code(cls, value: str) -> str:
        value = value.strip()
        normalized = value.upper().replace("-", "")
        if not re.fullmatch(r"SM[A-HJ-NP-Z2-9]{32}", normalized):
            raise ValueError("activation_code has an invalid format")
        return value

    @field_validator("device_id")
    @classmethod
    def normalize_device_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("device_id cannot be blank")
        return value


class LicenseStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    license_id: Annotated[str, Field(min_length=36, max_length=36)]
    device_id: Annotated[str, Field(min_length=8, max_length=256)]

    @field_validator("device_id")
    @classmethod
    def normalize_device_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("device_id cannot be blank")
        return value


class RevokeLicenseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[str | None, Field(max_length=500)] = None


class LicenseOutput(BaseModel):
    license_id: str
    customer_name: str
    registered_device_id: str | None
    license_type: str
    expires_at: datetime | None
    activation_status: str
    created_at: datetime
    activated_at: datetime | None
    revoked_at: datetime | None
    revoked_reason: str | None
