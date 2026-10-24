from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.database import Base, get_db, make_engine
from app.models import License
from app.rate_limit import SlidingWindowRateLimiter, enforce_rate_limit
from app.schemas import (
    ActivationRequest,
    CreateLicenseRequest,
    LicenseOutput,
    LicenseStatusRequest,
    LicenseType,
    RevokeLicenseRequest,
)
from app.security import (
    activation_code_hash,
    as_utc,
    generate_activation_code,
    load_signing_key,
    public_key_base64,
    sign_license,
    utc_now,
)

logger = logging.getLogger("licensing_api")


def _effective_status(record: License, now: datetime | None = None) -> str:
    if record.activation_status == "revoked":
        return "revoked"
    expires_at = as_utc(record.expires_at)
    if expires_at is not None and expires_at <= (now or utc_now()):
        return "expired"
    return record.activation_status


def _license_output(record: License) -> dict[str, Any]:
    return {
        "license_id": record.license_id,
        "customer_name": record.customer_name,
        "registered_device_id": record.registered_device_id,
        "license_type": record.license_type,
        "expires_at": record.expires_at,
        "activation_status": _effective_status(record),
        "created_at": record.created_at,
        "activated_at": record.activated_at,
        "revoked_at": record.revoked_at,
        "revoked_reason": record.revoked_reason,
    }


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "license_not_found", "message": "License not found."},
    )


def _check_admin(authorization: str | None, expected_token: str | None) -> None:
    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail={"code": "admin_auth_unavailable", "message": "Administrative API is not configured."},
        )
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied, expected_token):
        raise HTTPException(
            status_code=401,
            detail={"code": "admin_auth_required", "message": "Valid administrator credentials are required."},
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    engine = make_engine(settings.database_url)
    if settings.app_env != "production":
        # Development convenience only. Production schema changes run through Alembic.
        Base.metadata.create_all(bind=engine)
    signing_key = load_signing_key(settings)
    session_factory = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
    )

    app = FastAPI(title="Store Manager Licensing API", version="0.2.0")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.signing_key = signing_key
    app.state.rate_limiter = SlidingWindowRateLimiter()

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Do not echo submitted activation codes or device IDs in validation responses.
        details = [
            {key: error[key] for key in ("loc", "msg", "type") if key in error}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})

    @app.exception_handler(Exception)
    async def unexpected_error_handler(_request: Request, exc: Exception) -> JSONResponse:
        # Keep response bodies generic and avoid logging request bodies or secret values.
        logger.error("Unhandled licensing API exception: %s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"detail": {"code": "internal_error", "message": "An internal error occurred."}},
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/public-key")
    def get_public_key() -> dict[str, str]:
        return {
            "algorithm": "Ed25519",
            "key_id": settings.signing_key_id,
            "public_key": public_key_base64(signing_key),
            "encoding": "base64-raw-32-byte-key",
        }

    @app.post("/api/v1/licenses/activate")
    def activate_license(
        request: Request,
        payload: ActivationRequest,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_rate_limit(request, "activate", 10)
        code_hash = activation_code_hash(payload.activation_code)
        record = db.scalar(
            select(License)
            .where(License.activation_code_hash == code_hash)
            .with_for_update()
        )
        if record is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "invalid_activation", "message": "Activation could not be completed."},
            )
        status = _effective_status(record)
        if status == "revoked":
            raise HTTPException(
                status_code=403,
                detail={"code": "license_unavailable", "message": "This license is unavailable."},
            )
        if status == "expired":
            raise HTTPException(
                status_code=403,
                detail={"code": "license_expired", "message": "This license has expired."},
            )
        if record.registered_device_id and not secrets.compare_digest(
            record.registered_device_id, payload.device_id
        ):
            raise HTTPException(
                status_code=409,
                detail={"code": "device_mismatch", "message": "This license is registered to another device."},
            )

        now = utc_now()
        if record.activation_status == "pending":
            record.registered_device_id = payload.device_id
            record.activation_status = "active"
            record.activated_at = now
            if record.license_type == LicenseType.annual.value and record.expires_at is None:
                record.expires_at = now + timedelta(days=365)
            db.commit()
            db.refresh(record)
        return {
            "license": sign_license(record, signing_key, settings.signing_key_id, now),
            "activation_status": _effective_status(record),
        }

    @app.post("/api/v1/licenses/status")
    def check_license_status(
        request: Request,
        payload: LicenseStatusRequest,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_rate_limit(request, "status", 60)
        try:
            license_id = str(uuid.UUID(payload.license_id))
        except ValueError:
            raise _not_found()
        record = db.get(License, license_id)
        if (
            record is None
            or record.registered_device_id is None
            or not secrets.compare_digest(record.registered_device_id, payload.device_id)
        ):
            raise _not_found()
        status = _effective_status(record)
        return {
            "license_id": record.license_id,
            "activation_status": status,
            "license_type": record.license_type,
            "expires_at": record.expires_at,
            "is_active": status == "active",
        }

    @app.post("/api/v1/admin/licenses", status_code=201)
    def create_license(
        request: Request,
        payload: CreateLicenseRequest,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_rate_limit(request, "admin", 30)
        _check_admin(authorization, settings.admin_api_token)
        activation_code = generate_activation_code()
        record = License(
            license_id=str(uuid.uuid4()),
            customer_name=payload.customer_name,
            activation_code_hash=activation_code_hash(activation_code),
            registered_device_id=None,
            license_type=payload.license_type.value,
            expires_at=as_utc(payload.expires_at),
            activation_status="pending",
            created_at=utc_now(),
        )
        db.add(record)
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
        db.refresh(record)
        return {
            "license": _license_output(record),
            # Shown only in this authenticated response; the database stores only its hash.
            "activation_code": activation_code,
        }

    @app.get("/api/v1/admin/licenses", response_model=list[LicenseOutput])
    def list_licenses(
        request: Request,
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_rate_limit(request, "admin", 30)
        _check_admin(authorization, settings.admin_api_token)
        records = db.scalars(
            select(License).order_by(License.created_at.desc()).limit(limit).offset(offset)
        ).all()
        return [_license_output(record) for record in records]

    @app.get("/api/v1/admin/licenses/{license_id}", response_model=LicenseOutput)
    def get_license(
        request: Request,
        license_id: str,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_rate_limit(request, "admin", 30)
        _check_admin(authorization, settings.admin_api_token)
        try:
            normalized_id = str(uuid.UUID(license_id))
        except ValueError:
            raise _not_found()
        record = db.scalar(
            select(License).where(License.license_id == normalized_id).with_for_update()
        )
        if record is None:
            raise _not_found()
        return _license_output(record)

    @app.post("/api/v1/admin/licenses/{license_id}/issue")
    def issue_signed_license(
        request: Request,
        license_id: str,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_rate_limit(request, "admin", 30)
        _check_admin(authorization, settings.admin_api_token)
        try:
            normalized_id = str(uuid.UUID(license_id))
        except ValueError:
            raise _not_found()
        record = db.scalar(
            select(License).where(License.license_id == normalized_id).with_for_update()
        )
        if record is None:
            raise _not_found()
        if _effective_status(record) != "active" or not record.registered_device_id:
            raise HTTPException(
                status_code=409,
                detail={"code": "license_not_issuable", "message": "Only active licenses can be issued."},
            )
        return {"license": sign_license(record, signing_key, settings.signing_key_id)}

    @app.post("/api/v1/admin/licenses/{license_id}/revoke", response_model=LicenseOutput)
    def revoke_license(
        request: Request,
        license_id: str,
        payload: RevokeLicenseRequest,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_rate_limit(request, "admin", 30)
        _check_admin(authorization, settings.admin_api_token)
        try:
            normalized_id = str(uuid.UUID(license_id))
        except ValueError:
            raise _not_found()
        record = db.get(License, normalized_id)
        if record is None:
            raise _not_found()
        if record.activation_status != "revoked":
            record.activation_status = "revoked"
            record.revoked_at = utc_now()
            record.revoked_reason = payload.reason.strip() if payload.reason else None
            db.commit()
            db.refresh(record)
        return _license_output(record)

    return app
