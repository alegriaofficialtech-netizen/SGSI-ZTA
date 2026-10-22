"""Trusted scalar facts. HTTP routes cannot provide roles, assurance, risk or trust."""
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import now_utc
from app.models import Asset, User, UserSession
from app.models.assets import Criticality
from app.models.policies import Device
from app.models.risks import Risk, RiskLevel, RiskStatus
from app.policies.types import Action, DeviceStatus, DeviceTrust


def utc(value: datetime) -> datetime:
    """Existing naive database timestamps denote UTC, never host-local time."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True)
class PolicyContext:
    user_id: int
    roles: frozenset[str]
    session_id: str | None
    mfa_verified: bool
    session_age_minutes: float | None
    device_id: str | None
    device_trust: DeviceTrust
    asset_id: int | None
    asset_criticality: Criticality | None
    effective_risk_score: int | None
    effective_risk_level: RiskLevel | None
    effective_risk_id: int | None
    resource: str
    action: Action
    request_time: datetime
    simulation: bool


def active_user(db: Session, user_id: int) -> User:
    # populate_existing refreshes relationships too; JWT role claims are never used.
    user = db.scalar(select(User).where(User.id == user_id).execution_options(
        populate_existing=True
    ))
    if user is None or not user.is_active:
        raise HTTPException(401, "Active authentication is required.")
    return user


def _facts(
    db: Session, user: User, resource: str, action: Action, asset_id: int | None,
    device_id: UUID | None, *, session_id: str | None, mfa_verified: bool,
    age: float | None, moment: datetime, simulation: bool,
) -> PolicyContext:
    asset = db.scalar(select(Asset).where(Asset.id == asset_id).execution_options(
        populate_existing=True
    )) if asset_id is not None else None
    risk = db.scalar(
        select(Risk).where(
            Risk.asset_id == asset.id,
            Risk.status.in_((RiskStatus.OPEN, RiskStatus.IN_TREATMENT)),
        ).order_by(Risk.score.desc(), Risk.id.asc()).limit(1).execution_options(
            populate_existing=True
        )
    ) if asset is not None else None
    device = db.scalar(select(Device).where(Device.id == str(device_id)).execution_options(
        populate_existing=True
    )) if device_id is not None else None
    trust = DeviceTrust.UNTRUSTED
    if (
        device is not None and device.status == DeviceStatus.ACTIVE
        and device.assigned_user_id in (None, user.id)
    ):
        trust = DeviceTrust(device.trust_level)
    return PolicyContext(
        user_id=user.id, roles=frozenset(role.name for role in user.roles),
        session_id=session_id, mfa_verified=mfa_verified, session_age_minutes=age,
        device_id=device.id if device else None, device_trust=trust,
        asset_id=asset.id if asset else None,
        asset_criticality=asset.criticality if asset else None,
        # Unknown asset facts stay None internally; 0/LOW is only a response sentinel.
        effective_risk_score=(risk.score if risk else 0) if asset else None,
        effective_risk_level=(risk.level if risk else RiskLevel.LOW) if asset else None,
        effective_risk_id=risk.id if risk else None,
        resource=resource, action=action, request_time=utc(moment), simulation=simulation,
    )


def real_context(
    db: Session, authenticated_session: UserSession, resource: str, action: Action,
    asset_id: int | None = None, device_id: UUID | None = None,
) -> PolicyContext:
    """Only call after M2 AuthenticatedSession validation, including CSRF for POST."""
    user = active_user(db, authenticated_session.user_id)
    moment = utc(now_utc())
    elapsed = (moment - utc(authenticated_session.created_at)).total_seconds() / 60
    return _facts(
        db, user, resource, action, asset_id, device_id,
        session_id=authenticated_session.id,
        mfa_verified=authenticated_session.mfa_verified_at is not None,
        age=elapsed if elapsed >= 0 else None, moment=moment, simulation=False,
    )


def simulation_context(
    db: Session, subject: User, resource: str, action: Action,
    asset_id: int | None = None, device_id: UUID | None = None, *, assume_mfa: bool,
) -> PolicyContext:
    """The caller checks the academic demo allowlist. There is no subject session."""
    return _facts(
        db, subject, resource, action, asset_id, device_id,
        session_id=None, mfa_verified=assume_mfa, age=None,
        moment=utc(now_utc()), simulation=True,
    )
