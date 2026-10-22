from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select

from app.assets.service import asset_summary
from app.auth.dependencies import AuthenticatedSession, AuthenticatedUser, Database, require_roles
from app.database import now_utc
from app.models import AuditLog, MfaCredential, Role, User, UserSession
from app.policies.service import AuthorizationService
from app.policies.types import Decision
from app.risks.service import summary as risk_summary
from app.schemas.identity import AuditPublic

router = APIRouter(tags=["Overview"])
AuditReader = Annotated[User, Depends(require_roles("admin-ti", "auditor"))]


@router.get("/dashboard")
def dashboard(db: Database, user: AuthenticatedUser) -> dict:
    now = now_utc()
    global_scope = bool({role.name for role in user.roles} & {"admin-ti", "auditor"})
    audit_filters = [] if global_scope else [AuditLog.user_id == user.id]
    session_filters = [] if global_scope else [UserSession.user_id == user.id]
    user_filters = [] if global_scope else [User.id == user.id]
    recent = list(
        db.scalars(select(AuditLog).where(*audit_filters).order_by(AuditLog.id.desc()).limit(6))
    )
    buckets = []
    for offset in range(23, -1, -1):
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=offset)
        end = start + timedelta(hours=1)
        counts = dict(
            db.execute(
                select(AuditLog.decision, func.count())
                .where(
                    *audit_filters,
                    AuditLog.timestamp >= start,
                    AuditLog.timestamp < end,
                )
                .group_by(AuditLog.decision)
            ).all()
        )
        buckets.append(
            {
                "hour": start.isoformat() + "Z",
                "allow": counts.get("ALLOW", 0),
                "deny": counts.get("DENY", 0),
            }
        )
    return {
        "assets": asset_summary(db) if global_scope else None,
        "risk_management": risk_summary(db) if global_scope else None,
        "scope": "global" if global_scope else "own",
        "active_users": db.scalar(
            select(func.count(User.id)).where(*user_filters, User.is_active.is_(True))
        ),
        "active_sessions": db.scalar(
            select(func.count(UserSession.id)).where(
                *session_filters,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
            )
        ),
        "roles": db.scalar(select(func.count(Role.id))) if global_scope else len(user.roles),
        "mfa_enabled_users": db.scalar(
            select(func.count(User.id))
            .join(MfaCredential)
            .where(*user_filters, User.is_active.is_(True), MfaCredential.enabled.is_(True))
        ),
        "events_24h": db.scalar(
            select(func.count(AuditLog.id)).where(
                *audit_filters,
                AuditLog.timestamp >= now - timedelta(hours=24),
            )
        ),
        "logins_24h": db.scalar(
            select(func.count(AuditLog.id)).where(
                *audit_filters,
                AuditLog.action == "LOGIN_SUCCESS",
                AuditLog.timestamp >= now - timedelta(hours=24),
            )
        ),
        "activity": buckets,
        "recent_activity": [AuditPublic.model_validate(row).model_dump() for row in recent],
        "milestones": {
            "M0": "runtime verification required",
            "M1": "implemented",
            "M2": "implemented",
            "M3": "implemented",
            "M4": "implemented",
            "M5": "implemented",
        },
    }


@router.get("/audit", response_model=list[AuditPublic])
def audit(
    db: Database,
    request: Request,
    session: AuthenticatedSession,
    user: AuditReader,
) -> list[AuditLog]:
    outcome = AuthorizationService(db, request).authorize(
        session, resource="audit", action="read"
    )
    if outcome.decision != Decision.ALLOW:
        if outcome.decision == Decision.MFA_REQUIRED:
            raise HTTPException(403, "MFA requerido para consultar auditoría")
        raise HTTPException(403, "Acceso denegado por política Zero Trust")
    return list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(100)))
