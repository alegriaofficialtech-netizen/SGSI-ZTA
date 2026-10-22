"""Zero Trust Policy Enforcement Point (PEP) for Monitoring Management.

Integrates with M5 Zero Trust evaluation and persists policy decisions and audit logs.
"""
from typing import Literal
from uuid import uuid4

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.database import now_utc
from app.models import User, UserSession
from app.models.policies import PolicyDecision
from app.policies.types import Action, Decision, DeviceTrust, ReasonCode
from app.services import audit

MonitoringResource = Literal[
    "monitoring",
    "monitoring-sources",
    "monitoring-events",
    "alerts",
    "alert-rules",
    "monitoring-fim",
]
MonitoringAction = Action | Literal["read", "manage", "create", "update", "scan"]


class MonitoringPEP:
    """Enforces Zero Trust authorization for monitoring administration."""

    def __init__(self, db: Session, request: Request) -> None:
        self.db = db
        self.request = request

    def authorize(
        self,
        session: UserSession,
        *,
        resource: MonitoringResource,
        action: MonitoringAction,
    ) -> User:
        """Authorize human operators for monitoring resources.

        Permissions:
        - resources "monitoring", "monitoring-sources", "alerts", "alert-rules":
            - action "read": allowed for admin-ti, auditor
            - action "manage" / create / update: allowed only for admin-ti
            - other roles: DENY (ROLE_NOT_ALLOWED)
        """
        user = session.user
        roles = {role.name for role in user.roles}

        is_allowed = False
        reason = ReasonCode.ROLE_NOT_ALLOWED

        if action in (Action.READ, "read"):
            action_enum = Action.READ
            if roles.intersection({"admin-ti", "auditor"}):
                is_allowed = True
                reason = ReasonCode.POLICY_ALLOW
        elif action in (Action.CREATE, "create"):
            action_enum = Action.CREATE
            if "admin-ti" in roles:
                is_allowed = True
                reason = ReasonCode.POLICY_ALLOW
        else:
            action_enum = Action.UPDATE
            if "admin-ti" in roles:
                is_allowed = True
                reason = ReasonCode.POLICY_ALLOW

        decision = Decision.ALLOW if is_allowed else Decision.DENY

        # Persist Zero Trust Policy Decision
        decision_id = str(uuid4())
        decision_row = PolicyDecision(
            id=decision_id,
            user_id=user.id,
            session_id=session.id,
            policy_id=None,
            resource=resource,
            action=action_enum,
            decision=decision,
            reason_code=reason,
            risk_score_snapshot=0,
            risk_level_snapshot="LOW",
            mfa_snapshot=session.mfa_verified_at is not None,
            device_trust_snapshot=DeviceTrust.TRUSTED,
            simulation=False,
            created_at=now_utc(),
        )
        self.db.add(decision_row)
        self.db.flush()

        # Record audit log linked to decision
        audit_action = "ACCESS_ALLOWED" if is_allowed else "ACCESS_DENIED"
        audit.record(
            self.db,
            self.request,
            audit_action,
            resource,
            decision.value,
            user,
            detail=f"action={action_enum.value} reason={reason.value}",
            policy_decision_id=decision_id,
        )
        self.db.commit()

        if not is_allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Acceso denegado por política Zero Trust para {resource}:{action}",
            )

        return user
