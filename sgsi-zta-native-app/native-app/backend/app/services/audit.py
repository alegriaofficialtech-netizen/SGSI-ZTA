from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User


def record(
    db: Session,
    request: Request,
    action: str,
    resource: str,
    decision: str,
    user: User | None = None,
    username: str = "anonymous",
    detail: str = "",
    policy_decision_id: str | None = None,
) -> None:
    """Callers supply fixed details; never persist request bodies or credentials."""
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else username[:80],
            action=action,
            resource=resource,
            decision=decision,
            ip=request.client.host if request.client else "unknown",
            detail=detail,
            policy_decision_id=policy_decision_id,
        )
    )
