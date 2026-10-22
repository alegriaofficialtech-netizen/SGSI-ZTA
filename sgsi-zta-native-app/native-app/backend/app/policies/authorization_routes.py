from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.auth.dependencies import AuthenticatedSession, Database
from app.auth.security import digest
from app.database import now_utc
from app.models import LoginRateLimit
from app.models.policies import Policy, PolicyDecision
from app.policies.service import AuthorizationService
from app.schemas.policies import EvaluateInput, EvaluationResponse, SimulateInput
from app.services.audit import record

router = APIRouter(prefix="/authorization", tags=["Authorization"])


def consume_authz_rate_limit(
    db: Database,
    request: Request,
    *,
    bucket: str,
    default_limit: int = 30,
    window_seconds: int = 60,
) -> None:
    limit = getattr(request.app.state, "authz_rate_limit", default_limit)
    if limit is None:
        return
    peer = request.client.host if request.client else "unknown"
    key = digest(f"authz_rate_limit:{bucket}:{peer}")
    now = now_utc()
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    db.execute(
        insert(LoginRateLimit)
        .values(
            key=key,
            window_start=now,
            attempts=0,
        )
        .on_conflict_do_nothing(index_elements=["key"])
    )
    row = db.scalar(select(LoginRateLimit).where(LoginRateLimit.key == key).with_for_update())
    assert row is not None
    if row.window_start + timedelta(seconds=window_seconds) <= now:
        row.window_start, row.attempts = now, 0
    row.attempts += 1
    if row.attempts > limit:
        record(
            db,
            request,
            action="RATE_LIMITED",
            resource="authorization",
            decision="DENY",
            detail=f"Rate limit exceeded for {bucket}",
        )
        db.commit()
        raise HTTPException(
            429,
            "Rate limit exceeded for authorization operations. Please try again later.",
            headers={"Retry-After": str(window_seconds)},
        )


@router.post("/evaluate", response_model=EvaluationResponse)
def evaluate(
    body: EvaluateInput, request: Request, db: Database, session: AuthenticatedSession,
) -> EvaluationResponse:
    consume_authz_rate_limit(db, request, bucket=f"evaluate:{session.user.id}")
    if not {role.name for role in session.user.roles}.intersection({"admin-ti", "auditor"}):
        if not getattr(request.app.state, "allow_test_evaluate", False):
            record(
                db,
                request,
                action="ORACLE_PROBE_DENIED",
                resource="authorization",
                decision="DENY",
                user=session.user,
                detail="Role not permitted to evaluate authorization directly",
            )
            db.commit()
            raise HTTPException(403, "Your role does not permit authorization evaluations.")
    return AuthorizationService(db, request).authorize(session, **body.model_dump())


@router.post("/simulate", response_model=EvaluationResponse)
def simulate(
    body: SimulateInput, request: Request, db: Database, session: AuthenticatedSession,
) -> EvaluationResponse:
    consume_authz_rate_limit(db, request, bucket=f"simulate:{session.user.id}")
    return AuthorizationService(db, request).simulate(session, body)


@router.get("/metrics")
def metrics(db: Database, session: AuthenticatedSession) -> dict:
    if not {role.name for role in session.user.roles}.intersection({"admin-ti", "auditor"}):
        raise HTTPException(403, "Your role does not permit reading authorization metrics.")
    now = now_utc()
    since_24h = now - timedelta(hours=24)
    active_policies = db.scalar(
        select(func.count(Policy.id)).where(Policy.enabled.is_(True))
    ) or 0
    allow_24h = db.scalar(
        select(func.count(PolicyDecision.id)).where(
            PolicyDecision.decision == "ALLOW",
            PolicyDecision.created_at >= since_24h,
            PolicyDecision.simulation.is_(False),
        )
    ) or 0
    deny_24h = db.scalar(
        select(func.count(PolicyDecision.id)).where(
            PolicyDecision.decision == "DENY",
            PolicyDecision.created_at >= since_24h,
            PolicyDecision.simulation.is_(False),
        )
    ) or 0
    mfa_24h = db.scalar(
        select(func.count(PolicyDecision.id)).where(
            PolicyDecision.decision == "MFA_REQUIRED",
            PolicyDecision.created_at >= since_24h,
            PolicyDecision.simulation.is_(False),
        )
    ) or 0

    decisions_24h = list(
        db.execute(
            select(PolicyDecision.created_at, PolicyDecision.decision).where(
                PolicyDecision.created_at >= since_24h,
                PolicyDecision.simulation.is_(False),
            )
        )
    )
    hour_buckets = {}
    for i in range(24):
        slot = (now - timedelta(hours=23 - i)).strftime("%H:00")
        hour_buckets[slot] = {"hour": slot, "allow": 0, "deny": 0, "mfa": 0}

    for row_created_at, decision_val in decisions_24h:
        if row_created_at:
            slot = row_created_at.strftime("%H:00")
            if slot in hour_buckets:
                if decision_val == "ALLOW":
                    hour_buckets[slot]["allow"] += 1
                elif decision_val == "DENY":
                    hour_buckets[slot]["deny"] += 1
                elif decision_val == "MFA_REQUIRED":
                    hour_buckets[slot]["mfa"] += 1

    decisions_by_hour = list(hour_buckets.values())

    top_denied_rows = db.execute(
        select(PolicyDecision.resource, func.count(PolicyDecision.id))
        .where(
            PolicyDecision.decision == "DENY",
            PolicyDecision.created_at >= since_24h,
            PolicyDecision.simulation.is_(False),
        )
        .group_by(PolicyDecision.resource)
        .order_by(func.count(PolicyDecision.id).desc())
        .limit(10)
    ).all()
    top_denied_resources = [
        {"resource": res, "count": count} for res, count in top_denied_rows
    ]

    return {
        "active_policies_count": active_policies,
        "allow_24h_count": allow_24h,
        "deny_24h_count": deny_24h,
        "mfa_required_24h_count": mfa_24h,
        "decisions_by_hour": decisions_by_hour,
        "top_denied_resources": top_denied_resources,
        "allow_vs_deny": [
            {"name": "ALLOW", "value": allow_24h},
            {"name": "DENY", "value": deny_24h},
            {"name": "MFA_REQUIRED", "value": mfa_24h},
        ],
    }
