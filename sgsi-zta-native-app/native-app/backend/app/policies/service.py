"""Reusable authorization boundary: outcome and linked audit commit before returning."""
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User, UserSession
from app.models.policies import Policy, PolicyDecision
from app.models.risks import RiskLevel
from app.policies.context import PolicyContext, active_user, real_context, simulation_context
from app.policies.engine import EngineOutcome, PolicyRule, evaluate
from app.policies.types import Action, Decision
from app.schemas.policies import EvaluateInput, EvaluationContext, EvaluationResponse, SimulateInput
from app.seed import DEMO_USERS
from app.services import audit

_DEMO_USERNAMES = frozenset(username for username, *_ in DEMO_USERS)
_EVENT_NAMES = {
    Decision.ALLOW: "ACCESS_ALLOWED",
    Decision.DENY: "ACCESS_DENIED",
    Decision.MFA_REQUIRED: "ACCESS_MFA_REQUIRED",
}


class AuthorizationService:
    def __init__(self, db: Session, request: Request) -> None:
        self.db = db
        self.request = request

    def authorize(
        self, authenticated_session: UserSession, *, resource: str, action: Action | str,
        asset_id: int | None = None, device_id: UUID | str | None = None,
    ) -> EvaluationResponse:
        """Caller supplies a fully validated M2 session, never a password challenge."""
        selectors = EvaluateInput(
            resource=resource, action=action, asset_id=asset_id, device_id=device_id,
        )
        context = real_context(self.db, authenticated_session, **selectors.model_dump())
        return self._evaluate_and_persist(context, active_user(self.db, context.user_id))

    def simulate(
        self, authenticated_session: UserSession, selectors: SimulateInput,
    ) -> EvaluationResponse:
        operator = active_user(self.db, authenticated_session.user_id)
        if not {role.name for role in operator.roles}.intersection({"admin-ti", "auditor"}):
            raise HTTPException(403, "Your role does not permit simulation.")
        # Absence and non-demo identity are input/RBAC failures, not engine decisions.
        subject = self.db.scalar(select(User).where(
            User.id == selectors.subject_user_id
        ).execution_options(populate_existing=True))
        if subject is None:
            raise HTTPException(404, "Simulation subject not found.")
        if subject.username not in _DEMO_USERNAMES or not subject.is_active:
            raise HTTPException(403, "Simulation requires an active academic demo subject.")
        context = simulation_context(
            self.db, subject, selectors.resource, selectors.action,
            selectors.asset_id, selectors.device_id, assume_mfa=selectors.assume_mfa,
        )
        return self._evaluate_and_persist(context, operator)

    def _rules(self, context: PolicyContext) -> list[PolicyRule]:
        rows = self.db.scalars(select(Policy).where(
            Policy.enabled.is_(True), Policy.resource == context.resource,
            Policy.action == context.action,
        ).execution_options(populate_existing=True))
        return [
            PolicyRule(
                id=row.id, policy_code=row.policy_code, resource=row.resource, action=row.action,
                effect=row.effect, priority=row.priority, enabled=row.enabled,
                role_names=frozenset(role.name for role in row.roles),
                require_mfa=row.require_mfa, max_risk_score=row.max_risk_score,
                required_device_trust=row.required_device_trust,
                session_max_age_minutes=row.session_max_age_minutes,
                conditions=tuple({
                    "condition_type": item.condition_type, "operator": item.operator,
                    "value": item.value,
                } for item in row.conditions),
            )
            for row in rows
        ]

    def _evaluate_and_persist(self, context: PolicyContext, actor: User) -> EvaluationResponse:
        try:
            outcome: EngineOutcome = evaluate(context, self._rules(context))
            safe_context = EvaluationContext(
                mfa_verified=context.mfa_verified, device_trust=context.device_trust,
                effective_risk_score=(
                    context.effective_risk_score if context.effective_risk_score is not None else 0
                ),
                effective_risk_level=context.effective_risk_level or RiskLevel.LOW,
            )
            row = PolicyDecision(
                user_id=context.user_id, session_id=context.session_id,
                policy_id=outcome.policy_id, resource=context.resource, action=context.action,
                asset_id=context.asset_id, device_id=context.device_id,
                decision=outcome.decision, reason_code=outcome.reason_code,
                risk_score_snapshot=safe_context.effective_risk_score,
                risk_level_snapshot=safe_context.effective_risk_level,
                mfa_snapshot=context.mfa_verified, device_trust_snapshot=context.device_trust,
                simulation=context.simulation,
            )
            self.db.add(row)
            self.db.flush()  # Materialize UUID/FK before recording the linked audit.
            audit.record(
                self.db, self.request,
                "SIMULATION_DECISION" if context.simulation else _EVENT_NAMES[outcome.decision],
                context.resource, outcome.decision.value, actor,
                detail=outcome.reason_code.value, policy_decision_id=row.id,
            )
            response = EvaluationResponse(
                decision=outcome.decision, reason_code=outcome.reason_code,
                policy_code=outcome.policy_code, evaluation_id=row.id, context=safe_context,
            )
            self.db.commit()  # All three outcomes are durable before a later clinical 403.
            return response
        except Exception:
            self.db.rollback()
            raise
