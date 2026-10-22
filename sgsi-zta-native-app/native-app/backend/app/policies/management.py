"""Allowlisted policy management; one transaction owns state, version and audit."""
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import now_utc
from app.models import Role, User
from app.models.policies import Policy, PolicyCondition, PolicyVersion
from app.policies.types import ConditionOperator, ConditionType, PolicyEffect
from app.schemas.policies import PolicyCreate, PolicyResponse, PolicyUpdate
from app.services import audit

_MUTABLE_FIELDS = (
    "name", "description", "resource", "action", "effect", "priority", "require_mfa",
    "max_risk_score", "required_device_trust", "session_max_age_minutes",
)


def invalid_reference(field: str) -> None:
    raise HTTPException(422, [{
        "loc": ["body", field], "msg": "One or more role references do not exist.",
        "type": "value_error",
    }])


def get_policy(db: Session, identifier: UUID, *, lock: bool = False) -> Policy:
    statement = select(Policy).where(Policy.id == str(identifier))
    if lock:
        # Serialize version numbering on the parent, not on a possibly absent version.
        statement = statement.with_for_update().execution_options(populate_existing=True)
    row = db.scalar(statement)
    if row is None:
        raise HTTPException(404, "Policy not found.")
    return row


class PolicyManagement:
    def __init__(self, db: Session, request: Request, actor: User) -> None:
        self.db = db
        self.request = request
        self.actor = actor

    def _apply(self, row: Policy, body: PolicyCreate | PolicyUpdate) -> None:
        fields = body.model_fields_set if isinstance(body, PolicyUpdate) else set(
            PolicyCreate.model_fields
        )
        for field in _MUTABLE_FIELDS:
            if field in fields:
                setattr(row, field, getattr(body, field))
        if "role_ids" in fields:
            roles = list(self.db.scalars(select(Role).where(
                Role.id.in_(body.role_ids)
            ).order_by(Role.id)))
            if len(roles) != len(body.role_ids):
                invalid_reference("role_ids")
            row.roles = roles
        if "conditions" in fields:
            referenced = set()
            for condition in body.conditions:
                if condition.condition_type == ConditionType.ROLE:
                    referenced.update(condition.value if condition.operator == ConditionOperator.IN
                                      else [condition.value])
            if referenced:
                known = set(self.db.scalars(select(Role.name).where(Role.name.in_(referenced))))
                if known != referenced:
                    invalid_reference("conditions")
            # Omission preserves existing IDs; explicit replacement uses new condition IDs.
            row.conditions = [PolicyCondition(**condition.model_dump())
                              for condition in body.conditions]
        if row.effect == PolicyEffect.ALLOW and not row.roles:
            raise HTTPException(422, [{
                "loc": ["body", "role_ids"],
                "msg": "Policies with effect ALLOW must specify at least one role_id.",
                "type": "value_error",
            }])

    def _persist(self, row: Policy, action: str) -> PolicyResponse:
        self.db.flush()
        number = (self.db.scalar(select(func.max(PolicyVersion.version)).where(
            PolicyVersion.policy_id == row.id
        )) or 0) + 1
        response = PolicyResponse.model_validate(row)
        # Same pure structured projection used by the seed; never include ORM user/session data.
        self.db.add(PolicyVersion(
            policy_id=row.id, version=number, snapshot_json=response.model_dump(mode="json"),
            created_by=self.actor.id,
        ))
        self.db.flush()
        audit.record(self.db, self.request, action, f"policy:{row.id}", "ALLOW", self.actor,
                     detail=f"version={number}")
        self.db.commit()
        return response

    def create(self, body: PolicyCreate) -> PolicyResponse:
        try:
            if self.db.scalar(select(Policy.id).where(Policy.policy_code == body.policy_code)):
                raise HTTPException(409, "Policy code already exists.")
            row = Policy(policy_code=body.policy_code, created_by=self.actor.id,
                         updated_by=self.actor.id, enabled=True, disabled_at=None)
            self._apply(row, body)
            self.db.add(row)
            return self._persist(row, "POLICY_CREATED")
        except IntegrityError as error:
            self.db.rollback()
            raise HTTPException(409, "Policy mutation conflicts with stored state.") from error
        except Exception:
            self.db.rollback()
            raise

    def update(self, identifier: UUID, body: PolicyUpdate) -> PolicyResponse:
        try:
            row = get_policy(self.db, identifier, lock=True)
            self._apply(row, body)
            row.updated_by = self.actor.id
            row.updated_at = now_utc()
            return self._persist(row, "POLICY_UPDATED")
        except IntegrityError as error:
            self.db.rollback()
            raise HTTPException(409, "Policy mutation conflicts with stored state.") from error
        except Exception:
            self.db.rollback()
            raise

    def disable(self, identifier: UUID) -> PolicyResponse:
        try:
            row = get_policy(self.db, identifier, lock=True)
            if not row.enabled:
                return PolicyResponse.model_validate(row)
            row.enabled = False
            row.disabled_at = now_utc()
            row.updated_at = row.disabled_at
            row.updated_by = self.actor.id
            return self._persist(row, "POLICY_DISABLED")
        except IntegrityError as error:
            self.db.rollback()
            raise HTTPException(409, "Policy mutation conflicts with stored state.") from error
        except Exception:
            self.db.rollback()
            raise
