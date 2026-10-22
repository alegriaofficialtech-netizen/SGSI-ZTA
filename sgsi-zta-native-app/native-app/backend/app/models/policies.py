from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from app.database import Base, now_utc
from app.models.identity import Role, User
from app.models.risks import RiskLevel
from app.policies.types import (
    Action,
    ConditionOperator,
    ConditionType,
    Decision,
    DeviceStatus,
    DeviceTrust,
    PolicyEffect,
    ReasonCode,
)


def new_id() -> str:
    return str(uuid4())


def choice(kind, name):
    return Enum(
        kind,
        native_enum=False,
        create_constraint=True,
        name=name,
        values_callable=lambda enum: [member.value for member in enum],
    )


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint("priority BETWEEN 0 AND 1000", name="ck_policies_priority"),
        CheckConstraint(
            "max_risk_score IS NULL OR max_risk_score BETWEEN 0 AND 25",
            name="ck_policies_risk",
        ),
        CheckConstraint(
            "session_max_age_minutes IS NULL OR session_max_age_minutes BETWEEN 1 AND 10080",
            name="ck_policies_session_age",
        ),
        CheckConstraint(
            "(enabled = true AND disabled_at IS NULL) OR "
            "(enabled = false AND disabled_at IS NOT NULL)",
            name="ck_policies_disabled",
        ),
        CheckConstraint(
            "length(policy_code) BETWEEN 3 AND 40",
            name="ck_policies_code_length",
        ),
        CheckConstraint(
            "length(resource) BETWEEN 1 AND 64 AND resource NOT LIKE '%*%' "
            "AND resource NOT LIKE '%/%'",
            name="ck_policies_resource",
        ),
        Index("ix_policies_lookup", "resource", "action", "enabled", "priority"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    resource: Mapped[str] = mapped_column(String(64))
    action: Mapped[Action] = mapped_column(choice(Action, "policy_action"))
    effect: Mapped[PolicyEffect] = mapped_column(choice(PolicyEffect, "policy_effect"))
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    max_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    required_device_trust: Mapped[DeviceTrust | None] = mapped_column(
        choice(DeviceTrust, "policy_required_device_trust"),
        nullable=True,
    )
    session_max_age_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    roles: Mapped[list[Role]] = relationship(secondary="policy_roles", lazy="selectin")
    conditions: Mapped[list["PolicyCondition"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    @property
    def role_ids(self) -> list[int]:
        return sorted(role.id for role in self.roles)


class PolicyRole(Base):
    __tablename__ = "policy_roles"
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True, index=True)


class PolicyCondition(Base):
    __tablename__ = "policy_conditions"
    __table_args__ = (Index("ix_policy_conditions_policy_type", "policy_id", "condition_type"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"),
        index=True,
    )
    condition_type: Mapped[ConditionType] = mapped_column(choice(ConditionType, "condition_type"))
    operator: Mapped[ConditionOperator] = mapped_column(
        choice(ConditionOperator, "condition_operator")
    )
    value: Mapped[object] = mapped_column(JSON)
    policy: Mapped[Policy] = relationship(back_populates="conditions")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (CheckConstraint("synthetic = true", name="ck_devices_synthetic"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    assigned_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    trust_level: Mapped[DeviceTrust] = mapped_column(choice(DeviceTrust, "device_trust"))
    status: Mapped[DeviceStatus] = mapped_column(
        choice(DeviceStatus, "device_status"), default="ACTIVE"
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    __table_args__ = (
        CheckConstraint("risk_score_snapshot BETWEEN 0 AND 25", name="ck_policy_decisions_risk"),
        Index("ix_policy_decisions_user_created", "user_id", "created_at"),
        Index("ix_policy_decisions_resource_created", "resource", "created_at"),
        Index("ix_policy_decisions_decision_created", "decision", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("sessions.id"), nullable=True, index=True
    )
    policy_id: Mapped[str | None] = mapped_column(
        ForeignKey("policies.id"), nullable=True, index=True
    )
    resource: Mapped[str] = mapped_column(String(64))
    action: Mapped[Action] = mapped_column(choice(Action, "policy_decision_action"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True, index=True)
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id"), nullable=True, index=True
    )
    decision: Mapped[Decision] = mapped_column(choice(Decision, "policy_decision"))
    reason_code: Mapped[ReasonCode] = mapped_column(choice(ReasonCode, "policy_reason_code"))
    risk_score_snapshot: Mapped[int] = mapped_column(Integer)
    risk_level_snapshot: Mapped[RiskLevel] = mapped_column(choice(RiskLevel, "policy_risk_level"))
    mfa_snapshot: Mapped[bool] = mapped_column(Boolean)
    device_trust_snapshot: Mapped[DeviceTrust] = mapped_column(
        choice(DeviceTrust, "policy_device_trust_snapshot"),
    )
    simulation: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    user: Mapped["User"] = relationship("User", lazy="selectin")
    policy: Mapped["Policy | None"] = relationship("Policy", lazy="selectin")

    @property
    def subject_username(self) -> str | None:
        return self.user.username if self.user else None

    @property
    def policy_code(self) -> str | None:
        return self.policy.policy_code if self.policy else None


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_policy_versions_number"),
        CheckConstraint("version >= 1", name="ck_policy_versions_positive"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    snapshot_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))


@event.listens_for(PolicyCondition, "before_insert")
@event.listens_for(PolicyCondition, "before_update")
def validate_condition(mapper, connection, target):
    # Validation only: structured values are never evaluated as code.
    from app.schemas.policies import ConditionInput

    target.value = ConditionInput(
        condition_type=target.condition_type,
        operator=target.operator,
        value=target.value,
    ).value


def reject_mutation(mapper, connection, target):
    raise ValueError(f"{type(target).__name__} is append-only")


for immutable in (PolicyDecision, PolicyVersion):
    event.listen(immutable, "before_update", reject_mutation)
    event.listen(immutable, "before_delete", reject_mutation)


@event.listens_for(Session, "do_orm_execute")
def reject_bulk_mutation(state):
    if state.is_update or state.is_delete:
        mapper = state.bind_mapper
        if (
            mapper is not None
            and mapper.class_ in (PolicyDecision, PolicyVersion)
            and state.statement.table is not mapper.local_table
        ):
            raise ValueError(f"{mapper.class_.__name__} is append-only")
    # An ORM predicate may bind a mapper to Core DML; only mapped table targets are guarded.
    # Explicit Core table DML remains available to isolated fixtures and controlled maintenance.
