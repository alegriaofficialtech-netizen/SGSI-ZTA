import re
from datetime import UTC, datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from app.models.assets import Criticality
from app.models.risks import RiskLevel
from app.policies.types import (
    MAX_PRIORITY,
    MAX_RISK_SCORE,
    MAX_SESSION_AGE_MINUTES,
    Action,
    ConditionOperator,
    ConditionType,
    Decision,
    DeviceStatus,
    DeviceTrust,
    PolicyEffect,
    ReasonCode,
)

PositiveId = Annotated[StrictInt, Field(ge=1, le=2147483647)]
Resource = Annotated[
    str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
]
PolicyCode = Annotated[
    str, Field(min_length=3, max_length=40, pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
]
Priority = Annotated[StrictInt, Field(ge=0, le=MAX_PRIORITY)]
RiskScore = Annotated[StrictInt, Field(ge=0, le=MAX_RISK_SCORE)]
SessionAge = Annotated[StrictInt, Field(ge=1, le=MAX_SESSION_AGE_MINUTES)]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ConditionInput(InputModel):
    condition_type: ConditionType
    operator: ConditionOperator
    value: object

    @model_validator(mode="after")
    def typed_value(self) -> Self:
        kind, operator, value = self.condition_type, self.operator, self.value
        if kind == ConditionType.MFA:
            valid = operator == ConditionOperator.EQ and type(value) is bool
        elif kind in (ConditionType.RISK_SCORE, ConditionType.SESSION_AGE):
            maximum = (
                MAX_RISK_SCORE if kind == ConditionType.RISK_SCORE else MAX_SESSION_AGE_MINUTES
            )
            valid = (
                operator in (ConditionOperator.EQ, ConditionOperator.LTE, ConditionOperator.GTE)
                and type(value) is int
                and 0 <= value <= maximum
            )
        elif kind == ConditionType.TIME_WINDOW:
            valid = (
                operator == ConditionOperator.BETWEEN
                and isinstance(value, dict)
                and set(value) == {"start", "end"}
                and all(
                    isinstance(time, str) and re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", time)
                    for time in value.values()
                )
                and value["start"] != value["end"]
            )
        else:
            choices = {
                ConditionType.ASSET_CRITICALITY: set(Criticality),
                ConditionType.RISK_LEVEL: set(RiskLevel),
                ConditionType.DEVICE_TRUST: set(DeviceTrust),
            }
            values = value if operator == ConditionOperator.IN else [value]
            valid = (
                operator in (ConditionOperator.EQ, ConditionOperator.IN)
                and isinstance(values, list)
                and 1 <= len(values) <= 20
                and all(isinstance(item, str) for item in values)
            )
            if valid and kind == ConditionType.ROLE:
                valid = all(
                    len(item) <= 50 and re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", item)
                    for item in values
                )
            elif valid:
                valid = all(item in choices[kind] for item in values)
        if not valid:
            raise ValueError("Condition operator/value does not match its typed condition")
        return self


class ConditionResponse(ConditionInput):
    model_config = ConfigDict(from_attributes=True, extra="forbid")
    id: UUID


class EvaluateInput(InputModel):
    resource: Resource
    action: Action
    asset_id: PositiveId | None = None
    device_id: UUID | None = None


class SimulateInput(EvaluateInput):
    subject_user_id: PositiveId
    assume_mfa: StrictBool = False


class PolicyFields(InputModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    resource: Resource
    action: Action
    effect: PolicyEffect
    priority: Priority = 100
    require_mfa: StrictBool = False
    max_risk_score: RiskScore | None = None
    required_device_trust: DeviceTrust | None = None
    session_max_age_minutes: SessionAge | None = None
    role_ids: list[PositiveId] = Field(default_factory=list, max_length=20)
    conditions: list[ConditionInput] = Field(default_factory=list, max_length=32)

    @field_validator("role_ids")
    @classmethod
    def unique_roles(cls, values):
        if values is None:
            return values
        if len(set(values)) != len(values):
            raise ValueError("Role IDs must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_allow_roles(self) -> Self:
        if self.effect == PolicyEffect.ALLOW and not self.role_ids:
            raise ValueError("Policies with effect ALLOW must specify at least one role_id")
        return self


class PolicyCreate(PolicyFields):
    policy_code: PolicyCode


class PolicyUpdate(InputModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    resource: Resource | None = None
    action: Action | None = None
    effect: PolicyEffect | None = None
    priority: Priority | None = None
    require_mfa: StrictBool | None = None
    max_risk_score: RiskScore | None = None
    required_device_trust: DeviceTrust | None = None
    session_max_age_minutes: SessionAge | None = None
    role_ids: list[PositiveId] | None = Field(default=None, max_length=20)
    conditions: list[ConditionInput] | None = Field(default=None, max_length=32)
    unique_roles = field_validator("role_ids")(PolicyFields.unique_roles.__func__)

    @model_validator(mode="after")
    def nonnullable_fields(self) -> Self:
        nullable = {"max_risk_score", "required_device_trust", "session_max_age_minutes"}
        for name in self.model_fields_set - nullable:
            if getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        if not self.model_fields_set:
            raise ValueError("At least one policy field must be supplied")
        if self.effect == PolicyEffect.ALLOW and self.role_ids is not None and not self.role_ids:
            raise ValueError("Policies with effect ALLOW must specify at least one role_id")
        return self


class PolicyResponse(PolicyFields):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    policy_code: PolicyCode
    enabled: bool
    roles: list[str] = Field(default_factory=list)
    conditions: list[ConditionResponse]
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None
    created_by: int
    updated_by: int

    @field_validator("roles", mode="before")
    @classmethod
    def extract_role_names(cls, values):
        if not values:
            return []
        result = []
        for v in values:
            if hasattr(v, "name"):
                result.append(v.name)
            elif isinstance(v, str):
                result.append(v)
            else:
                result.append(str(v))
        return result


class EvaluationContext(BaseModel):
    mfa_verified: bool
    device_trust: DeviceTrust
    effective_risk_score: RiskScore
    effective_risk_level: RiskLevel


class EvaluationResponse(BaseModel):
    decision: Decision
    reason_code: ReasonCode
    policy_code: str | None
    evaluation_id: UUID
    context: EvaluationContext


class AuthorizationErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ReasonCode
    message: str
    decision_id: UUID
    policy_code: str | None = None
    context: EvaluationContext | None = None


class PolicyDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    user_id: int
    session_id: UUID | None
    policy_id: UUID | None
    resource: str
    action: Action
    asset_id: int | None
    device_id: UUID | None
    decision: Decision
    reason_code: ReasonCode
    risk_score_snapshot: int
    risk_level_snapshot: RiskLevel
    mfa_snapshot: bool
    device_trust_snapshot: DeviceTrust
    simulation: bool
    created_at: datetime
    subject_username: str | None = None
    policy_code: str | None = None


class PolicyVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    policy_id: UUID
    version: int
    snapshot_json: dict
    created_at: datetime
    created_by: int


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    device_code: str
    name: str
    assigned_user_id: int | None
    trust_level: DeviceTrust
    status: DeviceStatus
    last_seen_at: datetime | None
    synthetic: bool
    created_at: datetime
    updated_at: datetime


class PageFilters(InputModel):
    page: Annotated[StrictInt, Field(ge=1, le=100000)] = 1
    page_size: Annotated[StrictInt, Field(ge=1, le=100)] = 20


class PolicyFilters(PageFilters):
    resource: Resource | None = None
    action: Action | None = None
    enabled: StrictBool | None = None


class DecisionFilters(PageFilters):
    decision: Decision | None = None
    user_id: PositiveId | None = None
    resource: Resource | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    simulation: StrictBool | None = None

    @field_validator("date_from", "date_to")
    @classmethod
    def utc_date(cls, value):
        return value.astimezone(UTC).replace(tzinfo=None) if value and value.tzinfo else value

    @model_validator(mode="after")
    def ordered_dates(self) -> Self:
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must not exceed date_to")
        return self


class Page(BaseModel):
    page: int
    page_size: int
    total: int
    pages: int


class PolicyPage(Page):
    items: list[PolicyResponse]


class DecisionPage(Page):
    items: list[PolicyDecisionResponse]


class DevicePage(Page):
    items: list[DeviceResponse]


class ClinicalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    demo_id: str
    patient_synthetic_name: str
    age_range: str
    department: str
    record_type: str
    status: str
    diagnosis_summary: str | None = None
    phi_classified: bool
    decision_id: str
    policy_code: str | None = None
    context: EvaluationContext | None = None


class ClinicalSummaryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    demo_id: str
    patient_synthetic_name: str | None = None
    age_range: str | None = None
    department: str | None = None
    record_type: str | None = None
    status: str
    diagnosis_summary: str | None = None
    phi_classified: bool | None = None
    access_decision: str
    decision_id: str

