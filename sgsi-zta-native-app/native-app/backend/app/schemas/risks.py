from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.risks import (
    ControlCategory,
    Impact,
    ImplementationStatus,
    Probability,
    RelationshipType,
    RiskLevel,
    RiskStatus,
    Treatment,
)
from app.schemas.assets import OwnerPublic
from app.schemas.identity import AuditPublic


class CatalogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    code: str
    name: str
    description: str
    category: str
    active: bool


class AssetReference(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_code: str
    name: str


class RiskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    risk_code: str = Field(min_length=3, max_length=40, pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
    title: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    asset_id: int = Field(gt=0)
    threat_id: int = Field(gt=0)
    vulnerability_id: int = Field(gt=0)
    probability: Probability
    impact: Impact
    treatment: Treatment = Treatment.REDUCE
    status: RiskStatus = RiskStatus.OPEN
    owner_user_id: int = Field(gt=0)
    identified_at: datetime | None = None
    review_due_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def discard_client_calculation(cls, values):
        # POST compatibility: never trust supplied score/level. PATCH forbids them.
        if isinstance(values, dict):
            return {k: v for k, v in values.items() if k not in {"score", "level"}}
        return values

    @field_validator("probability", "impact", mode="before")
    @classmethod
    def integer_scale(cls, value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Selecciona un entero de 1 a 5")
        return value

    @field_validator("identified_at", "review_due_at")
    @classmethod
    def utc_date(cls, value):
        if value and value.tzinfo:
            return value.astimezone(UTC).replace(tzinfo=None)
        return value


class RiskUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(default="", min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    asset_id: int = Field(default=1, gt=0)
    threat_id: int = Field(default=1, gt=0)
    vulnerability_id: int = Field(default=1, gt=0)
    probability: Probability = Probability.RARE
    impact: Impact = Impact.INSIGNIFICANT
    treatment: Treatment = Treatment.REDUCE
    status: RiskStatus = RiskStatus.OPEN
    owner_user_id: int = Field(default=1, gt=0)
    review_due_at: datetime | None = None
    integer_scale = field_validator("probability", "impact", mode="before")(
        RiskCreate.integer_scale.__func__
    )
    utc_date = field_validator("review_due_at")(RiskCreate.utc_date.__func__)


class RiskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    risk_code: str
    title: str
    description: str
    asset_id: int
    threat_id: int
    vulnerability_id: int
    probability: Probability
    impact: Impact
    score: int
    level: RiskLevel
    treatment: Treatment
    status: RiskStatus
    owner_user_id: int
    identified_at: datetime
    review_due_at: datetime | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    asset: AssetReference
    threat: CatalogResponse
    vulnerability: CatalogResponse
    owner: OwnerPublic


class ControlCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    control_code: str = Field(min_length=3, max_length=40, pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    category: ControlCategory
    implementation_status: ImplementationStatus = ImplementationStatus.PLANNED
    owner_user_id: int = Field(gt=0)
    active: bool = True


class ControlUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(default="", min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    category: ControlCategory = ControlCategory.GOVERNANCE
    implementation_status: ImplementationStatus = ImplementationStatus.PLANNED
    owner_user_id: int = Field(default=1, gt=0)
    active: bool = True


class ControlResponse(ControlCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner: OwnerPublic
    created_at: datetime
    updated_at: datetime
    risk_count: int = 0


class LinkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    relationship_type: RelationshipType = RelationshipType.PREVENTIVE
    notes: str = Field(default="", max_length=1000)


class LinkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    risk_id: int
    control_id: int
    relationship_type: RelationshipType
    notes: str
    created_at: datetime
    active: bool
    control: ControlResponse


class RiskDetail(RiskResponse):
    controls: list[LinkResponse]
    history: list[AuditPublic]


class ControlDetail(ControlResponse):
    risks: list[RiskResponse]
    history: list[AuditPublic]


class RiskPage(BaseModel):
    items: list[RiskResponse]
    page: int
    page_size: int
    total: int
    pages: int


class ControlPage(BaseModel):
    items: list[ControlResponse]
    page: int
    page_size: int
    total: int
    pages: int
