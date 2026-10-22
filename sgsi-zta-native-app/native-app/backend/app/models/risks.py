from datetime import datetime
from enum import IntEnum, StrEnum

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, now_utc
from app.models.assets import Asset
from app.models.identity import User


class Probability(IntEnum):
    RARE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    ALMOST_CERTAIN = 5


class Impact(IntEnum):
    INSIGNIFICANT = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    SEVERE = 5


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Treatment(StrEnum):
    ACCEPT = "ACCEPT"
    AVOID = "AVOID"
    REDUCE = "REDUCE"
    TRANSFER = "TRANSFER"


class RiskStatus(StrEnum):
    OPEN = "OPEN"
    IN_TREATMENT = "IN_TREATMENT"
    ACCEPTED = "ACCEPTED"
    CLOSED = "CLOSED"


class ControlCategory(StrEnum):
    ACCESS_CONTROL = "ACCESS_CONTROL"
    IDENTITY = "IDENTITY"
    MONITORING = "MONITORING"
    ASSET_MANAGEMENT = "ASSET_MANAGEMENT"
    BACKUP = "BACKUP"
    AUDIT = "AUDIT"
    CHANGE_MANAGEMENT = "CHANGE_MANAGEMENT"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    GOVERNANCE = "GOVERNANCE"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"


class ImplementationStatus(StrEnum):
    PLANNED = "PLANNED"
    PARTIAL = "PARTIAL"
    IMPLEMENTED = "IMPLEMENTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RelationshipType(StrEnum):
    PREVENTIVE = "PREVENTIVE"
    DETECTIVE = "DETECTIVE"
    CORRECTIVE = "CORRECTIVE"


def choice(cls, name):
    return Enum(cls, native_enum=False, create_constraint=True, name=name)


class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(60))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(60))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Risk(Base):
    __tablename__ = "risks"
    __table_args__ = (
        CheckConstraint("probability BETWEEN 1 AND 5", name="ck_risks_probability"),
        CheckConstraint("impact BETWEEN 1 AND 5", name="ck_risks_impact"),
        CheckConstraint("score = probability * impact", name="ck_risks_score"),
        CheckConstraint(
            "level = CASE WHEN score <= 4 THEN 'LOW' WHEN score <= 9 THEN 'MEDIUM' "
            "WHEN score <= 16 THEN 'HIGH' ELSE 'CRITICAL' END",
            name="ck_risks_level",
        ),
        CheckConstraint(
            "(status = 'CLOSED' AND closed_at IS NOT NULL) OR "
            "(status <> 'CLOSED' AND closed_at IS NULL)",
            name="ck_risks_closed",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    risk_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    threat_id: Mapped[int] = mapped_column(ForeignKey("threats.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    probability: Mapped[int] = mapped_column(Integer)
    impact: Mapped[int] = mapped_column(Integer)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[RiskLevel] = mapped_column(choice(RiskLevel, "risk_level"), index=True)
    treatment: Mapped[Treatment] = mapped_column(choice(Treatment, "risk_treatment"))
    status: Mapped[RiskStatus] = mapped_column(choice(RiskStatus, "risk_status"), index=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    identified_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    review_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    asset: Mapped[Asset] = relationship(lazy="joined")
    threat: Mapped[Threat] = relationship(lazy="joined")
    vulnerability: Mapped[Vulnerability] = relationship(lazy="joined")
    owner: Mapped[User] = relationship(foreign_keys=[owner_user_id], lazy="joined")


class Control(Base):
    __tablename__ = "controls"
    id: Mapped[int] = mapped_column(primary_key=True)
    control_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[ControlCategory] = mapped_column(choice(ControlCategory, "control_category"))
    implementation_status: Mapped[ImplementationStatus] = mapped_column(
        choice(ImplementationStatus, "control_implementation"), index=True
    )
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    owner: Mapped[User] = relationship(lazy="joined")


class RiskControl(Base):
    __tablename__ = "risk_controls"
    __table_args__ = (
        CheckConstraint(
            "(active = true AND disabled_at IS NULL) OR "
            "(active = false AND disabled_at IS NOT NULL)",
            name="ck_risk_controls_active",
        ),
    )
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), primary_key=True, index=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("controls.id"), primary_key=True, index=True)
    relationship_type: Mapped[RelationshipType] = mapped_column(
        choice(RelationshipType, "risk_control_relationship")
    )
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    control: Mapped[Control] = relationship(lazy="joined")
