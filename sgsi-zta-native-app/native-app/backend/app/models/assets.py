from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, now_utc
from app.models.identity import User


class Criticality(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Classification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class AssetStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    MAINTENANCE = "MAINTENANCE"
    RETIRED = "RETIRED"


class AssetType(Base):
    __tablename__ = "asset_types"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)


class Department(Base):
    __tablename__ = "departments"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("synthetic = true", name="ck_assets_synthetic"),
        CheckConstraint(
            "(status = 'RETIRED' AND disabled_at IS NOT NULL) OR "
            "(status <> 'RETIRED' AND disabled_at IS NULL)",
            name="ck_assets_retirement",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    asset_type_id: Mapped[int] = mapped_column(ForeignKey("asset_types.id"), index=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), index=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality, native_enum=False, create_constraint=True, name="asset_criticality"),
        index=True,
    )
    classification: Mapped[Classification] = mapped_column(
        Enum(Classification, native_enum=False, create_constraint=True, name="asset_classification")
    )
    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus, native_enum=False, create_constraint=True, name="asset_status"),
        index=True,
    )
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    manufacturer: Mapped[str] = mapped_column(String(100), default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    serial_number: Mapped[str] = mapped_column(String(100), default="")
    ip_address_demo: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname_demo: Mapped[str] = mapped_column(String(120), default="")
    location_demo: Mapped[str] = mapped_column(String(160), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    asset_type: Mapped[AssetType] = relationship(lazy="joined")
    department: Mapped[Department] = relationship(lazy="joined")
    owner: Mapped[User] = relationship(foreign_keys=[owner_user_id], lazy="joined")
