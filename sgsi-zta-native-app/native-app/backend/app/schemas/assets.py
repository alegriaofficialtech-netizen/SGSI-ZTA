from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.assets import AssetStatus, Classification, Criticality
from app.schemas.identity import AuditPublic

DEMO_NETWORKS = tuple(
    ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    asset_code: str = Field(min_length=3, max_length=40, pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    asset_type_id: int = Field(gt=0)
    department_id: int = Field(gt=0)
    owner_user_id: int = Field(gt=0)
    criticality: Criticality = Criticality.LOW
    classification: Classification = Classification.INTERNAL
    status: AssetStatus = AssetStatus.ACTIVE
    monitoring_enabled: bool = False
    manufacturer: str = Field(default="", max_length=100)
    model: str = Field(default="", max_length=100)
    serial_number: str = Field(default="", max_length=100)
    ip_address_demo: str | None = None
    hostname_demo: str = Field(
        default="", max_length=120, pattern=r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)?$"
    )
    location_demo: str = Field(default="", max_length=160)
    notes: str = Field(default="", max_length=2000)

    @field_validator("ip_address_demo")
    @classmethod
    def documentation_ip(cls, value):
        if not value:
            return None
        try:
            address = ip_address(value)
        except ValueError:
            raise ValueError("La IP demo no es válida") from None
        if not any(address in network for network in DEMO_NETWORKS):
            raise ValueError("Usa una IP documental: 192.0.2.x, 198.51.100.x o 203.0.113.x")
        return str(address)


class AssetUpdate(AssetCreate):
    # Omitted fields preserve current values; explicit null only clears the demo IP.
    asset_code: str | None = Field(
        default=None, min_length=3, max_length=40, pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$"
    )
    name: str | None = Field(default=None, min_length=2, max_length=160)
    asset_type_id: int | None = Field(default=None, gt=0)
    department_id: int | None = Field(default=None, gt=0)
    owner_user_id: int | None = Field(default=None, gt=0)


class CatalogPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str


class OwnerPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    display_name: str


class AssetResponse(AssetCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    synthetic: Literal[True]
    asset_type: CatalogPublic
    department: CatalogPublic
    owner: OwnerPublic
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None


class AssetDetail(AssetResponse):
    history: list[AuditPublic]


class AssetPage(BaseModel):
    items: list[AssetResponse]
    page: int
    page_size: int
    total: int
    pages: int
