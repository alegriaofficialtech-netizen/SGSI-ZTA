"""Pydantic schemas for monitoring sources, event ingestion, alert rules, and alerts."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.monitoring.security import validate_payload_size
from app.monitoring.types import AlertStatus, EventType, Severity, SourceType


class MonitoringSourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_code: str = Field(..., min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=160)
    source_type: SourceType
    asset_id: int | None = None
    enabled: bool = True


class MonitoringSourceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    enabled: bool | None = None
    asset_id: int | None = None


class MonitoringSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    source_code: str
    name: str
    source_type: SourceType
    asset_id: int | None
    enabled: bool
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


class MonitoringSourceCreatedResponse(MonitoringSourceResponse):
    api_key: str = Field(
        ..., description="Raw secret API key. Shown once; never stored in plaintext."
    )


class MonitoringSourceKeyRotatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source_code: str
    api_key: str = Field(
        ..., description="New raw secret API key. Shown once; never stored in plaintext."
    )


class MonitoringEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_event_id: str = Field(..., min_length=1, max_length=128)
    event_type: EventType
    severity: Severity
    title: str = Field(..., min_length=1, max_length=200)
    message: str = Field(..., min_length=1, max_length=5000)
    occurred_at: datetime
    asset_id: int | None = None
    asset_code: str | None = Field(default=None, max_length=40)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def check_payload_limit(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_payload_size(value)
        return value


class MonitoringEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    source_id: str
    source_event_id: str
    event_type: EventType
    severity: Severity
    title: str
    occurred_at: datetime
    received_at: datetime
    fingerprint: str
    idempotent_replay: bool = False


class MonitoringEventItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    source_id: str
    source_code: str
    source_name: str
    source_event_id: str
    event_type: EventType
    severity: Severity
    title: str
    asset_id: int | None = None
    asset_name: str | None = None
    occurred_at: datetime
    received_at: datetime
    fingerprint: str


class MonitoringEventPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[MonitoringEventItemResponse]
    total: int
    page: int
    page_size: int


class MonitoringEventDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    source_id: str
    source_code: str
    source_name: str
    source_event_id: str
    event_type: EventType
    severity: Severity
    title: str
    message: str
    asset_id: int | None = None
    asset_name: str | None = None
    occurred_at: datetime
    received_at: datetime
    fingerprint: str
    payload: dict[str, Any] = Field(default_factory=dict)


# =========================================================================
# Alert Rules Schemas
# =========================================================================


class AlertRuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_code: str = Field(..., min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=160)
    description: str = Field(default="", max_length=2000)
    enabled: bool = True
    event_type: EventType
    minimum_severity: Severity
    asset_criticality: str | None = Field(default=None, max_length=20)
    cooldown_seconds: int = Field(default=300, ge=0)

    @field_validator("asset_criticality")
    @classmethod
    def validate_criticality(cls, value: str | None) -> str | None:
        if value is not None and value.upper() not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("asset_criticality debe ser LOW, MEDIUM, HIGH, CRITICAL o null")
        return value.upper() if value is not None else None


class AlertRuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    minimum_severity: Severity | None = None
    asset_criticality: str | None = Field(default=None, max_length=20)
    cooldown_seconds: int | None = Field(default=None, ge=0)

    @field_validator("asset_criticality")
    @classmethod
    def validate_criticality(cls, value: str | None) -> str | None:
        if value is not None and value.upper() not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("asset_criticality debe ser LOW, MEDIUM, HIGH, CRITICAL o null")
        return value.upper() if value is not None else None


class AlertRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    rule_code: str
    name: str
    description: str
    enabled: bool
    event_type: EventType
    minimum_severity: Severity
    asset_criticality: str | None
    cooldown_seconds: int
    created_by: int
    created_at: datetime
    updated_at: datetime


# =========================================================================
# Alert Read Schemas
# =========================================================================


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    alert_code: str
    event_id: str
    rule_id: str
    asset_id: int | None
    severity: Severity
    status: AlertStatus
    title: str
    description: str
    fingerprint: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: int | None
    resolved_at: datetime | None
    resolved_by: int | None
    created_at: datetime
    updated_at: datetime


class AlertPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AlertResponse]
    total: int
    page: int
    page_size: int


class AlertAcknowledgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=1000)


class AlertResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=1000)


class AlertHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    alert_id: str
    actor_user_id: int | None
    action: str
    previous_status: AlertStatus | None
    new_status: AlertStatus
    comment: str | None
    created_at: datetime


class AlertDetailResponse(AlertResponse):
    history: list[AlertHistoryResponse] = []


class AlertMetricsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts_open: int
    critical_open: int
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]


class EventsByHourPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hour: str
    count: int


class AlertsBySeverityPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: str
    count: int


class EventsByTypePoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str
    count: int


class TopAffectedAssetPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: int | None = None
    asset_name: str
    count: int


class MonitoringDashboardMetricsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events_24h: int
    alerts_open: int
    alerts_acknowledged: int
    alerts_resolved_24h: int
    critical_open: int
    high_open: int
    fim_targets_enabled: int
    fim_scans_24h: int
    fim_changes_24h: int
    events_by_hour: list[EventsByHourPoint] = []
    alerts_by_severity: list[AlertsBySeverityPoint] = []
    events_by_type: list[EventsByTypePoint] = []
    top_affected_assets: list[TopAffectedAssetPoint] = []


# =========================================================================
# FIM Schemas
# =========================================================================


class FimTargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_code: str = Field(
        ...,
        min_length=3,
        max_length=40,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="Unique code identifying the monitored target",
    )
    relative_path: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Relative path under monitoring-data",
    )
    asset_id: int | None = Field(
        default=None,
        description="Optional asset ID associated with the target",
    )
    enabled: bool = Field(
        default=True,
        description="Whether monitoring is enabled for this target",
    )


class FimTargetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: int | None = Field(
        default=None,
        description="Updated asset ID associated with the target",
    )
    enabled: bool | None = Field(
        default=None,
        description="Enable or disable monitoring for this target",
    )


class FimTargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    target_code: str
    relative_path: str
    asset_id: int | None
    baseline_sha256: str
    last_sha256: str | None
    enabled: bool
    last_checked_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FimScanResult(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    target_id: str
    target_code: str
    relative_path: str
    status: str
    baseline_sha256: str
    current_sha256: str | None
    event_id: str | None = None
    alert_id: str | None = None
    message: str


class FimGlobalScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_targets: int
    scanned: int
    unchanged: int
    changed: int
    missing: int
    errors: int
    results: list[FimScanResult]


class FimMetricsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fim_targets_enabled: int
    fim_scans_24h: int
    fim_changes_24h: int

