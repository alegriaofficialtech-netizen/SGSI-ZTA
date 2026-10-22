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
from app.models.assets import Asset
from app.models.identity import User
from app.monitoring.types import AlertStatus, EventType, Severity, SourceType


def new_id() -> str:
    return str(uuid4())


def choice(kind, name, nullable=False):
    return Enum(
        kind,
        native_enum=False,
        create_constraint=True,
        name=name,
        values_callable=lambda enum: [member.value for member in enum],
    )


class MonitoringSource(Base):
    __tablename__ = "monitoring_sources"
    __table_args__ = (
        CheckConstraint("length(source_code) BETWEEN 3 AND 40", name="ck_sources_code_len"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_code: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(
        choice(SourceType, "monitoring_source_type"), nullable=False
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=now_utc, onupdate=now_utc, nullable=False
    )

    asset: Mapped[Asset | None] = relationship()
    events: Mapped[list["MonitoringEvent"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class MonitoringEvent(Base):
    __tablename__ = "monitoring_events"
    __table_args__ = (
        UniqueConstraint(
            "source_id", "source_event_id", name="uq_monitoring_events_source_event"
        ),
        Index("ix_monitoring_events_occurred_at", "occurred_at"),
        Index("ix_monitoring_events_type_severity", "event_type", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("monitoring_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[EventType] = mapped_column(
        choice(EventType, "monitoring_event_type"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        choice(Severity, "monitoring_severity"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)

    source: Mapped[MonitoringSource] = relationship(back_populates="events")
    asset: Mapped[Asset | None] = relationship()


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (
        CheckConstraint("cooldown_seconds >= 0", name="ck_alert_rules_cooldown_positive"),
        CheckConstraint("length(rule_code) BETWEEN 3 AND 40", name="ck_alert_rules_code_len"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rule_code: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    event_type: Mapped[EventType] = mapped_column(
        choice(EventType, "monitoring_event_type"), nullable=False, index=True
    )
    minimum_severity: Mapped[Severity] = mapped_column(
        choice(Severity, "monitoring_severity"), nullable=False
    )
    asset_criticality: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=now_utc, onupdate=now_utc, nullable=False
    )

    creator: Mapped[User] = relationship()


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("occurrence_count >= 1", name="ck_alerts_occurrence_count_positive"),
        Index("ix_alerts_status_severity", "status", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    alert_code: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("monitoring_events.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        choice(Severity, "monitoring_severity"), nullable=False
    )
    status: Mapped[AlertStatus] = mapped_column(
        choice(AlertStatus, "alert_status"), default=AlertStatus.OPEN, nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=now_utc, onupdate=now_utc, nullable=False
    )

    event: Mapped[MonitoringEvent] = relationship()
    rule: Mapped[AlertRule] = relationship()
    asset: Mapped[Asset | None] = relationship()
    acknowledger: Mapped[User | None] = relationship(foreign_keys=[acknowledged_by])
    resolver: Mapped[User | None] = relationship(foreign_keys=[resolved_by])
    history: Mapped[list["AlertHistory"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertHistory.created_at.asc()",
    )


class AlertHistory(Base):
    __tablename__ = "alert_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    previous_status: Mapped[AlertStatus | None] = mapped_column(
        choice(AlertStatus, "alert_status", nullable=True), nullable=True
    )
    new_status: Mapped[AlertStatus] = mapped_column(
        choice(AlertStatus, "alert_status"), nullable=False
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)

    alert: Mapped[Alert] = relationship(back_populates="history")
    actor: Mapped[User | None] = relationship()


class FimTarget(Base):
    __tablename__ = "fim_targets"
    __table_args__ = (
        CheckConstraint(
            "relative_path NOT LIKE '/%' AND relative_path NOT LIKE '\\\\%' "
            "AND relative_path NOT LIKE '%..%'",
            name="ck_fim_targets_relative_path_safe",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_code: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    relative_path: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    baseline_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    last_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=now_utc, onupdate=now_utc, nullable=False
    )

    asset: Mapped[Asset | None] = relationship()


# Immutability Protection for MonitoringEvent and AlertHistory
def reject_mutation(mapper, connection, target):
    raise ValueError(f"{type(target).__name__} is append-only")


for immutable in (MonitoringEvent, AlertHistory):
    event.listen(immutable, "before_update", reject_mutation)
    event.listen(immutable, "before_delete", reject_mutation)


@event.listens_for(Session, "do_orm_execute")
def reject_bulk_mutation_monitoring(state):
    if state.is_update or state.is_delete:
        mapper = state.bind_mapper
        if mapper is not None and mapper.class_ in (MonitoringEvent, AlertHistory):
            raise ValueError(f"{mapper.class_.__name__} is append-only")
