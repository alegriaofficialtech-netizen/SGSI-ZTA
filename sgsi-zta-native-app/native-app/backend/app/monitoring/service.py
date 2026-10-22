"""Services for monitoring source management, rate limiting, and event ingestion."""
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.auth.security import digest
from app.database import now_utc
from app.models import Asset, User
from app.models.identity import LoginRateLimit
from app.models.monitoring import Alert, AlertHistory, AlertRule, MonitoringEvent, MonitoringSource
from app.monitoring.engine import AlertEngine
from app.monitoring.schemas import (
    AlertRuleCreate,
    AlertRuleUpdate,
    MonitoringEventCreate,
    MonitoringSourceCreate,
    MonitoringSourceUpdate,
)
from app.monitoring.security import (
    compute_event_fingerprint,
    generate_source_key,
    parse_source_key,
    sanitize_payload,
    verify_source_key,
)
from app.monitoring.types import AlertStatus, EventType, Severity, SourceType
from app.services import audit


class MonitoringSourceService:
    @staticmethod
    def list_sources(db: Session) -> list[MonitoringSource]:
        return list(
            db.scalars(select(MonitoringSource).order_by(MonitoringSource.created_at.desc()))
        )

    @staticmethod
    def get_source(db: Session, source_id: str | UUID) -> MonitoringSource:
        source = db.get(MonitoringSource, str(source_id))
        if not source:
            raise HTTPException(status_code=404, detail="Monitoring source not found.")
        return source

    @staticmethod
    def create_source(
        db: Session,
        request: Request,
        actor: User,
        body: MonitoringSourceCreate,
    ) -> tuple[MonitoringSource, str]:
        if body.source_code == "SRC-NATIVE-FIM" or body.source_type == SourceType.FIM:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Source code 'SRC-NATIVE-FIM' and source type FIM "
                    "are reserved for internal services."
                ),
            )

        # Validate uniqueness of source_code
        existing = db.scalar(
            select(MonitoringSource).where(MonitoringSource.source_code == body.source_code)
        )
        if existing:
            raise HTTPException(
                status_code=409, detail=f"Source code '{body.source_code}' already exists."
            )

        if body.asset_id is not None:
            asset = db.get(Asset, body.asset_id)
            if not asset:
                raise HTTPException(
                    status_code=422, detail=f"Asset id {body.asset_id} does not exist."
                )

        raw_key, key_hash = generate_source_key(body.source_code)

        source = MonitoringSource(
            source_code=body.source_code,
            name=body.name,
            source_type=body.source_type,
            asset_id=body.asset_id,
            enabled=body.enabled,
            key_hash=key_hash,
            last_seen_at=None,
        )
        db.add(source)
        db.flush()

        audit.record(
            db,
            request,
            action="MONITORING_SOURCE_CREATED",
            resource=f"monitoring-source:{source.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={source.source_code} type={source.source_type.value}",
        )
        db.commit()
        db.refresh(source)
        return source, raw_key

    @staticmethod
    def update_source(
        db: Session,
        request: Request,
        actor: User,
        source_id: str | UUID,
        body: MonitoringSourceUpdate,
    ) -> MonitoringSource:
        source = MonitoringSourceService.get_source(db, source_id)

        if body.asset_id is not None:
            asset = db.get(Asset, body.asset_id)
            if not asset:
                raise HTTPException(
                    status_code=422, detail=f"Asset id {body.asset_id} does not exist."
                )
            source.asset_id = body.asset_id

        if body.name is not None:
            source.name = body.name

        was_enabled = source.enabled
        if body.enabled is not None:
            source.enabled = body.enabled

        audit_action = (
            "MONITORING_SOURCE_DISABLED"
            if was_enabled and not source.enabled
            else "MONITORING_SOURCE_UPDATED"
        )

        audit.record(
            db,
            request,
            action=audit_action,
            resource=f"monitoring-source:{source.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={source.source_code} enabled={source.enabled}",
        )
        db.commit()
        db.refresh(source)
        return source

    @staticmethod
    def rotate_key(
        db: Session,
        request: Request,
        actor: User,
        source_id: str | UUID,
    ) -> tuple[MonitoringSource, str]:
        source = MonitoringSourceService.get_source(db, source_id)
        if source.source_code == "SRC-NATIVE-FIM" or source.source_type == SourceType.FIM:
            raise HTTPException(
                status_code=400,
                detail="Keys for internal monitoring sources cannot be rotated via external API.",
            )

        raw_key, key_hash = generate_source_key(source.source_code)
        source.key_hash = key_hash

        audit.record(
            db,
            request,
            action="MONITORING_SOURCE_KEY_ROTATED",
            resource=f"monitoring-source:{source.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={source.source_code}",
        )
        db.commit()
        db.refresh(source)
        return source, raw_key


class MonitoringIngestionService:
    @staticmethod
    def authenticate_source(
        db: Session,
        x_monitoring_key: str | None,
        x_monitoring_source: str | None = None,
    ) -> MonitoringSource:
        if not x_monitoring_key or not x_monitoring_key.strip():
            raise HTTPException(
                status_code=401,
                detail="Missing X-Monitoring-Key authentication header.",
            )

        source_code, raw_key = parse_source_key(x_monitoring_key, x_monitoring_source)
        if not source_code:
            raise HTTPException(
                status_code=401,
                detail="Invalid monitoring key format.",
            )

        source = db.scalar(
            select(MonitoringSource).where(MonitoringSource.source_code == source_code)
        )
        if not source:
            raise HTTPException(
                status_code=401,
                detail="Invalid monitoring credentials.",
            )

        if source.source_code == "SRC-NATIVE-FIM" or source.source_type == SourceType.FIM:
            raise HTTPException(
                status_code=403,
                detail="Internal monitoring source cannot ingest events via external API.",
            )

        if not verify_source_key(raw_key, source.key_hash):
            raise HTTPException(
                status_code=401,
                detail="Invalid monitoring credentials.",
            )

        if not source.enabled:
            raise HTTPException(
                status_code=403,
                detail=f"Monitoring source '{source.source_code}' is disabled.",
            )

        return source

    @staticmethod
    def consume_rate_limit(
        db: Session,
        request: Request,
        source: MonitoringSource,
        default_limit: int = 120,
        window_seconds: int = 60,
    ) -> None:
        limit = getattr(request.app.state, "monitoring_rate_limit", default_limit)
        if limit is None:
            return

        peer = request.client.host if request.client else "unknown"
        key = digest(f"monitoring_rate_limit:{source.id}:{peer}")
        now = now_utc()

        insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
        db.execute(
            insert(LoginRateLimit)
            .values(key=key, window_start=now, attempts=0)
            .on_conflict_do_nothing(index_elements=["key"])
        )
        row = db.scalar(select(LoginRateLimit).where(LoginRateLimit.key == key).with_for_update())
        assert row is not None

        if row.window_start + timedelta(seconds=window_seconds) <= now:
            row.window_start, row.attempts = now, 0
        row.attempts += 1
        db.commit()

        if row.attempts > limit:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded for event ingestion.",
                headers={"Retry-After": str(window_seconds)},
            )

    @staticmethod
    def ingest_event(
        db: Session,
        source: MonitoringSource,
        body: MonitoringEventCreate,
    ) -> tuple[MonitoringEvent, bool]:
        # 1. Resolve asset_id
        resolved_asset_id: int | None = None
        if body.asset_code:
            asset = db.scalar(select(Asset).where(Asset.asset_code == body.asset_code))
            if not asset:
                raise HTTPException(
                    status_code=422,
                    detail=f"Asset code '{body.asset_code}' does not exist.",
                )
            resolved_asset_id = asset.id
        elif body.asset_id is not None:
            asset = db.get(Asset, body.asset_id)
            if not asset:
                raise HTTPException(
                    status_code=422,
                    detail=f"Asset id {body.asset_id} does not exist.",
                )
            resolved_asset_id = body.asset_id
        else:
            resolved_asset_id = source.asset_id

        # 2. Idempotency check: (source_id, source_event_id)
        existing = db.scalar(
            select(MonitoringEvent).where(
                MonitoringEvent.source_id == source.id,
                MonitoringEvent.source_event_id == body.source_event_id,
            )
        )
        if existing:
            source.last_seen_at = now_utc()
            db.commit()
            return existing, True

        # 3. Payload sanitization
        clean_payload = sanitize_payload(body.payload)

        # 4. Deterministic server-side fingerprint
        fingerprint = compute_event_fingerprint(
            source_id=source.id,
            event_type=body.event_type.value,
            asset_id=resolved_asset_id,
            title=body.title,
            message=body.message,
        )

        now = now_utc()
        occurred_naive = (
            body.occurred_at.astimezone(UTC).replace(tzinfo=None)
            if body.occurred_at.tzinfo is not None
            else body.occurred_at
        )
        event = MonitoringEvent(
            source_id=source.id,
            asset_id=resolved_asset_id,
            source_event_id=body.source_event_id,
            event_type=body.event_type,
            severity=body.severity,
            title=body.title,
            message=body.message,
            occurred_at=occurred_naive,
            received_at=now,
            fingerprint=fingerprint,
            payload_json=clean_payload,
            created_at=now,
        )

        db.add(event)
        source.last_seen_at = now
        db.flush()

        # Invoke AlertEngine atomically in the same database transaction
        AlertEngine.process_event(db, event)

        try:
            db.commit()
            db.refresh(event)
            return event, False
        except IntegrityError:
            db.rollback()
            # Race condition duplicate check
            existing = db.scalar(
                select(MonitoringEvent).where(
                    MonitoringEvent.source_id == source.id,
                    MonitoringEvent.source_event_id == body.source_event_id,
                )
            )
            if existing:
                return existing, True
            raise


class AlertRuleService:
    @staticmethod
    def list_rules(db: Session) -> list[AlertRule]:
        return list(db.scalars(select(AlertRule).order_by(AlertRule.created_at.desc())))

    @staticmethod
    def get_rule(db: Session, rule_id: str | UUID) -> AlertRule:
        rule = db.get(AlertRule, str(rule_id))
        if not rule:
            raise HTTPException(status_code=404, detail="Regla de alerta no encontrada.")
        return rule

    @staticmethod
    def create_rule(
        db: Session,
        request: Request,
        actor: User,
        body: AlertRuleCreate,
    ) -> AlertRule:
        existing = db.scalar(select(AlertRule).where(AlertRule.rule_code == body.rule_code))
        if existing:
            raise HTTPException(
                status_code=409, detail=f"Código de regla '{body.rule_code}' ya existe."
            )

        rule = AlertRule(
            rule_code=body.rule_code,
            name=body.name,
            description=body.description,
            enabled=body.enabled,
            event_type=body.event_type,
            minimum_severity=body.minimum_severity,
            asset_criticality=body.asset_criticality,
            cooldown_seconds=body.cooldown_seconds,
            created_by=actor.id,
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        db.add(rule)
        db.flush()

        audit.record(
            db,
            request,
            action="ALERT_RULE_CREATED",
            resource=f"alert-rule:{rule.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={rule.rule_code} event_type={rule.event_type.value}",
        )
        db.commit()
        db.refresh(rule)
        return rule

    @staticmethod
    def update_rule(
        db: Session,
        request: Request,
        actor: User,
        rule_id: str | UUID,
        body: AlertRuleUpdate,
    ) -> AlertRule:
        rule = AlertRuleService.get_rule(db, rule_id)
        was_enabled = rule.enabled

        if body.name is not None:
            rule.name = body.name
        if body.description is not None:
            rule.description = body.description
        if body.enabled is not None:
            rule.enabled = body.enabled
        if body.minimum_severity is not None:
            rule.minimum_severity = body.minimum_severity
        if body.asset_criticality is not None:
            rule.asset_criticality = body.asset_criticality
        if body.cooldown_seconds is not None:
            rule.cooldown_seconds = body.cooldown_seconds

        rule.updated_at = now_utc()

        audit_action = (
            "ALERT_RULE_DISABLED"
            if was_enabled and not rule.enabled
            else "ALERT_RULE_UPDATED"
        )
        audit.record(
            db,
            request,
            action=audit_action,
            resource=f"alert-rule:{rule.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={rule.rule_code} enabled={rule.enabled}",
        )
        db.commit()
        db.refresh(rule)
        return rule


class AlertService:
    @staticmethod
    def get_alert(db: Session, alert_id: str | UUID) -> Alert:
        stmt = (
            select(Alert)
            .where(Alert.id == str(alert_id))
            .options(selectinload(Alert.history))
        )
        alert = db.scalar(stmt)
        if not alert:
            raise HTTPException(status_code=404, detail="Alerta no encontrada.")
        return alert

    @staticmethod
    def list_alerts(
        db: Session,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        rule: str | None = None,
        asset_id: int | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        sort_by: str = "created_at",
        sort_desc: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Alert], int]:
        if page < 1:
            raise HTTPException(status_code=422, detail="page debe ser >= 1")
        if page_size < 1 or page_size > 100:
            raise HTTPException(status_code=422, detail="page_size debe estar entre 1 y 100")

        sort_columns = {
            "created_at": Alert.created_at,
            "last_seen_at": Alert.last_seen_at,
            "first_seen_at": Alert.first_seen_at,
            "severity": Alert.severity,
            "status": Alert.status,
            "occurrence_count": Alert.occurrence_count,
        }
        if sort_by not in sort_columns:
            raise HTTPException(
                status_code=422,
                detail=f"Campo de ordenación no permitido. Permitidos: {list(sort_columns.keys())}",
            )

        query = select(Alert)
        count_query = select(func.count(Alert.id))

        filters = []
        if status is not None:
            filters.append(Alert.status == status)
        if severity is not None:
            filters.append(Alert.severity == severity)
        if asset_id is not None:
            filters.append(Alert.asset_id == asset_id)
        if rule is not None:
            filters.append(
                or_(
                    Alert.rule_id == rule,
                    Alert.rule.has(AlertRule.rule_code == rule),
                )
            )
        if date_from is not None:
            filters.append(Alert.created_at >= date_from)
        if date_to is not None:
            filters.append(Alert.created_at <= date_to)

        if filters:
            query = query.where(*filters)
            count_query = count_query.where(*filters)

        total = db.scalar(count_query) or 0

        sort_col = sort_columns[sort_by]
        query = query.order_by(sort_col.desc() if sort_desc else sort_col.asc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        items = list(db.scalars(query))
        return items, total

    @staticmethod
    def acknowledge_alert(
        db: Session,
        request: Request,
        actor: User,
        alert_id: str | UUID,
        comment: str | None = None,
    ) -> Alert:
        stmt = select(Alert).where(Alert.id == str(alert_id))
        if db.bind and db.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update()
        alert = db.scalar(stmt)
        if not alert:
            raise HTTPException(status_code=404, detail="Alerta no encontrada.")

        if alert.status == AlertStatus.ACKNOWLEDGED:
            raise HTTPException(
                status_code=400,
                detail="La alerta ya se encuentra en estado ACKNOWLEDGED.",
            )
        if alert.status == AlertStatus.RESOLVED:
            raise HTTPException(
                status_code=400,
                detail="No se puede reconocer una alerta en estado RESOLVED.",
            )
        if alert.status != AlertStatus.OPEN:
            raise HTTPException(
                status_code=400,
                detail=f"Transición de estado no permitida desde {alert.status.value}.",
            )

        prev_status = alert.status
        now = now_utc()
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = now
        alert.acknowledged_by = actor.id
        alert.updated_at = now

        history = AlertHistory(
            alert_id=alert.id,
            actor_user_id=actor.id,
            action="ALERT_ACKNOWLEDGED",
            previous_status=prev_status,
            new_status=AlertStatus.ACKNOWLEDGED,
            comment=comment,
            created_at=now,
        )
        db.add(history)

        audit.record(
            db,
            request,
            action="ALERT_ACKNOWLEDGED",
            resource=f"alert:{alert.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={alert.alert_code} comment={comment or ''}",
        )
        db.commit()
        return AlertService.get_alert(db, alert.id)

    @staticmethod
    def resolve_alert(
        db: Session,
        request: Request,
        actor: User,
        alert_id: str | UUID,
        comment: str | None = None,
    ) -> Alert:
        stmt = select(Alert).where(Alert.id == str(alert_id))
        if db.bind and db.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update()
        alert = db.scalar(stmt)
        if not alert:
            raise HTTPException(status_code=404, detail="Alerta no encontrada.")

        if alert.status == AlertStatus.RESOLVED:
            raise HTTPException(
                status_code=400,
                detail="La alerta ya se encuentra en estado RESOLVED.",
            )

        prev_status = alert.status
        now = now_utc()
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = now
        alert.resolved_by = actor.id
        alert.updated_at = now

        history = AlertHistory(
            alert_id=alert.id,
            actor_user_id=actor.id,
            action="ALERT_RESOLVED",
            previous_status=prev_status,
            new_status=AlertStatus.RESOLVED,
            comment=comment,
            created_at=now,
        )
        db.add(history)

        audit.record(
            db,
            request,
            action="ALERT_RESOLVED",
            resource=f"alert:{alert.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={alert.alert_code} comment={comment or ''}",
        )
        db.commit()
        return AlertService.get_alert(db, alert.id)

    @staticmethod
    def get_alert_history(db: Session, alert_id: str | UUID) -> list[AlertHistory]:
        alert = AlertService.get_alert(db, alert_id)
        return list(alert.history)


class MonitoringEventReadService:
    """Read service for monitoring events under Zero Trust PEP."""

    @staticmethod
    def list_events(
        db: Session,
        *,
        event_type: EventType | None = None,
        severity: Severity | None = None,
        source_id: str | UUID | None = None,
        asset_id: int | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        sort_by: str = "occurred_at",
        sort_desc: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Any], int]:
        from app.models.assets import Asset

        sort_columns = {
            "occurred_at": MonitoringEvent.occurred_at,
            "received_at": MonitoringEvent.received_at,
            "severity": MonitoringEvent.severity,
        }
        if sort_by not in sort_columns:
            allowed = list(sort_columns.keys())
            raise HTTPException(
                status_code=400,
                detail=f"Columna de ordenamiento inválida: {sort_by}. Permitidas: {allowed}",
            )

        query = (
            select(
                MonitoringEvent,
                MonitoringSource.source_code,
                MonitoringSource.name,
                Asset.name,
            )
            .join(MonitoringSource, MonitoringEvent.source_id == MonitoringSource.id)
            .outerjoin(Asset, MonitoringEvent.asset_id == Asset.id)
        )
        count_query = select(func.count(MonitoringEvent.id))

        filters = []
        if event_type is not None:
            filters.append(MonitoringEvent.event_type == event_type)
        if severity is not None:
            filters.append(MonitoringEvent.severity == severity)
        if source_id is not None:
            filters.append(MonitoringEvent.source_id == str(source_id))
        if asset_id is not None:
            filters.append(MonitoringEvent.asset_id == asset_id)
        if date_from is not None:
            filters.append(MonitoringEvent.occurred_at >= date_from)
        if date_to is not None:
            filters.append(MonitoringEvent.occurred_at <= date_to)

        if filters:
            query = query.where(*filters)
            count_query = count_query.where(*filters)

        total = db.scalar(count_query) or 0

        sort_col = sort_columns[sort_by]
        query = query.order_by(sort_col.desc() if sort_desc else sort_col.asc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        items = list(db.execute(query).all())
        return items, total

    @staticmethod
    def get_event(
        db: Session, event_id: str | UUID
    ) -> tuple[MonitoringEvent, str, str, str | None]:
        from app.models.assets import Asset

        query = (
            select(
                MonitoringEvent,
                MonitoringSource.source_code,
                MonitoringSource.name,
                Asset.name,
            )
            .join(MonitoringSource, MonitoringEvent.source_id == MonitoringSource.id)
            .outerjoin(Asset, MonitoringEvent.asset_id == Asset.id)
            .where(MonitoringEvent.id == str(event_id))
        )
        row = db.execute(query).first()
        if not row:
            raise HTTPException(status_code=404, detail="Evento de monitoreo no encontrado.")
        return row


