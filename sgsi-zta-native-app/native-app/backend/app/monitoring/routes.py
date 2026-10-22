from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Body, Header, Query, Request, Response, status

from app.auth.dependencies import AuthenticatedSession, Database
from app.monitoring.fim import FimService
from app.monitoring.metrics import (
    AlertMetricsService,
    DashboardMetricsService,
    FimMetricsService,
)
from app.monitoring.pep import MonitoringPEP
from app.monitoring.schemas import (
    AlertAcknowledgeRequest,
    AlertDetailResponse,
    AlertHistoryResponse,
    AlertMetricsResponse,
    AlertPageResponse,
    AlertResolveRequest,
    AlertResponse,
    AlertRuleCreate,
    AlertRuleResponse,
    AlertRuleUpdate,
    FimGlobalScanResponse,
    FimMetricsResponse,
    FimScanResult,
    FimTargetCreate,
    FimTargetResponse,
    FimTargetUpdate,
    MonitoringDashboardMetricsResponse,
    MonitoringEventCreate,
    MonitoringEventDetailResponse,
    MonitoringEventItemResponse,
    MonitoringEventPageResponse,
    MonitoringEventResponse,
    MonitoringSourceCreate,
    MonitoringSourceCreatedResponse,
    MonitoringSourceKeyRotatedResponse,
    MonitoringSourceResponse,
    MonitoringSourceUpdate,
)
from app.monitoring.service import (
    AlertRuleService,
    AlertService,
    MonitoringEventReadService,
    MonitoringIngestionService,
    MonitoringSourceService,
)
from app.monitoring.types import AlertStatus, EventType, Severity
from app.policies.types import Action

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


# =========================================================================
# 1. Monitoring Source Management (Protected by Zero Trust PEP)
# =========================================================================


@router.get("/sources", response_model=list[MonitoringSourceResponse])
def list_sources(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> list[MonitoringSourceResponse]:
    """List registered monitoring sources. Requires read permission on monitoring-sources."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring-sources", action=Action.READ
    )
    sources = MonitoringSourceService.list_sources(db)
    return [MonitoringSourceResponse.model_validate(source) for source in sources]


@router.post(
    "/sources",
    response_model=MonitoringSourceCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_source(
    body: MonitoringSourceCreate,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> MonitoringSourceCreatedResponse:
    """Create a new monitoring source and issue API key. Requires manage permission (admin-ti).

    The raw secret API key is returned exactly once in this response.
    """
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-sources", action=Action.CREATE
    )
    source, api_key = MonitoringSourceService.create_source(db, request, user, body)
    data = MonitoringSourceResponse.model_validate(source).model_dump()
    return MonitoringSourceCreatedResponse(**data, api_key=api_key)


@router.patch("/sources/{source_id}", response_model=MonitoringSourceResponse)
def update_source(
    source_id: UUID,
    body: MonitoringSourceUpdate,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> MonitoringSourceResponse:
    """Update monitoring source metadata (name, enabled, asset_id). Requires manage permission."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-sources", action=Action.UPDATE
    )
    source = MonitoringSourceService.update_source(db, request, user, source_id, body)
    return MonitoringSourceResponse.model_validate(source)


@router.post("/sources/{source_id}/rotate-key", response_model=MonitoringSourceKeyRotatedResponse)
def rotate_source_key(
    source_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> MonitoringSourceKeyRotatedResponse:
    """Rotate secret API key for monitoring source. Old key is immediately invalidated."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-sources", action=Action.UPDATE
    )
    source, api_key = MonitoringSourceService.rotate_key(db, request, user, source_id)
    return MonitoringSourceKeyRotatedResponse(
        id=source.id,
        source_code=source.source_code,
        api_key=api_key,
    )


# =========================================================================
# 2. Monitoring Event Ingestion (Authenticated by X-Monitoring-Key)
# =========================================================================


@router.post(
    "/events",
    response_model=MonitoringEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_event(
    body: MonitoringEventCreate,
    request: Request,
    response: Response,
    db: Database,
    x_monitoring_key: str | None = Header(default=None, alias="X-Monitoring-Key"),
    x_monitoring_source: str | None = Header(default=None, alias="X-Monitoring-Source"),
) -> MonitoringEventResponse:
    """Ingest security monitoring event from authenticated agent or system.

    Authentication via X-Monitoring-Key header.
    Idempotent replay returns 200 OK without creating duplicate records.
    """
    source = MonitoringIngestionService.authenticate_source(
        db, x_monitoring_key, x_monitoring_source
    )
    MonitoringIngestionService.consume_rate_limit(db, request, source)
    event, is_replay = MonitoringIngestionService.ingest_event(db, source, body)

    if is_replay:
        response.status_code = status.HTTP_200_OK

    return MonitoringEventResponse(
        id=event.id,
        source_id=event.source_id,
        source_event_id=event.source_event_id,
        event_type=event.event_type,
        severity=event.severity,
        title=event.title,
        occurred_at=event.occurred_at,
        received_at=event.received_at,
        fingerprint=event.fingerprint,
        idempotent_replay=is_replay,
    )


@router.get("/events", response_model=MonitoringEventPageResponse)
def list_events(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    event_type: EventType | None = Query(default=None),
    severity: Severity | None = Query(default=None),
    source_id: UUID | None = Query(default=None),
    asset_id: int | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    sort_by: str = Query(default="occurred_at"),
    sort_desc: bool = Query(default=True),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
) -> MonitoringEventPageResponse:
    """List monitoring events with filtering and pagination. Requires read on monitoring-events."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring-events", action=Action.READ
    )
    rows, total = MonitoringEventReadService.list_events(
        db,
        event_type=event_type,
        severity=severity,
        source_id=source_id,
        asset_id=asset_id,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by,
        sort_desc=sort_desc,
        page=page,
        page_size=page_size,
    )
    items = [
        MonitoringEventItemResponse(
            id=event.id,
            source_id=event.source_id,
            source_code=source_code,
            source_name=source_name,
            source_event_id=event.source_event_id,
            event_type=event.event_type,
            severity=event.severity,
            title=event.title,
            asset_id=event.asset_id,
            asset_name=asset_name,
            occurred_at=event.occurred_at,
            received_at=event.received_at,
            fingerprint=event.fingerprint,
        )
        for event, source_code, source_name, asset_name in rows
    ]
    return MonitoringEventPageResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/events/{event_id}", response_model=MonitoringEventDetailResponse)
def get_event(
    event_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> MonitoringEventDetailResponse:
    """Retrieve event with sanitized payload. Requires read on monitoring-events."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring-events", action=Action.READ
    )
    event, source_code, source_name, asset_name = MonitoringEventReadService.get_event(
        db, event_id
    )
    return MonitoringEventDetailResponse(
        id=event.id,
        source_id=event.source_id,
        source_code=source_code,
        source_name=source_name,
        source_event_id=event.source_event_id,
        event_type=event.event_type,
        severity=event.severity,
        title=event.title,
        message=event.message,
        asset_id=event.asset_id,
        asset_name=asset_name,
        occurred_at=event.occurred_at,
        received_at=event.received_at,
        fingerprint=event.fingerprint,
        payload=event.payload_json,
    )


# =========================================================================
# 3. Alert Rules Management (Protected by Zero Trust PEP)
# =========================================================================


@router.get("/rules", response_model=list[AlertRuleResponse])
def list_rules(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> list[AlertRuleResponse]:
    """List configured alert rules. Requires read permission on alert-rules."""
    MonitoringPEP(db, request).authorize(session, resource="alert-rules", action=Action.READ)
    rules = AlertRuleService.list_rules(db)
    return [AlertRuleResponse.model_validate(rule) for rule in rules]


@router.get("/rules/{rule_id}", response_model=AlertRuleResponse)
def get_rule(
    rule_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> AlertRuleResponse:
    """Retrieve an alert rule by ID. Requires read permission on alert-rules."""
    MonitoringPEP(db, request).authorize(session, resource="alert-rules", action=Action.READ)
    rule = AlertRuleService.get_rule(db, rule_id)
    return AlertRuleResponse.model_validate(rule)


@router.post(
    "/rules",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_rule(
    body: AlertRuleCreate,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> AlertRuleResponse:
    """Create a new alert rule. Requires manage permission (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="alert-rules", action=Action.CREATE
    )
    rule = AlertRuleService.create_rule(db, request, user, body)
    return AlertRuleResponse.model_validate(rule)


@router.patch("/rules/{rule_id}", response_model=AlertRuleResponse)
def update_rule(
    rule_id: UUID,
    body: AlertRuleUpdate,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> AlertRuleResponse:
    """Update or logically disable an alert rule. Requires manage permission (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="alert-rules", action=Action.UPDATE
    )
    rule = AlertRuleService.update_rule(db, request, user, rule_id, body)
    return AlertRuleResponse.model_validate(rule)


# =========================================================================
# 4. Alerts Read API (Protected by Zero Trust PEP)
# =========================================================================


@router.get("/alerts", response_model=AlertPageResponse)
def list_alerts(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    rule: str | None = Query(default=None),
    asset_id: int | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    sort_by: str = Query(default="created_at"),
    sort_desc: bool = Query(default=True),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
) -> AlertPageResponse:
    """List alerts with filtering, sorting allowlist, and validated pagination.

    Requires read permission on alerts (admin-ti, auditor).
    """
    MonitoringPEP(db, request).authorize(session, resource="alerts", action=Action.READ)
    items, total = AlertService.list_alerts(
        db,
        status=status_filter,
        severity=severity,
        rule=rule,
        asset_id=asset_id,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by,
        sort_desc=sort_desc,
        page=page,
        page_size=page_size,
    )
    return AlertPageResponse(
        items=[AlertResponse.model_validate(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetailResponse)
def get_alert(
    alert_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> AlertDetailResponse:
    """Retrieve alert detail by ID including history.

    Requires read permission on alerts (admin-ti, auditor).
    """
    MonitoringPEP(db, request).authorize(session, resource="alerts", action=Action.READ)
    alert = AlertService.get_alert(db, alert_id)
    return AlertDetailResponse.model_validate(alert)


@router.get("/alerts/{alert_id}/history", response_model=list[AlertHistoryResponse])
def get_alert_history(
    alert_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> list[AlertHistoryResponse]:
    """Retrieve historical status audit trail for an alert. Requires read permission on alerts."""
    MonitoringPEP(db, request).authorize(session, resource="alerts", action=Action.READ)
    history = AlertService.get_alert_history(db, alert_id)
    return [AlertHistoryResponse.model_validate(h) for h in history]


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertDetailResponse)
def acknowledge_alert(
    alert_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    body: AlertAcknowledgeRequest = Body(default_factory=AlertAcknowledgeRequest),
) -> AlertDetailResponse:
    """Acknowledge an OPEN alert. Requires manage permission (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="alerts", action=Action.UPDATE
    )
    alert = AlertService.acknowledge_alert(
        db, request, user, alert_id, comment=body.comment
    )
    return AlertDetailResponse.model_validate(alert)


@router.post("/alerts/{alert_id}/resolve", response_model=AlertDetailResponse)
def resolve_alert(
    alert_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    body: AlertResolveRequest = Body(default_factory=AlertResolveRequest),
) -> AlertDetailResponse:
    """Resolve an OPEN or ACKNOWLEDGED alert. Requires manage permission (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="alerts", action=Action.UPDATE
    )
    alert = AlertService.resolve_alert(
        db, request, user, alert_id, comment=body.comment
    )
    return AlertDetailResponse.model_validate(alert)


@router.get("/metrics/alerts", response_model=AlertMetricsResponse)
def get_alert_metrics(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> AlertMetricsResponse:
    """Retrieve dynamic real-time alert metrics by status and severity.
    
    Requires read permission on alerts.
    """
    MonitoringPEP(db, request).authorize(session, resource="alerts", action=Action.READ)
    return AlertMetricsResponse(
        alerts_open=AlertMetricsService.get_open_alerts_count(db),
        critical_open=AlertMetricsService.get_critical_open_alerts_count(db),
        alerts_by_severity=AlertMetricsService.get_alerts_by_severity(db),
        alerts_by_status=AlertMetricsService.get_alerts_by_status(db),
    )


@router.get("/metrics/dashboard", response_model=MonitoringDashboardMetricsResponse)
def get_dashboard_metrics(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> MonitoringDashboardMetricsResponse:
    """Retrieve unified dashboard metrics and chart time-series. Requires read on monitoring."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring", action=Action.READ
    )
    metrics = DashboardMetricsService.get_dashboard_metrics(db)
    return MonitoringDashboardMetricsResponse(**metrics)


# =========================================================================
# 5. File Integrity Monitoring (FIM) (Protected by Zero Trust PEP)
# =========================================================================


@router.get("/fim/targets", response_model=list[FimTargetResponse])
def list_fim_targets(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    enabled_only: bool = Query(default=False),
) -> list[FimTargetResponse]:
    """List monitored FIM targets. Requires read permission on monitoring-fim."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action=Action.READ
    )
    targets = FimService.list_targets(db, enabled_only=enabled_only)
    return [FimTargetResponse.model_validate(t) for t in targets]


@router.get("/fim/targets/{target_id}", response_model=FimTargetResponse)
def get_fim_target(
    target_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> FimTargetResponse:
    """Retrieve FIM target by ID. Requires read permission on monitoring-fim."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action=Action.READ
    )
    target = FimService.get_target(db, target_id)
    return FimTargetResponse.model_validate(target)


@router.post(
    "/fim/targets",
    response_model=FimTargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_fim_target(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    body: FimTargetCreate,
) -> FimTargetResponse:
    """Register a new FIM target and establish its baseline. Requires manage (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action=Action.CREATE
    )
    target = FimService.create_target(db, request, user, body)
    return FimTargetResponse.model_validate(target)


@router.patch("/fim/targets/{target_id}", response_model=FimTargetResponse)
def update_fim_target(
    target_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    body: FimTargetUpdate,
) -> FimTargetResponse:
    """Update FIM target configuration (enabled, asset_id). Requires manage (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action=Action.UPDATE
    )
    target = FimService.update_target(db, request, user, target_id, body)
    return FimTargetResponse.model_validate(target)


@router.post("/fim/targets/{target_id}/baseline", response_model=FimTargetResponse)
def rebaseline_fim_target(
    target_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> FimTargetResponse:
    """Calculate and set new baseline SHA-256 for a target. Requires manage (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action=Action.UPDATE
    )
    target = FimService.create_baseline(db, request, user, target_id)
    return FimTargetResponse.model_validate(target)


@router.post("/fim/targets/{target_id}/scan", response_model=FimScanResult)
def scan_fim_target(
    target_id: UUID,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> FimScanResult:
    """Scan a single FIM target. Requires scan permission (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action="scan"
    )
    return FimService.scan_target(db, request, user, target_id)


@router.post("/fim/scan", response_model=FimGlobalScanResponse)
def scan_all_fim_targets(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> FimGlobalScanResponse:
    """Execute scan across all enabled FIM targets. Requires scan permission (admin-ti)."""
    user = MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action="scan"
    )
    return FimService.scan_all_enabled(db, request, user)


@router.get("/metrics/fim", response_model=FimMetricsResponse)
def get_fim_metrics(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
) -> FimMetricsResponse:
    """Retrieve real-time FIM operational metrics. Requires read permission on monitoring-fim."""
    MonitoringPEP(db, request).authorize(
        session, resource="monitoring-fim", action=Action.READ
    )
    return FimMetricsResponse(
        fim_targets_enabled=FimMetricsService.get_enabled_targets_count(db),
        fim_scans_24h=FimMetricsService.get_scans_last_24h_count(db),
        fim_changes_24h=FimMetricsService.get_changes_last_24h_count(db),
    )

