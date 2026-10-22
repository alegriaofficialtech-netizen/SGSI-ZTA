"""Monitoring and Alert metrics foundation for SGSI-ZTA."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.monitoring import Alert
from app.monitoring.types import AlertStatus, Severity


class AlertMetricsService:
    """Computes dynamic, real-time alert metrics directly from the database."""

    @classmethod
    def get_open_alerts_count(cls, db: Session) -> int:
        """Return total count of alerts in OPEN status."""
        return (
            db.scalar(
                select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
            )
            or 0
        )

    @classmethod
    def get_critical_open_alerts_count(cls, db: Session) -> int:
        """Return count of OPEN alerts with CRITICAL severity."""
        return (
            db.scalar(
                select(func.count(Alert.id)).where(
                    Alert.status == AlertStatus.OPEN,
                    Alert.severity == Severity.CRITICAL,
                )
            )
            or 0
        )

    @classmethod
    def get_alerts_by_severity(cls, db: Session) -> dict[str, int]:
        """Return count of alerts grouped by severity."""
        counts = {sev.value: 0 for sev in Severity}
        rows = db.execute(
            select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        ).all()
        for sev, count in rows:
            sev_key = sev.value if hasattr(sev, "value") else str(sev)
            counts[sev_key] = count
        return counts

    @classmethod
    def get_alerts_by_status(cls, db: Session) -> dict[str, int]:
        """Return count of alerts grouped by status."""
        counts = {status.value: 0 for status in AlertStatus}
        rows = db.execute(
            select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
        ).all()
        for st, count in rows:
            st_key = st.value if hasattr(st, "value") else str(st)
            counts[st_key] = count
        return counts


class FimMetricsService:
    """Computes real-time FIM operational metrics."""

    @classmethod
    def get_enabled_targets_count(cls, db: Session) -> int:
        """Return total count of enabled FIM targets."""
        from app.models.monitoring import FimTarget

        return (
            db.scalar(
                select(func.count(FimTarget.id)).where(FimTarget.enabled.is_(True))
            )
            or 0
        )

    @classmethod
    def get_scans_last_24h_count(cls, db: Session) -> int:
        """Return total count of FIM scan executions in the last 24 hours."""
        from datetime import timedelta

        from app.database import now_utc
        from app.models.identity import AuditLog

        since = now_utc() - timedelta(hours=24)
        return (
            db.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action.in_(["FIM_SCAN_EXECUTED", "FIM_CHANGE_DETECTED"]),
                    AuditLog.timestamp >= since,
                )
            )
            or 0
        )

    @classmethod
    def get_changes_last_24h_count(cls, db: Session) -> int:
        """Return total count of file integrity change events in the last 24 hours."""
        from datetime import timedelta

        from app.database import now_utc
        from app.models.monitoring import MonitoringEvent
        from app.monitoring.types import EventType

        since = now_utc() - timedelta(hours=24)
        return (
            db.scalar(
                select(func.count(MonitoringEvent.id)).where(
                    MonitoringEvent.event_type == EventType.FILE_INTEGRITY_CHANGE,
                    MonitoringEvent.created_at >= since,
                )
            )
            or 0
        )


class DashboardMetricsService:
    """Aggregates high-level dashboard metrics for the monitoring console."""

    @classmethod
    def get_dashboard_metrics(cls, db: Session) -> dict:
        from datetime import timedelta

        from app.database import now_utc
        from app.models.assets import Asset
        from app.models.monitoring import MonitoringEvent
        from app.monitoring.types import EventType

        now = now_utc()
        last_24h = now - timedelta(hours=24)

        # 1. Event counts 24h
        events_24h = (
            db.scalar(
                select(func.count(MonitoringEvent.id)).where(
                    MonitoringEvent.occurred_at >= last_24h
                )
            )
            or 0
        )

        # 2. Alerts counts
        alerts_open = (
            db.scalar(
                select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
            )
            or 0
        )
        alerts_acknowledged = (
            db.scalar(
                select(func.count(Alert.id)).where(
                    Alert.status == AlertStatus.ACKNOWLEDGED
                )
            )
            or 0
        )
        alerts_resolved_24h = (
            db.scalar(
                select(func.count(Alert.id)).where(
                    Alert.status == AlertStatus.RESOLVED,
                    Alert.resolved_at >= last_24h,
                )
            )
            or 0
        )
        critical_open = (
            db.scalar(
                select(func.count(Alert.id)).where(
                    Alert.status == AlertStatus.OPEN,
                    Alert.severity == Severity.CRITICAL,
                )
            )
            or 0
        )
        high_open = (
            db.scalar(
                select(func.count(Alert.id)).where(
                    Alert.status == AlertStatus.OPEN,
                    Alert.severity == Severity.HIGH,
                )
            )
            or 0
        )

        # 3. FIM metrics
        fim_targets_enabled = FimMetricsService.get_enabled_targets_count(db)
        fim_scans_24h = FimMetricsService.get_scans_last_24h_count(db)
        fim_changes_24h = FimMetricsService.get_changes_last_24h_count(db)

        # 4. Events by hour (last 24 hours buckets)
        events_rows = (
            db.execute(
                select(MonitoringEvent.occurred_at).where(
                    MonitoringEvent.occurred_at >= last_24h
                )
            )
            .scalars()
            .all()
        )

        hour_counts: dict[str, int] = {}
        for i in range(24):
            bucket_time = now - timedelta(hours=23 - i)
            hour_str = bucket_time.strftime("%H:00")
            hour_counts[hour_str] = 0

        for occurred in events_rows:
            h_str = occurred.strftime("%H:00")
            if h_str in hour_counts:
                hour_counts[h_str] += 1

        events_by_hour = [{"hour": h, "count": c} for h, c in hour_counts.items()]

        # 5. Alerts by severity
        sev_counts = {sev.value: 0 for sev in Severity}
        alert_sev_rows = db.execute(
            select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        ).all()
        for sev, count in alert_sev_rows:
            s_val = sev.value if hasattr(sev, "value") else str(sev)
            sev_counts[s_val] = count
        alerts_by_severity = [
            {"severity": s, "count": sev_counts[s]}
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ]

        # 6. Events by type
        evt_type_counts = {et.value: 0 for et in EventType}
        evt_type_rows = db.execute(
            select(MonitoringEvent.event_type, func.count(MonitoringEvent.id))
            .where(MonitoringEvent.occurred_at >= last_24h)
            .group_by(MonitoringEvent.event_type)
        ).all()
        for et, count in evt_type_rows:
            et_val = et.value if hasattr(et, "value") else str(et)
            evt_type_counts[et_val] = count
        events_by_type = [
            {"event_type": et, "count": c}
            for et, c in evt_type_counts.items()
            if c > 0
        ]
        if not events_by_type:
            events_by_type = [
                {"event_type": et.value, "count": 0} for et in EventType
            ][:5]

        # 7. Top affected assets
        top_assets_rows = db.execute(
            select(
                Asset.id,
                Asset.name,
                func.count(MonitoringEvent.id),
            )
            .join(MonitoringEvent, MonitoringEvent.asset_id == Asset.id)
            .where(MonitoringEvent.occurred_at >= last_24h)
            .group_by(Asset.id, Asset.name)
            .order_by(func.count(MonitoringEvent.id).desc())
            .limit(5)
        ).all()
        top_affected_assets = [
            {"asset_id": aid, "asset_name": aname, "count": cnt}
            for aid, aname, cnt in top_assets_rows
        ]

        return {
            "events_24h": events_24h,
            "alerts_open": alerts_open,
            "alerts_acknowledged": alerts_acknowledged,
            "alerts_resolved_24h": alerts_resolved_24h,
            "critical_open": critical_open,
            "high_open": high_open,
            "fim_targets_enabled": fim_targets_enabled,
            "fim_scans_24h": fim_scans_24h,
            "fim_changes_24h": fim_changes_24h,
            "events_by_hour": events_by_hour,
            "alerts_by_severity": alerts_by_severity,
            "events_by_type": events_by_type,
            "top_affected_assets": top_affected_assets,
        }


