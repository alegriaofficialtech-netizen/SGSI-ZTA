"""Native deterministic Alert Engine for SGSI-ZTA monitoring.

Evaluates incoming MonitoringEvents against enabled AlertRules, enforces strict
severity ordering and asset criticality constraints, computes deterministic
fingerprints, and manages alert creation and deduplication within cooldown windows.
"""
import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.database import now_utc
from app.models.assets import Asset
from app.models.monitoring import Alert, AlertHistory, AlertRule, MonitoringEvent
from app.monitoring.types import AlertStatus, EventType, Severity

# Strict deterministic severity order: INFO < LOW < MEDIUM < HIGH < CRITICAL
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_matches(event_severity: Severity, minimum_severity: Severity) -> bool:
    """Return True if event_severity is greater than or equal to minimum_severity."""
    return SEVERITY_ORDER[event_severity] >= SEVERITY_ORDER[minimum_severity]


def to_naive_utc(dt: datetime) -> datetime:
    """Ensure datetime is naive UTC for consistent database comparisons."""
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def compute_alert_fingerprint(
    rule_id: str,
    asset_id: int | None,
    event_type: EventType,
    event_fingerprint: str,
) -> str:
    """Compute deterministic SHA-256 fingerprint for alert deduplication."""
    asset_part = asset_id if asset_id is not None else "none"
    raw = f"{rule_id}:{asset_part}:{event_type.value}:{event_fingerprint}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AlertEngine:
    """Deterministic, rule-based alert evaluation and deduplication engine."""

    @classmethod
    def process_event(cls, db: Session, event: MonitoringEvent) -> list[Alert]:
        """Process an ingested MonitoringEvent against all enabled AlertRules.

        Executes within the caller's database transaction to ensure atomicity.
        Returns the list of created or deduplicated Alert instances.
        """
        # 1. Fetch all enabled rules matching event_type
        rules = db.scalars(
            select(AlertRule).where(
                AlertRule.enabled.is_(True),
                AlertRule.event_type == event.event_type,
            )
        ).all()

        if not rules:
            return []

        # Cache asset if present for criticality checking
        event_asset: Asset | None = None
        if event.asset_id is not None:
            event_asset = db.scalar(select(Asset).where(Asset.id == event.asset_id))

        results: list[Alert] = []

        for rule in rules:
            # 2. Check minimum severity
            if not severity_matches(event.severity, rule.minimum_severity):
                continue

            # 3. Check optional asset criticality filter
            if rule.asset_criticality is not None:
                if event_asset is None:
                    # Rule requires a specific criticality, but event has no associated asset
                    continue
                # Asset criticality enum value string comparison
                asset_crit = (
                    event_asset.criticality.value
                    if hasattr(event_asset.criticality, "value")
                    else str(event_asset.criticality)
                )
                rule_crit = (
                    rule.asset_criticality.value
                    if hasattr(rule.asset_criticality, "value")
                    else str(rule.asset_criticality)
                )
                if asset_crit.upper() != rule_crit.upper():
                    continue

            # 4. Deterministic alert fingerprint
            alert_fingerprint = compute_alert_fingerprint(
                rule_id=rule.id,
                asset_id=event.asset_id,
                event_type=event.event_type,
                event_fingerprint=event.fingerprint,
            )

            # 5. Concurrency control: on PostgreSQL, acquire transaction advisory lock
            # to serialize deduplication checks for the exact (rule, fingerprint) pair.
            if db.bind and db.bind.dialect.name == "postgresql":
                # Convert 15 hex chars of md5 to 60-bit positive int
                lock_id = int(
                    hashlib.md5(f"alert:{rule.id}:{alert_fingerprint}".encode()).hexdigest()[:15],
                    16,
                )
                db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})

            # 6. Query most recent active alert (OPEN or ACKNOWLEDGED) with same fingerprint
            stmt = (
                select(Alert)
                .where(
                    Alert.rule_id == rule.id,
                    Alert.fingerprint == alert_fingerprint,
                    Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
                )
                .order_by(Alert.last_seen_at.desc())
                .limit(1)
            )

            if db.bind and db.bind.dialect.name == "postgresql":
                stmt = stmt.with_for_update()

            existing_alert = db.scalar(stmt)

            # 7. Evaluate cooldown window
            event_occurred = to_naive_utc(event.occurred_at)
            is_in_cooldown = False
            if existing_alert is not None:
                alert_last_seen = to_naive_utc(existing_alert.last_seen_at)
                elapsed_seconds = (event_occurred - alert_last_seen).total_seconds()
                if 0 <= elapsed_seconds <= rule.cooldown_seconds:
                    is_in_cooldown = True

            if is_in_cooldown and existing_alert is not None:
                # Deduplicate existing alert
                existing_alert.occurrence_count += 1
                if event_occurred > to_naive_utc(existing_alert.last_seen_at):
                    existing_alert.last_seen_at = event_occurred
                existing_alert.updated_at = now_utc()

                # Record AlertHistory for deduplication
                history = AlertHistory(
                    alert_id=existing_alert.id,
                    actor_user_id=None,
                    action="ALERT_DEDUPLICATED",
                    previous_status=existing_alert.status,
                    new_status=existing_alert.status,
                    comment=(
                        f"Deduplicated event {event.id} by rule {rule.rule_code} "
                        f"(occurrence #{existing_alert.occurrence_count})"
                    ),
                    created_at=now_utc(),
                )
                db.add(history)
                results.append(existing_alert)
            else:
                # Create brand new OPEN alert
                alert_code = f"ALT-{uuid4().hex[:12].upper()}"
                new_alert = Alert(
                    alert_code=alert_code,
                    event_id=event.id,
                    rule_id=rule.id,
                    asset_id=event.asset_id,
                    severity=event.severity,
                    status=AlertStatus.OPEN,
                    title=f"[{rule.rule_code}] {event.title}",
                    description=event.message,
                    fingerprint=alert_fingerprint,
                    occurrence_count=1,
                    first_seen_at=event_occurred,
                    last_seen_at=event_occurred,
                    created_at=now_utc(),
                    updated_at=now_utc(),
                )
                db.add(new_alert)
                db.flush()

                # Record AlertHistory for creation
                history = AlertHistory(
                    alert_id=new_alert.id,
                    actor_user_id=None,
                    action="ALERT_CREATED",
                    previous_status=None,
                    new_status=AlertStatus.OPEN,
                    comment=f"Alert opened by rule {rule.rule_code} for event {event.id}",
                    created_at=now_utc(),
                )
                db.add(history)
                results.append(new_alert)

        return results
