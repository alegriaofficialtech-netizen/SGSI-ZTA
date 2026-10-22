from uuid import uuid4

import pytest
from sqlalchemy import select, text

from app.database import SessionLocal, engine, now_utc
from app.models import User
from app.models.monitoring import (
    Alert,
    AlertHistory,
    AlertRule,
    AlertStatus,
    EventType,
    MonitoringEvent,
    MonitoringSource,
    Severity,
    SourceType,
)


def create_isolated_monitoring_fixture(db):
    admin_u = db.scalar(select(User).where(User.username == "admin.demo"))
    source = MonitoringSource(
        id=str(uuid4()),
        source_code=f"SRC-PG-{uuid4().hex[:6]}",
        name="Postgres Test Source",
        source_type=SourceType.APPLICATION,
        key_hash="fakehash",
    )
    db.add(source)
    db.flush()

    evt = MonitoringEvent(
        id=str(uuid4()),
        source_id=source.id,
        source_event_id=f"evt-{uuid4().hex[:6]}",
        event_type=EventType.POLICY_DENY,
        severity=Severity.HIGH,
        title="Test Event",
        message="Test event for DB trigger immutability",
        occurred_at=now_utc(),
        fingerprint=f"fp-{uuid4().hex[:8]}",
        payload_json={"test": True},
    )
    db.add(evt)
    db.flush()

    rule = AlertRule(
        id=str(uuid4()),
        rule_code=f"RULE-PG-{uuid4().hex[:6]}",
        name="Test Rule",
        event_type=EventType.POLICY_DENY,
        minimum_severity=Severity.HIGH,
        created_by=admin_u.id,
    )
    db.add(rule)
    db.flush()

    alert = Alert(
        id=str(uuid4()),
        alert_code=f"ALT-PG-{uuid4().hex[:8]}",
        event_id=evt.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        title="Test Alert",
        fingerprint=evt.fingerprint,
    )
    db.add(alert)
    db.flush()

    hist = AlertHistory(
        id=str(uuid4()),
        alert_id=alert.id,
        actor_user_id=admin_u.id,
        action="CREATE",
        previous_status=None,
        new_status=AlertStatus.OPEN,
        comment="Created in test",
    )
    db.add(hist)
    db.commit()
    return source, evt, rule, alert, hist


def test_monitoring_events_immutability_raw_sql_update_on_postgresql():
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL trigger immutability test")

    with SessionLocal() as db:
        _, evt, _, _, _ = create_isolated_monitoring_fixture(db)
        with pytest.raises(Exception, match="(?i)monitoring_events table is append-only"):
            db.execute(
                text("UPDATE monitoring_events SET title = 'Tampered' WHERE id = :id"),
                {"id": evt.id},
            )
            db.flush()
        db.rollback()


def test_monitoring_events_immutability_raw_sql_delete_on_postgresql():
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL trigger immutability test")

    with SessionLocal() as db:
        _, evt, _, _, _ = create_isolated_monitoring_fixture(db)
        with pytest.raises(Exception, match="(?i)monitoring_events table is append-only"):
            db.execute(
                text("DELETE FROM monitoring_events WHERE id = :id"),
                {"id": evt.id},
            )
            db.flush()
        db.rollback()


def test_alert_history_immutability_raw_sql_update_on_postgresql():
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL trigger immutability test")

    with SessionLocal() as db:
        _, _, _, _, hist = create_isolated_monitoring_fixture(db)
        with pytest.raises(Exception, match="(?i)alert_history table is append-only"):
            db.execute(
                text("UPDATE alert_history SET comment = 'Tampered' WHERE id = :id"),
                {"id": hist.id},
            )
            db.flush()
        db.rollback()


def test_alert_history_immutability_raw_sql_delete_on_postgresql():
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL trigger immutability test")

    with SessionLocal() as db:
        _, _, _, _, hist = create_isolated_monitoring_fixture(db)
        with pytest.raises(Exception, match="(?i)alert_history table is append-only"):
            db.execute(
                text("DELETE FROM alert_history WHERE id = :id"),
                {"id": hist.id},
            )
            db.flush()
        db.rollback()


def test_runtime_user_cannot_bypass_monitoring_immutability_on_postgresql():
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL trigger immutability test")

    with SessionLocal() as db:
        _, evt, _, _, hist = create_isolated_monitoring_fixture(db)

        # Attempting bypass using session variable
        db.execute(text("SET LOCAL sgsi.bypass_immutability = 'on'"))

        with pytest.raises(Exception, match="(?i)monitoring_events table is append-only"):
            db.execute(
                text("UPDATE monitoring_events SET title = 'Bypass attempt' WHERE id = :id"),
                {"id": evt.id},
            )
            db.flush()
        db.rollback()

        # Same for alert_history
        db.execute(text("SET LOCAL sgsi.bypass_immutability = 'on'"))
        with pytest.raises(Exception, match="(?i)alert_history table is append-only"):
            db.execute(
                text("DELETE FROM alert_history WHERE id = :id"),
                {"id": hist.id},
            )
            db.flush()
        db.rollback()
