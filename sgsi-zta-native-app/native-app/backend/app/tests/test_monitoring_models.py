from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal, now_utc
from app.models import Asset, User
from app.models.monitoring import (
    Alert,
    AlertHistory,
    AlertRule,
    AlertStatus,
    EventType,
    FimTarget,
    MonitoringEvent,
    MonitoringSource,
    Severity,
    SourceType,
)


def get_admin_user_id(db):
    return db.scalar(select(User.id).where(User.username == "admin.demo"))


def get_srv_asset_id(db):
    asset = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
    return asset.id if asset else None


def test_monitoring_enums():
    assert Severity.INFO.value == "INFO"
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"

    assert AlertStatus.OPEN.value == "OPEN"
    assert AlertStatus.ACKNOWLEDGED.value == "ACKNOWLEDGED"
    assert AlertStatus.RESOLVED.value == "RESOLVED"

    assert EventType.AUTH_FAILURE.value == "AUTH_FAILURE"
    assert EventType.AUTH_SUCCESS.value == "AUTH_SUCCESS"
    assert EventType.MFA_FAILURE.value == "MFA_FAILURE"
    assert EventType.POLICY_DENY.value == "POLICY_DENY"
    assert EventType.POLICY_MFA_REQUIRED.value == "POLICY_MFA_REQUIRED"
    assert EventType.FILE_INTEGRITY_CHANGE.value == "FILE_INTEGRITY_CHANGE"
    assert EventType.ASSET_CHANGE.value == "ASSET_CHANGE"
    assert EventType.RISK_CHANGE.value == "RISK_CHANGE"
    assert EventType.SECURITY_CONFIGURATION_CHANGE.value == "SECURITY_CONFIGURATION_CHANGE"

    assert SourceType.HOST.value == "HOST"
    assert SourceType.APPLICATION.value == "APPLICATION"
    assert SourceType.DATABASE.value == "DATABASE"
    assert SourceType.FIM.value == "FIM"
    assert SourceType.NETWORK.value == "NETWORK"
    assert SourceType.SYNTHETIC_AGENT.value == "SYNTHETIC_AGENT"


def test_monitoring_source_crud_and_uniqueness():
    with SessionLocal() as db:
        code = f"SRC-TEST-{uuid4().hex[:6]}"
        source = MonitoringSource(
            id=str(uuid4()),
            source_code=code,
            name="Test Application Source",
            source_type=SourceType.APPLICATION,
            asset_id=get_srv_asset_id(db),
            enabled=True,
            key_hash="$argon2id$v=19$m=65536,t=3,p=4$fakehashtest",
        )
        db.add(source)
        db.commit()

        # Unique source_code constraint
        dup = MonitoringSource(
            id=str(uuid4()),
            source_code=code,
            name="Duplicate Source",
            source_type=SourceType.HOST,
            key_hash="hash2",
        )
        db.add(dup)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_monitoring_event_idempotency_constraint():
    with SessionLocal() as db:
        source = MonitoringSource(
            id=str(uuid4()),
            source_code=f"SRC-IDEMP-{uuid4().hex[:6]}",
            name="Idempotency Test Source",
            source_type=SourceType.APPLICATION,
            key_hash="fakehash",
        )
        db.add(source)
        db.commit()

        src_event_id = "evt-unique-001"
        event1 = MonitoringEvent(
            id=str(uuid4()),
            source_id=source.id,
            source_event_id=src_event_id,
            event_type=EventType.POLICY_DENY,
            severity=Severity.HIGH,
            title="Access Denied by Policy",
            message="User admision denied read_sensitive",
            occurred_at=now_utc(),
            fingerprint="fp-test-001",
            payload_json={"resource": "clinical-demo"},
        )
        db.add(event1)
        db.commit()

        # Duplicate source_id + source_event_id must violate unique constraint
        event2 = MonitoringEvent(
            id=str(uuid4()),
            source_id=source.id,
            source_event_id=src_event_id,
            event_type=EventType.POLICY_DENY,
            severity=Severity.HIGH,
            title="Duplicate event",
            message="Same source event id",
            occurred_at=now_utc(),
            fingerprint="fp-test-001",
            payload_json={"resource": "clinical-demo"},
        )
        db.add(event2)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_monitoring_event_orm_immutability():
    with SessionLocal() as db:
        source = MonitoringSource(
            id=str(uuid4()),
            source_code=f"SRC-IMMUT-{uuid4().hex[:6]}",
            name="Immutability Test Source",
            source_type=SourceType.APPLICATION,
            key_hash="fakehash",
        )
        db.add(source)
        db.commit()

        evt = MonitoringEvent(
            id=str(uuid4()),
            source_id=source.id,
            source_event_id="evt-immut-001",
            event_type=EventType.AUTH_FAILURE,
            severity=Severity.MEDIUM,
            title="Failed Login Attempt",
            message="Invalid credentials",
            occurred_at=now_utc(),
            fingerprint="fp-immut-001",
            payload_json={"ip": "127.0.0.1"},
        )
        db.add(evt)
        db.commit()

        # ORM Update blocked
        evt.title = "Tampered Title"
        with pytest.raises((ValueError, Exception), match="(?i)append-only"):
            db.flush()
        db.rollback()

        # ORM Delete blocked
        evt = db.get(MonitoringEvent, evt.id)
        db.delete(evt)
        with pytest.raises((ValueError, Exception), match="(?i)append-only"):
            db.flush()
        db.rollback()


def test_alert_rule_constraints_and_uniqueness():
    with SessionLocal() as db:
        admin_id = get_admin_user_id(db)
        rule_code = f"RULE-TEST-{uuid4().hex[:6]}"
        rule = AlertRule(
            id=str(uuid4()),
            rule_code=rule_code,
            name="Critical FIM Rule",
            description="Alerts on FIM changes",
            enabled=True,
            event_type=EventType.FILE_INTEGRITY_CHANGE,
            minimum_severity=Severity.HIGH,
            cooldown_seconds=300,
            created_by=admin_id,
        )
        db.add(rule)
        db.commit()

        # Duplicate rule_code
        dup = AlertRule(
            id=str(uuid4()),
            rule_code=rule_code,
            name="Dup Rule",
            event_type=EventType.FILE_INTEGRITY_CHANGE,
            minimum_severity=Severity.HIGH,
            created_by=admin_id,
        )
        db.add(dup)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # Negative cooldown check
        invalid_rule = AlertRule(
            id=str(uuid4()),
            rule_code=f"RULE-NEG-{uuid4().hex[:6]}",
            name="Negative Cooldown Rule",
            event_type=EventType.FILE_INTEGRITY_CHANGE,
            minimum_severity=Severity.HIGH,
            cooldown_seconds=-10,
            created_by=admin_id,
        )
        db.add(invalid_rule)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_alert_and_alert_history_lifecycle():
    with SessionLocal() as db:
        admin_id = get_admin_user_id(db)
        source = MonitoringSource(
            id=str(uuid4()),
            source_code=f"SRC-ALRT-{uuid4().hex[:6]}",
            name="Alert Source",
            source_type=SourceType.APPLICATION,
            key_hash="fakehash",
        )
        db.add(source)
        db.flush()

        evt = MonitoringEvent(
            id=str(uuid4()),
            source_id=source.id,
            source_event_id="evt-alrt-001",
            event_type=EventType.MFA_FAILURE,
            severity=Severity.HIGH,
            title="MFA Failure",
            message="Invalid TOTP token",
            occurred_at=now_utc(),
            fingerprint="fp-alrt-001",
        )
        db.add(evt)
        db.flush()

        rule = AlertRule(
            id=str(uuid4()),
            rule_code=f"RULE-MFA-{uuid4().hex[:6]}",
            name="MFA Failure Rule",
            event_type=EventType.MFA_FAILURE,
            minimum_severity=Severity.HIGH,
            created_by=admin_id,
        )
        db.add(rule)
        db.flush()

        alert_code = f"ALT-{uuid4().hex[:8]}"
        alert = Alert(
            id=str(uuid4()),
            alert_code=alert_code,
            event_id=evt.id,
            rule_id=rule.id,
            severity=Severity.HIGH,
            status=AlertStatus.OPEN,
            title="Security Alert: MFA Failure",
            fingerprint=evt.fingerprint,
            occurrence_count=1,
            first_seen_at=now_utc(),
            last_seen_at=now_utc(),
        )
        db.add(alert)
        db.flush()

        hist = AlertHistory(
            id=str(uuid4()),
            alert_id=alert.id,
            actor_user_id=admin_id,
            action="CREATE",
            previous_status=None,
            new_status=AlertStatus.OPEN,
            comment="Alert created by rule engine",
        )
        db.add(hist)
        db.commit()

        # Test occurrence_count >= 1 check constraint
        invalid_alert = Alert(
            id=str(uuid4()),
            alert_code=f"ALT-INV-{uuid4().hex[:8]}",
            event_id=evt.id,
            rule_id=rule.id,
            severity=Severity.HIGH,
            status=AlertStatus.OPEN,
            title="Invalid Alert",
            fingerprint=evt.fingerprint,
            occurrence_count=0,
        )
        db.add(invalid_alert)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_alert_history_orm_immutability():
    with SessionLocal() as db:
        admin_id = get_admin_user_id(db)
        source = MonitoringSource(
            id=str(uuid4()),
            source_code=f"SRC-HIST-{uuid4().hex[:6]}",
            name="Hist Source",
            source_type=SourceType.APPLICATION,
            key_hash="fakehash",
        )
        db.add(source)
        db.flush()

        evt = MonitoringEvent(
            id=str(uuid4()),
            source_id=source.id,
            source_event_id="evt-hist-001",
            event_type=EventType.POLICY_DENY,
            severity=Severity.HIGH,
            title="Deny Event",
            message="Policy Denied",
            occurred_at=now_utc(),
            fingerprint="fp-hist-001",
        )
        db.add(evt)
        db.flush()

        rule = AlertRule(
            id=str(uuid4()),
            rule_code=f"RULE-HIST-{uuid4().hex[:6]}",
            name="Hist Rule",
            event_type=EventType.POLICY_DENY,
            minimum_severity=Severity.HIGH,
            created_by=admin_id,
        )
        db.add(rule)
        db.flush()

        alert = Alert(
            id=str(uuid4()),
            alert_code=f"ALT-HIST-{uuid4().hex[:8]}",
            event_id=evt.id,
            rule_id=rule.id,
            severity=Severity.HIGH,
            status=AlertStatus.OPEN,
            title="Alert for History",
            fingerprint=evt.fingerprint,
        )
        db.add(alert)
        db.flush()

        hist = AlertHistory(
            id=str(uuid4()),
            alert_id=alert.id,
            actor_user_id=admin_id,
            action="CREATE",
            previous_status=None,
            new_status=AlertStatus.OPEN,
        )
        db.add(hist)
        db.commit()

        # Update AlertHistory blocked
        hist.comment = "Tampered history comment"
        with pytest.raises((ValueError, Exception), match="(?i)append-only"):
            db.flush()
        db.rollback()

        # Delete AlertHistory blocked
        hist = db.get(AlertHistory, hist.id)
        db.delete(hist)
        with pytest.raises((ValueError, Exception), match="(?i)append-only"):
            db.flush()
        db.rollback()


def test_fim_target_relative_path_safety():
    with SessionLocal() as db:
        # Safe relative path
        target = FimTarget(
            id=str(uuid4()),
            target_code=f"FIM-TEST-{uuid4().hex[:6]}",
            relative_path="patient-demo.json",
            baseline_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            enabled=True,
        )
        db.add(target)
        db.commit()

        # Unsafe path: absolute with leading slash
        unsafe1 = FimTarget(
            id=str(uuid4()),
            target_code=f"FIM-UNSAFE1-{uuid4().hex[:6]}",
            relative_path="/etc/passwd",
            baseline_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        db.add(unsafe1)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # Unsafe path: path traversal with ..
        unsafe2 = FimTarget(
            id=str(uuid4()),
            target_code=f"FIM-UNSAFE2-{uuid4().hex[:6]}",
            relative_path="../sensitive-data/config.json",
            baseline_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        db.add(unsafe2)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
