"""Tests for M6.3 Alert Engine, Rule Matching, Deduplication, and Zero Trust PEP."""
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.database import SessionLocal, now_utc
from app.models.assets import Asset
from app.models.identity import User
from app.models.monitoring import Alert, AlertHistory, AlertRule, MonitoringEvent, MonitoringSource
from app.monitoring.engine import SEVERITY_ORDER, AlertEngine, severity_matches
from app.monitoring.types import AlertStatus, EventType, Severity, SourceType
from app.tests.conftest import login, ready_client

RULES_URL = "/api/v1/monitoring/rules"
ALERTS_URL = "/api/v1/monitoring/alerts"
EVENTS_URL = "/api/v1/monitoring/events"
SOURCES_URL = "/api/v1/monitoring/sources"


def auth_client(username: str = "admin.demo"):
    c = ready_client()
    resp = login(c, username)
    assert resp.status_code == 200
    c.headers["X-CSRF-Token"] = c.cookies.get("sgsi_csrf")
    return c


@pytest.fixture
def test_source_and_admin(client):
    admin = auth_client("admin.demo")
    code = f"SRC-ALERT-{uuid4().hex[:8]}"
    resp = admin.post(
        SOURCES_URL,
        json={
            "source_code": code,
            "name": "Alert Engine Test Source",
            "source_type": "HOST",
            "enabled": True,
        },
    )
    assert resp.status_code == 201
    return resp.json(), admin


# =========================================================================
# 1. Severity Ordering & Unit Rule Matching
# =========================================================================


def test_severity_ordering():
    assert SEVERITY_ORDER[Severity.INFO] < SEVERITY_ORDER[Severity.LOW]
    assert SEVERITY_ORDER[Severity.LOW] < SEVERITY_ORDER[Severity.MEDIUM]
    assert SEVERITY_ORDER[Severity.MEDIUM] < SEVERITY_ORDER[Severity.HIGH]
    assert SEVERITY_ORDER[Severity.HIGH] < SEVERITY_ORDER[Severity.CRITICAL]

    # minimum_severity = HIGH matches HIGH and CRITICAL, but NOT INFO, LOW, MEDIUM
    assert severity_matches(Severity.CRITICAL, Severity.HIGH) is True
    assert severity_matches(Severity.HIGH, Severity.HIGH) is True
    assert severity_matches(Severity.MEDIUM, Severity.HIGH) is False
    assert severity_matches(Severity.LOW, Severity.HIGH) is False
    assert severity_matches(Severity.INFO, Severity.HIGH) is False


def test_engine_rule_matching_and_severity_filter():
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin.demo"))
        source = MonitoringSource(
            source_code=f"SRC-UNIT-{uuid4().hex[:6]}",
            name="Unit Source",
            source_type=SourceType.HOST,
            enabled=True,
            key_hash="hash",
        )
        db.add(source)
        db.flush()

        rule_high = AlertRule(
            rule_code=f"RULE-UNIT-HIGH-{uuid4().hex[:6]}",
            name="Unit High Auth Failure",
            enabled=True,
            event_type=EventType.AUTH_FAILURE,
            minimum_severity=Severity.HIGH,
            cooldown_seconds=300,
            created_by=admin.id,
        )
        db.add(rule_high)
        db.flush()

        # Event with MEDIUM severity should NOT match rule_high
        med_event = MonitoringEvent(
            source_id=source.id,
            source_event_id=f"evt-{uuid4().hex[:8]}",
            event_type=EventType.AUTH_FAILURE,
            severity=Severity.MEDIUM,
            title="Med Auth Failure",
            message="Med fail",
            occurred_at=now_utc(),
            fingerprint=uuid4().hex,
        )
        db.add(med_event)
        db.flush()

        alerts = [a for a in AlertEngine.process_event(db, med_event) if a.rule_id == rule_high.id]
        assert len(alerts) == 0

        # Event with CRITICAL severity DOES match rule_high
        crit_event = MonitoringEvent(
            source_id=source.id,
            source_event_id=f"evt-{uuid4().hex[:8]}",
            event_type=EventType.AUTH_FAILURE,
            severity=Severity.CRITICAL,
            title="Crit Auth Failure",
            message="Crit fail",
            occurred_at=now_utc(),
            fingerprint=uuid4().hex,
        )
        db.add(crit_event)
        db.flush()

        alerts = [a for a in AlertEngine.process_event(db, crit_event) if a.rule_id == rule_high.id]
        assert len(alerts) == 1
        assert alerts[0].rule_id == rule_high.id
        assert alerts[0].status == AlertStatus.OPEN
        assert alerts[0].severity == Severity.CRITICAL


def test_engine_asset_criticality_filter():
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin.demo"))
        asset_crit = db.scalar(select(Asset).where(Asset.criticality == "CRITICAL"))
        asset_low = db.scalar(select(Asset).where(Asset.criticality == "LOW"))

        source = MonitoringSource(
            source_code=f"SRC-ASSET-{uuid4().hex[:6]}",
            name="Asset Source",
            source_type=SourceType.HOST,
            enabled=True,
            key_hash="hash",
        )
        db.add(source)
        db.flush()

        # Rule requires CRITICAL asset
        rule = AlertRule(
            rule_code=f"RULE-ASSET-CRIT-{uuid4().hex[:6]}",
            name="Critical Asset FIM",
            enabled=True,
            event_type=EventType.FILE_INTEGRITY_CHANGE,
            minimum_severity=Severity.LOW,
            asset_criticality="CRITICAL",
            cooldown_seconds=300,
            created_by=admin.id,
        )
        db.add(rule)
        db.flush()

        # Event on LOW asset -> NO alert
        if asset_low:
            event_low = MonitoringEvent(
                source_id=source.id,
                asset_id=asset_low.id,
                source_event_id=f"evt-{uuid4().hex[:8]}",
                event_type=EventType.FILE_INTEGRITY_CHANGE,
                severity=Severity.HIGH,
                title="Low Asset FIM",
                message="Change detected",
                occurred_at=now_utc(),
                fingerprint=uuid4().hex,
            )
            db.add(event_low)
            db.flush()
            low_alerts = [
                a for a in AlertEngine.process_event(db, event_low) if a.rule_id == rule.id
            ]
            assert len(low_alerts) == 0

        # Event without asset -> NO alert for rule requiring CRITICAL asset
        event_no_asset = MonitoringEvent(
            source_id=source.id,
            asset_id=None,
            source_event_id=f"evt-{uuid4().hex[:8]}",
            event_type=EventType.FILE_INTEGRITY_CHANGE,
            severity=Severity.HIGH,
            title="No Asset FIM",
            message="Change detected",
            occurred_at=now_utc(),
            fingerprint=uuid4().hex,
        )
        db.add(event_no_asset)
        db.flush()
        no_asset_alerts = [
            a for a in AlertEngine.process_event(db, event_no_asset) if a.rule_id == rule.id
        ]
        assert len(no_asset_alerts) == 0

        # Event on CRITICAL asset -> Alert created
        if asset_crit:
            event_crit = MonitoringEvent(
                source_id=source.id,
                asset_id=asset_crit.id,
                source_event_id=f"evt-{uuid4().hex[:8]}",
                event_type=EventType.FILE_INTEGRITY_CHANGE,
                severity=Severity.HIGH,
                title="Critical Asset FIM",
                message="Critical file changed",
                occurred_at=now_utc(),
                fingerprint=uuid4().hex,
            )
            db.add(event_crit)
            db.flush()
            crit_alerts = [
                a for a in AlertEngine.process_event(db, event_crit) if a.rule_id == rule.id
            ]
            assert len(crit_alerts) == 1
            assert crit_alerts[0].rule_id == rule.id


def test_disabled_rule_and_no_matching_rule_ignored():
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin.demo"))
        source = MonitoringSource(
            source_code=f"SRC-DIS-{uuid4().hex[:6]}",
            name="Disabled Rule Source",
            source_type=SourceType.HOST,
            enabled=True,
            key_hash="hash",
        )
        db.add(source)
        db.flush()

        disabled_rule = AlertRule(
            rule_code=f"RULE-DISABLED-{uuid4().hex[:6]}",
            name="Disabled Rule",
            enabled=False,
            event_type=EventType.SECURITY_CONFIGURATION_CHANGE,
            minimum_severity=Severity.LOW,
            cooldown_seconds=300,
            created_by=admin.id,
        )
        db.add(disabled_rule)
        db.flush()

        event = MonitoringEvent(
            source_id=source.id,
            source_event_id=f"evt-{uuid4().hex[:8]}",
            event_type=EventType.SECURITY_CONFIGURATION_CHANGE,
            severity=Severity.CRITICAL,
            title="Config changed",
            message="Disabled rule test",
            occurred_at=now_utc(),
            fingerprint=uuid4().hex,
        )
        db.add(event)
        db.flush()

        # Disabled rule must NOT create any alert
        assert len(AlertEngine.process_event(db, event)) == 0


# =========================================================================
# 2. End-to-End Ingestion, Deduplication, and Cooldown
# =========================================================================


def test_end_to_end_alert_creation_and_deduplication(client, test_source_and_admin):
    test_source, admin = test_source_and_admin
    rule_code = f"RULE-E2E-{uuid4().hex[:6]}"
    rule_resp = admin.post(
        RULES_URL,
        json={
            "rule_code": rule_code,
            "name": "E2E Dedup Test Rule",
            "enabled": True,
            "event_type": "AUTH_FAILURE",
            "minimum_severity": "MEDIUM",
            "cooldown_seconds": 60,
        },
    )
    assert rule_resp.status_code == 201
    rule_id = rule_resp.json()["id"]

    source_key = test_source["api_key"]
    ingest_client = ready_client()
    ingest_client.headers["X-Monitoring-Key"] = source_key

    t0 = datetime(2026, 10, 7, 10, 0, 0)

    # 1. First event -> creates alert OPEN
    evt1_resp = ingest_client.post(
        EVENTS_URL,
        json={
            "source_event_id": f"evt-1-{uuid4().hex[:6]}",
            "event_type": "AUTH_FAILURE",
            "severity": "HIGH",
            "title": "Failed login brute-force",
            "message": "Multiple bad passwords",
            "occurred_at": t0.isoformat() + "Z",
            "payload": {"ip": "10.0.0.99"},
        },
    )
    assert evt1_resp.status_code == 201

    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).where(Alert.rule_id == rule_id)).all()
        assert len(alerts) == 1
        a1 = alerts[0]
        assert a1.status == AlertStatus.OPEN
        assert a1.occurrence_count == 1
        assert a1.first_seen_at == t0
        assert a1.last_seen_at == t0

        # Check AlertHistory created
        hist = db.scalars(select(AlertHistory).where(AlertHistory.alert_id == a1.id)).all()
        assert len(hist) == 1
        assert hist[0].action == "ALERT_CREATED"

    # 2. Second compatible event arriving within cooldown (30 seconds later) -> deduplication
    t1 = t0 + timedelta(seconds=30)
    evt2_resp = ingest_client.post(
        EVENTS_URL,
        json={
            "source_event_id": f"evt-2-{uuid4().hex[:6]}",
            "event_type": "AUTH_FAILURE",
            "severity": "HIGH",
            "title": "Failed login brute-force",
            "message": "Multiple bad passwords",
            "occurred_at": t1.isoformat() + "Z",
            "payload": {"ip": "10.0.0.99"},
        },
    )
    assert evt2_resp.status_code == 201

    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).where(Alert.rule_id == rule_id)).all()
        # Still exactly 1 alert row!
        assert len(alerts) == 1
        a1 = alerts[0]
        assert a1.occurrence_count == 2
        assert a1.first_seen_at == t0
        assert a1.last_seen_at == t1

        # AlertHistory has ALERT_DEDUPLICATED appended
        hist = db.scalars(
            select(AlertHistory)
            .where(AlertHistory.alert_id == a1.id)
            .order_by(AlertHistory.created_at.asc())
        ).all()
        assert len(hist) == 2
        assert hist[1].action == "ALERT_DEDUPLICATED"

    # 3. Third event arriving outside cooldown (t0 + 120 seconds, cooldown is 60s) -> NEW alert
    t2 = t0 + timedelta(seconds=120)
    evt3_resp = ingest_client.post(
        EVENTS_URL,
        json={
            "source_event_id": f"evt-3-{uuid4().hex[:6]}",
            "event_type": "AUTH_FAILURE",
            "severity": "HIGH",
            "title": "Failed login brute-force",
            "message": "Multiple bad passwords",
            "occurred_at": t2.isoformat() + "Z",
            "payload": {"ip": "10.0.0.99"},
        },
    )
    assert evt3_resp.status_code == 201

    with SessionLocal() as db:
        alerts = db.scalars(
            select(Alert).where(Alert.rule_id == rule_id).order_by(Alert.first_seen_at.asc())
        ).all()
        # Now 2 alerts exist!
        assert len(alerts) == 2
        first_alert = alerts[0]
        second_alert = alerts[1]
        assert first_alert.occurrence_count == 2
        assert second_alert.occurrence_count == 1
        assert second_alert.first_seen_at == t2
        assert second_alert.status == AlertStatus.OPEN


def test_resolved_alert_never_reused(client, test_source_and_admin):
    test_source, admin = test_source_and_admin
    rule_code = f"RULE-RESOLVE-{uuid4().hex[:6]}"
    rule_resp = admin.post(
        RULES_URL,
        json={
            "rule_code": rule_code,
            "name": "Resolve Test Rule",
            "enabled": True,
            "event_type": "POLICY_DENY",
            "minimum_severity": "HIGH",
            "cooldown_seconds": 600,
        },
    )
    assert rule_resp.status_code == 201
    rule_id = rule_resp.json()["id"]

    source_key = test_source["api_key"]
    ingest = ready_client()
    ingest.headers["X-Monitoring-Key"] = source_key

    # Event 1 -> Alert OPEN
    ingest.post(
        EVENTS_URL,
        json={
            "source_event_id": f"evt-r1-{uuid4().hex[:6]}",
            "event_type": "POLICY_DENY",
            "severity": "HIGH",
            "title": "ZT Policy Denied",
            "message": "Blocked access",
            "occurred_at": now_utc().isoformat() + "Z",
            "payload": {},
        },
    )

    with SessionLocal() as db:
        alert = db.scalar(select(Alert).where(Alert.rule_id == rule_id))
        assert alert is not None
        # Mark alert as RESOLVED
        alert.status = AlertStatus.RESOLVED
        db.commit()

    # Event 2 arriving with same fingerprint inside cooldown window
    ingest.post(
        EVENTS_URL,
        json={
            "source_event_id": f"evt-r2-{uuid4().hex[:6]}",
            "event_type": "POLICY_DENY",
            "severity": "HIGH",
            "title": "ZT Policy Denied",
            "message": "Blocked access",
            "occurred_at": now_utc().isoformat() + "Z",
            "payload": {},
        },
    )

    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).where(Alert.rule_id == rule_id)).all()
        # Must NOT reopen resolved alert; must create a new OPEN alert!
        assert len(alerts) == 2
        resolved_alerts = [a for a in alerts if a.status == AlertStatus.RESOLVED]
        open_alerts = [a for a in alerts if a.status == AlertStatus.OPEN]
        assert len(resolved_alerts) == 1
        assert len(open_alerts) == 1


def test_multiple_matching_rules_create_multiple_alerts(client, test_source_and_admin):
    test_source, admin = test_source_and_admin
    code_a = f"RULE-MULTI-A-{uuid4().hex[:6]}"
    code_b = f"RULE-MULTI-B-{uuid4().hex[:6]}"

    admin.post(
        RULES_URL,
        json={
            "rule_code": code_a,
            "name": "Multi A",
            "enabled": True,
            "event_type": "RISK_CHANGE",
            "minimum_severity": "LOW",
            "cooldown_seconds": 300,
        },
    )
    admin.post(
        RULES_URL,
        json={
            "rule_code": code_b,
            "name": "Multi B",
            "enabled": True,
            "event_type": "RISK_CHANGE",
            "minimum_severity": "MEDIUM",
            "cooldown_seconds": 300,
        },
    )

    source_key = test_source["api_key"]
    ingest = ready_client()
    ingest.headers["X-Monitoring-Key"] = source_key

    # An event with HIGH severity matches BOTH rules!
    ingest.post(
        EVENTS_URL,
        json={
            "source_event_id": f"evt-multi-{uuid4().hex[:6]}",
            "event_type": "RISK_CHANGE",
            "severity": "HIGH",
            "title": "Risk score jumped",
            "message": "Risk elevated",
            "occurred_at": now_utc().isoformat() + "Z",
            "payload": {},
        },
    )

    with SessionLocal() as db:
        rule_a = db.scalar(select(AlertRule).where(AlertRule.rule_code == code_a))
        rule_b = db.scalar(select(AlertRule).where(AlertRule.rule_code == code_b))
        alert_a = db.scalar(select(Alert).where(Alert.rule_id == rule_a.id))
        alert_b = db.scalar(select(Alert).where(Alert.rule_id == rule_b.id))
        assert alert_a is not None
        assert alert_b is not None


# =========================================================================
# 3. Rule Management CRUD, Validation & Zero Trust PEP
# =========================================================================


def test_rule_crud_validation_and_zero_trust_pep(client):
    admin = auth_client("admin.demo")
    auditor = auth_client("auditor.demo")
    medico = auth_client("medico.demo")
    admision = auth_client("admision.demo")

    code = f"RULE-CRUD-{uuid4().hex[:6]}"

    # 1. Validation errors
    # Negative cooldown rejected
    bad_cooldown = admin.post(
        RULES_URL,
        json={
            "rule_code": code,
            "name": "Bad Cooldown",
            "event_type": "AUTH_FAILURE",
            "minimum_severity": "HIGH",
            "cooldown_seconds": -1,
        },
    )
    assert bad_cooldown.status_code == 422

    # Invalid severity rejected
    bad_sev = admin.post(
        RULES_URL,
        json={
            "rule_code": code,
            "name": "Bad Severity",
            "event_type": "AUTH_FAILURE",
            "minimum_severity": "UNKNOWN_SEV",
            "cooldown_seconds": 60,
        },
    )
    assert bad_sev.status_code == 422

    # 2. Admin creates rule
    create_resp = admin.post(
        RULES_URL,
        json={
            "rule_code": code,
            "name": "CRUD Rule Test",
            "description": "Rule for testing CRUD",
            "enabled": True,
            "event_type": "AUTH_FAILURE",
            "minimum_severity": "HIGH",
            "asset_criticality": "HIGH",
            "cooldown_seconds": 120,
        },
    )
    assert create_resp.status_code == 201
    rule_data = create_resp.json()
    assert rule_data["rule_code"] == code
    rule_id = rule_data["id"]

    # Duplicate rule_code rejected with 409
    dup_resp = admin.post(
        RULES_URL,
        json={
            "rule_code": code,
            "name": "Duplicate Code",
            "event_type": "AUTH_FAILURE",
            "minimum_severity": "HIGH",
        },
    )
    assert dup_resp.status_code == 409

    # 3. Auditor can read rules
    audit_list = auditor.get(RULES_URL)
    assert audit_list.status_code == 200
    assert any(r["id"] == rule_id for r in audit_list.json())

    audit_get = auditor.get(f"{RULES_URL}/{rule_id}")
    assert audit_get.status_code == 200
    assert audit_get.json()["rule_code"] == code

    # Auditor CANNOT create or update
    assert (
        auditor.post(
            RULES_URL,
            json={
                "rule_code": "R-AUD",
                "name": "Aud",
                "event_type": "AUTH_FAILURE",
                "minimum_severity": "LOW",
            },
        ).status_code
        == 403
    )
    assert auditor.patch(f"{RULES_URL}/{rule_id}", json={"name": "Hacked"}).status_code == 403

    # Clinical roles (medico, admision) CANNOT read or update rules
    assert medico.get(RULES_URL).status_code == 403
    assert medico.get(f"{RULES_URL}/{rule_id}").status_code == 403
    assert admision.get(RULES_URL).status_code == 403

    # 4. Admin updates and logically disables rule
    patch_resp = admin.patch(
        f"{RULES_URL}/{rule_id}",
        json={"name": "Updated CRUD Rule", "enabled": False},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["name"] == "Updated CRUD Rule"
    assert patch_resp.json()["enabled"] is False


# =========================================================================
# 4. Alerts Read API, Filters, and Zero Trust PEP
# =========================================================================


def test_alerts_read_api_filters_and_rbac(client):
    admin = auth_client("admin.demo")
    auditor = auth_client("auditor.demo")
    medico = auth_client("medico.demo")

    # Clinical roles cannot read alerts
    assert medico.get(ALERTS_URL).status_code == 403

    # Auditor and Admin can read alerts
    admin_list = admin.get(ALERTS_URL)
    assert admin_list.status_code == 200
    page_data = admin_list.json()
    assert "items" in page_data
    assert "total" in page_data
    assert "page" in page_data
    assert "page_size" in page_data

    audit_list = auditor.get(ALERTS_URL)
    assert audit_list.status_code == 200

    # Filters and sorting allowlist
    filter_resp = admin.get(
        f"{ALERTS_URL}?status=OPEN&severity=HIGH&page=1&page_size=10&sort_by=created_at&sort_desc=true"
    )
    assert filter_resp.status_code == 200

    # Invalid sort column rejected
    bad_sort = admin.get(f"{ALERTS_URL}?sort_by=invalid_column")
    assert bad_sort.status_code == 422

    # Invalid page rejected
    bad_page = admin.get(f"{ALERTS_URL}?page=0")
    assert bad_page.status_code == 422

    # Metrics endpoint
    metrics_resp = admin.get("/api/v1/monitoring/metrics/alerts")
    assert metrics_resp.status_code == 200
    metrics_data = metrics_resp.json()
    assert "alerts_open" in metrics_data
    assert "critical_open" in metrics_data
    assert "alerts_by_severity" in metrics_data


def test_rapid_fire_events_single_alert_deduplication(client, test_source_and_admin):
    test_source, admin = test_source_and_admin
    rule_code = f"RULE-RAPID-{uuid4().hex[:6]}"
    rule_resp = admin.post(
        RULES_URL,
        json={
            "rule_code": rule_code,
            "name": "Rapid Fire Rule",
            "enabled": True,
            "event_type": "AUTH_FAILURE",
            "minimum_severity": "MEDIUM",
            "cooldown_seconds": 60,
        },
    )
    assert rule_resp.status_code == 201
    rule_id = rule_resp.json()["id"]

    source_key = test_source["api_key"]
    ingest = ready_client()
    ingest.headers["X-Monitoring-Key"] = source_key

    now = now_utc()
    # Ingest 5 events within 5 seconds with identical title/message (same event fingerprint)
    for i in range(5):
        resp = ingest.post(
            EVENTS_URL,
            json={
                "source_event_id": f"evt-rapid-{i}-{uuid4().hex[:6]}",
                "event_type": "AUTH_FAILURE",
                "severity": "HIGH",
                "title": "Rapid Brute Force Attempt",
                "message": "Repeated failed login from same IP",
                "occurred_at": (now + timedelta(seconds=i)).isoformat() + "Z",
                "payload": {"ip": "192.168.1.100"},
            },
        )
        assert resp.status_code == 201

    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).where(Alert.rule_id == rule_id)).all()
        # Exactly 1 alert row with occurrence_count == 5
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 5
        assert alerts[0].status == AlertStatus.OPEN
