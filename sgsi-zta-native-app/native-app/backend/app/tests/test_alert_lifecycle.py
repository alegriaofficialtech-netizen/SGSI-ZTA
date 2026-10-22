"""Tests for M6.4 Alert Lifecycle, Transitions, History, RBAC/PEP, and Metrics."""
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.database import SessionLocal, now_utc
from app.models.identity import AuditLog
from app.models.monitoring import Alert, AlertHistory, MonitoringEvent
from app.monitoring.types import AlertStatus
from app.tests.conftest import login, ready_client

ALERTS_URL = "/api/v1/monitoring/alerts"
EVENTS_URL = "/api/v1/monitoring/events"
SOURCES_URL = "/api/v1/monitoring/sources"
METRICS_URL = "/api/v1/monitoring/metrics/alerts"


def auth_client(username: str = "admin.demo"):
    c = ready_client()
    resp = login(c, username)
    assert resp.status_code == 200
    c.headers["X-CSRF-Token"] = c.cookies.get("sgsi_csrf")
    return c


@pytest.fixture
def test_setup():
    admin = auth_client("admin.demo")
    auditor = auth_client("auditor.demo")
    medico = auth_client("medico.demo")
    admision = auth_client("admision.demo")

    # Create source
    code = f"SRC-LC-{uuid4().hex[:8]}"
    resp = admin.post(
        SOURCES_URL,
        json={
            "source_code": code,
            "name": "Lifecycle Test Source",
            "source_type": "HOST",
            "enabled": True,
        },
    )
    assert resp.status_code == 201
    source_data = resp.json()

    # Create dedicated rule for lifecycle testing
    rule_code = f"RULE-LC-{uuid4().hex[:6]}"
    rule_resp = admin.post(
        "/api/v1/monitoring/rules",
        json={
            "rule_code": rule_code,
            "name": "Lifecycle Rule",
            "enabled": True,
            "event_type": "SECURITY_CONFIGURATION_CHANGE",
            "minimum_severity": "MEDIUM",
            "cooldown_seconds": 300,
        },
    )
    assert rule_resp.status_code == 201
    rule_data = rule_resp.json()

    return {
        "admin": admin,
        "auditor": auditor,
        "medico": medico,
        "admision": admision,
        "source": source_data,
        "rule": rule_data,
    }


def create_test_alert(setup, severity="HIGH", title="Config Modified"):
    source_key = setup["source"]["api_key"]
    ingest = ready_client()
    ingest.headers["X-Monitoring-Key"] = source_key
    evt_id = f"evt-lc-{uuid4().hex[:8]}"
    resp = ingest.post(
        EVENTS_URL,
        json={
            "source_event_id": evt_id,
            "event_type": "SECURITY_CONFIGURATION_CHANGE",
            "severity": severity,
            "title": title,
            "message": "Sensitive security configuration altered",
            "occurred_at": now_utc().isoformat() + "Z",
            "payload": {"setting": "firewall_disabled"},
        },
    )
    assert resp.status_code == 201
    rule_id = setup["rule"]["id"]

    with SessionLocal() as db:
        alert = db.scalar(
            select(Alert).where(Alert.rule_id == rule_id).order_by(Alert.created_at.desc())
        )
        assert alert is not None
        return alert.id


# =========================================================================
# 1. Acknowledge Alert (OPEN -> ACKNOWLEDGED)
# =========================================================================


def test_acknowledge_alert_success(client, test_setup):
    admin = test_setup["admin"]
    alert_id = create_test_alert(test_setup)

    # 1. Acknowledge with comment
    ack_resp = admin.post(
        f"{ALERTS_URL}/{alert_id}/acknowledge",
        json={"comment": "Investigating potential unauthorized change."},
    )
    assert ack_resp.status_code == 200
    data = ack_resp.json()
    assert data["status"] == AlertStatus.ACKNOWLEDGED.value
    assert data["acknowledged_at"] is not None
    assert data["acknowledged_by"] is not None
    assert len(data["history"]) >= 2  # ALERT_CREATED + ALERT_ACKNOWLEDGED

    # Check database state
    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.acknowledged_by == alert.history[-1].actor_user_id

        # Check AlertHistory record
        hist = db.scalars(
            select(AlertHistory)
            .where(AlertHistory.alert_id == alert_id)
            .order_by(AlertHistory.created_at.asc())
        ).all()
        assert len(hist) == 2
        assert hist[0].action == "ALERT_CREATED"
        assert hist[1].action == "ALERT_ACKNOWLEDGED"
        assert hist[1].previous_status == AlertStatus.OPEN
        assert hist[1].new_status == AlertStatus.ACKNOWLEDGED
        assert hist[1].comment == "Investigating potential unauthorized change."

        # Check AuditLog record
        audit_row = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.action == "ALERT_ACKNOWLEDGED",
                AuditLog.resource == f"alert:{alert_id}",
            )
            .order_by(AuditLog.timestamp.desc())
        )
        assert audit_row is not None
        assert audit_row.decision == "ALLOW"
        assert audit_row.user_id == alert.acknowledged_by

    # Check dedicated /history endpoint
    hist_resp = admin.get(f"{ALERTS_URL}/{alert_id}/history")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert len(hist_data) == 2
    assert hist_data[1]["action"] == "ALERT_ACKNOWLEDGED"


# =========================================================================
# 2. Resolve Alert (OPEN -> RESOLVED and ACKNOWLEDGED -> RESOLVED)
# =========================================================================


def test_resolve_from_open_directly(client, test_setup):
    admin = test_setup["admin"]
    alert_id = create_test_alert(test_setup)

    # Direct resolution from OPEN
    res_resp = admin.post(
        f"{ALERTS_URL}/{alert_id}/resolve",
        json={"comment": "Resolved directly as authorized maintenance."},
    )
    assert res_resp.status_code == 200
    data = res_resp.json()
    assert data["status"] == AlertStatus.RESOLVED.value
    assert data["resolved_at"] is not None
    assert data["resolved_by"] is not None

    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_by is not None
        hist = db.scalars(
            select(AlertHistory)
            .where(AlertHistory.alert_id == alert_id)
            .order_by(AlertHistory.created_at.asc())
        ).all()
        assert len(hist) == 2
        assert hist[1].action == "ALERT_RESOLVED"
        assert hist[1].previous_status == AlertStatus.OPEN
        assert hist[1].new_status == AlertStatus.RESOLVED


def test_resolve_from_acknowledged(client, test_setup):
    admin = test_setup["admin"]
    alert_id = create_test_alert(test_setup)

    # 1. Acknowledge
    ack_resp = admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge", json={})
    assert ack_resp.status_code == 200

    # 2. Resolve
    res_resp = admin.post(
        f"{ALERTS_URL}/{alert_id}/resolve",
        json={"comment": "Remediation verified and patch applied."},
    )
    assert res_resp.status_code == 200
    data = res_resp.json()
    assert data["status"] == AlertStatus.RESOLVED.value
    assert data["acknowledged_at"] is not None
    assert data["resolved_at"] is not None

    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        assert alert.status == AlertStatus.RESOLVED
        hist = db.scalars(
            select(AlertHistory)
            .where(AlertHistory.alert_id == alert_id)
            .order_by(AlertHistory.created_at.asc())
        ).all()
        assert len(hist) == 3
        assert hist[0].action == "ALERT_CREATED"
        assert hist[1].action == "ALERT_ACKNOWLEDGED"
        assert hist[2].action == "ALERT_RESOLVED"
        assert hist[2].previous_status == AlertStatus.ACKNOWLEDGED
        assert hist[2].new_status == AlertStatus.RESOLVED


# =========================================================================
# 3. Block Invalid State Transitions
# =========================================================================


def test_invalid_transitions_blocked(client, test_setup):
    admin = test_setup["admin"]
    alert_id = create_test_alert(test_setup)

    # 1. Acknowledge once -> OK
    assert admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge").status_code == 200

    # 2. Acknowledge again while already ACKNOWLEDGED -> 400 Bad Request
    dup_ack = admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge")
    assert dup_ack.status_code == 400
    assert "ACKNOWLEDGED" in dup_ack.json()["detail"]

    # 3. Resolve alert -> OK
    assert admin.post(f"{ALERTS_URL}/{alert_id}/resolve").status_code == 200

    # 4. Acknowledge resolved alert -> 400 Bad Request
    ack_res = admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge")
    assert ack_res.status_code == 400
    assert "RESOLVED" in ack_res.json()["detail"]

    # 5. Resolve already RESOLVED alert -> 400 Bad Request
    dup_res = admin.post(f"{ALERTS_URL}/{alert_id}/resolve")
    assert dup_res.status_code == 400
    assert "RESOLVED" in dup_res.json()["detail"]

    # Ensure no extra history rows were created during failed transition attempts
    with SessionLocal() as db:
        hist = db.scalars(
            select(AlertHistory).where(AlertHistory.alert_id == alert_id)
        ).all()
        # Exactly 3: CREATED, ACKNOWLEDGED, RESOLVED
        assert len(hist) == 3


# =========================================================================
# 4. Actor Derived from Session (No Spoofing Allowed)
# =========================================================================


def test_actor_strictly_derived_from_session(client, test_setup):
    admin = test_setup["admin"]
    alert_id = create_test_alert(test_setup)

    # Attempting to supply client-controlled actor_user_id rejected by extra="forbid"
    spoofed = admin.post(
        f"{ALERTS_URL}/{alert_id}/acknowledge",
        json={"actor_user_id": 999, "comment": "Trying to spoof actor"},
    )
    assert spoofed.status_code == 422

    # Normal acknowledge uses actual session actor
    ack = admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge", json={"comment": "Valid"})
    assert ack.status_code == 200
    ack_data = ack.json()

    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        # Actor is the authenticated admin, not arbitrary value
        assert alert.acknowledged_by == ack_data["acknowledged_by"]
        assert alert.history[-1].actor_user_id == alert.acknowledged_by


# =========================================================================
# 5. Zero Trust RBAC / PEP on Alert Lifecycle
# =========================================================================


def test_zero_trust_rbac_on_alert_lifecycle(client, test_setup):
    admin = test_setup["admin"]
    auditor = test_setup["auditor"]
    medico = test_setup["medico"]
    admision = test_setup["admision"]
    alert_id = create_test_alert(test_setup)

    # 1. Auditor can read alert and history
    assert auditor.get(f"{ALERTS_URL}/{alert_id}").status_code == 200
    assert auditor.get(f"{ALERTS_URL}/{alert_id}/history").status_code == 200

    # 2. Auditor CANNOT acknowledge or resolve (403 Forbidden)
    assert auditor.post(f"{ALERTS_URL}/{alert_id}/acknowledge").status_code == 403
    assert auditor.post(f"{ALERTS_URL}/{alert_id}/resolve").status_code == 403

    # 3. Clinical roles CANNOT read, acknowledge, or resolve (403 Forbidden)
    assert medico.get(f"{ALERTS_URL}/{alert_id}").status_code == 403
    assert medico.post(f"{ALERTS_URL}/{alert_id}/acknowledge").status_code == 403
    assert medico.post(f"{ALERTS_URL}/{alert_id}/resolve").status_code == 403

    assert admision.get(f"{ALERTS_URL}/{alert_id}").status_code == 403
    assert admision.post(f"{ALERTS_URL}/{alert_id}/acknowledge").status_code == 403
    assert admision.post(f"{ALERTS_URL}/{alert_id}/resolve").status_code == 403

    # 4. Admin can acknowledge and resolve (200 OK)
    assert admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge").status_code == 200
    assert admin.post(f"{ALERTS_URL}/{alert_id}/resolve").status_code == 200


# =========================================================================
# 6. Interaction: Deduplication + Lifecycle
# =========================================================================


def test_deduplication_interaction_with_lifecycle(client, test_setup):
    admin = test_setup["admin"]
    source_key = test_setup["source"]["api_key"]
    rule_id = test_setup["rule"]["id"]

    ingest = ready_client()
    ingest.headers["X-Monitoring-Key"] = source_key

    # Event payload base
    base_payload = {
        "event_type": "SECURITY_CONFIGURATION_CHANGE",
        "severity": "HIGH",
        "title": "Dedup Lifecycle Test",
        "message": "Testing dedup across states",
        "payload": {"param": "val"},
    }

    t0 = datetime(2026, 10, 7, 12, 0, 0)

    # 1. Event 1 -> Alert OPEN created
    e1 = ingest.post(
        EVENTS_URL,
        json={
            **base_payload,
            "source_event_id": f"evt-dl-1-{uuid4().hex[:6]}",
            "occurred_at": t0.isoformat() + "Z",
        },
    )
    assert e1.status_code == 201

    with SessionLocal() as db:
        alert = db.scalar(select(Alert).where(Alert.rule_id == rule_id))
        assert alert.status == AlertStatus.OPEN
        assert alert.occurrence_count == 1
        alert_id = alert.id

    # 2. Event 2 arriving within cooldown -> deduplicates into OPEN alert
    e2 = ingest.post(
        EVENTS_URL,
        json={
            **base_payload,
            "source_event_id": f"evt-dl-2-{uuid4().hex[:6]}",
            "occurred_at": (t0 + timedelta(seconds=20)).isoformat() + "Z",
        },
    )
    assert e2.status_code == 201

    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        assert alert.status == AlertStatus.OPEN
        assert alert.occurrence_count == 2

    # 3. Transition alert to ACKNOWLEDGED
    assert admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge").status_code == 200

    # 4. Event 3 arriving within cooldown -> deduplicates into ACKNOWLEDGED alert
    e3 = ingest.post(
        EVENTS_URL,
        json={
            **base_payload,
            "source_event_id": f"evt-dl-3-{uuid4().hex[:6]}",
            "occurred_at": (t0 + timedelta(seconds=40)).isoformat() + "Z",
        },
    )
    assert e3.status_code == 201

    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        # Still the same alert, occurrence count incremented, status remains ACKNOWLEDGED
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.occurrence_count == 3
        # History has ALERT_DEDUPLICATED appended
        assert alert.history[-1].action == "ALERT_DEDUPLICATED"

    # 5. Transition alert to RESOLVED
    assert admin.post(f"{ALERTS_URL}/{alert_id}/resolve").status_code == 200

    # 6. Event 4 arriving with same fingerprint -> MUST NOT deduplicate into RESOLVED alert!
    e4 = ingest.post(
        EVENTS_URL,
        json={
            **base_payload,
            "source_event_id": f"evt-dl-4-{uuid4().hex[:6]}",
            "occurred_at": (t0 + timedelta(seconds=60)).isoformat() + "Z",
        },
    )
    assert e4.status_code == 201

    with SessionLocal() as db:
        all_alerts = db.scalars(
            select(Alert).where(Alert.rule_id == rule_id).order_by(Alert.first_seen_at.asc())
        ).all()
        # Exactly 2 alert rows now exist:
        # First one is RESOLVED with occurrence_count == 3
        # Second one is a brand new OPEN alert with occurrence_count == 1
        assert len(all_alerts) == 2
        assert all_alerts[0].status == AlertStatus.RESOLVED
        assert all_alerts[0].occurrence_count == 3
        assert all_alerts[1].status == AlertStatus.OPEN
        assert all_alerts[1].occurrence_count == 1


# =========================================================================
# 7. Metrics by Status
# =========================================================================


def test_metrics_alerts_by_status(client, test_setup):
    admin = test_setup["admin"]

    # Retrieve current metrics
    m_resp = admin.get(METRICS_URL)
    assert m_resp.status_code == 200
    data = m_resp.json()
    assert "alerts_open" in data
    assert "critical_open" in data
    assert "alerts_by_severity" in data
    assert "alerts_by_status" in data
    status_counts = data["alerts_by_status"]
    assert "OPEN" in status_counts
    assert "ACKNOWLEDGED" in status_counts
    assert "RESOLVED" in status_counts


# =========================================================================
# 8. No Recursion between Alert Actions and Event Ingestion
# =========================================================================


def test_no_recursion_between_alert_actions_and_monitoring_events(client, test_setup):
    admin = test_setup["admin"]
    alert_id = create_test_alert(test_setup)

    with SessionLocal() as db:
        events_before = db.scalar(select(func.count(MonitoringEvent.id)))
        audit_before = db.scalar(select(func.count(AuditLog.id)))

    # Acknowledge and resolve emit AuditLog, but NEVER MonitoringEvent
    admin.post(f"{ALERTS_URL}/{alert_id}/acknowledge")
    admin.post(f"{ALERTS_URL}/{alert_id}/resolve")

    with SessionLocal() as db:
        events_after = db.scalar(select(func.count(MonitoringEvent.id)))
        audit_after = db.scalar(select(func.count(AuditLog.id)))

        # Monitoring events count did NOT change
        assert events_after == events_before
        # Audit log count increased by at least 2
        assert audit_after >= audit_before + 2


def test_monitoring_events_read_and_dashboard_metrics(client, test_setup):
    admin = test_setup["admin"]
    auditor = test_setup["auditor"]
    medico = test_setup["medico"]

    source_key = test_setup["source"]["api_key"]
    source_code = test_setup["source"]["source_code"]
    evt_id = f"evt-read-{uuid4().hex[:8]}"
    ingest_resp = client.post(
        EVENTS_URL,
        headers={"X-Monitoring-Key": source_key, "X-Monitoring-Source": source_code},
        json={
            "source_event_id": evt_id,
            "event_type": "SECURITY_CONFIGURATION_CHANGE",
            "severity": "HIGH",
            "title": "Config updated test",
            "message": "Testing event read APIs",
            "occurred_at": now_utc().isoformat(),
            "payload": {"param": "value", "secret_token": "hidden"},
        },
    )
    assert ingest_resp.status_code == 201
    created_evt = ingest_resp.json()

    # List events as admin
    list_resp = admin.get(EVENTS_URL)
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert "items" in list_data
    assert list_data["total"] >= 1
    found = any(it["id"] == created_evt["id"] for it in list_data["items"])
    assert found

    # Get event detail as auditor
    detail_resp = auditor.get(f"{EVENTS_URL}/{created_evt['id']}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["id"] == created_evt["id"]
    assert detail_data["payload"]["secret_token"] == "[REDACTED]"
    assert detail_data["payload"]["param"] == "value"

    # Clinical role denied on read
    medico_resp = medico.get(EVENTS_URL)
    assert medico_resp.status_code == 403

    # Dashboard metrics endpoint
    dash_resp = admin.get("/api/v1/monitoring/metrics/dashboard")
    assert dash_resp.status_code == 200
    d_data = dash_resp.json()
    assert "events_24h" in d_data
    assert "alerts_open" in d_data
    assert "events_by_hour" in d_data
    assert "alerts_by_severity" in d_data
    assert "events_by_type" in d_data
    assert "top_affected_assets" in d_data

