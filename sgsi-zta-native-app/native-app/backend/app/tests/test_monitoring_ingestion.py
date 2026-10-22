from uuid import uuid4

from sqlalchemy import select

from app.database import SessionLocal, now_utc
from app.models.monitoring import MonitoringEvent, MonitoringSource
from app.monitoring.security import REDACTED
from app.tests.conftest import login, ready_client

SOURCES_URL = "/api/v1/monitoring/sources"
EVENTS_URL = "/api/v1/monitoring/events"


def auth_client(client, username="admin.demo"):
    c = ready_client()
    resp = login(c, username)
    assert resp.status_code == 200
    c.headers["X-CSRF-Token"] = c.cookies.get("sgsi_csrf")
    return c


# =========================================================================
# 1. Source Management & RBAC Tests
# =========================================================================


def test_source_crud_rbac_and_zero_trust_pep(client):
    # admin-ti can create source
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={
            "source_code": "SRC-TEST-01",
            "name": "Host Agent Test",
            "source_type": "HOST",
            "enabled": True,
        },
    )
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["source_code"] == "SRC-TEST-01"
    assert "api_key" in created_data
    assert created_data["api_key"].startswith("mon_SRC-TEST-01.")
    assert "key_hash" not in created_data
    source_id = created_data["id"]

    # auditor can read sources
    auditor = auth_client(client, "auditor.demo")
    list_resp = auditor.get(SOURCES_URL)
    assert list_resp.status_code == 200
    sources = list_resp.json()
    assert any(s["id"] == source_id for s in sources)
    # Key never returned twice or in list
    assert all("api_key" not in s and "key_hash" not in s for s in sources)

    # auditor CANNOT create or patch or rotate
    auditor_create = auditor.post(
        SOURCES_URL,
        json={
            "source_code": "SRC-AUD-DENY",
            "name": "Auditor Attempt",
            "source_type": "APPLICATION",
        },
    )
    assert auditor_create.status_code == 403

    auditor_patch = auditor.patch(f"{SOURCES_URL}/{source_id}", json={"name": "Hacked"})
    assert auditor_patch.status_code == 403

    auditor_rotate = auditor.post(f"{SOURCES_URL}/{source_id}/rotate-key")
    assert auditor_rotate.status_code == 403

    # Clinical roles (medico, admision) CANNOT read or write
    medico = auth_client(client, "medico.demo")
    assert medico.get(SOURCES_URL).status_code == 403
    assert (
        medico.post(
            SOURCES_URL,
            json={"source_code": "SRC-MED", "name": "Med", "source_type": "HOST"},
        ).status_code
        == 403
    )

    admision = auth_client(client, "admision.demo")
    assert admision.get(SOURCES_URL).status_code == 403

    # admin-ti can patch
    patch_resp = admin.patch(f"{SOURCES_URL}/{source_id}", json={"name": "Updated Host Agent"})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["name"] == "Updated Host Agent"
    assert "api_key" not in patch_resp.json()
    assert "key_hash" not in patch_resp.json()


def test_key_rotation_invalidates_old_key_and_authorizes_new(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={
            "source_code": "SRC-ROT-01",
            "name": "Rotation Source",
            "source_type": "HOST",
        },
    )
    assert create_resp.status_code == 201
    source_id = create_resp.json()["id"]
    old_key = create_resp.json()["api_key"]

    # Old key works for ingestion
    event_payload = {
        "source_event_id": f"evt-{uuid4()}",
        "event_type": "AUTH_SUCCESS",
        "severity": "INFO",
        "title": "Agent Login",
        "message": "User logged in",
        "occurred_at": now_utc().isoformat(),
    }
    r1 = client.post(EVENTS_URL, headers={"X-Monitoring-Key": old_key}, json=event_payload)
    assert r1.status_code == 201

    # Rotate key
    rotate_resp = admin.post(f"{SOURCES_URL}/{source_id}/rotate-key")
    assert rotate_resp.status_code == 200
    new_key = rotate_resp.json()["api_key"]
    assert new_key != old_key
    assert "key_hash" not in rotate_resp.json()

    # Old key is now INVALID
    event_payload_2 = {
        "source_event_id": f"evt-{uuid4()}",
        "event_type": "AUTH_SUCCESS",
        "severity": "INFO",
        "title": "Agent Login 2",
        "message": "User logged in again",
        "occurred_at": now_utc().isoformat(),
    }
    r2 = client.post(EVENTS_URL, headers={"X-Monitoring-Key": old_key}, json=event_payload_2)
    assert r2.status_code == 401

    # New key is VALID
    r3 = client.post(EVENTS_URL, headers={"X-Monitoring-Key": new_key}, json=event_payload_2)
    assert r3.status_code == 201


# =========================================================================
# 2. Ingestion Authentication & Security Tests
# =========================================================================


def test_ingestion_auth_missing_or_invalid_key(client):
    event_payload = {
        "source_event_id": f"evt-{uuid4()}",
        "event_type": "SECURITY_CONFIGURATION_CHANGE",
        "severity": "MEDIUM",
        "title": "Config Changed",
        "message": "Config modified",
        "occurred_at": now_utc().isoformat(),
    }
    # 1. Missing key
    r_missing = client.post(EVENTS_URL, json=event_payload)
    assert r_missing.status_code == 401

    # 2. Invalid format
    r_bad_fmt = client.post(
        EVENTS_URL, headers={"X-Monitoring-Key": "invalid-format"}, json=event_payload
    )
    assert r_bad_fmt.status_code == 401

    # 3. Nonexistent source
    r_nonexistent = client.post(
        EVENTS_URL,
        headers={"X-Monitoring-Key": "mon_NONEXISTENT.someSecretToken1234567890"},
        json=event_payload,
    )
    assert r_nonexistent.status_code == 401

    # 4. Wrong secret for existing source
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-AUTH-01", "name": "Auth Test", "source_type": "APPLICATION"},
    )
    assert create_resp.status_code == 201

    r_wrong_secret = client.post(
        EVENTS_URL,
        headers={"X-Monitoring-Key": "mon_SRC-AUTH-01.wrongSecretToken99999999"},
        json=event_payload,
    )
    assert r_wrong_secret.status_code == 401


def test_disabled_source_ingestion_rejected(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={
            "source_code": "SRC-DIS-01",
            "name": "Disabled Source",
            "source_type": "APPLICATION",
            "enabled": True,
        },
    )
    source_id = create_resp.json()["id"]
    api_key = create_resp.json()["api_key"]

    # Disable source
    admin.patch(f"{SOURCES_URL}/{source_id}", json={"enabled": False})

    event_payload = {
        "source_event_id": f"evt-{uuid4()}",
        "event_type": "AUTH_FAILURE",
        "severity": "HIGH",
        "title": "Failed auth",
        "message": "Bad password attempt",
        "occurred_at": now_utc().isoformat(),
    }
    r = client.post(EVENTS_URL, headers={"X-Monitoring-Key": api_key}, json=event_payload)
    assert r.status_code == 403
    assert "disabled" in r.json()["detail"].lower()


# =========================================================================
# 3. Idempotency & Persistence Tests
# =========================================================================


def test_event_ingestion_and_idempotency(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-IDEMP-01", "name": "Idemp Source", "source_type": "HOST"},
    )
    api_key = create_resp.json()["api_key"]
    source_id = create_resp.json()["id"]

    source_event_id = f"evt-uniq-{uuid4()}"
    event_payload = {
        "source_event_id": source_event_id,
        "event_type": "FILE_INTEGRITY_CHANGE",
        "severity": "CRITICAL",
        "title": "Integrity Alert /etc/shadow",
        "message": "File modified unexpectedly",
        "occurred_at": now_utc().isoformat(),
        "payload": {"file": "/etc/shadow", "hash": "abc123def456"},
    }

    # First ingestion -> 201 Created
    r1 = client.post(EVENTS_URL, headers={"X-Monitoring-Key": api_key}, json=event_payload)
    assert r1.status_code == 201
    d1 = r1.json()
    assert d1["idempotent_replay"] is False
    assert d1["source_id"] == source_id
    assert d1["source_event_id"] == source_event_id
    assert len(d1["fingerprint"]) == 64

    # Second ingestion with same source_event_id -> 200 OK idempotent replay
    r2 = client.post(EVENTS_URL, headers={"X-Monitoring-Key": api_key}, json=event_payload)
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["idempotent_replay"] is True
    assert d2["id"] == d1["id"]

    # Verify database has exactly ONE row
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(MonitoringEvent).where(
                    MonitoringEvent.source_id == source_id,
                    MonitoringEvent.source_event_id == source_event_id,
                )
            )
        )
        assert len(rows) == 1

        # Check source.last_seen_at was updated
        source = db.get(MonitoringSource, source_id)
        assert source.last_seen_at is not None


# =========================================================================
# 4. Sanitization & Secret Redaction Tests
# =========================================================================


def test_recursive_payload_sanitization(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-SAN-01", "name": "Sanitize Source", "source_type": "APPLICATION"},
    )
    api_key = create_resp.json()["api_key"]

    source_event_id = f"evt-san-{uuid4()}"
    event_payload = {
        "source_event_id": source_event_id,
        "event_type": "AUTH_FAILURE",
        "severity": "HIGH",
        "title": "Login Failed",
        "message": "Invalid password supplied",
        "occurred_at": now_utc().isoformat(),
        "payload": {
            "username": "admin",
            "password": "SuperSecretPassword123!",
            "nested": {
                "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
                "refresh_token": "rt-12345",
                "public_info": "safe_data",
                "headers": {
                    "authorization": "Bearer secret_token_xyz",
                    "cookie": "session=secret_cookie_val",
                },
            },
            "array_data": [
                {"api_key": "sk_live_123456", "item": "item1"},
                {"totp": "123456", "recovery_code": "rec-999"},
            ],
        },
    }

    r = client.post(EVENTS_URL, headers={"X-Monitoring-Key": api_key}, json=event_payload)
    assert r.status_code == 201

    with SessionLocal() as db:
        event = db.scalar(
            select(MonitoringEvent).where(MonitoringEvent.source_event_id == source_event_id)
        )
        assert event is not None
        payload = event.payload_json

        # Verify top-level secrets redacted
        assert payload["password"] == REDACTED
        assert payload["username"] == "admin"

        # Verify nested secrets redacted
        assert payload["nested"]["jwt"] == REDACTED
        assert payload["nested"]["refresh_token"] == REDACTED
        assert payload["nested"]["public_info"] == "safe_data"
        assert payload["nested"]["headers"]["authorization"] == REDACTED
        assert payload["nested"]["headers"]["cookie"] == REDACTED

        # Verify array secrets redacted
        assert payload["array_data"][0]["api_key"] == REDACTED
        assert payload["array_data"][0]["item"] == "item1"
        assert payload["array_data"][1]["totp"] == REDACTED
        assert payload["array_data"][1]["recovery_code"] == REDACTED


# =========================================================================
# 5. Schema Validation & Anti-Spoofing Tests
# =========================================================================


def test_extra_fields_and_role_spoofing_rejected(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-SPOOF-01", "name": "Spoof Source", "source_type": "HOST"},
    )
    api_key = create_resp.json()["api_key"]

    spoof_attempts = [
        {"role": "admin-ti"},
        {"roles": ["admin-ti"]},
        {"user_id": 1},
        {"mfa_verified": True},
        {"risk_score": 0},
        {"risk_level": "LOW"},
        {"device_trust": "TRUSTED"},
        {"source_id": str(uuid4())},
        {"created_at": now_utc().isoformat()},
        {"received_at": now_utc().isoformat()},
        {"fingerprint": "client_supplied_fingerprint"},
        {"unknown_field": "disallowed"},
    ]

    for attempt in spoof_attempts:
        payload = {
            "source_event_id": f"evt-{uuid4()}",
            "event_type": "AUTH_SUCCESS",
            "severity": "INFO",
            "title": "Normal event",
            "message": "Attempting injection",
            "occurred_at": now_utc().isoformat(),
            **attempt,
        }
        r = client.post(EVENTS_URL, headers={"X-Monitoring-Key": api_key}, json=payload)
        assert r.status_code == 422, f"Failed to reject extra field attempt: {attempt}"


def test_invalid_asset_reference_rejected(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-ASSET-01", "name": "Asset Source", "source_type": "HOST"},
    )
    api_key = create_resp.json()["api_key"]

    # Nonexistent asset_id
    r1 = client.post(
        EVENTS_URL,
        headers={"X-Monitoring-Key": api_key},
        json={
            "source_event_id": f"evt-{uuid4()}",
            "event_type": "AUTH_SUCCESS",
            "severity": "INFO",
            "title": "Title",
            "message": "Message",
            "occurred_at": now_utc().isoformat(),
            "asset_id": 999999,
        },
    )
    assert r1.status_code == 422

    # Nonexistent asset_code
    r2 = client.post(
        EVENTS_URL,
        headers={"X-Monitoring-Key": api_key},
        json={
            "source_event_id": f"evt-{uuid4()}",
            "event_type": "AUTH_SUCCESS",
            "severity": "INFO",
            "title": "Title",
            "message": "Message",
            "occurred_at": now_utc().isoformat(),
            "asset_code": "AST-NONEXISTENT",
        },
    )
    assert r2.status_code == 422


def test_payload_size_limit_enforced(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-SIZE-01", "name": "Size Source", "source_type": "HOST"},
    )
    api_key = create_resp.json()["api_key"]

    # 100 KB payload exceeds 64 KB limit
    huge_data = {"key": "x" * (100 * 1024)}
    r = client.post(
        EVENTS_URL,
        headers={"X-Monitoring-Key": api_key},
        json={
            "source_event_id": f"evt-{uuid4()}",
            "event_type": "AUTH_SUCCESS",
            "severity": "INFO",
            "title": "Title",
            "message": "Message",
            "occurred_at": now_utc().isoformat(),
            "payload": huge_data,
        },
    )
    assert r.status_code == 422


# =========================================================================
# 6. Rate Limiting Tests
# =========================================================================


def test_ingestion_rate_limiting_and_retry_after(client):
    admin = auth_client(client, "admin.demo")
    create_resp = admin.post(
        SOURCES_URL,
        json={"source_code": "SRC-RATE-01", "name": "Rate Source", "source_type": "HOST"},
    )
    api_key = create_resp.json()["api_key"]

    # Set rate limit to 3 requests for testing
    from app.main import app

    app.state.monitoring_rate_limit = 3

    try:
        for i in range(3):
            r = client.post(
                EVENTS_URL,
                headers={"X-Monitoring-Key": api_key},
                json={
                    "source_event_id": f"evt-rate-{i}-{uuid4()}",
                    "event_type": "AUTH_SUCCESS",
                    "severity": "INFO",
                    "title": f"Attempt {i}",
                    "message": "Within limit",
                    "occurred_at": now_utc().isoformat(),
                },
            )
            assert r.status_code == 201

        # 4th request must be rate limited
        r4 = client.post(
            EVENTS_URL,
            headers={"X-Monitoring-Key": api_key},
            json={
                "source_event_id": f"evt-rate-exceeded-{uuid4()}",
                "event_type": "AUTH_SUCCESS",
                "severity": "INFO",
                "title": "Exceeded",
                "message": "Exceeded limit",
                "occurred_at": now_utc().isoformat(),
            },
        )
        assert r4.status_code == 429
        assert "Retry-After" in r4.headers
        assert r4.headers["Retry-After"] == "60"
    finally:
        app.state.monitoring_rate_limit = None
