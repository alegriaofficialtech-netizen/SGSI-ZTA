# ruff: noqa: E402, E501
"""
M6 Acceptance Verification Script
=================================
Automated end-to-end verification of SGSI-ZTA M6 Monitoring, Alerts & FIM.
Executes against safe isolated database (PostgreSQL or SQLite), produces structured evidence.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv


def setup_environment():
    """Load environment variables if not already set."""
    for candidate in (
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ):
        if candidate.exists():
            load_dotenv(candidate)
            break

    if not os.environ.get("DATABASE_URL") and os.environ.get("TEST_DATABASE_URL"):
        os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]

    import secrets
    from cryptography.fernet import Fernet

    if not os.environ.get("JWT_SECRET"):
        os.environ["JWT_SECRET"] = secrets.token_urlsafe(64)
    if not os.environ.get("MFA_ENCRYPTION_KEY"):
        os.environ["MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    if not os.environ.get("DEMO_PASSWORD"):
        os.environ["DEMO_PASSWORD"] = "Tests!Aa9-" + secrets.token_urlsafe(20)
    if not os.environ.get("COOKIE_SECURE"):
        os.environ["COOKIE_SECURE"] = "false"


def check_database_safety(db_url: str, allow_production: bool = False) -> tuple[bool, str]:
    """Strict guard: refuses production database without dual explicit opt-in."""
    if not db_url:
        return False, "DATABASE_URL is not set."
    normalized = db_url.lower()
    if "sqlite" in normalized or "sgsi_native_test" in normalized or "test" in normalized.split("/")[-1]:
        return True, "Safe test database detected."

    is_prod_db = "sgsi_zta_db" in normalized or ("/postgres" in normalized and "test" not in normalized)
    if is_prod_db:
        env_opt_in = os.environ.get("ALLOW_PRODUCTION_ACCEPTANCE", "").strip().lower() == "true"
        if allow_production and env_opt_in:
            return True, "Production database allowed via explicit flag and env var."
        return False, "CRITICAL SAFETY GUARD: Refusing to run acceptance script against production database."

    return True, "Standard test database URL accepted."


def create_session_for(db, username: str, csrf_token: str):
    """Create authentic UserSession with TOTP MFA verified."""
    from sqlalchemy import select
    import pyotp
    from app.auth.mfa_service import cipher
    from app.auth.security import access_token, digest
    from app.database import now_utc
    from app.models import MfaCredential, User, UserSession

    user = db.scalar(select(User).where(User.username == username))
    if not user:
        raise RuntimeError(f"User {username} not found in database!")

    cred = db.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id))
    if not cred:
        secret = pyotp.random_base32()
        encrypted = cipher().encrypt(secret.encode()).decode()
        cred = MfaCredential(
            user_id=user.id,
            method="TOTP",
            secret_encrypted=encrypted,
            enabled=True,
            verified_at=now_utc(),
        )
        db.add(cred)
        db.commit()
    elif not cred.enabled:
        cred.enabled = True
        db.commit()

    raw_token = access_token(user.id, [r.code for r in user.roles], username=user.username)
    token_hash = digest(raw_token)
    session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        csrf_token=csrf_token,
        mfa_verified=True,
        mfa_method="TOTP",
        mfa_verified_at=now_utc(),
        expires_at=now_utc() + os.environ.get("SESSION_TTL", 3600),
    )
    db.add(session)
    db.commit()
    return raw_token, user


def run_m6_acceptance(allow_production: bool = False, output_file: str | None = None) -> dict:
    setup_environment()
    db_url = os.environ.get("DATABASE_URL", "")
    safe, msg = check_database_safety(db_url, allow_production)
    if not safe:
        print(f"[ERROR] {msg}")
        sys.exit(1)

    from fastapi.testclient import TestClient
    from sqlalchemy import select
    from app.database import get_db, now_utc
    from app.main import app
    from app.models import (
        Alert,
        AlertHistory,
        AlertRule,
        AuditLog,
        FimTarget,
        MonitoringEvent,
        MonitoringSource,
    )
    from app.monitoring.engine import normalize_severity, evaluate_event_for_alerts

    client = TestClient(app)
    db = next(get_db())

    evidence = {
        "milestone": "M6",
        "module": "Monitoring + Alerts + FIM",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "database_dialect": db.bind.dialect.name,
        "database_safe": safe,
        "checks_passed": 0,
        "checks_failed": 0,
        "details": [],
    }

    def record_check(name: str, passed: bool, info: str):
        if passed:
            evidence["checks_passed"] += 1
            evidence["details"].append({"name": name, "status": "PASS", "info": info})
            print(f"  [PASS] {name}: {info}")
        else:
            evidence["checks_failed"] += 1
            evidence["details"].append({"name": name, "status": "FAIL", "info": info})
            print(f"  [FAIL] {name}: {info}")

    print("\n=======================================================")
    print("STARTING M6 ACCEPTANCE VERIFICATION RUN")
    print(f"Target DB: {db.bind.dialect.name} | Safe: {safe}")
    print("=======================================================\n")

    # 1. Setup Auth Clients
    admin_csrf = str(uuid4())
    auditor_csrf = str(uuid4())
    medico_csrf = str(uuid4())

    admin_token, admin_user = create_session_for(db, "admin.demo", admin_csrf)
    auditor_token, auditor_user = create_session_for(db, "auditor.demo", auditor_csrf)
    medico_token, medico_user = create_session_for(db, "medico.demo", medico_csrf)

    admin_headers = {"x-csrf-token": admin_csrf}
    admin_cookies = {"sgsi_access": admin_token, "sgsi_csrf": admin_csrf}

    auditor_headers = {"x-csrf-token": auditor_csrf}
    auditor_cookies = {"sgsi_access": auditor_token, "sgsi_csrf": auditor_csrf}

    medico_headers = {"x-csrf-token": medico_csrf}
    medico_cookies = {"sgsi_access": medico_token, "sgsi_csrf": medico_csrf}

    record_check("Auth Sessions", True, f"Sessions established for admin (#{admin_user.id}), auditor (#{auditor_user.id}), medico (#{medico_user.id})")

    # 2. Source Creation (One-time API Key)
    source_code = f"SRC-ACCEPTANCE-{uuid4().hex[:6].upper()}"
    source_resp = client.post(
        "/api/v1/monitoring/sources",
        headers=admin_headers,
        cookies=admin_cookies,
        json={"source_code": source_code, "name": "Acceptance Test Source", "source_type": "APPLICATION"},
    )
    is_created = source_resp.status_code == 201
    source_data = source_resp.json() if is_created else {}
    raw_api_key = source_data.get("api_key", "")
    has_raw_key = raw_api_key.startswith("mon_")
    record_check("Source Registration", is_created and has_raw_key, f"Source {source_code} created with ephemeral one-time key format (mon_*)")

    # Check that key_hash is NEVER returned
    record_check("Key Hash Confidentiality", "key_hash" not in source_data, "Argon2id key_hash is NOT exposed in response payload")

    # Verify listing sources does NOT expose API key
    list_src_resp = client.get("/api/v1/monitoring/sources", headers=admin_headers, cookies=admin_cookies)
    sources_list = list_src_resp.json()
    exposed_keys = any("api_key" in s or "key_hash" in s for s in sources_list)
    record_check("Sources List Hygiene", list_src_resp.status_code == 200 and not exposed_keys, "Neither raw key nor key_hash exposed in GET /monitoring/sources")

    # 3. Authenticated Event Ingestion
    event_uid = str(uuid4())
    event_payload = {
        "source_event_id": event_uid,
        "event_type": "SECURITY_CONFIGURATION_CHANGE",
        "severity": "HIGH",
        "title": "M6 Acceptance Telemetry Event",
        "message": "Testing automated pipeline ingestion",
        "occurred_at": now_utc().isoformat(),
        "payload": {"config_item": "audit_policy", "auth_secret": "sensitive_password_123"},
    }

    ingest_headers = {"X-Monitoring-Key": raw_api_key, "X-Monitoring-Source": source_code}
    ingest_resp = client.post("/api/v1/monitoring/events", headers=ingest_headers, json=event_payload)
    event_created = ingest_resp.status_code == 201
    event_data = ingest_resp.json() if event_created else {}
    event_id = event_data.get("id")
    record_check("Event Ingestion", event_created and bool(event_id), f"Telemetry event accepted with 201 Created (ID: {event_id})")

    # 4. Idempotency Check
    dup_resp = client.post("/api/v1/monitoring/events", headers=ingest_headers, json=event_payload)
    is_idempotent = dup_resp.status_code in (200, 201) and dup_resp.json().get("id") == event_id
    record_check("Event Ingestion Idempotency", is_idempotent, "Duplicate ingestion of identical source_event_id handled idempotently")

    # 5. Forensic Event Inspection & Secret Redaction
    detail_resp = client.get(f"/api/v1/monitoring/events/{event_id}", headers=auditor_headers, cookies=auditor_cookies)
    detail_data = detail_resp.json()
    redacted = detail_data.get("payload", {}).get("auth_secret") == "[REDACTED]"
    record_check("Payload Sanitization", detail_resp.status_code == 200 and redacted, "Sensitive keys in payload automatically sanitized to [REDACTED]")

    # 6. Rule Creation & Deterministic Matching
    rule_code = f"RULE-ACC-{uuid4().hex[:6].upper()}"
    rule_resp = client.post(
        "/api/v1/monitoring/rules",
        headers=admin_headers,
        cookies=admin_cookies,
        json={
            "rule_code": rule_code,
            "name": "Acceptance High Severity Trigger",
            "event_type": "SECURITY_CONFIGURATION_CHANGE",
            "minimum_severity": "HIGH",
            "cooldown_seconds": 300,
            "enabled": True,
        },
    )
    rule_created = rule_resp.status_code == 201
    rule_id = rule_resp.json().get("id") if rule_created else None
    record_check("Rule Creation", rule_created and bool(rule_id), f"AlertRule {rule_code} created (cooldown: 300s, min: HIGH)")

    # 7. Alert Generation & Deduplication
    evt2_uid = str(uuid4())
    evt2_payload = {
        "source_event_id": evt2_uid,
        "event_type": "SECURITY_CONFIGURATION_CHANGE",
        "severity": "HIGH",
        "title": "Trigger Event for Rule",
        "message": "Generating alert via rule engine",
        "occurred_at": now_utc().isoformat(),
        "payload": {"actor": "sysadmin"},
    }
    client.post("/api/v1/monitoring/events", headers=ingest_headers, json=evt2_payload)

    # Check alert was created
    alerts_resp = client.get("/api/v1/monitoring/alerts", headers=admin_headers, cookies=admin_cookies)
    alerts = alerts_resp.json().get("items", [])
    matching_alerts = [a for a in alerts if a.get("rule_id") == rule_id and a.get("status") == "OPEN"]
    alert_exists = len(matching_alerts) > 0
    target_alert = matching_alerts[0] if alert_exists else {}
    target_alert_id = target_alert.get("id")
    initial_occurrences = target_alert.get("occurrence_count", 0)
    record_check("Alert Generation", alert_exists and initial_occurrences >= 1, f"OPEN alert created with rule {rule_code} (Count: {initial_occurrences})")

    # Deduplication test: ingest another matching event
    evt3_uid = str(uuid4())
    evt3_payload = {
        "source_event_id": evt3_uid,
        "event_type": "SECURITY_CONFIGURATION_CHANGE",
        "severity": "HIGH",
        "title": "Dedup Test Event",
        "message": "Second event within cooldown",
        "occurred_at": now_utc().isoformat(),
        "payload": {"actor": "sysadmin"},
    }
    client.post("/api/v1/monitoring/events", headers=ingest_headers, json=evt3_payload)

    alert_after_resp = client.get(f"/api/v1/monitoring/alerts/{target_alert_id}", headers=admin_headers, cookies=admin_cookies)
    alert_after = alert_after_resp.json()
    new_count = alert_after.get("occurrence_count", 0)
    dedup_worked = new_count > initial_occurrences
    record_check("Alert Deduplication", dedup_worked, f"Deduplication incremented occurrence count from {initial_occurrences} to {new_count}")

    # 8. Alert Lifecycle: ACKNOWLEDGE
    ack_resp = client.post(
        f"/api/v1/monitoring/alerts/{target_alert_id}/acknowledge",
        headers=admin_headers,
        cookies=admin_cookies,
        json={"comment": "Acknowledged in automated acceptance run"},
    )
    ack_success = ack_resp.status_code == 200 and ack_resp.json().get("status") == "ACKNOWLEDGED"
    record_check("Alert Acknowledge Transition", ack_success, "Alert transitioned OPEN -> ACKNOWLEDGED with audit comment")

    # 9. Alert Lifecycle: RESOLVE
    res_resp = client.post(
        f"/api/v1/monitoring/alerts/{target_alert_id}/resolve",
        headers=admin_headers,
        cookies=admin_cookies,
        json={"comment": "Resolved in automated acceptance run"},
    )
    res_success = res_resp.status_code == 200 and res_resp.json().get("status") == "RESOLVED"
    record_check("Alert Resolve Transition", res_success, "Alert transitioned ACKNOWLEDGED -> RESOLVED")

    # Verify AlertHistory recorded transitions
    alert_resolved_resp = client.get(f"/api/v1/monitoring/alerts/{target_alert_id}", headers=admin_headers, cookies=admin_cookies)
    history = alert_resolved_resp.json().get("history", [])
    actions = [h.get("action") for h in history]
    has_history = "ACKNOWLEDGE" in actions and "RESOLVE" in actions
    record_check("AlertHistory Immutability", has_history, f"AlertHistory recorded complete audit trail: {actions}")

    # 10. Subsequent event after RESOLVE creates NEW alert
    evt4_uid = str(uuid4())
    evt4_payload = {
        "source_event_id": evt4_uid,
        "event_type": "SECURITY_CONFIGURATION_CHANGE",
        "severity": "HIGH",
        "title": "Post-Resolve Event",
        "message": "Should open a fresh alert",
        "occurred_at": now_utc().isoformat(),
        "payload": {"actor": "sysadmin"},
    }
    client.post("/api/v1/monitoring/events", headers=ingest_headers, json=evt4_payload)

    alerts_post_resp = client.get("/api/v1/monitoring/alerts", headers=admin_headers, cookies=admin_cookies)
    new_open = [a for a in alerts_post_resp.json().get("items", []) if a.get("rule_id") == rule_id and a.get("status") == "OPEN"]
    record_check("Lifecycle Reset", len(new_open) >= 1, "New event after resolution created fresh OPEN alert as expected")

    # 11. FIM Synthetic Sandbox E2E
    data_dir = Path(__file__).resolve().parent.parent / "monitoring-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    fim_file = data_dir / "acceptance-patient-demo.json"
    initial_content = json.dumps({"patient_synthetic_id": "SYN-999", "status": "ACTIVE", "baseline": True}, indent=2)
    fim_file.write_text(initial_content, encoding="utf-8")

    # Register target
    target_code = f"FIM-ACC-{uuid4().hex[:6].upper()}"
    fim_reg_resp = client.post(
        "/api/v1/monitoring/fim/targets",
        headers=admin_headers,
        cookies=admin_cookies,
        json={"target_code": target_code, "relative_path": "acceptance-patient-demo.json", "enabled": True},
    )
    fim_created = fim_reg_resp.status_code == 201
    fim_target_id = fim_reg_resp.json().get("id") if fim_created else None
    baseline_hash = fim_reg_resp.json().get("baseline_sha256", "") if fim_created else ""
    record_check("FIM Target Registration", fim_created and bool(baseline_hash), f"FIM Target {target_code} registered with baseline {baseline_hash[:16]}...")

    # Scan clean
    scan_clean_resp = client.post(f"/api/v1/monitoring/fim/targets/{fim_target_id}/scan", headers=admin_headers, cookies=admin_cookies)
    scan_clean = scan_clean_resp.json()
    record_check("FIM Baseline Scan", scan_clean.get("status") == "MATCH", "FIM initial scan confirms MATCH with unmodified baseline")

    # Tamper file
    tampered_content = json.dumps({"patient_synthetic_id": "SYN-999", "status": "TAMPERED", "baseline": False}, indent=2)
    fim_file.write_text(tampered_content, encoding="utf-8")

    # Scan tampered
    scan_tampered_resp = client.post(f"/api/v1/monitoring/fim/targets/{fim_target_id}/scan", headers=admin_headers, cookies=admin_cookies)
    scan_tampered = scan_tampered_resp.json()
    tamper_detected = scan_tampered.get("status") == "CHANGED"
    record_check("FIM Tamper Detection", tamper_detected, f"FIM detected modification: CHANGED (new hash: {scan_tampered.get('current_sha256', '')[:16]}...)")

    # Restore file
    fim_file.write_text(initial_content, encoding="utf-8")
    scan_restored_resp = client.post(f"/api/v1/monitoring/fim/targets/{fim_target_id}/scan", headers=admin_headers, cookies=admin_cookies)
    scan_restored = scan_restored_resp.json()
    record_check("FIM Restoration Verification", scan_restored.get("status") == "MATCH", "FIM confirms MATCH after file restored to original baseline")

    # Cleanup synthetic test file
    try:
        fim_file.unlink(missing_ok=True)
    except Exception:
        pass

    # 12. Security & RBAC Enforcement
    # Auditor read-only test
    auditor_patch = client.patch(
        f"/api/v1/monitoring/sources/{source_data.get('id')}",
        headers=auditor_headers,
        cookies=auditor_cookies,
        json={"name": "Hacked Source"},
    )
    record_check("Auditor Mutation Denial", auditor_patch.status_code == 403, "Auditor blocked from mutating MonitoringSource (403 Forbidden)")

    # Clinical role denial
    medico_events = client.get("/api/v1/monitoring/events", headers=medico_headers, cookies=medico_cookies)
    record_check("Clinical Role Denial", medico_events.status_code == 403, "Clinical role (medico) blocked from monitoring APIs (403 Forbidden)")

    # Anonymous denial
    anon_events = client.get("/api/v1/monitoring/events")
    record_check("Anonymous Denial", anon_events.status_code == 401, "Anonymous request blocked with 401 Unauthorized")

    # 13. Dashboard Metrics Endpoint
    dash_resp = client.get("/api/v1/monitoring/metrics/dashboard", headers=admin_headers, cookies=admin_cookies)
    dash_data = dash_resp.json() if dash_resp.status_code == 200 else {}
    has_kpis = "events_24h" in dash_data and "alerts_open" in dash_data and "fim_targets_enabled" in dash_data
    record_check("Dashboard Aggregated Metrics", dash_resp.status_code == 200 and has_kpis, f"Real metrics served: events={dash_data.get('events_24h')}, alerts_open={dash_data.get('alerts_open')}, fim_targets={dash_data.get('fim_targets_enabled')}")

    # Summary
    all_passed = evidence["checks_failed"] == 0
    evidence["overall_status"] = "PASS" if all_passed else "FAIL"

    # Compute Evidence Hash
    serialized = json.dumps(evidence, sort_keys=True, indent=2)
    evidence["evidence_sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"\n[EVIDENCE] Saved to {out_path} (SHA-256: {evidence['evidence_sha256']})")

    print("\n=======================================================")
    print(f"ACCEPTANCE RUN FINISHED: {evidence['overall_status']}")
    print(f"Total Passed: {evidence['checks_passed']} | Failed: {evidence['checks_failed']}")
    print("=======================================================\n")

    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="M6 Acceptance Script")
    parser.add_argument("--allow-production", action="store_true", help="Explicit flag to allow production DB execution")
    parser.add_argument("--output", "-o", default=None, help="Path to write JSON evidence")
    args = parser.parse_args()

    ev = run_m6_acceptance(allow_production=args.allow_production, output_file=args.output)
    if ev["overall_status"] != "PASS":
        sys.exit(1)
