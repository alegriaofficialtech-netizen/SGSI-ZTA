# ruff: noqa: E402, E501
import argparse
import json
import os
import sys
from datetime import timedelta
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


def check_database_safety(db_url: str, allow_production_opt_in: bool = False) -> tuple[bool, str]:
    """
    Strict safety guard: refuses to run against production database (sgsi_zta_db)
    unless both CLI flag (--allow-production) and env var (ALLOW_PRODUCTION_ACCEPTANCE=true)
    are explicitly provided.
    """
    if not db_url:
        return False, "DATABASE_URL is not set."

    normalized = db_url.lower()

    # Safe test dialects/databases
    if (
        "sqlite" in normalized
        or "sgsi_native_test" in normalized
        or "test" in normalized.split("/")[-1]
    ):
        return True, "Safe test database detected."

    # Production database indicators
    is_prod_db = "sgsi_zta_db" in normalized or (
        "/postgres" in normalized and "test" not in normalized
    )
    if is_prod_db:
        env_opt_in = os.environ.get("ALLOW_PRODUCTION_ACCEPTANCE", "").strip().lower() == "true"
        if allow_production_opt_in and env_opt_in:
            return (
                True,
                "Production database allowed via explicit CLI flag and ALLOW_PRODUCTION_ACCEPTANCE=true.",
            )
        return False, (
            "CRITICAL SAFETY VIOLATION: Refusing to execute acceptance script against "
            "production database (sgsi_zta_db). To override intentionally, provide both "
            "--allow-production flag and ALLOW_PRODUCTION_ACCEPTANCE=true environment variable."
        )

    return True, "Standard non-production database URL accepted."


def make_headers(csrf_token: str):
    return {"x-csrf-token": csrf_token}


def make_cookies(csrf_token: str, token: str | None = None):
    cookies = {"sgsi_csrf": csrf_token}
    if token:
        cookies["sgsi_access"] = token
    return cookies


def create_session_for(db, username: str, csrf_token: str, mfa: bool = True):
    from sqlalchemy import select

    from app.auth.mfa_service import cipher
    from app.auth.security import access_token, digest
    from app.database import now_utc
    from app.models import MfaCredential, User, UserSession

    user = db.scalar(select(User).where(User.username == username))
    if not user:
        raise RuntimeError(f"User {username} not found in database!")

    if mfa:
        cred = db.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id))
        if not cred:
            import pyotp

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
            db.refresh(user)
        elif not cred.enabled:
            cred.enabled = True
            db.commit()
            db.refresh(user)

    s = UserSession(
        id=str(uuid4()),
        user_id=user.id,
        csrf_hash=digest(csrf_token),
        ip="127.0.0.1",
        user_agent="AcceptanceTestClient/1.0",
        remember=False,
        created_at=now_utc(),
        expires_at=now_utc() + timedelta(hours=8),
        mfa_verified_at=now_utc() if mfa else None,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    token = access_token(s)
    return s, token, user


def run_acceptance(
    allow_production: bool = False, evidence_output_path: Path | None = None
) -> dict:
    setup_environment()

    target_db_url = os.environ.get("DATABASE_URL", "")
    is_safe, safety_reason = check_database_safety(
        target_db_url, allow_production_opt_in=allow_production
    )
    if not is_safe:
        print(f"\n[SECURITY ABORT] {safety_reason}")
        raise RuntimeError(safety_reason)

    print(f"Database safety check passed: {safety_reason}")

    # Lazy import app, database, and models to ensure zero import side-effects
    from fastapi.testclient import TestClient
    from sqlalchemy import select, text, update

    from app.database import SessionLocal, engine, now_utc
    from app.main import app
    from app.models import Asset, AuditLog, User, UserSession
    from app.models.policies import Device, Policy, PolicyDecision, PolicyVersion

    print("=== STARTING M5.3 RUNTIME ACCEPTANCE VERIFICATION ===")

    client = TestClient(app)
    csrf_resp = client.get("/api/v1/auth/csrf")
    assert csrf_resp.status_code == 200, "Failed to retrieve CSRF token from backend"
    global_csrf = csrf_resp.json()["csrf_token"]

    def hdrs():
        return make_headers(global_csrf)

    def cks(token: str | None = None):
        return make_cookies(global_csrf, token)

    check_results = []
    created_session_ids: list[str] = []

    dialect_name = engine.dialect.name
    print(f"  Connected database dialect: {dialect_name}")

    try:
        # Check Alembic Migration Head (0006_db_immutability)
        alembic_head = None
        with SessionLocal() as db:
            try:
                alembic_head = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
            except Exception:
                alembic_head = "untracked"

        if dialect_name == "postgresql":
            if alembic_head != "0006_db_immutability":
                raise RuntimeError(
                    f"Alembic migration head mismatch! Expected '0006_db_immutability', got '{alembic_head}'."
                )
            print(f"  Alembic migration head verified: {alembic_head}")

        # 1. DATABASE LEVEL IMMUTABILITY (TRIGGER TEST)
        print("\n[CHECK 1] Database-Level Immutability...")
        with SessionLocal() as db:
            admin_u = db.scalar(select(User).where(User.username == "admin.demo"))
            assert admin_u is not None, "admin.demo user required"

            test_dec_id = str(uuid4())
            test_pol_id = str(uuid4())
            test_pol_code = f"POL-TEST-{uuid4().hex[:8]}"
            test_ver_id = str(uuid4())

            if dialect_name == "postgresql":
                # Use savepoint so rows are cleaned up without firing DELETE triggers
                sp_outer = db.begin_nested()
                try:
                    test_dec = PolicyDecision(
                        id=test_dec_id,
                        user_id=admin_u.id,
                        resource="test-acceptance-immutability",
                        action="read",
                        decision="ALLOW",
                        reason_code="POLICY_ALLOW",
                        risk_score_snapshot=0,
                        risk_level_snapshot="LOW",
                        mfa_snapshot=True,
                        device_trust_snapshot="TRUSTED",
                    )
                    db.add(test_dec)

                    test_pol = Policy(
                        id=test_pol_id,
                        policy_code=test_pol_code,
                        name="Acceptance Test Policy",
                        resource="test-acceptance",
                        action="read",
                        effect="ALLOW",
                        created_by=admin_u.id,
                        updated_by=admin_u.id,
                    )
                    db.add(test_pol)
                    db.flush()

                    test_ver = PolicyVersion(
                        id=test_ver_id,
                        policy_id=test_pol_id,
                        version=1,
                        snapshot_json={"test": True},
                        created_by=admin_u.id,
                    )
                    db.add(test_ver)
                    db.flush()

                    # Test UPDATE blocked on PolicyDecision
                    failed_update = False
                    sp_up = db.begin_nested()
                    try:
                        sp_up.session.execute(
                            text("UPDATE policy_decisions SET decision = 'DENY' WHERE id = :id"),
                            {"id": test_dec_id},
                        )
                        sp_up.session.flush()
                    except Exception as e:
                        sp_up.rollback()
                        failed_update = True
                        err_msg = str(e).lower()
                        assert any(
                            k in err_msg
                            for k in (
                                "append-only",
                                "immutability violation",
                                "cannot be updated or deleted",
                            )
                        ), f"Unexpected error: {e}"
                    assert failed_update, (
                        "CRITICAL: Immutability trigger failed to block UPDATE on policy_decisions!"
                    )

                    # Test DELETE blocked on PolicyDecision
                    failed_delete = False
                    sp_del = db.begin_nested()
                    try:
                        sp_del.session.execute(
                            text("DELETE FROM policy_decisions WHERE id = :id"),
                            {"id": test_dec_id},
                        )
                        sp_del.session.flush()
                    except Exception as e:
                        sp_del.rollback()
                        failed_delete = True
                        err_msg = str(e).lower()
                        assert any(
                            k in err_msg
                            for k in (
                                "append-only",
                                "immutability violation",
                                "cannot be updated or deleted",
                            )
                        ), f"Unexpected error: {e}"
                    assert failed_delete, (
                        "CRITICAL: Immutability trigger failed to block DELETE on policy_decisions!"
                    )

                    # Test UPDATE blocked on PolicyVersion
                    failed_ver_up = False
                    sp_vup = db.begin_nested()
                    try:
                        sp_vup.session.execute(
                            text("UPDATE policy_versions SET version = 2 WHERE id = :id"),
                            {"id": test_ver_id},
                        )
                        sp_vup.session.flush()
                    except Exception as e:
                        sp_vup.rollback()
                        failed_ver_up = True
                        err_msg = str(e).lower()
                        assert any(
                            k in err_msg
                            for k in (
                                "append-only",
                                "immutability violation",
                                "cannot be updated or deleted",
                            )
                        ), f"Unexpected error: {e}"
                    assert failed_ver_up, (
                        "CRITICAL: Immutability trigger failed to block UPDATE on policy_versions!"
                    )

                    # Test DELETE blocked on PolicyVersion
                    failed_ver_del = False
                    sp_vdel = db.begin_nested()
                    try:
                        sp_vdel.session.execute(
                            text("DELETE FROM policy_versions WHERE id = :id"),
                            {"id": test_ver_id},
                        )
                        sp_vdel.session.flush()
                    except Exception as e:
                        sp_vdel.rollback()
                        failed_ver_del = True
                        err_msg = str(e).lower()
                        assert any(
                            k in err_msg
                            for k in (
                                "append-only",
                                "immutability violation",
                                "cannot be updated or deleted",
                            )
                        ), f"Unexpected error: {e}"
                    assert failed_ver_del, (
                        "CRITICAL: Immutability trigger failed to block DELETE on policy_versions!"
                    )

                finally:
                    sp_outer.rollback()
                print(
                    "  PASS: PostgreSQL triggers strictly blocked UPDATE and DELETE without row leakage."
                )
            else:
                test_dec = PolicyDecision(
                    id=test_dec_id,
                    user_id=admin_u.id,
                    resource="test-acceptance-immutability",
                    action="read",
                    decision="ALLOW",
                    reason_code="POLICY_ALLOW",
                    risk_score_snapshot=0,
                    risk_level_snapshot="LOW",
                    mfa_snapshot=True,
                    device_trust_snapshot="TRUSTED",
                )
                db.add(test_dec)
                db.flush()
                test_dec.resource = "tampered"
                failed_orm_update = False
                try:
                    db.flush()
                except ValueError as e:
                    failed_orm_update = True
                    assert "append-only" in str(e).lower()
                assert failed_orm_update, "SQLite listener failed to block modification!"
                db.rollback()
                print("  PASS: SQLite ORM append-only listener verified.")

        check_results.append({"check": 1, "name": "DB Immutability Triggers", "status": "PASS"})

        # Setup standard users and devices
        with SessionLocal() as db:
            dev_med_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))
            dev_adm_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-ADM-01"))
            dev_unk_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-UNK-01"))

            s_med, tok_med, u_med = create_session_for(db, "medico.demo", global_csrf, mfa=True)
            created_session_ids.append(s_med.id)

            s_adm, tok_adm, u_adm = create_session_for(db, "admision.demo", global_csrf, mfa=False)
            created_session_ids.append(s_adm.id)

            s_adm_ti, tok_adm_ti, _ = create_session_for(db, "admin.demo", global_csrf, mfa=True)
            created_session_ids.append(s_adm_ti.id)

            s_aud, tok_aud, _ = create_session_for(db, "auditor.demo", global_csrf, mfa=True)
            created_session_ids.append(s_aud.id)

        # 2. ZERO TRUST ACCEPTANCE: MEDICO + MFA + DEV-MED-01 -> ALLOW
        print("\n[CHECK 2] Medico + MFA + DEV-MED-01 -> ALLOW...")
        r = client.get(
            f"/api/v1/clinical/PAT-DEMO-001?device_id={dev_med_id}",
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["demo_id"] == "PAT-DEMO-001"
        assert body["diagnosis_summary"] is not None
        assert body["patient_synthetic_name"] == "Carlos Mendoza (Sintético)"
        print("  PASS: Medico received clinical diagnosis on trusted device.")
        check_results.append({"check": 2, "name": "Medico Trusted ALLOW", "status": "PASS"})

        # 3. ZERO TRUST ACCEPTANCE: ADMISION SENSITIVE -> DENY
        print("\n[CHECK 3] Admision on sensitive record -> DENY (POL-CLIN-002)...")
        r = client.get(
            f"/api/v1/clinical/PAT-DEMO-003?device_id={dev_adm_id}",
            headers=hdrs(),
            cookies=cks(tok_adm),
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"
        err = r.json().get("detail", {})
        assert err.get("code") in ("EXPLICIT_DENY", "ROLE_NOT_ALLOWED"), (
            f"Expected EXPLICIT_DENY, got {err}"
        )
        print(f"  PASS: Admision blocked with {err.get('code')}.")
        check_results.append({"check": 3, "name": "Admision Sensitive DENY", "status": "PASS"})

        # 4. ZERO TRUST ACCEPTANCE: POLICY ENGINE WITHOUT MFA -> MFA_REQUIRED
        print("\n[CHECK 4] Policy Engine Evaluation without MFA -> MFA_REQUIRED...")
        with SessionLocal() as db:
            srv_his = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
            srv_his_id = srv_his.id if srv_his else None
        r = client.post(
            "/api/v1/authorization/simulate",
            json={
                "subject_user_id": u_med.id,
                "resource": "clinical-demo",
                "action": "read",
                "asset_id": srv_his_id,
                "device_id": str(dev_med_id),
                "assume_mfa": False,
            },
            headers=hdrs(),
            cookies=cks(tok_adm_ti),
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        sim = r.json()
        assert sim["decision"] == "MFA_REQUIRED", f"Expected MFA_REQUIRED, got {sim['decision']}"
        assert sim["reason_code"] == "MFA_REQUIRED", (
            f"Expected MFA_REQUIRED, got {sim['reason_code']}"
        )
        assert sim["policy_code"] == "POL-CLIN-001"
        print("  PASS: Policy Engine accurately issued MFA_REQUIRED when MFA is missing.")

        r_anon = client.get(
            f"/api/v1/clinical/PAT-DEMO-001?device_id={dev_med_id}",
            headers=hdrs(),
            cookies=cks(),
        )
        assert r_anon.status_code == 401
        print("  PASS: Anonymous request to PEP rejected with 401.")
        check_results.append(
            {"check": 4, "name": "MFA Required Simulation & Anon 401", "status": "PASS"}
        )

        # 5. ZERO TRUST ACCEPTANCE: MEDICO + DEV-UNK-01 -> DEVICE_UNTRUSTED / DENY
        print("\n[CHECK 5] Medico on UNTRUSTED device (DEV-UNK-01) -> DENY (POL-CLIN-003)...")
        r = client.get(
            f"/api/v1/clinical/PAT-DEMO-001?device_id={dev_unk_id}",
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"
        code = r.json().get("detail", {}).get("code")
        assert code in ("DEVICE_UNTRUSTED", "EXPLICIT_DENY"), (
            f"Expected untrusted device rejection, got {code}"
        )
        print(f"  PASS: UNTRUSTED device rejected with {code}.")
        check_results.append({"check": 5, "name": "Untrusted Device DENY", "status": "PASS"})

        # 6. ZERO TRUST ACCEPTANCE: ACTION TAMPERING RESISTANCE (C2)
        print("\n[CHECK 6] Action Parameter Tampering Resistance (C2)...")
        r = client.get(
            "/api/v1/clinical/records?action=read",
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 422, f"Expected 422 for query action tampering, got {r.status_code}"
        r = client.get(
            "/api/v1/clinical/records?user_action=read",
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 422, (
            f"Expected 422 for query user_action tampering, got {r.status_code}"
        )
        r = client.get(
            "/api/v1/clinical/PAT-DEMO-003?action=read",
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 422, (
            f"Expected 422 for detail action tampering, got {r.status_code}"
        )
        print("  PASS: Client action override attempts strictly rejected with 422.")
        check_results.append({"check": 6, "name": "Action Tampering Resistance", "status": "PASS"})

        # 7. ZERO TRUST ACCEPTANCE: CLINICAL LIST PEP & DATA MASKING (C1)
        print("\n[CHECK 7] Clinical Records List PEP & Sensitive Data Masking (C1)...")
        r = client.get(
            f"/api/v1/clinical/records?device_id={dev_adm_id}",
            headers=hdrs(),
            cookies=cks(tok_adm),
        )
        assert r.status_code == 200
        records = r.json()
        assert len(records) == 3
        for rec in records:
            assert rec["diagnosis_summary"] is None, (
                f"Leak: {rec['demo_id']} leaked diagnosis to admision!"
            )
            assert "DENEGADO" in rec["status"], f"Status not masked: {rec['status']}"
            assert rec["access_decision"] == "DENY"
            assert rec["patient_synthetic_name"] is None, (
                f"Leak: {rec['demo_id']} leaked patient name to admision!"
            )
            assert rec["age_range"] is None, f"Leak: {rec['demo_id']} leaked age range to admision!"
            assert rec["department"] is None, (
                f"Leak: {rec['demo_id']} leaked department to admision!"
            )
            assert rec["record_type"] is None, (
                f"Leak: {rec['demo_id']} leaked record_type to admision!"
            )
            assert rec["phi_classified"] is None, (
                f"Leak: {rec['demo_id']} leaked phi_classified to admision!"
            )
        print(
            "  PASS: All diagnosis summaries suppressed and demographic/clinical fields fully masked on DENY."
        )
        check_results.append({"check": 7, "name": "Clinical List PEP & Masking", "status": "PASS"})

        # 8. ORACLE PROBE RESTRICTION (H2)
        print("\n[CHECK 8] Oracle Probe Restriction on /authorization/evaluate (H2)...")
        r = client.post(
            "/api/v1/authorization/evaluate",
            json={"resource": "clinical-demo", "action": "read"},
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 403, (
            f"Expected 403 for medico calling evaluate, got {r.status_code}"
        )
        print("  PASS: Non-admin probe to /evaluate blocked with 403.")

        r = client.post(
            "/api/v1/authorization/evaluate",
            json={"resource": "clinical-demo", "action": "read"},
            headers=hdrs(),
            cookies=cks(tok_adm_ti),
        )
        assert r.status_code == 200, (
            f"Expected 200 for admin-ti calling evaluate, got {r.status_code}"
        )
        print("  PASS: admin-ti authorized on /evaluate.")
        check_results.append({"check": 8, "name": "Oracle Probe Restriction", "status": "PASS"})

        # 9. METRICS ENDPOINT (C3)
        print("\n[CHECK 9] Zero Trust Metrics Endpoint (C3)...")
        r = client.get(
            "/api/v1/authorization/metrics",
            headers=hdrs(),
            cookies=cks(tok_adm_ti),
        )
        assert r.status_code == 200
        metrics = r.json()
        assert metrics["active_policies_count"] >= 5, (
            f"Expected >= 5 policies, got {metrics['active_policies_count']}"
        )
        assert metrics["allow_24h_count"] >= 1
        assert len(metrics["decisions_by_hour"]) == 24, "Expected 24 hourly buckets in metrics"
        assert "top_denied_resources" in metrics
        print(
            f"  PASS: Metrics returned active_policies={metrics['active_policies_count']}, "
            f"allows={metrics['allow_24h_count']}, 24h_buckets={len(metrics['decisions_by_hour'])}."
        )
        check_results.append({"check": 9, "name": "Zero Trust Real Metrics", "status": "PASS"})

        # 10. ENFORCEMENT OF POL-ADMIN-001 & POL-AUDIT-001 (H1)
        print("\n[CHECK 10] POL-ADMIN-001 & POL-AUDIT-001 Enforcement (H1)...")
        r = client.get("/api/v1/audit", headers=hdrs(), cookies=cks(tok_aud))
        assert r.status_code == 200, f"Expected 200 for auditor on /audit, got {r.status_code}"
        print("  PASS: auditor authorized on /audit by POL-AUDIT-001.")

        r = client.get("/api/v1/audit", headers=hdrs(), cookies=cks(tok_med))
        assert r.status_code == 403, f"Expected 403 for medico on /audit, got {r.status_code}"
        print("  PASS: medico denied on /audit by POL-AUDIT-001 PEP.")
        check_results.append(
            {"check": 10, "name": "Admin & Audit PEP Enforcement", "status": "PASS"}
        )

        # 11. POLICY CRUD / RBAC & ALLOW EMPTY ROLE VALIDATION
        print("\n[CHECK 11] Policy CRUD / RBAC & ALLOW Empty Role Validation...")
        r = client.get("/api/v1/policies", headers=hdrs(), cookies=cks(tok_adm_ti))
        assert r.status_code == 200
        assert r.json()["total"] >= 5
        print(f"  PASS: admin-ti read {r.json()['total']} policies.")

        r = client.post(
            "/api/v1/policies",
            json={
                "name": "test-invalid-allow",
                "resource": "clinical-demo",
                "action": "read",
                "effect": "ALLOW",
                "role_ids": [],
            },
            headers=hdrs(),
            cookies=cks(tok_adm_ti),
        )
        assert r.status_code == 422, f"Expected 422 for ALLOW with role_ids=[], got {r.status_code}"
        print("  PASS: ALLOW policy with role_ids=[] strictly rejected with 422.")

        r = client.post(
            "/api/v1/policies",
            json={"name": "test-medico-forbidden", "resource": "test", "action": "read"},
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert r.status_code == 403
        print("  PASS: medico denied from managing policies.")
        check_results.append(
            {"check": 11, "name": "Policy CRUD & ALLOW Role Validation", "status": "PASS"}
        )

        # 12. AUDIT LOG LINKAGE
        print("\n[CHECK 12] Audit Log & Policy Decision In-Transaction Linkage...")
        # Issue an explicit clinical request to guarantee a new decision is persisted
        resp_link = client.get(
            f"/api/v1/clinical/PAT-DEMO-002?device_id={dev_med_id}",
            headers=hdrs(),
            cookies=cks(tok_med),
        )
        assert resp_link.status_code == 200, (
            f"Expected 200 on PAT-DEMO-002, got {resp_link.status_code}"
        )
        dec_id = resp_link.json()["decision_id"]

        with SessionLocal() as db:
            linked_dec = db.get(PolicyDecision, dec_id)
            assert linked_dec is not None, f"Failed to find created PolicyDecision for id {dec_id}"
            assert linked_dec.resource == "clinical-demo"
            assert linked_dec.decision == "ALLOW"
            assert linked_dec.user_id == u_med.id

            linked_audit = db.scalar(
                select(AuditLog).where(AuditLog.policy_decision_id == linked_dec.id)
            )
            assert linked_audit is not None, f"No AuditLog linked to decision {linked_dec.id}!"
            assert linked_audit.action in ("ACCESS_ALLOWED", "EVALUATE_POLICY"), (
                f"Unexpected audit action: {linked_audit.action}"
            )
            print(
                f"  PASS: PolicyDecision {linked_dec.id} verified linked to AuditLog {linked_audit.id} (action={linked_audit.action})."
            )
        check_results.append(
            {"check": 12, "name": "Audit Log & Policy Decision Linkage", "status": "PASS"}
        )

    finally:
        # Strict cleanup of all sessions created during acceptance verification (revoke to preserve FK integrity)
        if created_session_ids:
            with SessionLocal() as db:
                try:
                    db.execute(
                        update(UserSession)
                        .where(UserSession.id.in_(created_session_ids))
                        .values(revoked_at=now_utc())
                    )
                    db.commit()
                    print(
                        f"\n  Cleanup: successfully revoked {len(created_session_ids)} ephemeral test sessions."
                    )
                except Exception as e:
                    print(f"\n  Warning during session cleanup: {e}")

    all_passed = (len(check_results) == 12) and all(
        c.get("status") == "PASS" for c in check_results
    )

    evidence = {
        "timestamp": now_utc().isoformat(),
        "database_dialect": dialect_name,
        "alembic_version": alembic_head,
        "results": check_results,
        "total_checks": len(check_results),
        "all_passed": all_passed,
    }

    if evidence_output_path is None:
        evidence_output_path = (
            Path(__file__).resolve().parent / "evidence" / "m5_acceptance_evidence.json"
        )

    evidence_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(evidence_output_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print("\n========================================================")
    print(
        f"RUNTIME ACCEPTANCE SUMMARY: {len(check_results)}/12 CHECKS PASSED (all_passed={all_passed})"
    )
    print(f"Evidence written to {evidence_output_path}")
    print("========================================================")

    if not all_passed:
        raise RuntimeError("One or more acceptance checks failed!")

    return evidence


def main():
    parser = argparse.ArgumentParser(description="M5.3 Runtime Acceptance Verification")
    parser.add_argument(
        "--allow-production",
        action="store_true",
        help="Allow running acceptance against production DB if ALLOW_PRODUCTION_ACCEPTANCE=true is set.",
    )
    parser.add_argument(
        "--evidence-path",
        type=Path,
        default=None,
        help="Custom path to save acceptance evidence JSON.",
    )
    args = parser.parse_args()

    try:
        run_acceptance(
            allow_production=args.allow_production, evidence_output_path=args.evidence_path
        )
    except Exception as e:
        print(f"\nACCEPTANCE VERIFICATION FAILED: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
