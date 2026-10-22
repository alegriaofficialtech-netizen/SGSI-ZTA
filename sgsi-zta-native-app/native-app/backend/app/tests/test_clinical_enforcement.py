"""T04 synthetic clinical endpoint enforcement tests using real AuthorizationService."""
from uuid import UUID

import pytest
from sqlalchemy import select, text

from app.database import SessionLocal, engine
from app.models import Asset, AuditLog, Role, User
from app.models.policies import Device, Policy, PolicyDecision
from app.tests.conftest import login, password_login, ready_client

CLINICAL = "/api/v1/clinical"


def test_clinical_allow_medico_trusted_mfa(client):
    """Case 1: medico + MFA + trusted device + read -> ALLOW (200)."""
    login(client, "medico.demo")
    with SessionLocal() as db:
        device_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))

    response = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={device_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["demo_id"] == "PAT-DEMO-001"
    assert data["status"] == "OBSERVACION"
    assert "diagnosis_summary" in data
    assert data["diagnosis_summary"] is not None
    assert "department" in data
    assert "record_type" in data
    assert "age_range" in data

    # Verify decision persisted and audit recorded
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "medico.demo"))
        dec = db.scalar(
            select(PolicyDecision)
            .where(PolicyDecision.user_id == user.id, PolicyDecision.resource == "clinical-demo")
            .order_by(PolicyDecision.created_at.desc())
        )
        assert dec is not None
        assert dec.decision == "ALLOW"
        assert dec.reason_code == "POLICY_ALLOW"

        audit = db.scalar(
            select(AuditLog)
            .where(AuditLog.policy_decision_id == dec.id)
        )
        assert audit is not None
        assert audit.action == "ACCESS_ALLOWED"


def test_clinical_deny_admision_sensitive(client):
    """Case 2: admision + read_sensitive -> DENY (403, EXPLICIT_DENY)."""
    login(client, "admision.demo")
    response = client.get(f"{CLINICAL}/PAT-DEMO-003")
    assert response.status_code == 403
    err = response.json()["detail"]
    assert err["code"] == "EXPLICIT_DENY"
    assert "decision_id" in err
    UUID(err["decision_id"])

    # Verify decision persisted
    with SessionLocal() as db:
        dec = db.get(PolicyDecision, err["decision_id"])
        assert dec is not None
        assert dec.decision == "DENY"
        assert dec.reason_code == "EXPLICIT_DENY"
        assert dec.action == "read_sensitive"


def test_clinical_incomplete_m2_challenge_returns_401(client):
    """Case 3a: medico password-only challenge is not an authenticated session (401)."""
    password_login(client, "medico.demo")
    client.headers["X-CSRF-Token"] = client.cookies.get("sgsi_csrf", "")
    with SessionLocal() as db:
        device_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))

    resp = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={device_id}")
    assert resp.status_code == 401


def test_clinical_mfa_required_on_authenticated_session(client):
    """Case 3b: authenticated user on trusted device but lacking policy MFA -> 403 MFA_REQUIRED."""
    from uuid import uuid4
    with SessionLocal() as db:
        policy = db.scalar(select(Policy).where(Policy.policy_code == "POL-CLIN-001"))
        auditor_role = db.scalar(select(Role).where(Role.name == "auditor"))
        policy.roles.append(auditor_role)
        dev_id = str(uuid4())
        db.add(Device(
            id=dev_id, device_code="DEV-AUD-TRUSTED", name="Auditor Trusted Device",
            assigned_user_id=None, trust_level="TRUSTED", status="ACTIVE", synthetic=True,
        ))
        db.commit()

    password_login(client, "auditor.demo")
    client.headers["X-CSRF-Token"] = client.cookies.get("sgsi_csrf", "")

    response = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={dev_id}")
    assert response.status_code == 403
    err = response.json()["detail"]
    assert err["code"] == "MFA_REQUIRED"
    assert "Additional authentication is required" in err["message"]
    assert "decision_id" in err

    with SessionLocal() as db:
        dec = db.get(PolicyDecision, err["decision_id"])
        assert dec is not None
        assert dec.decision == "MFA_REQUIRED"
        assert dec.reason_code == "MFA_REQUIRED"


def test_clinical_untrusted_device_denied(client):
    """Case 4: medico + untrusted device -> DENY (403, DEVICE_UNTRUSTED)."""
    login(client, "medico.demo")
    with SessionLocal() as db:
        untrusted_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-UNK-01"))

    response = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={untrusted_id}")
    assert response.status_code == 403
    err = response.json()["detail"]
    assert err["code"] == "DEVICE_UNTRUSTED"
    assert "decision_id" in err

    with SessionLocal() as db:
        dec = db.get(PolicyDecision, err["decision_id"])
        assert dec is not None
        assert dec.decision == "DENY"
        assert dec.reason_code == "DEVICE_UNTRUSTED"


def test_clinical_default_deny_for_unauthorized_action(client):
    """Case 5: resource/action with no matching policy -> DENY (403, DEFAULT_DENY)."""
    login(client, "medico.demo")
    with SessionLocal() as db:
        dev_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))
    # PAT-DEMO-003 derives action 'read_sensitive'; no policy authorizes medico for read_sensitive
    response = client.get(f"{CLINICAL}/PAT-DEMO-003?device_id={dev_id}")
    assert response.status_code == 403
    err = response.json()["detail"]
    assert err["code"] == "DEFAULT_DENY"
    assert "decision_id" in err

    with SessionLocal() as db:
        dec = db.get(PolicyDecision, err["decision_id"])
        assert dec is not None
        assert dec.decision == "DENY"
        assert dec.reason_code == "DEFAULT_DENY"


def test_clinical_action_tampering_rejected_with_422(client):
    """C2 remediation: Client cannot inject action or user_action parameter."""
    login(client, "admision.demo")
    # Attempting to override action to 'read' on sensitive record
    resp1 = client.get(f"{CLINICAL}/PAT-DEMO-003?action=read")
    assert resp1.status_code == 422

    # Attempting user_action or other unknown query parameters
    resp2 = client.get(f"{CLINICAL}/PAT-DEMO-003?user_action=read")
    assert resp2.status_code == 422

    # On list endpoint
    resp3 = client.get(f"{CLINICAL}/records?action=read")
    assert resp3.status_code == 422


def test_clinical_anti_spoofing_rejects_unknown_query_parameters(client):
    """Anti-spoofing: client cannot inject asset_id, user_id, or role via query."""
    login(client, "medico.demo")
    with SessionLocal() as db:
        device_id = db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))

    # Injected asset_id
    resp = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={device_id}&asset_id=999")
    assert resp.status_code == 422

    # Injected user_id
    resp = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={device_id}&user_id=1")
    assert resp.status_code == 422

    # Injected role
    resp = client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={device_id}&role=admin-ti")
    assert resp.status_code == 422


def test_clinical_not_found(client):
    """404 for unknown record without creating decision."""
    login(client, "medico.demo")
    resp = client.get(f"{CLINICAL}/PAT-DEMO-999")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Clinical record not found."


def test_clinical_anonymous_rejected(client):
    """401 for unauthenticated request."""
    anon = ready_client()
    resp = anon.get(f"{CLINICAL}/PAT-DEMO-001")
    assert resp.status_code == 401


def test_clinical_records_list_pep_and_diagnosis_suppression(client):
    """C1 remediation: /clinical/records protects each record via PEP
    and suppresses diagnosis without ALLOW."""
    login(client, "admision.demo")
    resp = client.get(f"{CLINICAL}/records")
    assert resp.status_code == 200
    records = resp.json()
    assert len(records) >= 3

    # All records for admision should have diagnosis_summary == None,
    # status marked DENEGADO, and all demographic/clinical fields masked
    for item in records:
        assert item["diagnosis_summary"] is None
        assert "DENEGADO" in item["status"]
        assert item["access_decision"] == "DENY"
        assert item["patient_synthetic_name"] is None
        assert item["age_range"] is None
        assert item["department"] is None
        assert item["record_type"] is None
        assert item["phi_classified"] is None

    # Decisions must be persisted
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admision.demo"))
        decisions = list(
            db.scalars(
                select(PolicyDecision).where(
                    PolicyDecision.user_id == user.id,
                    PolicyDecision.resource == "clinical-demo",
                )
            )
        )
        assert len(decisions) >= 3


def test_authorization_evaluate_restricted_to_admin_and_auditor(client):
    """H2 remediation: Non-privileged users cannot invoke /authorization/evaluate
    as an oracle probe."""
    # medico cannot evaluate
    login(client, "medico.demo")
    resp = client.post(
        "/api/v1/authorization/evaluate",
        json={"resource": "clinical-demo", "action": "read"},
    )
    assert resp.status_code == 403

    # admision cannot evaluate
    login(client, "admision.demo")
    resp = client.post(
        "/api/v1/authorization/evaluate",
        json={"resource": "clinical-demo", "action": "read"},
    )
    assert resp.status_code == 403

    # auditor can evaluate
    login(client, "auditor.demo")
    resp = client.post(
        "/api/v1/authorization/evaluate",
        json={"resource": "clinical-demo", "action": "read"},
    )
    assert resp.status_code == 200

    # admin-ti can evaluate
    login(client, "admin.demo")
    resp = client.post(
        "/api/v1/authorization/evaluate",
        json={"resource": "clinical-demo", "action": "read"},
    )
    assert resp.status_code == 200


def test_user_management_update_enforces_pol_admin_001(client):
    """H1 remediation: PATCH /users/{user_id} enforces POL-ADMIN-001 via AuthorizationService."""
    login(client, "admin.demo")
    with SessionLocal() as db:
        other_user = db.scalar(select(User).where(User.username == "admision.demo"))
        assert other_user is not None
        other_id = other_user.id

    resp = client.patch(
        f"/api/v1/users/{other_id}",
        json={"display_name": "Admisión Updated Demo"},
    )
    assert resp.status_code == 200

    # Verify PolicyDecision was persisted for user-management update
    with SessionLocal() as db:
        dec = db.scalar(
            select(PolicyDecision)
            .where(
                PolicyDecision.resource == "user-management",
                PolicyDecision.action == "update",
            )
            .order_by(PolicyDecision.created_at.desc())
        )
        assert dec is not None
        assert dec.decision == "ALLOW"
        assert dec.policy_id is not None


def test_audit_endpoint_enforces_pol_audit(client):
    """H1 remediation: GET /audit enforces POL-AUDIT via AuthorizationService."""
    # Auditor is allowed
    login(client, "auditor.demo")
    resp = client.get("/api/v1/audit")
    assert resp.status_code == 200

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "auditor.demo"))
        dec = db.scalar(
            select(PolicyDecision)
            .where(PolicyDecision.user_id == user.id, PolicyDecision.resource == "audit")
            .order_by(PolicyDecision.created_at.desc())
        )
        assert dec is not None
        assert dec.decision == "ALLOW"

    # Medico is denied
    login(client, "medico.demo")
    resp2 = client.get("/api/v1/audit")
    assert resp2.status_code == 403


def test_db_immutability_triggers():
    """DB immutability: Raw SQL UPDATE/DELETE on policy_decisions is rejected."""
    with SessionLocal() as db:
        # Create a sample decision row
        admin = db.scalar(select(User).where(User.username == "admin.demo"))
        decision = PolicyDecision(
            user_id=admin.id,
            resource="test-immutability",
            action="read",
            decision="ALLOW",
            reason_code="POLICY_ALLOW",
            risk_score_snapshot=10,
            risk_level_snapshot="LOW",
            mfa_snapshot=True,
            device_trust_snapshot="TRUSTED",
        )
        db.add(decision)
        db.commit()
        decision_id = decision.id

    if engine.dialect.name == "postgresql":
        # In PostgreSQL, test that raw UPDATE fails with trigger exception even with bypass attempt
        with SessionLocal() as db:
            db.execute(text("SET LOCAL sgsi.bypass_immutability = 'on'"))
            failed_update = False
            try:
                db.execute(
                    text("UPDATE policy_decisions SET resource = 'tampered' WHERE id = :id"),
                    {"id": decision_id},
                )
                db.flush()
            except Exception as exc:
                db.rollback()
                failed_update = True
                assert "append-only" in str(exc).lower()
            assert failed_update, "Trigger failed to block UPDATE on policy_decisions!"

        # In PostgreSQL, test that raw DELETE fails with trigger exception even with bypass attempt
        with SessionLocal() as db:
            db.execute(text("SET LOCAL sgsi.bypass_immutability = 'on'"))
            failed_delete = False
            try:
                db.execute(
                    text("DELETE FROM policy_decisions WHERE id = :id"),
                    {"id": decision_id},
                )
                db.flush()
            except Exception as exc:
                db.rollback()
                failed_delete = True
                assert "append-only" in str(exc).lower()
            assert failed_delete, "Trigger failed to block DELETE on policy_decisions!"
    else:
        # In SQLite, SQLAlchemy model listeners prevent update and delete
        with SessionLocal() as db:
            dec_row = db.get(PolicyDecision, decision_id)
            dec_row.resource = "tampered"
            with pytest.raises(ValueError, match="append-only"):
                db.commit()


def test_authorization_metrics_excludes_simulations_and_calculates_real_aggregates(client):
    """Metrics endpoint strictly excludes simulations and aggregates real decisions."""
    login(client, "admin.demo")

    initial_metrics = client.get("/api/v1/authorization/metrics").json()
    init_allow = initial_metrics["allow_24h_count"]
    init_deny = initial_metrics["deny_24h_count"]

    with SessionLocal() as db:
        med = db.scalar(select(User).where(User.username == "medico.demo"))
        adm = db.scalar(select(User).where(User.username == "admision.demo"))
        dev_med = db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))
        dev_adm = db.scalar(select(Device.id).where(Device.device_code == "DEV-ADM-01"))
        srv_his = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))

    # 1. Execute simulations (both allow and deny)
    sim_allow = client.post(
        "/api/v1/authorization/simulate",
        json={
            "subject_user_id": med.id,
            "resource": "clinical-demo",
            "action": "read",
            "asset_id": srv_his.id,
            "device_id": str(dev_med),
            "assume_mfa": True,
        },
    )
    assert sim_allow.status_code == 200
    assert sim_allow.json()["decision"] == "ALLOW"

    sim_deny = client.post(
        "/api/v1/authorization/simulate",
        json={
            "subject_user_id": adm.id,
            "resource": "clinical-demo",
            "action": "read_sensitive",
            "assume_mfa": False,
        },
    )
    assert sim_deny.status_code == 200
    assert sim_deny.json()["decision"] == "DENY"

    # Simulations MUST NOT increment 24h access counts
    metrics_post_sim = client.get("/api/v1/authorization/metrics").json()
    assert metrics_post_sim["allow_24h_count"] == init_allow
    assert metrics_post_sim["deny_24h_count"] == init_deny

    # 2. Execute a real ALLOW via clinical PEP
    medico_client = ready_client()
    login(medico_client, "medico.demo")
    resp_allow = medico_client.get(f"{CLINICAL}/PAT-DEMO-001?device_id={dev_med}")
    assert resp_allow.status_code == 200

    metrics_post_allow = client.get("/api/v1/authorization/metrics").json()
    assert metrics_post_allow["allow_24h_count"] == init_allow + 1
    assert metrics_post_allow["deny_24h_count"] == init_deny

    # 3. Execute a real DENY via clinical PEP
    adm_client = ready_client()
    login(adm_client, "admision.demo")
    resp_deny = adm_client.get(f"{CLINICAL}/PAT-DEMO-003?device_id={dev_adm}")
    assert resp_deny.status_code == 403

    metrics_post_deny = client.get("/api/v1/authorization/metrics").json()
    assert metrics_post_deny["allow_24h_count"] == init_allow + 1
    assert metrics_post_deny["deny_24h_count"] == init_deny + 1

    # 4. Verify decisions_by_hour contains real counts
    assert len(metrics_post_deny["decisions_by_hour"]) == 24
    assert all(
        "hour" in b and "allow" in b and "deny" in b and "mfa" in b
        for b in metrics_post_deny["decisions_by_hour"]
    )
    latest_bucket = metrics_post_deny["decisions_by_hour"][-1]
    assert latest_bucket["allow"] >= 1
    assert latest_bucket["deny"] >= 1

    # 5. Verify top_denied_resources includes clinical-demo
    assert len(metrics_post_deny["top_denied_resources"]) >= 1
    assert any(
        r["resource"] == "clinical-demo" and r["count"] >= 1
        for r in metrics_post_deny["top_denied_resources"]
    )
