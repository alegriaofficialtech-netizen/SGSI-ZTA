"""T02 boundaries use real M2 sessions/TOTP, never dependency overrides."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal, now_utc
from app.models import Asset, AuditLog, Role, User, UserSession
from app.models.policies import Device, Policy, PolicyCondition, PolicyDecision
from app.models.risks import Risk
from app.tests.conftest import login, password_login, ready_client

EVALUATE = "/api/v1/authorization/evaluate"
SIMULATE = "/api/v1/authorization/simulate"


def identifiers():
    with SessionLocal() as db:
        return {
            "medico": db.scalar(select(User.id).where(User.username == "medico.demo")),
            "admision": db.scalar(select(User.id).where(User.username == "admision.demo")),
            "trusted": db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01")),
            "untrusted": db.scalar(select(Device.id).where(Device.device_code == "DEV-UNK-01")),
            "asset": db.scalar(select(Asset.id).where(Asset.asset_code == "LAP-MED-01")),
        }


def payload(**changes):
    ids = identifiers()
    return {"resource": "clinical-demo", "action": "read",
            "asset_id": ids["asset"], "device_id": ids["trusted"], **changes}


def decision_rows():
    with SessionLocal() as db:
        return db.scalar(select(func.count(PolicyDecision.id)))


def assert_linked(response, expected, event, subject=None, simulation=False):
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == expected
    with SessionLocal() as db:
        row = db.get(PolicyDecision, body["evaluation_id"])
        assert row is not None and row.decision == expected and row.simulation == simulation
        if subject is not None:
            assert row.user_id == subject
        logs = list(db.scalars(
            select(AuditLog).where(AuditLog.policy_decision_id == row.id)
        ))
        assert len(logs) == 1 and logs[0].action == event and logs[0].decision == expected
        assert logs[0].detail == row.reason_code
        assert row.mfa_snapshot == body["context"]["mfa_verified"]
        assert row.device_trust_snapshot == body["context"]["device_trust"]
        assert row.risk_score_snapshot == body["context"]["effective_risk_score"]
    assert set(body) == {"decision", "reason_code", "policy_code", "evaluation_id", "context"}
    assert set(body["context"]) == {
        "mfa_verified", "device_trust", "effective_risk_score", "effective_risk_level"
    }
    return body


@pytest.fixture(autouse=True)
def enable_test_authorization_eval(request):
    if (
        "strict_h2" in request.keywords
        or "h2" in request.node.name.lower()
        or "rate_limit" in request.node.name.lower()
    ):
        yield
        return
    from app.main import app
    app.state.allow_test_evaluate = True
    yield
    app.state.allow_test_evaluate = False


def test_allow_medico_trusted_mfa(client):
    assert login(client, "medico.demo").status_code == 200
    body = assert_linked(client.post(EVALUATE, json=payload()), "ALLOW", "ACCESS_ALLOWED",
                         identifiers()["medico"])
    assert body["reason_code"] == "POLICY_ALLOW" and body["policy_code"] == "POL-CLIN-001"
    assert body["context"] == {"mfa_verified": True, "device_trust": "TRUSTED",
                               "effective_risk_score": 12, "effective_risk_level": "HIGH"}


def test_deny_admision_sensitive(client):
    assert login(client, "admision.demo").status_code == 200
    body = assert_linked(client.post(EVALUATE, json=payload(action="read_sensitive")),
                         "DENY", "ACCESS_DENIED", identifiers()["admision"])
    assert body["reason_code"] == "EXPLICIT_DENY"


def test_deny_untrusted_device(client):
    login(client, "medico.demo")
    body = assert_linked(client.post(EVALUATE, json=payload(
        device_id=identifiers()["untrusted"])), "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "DEVICE_UNTRUSTED"
    assert body["policy_code"] == "POL-CLIN-003"


def test_default_deny(client):
    login(client, "medico.demo")
    body = assert_linked(client.post(EVALUATE, json=payload(resource="unknown-resource")),
                         "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "DEFAULT_DENY" and body["policy_code"] is None


def test_password_only_policy_mfa_required_is_durable(client):
    with SessionLocal() as db:
        policy = db.scalar(select(Policy).where(Policy.policy_code == "POL-AUDIT-001"))
        policy.require_mfa = True
        db.commit()
    assert password_login(client, "auditor.demo").json()["status"] == "AUTHENTICATED"
    body = assert_linked(client.post(EVALUATE, json=payload(resource="audit")),
                         "MFA_REQUIRED", "ACCESS_MFA_REQUIRED")
    assert body["reason_code"] == "MFA_REQUIRED" and body["context"]["mfa_verified"] is False


@pytest.mark.parametrize("spoof", [
    {"user_id": 1}, {"role": "admin-ti"}, {"mfa_verified": True},
    {"risk_score": 1}, {"device_trust": "TRUSTED"},
    {"roles": ["admin-ti"]}, {"risk_level": "LOW"}, {"asset_criticality": "LOW"},
    {"assume_mfa": True},
])
def test_body_spoof_rejected_without_decision(client, spoof):
    login(client, "admision.demo")
    response = client.post(EVALUATE, json=payload(**spoof))
    assert response.status_code == 422, response.text
    assert decision_rows() == 0
    assert all("input" not in error for error in response.json()["detail"])


def test_headers_cannot_spoof_context(client):
    login(client, "admision.demo")
    body = assert_linked(client.post(EVALUATE, json=payload(action="read_sensitive"), headers={
        "X-User-Id": str(identifiers()["medico"]), "X-Role": "admin-ti",
        "X-Roles": "medico", "X-Mfa-Verified": "true", "X-Risk-Score": "0",
        "X-Device-Trust": "TRUSTED",
    }), "DENY", "ACCESS_DENIED", identifiers()["admision"])
    assert body["context"]["mfa_verified"] is False
    assert body["context"]["device_trust"] == "UNTRUSTED"


@pytest.mark.parametrize("changes", [
    {"resource": "../clinical"}, {"resource": "*"}, {"action": "execute"},
    {"asset_id": True}, {"asset_id": "1"}, {"asset_id": 2147483648},
    {"asset_id": 0}, {"device_id": "DEV-MED-01"},
])
def test_validation_does_not_persist_decisions(client, changes):
    login(client, "medico.demo")
    assert client.post(EVALUATE, json=payload(**changes)).status_code == 422
    assert decision_rows() == 0


def test_anonymous_evaluate(client):
    assert client.post(EVALUATE, json=payload()).status_code == 401
    assert decision_rows() == 0


def test_incomplete_m2_challenge_is_not_a_session(client):
    challenge = password_login(client, "medico.demo").json()["challenge_token"]
    client.cookies.set("sgsi_access", challenge)
    assert client.post(EVALUATE, json=payload()).status_code == 401
    assert decision_rows() == 0


def test_tampered_jwt(client):
    login(client, "medico.demo")
    token = client.cookies.get("sgsi_access")
    client.cookies.clear()
    client.cookies.set("sgsi_access", token + "tampered")
    # Preserve double-submit CSRF so this reaches JWT validation.
    client.cookies.set("sgsi_csrf", client.headers["X-CSRF-Token"])
    assert client.post(EVALUATE, json=payload()).status_code == 401
    assert decision_rows() == 0


@pytest.mark.parametrize("state", ["revoked", "expired", "inactive", "wrong-owner", "no-mfa"])
def test_invalidated_authenticated_session_rejected(client, state):
    login(client, "medico.demo")
    with SessionLocal() as db:
        session = db.scalar(select(UserSession))
        if state == "revoked":
            session.revoked_at = now_utc()
        elif state == "expired":
            session.expires_at = now_utc() - timedelta(seconds=1)
        elif state == "inactive":
            session.user.is_active = False
        elif state == "wrong-owner":
            session.user_id = identifiers()["admision"]
        else:
            session.mfa_verified_at = None
        db.commit()
    assert client.post(EVALUATE, json=payload()).status_code == 401
    assert decision_rows() == 0


def test_session_csrf_not_just_double_submit(client):
    login(client, "medico.demo")
    client.cookies.set("sgsi_csrf", "attacker-csrf")
    client.headers["X-CSRF-Token"] = "attacker-csrf"
    assert client.post(EVALUATE, json=payload()).status_code == 403
    assert decision_rows() == 0


@pytest.mark.parametrize("selector", ["missing", "unknown", "inactive", "other-user"])
def test_device_selectors_are_not_attestation(client, selector):
    login(client, "medico.demo")
    changes = {}
    if selector == "missing":
        changes["device_id"] = None
    elif selector == "unknown":
        changes["device_id"] = str(uuid4())
    elif selector == "inactive":
        with SessionLocal() as db:
            db.get(Device, identifiers()["trusted"]).status = "INACTIVE"
            db.commit()
    else:
        with SessionLocal() as db:
            db.get(Device, identifiers()["trusted"]).assigned_user_id = identifiers()["admision"]
            db.commit()
    body = assert_linked(client.post(EVALUATE, json=payload(**changes)), "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "DEVICE_UNTRUSTED"
    if selector in {"unknown", "missing"}:
        with SessionLocal() as db:
            assert db.get(PolicyDecision, body["evaluation_id"]).device_id is None


@pytest.mark.parametrize("asset_id", [None, 2147483647])
def test_missing_asset_does_not_satisfy_max_risk(client, asset_id):
    login(client, "medico.demo")
    body = assert_linked(client.post(EVALUATE, json=payload(asset_id=asset_id)),
                         "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "DEFAULT_DENY"
    with SessionLocal() as db:
        assert db.get(PolicyDecision, body["evaluation_id"]).asset_id is None


def add_risk(db, code, score, status="OPEN"):
    existing = db.scalar(select(Risk).where(Risk.asset_id == identifiers()["asset"]))
    row = Risk(
        risk_code=code, title="Synthetic risk test", asset_id=existing.asset_id,
        threat_id=existing.threat_id, vulnerability_id=existing.vulnerability_id,
        probability=5 if score in (20, 25) else 3,
        impact=score // (5 if score in (20, 25) else 3), score=score,
        level="CRITICAL" if score > 16 else "HIGH", treatment="REDUCE", status=status,
        owner_user_id=existing.owner_user_id, created_by=existing.created_by,
        updated_by=existing.updated_by,
        closed_at=now_utc() if status == "CLOSED" else None,
    )
    db.add(row)
    return row


def test_active_max_not_sum_and_closed_accepted_ignored(client):
    login(client, "medico.demo")
    with SessionLocal() as db:
        add_risk(db, "T02-SECOND", 12, "IN_TREATMENT")
        add_risk(db, "T02-CLOSED", 25, "CLOSED")
        add_risk(db, "T02-ACCEPTED", 25, "ACCEPTED")
        db.commit()
    body = assert_linked(client.post(EVALUATE, json=payload()), "ALLOW", "ACCESS_ALLOWED")
    assert body["context"]["effective_risk_score"] == 12


def test_deny_risk_threshold(client):
    login(client, "medico.demo")
    with SessionLocal() as db:
        add_risk(db, "T02-MAX", 25, "IN_TREATMENT")
        db.commit()
    body = assert_linked(client.post(EVALUATE, json=payload()), "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "RISK_THRESHOLD_EXCEEDED"
    assert body["context"]["effective_risk_score"] == 25
    assert body["context"]["effective_risk_level"] == "CRITICAL"


def test_no_active_risk_zero_low(client):
    login(client, "medico.demo")
    with SessionLocal() as db:
        risk = db.scalar(select(Risk).where(Risk.asset_id == identifiers()["asset"]))
        risk.status = "ACCEPTED"
        db.commit()
    body = assert_linked(client.post(EVALUATE, json=payload()), "ALLOW", "ACCESS_ALLOWED")
    assert body["context"]["effective_risk_score"] == 0
    assert body["context"]["effective_risk_level"] == "LOW"


def test_real_session_age_is_server_created_age(client):
    login(client, "medico.demo")
    with SessionLocal() as db:
        db.scalar(select(UserSession)).created_at = now_utc() - timedelta(minutes=5)
        db.scalar(select(Policy).where(
            Policy.policy_code == "POL-CLIN-001")).session_max_age_minutes = 1
        db.commit()
    body = assert_linked(client.post(EVALUATE, json=payload()), "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "SESSION_TOO_OLD"


@pytest.mark.parametrize("operator", ["admin.demo", "auditor.demo"])
@pytest.mark.parametrize("assume_mfa,expected", [(False, "MFA_REQUIRED"), (True, "ALLOW")])
def test_simulation_rbac_mfa_subject_and_actor(client, operator, assume_mfa, expected):
    login(client, operator)
    response = client.post(SIMULATE, json=payload(
        subject_user_id=identifiers()["medico"], assume_mfa=assume_mfa))
    body = assert_linked(response, expected, "SIMULATION_DECISION",
                         identifiers()["medico"], simulation=True)
    with SessionLocal() as db:
        row = db.get(PolicyDecision, body["evaluation_id"])
        assert row.session_id is None
        audit = db.scalar(select(AuditLog).where(AuditLog.policy_decision_id == row.id))
        assert audit.username == operator and audit.user_id != row.user_id
        assert db.scalar(select(func.count(UserSession.id))) == 1


@pytest.mark.parametrize("operator", ["medico.demo", "admision.demo"])
def test_simulation_denies_other_roles(client, operator):
    login(client, operator)
    assert client.post(SIMULATE, json=payload(
        subject_user_id=identifiers()["medico"])).status_code == 403
    assert decision_rows() == 0


def test_simulation_does_not_borrow_operator_age(client):
    login(client, "admin.demo")
    with SessionLocal() as db:
        db.scalar(select(Policy).where(
            Policy.policy_code == "POL-CLIN-001")).session_max_age_minutes = 100
        db.commit()
    body = assert_linked(client.post(SIMULATE, json=payload(
        subject_user_id=identifiers()["medico"], assume_mfa=True)),
        "DENY", "SIMULATION_DECISION", simulation=True)
    assert body["reason_code"] == "DEFAULT_DENY"


@pytest.mark.parametrize("subject_kind,expected_status", [
    ("absent", 404), ("non-demo", 403), ("inactive-demo", 403),
])
def test_simulation_subject_allowlist(client, subject_kind, expected_status):
    login(client, "admin.demo")
    subject_id = 2147483647
    with SessionLocal() as db:
        if subject_kind == "inactive-demo":
            subject = db.get(User, identifiers()["medico"])
            subject.is_active = False
            subject_id = subject.id
        elif subject_kind == "non-demo":
            subject = User(username="employee.demo", display_name="Synthetic test",
                           department="Test", password_hash="not-a-credential",
                           roles=[db.scalar(select(Role).where(Role.name == "medico"))])
            db.add(subject)
            db.flush()
            subject_id = subject.id
        db.commit()
    assert client.post(SIMULATE, json=payload(
        subject_user_id=subject_id)).status_code == expected_status
    assert decision_rows() == 0


def test_simulation_roles_and_device_are_subject_derived(client):
    login(client, "admin.demo")
    body = assert_linked(client.post(SIMULATE, json=payload(
        subject_user_id=identifiers()["admision"], assume_mfa=True)),
        "DENY", "SIMULATION_DECISION", identifiers()["admision"], simulation=True)
    assert body["context"]["device_trust"] == "UNTRUSTED"
    assert body["policy_code"] == "POL-CLIN-003"


def test_current_roles_reloaded_from_database(client):
    login(client, "medico.demo")
    with SessionLocal() as db:
        db.get(User, identifiers()["medico"]).roles = [
            db.scalar(select(Role).where(Role.name == "admision"))]
        db.commit()
    body = assert_linked(client.post(EVALUATE, json=payload()), "DENY", "ACCESS_DENIED")
    assert body["reason_code"] == "ROLE_NOT_ALLOWED"


@pytest.mark.parametrize("stage", ["decision-flush", "audit", "audit-flush", "commit"])
def test_decision_and_audit_rollback_atomically(client, monkeypatch, stage):
    from app.policies.service import AuthorizationService
    from app.services import audit

    login(client, "medico.demo")
    commits = []
    original_commit = SessionLocal.class_.commit

    def broken_record(db, *args, **kwargs):
        assert db.scalar(select(func.count(PolicyDecision.id))) == 1
        raise RuntimeError("Synthetic audit failure")

    def tracked_commit(db):
        commits.append(True)
        if stage == "commit":
            db.flush()
            raise RuntimeError("Synthetic commit failure")
        return original_commit(db)

    if stage == "decision-flush":
        original_flush = SessionLocal.class_.flush

        def broken_flush(db, *args, **kwargs):
            if any(isinstance(row, PolicyDecision) for row in db.new):
                raise RuntimeError("Synthetic decision flush failure")
            return original_flush(db, *args, **kwargs)

        monkeypatch.setattr(SessionLocal.class_, "flush", broken_flush)
    elif stage == "audit":
        monkeypatch.setattr(audit, "record", broken_record)
    elif stage == "audit-flush":
        original_record = audit.record

        def invalid_record(db, *args, **kwargs):
            original_record(db, *args, **kwargs)
            new_log = next(row for row in db.new if isinstance(row, AuditLog))
            new_log.action = None
        monkeypatch.setattr(audit, "record", invalid_record)
    monkeypatch.setattr(SessionLocal.class_, "commit", tracked_commit)
    expected_error = IntegrityError if stage == "audit-flush" else RuntimeError
    expected_message = None if stage == "audit-flush" else "Synthetic"
    with pytest.raises(expected_error, match=expected_message):
        client.post(EVALUATE, json=payload())
    assert commits == ([] if stage in {"audit", "decision-flush"} else [True])
    with SessionLocal() as db:
        assert db.scalar(select(func.count(PolicyDecision.id))) == 0
        assert db.scalar(select(func.count(AuditLog.id)).where(
            AuditLog.policy_decision_id.is_not(None))) == 0
    assert AuthorizationService is not None


def test_authorize_commits_once_and_survives_later_clinical_403(client):
    login(client, "medico.demo")
    ids = identifiers()
    resp = client.get(f"/api/v1/clinical/PAT-DEMO-001?device_id={ids['untrusted']}")
    assert resp.status_code == 403
    err = resp.json().get("detail", {})
    assert err.get("code") in ("DEVICE_UNTRUSTED", "EXPLICIT_DENY")
    decision_id = err.get("decision_id")
    assert decision_id is not None
    with SessionLocal() as db:
        row = db.get(PolicyDecision, str(decision_id))
        assert row is not None
        assert row.decision == "DENY"
        assert row.reason_code == "DEVICE_UNTRUSTED"
        linked_log = db.scalars(
            select(AuditLog).where(AuditLog.policy_decision_id == row.id)
        ).first()
        assert linked_log is not None
        assert linked_log.action == "ACCESS_DENIED"


def test_t03_routes_mounted_and_t04_unmounted(client):
    # Unauthenticated gets 401 on T03 routes
    anonymous = ready_client()
    for path in ["/api/v1/policies", "/api/v1/policy-decisions", "/api/v1/devices"]:
        assert anonymous.get(path).status_code == 401

    # admin-ti accesses T03 mounted routes
    login(client, "admin.demo")
    for path in ["/api/v1/policies", "/api/v1/policy-decisions", "/api/v1/devices"]:
        response = client.get(path)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data and "total" in data

    auditor_client = ready_client()
    login(auditor_client, "auditor.demo")
    assert auditor_client.get("/api/v1/policies").status_code == 200
    assert (
        auditor_client.post("/api/v1/policies", json={"policy_code": "POL-AUD-X"}).status_code
        == 403
    )

    medico_client = ready_client()
    login(medico_client, "medico.demo")
    assert medico_client.get("/api/v1/policies").status_code == 403

    # Decisions and devices are read-only according to contract
    assert client.post("/api/v1/policy-decisions", json={}).status_code == 405
    assert client.post("/api/v1/devices", json={}).status_code == 405

    # T04 clinical route is mounted
    assert client.get("/api/v1/clinical/PAT-DEMO-001").status_code == 403


def test_context_current_criticality_and_deterministic_max_risk_tie(client):
    from app.policies.context import real_context

    login(client, "medico.demo")
    ids = identifiers()
    with SessionLocal() as db:
        original = db.scalar(select(Risk).where(Risk.asset_id == ids["asset"]))
        original_id = original.id
        new_risk = add_risk(db, "T02-TIE", 12, "IN_TREATMENT")
        db.get(Asset, ids["asset"]).criticality = "CRITICAL"
        db.commit()
        assert new_risk.id > original_id
        facts = real_context(
            db, db.scalar(select(UserSession)), "clinical-demo", "read",
            ids["asset"], ids["trusted"],
        )
        assert facts.effective_risk_id == original_id
        assert facts.effective_risk_score == 12 and facts.effective_risk_level == "HIGH"
        assert facts.asset_criticality == "CRITICAL"
        assert facts.roles == frozenset({"medico"})
        assert facts.session_age_minutes is not None and facts.session_age_minutes >= 0


def test_missing_asset_condition_blocks_simulated_mfa_candidate(client):
    login(client, "admin.demo")
    with SessionLocal() as db:
        policy = db.scalar(select(Policy).where(Policy.policy_code == "POL-CLIN-001"))
        policy.max_risk_score = None
        policy.conditions.append(PolicyCondition(
            condition_type="ASSET_CRITICALITY", operator="EQ", value="HIGH"))
        db.commit()
    body = assert_linked(client.post(SIMULATE, json=payload(
        subject_user_id=identifiers()["medico"], assume_mfa=False, asset_id=2147483647)),
        "DENY", "SIMULATION_DECISION", simulation=True)
    assert body["reason_code"] == "DEFAULT_DENY"


@pytest.mark.parametrize("spoof", [
    {"user_id": 1}, {"role": "admin-ti"}, {"mfa_verified": True},
    {"risk_score": 1}, {"device_trust": "TRUSTED"},
])
def test_simulation_rejects_untrusted_facts(client, spoof):
    login(client, "admin.demo")
    assert client.post(SIMULATE, json=payload(
        subject_user_id=identifiers()["medico"], **spoof)).status_code == 422
    assert decision_rows() == 0


@pytest.mark.parametrize("subject_name", ["medico", "admision"])
def test_simulation_never_borrows_operator_roles(client, subject_name):
    login(client, "auditor.demo")
    body = assert_linked(client.post(SIMULATE, json=payload(
        resource="audit", subject_user_id=identifiers()[subject_name], assume_mfa=True)),
        "DENY", "SIMULATION_DECISION", simulation=True)
    assert body["reason_code"] == "ROLE_NOT_ALLOWED"


def test_h2_oracle_probe_medico_blocked_and_audited(client):
    """H2: medico role is blocked from /evaluate with 403, audited, no decision created."""
    login(client, "medico.demo")
    resp = client.post(EVALUATE, json=payload())
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Your role does not permit authorization evaluations."

    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == "medico.demo"))
        log = db.scalars(
            select(AuditLog).where(
                AuditLog.action == "ORACLE_PROBE_DENIED",
                AuditLog.user_id == u.id,
            )
        ).first()
        assert log is not None
        assert log.decision == "DENY"
        decisions_count = db.scalar(
            select(func.count(PolicyDecision.id)).where(PolicyDecision.user_id == u.id)
        )
        assert decisions_count == 0


def test_h2_oracle_probe_admision_blocked_and_audited(client):
    """H2: admision role is blocked from /evaluate with 403, audited, no decision created."""
    login(client, "admision.demo")
    resp = client.post(EVALUATE, json=payload())
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Your role does not permit authorization evaluations."

    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == "admision.demo"))
        log = db.scalars(
            select(AuditLog).where(
                AuditLog.action == "ORACLE_PROBE_DENIED",
                AuditLog.user_id == u.id,
            )
        ).first()
        assert log is not None
        assert log.decision == "DENY"
        decisions_count = db.scalar(
            select(func.count(PolicyDecision.id)).where(PolicyDecision.user_id == u.id)
        )
        assert decisions_count == 0


def test_rate_limit_evaluate_threshold_and_retry_after(client):
    """Rate limit on /evaluate: burst under threshold allowed, exceeding gives 429."""
    from app.main import app
    login(client, "admin.demo")
    app.state.authz_rate_limit = 3
    try:
        for _ in range(3):
            r = client.post(EVALUATE, json=payload())
            assert r.status_code in (200, 403)

        r4 = client.post(EVALUATE, json=payload())
        assert r4.status_code == 429
        assert "Retry-After" in r4.headers
        assert r4.headers["Retry-After"] == "60"
    finally:
        app.state.authz_rate_limit = None


def test_rate_limit_simulate_threshold_and_retry_after(client):
    """Rate limit on /simulate: burst under threshold allowed, exceeding gives 429."""
    from app.main import app
    login(client, "admin.demo")
    app.state.authz_rate_limit = 3
    ids = identifiers()
    sim_payload = {
        "subject_user_id": ids["medico"],
        "resource": "clinical-demo",
        "action": "read",
        "asset_id": ids["asset"],
        "device_id": ids["trusted"],
        "assume_mfa": True,
    }
    try:
        for _ in range(3):
            r = client.post(SIMULATE, json=sim_payload)
            assert r.status_code == 200

        r4 = client.post(SIMULATE, json=sim_payload)
        assert r4.status_code == 429
        assert "Retry-After" in r4.headers
        assert r4.headers["Retry-After"] == "60"
    finally:
        app.state.authz_rate_limit = None
