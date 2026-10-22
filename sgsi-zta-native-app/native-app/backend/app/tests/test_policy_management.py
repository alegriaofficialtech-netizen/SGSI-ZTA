"""T03 policy management uses real sessions and atomic immutable history."""
import copy
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.models import AuditLog, Role, User, UserSession
from app.models.policies import Policy, PolicyCondition, PolicyRole, PolicyVersion
from app.schemas.policies import PolicyResponse
from app.tests.conftest import login, password_login

POLICIES = "/api/v1/policies"


def authenticated(client, username="admin.demo"):
    response = login(client, username)
    assert response.status_code == 200
    assert response.json()["status"] == "AUTHENTICATED"
    client.headers["X-CSRF-Token"] = client.cookies.get("sgsi_csrf")
    return client


@pytest.fixture
def admin(client):
    return authenticated(client)


def role_id(name):
    with SessionLocal() as db:
        return db.scalar(select(Role.id).where(Role.name == name))


def policy_id(code="POL-CLIN-001"):
    with SessionLocal() as db:
        return db.scalar(select(Policy.id).where(Policy.policy_code == code))


def payload(**changes):
    base = {
        "policy_code": "POL-T03-001",
        "name": "Synthetic management policy",
        "resource": "clinical-demo",
        "action": "read",
        "effect": "ALLOW",
        "role_ids": [role_id("medico")],
    }
    base.update(changes)
    return base


def create(admin, **changes):
    response = admin.post(POLICIES, json=payload(**changes))
    assert response.status_code == 201
    return response.json()


def versions(db, identifier):
    return list(db.scalars(select(PolicyVersion).where(
        PolicyVersion.policy_id == identifier
    ).order_by(PolicyVersion.version)))


def state():
    """Include relational rows and historical bytes for rollback assertions."""
    with SessionLocal() as db:
        return {
            "policies": [PolicyResponse.model_validate(row).model_dump(mode="json") for row in
                         db.scalars(select(Policy).order_by(Policy.id))],
            "roles": list(db.execute(select(PolicyRole.policy_id, PolicyRole.role_id).order_by(
                PolicyRole.policy_id, PolicyRole.role_id))),
            "conditions": [(row.id, row.policy_id, row.condition_type, row.operator, row.value)
                           for row in db.scalars(select(PolicyCondition).order_by(
                               PolicyCondition.id))],
            "versions": [(row.id, row.policy_id, row.version, copy.deepcopy(row.snapshot_json))
                         for row in db.scalars(select(PolicyVersion).order_by(PolicyVersion.id))],
            "audit": [(row.id, row.action, row.resource, row.detail) for row in
                      db.scalars(select(AuditLog).order_by(AuditLog.id))],
        }


def test_create_update_disable_versions_and_audit(admin):
    initial = create(admin, role_ids=[role_id("medico")], conditions=[{
        "condition_type": "MFA", "operator": "EQ", "value": True
    }])
    UUID(initial["id"])
    assert initial["priority"] == 100 and initial["description"] == ""
    assert initial["enabled"] is True and initial["require_mfa"] is False
    assert initial["max_risk_score"] is None and initial["disabled_at"] is None
    assert initial["required_device_trust"] is None
    assert initial["session_max_age_minutes"] is None
    identifier = initial["id"]
    with SessionLocal() as db:
        first = copy.deepcopy(versions(db, identifier)[0].snapshot_json)
        actor = db.scalar(select(User.id).where(User.username == "admin.demo"))
    assert first == initial and first["created_by"] == actor
    patch = {"name": "Updated synthetic policy", "role_ids": [role_id("auditor")],
             "conditions": [{"condition_type": "RISK_SCORE", "operator": "LTE", "value": 12}],
             "require_mfa": True, "max_risk_score": 20, "action": "read_sensitive",
             "required_device_trust": "TRUSTED", "session_max_age_minutes": 60}
    changed = admin.patch(f"{POLICIES}/{identifier}", json=patch)
    assert changed.status_code == 200
    updated = changed.json()
    assert updated["action"] == "read_sensitive"
    assert updated["role_ids"] == patch["role_ids"] and updated["require_mfa"] is True
    assert updated["conditions"][0]["value"] == 12
    disabled = admin.post(f"{POLICIES}/{identifier}/disable")
    assert disabled.status_code == 200
    last = disabled.json()
    assert last["enabled"] is False and last["disabled_at"] is not None
    assert last["created_at"] == initial["created_at"]
    with SessionLocal() as db:
        history = versions(db, identifier)
        assert [row.version for row in history] == [1, 2, 3]
        assert [row.snapshot_json for row in history] == [first, updated, last]
        assert all(row.created_by == actor for row in history)
        logs = list(db.scalars(select(AuditLog).where(
            AuditLog.resource == f"policy:{identifier}"
        ).order_by(AuditLog.id)))
        assert [row.action for row in logs] == [
            "POLICY_CREATED", "POLICY_UPDATED", "POLICY_DISABLED"
        ]
        assert all(row.user_id == actor and row.decision == "ALLOW" for row in logs)
        assert all(row.policy_decision_id is None for row in logs)
        assert [row.detail for row in logs] == ["version=1", "version=2", "version=3"]
    history = admin.get(f"{POLICIES}/{identifier}/versions")
    assert history.status_code == 200
    assert [item["version"] for item in history.json()] == [1, 2, 3]


def test_partial_collections_and_explicit_clears(admin):
    initial = create(admin, effect="DENY", role_ids=[role_id("medico"), role_id("auditor")],
                     conditions=[{"condition_type": "DEVICE_TRUST", "operator": "EQ",
                                  "value": "TRUSTED"}], max_risk_score=12,
                     required_device_trust="LIMITED", session_max_age_minutes=20)
    url = f"{POLICIES}/{initial['id']}"
    renamed = admin.patch(url, json={"name": "Renamed policy"})
    assert renamed.status_code == 200
    assert renamed.json()["role_ids"] == initial["role_ids"]
    assert renamed.json()["conditions"] == initial["conditions"]
    replaced = admin.patch(url, json={"conditions": [{
        "condition_type": "RISK_LEVEL", "operator": "IN", "value": ["LOW", "MEDIUM"]
    }]})
    assert replaced.status_code == 200 and replaced.json()["role_ids"] == initial["role_ids"]
    assert replaced.json()["conditions"][0]["id"] != initial["conditions"][0]["id"]
    cleared = admin.patch(url, json={"role_ids": [], "conditions": [], "max_risk_score": None,
                                    "required_device_trust": None,
                                    "session_max_age_minutes": None})
    assert cleared.status_code == 200
    assert cleared.json()["role_ids"] == [] and cleared.json()["conditions"] == []
    assert all(cleared.json()[key] is None for key in (
        "max_risk_score", "required_device_trust", "session_max_age_minutes"
    ))
    with SessionLocal() as db:
        history = versions(db, initial["id"])
        assert [row.version for row in history] == [1, 2, 3, 4]
        assert history[0].snapshot_json == initial
        assert db.scalar(select(func.count(PolicyCondition.id)).where(
            PolicyCondition.policy_id == initial["id"])) == 0
        assert db.scalar(select(func.count(PolicyRole.role_id)).where(
            PolicyRole.policy_id == initial["id"])) == 0


def test_disable_is_idempotent_and_patch_never_reenables(admin):
    identifier = create(admin)["id"]
    url = f"{POLICIES}/{identifier}"
    first = admin.post(url + "/disable")
    assert first.status_code == 200
    before = state()
    assert admin.post(url + "/disable").json() == first.json()
    assert state() == before
    update = admin.patch(url, json={"name": "Still disabled"})
    assert update.status_code == 200 and update.json()["enabled"] is False
    assert update.json()["disabled_at"] == first.json()["disabled_at"]
    with SessionLocal() as db:
        assert [row.version for row in versions(db, identifier)] == [1, 2, 3]


def test_identical_accepted_patch_adds_exactly_one_version(admin):
    identifier = create(admin)["id"]
    assert admin.patch(f"{POLICIES}/{identifier}", json={
        "name": "Synthetic management policy"
    }).status_code == 200
    with SessionLocal() as db:
        assert [row.version for row in versions(db, identifier)] == [1, 2]


@pytest.mark.parametrize("operation", ["create", "update", "disable"])
@pytest.mark.parametrize("failure", ["version", "audit", "commit"])
def test_mutations_rollback_every_related_row(admin, monkeypatch, operation, failure):
    initial = create(admin, role_ids=[role_id("medico")], conditions=[{
        "condition_type": "MFA", "operator": "EQ", "value": True
    }])
    before = state()

    def reject(*args, **kwargs):
        raise RuntimeError("Injected transaction failure")

    target = PolicyVersion if failure == "version" else AuditLog
    if failure == "commit":
        from app.database import ApplicationSession
        monkeypatch.setattr(ApplicationSession, "commit", reject)
    else:
        event.listen(target, "before_insert", reject)
    try:
        with pytest.raises(RuntimeError, match="Injected transaction failure"):
            if operation == "create":
                admin.post(POLICIES, json=payload(policy_code="POL-ROLLBACK-001",
                    role_ids=[role_id("auditor")], conditions=[{
                        "condition_type": "RISK_SCORE", "operator": "LTE", "value": 10
                    }]))
            elif operation == "update":
                admin.patch(f"{POLICIES}/{initial['id']}", json={
                    "name": "Rolled back", "role_ids": [role_id("auditor")],
                    "conditions": [], "require_mfa": True
                })
            else:
                admin.post(f"{POLICIES}/{initial['id']}/disable")
    finally:
        if failure != "commit":
            event.remove(target, "before_insert", reject)
    assert state() == before


def test_duplicate_code_and_database_race_conflict_are_atomic(admin):
    initial = create(admin)
    before = state()
    duplicate = admin.post(POLICIES, json=payload())
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Policy code already exists."}
    assert state() == before

    def conflict(*args):
        raise IntegrityError("test constraint", {}, RuntimeError("test conflict"))

    event.listen(PolicyVersion, "before_insert", conflict)
    try:
        response = admin.patch(f"{POLICIES}/{initial['id']}", json={"priority": 900})
        assert response.status_code == 409
        assert response.json() == {"detail": "Policy mutation conflicts with stored state."}
    finally:
        event.remove(PolicyVersion, "before_insert", conflict)
    assert state() == before


@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("invalid", [
    {"role_ids": [2147483647]},
    {"conditions": [{"condition_type": "ROLE", "operator": "EQ", "value": "unknown-role"}]},
    {"conditions": [{"condition_type": "ROLE", "operator": "IN",
                     "value": ["medico", "unknown-role"]}]},
])
def test_missing_role_references_are_422_without_mutation(admin, operation, invalid):
    before = state()
    url = POLICIES if operation == "create" else f"{POLICIES}/{policy_id()}"
    response = admin.request("POST" if operation == "create" else "PATCH", url,
                             json=payload(**invalid) if operation == "create" else invalid)
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)
    assert "input" not in response.json()["detail"][0]
    assert state() == before


@pytest.mark.parametrize("invalid", [
    {"priority": True}, {"priority": "20"}, {"priority": 20.0}, {"priority": -1},
    {"priority": 1001}, {"require_mfa": "false"}, {"require_mfa": 1},
    {"max_risk_score": True}, {"max_risk_score": 26},
    {"session_max_age_minutes": 0}, {"session_max_age_minutes": 10081},
    {"role_ids": [True]}, {"role_ids": ["1"]}, {"role_ids": [0]},
    {"role_ids": [-1]}, {"role_ids": [2147483648]}, {"role_ids": [2**100]},
    {"enabled": True}, {"created_by": 1}, {"updated_by": 1}, {"version": 1},
    {"id": str(uuid4())}, {"unknown": "secret-sentinel"}, {"resource": "*"},
    {"action": "READ"}, {"effect": "EXECUTE"},
    {"conditions": [{"condition_type": "MFA", "operator": "EQ", "value": "true"}]},
    {"conditions": [{"condition_type": "RISK_SCORE", "operator": "LTE", "value": True}]},
    {"conditions": [{"condition_type": "TIME_WINDOW", "operator": "BETWEEN",
                     "value": {"start": "24:00", "end": "09:00"}}]},
    {"conditions": [{"condition_type": "PYTHON", "operator": "EQ", "value": "eval()"}]},
])
def test_create_strict_validation_and_no_mass_assignment(admin, invalid):
    before = state()
    response = admin.post(POLICIES, json=payload(**invalid))
    assert response.status_code == 422
    assert state() == before
    assert all("input" not in error for error in response.json()["detail"])
    assert "secret-sentinel" not in response.text


@pytest.mark.parametrize("patch", [
    {}, {"name": None}, {"description": None}, {"require_mfa": None},
    {"role_ids": None}, {"conditions": None}, {"policy_code": "POL-OTHER"},
    {"disabled_at": None}, {"enabled": False}, {"priority": "2"},
])
def test_patch_strict_validation(admin, patch):
    before = state()
    assert admin.patch(f"{POLICIES}/{policy_id()}", json=patch).status_code == 422
    assert state() == before


def test_duplicate_role_ids_and_valid_typed_conditions(admin):
    assert admin.post(POLICIES, json=payload(role_ids=[role_id("medico")] * 2)).status_code == 422
    row = create(admin, conditions=[
        {"condition_type": "ROLE", "operator": "IN", "value": ["medico", "auditor"]},
        {"condition_type": "MFA", "operator": "EQ", "value": False},
        {"condition_type": "ASSET_CRITICALITY", "operator": "EQ", "value": "HIGH"},
        {"condition_type": "RISK_LEVEL", "operator": "EQ", "value": "HIGH"},
        {"condition_type": "RISK_SCORE", "operator": "GTE", "value": 10},
        {"condition_type": "DEVICE_TRUST", "operator": "IN", "value": ["TRUSTED", "LIMITED"]},
        {"condition_type": "SESSION_AGE", "operator": "LTE", "value": 60},
        {"condition_type": "TIME_WINDOW", "operator": "BETWEEN",
         "value": {"start": "22:00", "end": "06:00"}},
    ])
    assert len(row["conditions"]) == 8


@pytest.mark.parametrize("username", ["auditor.demo", "medico.demo", "admision.demo"])
def test_nonadmins_cannot_mutate_policies(client, username):
    authenticated(client, username)
    before = state()
    identifier = policy_id()
    assert client.post(POLICIES, json=payload()).status_code == 403
    assert client.patch(f"{POLICIES}/{identifier}", json={"name": "Denied"}).status_code == 403
    assert client.post(f"{POLICIES}/{identifier}/disable").status_code == 403
    assert state() == before


def test_authentication_and_session_csrf_are_not_weakened(client):
    assert client.post(POLICIES, json=payload()).status_code == 401
    assert password_login(client).json()["status"] != "AUTHENTICATED"
    assert client.get(POLICIES).status_code == 401
    authenticated(client)
    client.headers["X-CSRF-Token"] = "wrong-token"
    assert client.post(POLICIES, json=payload()).status_code == 403
    client.cookies.set("sgsi_csrf", "forged", domain="testserver.local", path="/")
    client.headers["X-CSRF-Token"] = "forged"
    assert client.patch(f"{POLICIES}/{policy_id()}", json={"name": "Denied"}).status_code == 403


def test_revoked_session_cannot_write(admin):
    with SessionLocal() as db:
        from app.database import now_utc
        row = db.scalar(select(UserSession).where(UserSession.user_id ==
                        db.scalar(select(User.id).where(User.username == "admin.demo"))))
        row.revoked_at = now_utc()
        db.commit()
    assert admin.post(POLICIES, json=payload()).status_code == 401


def test_disable_rejects_bodies_and_policy_delete_is_absent(admin):
    before = state()
    identifier = policy_id()
    assert admin.post(f"{POLICIES}/{identifier}/disable", json={"enabled": True}).status_code == 422
    assert admin.delete(f"{POLICIES}/{identifier}").status_code == 405
    assert state() == before


def test_mutation_locks_parent_row_before_history_numbering(admin):
    from app.database import ApplicationSession
    observed = []

    def inspect_statement(state):
        if getattr(state.statement, "_for_update_arg", None) is not None:
            observed.append(str(state.statement))

    # do_orm_execute also covers scalar(), which does not call Session.execute().
    event.listen(ApplicationSession, "do_orm_execute", inspect_statement)
    try:
        identifier = policy_id()
        assert admin.patch(f"{POLICIES}/{identifier}", json={"priority": 301}).status_code == 200
        assert admin.post(f"{POLICIES}/{identifier}/disable").status_code == 200
    finally:
        event.remove(ApplicationSession, "do_orm_execute", inspect_statement)
    assert len(observed) == 2 and all("policies" in sql and "FOR UPDATE" in sql for sql in observed)


def test_history_guards_remain_active_after_management(admin):
    identifier = create(admin)["id"]
    with SessionLocal() as db:
        historical = versions(db, identifier)[0]
        historical.snapshot_json = {"rewritten": True}
        with pytest.raises(ValueError, match="append-only"):
            db.commit()
        db.rollback()
        with pytest.raises(ValueError, match="append-only"):
            db.bulk_update_mappings(PolicyVersion, [{"id": historical.id, "version": 99}])
        db.rollback()
    assert admin.get(f"{POLICIES}/{identifier}/versions").json()[0]["snapshot_json"]["name"] == (
        "Synthetic management policy"
    )


def test_allow_policy_without_roles_rejected_with_422(admin):
    """Negative test: Policies with effect ALLOW must specify at least one role_id."""
    # Create with empty role_ids must return 422
    resp = admin.post(POLICIES, json=payload(effect="ALLOW", role_ids=[]))
    assert resp.status_code == 422

    # Create ALLOW policy first
    created = create(admin)
    policy_uuid = created["id"]

    # Updating role_ids to empty on ALLOW policy must return 422
    update_resp = admin.patch(f"{POLICIES}/{policy_uuid}", json={"role_ids": []})
    assert update_resp.status_code == 422


def test_deny_policy_without_roles_permitted(admin):
    """DENY policies can have empty role_ids (e.g. default asset-level blocks)."""
    resp = admin.post(
        POLICIES,
        json=payload(policy_code="POL-DENY-001", effect="DENY", role_ids=[]),
    )
    assert resp.status_code == 201
