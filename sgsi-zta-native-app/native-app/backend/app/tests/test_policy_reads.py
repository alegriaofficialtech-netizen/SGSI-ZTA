"""Read-only T03 projections and fail-closed textual query boundaries."""
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import User
from app.models.policies import Device, PolicyDecision
from app.tests.test_policy_management import POLICIES, authenticated, policy_id

DECISIONS = "/api/v1/policy-decisions"
DEVICES = "/api/v1/devices"
DECISION_FIELDS = {
    "id", "user_id", "session_id", "policy_id", "resource", "action", "asset_id",
    "device_id", "decision", "reason_code", "risk_score_snapshot", "risk_level_snapshot",
    "mfa_snapshot", "device_trust_snapshot", "simulation", "created_at",
    "subject_username", "policy_code",
}
DEVICE_FIELDS = {
    "id", "device_code", "name", "assigned_user_id", "trust_level", "status",
    "last_seen_at", "synthetic", "created_at", "updated_at",
}


@pytest.fixture
def reader(client):
    return authenticated(client, "auditor.demo")


@pytest.fixture
def decisions():
    with SessionLocal() as db:
        medico = db.scalar(select(User.id).where(User.username == "medico.demo"))
        auditor = db.scalar(select(User.id).where(User.username == "auditor.demo"))
        rows = []
        for user, resource, outcome, simulation, stamp in [
            (medico, "clinical-demo", "ALLOW", False, datetime(2026, 10, 1, 8)),
            (medico, "clinical-demo", "DENY", False, datetime(2026, 10, 1, 9)),
            (auditor, "audit", "MFA_REQUIRED", True, datetime(2026, 10, 2, 9)),
            (medico, "clinical-demo", "DENY", True, datetime(2026, 10, 1, 9)),
        ]:
            row = PolicyDecision(
                user_id=user, resource=resource, action="read", decision=outcome,
                reason_code={"ALLOW": "POLICY_ALLOW", "DENY": "DEFAULT_DENY",
                             "MFA_REQUIRED": "MFA_REQUIRED"}[outcome],
                risk_score_snapshot=0, risk_level_snapshot="LOW", mfa_snapshot=False,
                device_trust_snapshot="UNTRUSTED", simulation=simulation, created_at=stamp,
            )
            db.add(row)
            rows.append(row)
        db.commit()
        return {"ids": [row.id for row in rows], "medico": medico, "auditor": auditor}


def device_id():
    with SessionLocal() as db:
        return db.scalar(select(Device.id).where(Device.device_code == "DEV-MED-01"))


@pytest.mark.parametrize("username", ["admin.demo", "auditor.demo"])
def test_admin_and_auditor_read_all_projections(client, username, decisions):
    authenticated(client, username)
    policy = policy_id()
    device = device_id()
    for url in [POLICIES, f"{POLICIES}/{policy}", f"{POLICIES}/{policy}/versions",
                DECISIONS, f"{DECISIONS}/{decisions['ids'][0]}", DEVICES, f"{DEVICES}/{device}"]:
        assert client.get(url).status_code == 200


@pytest.mark.parametrize("username", ["medico.demo", "admision.demo"])
def test_other_roles_denied_reading_every_projection(client, username, decisions):
    authenticated(client, username)
    for url in [POLICIES, f"{POLICIES}/{policy_id()}", f"{POLICIES}/{policy_id()}/versions",
                DECISIONS, f"{DECISIONS}/{decisions['ids'][0]}", DEVICES,
                f"{DEVICES}/{device_id()}"]:
        assert client.get(url).status_code == 403


def test_anonymous_and_tampered_token_denied(client, decisions):
    for url in [POLICIES, DECISIONS, DEVICES, f"{POLICIES}/{policy_id()}/versions"]:
        assert client.get(url).status_code == 401
    authenticated(client, "auditor.demo")
    client.cookies.set("sgsi_access", "tampered", domain="testserver.local", path="/")
    assert client.get(DECISIONS).status_code == 401


def test_policy_filters_pagination_and_stable_order(reader):
    response = reader.get(POLICIES)
    assert response.status_code == 200
    all_rows = response.json()
    assert all_rows["total"] == 5 and all_rows["pages"] == 1
    expected = sorted(item["policy_code"] for item in all_rows["items"])
    page = reader.get(POLICIES, params={"page": 2, "page_size": 2})
    assert page.status_code == 200
    assert {key: page.json()[key] for key in ("page", "page_size", "total", "pages")} == {
        "page": 2, "page_size": 2, "total": 5, "pages": 3
    }
    assert [item["policy_code"] for item in page.json()["items"]] == expected[2:4]
    selected = reader.get(POLICIES, params={
        "resource": "clinical-demo", "action": "read", "enabled": "true"
    }).json()
    assert {item["policy_code"] for item in selected["items"]} == {"POL-CLIN-001", "POL-CLIN-003"}
    empty = reader.get(POLICIES, params={"enabled": "false"}).json()
    assert empty["items"] == [] and empty["total"] == 0 and empty["pages"] == 0
    assert reader.get(POLICIES, params={"page": 100000}).json()["items"] == []


def test_decision_filters_inclusive_utc_and_total(reader, decisions):
    response = reader.get(DECISIONS)
    assert response.status_code == 200
    all_rows = response.json()
    assert all_rows["total"] == 4
    assert all_rows["items"][0]["decision"] == "MFA_REQUIRED"
    page = reader.get(DECISIONS, params={"page": 2, "page_size": 2}).json()
    assert page["pages"] == 2 and page["total"] == 4
    assert page["items"] == all_rows["items"][2:]
    assert [item["id"] for item in all_rows["items"][1:3]] == sorted(decisions["ids"][1::2])
    filters = {"decision": "DENY", "resource": "clinical-demo", "user_id": decisions["medico"],
               "simulation": "false", "date_from": "2026-10-01T11:00:00+02:00",
               "date_to": "2026-10-01T04:00:00-05:00", "page_size": 1}
    selected = reader.get(DECISIONS, params=filters)
    assert selected.status_code == 200
    assert selected.json()["total"] == 1
    assert selected.json()["items"][0]["id"] == decisions["ids"][1]
    naive = reader.get(DECISIONS, params={"date_from": "2026-10-01T09:00:00",
                                        "date_to": "2026-10-01T09:00:00Z"}).json()
    assert naive["total"] == 2
    assert reader.get(DECISIONS, params={"simulation": "true"}).json()["total"] == 2
    assert reader.get(DECISIONS, params={"user_id": decisions["auditor"]}).json()["total"] == 1
    assert reader.get(DECISIONS, params={"decision": "ALLOW"}).json()["total"] == 1
    assert reader.get(DECISIONS, params={"resource": "audit"}).json()["total"] == 1
    assert reader.get(DECISIONS, params={"date_to": "2026-10-01T07:59:59Z"}).json()["pages"] == 0
    assert reader.get(DECISIONS, params={"date_from": "2026-10-02T00:00:00Z"}).json()["total"] == 1


@pytest.mark.parametrize("params", [
    {"date_from": "2026-10-02T00:00:00Z", "date_to": "2026-10-01T23:59:59Z"},
    {"date_from": "2026-10-01T09:00:00-05:00", "date_to": "2026-10-01T12:00:00Z"},
    {"date_from": "not-a-date"}, {"date_to": "2026-02-30T00:00:00Z"},
    {"date_from": "2026-10-01"}, {"date_to": "1790834400"},
    {"date_to": "0001-01-01T00:00:00+14:00"},
    {"user_id": "true"}, {"user_id": "1.0"}, {"user_id": "-1"}, {"user_id": "0"},
    {"user_id": "2147483648"}, {"user_id": str(2**100)},
    {"user_id": "+1"}, {"user_id": " 1"},
    {"decision": "allow"}, {"resource": "../audit"},
    {"simulation": "1"}, {"simulation": "yes"}, {"simulation": "TRUE"},
    {"user": "1"}, {"session_id": str(uuid4())},
])
def test_decision_query_validation_fail_closed(reader, params):
    response = reader.get(DECISIONS, params=params)
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)
    assert all("input" not in error for error in response.json()["detail"])


@pytest.mark.parametrize("endpoint", [POLICIES, DECISIONS, DEVICES])
@pytest.mark.parametrize("params", [
    {"page": "0"}, {"page": "100001"}, {"page_size": "0"}, {"page_size": "101"},
    {"page": "true"}, {"page": "1.0"}, {"page": "1e2"}, {"page": "-1"},
    {"page": "+1"}, {"page": " 1"}, {"page": "9" * 100}, {"unexpected": "secret-sentinel"},
])
def test_bounded_text_pagination_validation(reader, endpoint, params):
    response = reader.get(endpoint, params=params)
    assert response.status_code == 422
    assert "secret-sentinel" not in response.text


@pytest.mark.parametrize("params", [
    {"enabled": "1"}, {"enabled": "yes"}, {"enabled": "TRUE"},
    {"action": "READ"}, {"resource": "*"},
])
def test_policy_query_validation(reader, params):
    assert reader.get(POLICIES, params=params).status_code == 422


@pytest.mark.parametrize("endpoint,key,value", [
    (POLICIES, "page", "1"), (POLICIES, "enabled", "true"),
    (DECISIONS, "simulation", "false"), (DEVICES, "page_size", "20"),
])
def test_duplicate_query_parameters_rejected(reader, endpoint, key, value):
    assert reader.get(endpoint, params=[(key, value), (key, value)]).status_code == 422


def test_device_projection_order_pagination_and_secret_exclusion(reader, decisions):
    response = reader.get(DEVICES)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3 and body["pages"] == 1
    assert [item["device_code"] for item in body["items"]] == [
        "DEV-ADM-01", "DEV-MED-01", "DEV-UNK-01"
    ]
    for item in body["items"]:
        assert set(item) == DEVICE_FIELDS and item["synthetic"] is True
        assert reader.get(f"{DEVICES}/{item['id']}").json() == item
    second_page = reader.get(DEVICES, params={"page": 2, "page_size": 2})
    assert second_page.json()["items"] == body["items"][2:]
    rows = reader.get(DECISIONS).json()["items"]
    for item in rows:
        assert set(item) == DECISION_FIELDS
        assert reader.get(f"{DECISIONS}/{item['id']}").json() == item
    version = reader.get(f"{POLICIES}/{policy_id()}/versions").json()[0]
    assert set(version) == {
        "id", "policy_id", "version", "snapshot_json", "created_at", "created_by"
    }
    assert set(version["snapshot_json"]) == set(reader.get(f"{POLICIES}/{policy_id()}").json())


@pytest.mark.parametrize("endpoint", [POLICIES, DECISIONS, DEVICES])
def test_uuid_validation_and_not_found(reader, endpoint):
    assert reader.get(f"{endpoint}/not-a-uuid").status_code == 422
    assert reader.get(f"{endpoint}/{uuid4()}").status_code == 404
    if endpoint == POLICIES:
        assert reader.get(f"{endpoint}/{uuid4()}/versions").status_code == 404


@pytest.mark.parametrize("endpoint", [DECISIONS, DEVICES])
@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE"])
def test_no_normal_decision_or_device_mutations(reader, decisions, endpoint, method):
    identifier = decisions["ids"][0] if endpoint == DECISIONS else device_id()
    for url in [endpoint, f"{endpoint}/{identifier}"]:
        assert reader.request(method, url, json={"decision": "ALLOW"}).status_code == 405
    assert reader.post(f"{endpoint}/{identifier}/disable").status_code == 404


def test_no_version_mutation_routes(reader):
    url = f"{POLICIES}/{policy_id()}/versions"
    for method in ["POST", "PATCH", "DELETE"]:
        assert reader.request(method, url, json={"snapshot_json": {}}).status_code == 405
