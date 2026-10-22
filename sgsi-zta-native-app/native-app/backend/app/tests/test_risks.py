import json

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.models import Asset, Control, Risk, RiskControl, Threat, User, Vulnerability
from app.risks.engine import calculate_score, classify_risk
from app.risks.seed import seed_risks
from app.tests.conftest import login, password_login


def draft(**changes):
    with SessionLocal() as db:
        return (
            dict(
                risk_code="TEST-RISK-01",
                title="Riesgo sintético de prueba",
                asset_id=db.scalar(select(Asset.id).where(Asset.asset_code == "SRV-HIS-01")),
                threat_id=db.scalar(select(Threat.id).where(Threat.code == "THR-001")),
                vulnerability_id=db.scalar(
                    select(Vulnerability.id).where(Vulnerability.code == "VUL-002")
                ),
                probability=3,
                impact=3,
                owner_user_id=db.scalar(select(User.id).where(User.username == "admin.demo")),
            )
            | changes
        )


def create(client, **changes):
    return client.post("/api/v1/risks", json=draft(**changes))


def control_draft(**changes):
    return {
        "control_code": "TEST-CTRL-01",
        "name": "Control sintético de prueba",
        "category": "IDENTITY",
        "owner_user_id": draft()["owner_user_id"],
    } | changes


@pytest.mark.parametrize(
    "p,i,score,level",
    [
        (1, 1, 1, "LOW"),
        (2, 2, 4, "LOW"),
        (3, 3, 9, "MEDIUM"),
        (4, 4, 16, "HIGH"),
        (5, 5, 25, "CRITICAL"),
        (1, 5, 5, "MEDIUM"),
        (2, 5, 10, "HIGH"),
        (4, 5, 20, "CRITICAL"),
    ],
)
def test_risk_calculation_boundaries(p, i, score, level):
    assert calculate_score(p, i) == score and classify_risk(score) == level


@pytest.mark.parametrize(
    "score,level",
    [
        (4, "LOW"),
        (5, "MEDIUM"),
        (9, "MEDIUM"),
        (10, "HIGH"),
        (16, "HIGH"),
        (17, "CRITICAL"),
        (25, "CRITICAL"),
    ],
)
def test_level_thresholds(score, level):
    assert classify_risk(score) == level


@pytest.mark.parametrize("p,i", [(0, 1), (6, 1), (1, -1), (1, 100), (True, 2), (2, False)])
def test_engine_invalid_values(p, i):
    with pytest.raises(ValueError):
        calculate_score(p, i)


def test_create_risk_admin_mfa_and_calculation(client):
    assert login(client).json()["assurance"] == "PASSWORD_MFA"
    result = create(client, probability=4, impact=5)
    assert result.status_code == 201
    row = result.json()
    assert (
        row["score"] == 20
        and row["level"] == "CRITICAL"
        and row["asset"]["asset_code"] == "SRV-HIS-01"
    )
    assert "created_by" not in row and "password_hash" not in str(row)
    assert client.get("/api/v1/risks/summary").json()["total"] == 9


def test_duplicate_risk_code(client):
    login(client)
    assert create(client).status_code == 201 and create(client).status_code == 409


@pytest.mark.parametrize(
    "changes",
    [
        {"probability": 100},
        {"impact": -1},
        {"probability": True},
        {"impact": 1.5},
        {"asset_id": 999999},
        {"threat_id": 999999},
        {"vulnerability_id": 999999},
        {"owner_user_id": 999999},
        {"title": ""},
        {"risk_code": "bad code"},
        {"status": "INVALID"},
        {"treatment": "INVALID"},
        {"created_by": 1},
        {"id": 999},
    ],
)
def test_invalid_create(client, changes):
    login(client)
    assert create(client, **changes).status_code == 422


def test_client_supplied_score_level_recalculated(client):
    login(client)
    row = create(client, probability=1, impact=1, score=100, level="CRITICAL").json()
    assert row["score"] == 1 and row["level"] == "LOW"


@pytest.mark.parametrize("field", ["id", "risk_code", "score", "level", "created_at", "created_by"])
def test_patch_mass_assignment_denied(client, field):
    login(client)
    row = create(client).json()
    assert client.patch(f"/api/v1/risks/{row['id']}", json={field: 1}).status_code == 422


def test_update_close_reopen_history(client):
    login(client)
    row = create(client).json()
    path = f"/api/v1/risks/{row['id']}"
    with SessionLocal() as db:
        owner = db.scalar(select(User.id).where(User.username == "medico.demo"))
    changed = client.patch(
        path,
        json={
            "probability": 4,
            "impact": 5,
            "treatment": "ACCEPT",
            "owner_user_id": owner,
            "description": "Free text excluded from audit",
        },
    ).json()
    assert changed["score"] == 20 and changed["level"] == "CRITICAL"
    assert client.post(path + "/close").json()["closed_at"]
    assert client.post(path + "/close").status_code == 200
    history = client.get(path).json()["history"]
    actions = {row["action"] for row in history}
    assert {
        "RISK_CREATED",
        "RISK_UPDATED",
        "RISK_SCORE_CHANGED",
        "RISK_LEVEL_CHANGED",
        "RISK_TREATMENT_CHANGED",
        "RISK_OWNER_CHANGED",
        "RISK_STATUS_CHANGED",
        "RISK_CLOSED",
    } <= actions
    score = next(row for row in history if row["action"] == "RISK_SCORE_CHANGED")
    assert json.loads(score["detail"]) == {"field": "score", "before": 9, "after": 20}
    assert "Free text excluded" not in str(history)
    assert sum(row["action"] == "RISK_CLOSED" for row in history) == 1
    assert (
        client.patch(path, json={"status": "OPEN", "review_due_at": None}).json()["closed_at"]
        is None
    )
    assert client.delete(path).status_code == 405


def test_matrix_all_cells_single_backend_calculation(client):
    login(client)
    data = client.get("/api/v1/risks/matrix").json()
    assert len(data["cells"]) == 25 and sum(cell["count"] for cell in data["cells"]) == 7
    for cell in data["cells"]:
        assert cell["score"] == calculate_score(cell["probability"], cell["impact"])
        assert cell["level"] == classify_risk(cell["score"])
        params = {
            "probability": cell["probability"],
            "impact": cell["impact"],
            "exclude_closed": "true",
        }
        assert client.get("/api/v1/risks", params=params).json()["total"] == cell["count"]
    assert client.get("/api/v1/risks/matrix?include_closed=true").json()["total"] == 8


def test_list_search_filters_sort_pagination(client):
    login(client)
    result = client.get("/api/v1/risks?search=SRV-HIS-01").json()
    assert result["total"] == 1 and result["items"][0]["risk_code"] == "R-001"
    assert client.get("/api/v1/risks?search=%").json()["total"] == 0
    row = result["items"][0]
    params = {
        "asset_id": row["asset_id"],
        "level": "CRITICAL",
        "status": "OPEN",
        "treatment": "REDUCE",
        "owner": row["owner_user_id"],
        "threat": row["threat_id"],
        "vulnerability": row["vulnerability_id"],
    }
    assert client.get("/api/v1/risks", params=params).json()["total"] == 1
    page = client.get("/api/v1/risks?page_size=3&sort_by=score&sort_order=desc").json()
    assert len(page["items"]) == 3 and page["pages"] == 3
    assert [item["score"] for item in page["items"]] == [20, 15, 12]
    assert client.get("/api/v1/risks?search=Acceso%20no%20autorizado").json()["total"] >= 1
    assert client.get("/api/v1/risks/999999").status_code == 404


@pytest.mark.parametrize(
    "query",
    [
        "sort_by=score;DROP",
        "page=100001",
        "page_size=101",
        "probability=6",
        "owner=-1",
        "level=invalid",
    ],
)
def test_query_validation(client, query):
    login(client)
    assert client.get("/api/v1/risks?" + query).status_code == 422


def test_control_crud_traceability_and_logical_unlink(client):
    login(client)
    response = client.post("/api/v1/controls", json=control_draft())
    assert response.status_code == 201
    control = response.json()
    cp = f"/api/v1/controls/{control['id']}"
    assert client.post("/api/v1/controls", json=control_draft()).status_code == 409
    assert (
        client.patch(
            cp, json={"implementation_status": "IMPLEMENTED", "name": "Control actualizado Demo"}
        ).status_code
        == 200
    )
    risk = create(client).json()
    rp = f"/api/v1/risks/{risk['id']}"
    link = rp + f"/controls/{control['id']}"
    assert (
        client.post(
            link, json={"notes": "Free notes excluded from audit", "relationship_type": "DETECTIVE"}
        ).status_code
        == 201
    )
    assert client.post(link, json={}).status_code == 409
    assert client.get(cp).json()["risk_count"] == 1
    assert client.get(cp).json()["risks"][0]["id"] == risk["id"]
    assert client.get(rp).json()["controls"][0]["control"]["id"] == control["id"]
    assert client.delete(link).json()["active"] is False
    assert client.delete(link).status_code == 200
    assert client.get(rp + "/controls").json() == []
    with SessionLocal() as db:
        relation = db.get(RiskControl, (risk["id"], control["id"]))
        assert not relation.active and relation.disabled_at
    assert client.post(link, json={}).status_code == 201
    actions = {item["action"] for item in client.get(rp).json()["history"]}
    assert {"RISK_CONTROL_LINKED", "RISK_CONTROL_UNLINKED"} <= actions
    assert "Free notes excluded" not in str(client.get(rp).json()["history"])
    assert client.post(cp + "/disable").json()["active"] is False
    assert client.post(link, json={}).status_code == 409
    assert {"CONTROL_CREATED", "CONTROL_UPDATED", "CONTROL_STATUS_CHANGED", "CONTROL_DISABLED"} <= {
        item["action"] for item in client.get(cp).json()["history"]
    }
    assert client.patch(cp, json={"active": True}).json()["active"]


def test_missing_link_references(client):
    login(client)
    assert client.post("/api/v1/risks/999999/controls/1", json={}).status_code == 404
    assert client.post("/api/v1/risks/1/controls/999999", json={}).status_code == 404
    assert client.delete("/api/v1/risks/1/controls/999999").status_code == 404


def test_catalogs_controls_filters_dashboard(client):
    login(client)
    assert len(client.get("/api/v1/threats").json()) == 10
    assert len(client.get("/api/v1/vulnerabilities").json()) == 10
    assert (
        client.get("/api/v1/controls?category=IDENTITY&implementation_status=IMPLEMENTED").json()[
            "total"
        ]
        == 2
    )
    assert client.get("/api/v1/controls?search=MULTIFACTOR").json()["total"] == 1
    summary = client.get("/api/v1/dashboard").json()["risk_management"]
    assert summary["total"] == 8 and summary["controls_total"] == 10
    assert sum(item["value"] for item in summary["by_level"]) == 8
    assert sum(item["value"] for item in summary["controls_by_status"]) == 10


@pytest.mark.parametrize(
    "username",
    [
        "auditor.demo",
        "medico.demo",
        "admision.demo",
        "enfermeria.demo",
        "farmacia.demo",
        "laboratorio.demo",
    ],
)
def test_rbac_all_roles(client, username):
    response = login(client, username)
    if username == "medico.demo":
        assert response.json()["assurance"] == "PASSWORD_MFA"
    expected = 200 if username == "auditor.demo" else 403
    for path in (
        "/risks",
        "/risks/matrix",
        "/risks/summary",
        "/risks/options",
        "/controls",
        "/threats",
        "/vulnerabilities",
    ):
        assert client.get("/api/v1" + path).status_code == expected
    for path in (
        "/risks",
        "/controls",
        "/risks/1/close",
        "/controls/1/disable",
        "/risks/1/controls/1",
    ):
        assert client.post("/api/v1" + path, json={}).status_code == 403
    assert client.patch("/api/v1/risks/1", json={"probability": 4}).status_code == 403
    assert client.patch("/api/v1/controls/1", json={"active": False}).status_code == 403
    assert client.delete("/api/v1/risks/1/controls/1").status_code == 403
    if username != "auditor.demo":
        assert client.get("/api/v1/dashboard").json()["risk_management"] is None


def test_unauth_incomplete_mfa_jwt_csrf(client):
    assert client.get("/api/v1/risks").status_code == 401
    assert password_login(client).json()["status"] == "MFA_SETUP_REQUIRED"
    assert client.get("/api/v1/risks").status_code == 401
    login(client)
    client.headers.pop("X-CSRF-Token")
    assert create(client).status_code == 403
    client.cookies.set("sgsi_access", "tampered", domain="testserver.local", path="/")
    assert client.get("/api/v1/risks").status_code == 401


def test_seed_preserves_edits_closure_and_unlinks(client):
    login(client)
    row = client.get("/api/v1/risks?search=R-001").json()["items"][0]
    rp = f"/api/v1/risks/{row['id']}"
    control = client.get(rp).json()["controls"][0]["control"]
    assert (
        client.patch(
            rp, json={"title": "Edición manual conservada", "probability": 1, "impact": 1}
        ).status_code
        == 200
    )
    assert client.post(rp + "/close").status_code == 200
    assert client.delete(rp + f"/controls/{control['id']}").status_code == 200
    assert client.post(f"/api/v1/controls/{control['id']}/disable").status_code == 200
    with SessionLocal() as db:
        seed_risks(db)
        seed_risks(db)
        assert db.scalar(select(func.count(Risk.id))) == 8
        assert db.scalar(select(func.count(Control.id))) == 10
        assert db.scalar(select(func.count()).select_from(RiskControl)) == 8
        assert not db.get(RiskControl, (row["id"], control["id"])).active
    final = client.get(rp).json()
    assert (
        final["title"] == "Edición manual conservada"
        and final["status"] == "CLOSED"
        and final["score"] == 1
    )


def test_database_score_constraints():
    with SessionLocal() as db:
        row = db.scalar(select(Risk))
        row.score = 99
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_transaction_rolls_back_if_audit_fails(client, monkeypatch):
    login(client)
    from app.risks import service

    def fail(*args, **kwargs):
        raise RuntimeError("Injected audit failure")

    monkeypatch.setattr(service, "event", fail)
    with pytest.raises(RuntimeError):
        create(client)
    with SessionLocal() as db:
        assert not db.scalar(select(Risk).where(Risk.risk_code == "TEST-RISK-01"))
