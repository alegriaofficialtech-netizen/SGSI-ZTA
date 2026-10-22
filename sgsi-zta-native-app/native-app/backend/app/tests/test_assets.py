import json

import pytest
from sqlalchemy import func, select

from app.assets.seed import seed_assets
from app.database import SessionLocal
from app.models import Asset, AssetType, AuditLog, Department, User
from app.seed import seed
from app.tests.conftest import TEST_PASSWORD, login, password_login


def draft(**extra):
    with SessionLocal() as db:
        values = {
            "asset_code": "TEST-DEMO-01",
            "name": "Equipo Temporal Demo",
            "asset_type_id": db.scalar(select(AssetType.id).where(AssetType.name == "Server")),
            "department_id": db.scalar(select(Department.id).where(Department.name == "TI")),
            "owner_user_id": db.scalar(select(User.id).where(User.username == "admin.demo")),
            "criticality": "HIGH",
            "classification": "INTERNAL",
            "monitoring_enabled": True,
            "hostname_demo": "test-demo",
            "ip_address_demo": "192.0.2.30",
        }
        return values | extra


def first_asset(client):
    return client.get("/api/v1/assets").json()["items"][0]


def create(client, **extra):
    return client.post("/api/v1/assets", json=draft(**extra))


def test_create_asset_admin(client):
    assert login(client).json()["assurance"] == "PASSWORD_MFA"
    before = client.get("/api/v1/dashboard").json()["assets"]["total"]
    result = create(client)
    assert result.status_code == 201
    asset = result.json()
    assert asset["synthetic"] and asset["owner"]["username"] == "admin.demo"
    assert client.get("/api/v1/dashboard").json()["assets"]["total"] == before + 1
    assert "created_by" not in asset and "password_hash" not in str(asset)
    with SessionLocal() as db:
        record = db.get(Asset, asset["id"])
        assert record.created_by == record.updated_by == asset["owner_user_id"]


def test_create_asset_duplicate_code(client):
    login(client)
    assert create(client).status_code == 201
    assert create(client).status_code == 409


def test_create_asset_invalid_type(client):
    login(client)
    assert create(client, asset_type_id=99999).status_code == 422


def test_get_assets(client):
    login(client)
    result = client.get("/api/v1/assets").json()
    assert result["total"] == len(result["items"]) == 10
    assert result["pages"] == 1
    assert len(client.get("/api/v1/asset-types").json()) == 10
    assert len(client.get("/api/v1/departments").json()) == 7


def test_get_asset_by_id(client):
    login(client)
    item = first_asset(client)
    assert client.get(f"/api/v1/assets/{item['id']}").json()["asset_code"] == item["asset_code"]
    assert client.get("/api/v1/assets/999999").status_code == 404


def test_update_asset_admin(client):
    login(client)
    item = first_asset(client)
    result = client.patch(f"/api/v1/assets/{item['id']}", json={"name": "Nombre actualizado Demo"})
    assert result.status_code == 200 and result.json()["name"] == "Nombre actualizado Demo"
    assert result.json()["criticality"] == item["criticality"]


def test_update_asset_audit_created(client):
    login(client)
    item = create(client).json()
    with SessionLocal() as db:
        owner = db.scalar(select(User.id).where(User.username == "medico.demo"))
    result = client.patch(
        f"/api/v1/assets/{item['id']}",
        json={
            "criticality": "CRITICAL",
            "classification": "RESTRICTED",
            "status": "MAINTENANCE",
            "owner_user_id": owner,
            "notes": "Demo notes omitted from audit",
        },
    )
    assert result.status_code == 200
    history = client.get(f"/api/v1/assets/{item['id']}").json()["history"]
    assert {row["action"] for row in history} >= {
        "ASSET_CREATED",
        "ASSET_UPDATED",
        "ASSET_CRITICALITY_CHANGED",
        "ASSET_OWNER_CHANGED",
        "ASSET_STATUS_CHANGED",
        "ASSET_CLASSIFICATION_CHANGED",
    }
    changed = next(row for row in history if row["action"] == "ASSET_CRITICALITY_CHANGED")
    assert json.loads(changed["detail"])["before"] == "HIGH"
    assert json.loads(changed["detail"])["after"] == "CRITICAL"
    assert changed["username"] == "admin.demo" and changed["resource"] == f"assets/{item['id']}"
    assert "Demo notes omitted" not in str(history)


def test_disable_asset(client):
    login(client)
    item = create(client).json()
    before = client.get("/api/v1/assets/summary").json()
    result = client.post(f"/api/v1/assets/{item['id']}/disable").json()
    assert (
        result["status"] == "RETIRED" and result["disabled_at"] and not result["monitoring_enabled"]
    )
    assert client.get(f"/api/v1/assets/{item['id']}").status_code == 200
    assert client.delete(f"/api/v1/assets/{item['id']}").status_code == 405
    after = client.get("/api/v1/assets/summary").json()
    assert after["total"] == before["total"] and after["monitored"] == before["monitored"] - 1
    assert sum(row["value"] for row in after["by_status"]) == after["total"]
    assert client.post(f"/api/v1/assets/{item['id']}/disable").status_code == 200
    with SessionLocal() as db:
        assert (
            db.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.resource == f"assets/{item['id']}", AuditLog.action == "ASSET_DISABLED"
                )
            )
            == 1
        )
    assert (
        client.patch(
            f"/api/v1/assets/{item['id']}", json={"status": "ACTIVE", "monitoring_enabled": True}
        ).json()["disabled_at"]
        is None
    )


def test_auditor_can_read_asset(client):
    login(client, "auditor.demo")
    assert client.get("/api/v1/assets").status_code == 200
    assert client.get(f"/api/v1/assets/{first_asset(client)['id']}").status_code == 200


def test_auditor_cannot_create_asset(client):
    login(client, "auditor.demo")
    assert create(client).status_code == 403
    item = first_asset(client)
    assert (
        client.patch(f"/api/v1/assets/{item['id']}", json={"criticality": "LOW"}).status_code == 403
    )
    assert client.post(f"/api/v1/assets/{item['id']}/disable").status_code == 403
    assert client.get("/api/v1/assets/owners").status_code == 403


def test_medico_cannot_modify_asset(client):
    assert login(client, "medico.demo").json()["assurance"] == "PASSWORD_MFA"
    assert client.patch("/api/v1/assets/1", json={"name": "Medico Demo"}).status_code == 403
    assert client.get("/api/v1/assets").status_code == 403
    assert client.get("/api/v1/dashboard").json()["assets"] is None


def test_admision_cannot_disable_asset(client):
    login(client, "admision.demo")
    assert client.post("/api/v1/assets/1/disable").status_code == 403


@pytest.mark.parametrize("username", ["farmacia.demo", "laboratorio.demo", "enfermeria.demo"])
def test_operational_roles_have_no_inventory(client, username):
    login(client, username)
    for path in ("assets", "asset-types", "departments", "assets/summary"):
        assert client.get(f"/api/v1/{path}").status_code == 403


def test_asset_pagination(client):
    login(client)
    first = client.get("/api/v1/assets?page=1&page_size=3").json()
    second = client.get("/api/v1/assets?page=2&page_size=3").json()
    assert first["total"] == 10 and first["pages"] == 4
    assert not {item["id"] for item in first["items"]} & {item["id"] for item in second["items"]}
    assert client.get("/api/v1/assets?page=9&page_size=3").json()["items"] == []


@pytest.mark.parametrize(
    "search,code",
    [("srv-his", "SRV-HIS-01"), ("Servidor HIS", "SRV-HIS-01"), ("lap-med-demo", "LAP-MED-01")],
)
def test_asset_search(client, search, code):
    login(client)
    assert code in {
        item["asset_code"]
        for item in client.get("/api/v1/assets", params={"search": search}).json()["items"]
    }
    assert client.get("/api/v1/assets", params={"search": "%_"}).json()["total"] == 0


def test_asset_filter_criticality(client):
    login(client)
    rows = client.get("/api/v1/assets?criticality=CRITICAL").json()
    assert rows["total"] == 2 and all(item["criticality"] == "CRITICAL" for item in rows["items"])


def test_asset_filter_department(client):
    login(client)
    department = draft()["department_id"]
    rows = client.get(
        f"/api/v1/assets?department={department}&classification=RESTRICTED&status=ACTIVE&monitoring_enabled=false"
    ).json()["items"]
    assert len(rows) == 1 and rows[0]["asset_code"] == "BKP-HIS-01"
    result = client.get(f"/api/v1/assets?asset_type={draft()['asset_type_id']}").json()
    assert result["total"] == 1


def test_asset_sort(client):
    login(client)
    rows = client.get("/api/v1/assets?sort_by=asset_code&sort_order=desc").json()["items"]
    assert [row["asset_code"] for row in rows] == sorted(
        [row["asset_code"] for row in rows], reverse=True
    )
    assert (
        client.get("/api/v1/assets?sort_by=criticality&sort_order=desc").json()["items"][0][
            "criticality"
        ]
        == "CRITICAL"
    )


def test_asset_owner_relation(client):
    login(client)
    with SessionLocal() as db:
        owner = db.scalar(select(User.id).where(User.username == "medico.demo"))
    item = create(client, owner_user_id=owner).json()
    assert item["owner"]["username"] == "medico.demo"
    assert create(client, asset_code="BAD-OWNER-01", owner_user_id=99999).status_code == 422
    assert create(client, asset_code="BAD-AREA-01", department_id=99999).status_code == 422
    with SessionLocal() as db:
        db.get(User, owner).is_active = False
        db.commit()
    assert create(client, asset_code="INACTIVE-OWNER", owner_user_id=owner).status_code == 422


def test_asset_seed_idempotent():
    with SessionLocal() as db:
        row = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
        row.name = "Operator edit Demo"
        row.status = "MAINTENANCE"
        db.commit()
        seed_assets(db)
        seed(db, TEST_PASSWORD)
        assert db.scalar(select(func.count(Asset.id))) == 10
        assert db.scalar(select(func.count(AssetType.id))) == 10
        assert db.scalar(select(func.count(Department.id))) == 7
        assert db.get(Asset, row.id).name == "Operator edit Demo" and row.status == "MAINTENANCE"


def test_assets_require_session_and_mfa(client):
    assert client.get("/api/v1/assets").status_code == 401
    assert password_login(client).json()["status"] == "MFA_SETUP_REQUIRED"
    assert client.get("/api/v1/assets").status_code == 401
    assert create(client).status_code == 401


def test_assets_tampered_jwt_denied(client):
    login(client)
    parts = client.cookies.get("sgsi_access").split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    client.cookies.set("sgsi_access", ".".join(parts), domain="testserver.local", path="/api/v1")
    assert client.get("/api/v1/assets").status_code == 401


@pytest.mark.parametrize(
    "changes",
    [
        {"asset_code": "X'; DROP TABLE assets;--"},
        {"criticality": "URGENT"},
        {"status": "DELETED"},
        {"classification": "SECRET"},
        {"ip_address_demo": "10.0.0.1"},
        {"ip_address_demo": "192.0.2.999"},
        {"ip_address_demo": "::1"},
        {"id": 1},
        {"created_by": 1},
        {"created_at": "2020-01-01"},
        {"synthetic": False},
    ],
)
def test_asset_validation_and_mass_assignment(client, changes):
    login(client)
    assert create(client, **changes).status_code == 422
    assert (
        client.patch(f"/api/v1/assets/{first_asset(client)['id']}", json=changes).status_code == 422
    )


@pytest.mark.parametrize(
    "query",
    [
        "page_size=10000000",
        "page=0",
        "page=100001",
        "sort_by=name;DROP",
        "sort_order=random",
        "criticality=URGENT",
    ],
)
def test_asset_query_bounds(client, query):
    login(client)
    assert client.get(f"/api/v1/assets?{query}").status_code == 422


def test_asset_csrf_required(client):
    login(client)
    del client.headers["X-CSRF-Token"]
    assert create(client).status_code == 403


def test_asset_partial_updates_and_null_validation(client):
    login(client)
    item = create(client).json()
    path = f"/api/v1/assets/{item['id']}"
    assert client.patch(path, json={"name": None}).status_code == 422
    assert client.patch(path, json={"ip_address_demo": None}).json()["ip_address_demo"] is None
    assert client.patch(path, json={}).status_code == 200
    assert client.patch(path, json={"asset_code": "SRV-HIS-01"}).status_code == 409


def test_asset_history_scoped_and_dashboard_counts(client):
    login(client)
    first = create(client).json()
    second = create(client, asset_code="TEST-DEMO-02").json()
    history = client.get(f"/api/v1/assets/{first['id']}").json()["history"]
    assert all(entry["resource"] != f"assets/{second['id']}" for entry in history)
    summary = client.get("/api/v1/dashboard").json()["assets"]
    with SessionLocal() as db:
        assert summary["total"] == db.scalar(select(func.count(Asset.id)))
    for dimension in ("by_status", "by_type", "by_department", "by_criticality"):
        assert sum(item["value"] for item in summary[dimension]) == summary["total"]
