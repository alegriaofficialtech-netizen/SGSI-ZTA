"""Deployed PostgreSQL acceptance. Uses existing M2 credentials only in memory."""

import argparse
import json
from datetime import UTC, datetime

import httpx
from sqlalchemy import select

from app.assets.acceptance import authenticated_client, deployed_url
from app.database import SessionLocal
from app.models import Risk, RiskControl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["initial", "persistence", "public"], required=True)
    phase = parser.parse_args().phase
    url = deployed_url()
    checks = {}
    with httpx.Client(
        base_url=url,
        headers={"Host": "localhost:8090"} if url.startswith("http:") else {},
        trust_env=False,
        timeout=30,
    ) as anonymous:
        for path in ("/risks", "/risks/matrix", "/controls", "/threats"):
            assert anonymous.get("/api/v1" + path).status_code == 401
        for path in ("/login", "/dashboard", "/assets", "/risks", "/risks/matrix", "/controls"):
            assert 'id="root"' in anonymous.get(path).text
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert anonymous.get(path).status_code in (403, 404)
    checks["protected_routes_docs"] = "PASS"
    with authenticated_client("admin.demo", url) as admin:
        options = admin.get("/api/v1/risks/options").json()
        owner = next(row["id"] for row in options["owners"] if row["username"] == "admin.demo")
        asset = next(row["id"] for row in options["assets"] if row["asset_code"] == "SRV-HIS-01")
        threats = admin.get("/api/v1/threats").json()
        vulnerabilities = admin.get("/api/v1/vulnerabilities").json()
        assert len(threats) == len(vulnerabilities) == 10
        seeded = admin.get("/api/v1/risks?search=R-001").json()["items"][0]
        assert seeded["score"] == 20 and seeded["level"] == "CRITICAL"
        seeded_links = admin.get(f"/api/v1/risks/{seeded['id']}/controls").json()
        assert {"CTRL-001", "CTRL-002", "CTRL-004"} <= {
            row["control"]["control_code"] for row in seeded_links
        }
        if phase == "initial":
            assert admin.get("/api/v1/risks?search=TEST-M4-RISK").json()["total"] == 0, (
                "Preserve existing acceptance data before rerun"
            )
            response = admin.post(
                "/api/v1/risks",
                json={
                    "risk_code": "TEST-M4-RISK",
                    "title": "Escenario Temporal Demo M4",
                    "description": "Persistencia M4 verificada",
                    "asset_id": asset,
                    "threat_id": threats[0]["id"],
                    "vulnerability_id": vulnerabilities[1]["id"],
                    "probability": 3,
                    "impact": 3,
                    "owner_user_id": owner,
                    "score": 99,
                    "level": "CRITICAL",
                },
            )
            assert response.status_code == 201
            risk = response.json()
            assert risk["score"] == 9 and risk["level"] == "MEDIUM"
            rp = f"/api/v1/risks/{risk['id']}"
            assert (
                admin.patch(
                    rp, json={"probability": 4, "impact": 5, "status": "IN_TREATMENT"}
                ).json()["score"]
                == 20
            )
            assert admin.post(rp + "/close").json()["closed_at"]
            assert admin.patch(rp, json={"status": "IN_TREATMENT"}).json()["closed_at"] is None
            response = admin.post(
                "/api/v1/controls",
                json={
                    "control_code": "TEST-M4-CTRL",
                    "name": "Medida Temporal Demo M4",
                    "description": "Control académico para comprobar persistencia",
                    "category": "GOVERNANCE",
                    "implementation_status": "PLANNED",
                    "owner_user_id": owner,
                },
            )
            assert response.status_code == 201
            control = response.json()
            cp = f"/api/v1/controls/{control['id']}"
            assert admin.patch(cp, json={"implementation_status": "IMPLEMENTED"}).status_code == 200
            assert admin.post(cp + "/disable").json()["active"] is False
            assert admin.patch(cp, json={"active": True}).json()["active"]
            link = rp + f"/controls/{control['id']}"
            assert (
                admin.post(
                    link,
                    json={"notes": "Persistencia M4 verificada", "relationship_type": "DETECTIVE"},
                ).status_code
                == 201
            )
            assert admin.post(link, json={}).status_code == 409
            assert admin.delete(link).json()["active"] is False
            assert (
                admin.post(
                    link,
                    json={"notes": "Persistencia M4 verificada", "relationship_type": "DETECTIVE"},
                ).status_code
                == 201
            )
            checks["admin_mfa_crud_close_reopen_control_link_unlink"] = "PASS"
        risk = admin.get("/api/v1/risks?search=TEST-M4-RISK").json()["items"][0]
        rp = f"/api/v1/risks/{risk['id']}"
        detail = admin.get(rp).json()
        assert (
            detail["score"] == 20
            and detail["level"] == "CRITICAL"
            and detail["status"] == "IN_TREATMENT"
        )
        assert detail["description"] == "Persistencia M4 verificada"
        link = next(
            row for row in detail["controls"] if row["control"]["control_code"] == "TEST-M4-CTRL"
        )
        assert (
            link["notes"] == "Persistencia M4 verificada"
            and link["relationship_type"] == "DETECTIVE"
        )
        assert (
            link["control"]["active"] and link["control"]["implementation_status"] == "IMPLEMENTED"
        )
        assert {
            "RISK_CREATED",
            "RISK_SCORE_CHANGED",
            "RISK_LEVEL_CHANGED",
            "RISK_STATUS_CHANGED",
            "RISK_CLOSED",
            "RISK_CONTROL_LINKED",
            "RISK_CONTROL_UNLINKED",
        } <= {row["action"] for row in detail["history"]}
        matrix = admin.get("/api/v1/risks/matrix").json()
        assert (
            len(matrix["cells"]) == 25
            and sum(row["count"] for row in matrix["cells"]) == matrix["total"]
        )
        cell = next(
            row for row in matrix["cells"] if row["probability"] == 4 and row["impact"] == 5
        )
        assert cell["level"] == "CRITICAL" and cell["score"] == 20 and cell["count"] >= 2
        assert (
            admin.get("/api/v1/risks?probability=4&impact=5&exclude_closed=true").json()["total"]
            == cell["count"]
        )
        summary = admin.get("/api/v1/dashboard").json()["risk_management"]
        assert summary["total"] >= 9 and summary["controls_total"] >= 11
        assert sum(row["value"] for row in summary["by_level"]) == summary["total"]
        for query in ("probability=100", "impact=-1", "sort_by=SQL", "page_size=100000"):
            assert admin.get("/api/v1/risks?" + query).status_code == 422
        assert admin.patch(rp, json={"score": 100, "level": "LOW"}).status_code == 422
        assert admin.post("/api/v1/auth/refresh").status_code == 200
        checks["persistence_matrix_summary_safe_audit"] = "PASS"
        risk_id = risk["id"]
        control_id = link["control_id"]
    for username in ("auditor.demo", "medico.demo", "admision.demo"):
        with authenticated_client(username, url) as client:
            expected = 200 if username == "auditor.demo" else 403
            for path in ("/risks", "/risks/matrix", "/controls"):
                assert client.get("/api/v1" + path).status_code == expected
            assert client.post("/api/v1/risks", json={}).status_code == 403
            assert (
                client.patch(f"/api/v1/risks/{risk_id}", json={"probability": 1}).status_code == 403
            )
            assert client.post(f"/api/v1/risks/{risk_id}/close").status_code == 403
            assert (
                client.post(f"/api/v1/risks/{risk_id}/controls/{control_id}", json={}).status_code
                == 403
            )
            assert (
                client.delete(f"/api/v1/risks/{risk_id}/controls/{control_id}").status_code == 403
            )
            assert (
                client.patch(f"/api/v1/controls/{control_id}", json={"active": False}).status_code
                == 403
            )
        checks[username + "_rbac"] = "PASS"
    with SessionLocal() as db:
        row = db.scalar(select(Risk).where(Risk.risk_code == "TEST-M4-RISK"))
        assert db.get(RiskControl, (row.id, control_id)).active
    print(
        json.dumps(
            {
                "status": "PASS",
                "phase": phase,
                "database": "PostgreSQL",
                "timestamp": datetime.now(UTC).isoformat(),
                "checks": checks,
                "risk_id": risk_id,
                "control_id": control_id,
                "summary": summary,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
