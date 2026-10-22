"""Real deployed acceptance. Password/TOTP stay on the server; output is sanitized."""

import argparse
import json
import time
from contextlib import contextmanager
from datetime import UTC, datetime

import httpx
import pyotp
from sqlalchemy import select

from app.auth.mfa_service import decrypt_secret
from app.config import get_settings
from app.database import SessionLocal, now_utc
from app.models import Asset, MfaCredential, User


def deployed_url():
    settings = get_settings()
    return next(
        (
            value
            for value in settings.allowed_origins
            if value.startswith("https://") and value.endswith(".trycloudflare.com")
        ),
        "http://frontend:8080",
    )


@contextmanager
def authenticated_client(username, url, *, logout=True):
    headers = (
        {"Origin": url}
        if url.startswith("https://")
        else {"Host": "localhost:8090", "Origin": "http://localhost:8090"}
    )
    client = httpx.Client(base_url=url, headers=headers, trust_env=False, timeout=30)
    try:
        client.headers["X-CSRF-Token"] = client.get("/api/v1/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": username,
                "password": get_settings().demo_password.get_secret_value(),
            },
        )
        assert response.status_code == 200, "Deployed password login failed"
        data = response.json()
        if data["status"] != "AUTHENTICATED":
            assert not data["setup_required"], "Existing M2 enrollment must persist"
            assert client.get("/api/v1/assets").status_code == 401, "Assets accessible before MFA"
            with SessionLocal() as db:
                user = db.scalar(select(User).where(User.username == username))
                credential = db.scalar(
                    select(MfaCredential).where(MfaCredential.user_id == user.id)
                )
                totp = pyotp.TOTP(decrypt_secret(credential.secret_encrypted))
                last_step = credential.last_totp_step
            while totp.timecode(datetime.now(UTC)) <= last_step:
                time.sleep(1)
            response = client.post(
                "/api/v1/auth/mfa/verify",
                json={"challenge_token": data["challenge_token"], "code": totp.now()},
            )
            assert response.status_code == 200 and response.json()["assurance"] == "PASSWORD_MFA", (
                "Deployed MFA failed"
            )
        yield client
    finally:
        if logout:
            try:
                client.post("/api/v1/auth/logout")
            except httpx.HTTPError:
                pass
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["initial", "persistence", "public"], required=True)
    args = parser.parse_args()
    url = deployed_url()
    checks = {}
    with httpx.Client(
        base_url=url,
        headers={"Host": "localhost:8090"} if url.startswith("http:") else {},
        trust_env=False,
        timeout=30,
    ) as anonymous:
        assert anonymous.get("/api/v1/assets").status_code == 401
        assert anonymous.get("/api/v1/health").json()["database"] == "connected"
        for path in ("/login", "/dashboard", "/assets", "/assets/1", "/assets/new"):
            assert 'id="root"' in anonymous.get(path).text
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert anonymous.get(path).status_code in (403, 404)
    checks["same_origin_health_protected_assets_docs"] = "PASS"
    with authenticated_client("admin.demo", url) as admin:
        summary = admin.get("/api/v1/assets/summary").json()
        types = admin.get("/api/v1/asset-types").json()
        departments = admin.get("/api/v1/departments").json()
        owners = admin.get("/api/v1/assets/owners").json()
        assert len(types) == 10 and len(departments) == 7
        rows = admin.get("/api/v1/assets", params={"search": "TEST-DEMO-01"}).json()["items"]
        if args.phase == "initial":
            assert not rows, (
                "Acceptance demo asset already exists; preserve and inspect before rerun"
            )
            response = admin.post(
                "/api/v1/assets",
                json={
                    "asset_code": "TEST-DEMO-01",
                    "name": "Equipo Temporal de Demostración",
                    "asset_type_id": next(
                        item["id"] for item in types if item["name"] == "Desktop"
                    ),
                    "department_id": next(
                        item["id"] for item in departments if item["name"] == "TI"
                    ),
                    "owner_user_id": next(
                        item["id"] for item in owners if item["username"] == "admin.demo"
                    ),
                    "criticality": "HIGH",
                    "classification": "INTERNAL",
                    "monitoring_enabled": True,
                    "ip_address_demo": "192.0.2.30",
                    "hostname_demo": "test-demo-01",
                },
            )
            assert response.status_code == 201
            item = response.json()
            response = admin.patch(
                f"/api/v1/assets/{item['id']}",
                json={"criticality": "CRITICAL", "notes": "Persistencia M3 verificada"},
            )
            assert response.status_code == 200
            assert admin.get("/api/v1/assets/summary").json()["total"] == summary["total"] + 1
            assert admin.post(f"/api/v1/assets/{item['id']}/disable").json()["status"] == "RETIRED"
            assert admin.get("/api/v1/assets/summary").json()["monitored"] == summary["monitored"]
            checks["admin_mfa_create_edit_retire_counts"] = "PASS"
        else:
            assert len(rows) == 1
            item = rows[0]
            assert item["criticality"] == "CRITICAL" and item["status"] == "RETIRED"
            assert item["notes"] == "Persistencia M3 verificada"
            checks["asset_and_edit_persisted"] = "PASS"
        asset_id = item["id"]
        history = admin.get(f"/api/v1/assets/{asset_id}").json()["history"]
        assert {
            "ASSET_CREATED",
            "ASSET_UPDATED",
            "ASSET_CRITICALITY_CHANGED",
            "ASSET_DISABLED",
        } <= {entry["action"] for entry in history}
        checks["safe_history_audit"] = "PASS"
        assert (
            admin.get(
                "/api/v1/assets?criticality=HIGH&page_size=3&sort_by=asset_code&sort_order=desc"
            ).status_code
            == 200
        )
        assert admin.get("/api/v1/assets?page_size=10000000").status_code == 422
        assert admin.get("/api/v1/assets?sort_by=SQL").status_code == 422
        assert admin.post("/api/v1/auth/refresh").status_code == 200
        assert admin.post("/api/v1/auth/logout").status_code == 200
    for username in ("auditor.demo", "medico.demo", "admision.demo"):
        with authenticated_client(username, url) as client:
            if username == "auditor.demo":
                assert client.get("/api/v1/assets").status_code == 200
                assert client.post("/api/v1/assets", json={}).status_code == 403
            assert (
                client.patch(f"/api/v1/assets/{asset_id}", json={"criticality": "LOW"}).status_code
                == 403
            )
            assert client.post(f"/api/v1/assets/{asset_id}/disable").status_code == 403
            assert client.post("/api/v1/auth/logout").status_code == 200
        checks[username + "_rbac"] = "PASS"
    with SessionLocal() as db:
        assert db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
    print(
        json.dumps(
            {
                "status": "PASS",
                "phase": args.phase,
                "timestamp": now_utc().isoformat() + "Z",
                "database": "PostgreSQL",
                "asset_id": asset_id,
                "checks": checks,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
