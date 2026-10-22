import secrets
from datetime import timedelta

import jwt
from sqlalchemy import func, inspect, select

from app.auth.security import decode_access, digest
from app.config import get_settings
from app.database import SessionLocal, engine, now_utc
from app.models import AuditLog, RefreshToken, Role, User
from app.seed import seed
from app.tests.conftest import TEST_PASSWORD, login, ready_client


def audit_actions() -> list[str]:
    with SessionLocal() as db:
        return list(db.scalars(select(AuditLog.action)).all())


def test_health_database_connected(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_migration_tables_exist():
    assert set(inspect(engine).get_table_names()) >= {
        "users",
        "roles",
        "user_roles",
        "groups",
        "user_groups",
        "sessions",
        "refresh_tokens",
        "audit_logs",
        "login_rate_limits",
        "alembic_version",
    }


def test_seed_idempotent_and_mfa_metadata():
    with SessionLocal() as db:
        original = db.scalar(select(User).where(User.username == "admin.demo")).password_hash
        seed(db, TEST_PASSWORD)
        assert db.scalar(select(func.count(User.id))) == 7
        assert db.scalar(select(func.count(Role.id))) == 7
        assert (
            db.scalar(select(User).where(User.username == "admin.demo")).password_hash == original
        )
        required = set(db.scalars(select(Role.name).where(Role.mfa_required.is_(True))))
        assert required == {"admin-ti", "medico"}


def test_login_success(client):
    response = login(client)
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "admin.demo"
    assert response.json()["assurance"] == "PASSWORD_MFA"
    assert response.json()["mfa_status"] == "VERIFIED"
    assert "access_token" not in response.json()
    assert client.get("/api/v1/auth/me").status_code == 200
    assert "LOGIN_SUCCESS" in audit_actions()


def test_login_invalid_password(client):
    response = client.post(
        "/api/v1/auth/login", json={"username": "admin.demo", "password": "invalid"}
    )
    assert response.status_code == 401
    assert not client.cookies.get("sgsi_access")
    assert "LOGIN_FAILED" in audit_actions()


def test_unknown_user_has_same_public_error(client):
    a = client.post("/api/v1/auth/login", json={"username": "unknown.demo", "password": "wrong"})
    b = client.post("/api/v1/auth/login", json={"username": "admin.demo", "password": "wrong"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_password_hashed_and_not_serialized(client):
    login(client)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin.demo"))
        assert user.password_hash.startswith("$argon2id$")
        assert user.password_hash != TEST_PASSWORD
    body = client.get("/api/v1/users").text
    assert "password" not in body and TEST_PASSWORD not in body and "$argon2" not in body


def test_cookies_httponly_and_scoped(client):
    response = login(client)
    cookies = response.headers.get_list("set-cookie")
    assert any("sgsi_access=" in c and "HttpOnly" in c and "Path=/api/v1;" in c for c in cookies)
    assert any(
        "sgsi_refresh=" in c and "HttpOnly" in c and "Path=/api/v1/auth;" in c for c in cookies
    )
    assert all("SameSite=strict" in c for c in cookies)


def test_remember_persists_csrf_and_session_cookies(client):
    response = login(client, remember=True)
    assert all("Max-Age=" in cookie for cookie in response.headers.get_list("set-cookie"))
    assert not client.get("/api/v1/auth/csrf").headers.get_list("set-cookie")
    assert client.post("/api/v1/auth/refresh").status_code == 200


def test_protected_requires_login(client):
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/api/v1/dashboard").status_code == 401


def test_role_enforcement_backend(client):
    login(client, "admision.demo")
    assert client.get("/api/v1/users").status_code == 403
    assert client.get("/api/v1/dashboard").json()["scope"] == "own"
    assert "AUTHORIZATION_DENIED" in audit_actions()


def test_client_role_spoof_denied(client):
    login(client, "medico.demo")
    response = client.post(
        "/api/v1/users",
        json={
            "username": "spoof.demo",
            "display_name": "Spoof Demo",
            "department": "Demo",
            "password": TEST_PASSWORD,
            "roles": ["admin-ti"],
        },
    )
    assert response.status_code == 403


def test_jwt_claims_and_expiry(client):
    login(client)
    token = client.cookies.get("sgsi_access")
    claims = decode_access(token)
    assert {"sub", "sid", "exp", "iat", "nbf", "iss", "aud", "type"} <= set(claims)
    assert "role" not in claims
    claims["exp"] = now_utc() - timedelta(seconds=1)
    expired = jwt.encode(claims, get_settings().jwt_secret.get_secret_value(), algorithm="HS256")
    client.cookies.set("sgsi_access", expired, domain="testserver.local", path="/api/v1")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_tampered_jwt_rejected(client):
    login(client)
    parts = client.cookies.get("sgsi_access").split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    client.cookies.set("sgsi_access", ".".join(parts), domain="testserver.local", path="/api/v1")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_refresh_rotation_and_hash_only_storage(client):
    login(client)
    original = client.cookies.get("sgsi_refresh")
    assert client.post("/api/v1/auth/refresh").status_code == 200
    assert client.cookies.get("sgsi_refresh") != original
    with SessionLocal() as db:
        tokens = list(db.scalars(select(RefreshToken)).all())
        assert len(tokens) == 2
        assert all(token.token_hash != original for token in tokens)
        assert any(token.token_hash == digest(original) and token.used_at for token in tokens)


def test_refresh_reuse_revokes_entire_session(client):
    login(client)
    old = client.cookies.get("sgsi_refresh")
    assert client.post("/api/v1/auth/refresh").status_code == 200
    client.cookies.set("sgsi_refresh", old, domain="testserver.local", path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401
    assert "REFRESH_REUSE_DETECTED" in audit_actions()


def test_logout_revocation(client):
    login(client)
    access = client.cookies.get("sgsi_access")
    refresh = client.cookies.get("sgsi_refresh")
    csrf = client.headers["X-CSRF-Token"]
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert not client.cookies.get("sgsi_access")
    client.cookies.set("sgsi_access", access, domain="testserver.local", path="/api/v1")
    client.cookies.set("sgsi_refresh", refresh, domain="testserver.local", path="/api/v1/auth")
    client.cookies.set("sgsi_csrf", csrf, domain="testserver.local", path="/")
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.post("/api/v1/auth/refresh").status_code == 401
    assert "LOGOUT" in audit_actions()


def test_csrf_required_even_on_login(client):
    del client.headers["X-CSRF-Token"]
    assert login(client).status_code == 403


def test_csrf_session_binding(client):
    login(client)
    fake = secrets.token_urlsafe(32)
    client.cookies.set("sgsi_csrf", fake, domain="testserver.local", path="/")
    client.headers["X-CSRF-Token"] = fake
    assert client.post("/api/v1/auth/refresh").status_code == 403


def test_cross_origin_rejected(client):
    assert (
        client.post(
            "/api/v1/auth/login",
            headers={"Origin": "https://evil.invalid"},
            json={
                "username": "admin.demo",
                "password": TEST_PASSWORD,
            },
        ).status_code
        == 403
    )


def test_rate_limited_and_audited(client):
    for _ in range(get_settings().login_limit):
        assert (
            client.post(
                "/api/v1/auth/login", json={"username": "unknown.demo", "password": "wrong"}
            ).status_code
            == 401
        )
    response = client.post(
        "/api/v1/auth/login", json={"username": "unknown.demo", "password": "wrong"}
    )
    assert response.status_code == 429 and "Retry-After" in response.headers
    assert "LOGIN_RATE_LIMITED" in audit_actions()
    assert login(client, "admision.demo").status_code == 200


def test_user_create_update_disable_preserves_audit(client):
    login(client)
    response = client.post(
        "/api/v1/users",
        json={
            "username": "nuevo.demo",
            "display_name": "Nuevo Demo",
            "department": "Demo",
            "password": TEST_PASSWORD,
            "roles": ["admision"],
        },
    )
    assert response.status_code == 201
    user_id = response.json()["id"]
    assert (
        client.patch(f"/api/v1/users/{user_id}", json={"display_name": "Editado Demo"}).status_code
        == 200
    )
    assert (
        client.patch(f"/api/v1/users/{user_id}", json={"is_active": False}).json()["is_active"]
        is False
    )
    assert client.delete(f"/api/v1/users/{user_id}").status_code == 405
    assert {"USER_CREATED", "USER_UPDATED"} <= set(audit_actions())


def test_disable_user_revokes_existing_session(client):
    with ready_client() as other:
        login(other, "admision.demo")
        other_id = other.get("/api/v1/auth/me").json()["id"]
        login(client)
        assert (
            client.patch(f"/api/v1/users/{other_id}", json={"is_active": False}).status_code == 200
        )
        assert other.get("/api/v1/auth/me").status_code == 401
        assert login(other, "admision.demo").status_code == 401


def test_cannot_disable_or_demote_self(client):
    user_id = login(client).json()["user"]["id"]
    assert client.patch(f"/api/v1/users/{user_id}", json={"is_active": False}).status_code == 409
    assert client.patch(f"/api/v1/users/{user_id}", json={"roles": ["admision"]}).status_code == 409


def test_strong_password_and_validation_do_not_echo_secret(client):
    login(client)
    response = client.post(
        "/api/v1/users",
        json={
            "username": "weak.demo",
            "display_name": "Weak Demo",
            "department": "Demo",
            "password": "weak-secret-unique",
            "roles": ["admision"],
        },
    )
    assert response.status_code == 422
    assert "weak-secret-unique" not in response.text


def test_auditor_can_read_audit_but_cannot_manage_users(client):
    login(client, "auditor.demo")
    assert client.get("/api/v1/audit").status_code == 200
    assert client.get("/api/v1/users").status_code == 403


def test_audit_immutable_api_and_no_credentials(client):
    login(client)
    rows = client.get("/api/v1/audit").json()
    assert rows and any(r["action"] == "LOGIN_SUCCESS" for r in rows)
    for method in ["post", "patch", "delete"]:
        assert getattr(client, method)("/api/v1/audit").status_code == 405
    serialized = str(rows)
    assert TEST_PASSWORD not in serialized
    assert client.cookies.get("sgsi_access") not in serialized
    assert client.cookies.get("sgsi_refresh") not in serialized


def test_session_owner_enforced(client):
    with ready_client() as other:
        login(other, "admision.demo")
        other_session = other.get("/api/v1/auth/sessions").json()[0]["id"]
        login(client)
        assert client.delete(f"/api/v1/auth/sessions/{other_session}").status_code == 404
        own = client.get("/api/v1/auth/sessions").json()[0]["id"]
        assert client.delete(f"/api/v1/auth/sessions/{own}").status_code == 200
        assert client.get("/api/v1/auth/me").status_code == 401


def test_dashboard_values_come_from_database(client):
    login(client)
    data = client.get("/api/v1/dashboard").json()
    with SessionLocal() as db:
        assert data["active_users"] == db.scalar(
            select(func.count(User.id)).where(User.is_active.is_(True))
        )
        assert data["events_24h"] == db.scalar(select(func.count(AuditLog.id)))
        from app.models import MfaCredential

        assert data["mfa_enabled_users"] == db.scalar(
            select(func.count(MfaCredential.id)).where(MfaCredential.enabled.is_(True))
        )
        assert data["logins_24h"] == db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.action == "LOGIN_SUCCESS")
        )
    assert len(data["activity"]) == 24
    assert sum(bucket["allow"] for bucket in data["activity"]) == data["events_24h"]


def test_secure_headers(client):
    response = client.get("/api/v1/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
