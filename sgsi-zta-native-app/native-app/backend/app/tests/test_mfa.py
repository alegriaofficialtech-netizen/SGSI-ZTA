import json
from datetime import timedelta

import pyotp
from sqlalchemy import func, select

from app.auth.mfa_service import decrypt_secret
from app.config import get_settings
from app.database import SessionLocal, now_utc
from app.models import AuditLog, MfaChallenge, MfaCredential, RecoveryCode, User, UserSession
from app.tests.conftest import TEST_PASSWORD, login, password_login, ready_client


def enrollment(client, username="medico.demo"):
    result = password_login(client, username).json()
    token = result["challenge_token"]
    setup = client.post("/api/v1/auth/mfa/setup", json={"challenge_token": token})
    assert setup.status_code == 200
    return token, pyotp.parse_uri(setup.json()["provisioning_uri"]).secret


def activate(client, username="medico.demo"):
    token, secret = enrollment(client, username)
    result = client.post(
        "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": pyotp.TOTP(secret).now()}
    )
    assert result.status_code == 200
    return token, secret, result


def actions():
    with SessionLocal() as db:
        return set(db.scalars(select(AuditLog.action)))


def test_medico_requires_mfa(client):
    result = password_login(client, "medico.demo")
    assert result.json()["status"] == "MFA_SETUP_REQUIRED"
    assert not client.cookies.get("sgsi_access")


def test_admin_requires_mfa(client):
    assert password_login(client, "admin.demo").json()["status"] == "MFA_SETUP_REQUIRED"


def test_admision_does_not_require_mfa(client):
    result = password_login(client, "admision.demo")
    assert result.json()["status"] == "AUTHENTICATED"
    assert result.json()["assurance"] == "PASSWORD_ONLY"
    assert client.get("/api/v1/dashboard").status_code == 200


def test_mfa_setup(client):
    token, secret = enrollment(client)
    with SessionLocal() as db:
        challenge = db.scalar(select(MfaChallenge))
        assert challenge.token_hash != token
        assert challenge.secret_encrypted != secret
        assert decrypt_secret(challenge.secret_encrypted) == secret
        assert db.scalar(select(func.count(UserSession.id))) == 0
    assert "MFA_SETUP_STARTED" in actions()


def test_mfa_secret_not_returned_after_setup(client):
    token, secret, result = activate(client)
    for path in ["/api/v1/auth/me", "/api/v1/dashboard", "/api/v1/auth/sessions"]:
        body = client.get(path).text
        assert secret not in body and "provisioning_uri" not in body
    assert secret not in result.text
    assert client.post("/api/v1/auth/mfa/setup", json={"challenge_token": token}).status_code == 401


def test_invalid_totp_denied(client):
    token, secret = enrollment(client)
    wrong = "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": wrong}
        ).status_code
        == 401
    )
    assert not client.cookies.get("sgsi_access")


def test_valid_totp_allowed(client):
    _, _, result = activate(client)
    assert result.json()["assurance"] == "PASSWORD_MFA"
    assert result.json()["user"]["mfa_enabled"] is True
    assert client.get("/api/v1/dashboard").status_code == 200


def test_mfa_incomplete_cannot_access_protected_route(client):
    password_login(client, "medico.demo")
    for path in [
        "/api/v1/users",
        "/api/v1/dashboard",
        "/api/v1/auth/sessions",
        "/api/v1/auth/me",
        "/api/v1/audit",
    ]:
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_expired_mfa_challenge_denied(client):
    token, secret = enrollment(client)
    with SessionLocal() as db:
        db.scalar(select(MfaChallenge)).expires_at = now_utc() - timedelta(seconds=1)
        db.commit()
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
        ).status_code
        == 401
    )


def test_mfa_success_audited(client):
    activate(client)
    assert {
        "MFA_CHALLENGE",
        "MFA_SETUP_STARTED",
        "MFA_ENABLED",
        "MFA_SUCCESS",
        "LOGIN_SUCCESS",
    } <= actions()


def test_mfa_failure_audited(client):
    token, _ = enrollment(client)
    client.post("/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": "abcdef"})
    assert "MFA_FAILED" in actions()


def test_totp_secret_not_exposed_in_api(client):
    _, secret, _ = activate(client, "admin.demo")
    for path in ["/api/v1/users", "/api/v1/audit", "/api/v1/auth/me"]:
        text = client.get(path).text
        assert secret not in text and "secret_encrypted" not in text and "otpauth://" not in text
    with SessionLocal() as db:
        serialized = json.dumps(
            [{"action": row.action, "detail": row.detail} for row in db.scalars(select(AuditLog))]
        )
        assert secret not in serialized and TEST_PASSWORD not in serialized


def test_challenge_bound_to_browser_csrf(client):
    token, secret = enrollment(client)
    with ready_client() as other:
        assert (
            other.post(
                "/api/v1/auth/mfa/verify",
                json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
            ).status_code
            == 403
        )


def test_challenge_token_is_not_an_access_token(client):
    token, _ = enrollment(client)
    client.cookies.set("sgsi_access", token, domain="testserver.local", path="/api/v1")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_challenge_attempts_exhausted(client):
    token, secret = enrollment(client)
    for _ in range(get_settings().mfa_max_attempts):
        assert (
            client.post(
                "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": "abcdef"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
        ).status_code
        == 401
    )


def test_totp_replay_denied(client):
    _, secret, _ = activate(client)
    client.post("/api/v1/auth/logout")
    client.headers["X-CSRF-Token"] = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    token = password_login(client, "medico.demo").json()["challenge_token"]
    with SessionLocal() as db:
        credential = db.scalar(select(MfaCredential))
        code = pyotp.TOTP(secret).at(credential.last_totp_step * 30)
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": code}
        ).status_code
        == 401
    )


def test_challenge_one_use_and_new_login_invalidates_old(client):
    old = password_login(client, "medico.demo").json()["challenge_token"]
    token, secret, _ = activate(client)
    for previous in [old, token]:
        assert (
            client.post(
                "/api/v1/auth/mfa/verify",
                json={"challenge_token": previous, "code": pyotp.TOTP(secret).now()},
            ).status_code
            == 401
        )


def test_recovery_codes_hashed_single_use(client):
    _, _, result = activate(client)
    code = result.json()["recovery_codes"][0]
    with SessionLocal() as db:
        rows = list(db.scalars(select(RecoveryCode)))
        assert len(rows) == 10 and all(code not in row.code_hash for row in rows)
    token = password_login(client, "medico.demo").json()["challenge_token"]
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": code, "recovery": True},
        ).status_code
        == 200
    )
    token = password_login(client, "medico.demo").json()["challenge_token"]
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": code, "recovery": True},
        ).status_code
        == 401
    )
    assert "MFA_RECOVERY_USED" in actions()


def test_old_password_only_session_denied_after_role_change(client):
    login(client, "admision.demo")
    with SessionLocal() as db:
        from app.models import Role

        user = db.scalar(select(User).where(User.username == "admision.demo"))
        user.roles = [db.scalar(select(Role).where(Role.name == "medico"))]
        db.commit()
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_mfa_disabled_user_cannot_finish_challenge(client):
    token, secret = enrollment(client)
    with SessionLocal() as db:
        db.scalar(select(User).where(User.username == "medico.demo")).is_active = False
        db.commit()
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
        ).status_code
        == 401
    )


def test_required_mfa_cannot_be_disabled(client):
    activate(client)
    assert (
        client.post(
            "/api/v1/auth/mfa/disable", json={"password": TEST_PASSWORD, "code": "123456"}
        ).status_code
        == 409
    )


def test_mfa_validation_does_not_echo_secrets(client):
    response = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "challenge_token": "private-too-short",
            "code": "private-code",
            "unexpected": "private-input",
        },
    )
    assert response.status_code == 422
    assert all(
        value not in response.text
        for value in ["private-too-short", "private-code", "private-input"]
    )


def test_docs_disabled(client):
    for path in [
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/docs",
        "/api/v1/redoc",
        "/api/v1/openapi.json",
    ]:
        assert client.get(path).status_code == 404


def test_recovery_regeneration_requires_fresh_factor_and_invalidates_old_codes(client):
    _, secret, result = activate(client)
    old_code = result.json()["recovery_codes"][0]
    import time

    code = pyotp.TOTP(secret).at(time.time() + 30)
    result = client.post(
        "/api/v1/auth/mfa/recovery/regenerate", json={"password": TEST_PASSWORD, "code": code}
    )
    assert result.status_code == 200 and len(result.json()["recovery_codes"]) == 10
    token = password_login(client, "medico.demo").json()["challenge_token"]
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": old_code, "recovery": True},
        ).status_code
        == 401
    )
    assert "MFA_RECOVERY_REGENERATED" in actions()


def test_account_limit_survives_new_challenges(client):
    for _ in range(2):
        token, _ = enrollment(client)
        for _ in range(5):
            assert (
                client.post(
                    "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": "abcdef"}
                ).status_code
                == 401
            )
    token, secret = enrollment(client)
    assert (
        client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
        ).status_code
        == 429
    )


def test_credential_stays_encrypted_after_database_reconnect(client):
    _, secret, _ = activate(client)
    from app.database import engine

    engine.dispose()
    with SessionLocal() as db:
        credential = db.scalar(select(MfaCredential))
        assert credential.enabled and credential.secret_encrypted != secret
        assert decrypt_secret(credential.secret_encrypted) == secret
