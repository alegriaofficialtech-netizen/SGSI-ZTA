"""Deployed M2 acceptance through Caddy/public HTTPS. Emits only safe results.

New demo recovery codes are retained encrypted for the operator, never as log text.
"""

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pyotp
from sqlalchemy import inspect, select

from app.auth.mfa_service import cipher, decrypt_secret
from app.config import get_settings
from app.database import SessionLocal, engine, now_utc
from app.models import AuditLog, MfaCredential, User


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://frontend:8080")
    parser.add_argument("--phase", choices=["initial", "persistence", "public"], default="initial")
    args = parser.parse_args()
    config = get_settings()
    checks = {}
    headers = {"Origin": args.url}
    if args.phase != "public":
        headers = {"Host": "localhost:8090", "Origin": "http://localhost:8090"}
    handoff = {}
    if args.phase == "public":
        assert config.cookie_secure, "Public cookies must be Secure"
    with httpx.Client(base_url=args.url, headers=headers, trust_env=False, timeout=30) as client:
        for path in ["/", "/login", "/mfa", "/mfa/setup"]:
            response = client.get(path)
            assert response.status_code == 200 and 'id="root"' in response.text
            assert "content-security-policy" in response.headers
        checks["frontend_same_origin"] = "PASS"
        assert client.get("/api/v1/health").json()["database"] == "connected"
        checks["database_connected"] = "PASS"
        for path in [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/v1/docs",
            "/api/v1/redoc",
            "/api/v1/openapi.json",
            "/debug",
            "/internal",
            "/admin-api",
        ]:
            assert client.get(path).status_code in (403, 404)
        checks["docs_debug_blocked"] = "PASS"
        # HTTP-only smoke must supply CSRF manually after Secure cookies are enabled.
        # Private acceptance is deliberately run before demo mode changes cookie settings.
        for username in ["medico.demo", "admin.demo", "admision.demo"]:
            csrf = client.get("/api/v1/auth/csrf").json()["csrf_token"]
            client.headers["X-CSRF-Token"] = csrf
            result = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": config.demo_password.get_secret_value()},
            )
            assert result.status_code == 200
            data = result.json()
            if username == "admision.demo":
                assert data["status"] == "AUTHENTICATED" and data["assurance"] == "PASSWORD_ONLY"
                assert client.get("/api/v1/dashboard").status_code == 200
                checks["admision_no_mfa"] = "PASS"
            else:
                token = data["challenge_token"]
                for path in ["/api/v1/users", "/api/v1/dashboard", "/api/v1/auth/sessions"]:
                    assert client.get(path).status_code == 401
                assert client.post("/api/v1/auth/refresh").status_code == 401
                checks[username + "_incomplete_denied"] = "PASS"
                if data["setup_required"]:
                    assert args.phase == "initial", "MFA did not persist"
                    result = client.post("/api/v1/auth/mfa/setup", json={"challenge_token": token})
                    assert result.status_code == 200
                    secret = pyotp.parse_uri(result.json()["provisioning_uri"]).secret
                    last_step = -1
                else:
                    assert data["status"] == "MFA_REQUIRED"
                    with SessionLocal() as db:
                        user = db.scalar(select(User).where(User.username == username))
                        credential = db.scalar(
                            select(MfaCredential).where(MfaCredential.user_id == user.id)
                        )
                        assert credential.enabled
                        secret = decrypt_secret(credential.secret_encrypted)
                        last_step = credential.last_totp_step
                    assert (
                        client.post(
                            "/api/v1/auth/mfa/setup", json={"challenge_token": token}
                        ).status_code
                        == 409
                    )
                wrong = "000000"
                if wrong in [
                    pyotp.TOTP(secret).at(time.time() + offset) for offset in (-30, 0, 30)
                ]:
                    wrong = "111111"
                assert (
                    client.post(
                        "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": wrong}
                    ).status_code
                    == 401
                )
                checks[username + "_invalid_denied"] = "PASS"
                totp = pyotp.TOTP(secret)
                # Wait for a fresh time step rather than weakening replay protection.
                while totp.timecode(datetime.now(UTC)) <= last_step:
                    time.sleep(1)
                result = client.post(
                    "/api/v1/auth/mfa/verify", json={"challenge_token": token, "code": totp.now()}
                )
                assert result.status_code == 200 and result.json()["assurance"] == "PASSWORD_MFA"
                if result.json().get("recovery_codes"):
                    handoff[username] = result.json()["recovery_codes"]
                assert secret not in result.text
                assert client.get("/api/v1/dashboard").status_code == 200
                assert client.get("/api/v1/auth/sessions").status_code == 200
                checks[username + "_valid_allowed"] = "PASS"
                if username == "admin.demo":
                    assert client.get("/api/v1/users").status_code == 200
                    audit = client.get("/api/v1/audit")
                    assert "MFA_SUCCESS" in audit.text and secret not in audit.text
                if args.phase == "public":
                    cookie_headers = result.headers.get_list("set-cookie")
                    assert all("Secure" in item for item in cookie_headers)
                    assert all(
                        "HttpOnly" in item for item in cookie_headers if "sgsi_csrf" not in item
                    )
                    checks["secure_httponly_cookies"] = "PASS"
            assert client.post("/api/v1/auth/refresh").status_code == 200
            assert client.post("/api/v1/auth/logout").status_code == 200
            assert client.get("/api/v1/auth/me").status_code == 401
        checks["refresh_logout"] = "PASS"
    assert {"mfa_credentials", "mfa_challenges", "recovery_codes"} <= set(
        inspect(engine).get_table_names()
    )
    with SessionLocal() as db:
        audit_actions = set(db.scalars(select(AuditLog.action)))
        assert {"MFA_SETUP_STARTED", "MFA_ENABLED", "MFA_SUCCESS", "MFA_FAILED"} <= audit_actions
    checks["migrations_audit"] = "PASS"
    if handoff:
        # Ciphertext only: operator can view once through an explicit local command.
        Path("/tmp/m2-demo-recovery.enc").write_bytes(
            cipher().encrypt(json.dumps(handoff).encode())
        )
    print(
        json.dumps(
            {
                "status": "PASS",
                "phase": args.phase,
                "timestamp": now_utc().isoformat() + "Z",
                "checks": checks,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
