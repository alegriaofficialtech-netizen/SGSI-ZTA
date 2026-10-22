import os
import secrets
import tempfile
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import delete, text

temporary = tempfile.TemporaryDirectory(prefix="sgsi-native-tests-")
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", f"sqlite:///{Path(temporary.name) / 'test.db'}"
)
os.environ["JWT_SECRET"] = secrets.token_urlsafe(64)
os.environ["DEMO_PASSWORD"] = "Tests!Aa9-" + secrets.token_urlsafe(20)
os.environ["COOKIE_SECURE"] = "false"
os.environ["MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed  # noqa: E402

TEST_PASSWORD = os.environ["DEMO_PASSWORD"]


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    # Never point TEST_DATABASE_URL at the application database; use isolated test service.
    if engine.dialect.name == "postgresql" and engine.url.database != "sgsi_native_test":
        raise RuntimeError("Refusing destructive tests outside sgsi_native_test")
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    yield
    engine.dispose()
    temporary.cleanup()


@pytest.fixture(autouse=True)
def reset_database(migrated_database):
    with SessionLocal() as db:
        if db.bind.dialect.name == "postgresql":
            table_names = ", ".join(f'"{table.name}"' for table in Base.metadata.sorted_tables)
            db.execute(text(f"TRUNCATE TABLE {table_names} RESTART IDENTITY CASCADE"))
            db.commit()
        else:
            for table in reversed(Base.metadata.sorted_tables):
                db.execute(delete(table))
            db.commit()
        seed(db, TEST_PASSWORD)


def ready_client() -> TestClient:
    client = TestClient(app)
    client.headers["X-CSRF-Token"] = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    return client


@pytest.fixture
def client():
    with ready_client() as instance:
        yield instance


def password_login(client: TestClient, username: str = "admin.demo", **extra):
    return client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": TEST_PASSWORD,
            **extra,
        },
    )


def login(client: TestClient, username: str = "admin.demo", **extra):
    """Complete real MFA for M1 regression tests; M2 tests use password_login."""
    import pyotp
    from sqlalchemy import select

    from app.auth.mfa_service import decrypt_secret
    from app.models import MfaCredential, User

    response = password_login(client, username, **extra)
    if response.status_code != 200 or response.json()["status"] == "AUTHENTICATED":
        return response
    challenge = response.json()["challenge_token"]
    if response.json()["setup_required"]:
        setup = client.post("/api/v1/auth/mfa/setup", json={"challenge_token": challenge}).json()
        secret = pyotp.parse_uri(setup["provisioning_uri"]).secret
    else:
        with SessionLocal() as db:
            user = db.scalar(select(User).where(User.username == username))
            secret = decrypt_secret(
                db.scalar(
                    select(MfaCredential).where(MfaCredential.user_id == user.id)
                ).secret_encrypted
            )
    return client.post(
        "/api/v1/auth/mfa/verify",
        json={"challenge_token": challenge, "code": pyotp.TOTP(secret).now()},
    )
