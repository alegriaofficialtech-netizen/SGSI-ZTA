import hashlib
import secrets
from datetime import timedelta

import jwt
from pwdlib import PasswordHash

from app.config import get_settings
from app.database import now_utc
from app.models import UserSession

password_hasher = PasswordHash.recommended()
# Unknown-user attempts still perform an Argon2 verification.
dummy_hash = password_hasher.hash(secrets.token_urlsafe(24))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def access_token(session: UserSession) -> str:
    config = get_settings()
    now = now_utc()
    return jwt.encode(
        {
            "sub": str(session.user_id),
            "sid": session.id,
            "type": "access",
            "jti": secrets.token_hex(16),
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=config.access_minutes),
            "iss": config.jwt_issuer,
            "aud": config.jwt_audience,
        },
        config.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )


def decode_access(token: str) -> dict:
    config = get_settings()
    return jwt.decode(
        token,
        config.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        issuer=config.jwt_issuer,
        audience=config.jwt_audience,
        options={"require": ["exp", "iat", "nbf", "sub", "sid", "jti", "type"]},
    )
