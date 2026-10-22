import secrets
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.mfa_policy import session_satisfies_policy
from app.auth.security import decode_access, digest
from app.database import get_db, now_utc
from app.models import User, UserSession
from app.services.audit import record

Database = Annotated[Session, Depends(get_db)]


def current_session(request: Request, db: Database) -> UserSession:
    token = request.cookies.get("sgsi_access", "")
    try:
        claims = decode_access(token)
        session = db.get(UserSession, claims["sid"])
        if (
            claims["type"] != "access"
            or not session
            or session.revoked_at
            or session.expires_at <= now_utc()
            or str(session.user_id) != claims["sub"]
            or not session.user.is_active
            or not session_satisfies_policy(session)
        ):
            raise HTTPException(401, "Sesión inválida o revocada")
    except (jwt.InvalidTokenError, KeyError, TypeError) as error:
        raise HTTPException(401, "Autenticación requerida") from error
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        verify_session_csrf(request, session)
    return session


def verify_session_csrf(request: Request, session: UserSession) -> None:
    if not secrets.compare_digest(
        digest(request.headers.get("x-csrf-token", "")), session.csrf_hash
    ):
        raise HTTPException(403, "CSRF inválido para esta sesión")


AuthenticatedSession = Annotated[UserSession, Depends(current_session)]


def current_user(session: AuthenticatedSession) -> User:
    return session.user


AuthenticatedUser = Annotated[User, Depends(current_user)]


def require_roles(*allowed: str):
    def authorize(request: Request, db: Database, user: AuthenticatedUser) -> User:
        if not {role.name for role in user.roles}.intersection(allowed):
            record(db, request, "AUTHORIZATION_DENIED", request.url.path, "DENY", user)
            db.commit()
            raise HTTPException(403, "Tu rol no permite esta operación")
        return user

    return authorize
