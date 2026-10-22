import secrets

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import select

from app.auth.dependencies import (
    AuthenticatedSession,
    AuthenticatedUser,
    Database,
    verify_session_csrf,
)
from app.auth.mfa_policy import needs_factor, session_satisfies_policy
from app.auth.mfa_service import begin
from app.auth.security import dummy_hash, password_hasher
from app.auth.service import (
    clear_cookies,
    consume_login_limit,
    create_session,
    issue_cookies,
    resolve_refresh,
)
from app.config import get_settings
from app.database import now_utc
from app.models import User, UserSession
from app.schemas.identity import LoginInput, UserPublic
from app.services.audit import record
from app.users.service import public_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/csrf")
def csrf(request: Request, response: Response) -> dict[str, str]:
    token = request.cookies.get("sgsi_csrf") or secrets.token_urlsafe(32)
    if not request.cookies.get("sgsi_csrf"):
        response.set_cookie(
            "sgsi_csrf",
            token,
            secure=get_settings().cookie_secure,
            httponly=False,
            samesite="lax",
            path="/",
        )
    return {"csrf_token": token}


@router.post("/login")
def login(body: LoginInput, request: Request, response: Response, db: Database) -> dict:
    consume_login_limit(db, request, limit=get_settings().login_peer_limit)
    consume_login_limit(db, request, bucket="login-account:" + body.username.strip().lower())
    user = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    valid = password_hasher.verify(
        body.password.get_secret_value(),
        user.password_hash if user else dummy_hash,
    )
    if not user or not valid or not user.is_active:
        record(db, request, "LOGIN_FAILED", "auth", "DENY", username=body.username)
        db.commit()
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    # One cookie session per browser: replacing it revokes the previous session.
    if request.cookies.get("sgsi_refresh"):
        try:
            _, old = resolve_refresh(db, request)
            verify_session_csrf(request, old)
            old.revoked_at = now_utc()
        except HTTPException:
            pass
    # Password validation alone must never leave an earlier access cookie usable.
    for name, path in [("sgsi_access", "/api/v1"), ("sgsi_refresh", "/api/v1/auth")]:
        response.delete_cookie(
            name, path=path, secure=get_settings().cookie_secure, samesite="lax"
        )
    if needs_factor(user):
        result = begin(db, request, user, body.remember)
    else:
        result = create_session(db, request, response, user, body.remember)
    db.commit()
    return result


@router.get("/me", response_model=UserPublic)
def me(user: AuthenticatedUser) -> UserPublic:
    return public_user(user)


@router.post("/refresh")
def refresh(request: Request, response: Response, db: Database) -> dict[str, str]:
    token, session = resolve_refresh(db, request)
    verify_session_csrf(request, session)
    if token.used_at:
        session.revoked_at = now_utc()
        record(db, request, "REFRESH_REUSE_DETECTED", "auth", "DENY", session.user)
        db.commit()
        raise HTTPException(401, "Refresh reutilizado; sesión revocada")
    if (
        session.revoked_at
        or token.expires_at <= now_utc()
        or not session.user.is_active
        or not session_satisfies_policy(session)
    ):
        raise HTTPException(401, "Sesión expirada o revocada")
    token.used_at = now_utc()
    issue_cookies(db, response, session)
    record(db, request, "SESSION_REFRESHED", "auth", "ALLOW", session.user)
    db.commit()
    return {"status": "rotated"}


@router.post("/logout")
def logout(request: Request, response: Response, db: Database) -> dict[str, str]:
    try:
        _, session = resolve_refresh(db, request)
    except HTTPException:
        clear_cookies(response)
        return {"status": "signed_out"}
    verify_session_csrf(request, session)
    session.revoked_at = now_utc()
    record(db, request, "LOGOUT", "auth", "ALLOW", session.user)
    db.commit()
    clear_cookies(response)
    return {"status": "signed_out"}


@router.get("/sessions")
def sessions(db: Database, session: AuthenticatedSession) -> list[dict]:
    rows = db.scalars(
        select(UserSession)
        .where(
            UserSession.user_id == session.user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now_utc(),
        )
        .order_by(UserSession.created_at.desc())
    ).all()
    return [
        {
            "id": row.id,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
            "ip": row.ip,
            "user_agent": row.user_agent,
            "current": row.id == session.id,
        }
        for row in rows
    ]


@router.delete("/sessions/{session_id}")
def revoke(session_id: str, request: Request, db: Database, session: AuthenticatedSession) -> dict:
    target = db.get(UserSession, session_id)
    if not target or target.user_id != session.user_id:
        raise HTTPException(404, "Sesión no encontrada")
    target.revoked_at = now_utc()
    record(db, request, "SESSION_REVOKED", "auth", "ALLOW", session.user)
    db.commit()
    return {"status": "revoked"}
