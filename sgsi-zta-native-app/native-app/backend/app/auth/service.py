import secrets
from datetime import timedelta

from fastapi import HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.auth.security import access_token, digest
from app.config import get_settings
from app.database import now_utc
from app.models import LoginRateLimit, RefreshToken, User, UserSession
from app.services.audit import record


def consume_login_limit(
    db: Session, request: Request, *, bucket: str | None = None, limit: int | None = None
) -> None:
    config = get_settings()
    key = digest(bucket or (request.client.host if request.client else "unknown"))
    now = now_utc()
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    db.execute(
        insert(LoginRateLimit)
        .values(
            key=key,
            window_start=now,
            attempts=0,
        )
        .on_conflict_do_nothing(index_elements=["key"])
    )
    bucket = db.scalar(select(LoginRateLimit).where(LoginRateLimit.key == key).with_for_update())
    assert bucket is not None
    if bucket.window_start + timedelta(seconds=config.login_window_seconds) <= now:
        bucket.window_start, bucket.attempts = now, 0
    bucket.attempts += 1
    if bucket.attempts > (limit if limit is not None else config.login_limit):
        record(db, request, "LOGIN_RATE_LIMITED", "auth", "DENY")
        db.commit()
        raise HTTPException(
            429,
            "Demasiados intentos. Intenta más tarde.",
            headers={
                "Retry-After": str(config.login_window_seconds),
            },
        )


def create_session(
    db: Session,
    request: Request,
    response: Response,
    user: User,
    remember: bool,
    *,
    mfa_verified: bool = False,
) -> dict:
    from app.users.service import public_user

    config = get_settings()
    lifetime = (
        timedelta(days=config.remember_days) if remember else timedelta(hours=config.refresh_hours)
    )
    session = UserSession(
        user_id=user.id,
        csrf_hash=digest(request.headers["x-csrf-token"]),
        ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "")[:255],
        remember=remember,
        expires_at=now_utc() + lifetime,
        mfa_verified_at=now_utc() if mfa_verified else None,
    )
    db.add(session)
    db.flush()
    issue_cookies(db, response, session)
    response.set_cookie(
        "sgsi_csrf",
        request.headers["x-csrf-token"],
        secure=config.cookie_secure,
        httponly=False,
        samesite="lax",
        path="/",
        max_age=int(lifetime.total_seconds()) if remember else None,
    )
    user.last_login = now_utc()
    record(db, request, "LOGIN_SUCCESS", "auth", "ALLOW", user)
    return {
        "status": "AUTHENTICATED",
        "user": public_user(user),
        "token_transport": "httponly_cookie",
        "expires_in": config.access_minutes * 60,
        "assurance": "PASSWORD_MFA" if mfa_verified else "PASSWORD_ONLY",
        "mfa_status": "VERIFIED" if mfa_verified else "NOT_REQUIRED",
    }


def issue_cookies(db: Session, response: Response, session: UserSession) -> None:
    config = get_settings()
    refresh = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            session_id=session.id,
            token_hash=digest(refresh),
            expires_at=session.expires_at,
        )
    )
    seconds = max(1, int((session.expires_at - now_utc()).total_seconds()))
    response.set_cookie(
        "sgsi_access",
        access_token(session),
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path="/api/v1",
        max_age=config.access_minutes * 60 if session.remember else None,
    )
    response.set_cookie(
        "sgsi_refresh",
        refresh,
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path="/api/v1/auth",
        max_age=seconds if session.remember else None,
    )


def clear_cookies(response: Response) -> None:
    for name, path in [
        ("sgsi_access", "/api/v1"),
        ("sgsi_refresh", "/api/v1/auth"),
        ("sgsi_csrf", "/"),
    ]:
        response.delete_cookie(
            name, path=path, secure=get_settings().cookie_secure, samesite="lax"
        )


def resolve_refresh(db: Session, request: Request) -> tuple[RefreshToken, UserSession]:
    token = db.scalar(
        select(RefreshToken)
        .where(
            RefreshToken.token_hash == digest(request.cookies.get("sgsi_refresh", "")),
        )
        .with_for_update()
    )
    if not token:
        raise HTTPException(401, "Refresh inválido")
    session = db.scalar(
        select(UserSession)
        .where(
            UserSession.id == token.session_id,
        )
        .with_for_update()
    )
    if not session:
        raise HTTPException(401, "Sesión inválida")
    return token, session
