"""Native MFA workflow. PyOTP owns TOTP; Fernet owns authenticated encryption."""

import io
import re
import secrets
from datetime import UTC, timedelta

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.auth.mfa_policy import enabled
from app.auth.security import digest, password_hasher
from app.auth.service import consume_login_limit
from app.config import get_settings
from app.database import now_utc
from app.models import MfaChallenge, MfaCredential, RecoveryCode, User, UserSession
from app.services.audit import record


def cipher() -> Fernet:
    return Fernet(get_settings().mfa_encryption_key.get_secret_value().encode())


def decrypt_secret(encrypted: str) -> str:
    return cipher().decrypt(encrypted.encode()).decode()


def begin(db: Session, request: Request, user: User, remember: bool) -> dict:
    # Serialize all MFA changes for an account, including concurrent challenges.
    db.scalar(select(User).where(User.id == user.id).with_for_update())
    db.refresh(user)
    db.execute(
        update(MfaChallenge)
        .where(MfaChallenge.user_id == user.id, MfaChallenge.consumed_at.is_(None))
        .values(consumed_at=now_utc())
    )
    token = secrets.token_urlsafe(48)
    setup = not enabled(user)
    db.add(
        MfaChallenge(
            user_id=user.id,
            token_hash=digest(token),
            csrf_hash=digest(request.headers["x-csrf-token"]),
            remember=remember,
            setup_required=setup,
            expires_at=now_utc() + timedelta(seconds=get_settings().mfa_challenge_seconds),
        )
    )
    record(db, request, "MFA_CHALLENGE", "auth/mfa", "ALLOW", user)
    return {
        "status": "MFA_SETUP_REQUIRED" if setup else "MFA_REQUIRED",
        "challenge_token": token,
        "setup_required": setup,
        "expires_in": get_settings().mfa_challenge_seconds,
    }


def resolve(db: Session, request: Request, token: str) -> tuple[MfaChallenge, User]:
    challenge = db.scalar(select(MfaChallenge).where(MfaChallenge.token_hash == digest(token)))
    if not challenge:
        raise HTTPException(401, "Verificación vencida. Inicia sesión de nuevo.")
    user = db.scalar(select(User).where(User.id == challenge.user_id).with_for_update())
    # Reload after the account lock: another request may have consumed this challenge.
    db.refresh(challenge)
    if (
        not user
        or not user.is_active
        or challenge.consumed_at
        or challenge.expires_at <= now_utc()
        or challenge.attempts >= get_settings().mfa_max_attempts
    ):
        raise HTTPException(401, "Verificación vencida. Inicia sesión de nuevo.")
    if not secrets.compare_digest(
        challenge.csrf_hash, digest(request.headers.get("x-csrf-token", ""))
    ):
        raise HTTPException(403, "Verificación no válida para este navegador")
    return challenge, user


def setup(db: Session, request: Request, token: str) -> dict:
    challenge, user = resolve(db, request, token)
    if not challenge.setup_required or enabled(user):
        raise HTTPException(409, "El autenticador ya está configurado")
    if not challenge.secret_encrypted:
        challenge.secret_encrypted = cipher().encrypt(pyotp.random_base32().encode()).decode()
        record(db, request, "MFA_SETUP_STARTED", "auth/mfa", "ALLOW", user)
    uri = pyotp.TOTP(decrypt_secret(challenge.secret_encrypted)).provisioning_uri(
        name=user.username, issuer_name="SGSI-ZTA Hospital"
    )
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    import base64

    return {
        "provisioning_uri": uri,
        "qr_data_url": "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode(),
        "expires_in": max(0, int((challenge.expires_at - now_utc()).total_seconds())),
    }


def totp_step(secret: str, code: str, last_step: int = -1) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    current = totp.timecode(now_utc().replace(tzinfo=UTC))
    for step in (current, current - 1, current + 1):
        if step > last_step and totp.verify(code, for_time=step * totp.interval):
            return step
    return None


def regenerate_codes(db: Session, user: User) -> list[str]:
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = [secrets.token_hex(16) for _ in range(10)]
    db.add_all([RecoveryCode(user_id=user.id, code_hash=digest(code)) for code in codes])
    return ["-".join(code[i : i + 8] for i in range(0, 32, 8)) for code in codes]


def verify(
    db: Session, request: Request, token: str, code: str, recovery: bool
) -> tuple[User, bool, list[str] | None]:
    challenge, user = resolve(db, request, token)
    consume_login_limit(db, request, bucket=f"mfa-account:{user.id}")
    challenge.attempts += 1
    codes = None
    credential = db.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id))
    valid = False
    if recovery and not challenge.setup_required and credential and credential.enabled:
        normalized = code.strip().replace("-", "").lower()
        row = db.scalar(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.code_hash == digest(normalized),
                RecoveryCode.used_at.is_(None),
            )
        )
        if row:
            row.used_at = now_utc()
            valid = True
            record(db, request, "MFA_RECOVERY_USED", "auth/mfa", "ALLOW", user)
    elif not recovery:
        encrypted = (
            challenge.secret_encrypted
            if challenge.setup_required
            else (credential.secret_encrypted if credential and credential.enabled else None)
        )
        step = (
            totp_step(
                decrypt_secret(encrypted),
                code,
                credential.last_totp_step if credential and credential.enabled else -1,
            )
            if encrypted
            else None
        )
        if step is not None:
            valid = True
            if challenge.setup_required:
                if credential and credential.enabled:
                    raise HTTPException(409, "El autenticador ya está configurado")
                if not credential:
                    credential = MfaCredential(user_id=user.id, secret_encrypted=encrypted)
                    db.add(credential)
                else:
                    credential.secret_encrypted = encrypted
                    credential.enabled = True
                    credential.verified_at = now_utc()
                codes = regenerate_codes(db, user)
                record(db, request, "MFA_ENABLED", "auth/mfa", "ALLOW", user)
            credential.last_totp_step = step
    if not valid:
        record(db, request, "MFA_FAILED", "auth/mfa", "DENY", user)
        db.commit()
        raise HTTPException(401, "Código incorrecto o ya utilizado. Revisa tu autenticador.")
    challenge.consumed_at = now_utc()
    challenge.secret_encrypted = None
    db.flush()
    db.refresh(user)
    record(db, request, "MFA_SUCCESS", "auth/mfa", "ALLOW", user)
    return user, challenge.remember, codes


def confirm_factor(
    db: Session, request: Request, user: User, password: str, code: str
) -> MfaCredential:
    db.scalar(select(User).where(User.id == user.id).with_for_update())
    consume_login_limit(db, request, bucket=f"mfa-account:{user.id}")
    credential = db.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id))
    password_valid = password_hasher.verify(password, user.password_hash)
    step = (
        totp_step(decrypt_secret(credential.secret_encrypted), code, credential.last_totp_step)
        if credential and credential.enabled
        else None
    )
    if not password_valid or step is None:
        record(db, request, "MFA_FAILED", "auth/mfa", "DENY", user)
        db.commit()
        raise HTTPException(401, "Contraseña o código incorrecto o ya utilizado")
    credential.last_totp_step = step
    return credential


def revoke_account_sessions(db: Session, user: User) -> None:
    db.execute(
        update(UserSession).where(UserSession.user_id == user.id).values(revoked_at=now_utc())
    )
