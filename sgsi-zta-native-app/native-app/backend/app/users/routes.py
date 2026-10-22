from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.auth.dependencies import AuthenticatedSession, Database, require_roles
from app.auth.security import password_hasher
from app.database import now_utc
from app.models import Role, User, UserSession
from app.policies.service import AuthorizationService
from app.policies.types import Decision
from app.schemas.identity import UserCreate, UserPublic, UserUpdate
from app.services.audit import record
from app.users.service import public_user, validated_roles

router = APIRouter(prefix="/users", tags=["Users"])
Admin = Annotated[User, Depends(require_roles("admin-ti"))]


@router.get("", response_model=list[UserPublic])
def users(db: Database, admin: Admin) -> list[UserPublic]:
    return [public_user(user) for user in db.scalars(select(User).order_by(User.username)).all()]


@router.get("/roles")
def roles(db: Database, admin: Admin) -> list[dict]:
    return [
        {"name": role.name, "description": role.description, "mfa_required": role.mfa_required}
        for role in db.scalars(select(Role).order_by(Role.name)).all()
    ]


@router.post("", status_code=201, response_model=UserPublic)
def create(body: UserCreate, request: Request, db: Database, admin: Admin) -> UserPublic:
    user = User(
        username=body.username,
        display_name=body.display_name,
        department=body.department,
        password_hash=password_hasher.hash(body.password.get_secret_value()),
        roles=validated_roles(db, body.roles),
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "El usuario ya existe") from error
    record(db, request, "USER_CREATED", f"users/{user.id}", "ALLOW", admin)
    db.commit()
    return public_user(user)


@router.patch("/{user_id}", response_model=UserPublic)
def update(
    user_id: int,
    body: UserUpdate,
    request: Request,
    db: Database,
    admin: Admin,
    session: AuthenticatedSession,
) -> UserPublic:
    outcome = AuthorizationService(db, request).authorize(
        session, resource="user-management", action="update"
    )
    if outcome.decision != Decision.ALLOW:
        if outcome.decision == Decision.MFA_REQUIRED:
            raise HTTPException(403, "MFA requerido para modificar usuarios")
        raise HTTPException(403, "Acceso denegado por política Zero Trust")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    changes = body.model_dump(exclude_unset=True)
    if any(value is None for value in changes.values()):
        raise HTTPException(422, "Los campos actualizados no admiten null")
    if user.id == admin.id and (
        changes.get("is_active") is False
        or ("roles" in changes and "admin-ti" not in changes["roles"])
    ):
        raise HTTPException(409, "No puedes desactivar ni retirar tu propio rol administrador")
    for field in ("display_name", "department", "is_active"):
        if field in changes:
            setattr(user, field, changes[field])
    if "roles" in changes:
        user.roles = validated_roles(db, changes["roles"])
    if changes.get("is_active") is False or "roles" in changes:
        for session in db.scalars(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
            )
        ).all():
            session.revoked_at = now_utc()
    record(db, request, "USER_UPDATED", f"users/{user.id}", "ALLOW", admin)
    db.commit()
    return public_user(user)
