from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.mfa_policy import enabled, required
from app.models import Role, User
from app.schemas.identity import UserPublic


def public_user(user: User) -> UserPublic:
    return UserPublic(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        department=user.department,
        roles=[role.name for role in user.roles],
        groups=[group.name for group in user.groups],
        is_active=user.is_active,
        mfa_required=required(user),
        mfa_enabled=enabled(user),
        last_login=user.last_login,
        created_at=user.created_at,
    )


def validated_roles(db: Session, names: list[str]) -> list[Role]:
    roles = list(db.scalars(select(Role).where(Role.name.in_(names))).all())
    if {role.name for role in roles} != set(names):
        raise HTTPException(422, "Rol desconocido")
    return roles
