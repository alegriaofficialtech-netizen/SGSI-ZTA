from app.models import User, UserSession

REQUIRED_ROLES = frozenset({"admin-ti", "medico"})


def required(user: User) -> bool:
    return bool({role.name for role in user.roles} & REQUIRED_ROLES)


def enabled(user: User) -> bool:
    return bool(user.mfa_credential and user.mfa_credential.enabled)


def needs_factor(user: User) -> bool:
    return required(user) or enabled(user)


def session_satisfies_policy(session: UserSession) -> bool:
    return not needs_factor(session.user) or bool(session.mfa_verified_at and enabled(session.user))
