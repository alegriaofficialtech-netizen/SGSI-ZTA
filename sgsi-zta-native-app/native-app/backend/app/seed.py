from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import password_hasher
from app.config import get_settings
from app.database import SessionLocal
from app.models import Group, Role, User
from app.schemas.identity import UserCreate

DEMO_USERS = [
    ("admin.demo", "Administrador Demo", "Tecnología de información", "admin-ti"),
    ("medico.demo", "Médico Demo", "Atención médica", "medico"),
    ("enfermeria.demo", "Enfermería Demo", "Enfermería", "enfermeria"),
    ("admision.demo", "Admisión Demo", "Admisión", "admision"),
    ("laboratorio.demo", "Laboratorio Demo", "Laboratorio", "laboratorio"),
    ("farmacia.demo", "Farmacia Demo", "Farmacia", "farmacia"),
    ("auditor.demo", "Auditor Demo", "Auditoría", "auditor"),
]


def seed(db: Session, password: str) -> None:
    for username, name, department, role_name in DEMO_USERS:
        role = db.scalar(select(Role).where(Role.name == role_name))
        if not role:
            role = Role(
                name=role_name,
                description=f"Rol académico {department}",
                mfa_required=role_name in {"admin-ti", "medico"},
            )
            db.add(role)
        group = db.scalar(select(Group).where(Group.name == department))
        if not group:
            group = Group(name=department)
            db.add(group)
        if not db.scalar(select(User).where(User.username == username)):
            validated = UserCreate(
                username=username,
                display_name=name,
                department=department,
                password=password,
                roles=[role_name],
            )
            db.add(
                User(
                    username=username,
                    display_name=name,
                    department=department,
                    password_hash=password_hasher.hash(validated.password.get_secret_value()),
                    roles=[role],
                    groups=[group],
                )
            )
    db.commit()
    from app.assets.seed import seed_assets

    seed_assets(db)
    from app.risks.seed import seed_risks

    seed_risks(db)
    from app.policies.seed import seed_policies

    seed_policies(db)
    from app.monitoring.seed import seed_monitoring_fim, seed_monitoring_rules

    seed_monitoring_rules(db)
    seed_monitoring_fim(db)


if __name__ == "__main__":
    secret = get_settings().demo_password
    if not secret:
        raise SystemExit("DEMO_PASSWORD must be supplied through the environment")
    with SessionLocal() as database:
        seed(database, secret.get_secret_value())
    print("Synthetic seed complete (idempotent). Credentials are never printed.")
