"""Idempotent synthetic policy/device seed; preserve all existing rows."""
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from app.models import Role, User
from app.models.policies import Device, Policy, PolicyCondition, PolicyVersion
from app.policies.types import ConditionOperator, ConditionType
from app.schemas.policies import PolicyResponse

POLICIES = (
    ("POL-CLIN-001", "Clinical demo read", "clinical-demo", "read", "ALLOW", "medico",
     {"require_mfa": True, "required_device_trust": "TRUSTED", "max_risk_score": 20}),
    ("POL-CLIN-002", "Admission sensitive read denied", "clinical-demo", "read_sensitive",
     "DENY", "admision", {"priority": 200}),
    ("POL-ADMIN-001", "User management update", "user-management", "update", "ALLOW",
     "admin-ti", {"require_mfa": True}),
    ("POL-AUDIT-001", "Audit read", "audit", "read", "ALLOW", ("auditor", "admin-ti"), {}),
    ("POL-CLIN-003", "Untrusted clinical device denied", "clinical-demo", "read", "DENY",
     None, {"priority": 1000}),
)
DEVICES = (
    ("DEV-MED-01", "Laptop Médico Demo", "medico.demo", "TRUSTED"),
    ("DEV-ADM-01", "PC Admisión Demo", "admision.demo", "LIMITED"),
    ("DEV-UNK-01", "Dispositivo No Confiable Demo", None, "UNTRUSTED"),
)


def seed_id(kind: str, code: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"sgsi-zta-native:{kind}:{code}"))


def seed_policies(db) -> None:
    try:
        admin = db.scalar(select(User).where(User.username == "admin.demo"))
        if admin is None:
            raise RuntimeError("M5 seed requires the existing identity seed")
        for code, name, username, trust in DEVICES:
            if db.scalar(select(Device.id).where(Device.device_code == code)):
                continue
            subject = db.scalar(select(User).where(User.username == username)) if username else None
            if username and subject is None:
                raise RuntimeError("M5 seed requires its existing demo device owner")
            db.add(Device(
                id=seed_id("device", code), device_code=code, name=name,
                assigned_user_id=subject.id if subject else None, trust_level=trust,
                status="ACTIVE", synthetic=True,
            ))
        for code, name, resource, action, effect, role_spec, options in POLICIES:
            if db.scalar(select(Policy.id).where(Policy.policy_code == code)):
                continue
            role_names = [role_spec] if isinstance(role_spec, str) else list(role_spec or [])
            roles = []
            for rname in role_names:
                role = db.scalar(select(Role).where(Role.name == rname))
                if role is None:
                    raise RuntimeError("M5 seed requires its existing demo policy role")
                roles.append(role)
            row = Policy(
                id=seed_id("policy", code), policy_code=code, name=name,
                description="Academic synthetic policy; not a production authorization claim.",
                resource=resource, action=action, effect=effect, created_by=admin.id,
                updated_by=admin.id, roles=roles, conditions=[], **options,
            )
            if code == "POL-CLIN-003":
                row.conditions.append(PolicyCondition(
                    id=seed_id("condition", code + ":device"),
                    condition_type=ConditionType.DEVICE_TRUST,
                    operator=ConditionOperator.EQ, value="UNTRUSTED",
                ))
            db.add(row)
            db.flush()
            db.add(PolicyVersion(
                id=seed_id("version", code + ":1"), policy_id=row.id, version=1,
                snapshot_json=PolicyResponse.model_validate(row).model_dump(mode="json"),
                created_by=admin.id,
            ))
        db.commit()
    except Exception:
        db.rollback()
        raise

