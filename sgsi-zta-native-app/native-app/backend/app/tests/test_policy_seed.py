from sqlalchemy import func, select

from app.database import SessionLocal, now_utc
from app.models import Role, User
from app.models.policies import Device, Policy, PolicyCondition, PolicyVersion
from app.policies.seed import seed_policies
from app.schemas.policies import PolicyResponse


def test_seed_twice_counts_and_deterministic_ids():
    with SessionLocal() as db:
        original = {row.policy_code: row.id for row in db.scalars(select(Policy))}
        seed_policies(db)
        seed_policies(db)
        assert {row.policy_code: row.id for row in db.scalars(select(Policy))} == original
        for model, expected in ((Policy, 5), (Device, 3), (PolicyVersion, 5), (User, 7), (Role, 7)):
            assert db.scalar(select(func.count()).select_from(model)) == expected
        assert db.scalar(select(func.count()).select_from(PolicyCondition)) == 1


def test_seed_preserves_policy_device_edits_disable_and_versions():
    with SessionLocal() as db:
        row = db.scalar(select(Policy).where(Policy.policy_code == "POL-CLIN-001"))
        row.name = "Manually edited"
        row.max_risk_score = 7
        row.enabled = False
        row.disabled_at = now_utc()
        device = db.scalar(select(Device).where(Device.device_code == "DEV-MED-01"))
        device.trust_level = "LIMITED"
        actor = db.scalar(select(User.id).where(User.username == "admin.demo"))
        db.add(
            PolicyVersion(
                policy_id=row.id, version=2, snapshot_json={"manual": True}, created_by=actor
            )
        )
        db.commit()
        seed_policies(db)
        seed_policies(db)
        db.refresh(row)
        db.refresh(device)
        assert row.name == "Manually edited" and row.max_risk_score == 7
        assert row.enabled is False and row.disabled_at is not None
        assert device.trust_level == "LIMITED"
        versions = list(db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == row.id)))
        assert {version.version for version in versions} == {1, 2}
        assert next(version for version in versions if version.version == 2).snapshot_json == {
            "manual": True
        }


def test_seed_roles_device_ownership_and_initial_snapshot():
    with SessionLocal() as db:
        medico = db.scalar(select(User).where(User.username == "medico.demo"))
        policy = db.scalar(select(Policy).where(Policy.policy_code == "POL-CLIN-001"))
        assert {role.name for role in policy.roles} == {"medico"}
        assert policy.require_mfa is True and policy.max_risk_score == 20
        device = db.scalar(select(Device).where(Device.device_code == "DEV-MED-01"))
        assert device.assigned_user_id == medico.id and device.trust_level == "TRUSTED"
        unknown = db.scalar(select(Device).where(Device.device_code == "DEV-UNK-01"))
        assert unknown.assigned_user_id is None and unknown.trust_level == "UNTRUSTED"
        version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy.id, PolicyVersion.version == 1
            )
        )
        assert version.snapshot_json == PolicyResponse.model_validate(policy).model_dump(
            mode="json"
        )
        deny = db.scalar(select(Policy).where(Policy.policy_code == "POL-CLIN-003"))
        assert deny.effect == "DENY"
        assert deny.conditions[0].value == "UNTRUSTED"
