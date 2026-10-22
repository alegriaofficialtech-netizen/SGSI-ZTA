from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import delete, inspect, select, text, update
from sqlalchemy.exc import DataError, IntegrityError

from app.database import SessionLocal, engine
from app.models import Asset, AuditLog, Role, User
from app.models.policies import Device, Policy, PolicyDecision, PolicyRole, PolicyVersion
from app.policies.types import Decision, DeviceTrust, ReasonCode
from app.schemas.policies import (
    ConditionInput,
    DecisionFilters,
    EvaluateInput,
    PolicyCreate,
    PolicyUpdate,
    SimulateInput,
)


def admin_id(db):
    return db.scalar(select(User.id).where(User.username == "admin.demo"))


def policy(db, **changes):
    values = {
        "policy_code": "POL-TEST-001",
        "name": "Test policy",
        "resource": "clinical-demo",
        "action": "read",
        "effect": "ALLOW",
        "created_by": admin_id(db),
        "updated_by": admin_id(db),
    }
    row = Policy(**(values | changes))
    db.add(row)
    db.flush()
    return row


def decision(db):
    row = PolicyDecision(
        user_id=admin_id(db),
        resource="clinical-demo",
        action="read",
        decision=Decision.DENY,
        reason_code=ReasonCode.DEFAULT_DENY,
        risk_score_snapshot=0,
        risk_level_snapshot="LOW",
        mfa_snapshot=False,
        device_trust_snapshot=DeviceTrust.UNTRUSTED,
    )
    db.add(row)
    db.flush()
    return row


def test_migration_tables_and_audit_link():
    schema = inspect(engine)
    assert set(schema.get_table_names()) >= {
        "policies",
        "policy_roles",
        "policy_conditions",
        "devices",
        "policy_decisions",
        "policy_versions",
    }
    assert "policy_decision_id" in {column["name"] for column in schema.get_columns("audit_logs")}
    assert any(
        fk["referred_table"] == "policy_decisions" for fk in schema.get_foreign_keys("audit_logs")
    )


@pytest.mark.parametrize(
    "values",
    [
        {"priority": -1},
        {"priority": 1001},
        {"max_risk_score": -1},
        {"max_risk_score": 26},
        {"session_max_age_minutes": 0},
        {"session_max_age_minutes": 10081},
        {"enabled": False},
        {"effect": "EXECUTE"},
        {"action": "wildcard"},
    ],
)
def test_policy_database_bounds(values):
    with SessionLocal() as db, pytest.raises((IntegrityError, DataError)):
        policy(db, **values)


def test_foreign_keys_and_role_unique():
    with SessionLocal() as db:
        if engine.dialect.name == "sqlite":
            db.execute(text("PRAGMA foreign_keys=ON"))
        row = policy(db)
        role = db.scalar(select(Role.id).where(Role.name == "medico"))
        db.add(PolicyRole(policy_id=row.id, role_id=role))
        db.flush()
        db.expunge_all()
        with pytest.raises(IntegrityError):
            db.add(PolicyRole(policy_id=row.id, role_id=role))
            db.flush()
        db.rollback()
        with pytest.raises(IntegrityError):
            db.add(PolicyRole(policy_id=str(uuid4()), role_id=role))
            db.flush()


def test_device_requires_synthetic_and_valid_assignment():
    with SessionLocal() as db:
        db.add(
            Device(
                device_code="DEV-TEST",
                name="Test device",
                trust_level="TRUSTED",
                status="ACTIVE",
                synthetic=False,
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()


@pytest.mark.parametrize(
    "field",
    [
        "user_id",
        "role",
        "roles",
        "mfa_verified",
        "risk_score",
        "risk_level",
        "asset_criticality",
        "device_trust",
        "assume_mfa",
    ],
)
def test_evaluate_rejects_spoof_fields(field):
    with pytest.raises(ValidationError):
        EvaluateInput.model_validate({"resource": "clinical-demo", "action": "read", field: True})


@pytest.mark.parametrize("value", [True, "1", 0, -1, "47b2962a-a80d-4489-9533-b732debc9935"])
def test_legacy_id_is_strict_positive_integer(value):
    with pytest.raises(ValidationError):
        EvaluateInput(resource="asset", action="read", asset_id=value)
    with pytest.raises(ValidationError):
        SimulateInput(resource="asset", action="read", subject_user_id=value)


@pytest.mark.parametrize("value", ["*", "../audit", "clinical_demo", "a OR 1=1", ""])
def test_resource_validation(value):
    with pytest.raises(ValidationError):
        EvaluateInput(resource=value, action="read")


def test_unknown_resource_and_simulation_contract():
    body = EvaluateInput(resource="unknown-resource", action="read", asset_id=1)
    assert body.resource == "unknown-resource"
    body = SimulateInput(
        resource="clinical-demo", action="read", subject_user_id=2, assume_mfa=False
    )
    assert body.assume_mfa is False
    with pytest.raises(ValidationError):
        SimulateInput(
            resource="clinical-demo", action="read", subject_user_id=2, assume_mfa="false"
        )
    with pytest.raises(ValidationError):
        EvaluateInput(resource="asset", action="READ")


@pytest.mark.parametrize(
    ("kind", "operator", "value"),
    [
        ("ROLE", "IN", ["medico"]),
        ("MFA", "EQ", True),
        ("ASSET_CRITICALITY", "EQ", "HIGH"),
        ("RISK_LEVEL", "IN", ["HIGH", "CRITICAL"]),
        ("RISK_SCORE", "LTE", 20),
        ("DEVICE_TRUST", "EQ", "UNTRUSTED"),
        ("SESSION_AGE", "LTE", 60),
        ("TIME_WINDOW", "BETWEEN", {"start": "22:00", "end": "06:00"}),
    ],
)
def test_typed_conditions(kind, operator, value):
    condition = ConditionInput(condition_type=kind, operator=operator, value=value)
    assert condition.value == value


@pytest.mark.parametrize(
    ("kind", "operator", "value"),
    [
        ("MFA", "EQ", "true"),
        ("ROLE", "LTE", 1),
        ("RISK_SCORE", "LTE", True),
        ("RISK_SCORE", "LTE", 26),
        ("SESSION_AGE", "LTE", 10081),
        ("DEVICE_TRUST", "EQ", "ROOT"),
        ("ASSET_CRITICALITY", "EQ", "URGENT"),
        ("RISK_LEVEL", "EQ", "MINIMAL"),
        ("TIME_WINDOW", "BETWEEN", {"start": "25:00", "end": "06:00"}),
        ("TIME_WINDOW", "BETWEEN", {"start": "06:00", "end": "06:00"}),
        ("TIME_WINDOW", "BETWEEN", {"start": "06:00", "end": "08:00", "code": "exec()"}),
    ],
)
def test_invalid_conditions(kind, operator, value):
    with pytest.raises(ValidationError):
        ConditionInput(condition_type=kind, operator=operator, value=value)


def test_management_patch_and_bounds():
    body = PolicyCreate(
        policy_code="POL-NEW-001",
        name="New policy",
        resource="asset",
        action="read",
        effect="ALLOW",
        role_ids=[1],
    )
    assert body.require_mfa is False
    assert PolicyUpdate(max_risk_score=None).model_dump(exclude_unset=True) == {
        "max_risk_score": None
    }
    for values in ({"priority": True}, {"role_ids": [True]}, {"name": None}, {"enabled": False}):
        with pytest.raises(ValidationError):
            PolicyUpdate(**values)


def test_version_unique_and_positive():
    with SessionLocal() as db:
        row = policy(db)
        db.add(
            PolicyVersion(
                policy_id=row.id,
                version=1,
                snapshot_json={},
                created_by=admin_id(db),
            )
        )
        db.flush()
        with pytest.raises(IntegrityError):
            db.add(
                PolicyVersion(
                    policy_id=row.id,
                    version=1,
                    snapshot_json={},
                    created_by=admin_id(db),
                )
            )
            db.flush()
        db.rollback()


@pytest.mark.parametrize("model", [PolicyDecision, PolicyVersion])
@pytest.mark.parametrize("operation", ["change", "delete", "bulk_update", "bulk_delete"])
def test_append_only_orm(model, operation):
    with SessionLocal() as db:
        if model is PolicyDecision:
            row = decision(db)
            field = "simulation"
            value = True
        else:
            row = PolicyVersion(
                policy_id=policy(db).id,
                version=1,
                snapshot_json={},
                created_by=admin_id(db),
            )
            db.add(row)
            db.flush()
            field = "snapshot_json"
            value = {"modified": True}
        with pytest.raises(ValueError, match="append-only"):
            if operation == "change":
                setattr(row, field, value)
                db.flush()
            elif operation == "delete":
                db.delete(row)
                db.flush()
            elif operation == "bulk_update":
                db.execute(update(model).where(model.id == row.id).values({field: value}))
            else:
                db.execute(delete(model).where(model.id == row.id))
        db.rollback()


def test_decision_audit_and_core_cleanup():
    with SessionLocal() as db:
        row = decision(db)
        audit = AuditLog(
            username="admin.demo",
            action="ACCESS_DENIED",
            resource="clinical-demo",
            decision="DENY",
            ip="127.0.0.1",
            policy_decision_id=row.id,
        )
        db.add(audit)
        db.flush()
        assert audit.policy_decision_id == row.id
        db.execute(delete(AuditLog.__table__).where(AuditLog.id == audit.id))
        if db.bind.dialect.name == "postgresql":
            with pytest.raises(Exception, match="(?i)append-only"):
                db.execute(delete(PolicyDecision.__table__).where(PolicyDecision.id == row.id))
        else:
            db.execute(delete(PolicyDecision.__table__).where(PolicyDecision.id == row.id))
        db.rollback()


def test_decision_database_score_bound():
    with SessionLocal() as db:
        with pytest.raises(IntegrityError):
            db.execute(
                PolicyDecision.__table__.insert().values(
                    id=str(uuid4()),
                    user_id=admin_id(db),
                    resource="clinical-demo",
                    action="read",
                    decision="DENY",
                    reason_code="DEFAULT_DENY",
                    risk_score_snapshot=26,
                    risk_level_snapshot="LOW",
                    mfa_snapshot=False,
                    device_trust_snapshot="UNTRUSTED",
                )
            )
        db.rollback()


def test_action_enum_values_and_database_round_trip():
    from app.policies.types import Action

    for model in (Policy, PolicyDecision):
        assert model.__table__.c.action.type.enums == [action.value for action in Action]
    with SessionLocal() as db:
        row = policy(db)
        evaluated = decision(db)
        db.expire_all()
        assert row.action == Action.READ
        assert evaluated.action == Action.READ
        assert (
            db.scalar(text("SELECT action FROM policies WHERE id = :id"), {"id": row.id}) == "read"
        )


@pytest.mark.parametrize("model", [PolicyDecision, PolicyVersion])
@pytest.mark.parametrize("operation", ["update", "delete"])
def test_core_maintenance_with_orm_predicate(model, operation):
    with SessionLocal() as db:
        if model is PolicyDecision:
            row = decision(db)
            changes = {"simulation": True}
        else:
            row = PolicyVersion(
                policy_id=policy(db).id,
                version=1,
                snapshot_json={},
                created_by=admin_id(db),
            )
            db.add(row)
            db.flush()
            changes = {"snapshot_json": {"maintenance": True}}
        if operation == "update":
            statement = model.__table__.update().where(model.id == row.id).values(**changes)
        else:
            statement = delete(model.__table__).where(model.id == row.id)
        if db.bind.dialect.name == "postgresql":
            with pytest.raises(Exception, match="(?i)append-only"):
                db.execute(statement)
        else:
            assert db.execute(statement).rowcount == 1
        db.rollback()


@pytest.mark.parametrize("model", [PolicyDecision, PolicyVersion])
@pytest.mark.parametrize("helper", ["bulk_update_mappings", "bulk_save_objects"])
def test_legacy_bulk_helpers_cannot_rewrite(model, helper):
    with SessionLocal() as db:
        if model is PolicyDecision:
            row = decision(db)
            field, original, changed = "simulation", False, True
        else:
            row = PolicyVersion(
                policy_id=policy(db).id, version=1,
                snapshot_json={"original": True}, created_by=admin_id(db),
            )
            db.add(row)
            field, original, changed = "snapshot_json", {"original": True}, {"changed": True}
        db.commit()
        identifier = row.id
        rejected = None
        try:
            if helper == "bulk_update_mappings":
                db.bulk_update_mappings(model, [{"id": identifier, field: changed}])
            else:
                db.expunge(row)
                setattr(row, field, changed)
                db.bulk_save_objects([row])
            db.commit()
        except ValueError as error:
            rejected = error
            db.rollback()
    with SessionLocal() as verify:
        assert getattr(verify.get(model, identifier), field) == original
    assert rejected is not None and "append-only" in str(rejected)


LEGACY_ID_INPUTS = [
    pytest.param(
        EvaluateInput, {"resource": "asset", "action": "read"}, "asset_id", id="evaluate-asset",
    ),
    pytest.param(
        SimulateInput, {"resource": "asset", "action": "read", "subject_user_id": 1},
        "asset_id", id="simulate-asset",
    ),
    pytest.param(
        SimulateInput, {"resource": "asset", "action": "read"},
        "subject_user_id", id="simulate-subject",
    ),
    pytest.param(
        PolicyCreate, {"policy_code": "POL-BOUND-001", "name": "Bounded policy",
                       "resource": "asset", "action": "read", "effect": "ALLOW"},
        "role_ids", id="create-roles",
    ),
    pytest.param(PolicyUpdate, {}, "role_ids", id="update-roles"),
    pytest.param(DecisionFilters, {}, "user_id", id="decision-user-filter"),
]


@pytest.mark.parametrize("schema,base,field", LEGACY_ID_INPUTS)
@pytest.mark.parametrize("identifier", [2147483648, 2**100])
def test_legacy_identifier_rejects_out_of_range(schema, base, field, identifier):
    value = [identifier] if field == "role_ids" else identifier
    with pytest.raises(ValidationError):
        schema(**(base | {field: value}))


@pytest.mark.parametrize("schema,base,field", LEGACY_ID_INPUTS)
@pytest.mark.parametrize("identifier", [1, 2147483647])
def test_legacy_identifier_accepts_storage_boundaries(schema, base, field, identifier):
    value = [identifier] if field == "role_ids" else identifier
    assert getattr(schema(**(base | {field: value})), field) == value


def test_oversized_asset_id_rejected_before_database_binding():
    with SessionLocal() as db, pytest.raises(ValidationError):
        body = EvaluateInput(resource="asset", action="read", asset_id=2**100)
        db.scalar(select(Asset.id).where(Asset.id == body.asset_id))


@pytest.mark.parametrize("helper", ["bulk_update_mappings", "bulk_save_objects"])
def test_legacy_bulk_helpers_preserve_other_model_updates(helper):
    with SessionLocal() as db:
        row = db.get(User, admin_id(db))
        identifier = row.id
        if helper == "bulk_update_mappings":
            db.bulk_update_mappings(User, [{"id": identifier, "display_name": "Bulk update demo"}])
        else:
            db.expunge(row)
            row.display_name = "Bulk update demo"
            db.bulk_save_objects(
                [row], return_defaults=True, update_changed_only=False, preserve_order=False,
            )
        db.commit()
    with SessionLocal() as verify:
        assert verify.get(User, identifier).display_name == "Bulk update demo"


@pytest.mark.parametrize("model", [PolicyDecision, PolicyVersion])
def test_legacy_bulk_save_allows_append_only_inserts(model):
    with SessionLocal() as db:
        identifier = str(uuid4())
        if model is PolicyDecision:
            row = PolicyDecision(
                id=identifier, user_id=admin_id(db), resource="asset", action="read",
                decision=Decision.DENY, reason_code=ReasonCode.DEFAULT_DENY,
                risk_score_snapshot=0, risk_level_snapshot="LOW", mfa_snapshot=False,
                device_trust_snapshot=DeviceTrust.UNTRUSTED,
            )
        else:
            row = PolicyVersion(
                id=identifier, policy_id=policy(db).id, version=1,
                snapshot_json={"insert": True}, created_by=admin_id(db),
            )
        db.bulk_save_objects(
            iter([row]), return_defaults=True, update_changed_only=False, preserve_order=False,
        )
        db.commit()
    with SessionLocal() as verify:
        assert verify.get(model, identifier) is not None


@pytest.mark.parametrize("model", [PolicyDecision, PolicyVersion])
def test_legacy_bulk_save_preflights_entire_generator(model):
    with SessionLocal() as db:
        row = decision(db) if model is PolicyDecision else PolicyVersion(
            policy_id=policy(db).id, version=1, snapshot_json={}, created_by=admin_id(db),
        )
        if model is PolicyVersion:
            db.add(row)
        db.commit()
        db.expunge(row)
        if model is PolicyDecision:
            row.simulation = True
        else:
            row.snapshot_json = {"modified": True}
        device = Device(
            id=str(uuid4()), device_code="DEV-BULK-PREFLIGHT", name="Preflight device",
            trust_level="UNTRUSTED", status="ACTIVE", synthetic=True,
        )
        with pytest.raises(ValueError, match="append-only"):
            db.bulk_save_objects(iter([device, row]))
        db.commit()
        assert db.get(Device, device.id) is None


def test_application_session_is_narrow_and_preserves_configuration():
    from sqlalchemy.orm import Session

    from app.database import ApplicationSession

    with SessionLocal() as db:
        assert isinstance(db, ApplicationSession)
        assert db.get_bind() is engine
        assert db.expire_on_commit is False
    assert Session.bulk_update_mappings.__module__ == "sqlalchemy.orm.session"
    assert Session.bulk_save_objects.__module__ == "sqlalchemy.orm.session"
