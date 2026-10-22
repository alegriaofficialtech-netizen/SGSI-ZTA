from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text, update

from app.database import SessionLocal, engine
from app.models import Policy, PolicyDecision, PolicyVersion, User


def create_isolated_decision(db) -> PolicyDecision:
    u = db.scalar(select(User).where(User.username == "admin.demo"))
    row = PolicyDecision(
        id=str(uuid4()),
        user_id=u.id,
        resource="test-immutability-resource",
        action="read",
        decision="ALLOW",
        reason_code="POLICY_ALLOW",
        risk_score_snapshot=10,
        risk_level_snapshot="LOW",
        mfa_snapshot=True,
        device_trust_snapshot="TRUSTED",
    )
    db.add(row)
    db.commit()
    return row


def create_isolated_version(db) -> tuple[Policy, PolicyVersion]:
    u = db.scalar(select(User).where(User.username == "admin.demo"))
    pol = Policy(
        id=str(uuid4()),
        policy_code=f"POL-TEST-IMMUT-{uuid4().hex[:6]}",
        name="Test Immutability Policy",
        description="Isolated policy for version immutability tests",
        resource="test-immutability",
        action="read",
        effect="DENY",
        priority=999,
        enabled=True,
        created_by=u.id,
        updated_by=u.id,
    )
    db.add(pol)
    db.flush()
    ver = PolicyVersion(
        id=str(uuid4()),
        policy_id=pol.id,
        version=1,
        snapshot_json={"test": True},
        created_by=u.id,
    )
    db.add(ver)
    db.commit()
    return pol, ver


def test_policy_decisions_immutability_orm_update():
    with SessionLocal() as db:
        row = create_isolated_decision(db)
        row.resource = "tampered-resource"
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.commit()
        db.rollback()


def test_policy_decisions_immutability_orm_delete():
    with SessionLocal() as db:
        row = create_isolated_decision(db)
        db.delete(row)
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.commit()
        db.rollback()


def test_policy_decisions_immutability_core_update():
    with SessionLocal() as db:
        row = create_isolated_decision(db)
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.execute(
                update(PolicyDecision)
                .where(PolicyDecision.id == row.id)
                .values(resource="tampered")
            )
            db.commit()
        db.rollback()


def test_policy_decisions_immutability_core_delete():
    with SessionLocal() as db:
        row = create_isolated_decision(db)
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.execute(delete(PolicyDecision).where(PolicyDecision.id == row.id))
            db.commit()
        db.rollback()


def test_policy_decisions_immutability_raw_sql_update():
    with SessionLocal() as db:
        row = create_isolated_decision(db)
        if engine.dialect.name == "postgresql":
            with pytest.raises(Exception, match="(?i)append-only"):
                db.execute(
                    text("UPDATE policy_decisions SET decision = 'DENY' WHERE id = :id"),
                    {"id": row.id},
                )
                db.flush()
            db.rollback()
        else:
            # SQLite does not fire SQL triggers unless created in SQLite; tested via ORM/Core
            pass


def test_policy_decisions_immutability_raw_sql_delete():
    with SessionLocal() as db:
        row = create_isolated_decision(db)
        if engine.dialect.name == "postgresql":
            with pytest.raises(Exception, match="(?i)append-only"):
                db.execute(
                    text("DELETE FROM policy_decisions WHERE id = :id"),
                    {"id": row.id},
                )
                db.flush()
            db.rollback()


def test_policy_versions_immutability_orm_update():
    with SessionLocal() as db:
        pol, ver = create_isolated_version(db)
        ver.version = 999
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.commit()
        db.rollback()


def test_policy_versions_immutability_orm_delete():
    with SessionLocal() as db:
        pol, ver = create_isolated_version(db)
        db.delete(ver)
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.commit()
        db.rollback()


def test_policy_versions_immutability_core_update():
    with SessionLocal() as db:
        pol, ver = create_isolated_version(db)
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.execute(
                update(PolicyVersion).where(PolicyVersion.id == ver.id).values(version=999)
            )
            db.commit()
        db.rollback()


def test_policy_versions_immutability_core_delete():
    with SessionLocal() as db:
        pol, ver = create_isolated_version(db)
        with pytest.raises((ValueError, Exception), match="append-only"):
            db.execute(delete(PolicyVersion).where(PolicyVersion.id == ver.id))
            db.commit()
        db.rollback()


def test_policy_versions_immutability_raw_sql_update():
    with SessionLocal() as db:
        pol, ver = create_isolated_version(db)
        if engine.dialect.name == "postgresql":
            with pytest.raises(Exception, match="(?i)append-only"):
                db.execute(
                    text("UPDATE policy_versions SET version = 999 WHERE id = :id"),
                    {"id": ver.id},
                )
                db.flush()
            db.rollback()


def test_policy_versions_immutability_raw_sql_delete():
    with SessionLocal() as db:
        pol, ver = create_isolated_version(db)
        if engine.dialect.name == "postgresql":
            with pytest.raises(Exception, match="(?i)append-only"):
                db.execute(
                    text("DELETE FROM policy_versions WHERE id = :id"),
                    {"id": ver.id},
                )
                db.flush()
            db.rollback()


def test_runtime_user_bypass_attempt_is_blocked_on_postgresql():
    """In PostgreSQL, runtime user setting GUC sgsi.bypass_immutability='on' is STILL BLOCKED."""
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL-specific test")

    with SessionLocal() as db:
        row = create_isolated_decision(db)
        # Runtime user attempts to enable bypass GUC
        db.execute(text("SET LOCAL sgsi.bypass_immutability = 'on'"))
        with pytest.raises(Exception, match="(?i)append-only"):
            db.execute(
                text("UPDATE policy_decisions SET decision = 'DENY' WHERE id = :id"),
                {"id": row.id},
            )
            db.flush()
        db.rollback()


def test_runtime_user_cannot_drop_trigger_on_postgresql():
    """In PostgreSQL, non-owner runtime user cannot drop immutability triggers."""
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL-specific test")

    with SessionLocal() as db:
        is_superuser = db.scalar(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        )
        owner = db.scalar(
            text(
                "SELECT tableowner FROM pg_tables "
                "WHERE tablename = 'policy_decisions' AND schemaname = 'public'"
            )
        )
        current_u = db.scalar(text("SELECT current_user"))

        if is_superuser:
            sp = db.begin_nested()
            try:
                db.execute(
                    text(
                        "DO $$ BEGIN "
                        "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = "
                        "'test_unprivileged_runtime') THEN "
                        "CREATE ROLE test_unprivileged_runtime NOSUPERUSER; "
                        "END IF; "
                        "END $$;"
                    )
                )
                db.execute(text("SET LOCAL ROLE test_unprivileged_runtime"))
                with pytest.raises(Exception, match="(?i)must be owner"):
                    db.execute(
                        text(
                            "DROP TRIGGER trg_protect_policy_decisions_update "
                            "ON policy_decisions"
                        )
                    )
                    db.flush()
            finally:
                sp.rollback()
        elif owner != current_u:
            with pytest.raises(Exception, match="(?i)must be owner"):
                db.execute(
                    text(
                        "DROP TRIGGER trg_protect_policy_decisions_update "
                        "ON policy_decisions"
                    )
                )
                db.flush()
            db.rollback()
