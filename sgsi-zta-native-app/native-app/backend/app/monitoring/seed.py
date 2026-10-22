"""Idempotent seed for academic monitoring alert rules."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import now_utc
from app.models.identity import User
from app.models.monitoring import AlertRule
from app.monitoring.types import EventType, Severity

DEFAULT_RULES = (
    (
        "RULE-FIM-HIGH",
        "Detección de integridad de archivos críticos",
        "Alerta académica ante cambios de alta severidad en integridad de archivos.",
        EventType.FILE_INTEGRITY_CHANGE,
        Severity.HIGH,
        300,
    ),
    (
        "RULE-AUTH-FAILURE",
        "Fallos reiterados o sospechosos de autenticación",
        "Alerta ante eventos de fallo de autenticación con severidad media o superior.",
        EventType.AUTH_FAILURE,
        Severity.MEDIUM,
        180,
    ),
    (
        "RULE-ZT-DENY",
        "Denegación de políticas Zero Trust de alto riesgo",
        "Alerta académica ante denegaciones de acceso de severidad alta o crítica.",
        EventType.POLICY_DENY,
        Severity.HIGH,
        300,
    ),
)


def seed_monitoring_rules(db: Session) -> None:
    """Seed default academic alert rules idempotently."""
    admin = db.scalar(select(User).where(User.username == "admin.demo"))
    if not admin:
        return

    for code, name, desc, event_type, min_sev, cooldown in DEFAULT_RULES:
        existing = db.scalar(select(AlertRule).where(AlertRule.rule_code == code))
        if existing:
            continue
        rule = AlertRule(
            rule_code=code,
            name=name,
            description=desc,
            enabled=True,
            event_type=event_type,
            minimum_severity=min_sev,
            asset_criticality=None,
            cooldown_seconds=cooldown,
            created_by=admin.id,
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        db.add(rule)

    db.commit()


def seed_monitoring_fim(db: Session) -> None:
    """Seed internal FIM source and synthetic FIM targets idempotently.

    Never overwrites existing targets or modified baselines on subsequent seeds.
    """
    from app.models.assets import Asset
    from app.models.monitoring import FimTarget
    from app.monitoring.fim import (
        compute_file_sha256,
        get_or_create_internal_fim_source,
        resolve_safe_fim_path,
    )

    # 1. Initialize internal FIM monitoring source
    get_or_create_internal_fim_source(db)

    # 2. Resolve asset reference if present
    srv_his = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
    srv_his_id = srv_his.id if srv_his else None

    synthetic_targets = (
        ("FIM-PATIENT-DEMO", "patient-demo.json", srv_his_id),
        ("FIM-HOSPITAL-CONFIG", "hospital-config-demo.json", srv_his_id),
        ("FIM-LIS-DEMO", "lis-interface-demo.json", srv_his_id),
    )

    now = now_utc()
    for code, rel_path, asset_id in synthetic_targets:
        existing = db.scalar(select(FimTarget).where(FimTarget.target_code == code))
        if existing:
            continue

        try:
            resolved_path = resolve_safe_fim_path(rel_path)
            if not resolved_path.is_file():
                continue
            initial_hash = compute_file_sha256(resolved_path)
        except Exception:
            continue

        target = FimTarget(
            target_code=code,
            relative_path=rel_path,
            asset_id=asset_id,
            baseline_sha256=initial_hash,
            last_sha256=initial_hash,
            enabled=True,
            last_checked_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(target)

    db.commit()
