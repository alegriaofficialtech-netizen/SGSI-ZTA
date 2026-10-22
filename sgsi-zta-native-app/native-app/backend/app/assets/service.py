import json

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import now_utc
from app.models import Asset, AssetType, Department, User
from app.models.assets import AssetStatus
from app.services.audit import record

SENSITIVE_EVENTS = {
    "owner_user_id": "ASSET_OWNER_CHANGED",
    "criticality": "ASSET_CRITICALITY_CHANGED",
    "classification": "ASSET_CLASSIFICATION_CHANGED",
    "status": "ASSET_STATUS_CHANGED",
}
SAFE_HISTORY_FIELDS = {*SENSITIVE_EVENTS, "asset_type_id", "department_id", "monitoring_enabled"}


def validate_relations(db: Session, changes: dict) -> None:
    for field, model in (
        ("asset_type_id", AssetType),
        ("department_id", Department),
        ("owner_user_id", User),
    ):
        if field not in changes:
            continue
        related = db.get(model, changes[field])
        if not related:
            raise HTTPException(422, f"Referencia no válida: {field}")
        if field == "owner_user_id" and (
            not related.is_active or not related.username.endswith(".demo")
        ):
            raise HTTPException(422, "El responsable debe ser un usuario .demo activo")


def get_asset(db: Session, asset_id: int, *, lock=False) -> Asset:
    asset = (
        db.scalar(select(Asset).where(Asset.id == asset_id).with_for_update(of=Asset))
        if lock
        else db.get(Asset, asset_id)
    )
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    return asset


def apply_status(asset: Asset) -> None:
    asset.disabled_at = (
        (asset.disabled_at or now_utc()) if asset.status == AssetStatus.RETIRED else None
    )
    if asset.status == AssetStatus.RETIRED:
        asset.monitoring_enabled = False


def save(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "El código del activo ya existe") from error


def change_asset(
    db: Session, request: Request, asset: Asset, changes: dict, actor: User, *, disable=False
) -> Asset:
    if any(value is None for field, value in changes.items() if field != "ip_address_demo"):
        raise HTTPException(422, "Los campos actualizados no admiten null")
    validate_relations(db, changes)
    if (
        "status" not in changes
        and asset.status == AssetStatus.RETIRED
        and changes.get("monitoring_enabled")
    ):
        raise HTTPException(409, "Reactiva el activo antes de habilitar su monitoreo")
    before = {field: getattr(asset, field) for field in SAFE_HISTORY_FIELDS}
    changed = sorted(field for field, value in changes.items() if getattr(asset, field) != value)
    for field, value in changes.items():
        setattr(asset, field, value)
    apply_status(asset)
    if not changed:
        return asset
    asset.updated_by = actor.id
    asset.updated_at = now_utc()
    resource = f"assets/{asset.id}"
    record(
        db,
        request,
        "ASSET_DISABLED" if disable else "ASSET_UPDATED",
        resource,
        "ALLOW",
        actor,
        detail=json.dumps({"asset_id": asset.id, "fields": changed}),
    )
    for field, action in SENSITIVE_EVENTS.items():
        if before[field] != getattr(asset, field):
            record(
                db,
                request,
                action,
                resource,
                "ALLOW",
                actor,
                detail=json.dumps(
                    {
                        "asset_id": asset.id,
                        "field": field,
                        "before": before[field],
                        "after": getattr(asset, field),
                    }
                ),
            )
    save(db)
    db.refresh(asset)
    return asset


def asset_summary(db: Session) -> dict:
    def counts(field):
        return [
            {"name": str(name), "value": count}
            for name, count in db.execute(
                select(field, func.count(Asset.id)).select_from(Asset).group_by(field)
            ).all()
        ]

    return {
        "total": db.scalar(select(func.count(Asset.id))),
        "critical": db.scalar(select(func.count(Asset.id)).where(Asset.criticality == "CRITICAL")),
        "high": db.scalar(select(func.count(Asset.id)).where(Asset.criticality == "HIGH")),
        "monitored": db.scalar(
            select(func.count(Asset.id)).where(Asset.monitoring_enabled.is_(True))
        ),
        "by_status": counts(Asset.status),
        "by_criticality": counts(Asset.criticality),
        "by_type": [
            {"name": name, "value": count}
            for name, count in db.execute(
                select(AssetType.name, func.count(Asset.id))
                .join(Asset, Asset.asset_type_id == AssetType.id)
                .group_by(AssetType.name)
            ).all()
        ],
        "by_department": [
            {"name": name, "value": count}
            for name, count in db.execute(
                select(Department.name, func.count(Asset.id))
                .join(Asset, Asset.department_id == Department.id)
                .group_by(Department.name)
            ).all()
        ],
        "count_scope": "ALL_INCLUDING_RETIRED",
    }
