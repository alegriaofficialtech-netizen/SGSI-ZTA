import json
from math import ceil
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import case, func, or_, select

from app.assets.service import (
    apply_status,
    asset_summary,
    change_asset,
    get_asset,
    save,
    validate_relations,
)
from app.auth.dependencies import Database, require_roles
from app.models import Asset, AssetType, AuditLog, Department, User
from app.models.assets import AssetStatus, Classification, Criticality
from app.schemas.assets import (
    AssetCreate,
    AssetDetail,
    AssetPage,
    AssetResponse,
    AssetUpdate,
    CatalogPublic,
    OwnerPublic,
)
from app.schemas.identity import AuditPublic
from app.services.audit import record

router = APIRouter(tags=["Assets"])
Reader = Annotated[User, Depends(require_roles("admin-ti", "auditor"))]
Admin = Annotated[User, Depends(require_roles("admin-ti"))]
SortField = Literal[
    "asset_code", "name", "criticality", "classification", "status", "created_at", "updated_at"
]


@router.get("/asset-types", response_model=list[CatalogPublic])
def types(db: Database, user: Reader):
    return list(db.scalars(select(AssetType).order_by(AssetType.name)))


@router.get("/departments", response_model=list[CatalogPublic])
def departments(db: Database, user: Reader):
    return list(db.scalars(select(Department).order_by(Department.name)))


@router.get("/assets/owners", response_model=list[OwnerPublic])
def owners(db: Database, user: Admin):
    return list(
        db.scalars(
            select(User)
            .where(User.is_active.is_(True), User.username.endswith(".demo"))
            .order_by(User.username)
        )
    )


@router.get("/assets/summary")
def summary(db: Database, user: Reader):
    return asset_summary(db)


@router.get("/assets", response_model=AssetPage)
def assets(
    db: Database,
    user: Reader,
    page: Annotated[int, Query(ge=1, le=100000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    search: Annotated[str, Query(max_length=120)] = "",
    criticality: Criticality | None = None,
    classification: Classification | None = None,
    status: AssetStatus | None = None,
    department: Annotated[int | None, Query(gt=0)] = None,
    asset_type: Annotated[int | None, Query(gt=0)] = None,
    monitoring_enabled: bool | None = None,
    sort_by: SortField = "asset_code",
    sort_order: Literal["asc", "desc"] = "asc",
):
    conditions = []
    if search.strip():
        escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(
            or_(
                *[
                    field.ilike(f"%{escaped}%", escape="\\")
                    for field in (Asset.asset_code, Asset.name, Asset.hostname_demo)
                ]
            )
        )
    for field, value in (
        (Asset.criticality, criticality),
        (Asset.classification, classification),
        (Asset.status, status),
        (Asset.department_id, department),
        (Asset.asset_type_id, asset_type),
        (Asset.monitoring_enabled, monitoring_enabled),
    ):
        if value is not None:
            conditions.append(field == value)
    total = db.scalar(select(func.count(Asset.id)).where(*conditions))
    column = getattr(Asset, sort_by)  # Literal whitelist validated before this lookup.
    if sort_by == "criticality":
        column = case({"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}, value=Asset.criticality)
    rows = db.scalars(
        select(Asset)
        .where(*conditions)
        .order_by(column.desc() if sort_order == "desc" else column.asc(), Asset.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "items": rows,
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": ceil(total / page_size),
    }


@router.post("/assets", response_model=AssetResponse, status_code=201)
def create(body: AssetCreate, request: Request, db: Database, admin: Admin):
    values = body.model_dump()
    validate_relations(db, values)
    asset = Asset(**values, created_by=admin.id, updated_by=admin.id, synthetic=True)
    apply_status(asset)
    db.add(asset)
    # Obtain the resource ID while handling concurrent unique-code conflicts.
    from fastapi import HTTPException
    from sqlalchemy.exc import IntegrityError

    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "El código del activo ya existe") from error
    record(
        db,
        request,
        "ASSET_CREATED",
        f"assets/{asset.id}",
        "ALLOW",
        admin,
        detail=json.dumps({"asset_id": asset.id, "asset_code": asset.asset_code}),
    )
    save(db)
    db.refresh(asset)
    return asset


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def detail(asset_id: int, db: Database, user: Reader):
    asset = get_asset(db, asset_id)
    result = AssetResponse.model_validate(asset).model_dump()
    result["history"] = [
        AuditPublic.model_validate(row)
        for row in db.scalars(
            select(AuditLog)
            .where(AuditLog.resource == f"assets/{asset.id}", AuditLog.action.startswith("ASSET_"))
            .order_by(AuditLog.id.desc())
            .limit(30)
        )
    ]
    return result


@router.patch("/assets/{asset_id}", response_model=AssetResponse)
def update(asset_id: int, body: AssetUpdate, request: Request, db: Database, admin: Admin):
    return change_asset(
        db, request, get_asset(db, asset_id, lock=True), body.model_dump(exclude_unset=True), admin
    )


@router.post("/assets/{asset_id}/disable", response_model=AssetResponse)
def disable(asset_id: int, request: Request, db: Database, admin: Admin):
    return change_asset(
        db,
        request,
        get_asset(db, asset_id, lock=True),
        {"status": AssetStatus.RETIRED, "monitoring_enabled": False},
        admin,
        disable=True,
    )
