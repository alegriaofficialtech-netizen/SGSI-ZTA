from math import ceil
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select

from app.auth.dependencies import Database, require_roles
from app.models import Asset, Control, Risk, Threat, User, Vulnerability
from app.models.risks import ControlCategory, ImplementationStatus, RiskLevel, RiskStatus, Treatment
from app.risks import service
from app.risks.engine import THRESHOLDS, calculate_score, classify_risk
from app.schemas.assets import OwnerPublic
from app.schemas.risks import (
    AssetReference,
    CatalogResponse,
    ControlCreate,
    ControlDetail,
    ControlPage,
    ControlResponse,
    ControlUpdate,
    LinkCreate,
    LinkResponse,
    RiskCreate,
    RiskDetail,
    RiskPage,
    RiskResponse,
    RiskUpdate,
)

router = APIRouter(tags=["Risks and controls"])
Reader = Annotated[User, Depends(require_roles("admin-ti", "auditor"))]
Admin = Annotated[User, Depends(require_roles("admin-ti"))]
Page = Annotated[int, Query(ge=1, le=100000)]
PageSize = Annotated[int, Query(ge=1, le=100)]
Positive = Annotated[int | None, Query(gt=0)]


@router.get("/threats", response_model=list[CatalogResponse])
def threats(db: Database, user: Reader):
    return list(db.scalars(select(Threat).order_by(Threat.code)))


@router.get("/vulnerabilities", response_model=list[CatalogResponse])
def vulnerabilities(db: Database, user: Reader):
    return list(db.scalars(select(Vulnerability).order_by(Vulnerability.code)))


@router.get("/risks/options")
def options(db: Database, user: Reader):
    return {
        "assets": [
            AssetReference.model_validate(row)
            for row in db.scalars(
                select(Asset).where(Asset.status != "RETIRED").order_by(Asset.asset_code)
            )
        ],
        "owners": [
            OwnerPublic.model_validate(row)
            for row in db.scalars(
                select(User)
                .where(User.is_active.is_(True), User.username.endswith(".demo"))
                .order_by(User.username)
            )
        ],
    }


@router.get("/risks/summary")
@router.get("/controls/summary")
def summary(db: Database, user: Reader):
    return service.summary(db)


@router.get("/risks/matrix")
def matrix(db: Database, user: Reader, include_closed: bool = False, asset_id: Positive = None):
    conditions = [] if include_closed else [Risk.status != RiskStatus.CLOSED]
    if asset_id is not None:
        conditions.append(Risk.asset_id == asset_id)
    counts = {
        (p, i): count
        for p, i, count in db.execute(
            select(Risk.probability, Risk.impact, func.count(Risk.id))
            .where(*conditions)
            .group_by(Risk.probability, Risk.impact)
        )
    }
    cells = []
    for p in range(5, 0, -1):
        for i in range(1, 6):
            score = calculate_score(p, i)
            cells.append(
                {
                    "probability": p,
                    "impact": i,
                    "score": score,
                    "level": classify_risk(score),
                    "count": counts.get((p, i), 0),
                }
            )
    return {
        "cells": cells,
        "total": sum(counts.values()),
        "include_closed": include_closed,
        "thresholds": [{"maximum": maximum, "level": level} for maximum, level in THRESHOLDS],
    }


@router.get("/risks", response_model=RiskPage)
def risks(
    db: Database,
    user: Reader,
    page: Page = 1,
    page_size: PageSize = 20,
    search: Annotated[str, Query(max_length=120)] = "",
    asset_id: Positive = None,
    level: RiskLevel | None = None,
    status: RiskStatus | None = None,
    treatment: Treatment | None = None,
    owner: Positive = None,
    threat: Positive = None,
    vulnerability: Positive = None,
    probability: Annotated[int | None, Query(ge=1, le=5)] = None,
    impact: Annotated[int | None, Query(ge=1, le=5)] = None,
    exclude_closed: bool = False,
    sort_by: Literal[
        "risk_code", "score", "level", "status", "created_at", "updated_at"
    ] = "risk_code",
    sort_order: Literal["asc", "desc"] = "asc",
):
    conditions = []
    if search.strip():
        escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(
            or_(
                *[
                    field.ilike(f"%{escaped}%", escape="\\")
                    for field in (
                        Risk.risk_code,
                        Risk.title,
                        Asset.asset_code,
                        Asset.name,
                        Threat.name,
                    )
                ]
            )
        )
    for field, value in (
        (Risk.asset_id, asset_id),
        (Risk.level, level),
        (Risk.status, status),
        (Risk.treatment, treatment),
        (Risk.owner_user_id, owner),
        (Risk.threat_id, threat),
        (Risk.vulnerability_id, vulnerability),
        (Risk.probability, probability),
        (Risk.impact, impact),
    ):
        if value is not None:
            conditions.append(field == value)
    if exclude_closed:
        conditions.append(Risk.status != RiskStatus.CLOSED)
    base = (
        select(Risk)
        .join(Asset, Risk.asset_id == Asset.id)
        .join(Threat, Risk.threat_id == Threat.id)
        .where(*conditions)
    )
    total = db.scalar(select(func.count()).select_from(base.with_only_columns(Risk.id).subquery()))
    column = Risk.score if sort_by == "level" else getattr(Risk, sort_by)
    rows = db.scalars(
        base.order_by(column.desc() if sort_order == "desc" else column.asc(), Risk.id.asc())
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


@router.post("/risks", response_model=RiskResponse, status_code=201)
def create_risk(body: RiskCreate, request: Request, db: Database, user: Admin):
    return service.create_risk(db, request, user, body.model_dump())


@router.get("/risks/{risk_id}", response_model=RiskDetail)
def risk_detail(risk_id: int, db: Database, user: Reader):
    return service.risk_detail(db, service.get(db, Risk, risk_id))


@router.patch("/risks/{risk_id}", response_model=RiskResponse)
def update_risk(risk_id: int, body: RiskUpdate, request: Request, db: Database, user: Admin):
    return service.change_risk(
        db,
        request,
        user,
        service.get(db, Risk, risk_id, lock=True),
        body.model_dump(exclude_unset=True),
    )


@router.post("/risks/{risk_id}/close", response_model=RiskResponse)
def close(risk_id: int, request: Request, db: Database, user: Admin):
    return service.change_risk(
        db, request, user, service.get(db, Risk, risk_id, lock=True), {"status": RiskStatus.CLOSED}
    )


@router.get("/risks/{risk_id}/controls", response_model=list[LinkResponse])
def risk_controls(risk_id: int, db: Database, user: Reader):
    service.get(db, Risk, risk_id)
    return service.links(db, risk_id)


@router.post("/risks/{risk_id}/controls/{control_id}", response_model=LinkResponse, status_code=201)
def link(
    risk_id: int, control_id: int, body: LinkCreate, request: Request, db: Database, user: Admin
):
    return service.link_control(db, request, user, risk_id, control_id, body.model_dump())


@router.delete("/risks/{risk_id}/controls/{control_id}")
def unlink(risk_id: int, control_id: int, request: Request, db: Database, user: Admin):
    row = service.unlink_control(db, request, user, risk_id, control_id)
    return {
        "risk_id": row.risk_id,
        "control_id": row.control_id,
        "active": row.active,
        "disabled_at": row.disabled_at,
    }


@router.get("/controls/options", response_model=list[ControlResponse])
def control_options(db: Database, user: Reader):
    return list(
        db.scalars(select(Control).where(Control.active.is_(True)).order_by(Control.control_code))
    )


@router.get("/controls", response_model=ControlPage)
def controls(
    db: Database,
    user: Reader,
    page: Page = 1,
    page_size: PageSize = 20,
    search: Annotated[str, Query(max_length=120)] = "",
    category: ControlCategory | None = None,
    implementation_status: ImplementationStatus | None = None,
    owner: Positive = None,
    active: bool | None = None,
    sort_by: Literal[
        "control_code", "name", "implementation_status", "created_at", "updated_at"
    ] = "control_code",
    sort_order: Literal["asc", "desc"] = "asc",
):
    conditions = []
    if search.strip():
        escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(
            or_(
                Control.control_code.ilike(f"%{escaped}%", escape="\\"),
                Control.name.ilike(f"%{escaped}%", escape="\\"),
            )
        )
    for field, value in (
        (Control.category, category),
        (Control.implementation_status, implementation_status),
        (Control.owner_user_id, owner),
        (Control.active, active),
    ):
        if value is not None:
            conditions.append(field == value)
    total = db.scalar(select(func.count(Control.id)).where(*conditions))
    column = getattr(Control, sort_by)
    rows = list(
        db.scalars(
            select(Control)
            .where(*conditions)
            .order_by(column.desc() if sort_order == "desc" else column.asc(), Control.id.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return {
        "items": [service.control_response(db, row) for row in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": ceil(total / page_size),
    }


@router.post("/controls", response_model=ControlResponse, status_code=201)
def create_control(body: ControlCreate, request: Request, db: Database, user: Admin):
    return service.create_control(db, request, user, body.model_dump())


@router.get("/controls/{control_id}", response_model=ControlDetail)
def control_detail(control_id: int, db: Database, user: Reader):
    return service.control_detail(db, service.get(db, Control, control_id))


@router.patch("/controls/{control_id}", response_model=ControlResponse)
def update_control(
    control_id: int, body: ControlUpdate, request: Request, db: Database, user: Admin
):
    return service.change_control(
        db,
        request,
        user,
        service.get(db, Control, control_id, lock=True),
        body.model_dump(exclude_unset=True),
    )


@router.post("/controls/{control_id}/disable", response_model=ControlResponse)
def disable(control_id: int, request: Request, db: Database, user: Admin):
    return service.change_control(
        db, request, user, service.get(db, Control, control_id, lock=True), {"active": False}
    )
