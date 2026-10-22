import json

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.database import now_utc
from app.models import Asset, AuditLog, Control, Risk, RiskControl, Threat, User, Vulnerability
from app.models.risks import RiskStatus
from app.risks.engine import calculate_score, classify_risk
from app.schemas.risks import ControlResponse, LinkResponse, RiskResponse
from app.services.audit import record

RISK_EVENTS = {
    "score": "RISK_SCORE_CHANGED",
    "level": "RISK_LEVEL_CHANGED",
    "treatment": "RISK_TREATMENT_CHANGED",
    "owner_user_id": "RISK_OWNER_CHANGED",
    "status": "RISK_STATUS_CHANGED",
}
SAFE_RISK = {*RISK_EVENTS, "probability", "impact", "asset_id", "threat_id", "vulnerability_id"}


def get(db, model, identifier, *, lock=False):
    row = (
        db.scalar(select(model).where(model.id == identifier).with_for_update(of=model))
        if lock
        else db.get(model, identifier)
    )
    if not row:
        raise HTTPException(404, "Registro no encontrado")
    return row


def owner(db, values):
    if "owner_user_id" in values:
        row = db.get(User, values["owner_user_id"])
        if not row or not row.is_active or not row.username.endswith(".demo"):
            raise HTTPException(422, "El responsable debe ser un usuario .demo activo")


def risk_relations(db, values):
    owner(db, values)
    for field, model in (
        ("asset_id", Asset),
        ("threat_id", Threat),
        ("vulnerability_id", Vulnerability),
    ):
        if field in values:
            row = db.get(model, values[field])
            if not row:
                raise HTTPException(422, "Referencia no válida: " + field)
            if model == Asset and row.status == "RETIRED":
                raise HTTPException(
                    409, "Selecciona un activo no retirado para la nueva asociación"
                )
            if model != Asset and not row.active:
                raise HTTPException(409, "El catálogo seleccionado está inactivo")


def finish(db, row):
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(
            409, "Código o relación duplicada; la operación fue revertida"
        ) from error
    db.refresh(row)
    return row


def event(db, request, actor, action, resource, **detail):
    record(db, request, action, resource, "ALLOW", actor, detail=json.dumps(detail))


def calculate(row):
    row.score = calculate_score(row.probability, row.impact)
    row.level = classify_risk(row.score)
    row.closed_at = (row.closed_at or now_utc()) if row.status == RiskStatus.CLOSED else None


def create_risk(db, request, actor, values):
    risk_relations(db, values)
    if values.get("identified_at") is None:
        values.pop("identified_at", None)
    row = Risk(**values, created_by=actor.id, updated_by=actor.id)
    calculate(row)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "El código del riesgo ya existe") from error
    event(
        db,
        request,
        actor,
        "RISK_CREATED",
        f"risks/{row.id}",
        risk_id=row.id,
        risk_code=row.risk_code,
    )
    return finish(db, row)


def change_risk(db, request, actor, row, values):
    risk_relations(db, values)
    before = {field: getattr(row, field) for field in SAFE_RISK}
    fields = sorted(field for field, value in values.items() if getattr(row, field) != value)
    if not fields:
        return row
    for field, value in values.items():
        setattr(row, field, value)
    calculate(row)
    row.updated_by = actor.id
    row.updated_at = now_utc()
    resource = f"risks/{row.id}"
    event(db, request, actor, "RISK_UPDATED", resource, risk_id=row.id, fields=fields)
    for field in SAFE_RISK:
        after = getattr(row, field)
        if before[field] != after:
            event(
                db,
                request,
                actor,
                RISK_EVENTS.get(field, "RISK_UPDATED"),
                resource,
                field=field,
                before=before[field],
                after=after,
            )
    if row.status == RiskStatus.CLOSED and before["status"] != RiskStatus.CLOSED:
        event(db, request, actor, "RISK_CLOSED", resource, risk_id=row.id)
    return finish(db, row)


def create_control(db, request, actor, values):
    owner(db, values)
    row = Control(**values)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "El código del control ya existe") from error
    event(
        db,
        request,
        actor,
        "CONTROL_CREATED",
        f"controls/{row.id}",
        control_id=row.id,
        control_code=row.control_code,
    )
    return finish(db, row)


def change_control(db, request, actor, row, values):
    owner(db, values)
    fields = sorted(field for field, value in values.items() if getattr(row, field) != value)
    before = row.implementation_status
    active = row.active
    if not fields:
        return row
    for field, value in values.items():
        setattr(row, field, value)
    row.updated_at = now_utc()
    resource = f"controls/{row.id}"
    event(db, request, actor, "CONTROL_UPDATED", resource, control_id=row.id, fields=fields)
    if before != row.implementation_status:
        event(
            db,
            request,
            actor,
            "CONTROL_STATUS_CHANGED",
            resource,
            field="implementation_status",
            before=before,
            after=row.implementation_status,
        )
    if active and not row.active:
        event(db, request, actor, "CONTROL_DISABLED", resource, control_id=row.id)
    return finish(db, row)


def link_control(db, request, actor, risk_id, control_id, values):
    get(db, Risk, risk_id, lock=True)
    control = get(db, Control, control_id, lock=True)
    if not control.active:
        raise HTTPException(409, "El control está deshabilitado")
    row = db.get(RiskControl, (risk_id, control_id))
    if row and row.active:
        raise HTTPException(409, "El control ya está asociado")
    if row:
        for key, value in values.items():
            setattr(row, key, value)
        row.active = True
        row.disabled_at = None
        row.updated_at = now_utc()
    else:
        row = RiskControl(risk_id=risk_id, control_id=control_id, **values, created_by=actor.id)
        db.add(row)
    event(
        db,
        request,
        actor,
        "RISK_CONTROL_LINKED",
        f"risks/{risk_id}",
        risk_id=risk_id,
        control_id=control_id,
        relationship_type=values["relationship_type"],
    )
    return finish(db, row)


def unlink_control(db, request, actor, risk_id, control_id):
    get(db, Risk, risk_id, lock=True)
    get(db, Control, control_id)
    row = db.get(RiskControl, (risk_id, control_id))
    if not row:
        raise HTTPException(404, "La relación no existe")
    if not row.active:
        return row
    row.active = False
    row.disabled_at = row.updated_at = now_utc()
    event(
        db,
        request,
        actor,
        "RISK_CONTROL_UNLINKED",
        f"risks/{risk_id}",
        risk_id=risk_id,
        control_id=control_id,
    )
    return finish(db, row)


def history(db, resource):
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.resource == resource)
            .order_by(AuditLog.id.desc())
            .limit(50)
        )
    )


def control_response(db, row):
    data = ControlResponse.model_validate(row).model_dump()
    data["risk_count"] = db.scalar(
        select(func.count())
        .select_from(RiskControl)
        .where(RiskControl.control_id == row.id, RiskControl.active.is_(True))
    )
    return data


def links(db, risk_id):
    return list(
        db.scalars(
            select(RiskControl)
            .where(RiskControl.risk_id == risk_id, RiskControl.active.is_(True))
            .order_by(RiskControl.control_id)
        )
    )


def risk_detail(db, row):
    return RiskResponse.model_validate(row).model_dump() | {
        "controls": [LinkResponse.model_validate(item) for item in links(db, row.id)],
        "history": history(db, f"risks/{row.id}"),
    }


def control_detail(db, row):
    risks = list(
        db.scalars(
            select(Risk)
            .join(RiskControl, RiskControl.risk_id == Risk.id)
            .where(RiskControl.control_id == row.id, RiskControl.active.is_(True))
            .order_by(Risk.risk_code)
        )
    )
    # Link audit events live on risks, so include the safe control-id scoped events.
    return control_response(db, row) | {
        "risks": risks,
        "history": history(db, f"controls/{row.id}"),
    }


def summary(db):
    def counts(model, field):
        return [
            {"name": str(name), "value": value}
            for name, value in db.execute(select(field, func.count(model.id)).group_by(field))
        ]

    def count(model, *conditions):
        return db.scalar(select(func.count(model.id)).where(*conditions))

    return {
        "total": count(Risk),
        "critical": count(Risk, Risk.level == "CRITICAL"),
        "high": count(Risk, Risk.level == "HIGH"),
        "open": count(Risk, Risk.status == "OPEN"),
        "in_treatment": count(Risk, Risk.status == "IN_TREATMENT"),
        "closed": count(Risk, Risk.status == "CLOSED"),
        "controls_total": count(Control),
        "implemented": count(Control, Control.implementation_status == "IMPLEMENTED"),
        "partial": count(Control, Control.implementation_status == "PARTIAL"),
        "planned": count(Control, Control.implementation_status == "PLANNED"),
        "disabled_controls": count(Control, Control.active.is_(False)),
        "by_level": counts(Risk, Risk.level),
        "by_treatment": counts(Risk, Risk.treatment),
        "controls_by_status": counts(Control, Control.implementation_status),
        "count_scope": "ALL_INCLUDING_CLOSED_AND_DISABLED",
    }
