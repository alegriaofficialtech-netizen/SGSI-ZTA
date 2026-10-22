"""Authenticated M5 management and read-only, bounded historical projections."""
import re
from datetime import datetime
from math import ceil
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import func, select

from app.auth.dependencies import AuthenticatedSession, Database
from app.models import User
from app.models.policies import Device, Policy, PolicyDecision, PolicyVersion
from app.policies.management import PolicyManagement, get_policy
from app.schemas.policies import (
    DecisionFilters,
    DecisionPage,
    DevicePage,
    DeviceResponse,
    PageFilters,
    PolicyCreate,
    PolicyDecisionResponse,
    PolicyFilters,
    PolicyPage,
    PolicyResponse,
    PolicyUpdate,
    PolicyVersionResponse,
)

router = APIRouter(tags=["Policies"])


def reader(session: AuthenticatedSession) -> User:
    if not {role.name for role in session.user.roles}.intersection({"admin-ti", "auditor"}):
        raise HTTPException(403, "Your role does not permit policy management reads.")
    return session.user


def administrator(session: AuthenticatedSession) -> User:
    if "admin-ti" not in {role.name for role in session.user.roles}:
        raise HTTPException(403, "Your role does not permit policy management writes.")
    return session.user


Reader = Annotated[User, Depends(reader)]
Admin = Annotated[User, Depends(administrator)]


def invalid_query(name: str, message: str) -> None:
    raise RequestValidationError([{
        "loc": ("query", name), "msg": message, "type": "value_error",
    }])


def query_filters(request: Request, schema):
    """Parse wire strings only; strict schemas then enforce ranges and enum values."""
    values = {}
    for name, raw in request.query_params.multi_items():
        if name not in schema.model_fields:
            invalid_query(name, "Unknown query parameter.")
        if name in values:
            invalid_query(name, "Query parameters must not be repeated.")
        if name in {"page", "page_size", "user_id"}:
            if not re.fullmatch(r"[1-9][0-9]{0,9}", raw):
                invalid_query(name, "Expected a bounded positive decimal integer.")
            values[name] = int(raw)
        elif name in {"enabled", "simulation"}:
            if raw not in {"true", "false"}:
                invalid_query(name, "Expected true or false.")
            values[name] = raw == "true"
        elif name in {"date_from", "date_to"}:
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?",
                raw,
            ):
                invalid_query(name, "Expected an ISO datetime; naive timestamps denote UTC.")
            try:
                values[name] = datetime.fromisoformat(raw)
            except ValueError:
                invalid_query(name, "Invalid ISO datetime.")
        else:
            values[name] = raw
    try:
        return schema.model_validate(values)
    except ValidationError as error:
        raise RequestValidationError([
            {"loc": ("query", *item["loc"]), "msg": item["msg"], "type": item["type"]}
            for item in error.errors()
        ]) from error
    except (ValueError, OverflowError):
        invalid_query("date_from", "Datetime cannot be represented in UTC.")


def policy_filters(request: Request) -> PolicyFilters:
    return query_filters(request, PolicyFilters)


def decision_filters(request: Request) -> DecisionFilters:
    return query_filters(request, DecisionFilters)


def page_filters(request: Request) -> PageFilters:
    return query_filters(request, PageFilters)


async def no_body(request: Request) -> None:
    if await request.body():
        raise RequestValidationError([{
            "loc": ("body",), "msg": "Disable does not accept a request body.",
            "type": "value_error",
        }])


def page(db, model, filters, predicates, ordering):
    total = db.scalar(select(func.count()).select_from(model).where(*predicates))
    items = list(db.scalars(select(model).where(*predicates).order_by(*ordering).offset(
        (filters.page - 1) * filters.page_size
    ).limit(filters.page_size)))
    return {"items": items, "page": filters.page, "page_size": filters.page_size,
            "total": total, "pages": ceil(total / filters.page_size)}


@router.get("/policies", response_model=PolicyPage)
def policies(
    db: Database, user: Reader, filters: Annotated[PolicyFilters, Depends(policy_filters)],
):
    predicates = []
    for column, value in ((Policy.resource, filters.resource), (Policy.action, filters.action),
                          (Policy.enabled, filters.enabled)):
        if value is not None:
            predicates.append(column == value)
    return page(db, Policy, filters, predicates, (Policy.policy_code, Policy.id))


@router.post("/policies", response_model=PolicyResponse, status_code=201)
def create_policy(body: PolicyCreate, request: Request, db: Database, user: Admin):
    return PolicyManagement(db, request, user).create(body)


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
def policy_detail(policy_id: UUID, db: Database, user: Reader):
    return get_policy(db, policy_id)


@router.patch("/policies/{policy_id}", response_model=PolicyResponse)
def update_policy(policy_id: UUID, body: PolicyUpdate, request: Request, db: Database, user: Admin):
    return PolicyManagement(db, request, user).update(policy_id, body)


@router.post("/policies/{policy_id}/disable", response_model=PolicyResponse,
             dependencies=[Depends(no_body)])
def disable_policy(policy_id: UUID, request: Request, db: Database, user: Admin):
    return PolicyManagement(db, request, user).disable(policy_id)


@router.get("/policies/{policy_id}/versions", response_model=list[PolicyVersionResponse])
def policy_versions(policy_id: UUID, db: Database, user: Reader):
    get_policy(db, policy_id)
    return list(db.scalars(select(PolicyVersion).where(
        PolicyVersion.policy_id == str(policy_id)
    ).order_by(PolicyVersion.version)))


@router.get("/policy-decisions", response_model=DecisionPage)
def decisions(db: Database, user: Reader,
              filters: Annotated[DecisionFilters, Depends(decision_filters)]):
    predicates = []
    for column, value in (
        (PolicyDecision.decision, filters.decision), (PolicyDecision.user_id, filters.user_id),
        (PolicyDecision.resource, filters.resource),
        (PolicyDecision.simulation, filters.simulation),
    ):
        if value is not None:
            predicates.append(column == value)
    if filters.date_from is not None:
        predicates.append(PolicyDecision.created_at >= filters.date_from)
    if filters.date_to is not None:
        predicates.append(PolicyDecision.created_at <= filters.date_to)
    return page(db, PolicyDecision, filters, predicates,
                (PolicyDecision.created_at.desc(), PolicyDecision.id))


@router.get("/policy-decisions/{decision_id}", response_model=PolicyDecisionResponse)
def decision_detail(decision_id: UUID, db: Database, user: Reader):
    row = db.get(PolicyDecision, str(decision_id))
    if row is None:
        raise HTTPException(404, "Policy decision not found.")
    return row


@router.get("/devices", response_model=DevicePage)
def devices(db: Database, user: Reader, filters: Annotated[PageFilters, Depends(page_filters)]):
    return page(db, Device, filters, [], (Device.device_code, Device.id))


@router.get("/devices/{device_id}", response_model=DeviceResponse)
def device_detail(device_id: UUID, db: Database, user: Reader):
    row = db.get(Device, str(device_id))
    if row is None:
        raise HTTPException(404, "Device not found.")
    return row
