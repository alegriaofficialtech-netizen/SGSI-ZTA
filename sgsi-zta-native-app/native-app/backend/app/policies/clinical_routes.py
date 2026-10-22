"""Authenticated synthetic clinical endpoint protected by AuthorizationService."""
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from app.auth.dependencies import AuthenticatedSession, Database
from app.models import Asset
from app.policies.service import AuthorizationService
from app.policies.types import Decision
from app.schemas.policies import ClinicalResponse, ClinicalSummaryItem

router = APIRouter(tags=["Clinical"])

SYNTHETIC_CLINICAL_RECORDS = {
    "PAT-DEMO-001": {
        "demo_id": "PAT-DEMO-001",
        "patient_synthetic_name": "Carlos Mendoza (Sintético)",
        "age_range": "45-50",
        "department": "Cardiología / UCI",
        "record_type": "Informe Electrocardiograma y Marcadores",
        "status": "OBSERVACION",
        "diagnosis_summary": (
            "Trazado con taquicardia sinusal leve en reposo; biomarcadores normales."
        ),
        "phi_classified": True,
        "default_action": "read",
    },
    "PAT-DEMO-002": {
        "demo_id": "PAT-DEMO-002",
        "patient_synthetic_name": "Elena Ramos (Sintética)",
        "age_range": "30-35",
        "department": "Laboratorio de Hematología",
        "record_type": "Hemograma Completo y Perfil Bioquímico",
        "status": "ESTABLE",
        "diagnosis_summary": (
            "Recuento leucocitario y plaquetario dentro de parámetros fisiológicos estándar."
        ),
        "phi_classified": False,
        "default_action": "read",
    },
    "PAT-DEMO-003": {
        "demo_id": "PAT-DEMO-003",
        "patient_synthetic_name": "Javier Quispe (Sintético)",
        "age_range": "60-65",
        "department": "Oncología Médica",
        "record_type": "Biopsia Tisular y Panel Genético Ficticio",
        "status": "CRITICO",
        "diagnosis_summary": (
            "Muestra patológica con hallazgo inflamatorio agudo severo. "
            "Requiere interconsulta urgente."
        ),
        "phi_classified": True,
        "default_action": "read_sensitive",
    },
}


@router.get("/clinical/records", response_model=list[ClinicalSummaryItem])
def list_clinical_records(
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    device_id: UUID | None = None,
) -> list[ClinicalSummaryItem]:
    if "action" in request.query_params:
        raise HTTPException(422, [{
            "loc": ["query", "action"],
            "msg": "Client cannot specify action.",
            "type": "value_error",
        }])

    allowed_params = {"device_id"}
    for param in request.query_params.keys():
        if param not in allowed_params:
            raise HTTPException(422, [{
                "loc": ["query", param],
                "msg": "Unknown query parameter.",
                "type": "value_error",
            }])

    asset = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
    asset_id = asset.id if asset else None
    service = AuthorizationService(db, request)

    output = []
    for k, v in SYNTHETIC_CLINICAL_RECORDS.items():
        eval_res = service.authorize(
            session,
            resource="clinical-demo",
            action=v["default_action"],
            asset_id=asset_id,
            device_id=device_id,
        )
        if eval_res.decision == Decision.ALLOW:
            output.append(ClinicalSummaryItem(
                id=f"rec-{k[-3:]}",
                demo_id=v["demo_id"],
                patient_synthetic_name=v["patient_synthetic_name"],
                age_range=v["age_range"],
                department=v["department"],
                record_type=v["record_type"],
                status=v["status"],
                diagnosis_summary=v["diagnosis_summary"],
                phi_classified=v["phi_classified"],
                access_decision="ALLOW",
                decision_id=str(eval_res.evaluation_id),
            ))
        else:
            output.append(ClinicalSummaryItem(
                id=f"rec-{k[-3:]}",
                demo_id=v["demo_id"],
                patient_synthetic_name=None,
                age_range=None,
                department=None,
                record_type=None,
                status=f"DENEGADO ({eval_res.reason_code.value})",
                diagnosis_summary=None,
                phi_classified=None,
                access_decision=eval_res.decision.value,
                decision_id=str(eval_res.evaluation_id),
            ))
    return output


@router.get("/clinical/{id}", response_model=ClinicalResponse)
@router.get("/clinical/records/{id}", response_model=ClinicalResponse)
def get_clinical_record(
    id: str,
    request: Request,
    db: Database,
    session: AuthenticatedSession,
    device_id: UUID | None = None,
) -> ClinicalResponse:
    if "action" in request.query_params:
        raise HTTPException(422, [{
            "loc": ["query", "action"],
            "msg": "Client cannot specify action.",
            "type": "value_error",
        }])

    allowed_params = {"device_id"}
    for param in request.query_params.keys():
        if param not in allowed_params:
            raise HTTPException(422, [{
                "loc": ["query", param],
                "msg": "Unknown query parameter.",
                "type": "value_error",
            }])

    record = SYNTHETIC_CLINICAL_RECORDS.get(id)
    if record is None:
        raise HTTPException(404, "Clinical record not found.")

    chosen_action = record["default_action"]

    # Server-derived asset context; client cannot supply asset_id
    asset = db.scalar(select(Asset).where(Asset.asset_code == "SRV-HIS-01"))
    asset_id = asset.id if asset else None

    service = AuthorizationService(db, request)
    response = service.authorize(
        session,
        resource="clinical-demo",
        action=chosen_action,
        asset_id=asset_id,
        device_id=device_id,
    )

    if response.decision == Decision.ALLOW:
        return ClinicalResponse(
            demo_id=record["demo_id"],
            patient_synthetic_name=record["patient_synthetic_name"],
            age_range=record["age_range"],
            department=record["department"],
            record_type=record["record_type"],
            status=record["status"],
            diagnosis_summary=record["diagnosis_summary"],
            phi_classified=record["phi_classified"],
            decision_id=str(response.evaluation_id),
            policy_code=response.policy_code,
            context=response.context,
        )

    message = (
        "Additional authentication is required."
        if response.decision == Decision.MFA_REQUIRED
        else "Access denied by Zero Trust policy."
    )
    raise HTTPException(
        403,
        {
            "code": response.reason_code.value,
            "message": message,
            "decision_id": str(response.evaluation_id),
            "policy_code": response.policy_code,
            "context": response.context.model_dump(mode="json"),
        },
    )
