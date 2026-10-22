from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import delete

from app.auth import mfa_service
from app.auth.dependencies import AuthenticatedUser, Database
from app.auth.mfa_policy import required
from app.auth.service import clear_cookies, create_session
from app.models import RecoveryCode
from app.schemas.mfa import ChallengeInput, FactorConfirmation, VerifyInput
from app.services.audit import record

router = APIRouter(prefix="/auth/mfa", tags=["MFA"])


@router.post("/setup")
def setup(body: ChallengeInput, request: Request, db: Database) -> dict:
    result = mfa_service.setup(db, request, body.challenge_token.get_secret_value())
    db.commit()
    return result


@router.post("/verify")
def verify(body: VerifyInput, request: Request, response: Response, db: Database) -> dict:
    user, remember, codes = mfa_service.verify(
        db,
        request,
        body.challenge_token.get_secret_value(),
        body.code.get_secret_value(),
        body.recovery,
    )
    result = create_session(db, request, response, user, remember, mfa_verified=True)
    if codes is not None:
        result["recovery_codes"] = codes
    db.commit()
    return result


@router.post("/recovery/regenerate")
def regenerate(
    body: FactorConfirmation, request: Request, db: Database, user: AuthenticatedUser
) -> dict:
    mfa_service.confirm_factor(
        db, request, user, body.password.get_secret_value(), body.code.get_secret_value()
    )
    codes = mfa_service.regenerate_codes(db, user)
    record(db, request, "MFA_RECOVERY_REGENERATED", "auth/mfa", "ALLOW", user)
    db.commit()
    return {"recovery_codes": codes}


@router.post("/disable")
def disable(
    body: FactorConfirmation,
    request: Request,
    response: Response,
    db: Database,
    user: AuthenticatedUser,
) -> dict:
    if required(user):
        raise HTTPException(409, "Tu rol requiere un segundo factor")
    credential = mfa_service.confirm_factor(
        db, request, user, body.password.get_secret_value(), body.code.get_secret_value()
    )
    credential.enabled = False
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    mfa_service.revoke_account_sessions(db, user)
    record(db, request, "MFA_DISABLED", "auth/mfa", "ALLOW", user)
    db.commit()
    clear_cookies(response)
    return {"status": "disabled"}
