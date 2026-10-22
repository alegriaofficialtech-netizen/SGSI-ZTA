import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.dashboard import router as dashboard_router
from app.assets.routes import router as assets_router
from app.auth.mfa_routes import router as mfa_router
from app.auth.routes import router as auth_router
from app.config import get_settings
from app.database import SessionLocal, engine
from app.monitoring.routes import router as monitoring_router
from app.policies.authorization_routes import router as authorization_router
from app.policies.clinical_routes import router as clinical_router
from app.policies.routes import router as policies_router
from app.risks.routes import router as risks_router
from app.users.routes import router as users_router

settings = get_settings()


@asynccontextmanager
async def lifespan(application: FastAPI):
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    yield
    engine.dispose()


app = FastAPI(
    title="SGSI-ZTA Hospital Lab · Native API",
    version="0.4.0",
    description="Academic synthetic M0–M4. Native identity, assets, risks and controls.",
    docs_url=None,
    openapi_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# En modo demo aceptamos cualquier host y cualquier origen
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
def root_health():
    return {"status": "ok"}


@app.middleware("http")
async def security_headers_and_csrf(request: Request, call_next):
    # En modo demo permitimos cualquier petición para compatibilidad con túneles
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    return JSONResponse(
        {
            "detail": [
                {"loc": item["loc"], "msg": item["msg"], "type": item["type"]}
                for item in error.errors()
            ]
        },
        status_code=422,
    )


@app.get("/api/v1/health", tags=["Health"], response_model=None)
def health() -> dict | JSONResponse:
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected", "environment": "ACADEMIC_SYNTHETIC"}
    except SQLAlchemyError:
        return JSONResponse({"status": "unavailable", "database": "unavailable"}, status_code=503)


app.include_router(auth_router, prefix="/api/v1")
app.include_router(mfa_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(assets_router, prefix="/api/v1")
app.include_router(risks_router, prefix="/api/v1")
app.include_router(authorization_router, prefix="/api/v1")
app.include_router(policies_router, prefix="/api/v1")
app.include_router(clinical_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1")
