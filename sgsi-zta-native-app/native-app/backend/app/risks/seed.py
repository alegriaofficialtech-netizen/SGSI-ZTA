"""Original synthetic scenarios, not detected incidents or certified compliance."""

from sqlalchemy import select

from app.models import Asset, Control, Risk, RiskControl, Threat, User, Vulnerability
from app.risks.service import calculate

THREATS = [
    "Acceso no autorizado",
    "Compromiso de credenciales",
    "Modificación no autorizada de información",
    "Interrupción del servicio",
    "Malware",
    "Pérdida de información",
    "Error humano",
    "Uso indebido de privilegios",
    "Falla de respaldo",
    "Acceso desde dispositivo no confiable",
]
VULNERABILITIES = [
    "Contraseña débil",
    "Ausencia de MFA",
    "Privilegios excesivos",
    "Falta de monitoreo",
    "Configuración insegura",
    "Falta de respaldo verificado",
    "Sistema desactualizado",
    "Segmentación insuficiente",
    "Auditoría insuficiente",
    "Clasificación de activos incompleta",
]
CONTROLS = [
    (
        "Autenticación multifactor",
        "IDENTITY",
        "IMPLEMENTED",
        "Requerir un segundo factor para usuarios o funciones de mayor criticidad.",
    ),
    (
        "Gestión de privilegios",
        "ACCESS_CONTROL",
        "PARTIAL",
        "Asignar permisos mínimos y revisar las funciones autorizadas.",
    ),
    (
        "Monitoreo de integridad",
        "MONITORING",
        "PLANNED",
        "Revisar cambios inesperados en componentes del laboratorio.",
    ),
    (
        "Registro de eventos",
        "AUDIT",
        "PARTIAL",
        "Conservar acciones relevantes con actor, recurso y fecha.",
    ),
    (
        "Gestión de respaldos",
        "BACKUP",
        "PLANNED",
        "Programar copias y verificar restauraciones de datos sintéticos.",
    ),
    (
        "Clasificación de activos",
        "ASSET_MANAGEMENT",
        "IMPLEMENTED",
        "Registrar sensibilidad y criticidad para orientar el tratamiento.",
    ),
    (
        "Revisión periódica de accesos",
        "GOVERNANCE",
        "PARTIAL",
        "Evaluar periódicamente quién necesita acceso a cada recurso.",
    ),
    (
        "Gestión de sesiones",
        "IDENTITY",
        "IMPLEMENTED",
        "Limitar vigencia y revocar sesiones al cerrar el acceso.",
    ),
    (
        "Segregación de funciones",
        "GOVERNANCE",
        "PLANNED",
        "Distribuir tareas sensibles entre funciones distintas.",
    ),
    (
        "Control de cambios",
        "CHANGE_MANAGEMENT",
        "PLANNED",
        "Registrar y revisar cambios antes de aplicarlos al laboratorio.",
    ),
]
SCENARIOS = [
    ("SRV-HIS-01", 1, 2, 4, 5, "REDUCE", "OPEN", "Acceso no autorizado al servidor HIS Demo"),
    (
        "DB-HIS-01",
        3,
        3,
        3,
        5,
        "REDUCE",
        "IN_TREATMENT",
        "Alteración de información sintética del HIS",
    ),
    ("LAP-MED-01", 10, 8, 3, 4, "REDUCE", "OPEN", "Acceso desde laptop sin confianza verificada"),
    (
        "BKP-HIS-01",
        6,
        6,
        2,
        5,
        "REDUCE",
        "OPEN",
        "Pérdida de información por respaldo sin verificar",
    ),
    (
        "FW-LAB-01",
        4,
        5,
        2,
        4,
        "TRANSFER",
        "IN_TREATMENT",
        "Interrupción por configuración de firewall",
    ),
    ("PC-ADM-01", 7, 9, 2, 2, "ACCEPT", "ACCEPTED", "Error de registro en estación de admisión"),
    ("PC-FAR-01", 5, 7, 3, 3, "REDUCE", "OPEN", "Malware en estación sintética de farmacia"),
    ("NET-LAB-01", 8, 8, 1, 3, "AVOID", "CLOSED", "Uso de privilegios en segmento de laboratorio"),
]


def seed_risks(db):
    admin = db.scalar(select(User).where(User.username == "admin.demo"))
    for model, prefix, names in ((Threat, "THR", THREATS), (Vulnerability, "VUL", VULNERABILITIES)):
        for n, name in enumerate(names, 1):
            code = f"{prefix}-{n:03}"
            if not db.scalar(select(model.id).where(model.code == code)):
                db.add(
                    model(
                        code=code,
                        name=name,
                        description=(
                            f"Escenario académico sintético: {name.lower()}. "
                            "No representa un hallazgo real."
                        ),
                        category="ACADEMIC_SCENARIO",
                        active=True,
                    )
                )
    db.flush()
    for n, (name, category, status, description) in enumerate(CONTROLS, 1):
        code = f"CTRL-{n:03}"
        if not db.scalar(select(Control.id).where(Control.control_code == code)):
            db.add(
                Control(
                    control_code=code,
                    name=name,
                    description=description,
                    category=category,
                    implementation_status=status,
                    owner_user_id=admin.id,
                    active=True,
                )
            )
    db.flush()
    for n, (asset_code, threat, vul, p, i, treatment, status, title) in enumerate(SCENARIOS, 1):
        code = f"R-{n:03}"
        if not db.scalar(select(Risk.id).where(Risk.risk_code == code)):
            asset = db.scalar(select(Asset).where(Asset.asset_code == asset_code))
            if not asset:
                raise RuntimeError("Required M3 seed asset missing: " + asset_code)
            row = Risk(
                risk_code=code,
                title=title,
                description=(
                    "Escenario académico sintético para explorar tratamiento y trazabilidad."
                ),
                asset_id=asset.id,
                threat_id=db.scalar(select(Threat.id).where(Threat.code == f"THR-{threat:03}")),
                vulnerability_id=db.scalar(
                    select(Vulnerability.id).where(Vulnerability.code == f"VUL-{vul:03}")
                ),
                probability=p,
                impact=i,
                treatment=treatment,
                status=status,
                owner_user_id=admin.id,
                created_by=admin.id,
                updated_by=admin.id,
            )
            calculate(row)
            db.add(row)
    db.flush()
    for risk_n, control_numbers in ((1, [1, 2, 4]), (2, [2, 4]), (3, [1, 7]), (4, [5])):
        risk_id = db.scalar(select(Risk.id).where(Risk.risk_code == f"R-{risk_n:03}"))
        for control_n in control_numbers:
            control_id = db.scalar(
                select(Control.id).where(Control.control_code == f"CTRL-{control_n:03}")
            )
            # Retain inactive pairs, so rerunning seed never restores manual unlinking.
            if not db.get(RiskControl, (risk_id, control_id)):
                db.add(
                    RiskControl(
                        risk_id=risk_id,
                        control_id=control_id,
                        relationship_type="PREVENTIVE",
                        notes="Relación sintética inicial.",
                        created_by=admin.id,
                        active=True,
                    )
                )
    db.commit()
