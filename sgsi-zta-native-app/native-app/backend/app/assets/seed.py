"""Import the reviewed synthetic CSV once per code; never overwrite operator edits."""

import csv
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetType, Department, User
from app.schemas.assets import AssetCreate

TYPES = (
    "Server",
    "Database",
    "Desktop",
    "Laptop",
    "Network Device",
    "Firewall",
    "Backup",
    "Software",
    "Medical Demo Device",
    "Other",
)
DEPARTMENTS = (
    "TI",
    "Admisión",
    "Medicina",
    "Enfermería",
    "Laboratorio",
    "Farmacia",
    "Administración",
)
DATASET = Path(__file__).resolve().parents[2] / "data/synthetic/assets.csv"
if not DATASET.exists():
    DATASET = Path(__file__).resolve().parents[3] / "data/synthetic/assets.csv"


def seed_assets(db: Session) -> None:
    for model, names in ((AssetType, TYPES), (Department, DEPARTMENTS)):
        for name in names:
            if not db.scalar(select(model).where(model.name == name)):
                db.add(model(name=name))
        db.flush()
    types = {row.name: row.id for row in db.scalars(select(AssetType))}
    departments = {row.name: row.id for row in db.scalars(select(Department))}
    users = {row.username: row.id for row in db.scalars(select(User))}
    with DATASET.open(encoding="utf-8", newline="") as source:
        for row in csv.DictReader(source):
            if row["synthetic"] != "true":
                raise ValueError("Only synthetic seed assets are accepted")
            if db.scalar(select(Asset.id).where(Asset.asset_code == row["asset_code"])):
                continue
            values = AssetCreate(
                **{
                    key: value
                    for key, value in row.items()
                    if key
                    in {
                        "asset_code",
                        "name",
                        "criticality",
                        "classification",
                        "status",
                        "hostname_demo",
                        "ip_address_demo",
                        "location_demo",
                    }
                },
                asset_type_id=types[row["asset_type"]],
                department_id=departments[row["department"]],
                owner_user_id=users[row["owner_username"]],
                monitoring_enabled=row["monitoring_enabled"] == "true",
                description="Activo completamente sintético del laboratorio académico SGSI-ZTA.",
            ).model_dump()
            db.add(
                Asset(
                    **values,
                    synthetic=True,
                    created_by=users["admin.demo"],
                    updated_by=users["admin.demo"],
                )
            )
    db.commit()
