"""Normalized synthetic asset inventory. Preserve identity and MFA tables."""

import sqlalchemy as sa
from alembic import op

revision = "0003_assets"
down_revision = "0002_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("asset_types", "departments"):
        op.create_table(
            table,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(80), unique=True, nullable=False),
        )
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("asset_type_id", sa.Integer(), sa.ForeignKey("asset_types.id"), nullable=False),
        sa.Column("department_id", sa.Integer(), sa.ForeignKey("departments.id"), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "criticality",
            sa.Enum(
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
                native_enum=False,
                create_constraint=True,
                name="asset_criticality",
            ),
            nullable=False,
        ),
        sa.Column(
            "classification",
            sa.Enum(
                "PUBLIC",
                "INTERNAL",
                "CONFIDENTIAL",
                "RESTRICTED",
                native_enum=False,
                create_constraint=True,
                name="asset_classification",
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "INACTIVE",
                "MAINTENANCE",
                "RETIRED",
                native_enum=False,
                create_constraint=True,
                name="asset_status",
            ),
            nullable=False,
        ),
        sa.Column("monitoring_enabled", sa.Boolean(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        *[
            sa.Column(field, sa.String(length), nullable=False)
            for field, length in [
                ("manufacturer", 100),
                ("model", 100),
                ("serial_number", 100),
                ("hostname_demo", 120),
                ("location_demo", 160),
            ]
        ],
        sa.Column("ip_address_demo", sa.String(45), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.CheckConstraint("synthetic = true", name="ck_assets_synthetic"),
        sa.CheckConstraint(
            "(status = 'RETIRED' AND disabled_at IS NOT NULL) OR "
            "(status <> 'RETIRED' AND disabled_at IS NULL)",
            name="ck_assets_retirement",
        ),
    )
    for field in (
        "asset_code",
        "asset_type_id",
        "department_id",
        "owner_user_id",
        "criticality",
        "status",
    ):
        op.create_index(f"ix_assets_{field}", "assets", [field], unique=field == "asset_code")
    op.create_index("ix_audit_logs_resource", "audit_logs", ["resource"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_resource", table_name="audit_logs")
    op.drop_table("assets")
    op.drop_table("departments")
    op.drop_table("asset_types")
