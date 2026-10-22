"""Academic risks, controls and reversible traceability; preserve M0-M3."""

import sqlalchemy as sa
from alembic import op

revision = "0004_risks_controls"
down_revision = "0003_assets"
branch_labels = None
depends_on = None


def enum(name, *values):
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True)


def fk(name, table):
    return sa.Column(name, sa.Integer(), sa.ForeignKey(table + ".id"), nullable=False)


def upgrade():
    for table in ("threats", "vulnerabilities"):
        op.create_table(
            table,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("code", sa.String(40), unique=True, nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("category", sa.String(60), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
        )
    op.create_table(
        "risks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("risk_code", sa.String(40), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        fk("asset_id", "assets"),
        fk("threat_id", "threats"),
        fk("vulnerability_id", "vulnerabilities"),
        sa.Column("probability", sa.Integer(), nullable=False),
        sa.Column("impact", sa.Integer(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", enum("risk_level", "LOW", "MEDIUM", "HIGH", "CRITICAL"), nullable=False),
        sa.Column(
            "treatment",
            enum("risk_treatment", "ACCEPT", "AVOID", "REDUCE", "TRANSFER"),
            nullable=False,
        ),
        sa.Column(
            "status",
            enum("risk_status", "OPEN", "IN_TREATMENT", "ACCEPTED", "CLOSED"),
            nullable=False,
        ),
        fk("owner_user_id", "users"),
        *[
            sa.Column(name, sa.DateTime(), nullable=False)
            for name in ("identified_at", "created_at", "updated_at")
        ],
        sa.Column("review_due_at", sa.DateTime(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        fk("created_by", "users"),
        fk("updated_by", "users"),
        sa.CheckConstraint("probability BETWEEN 1 AND 5", name="ck_risks_probability"),
        sa.CheckConstraint("impact BETWEEN 1 AND 5", name="ck_risks_impact"),
        sa.CheckConstraint("score = probability * impact", name="ck_risks_score"),
        sa.CheckConstraint(
            "level = CASE WHEN score <= 4 THEN 'LOW' WHEN score <= 9 THEN 'MEDIUM' "
            "WHEN score <= 16 THEN 'HIGH' ELSE 'CRITICAL' END",
            name="ck_risks_level",
        ),
        sa.CheckConstraint(
            "(status = 'CLOSED' AND closed_at IS NOT NULL) OR "
            "(status <> 'CLOSED' AND closed_at IS NULL)",
            name="ck_risks_closed",
        ),
    )
    for name in (
        "risk_code",
        "asset_id",
        "threat_id",
        "vulnerability_id",
        "level",
        "status",
        "owner_user_id",
    ):
        op.create_index("ix_risks_" + name, "risks", [name], unique=name == "risk_code")
    op.create_table(
        "controls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("control_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "category",
            enum(
                "control_category",
                "ACCESS_CONTROL",
                "IDENTITY",
                "MONITORING",
                "ASSET_MANAGEMENT",
                "BACKUP",
                "AUDIT",
                "CHANGE_MANAGEMENT",
                "NETWORK_SECURITY",
                "GOVERNANCE",
                "INCIDENT_RESPONSE",
            ),
            nullable=False,
        ),
        sa.Column(
            "implementation_status",
            enum("control_implementation", "PLANNED", "PARTIAL", "IMPLEMENTED", "NOT_APPLICABLE"),
            nullable=False,
        ),
        fk("owner_user_id", "users"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    for name in ("control_code", "implementation_status", "owner_user_id"):
        op.create_index("ix_controls_" + name, "controls", [name], unique=name == "control_code")
    op.create_table(
        "risk_controls",
        sa.Column("risk_id", sa.Integer(), sa.ForeignKey("risks.id"), primary_key=True),
        sa.Column("control_id", sa.Integer(), sa.ForeignKey("controls.id"), primary_key=True),
        sa.Column(
            "relationship_type",
            enum("risk_control_relationship", "PREVENTIVE", "DETECTIVE", "CORRECTIVE"),
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        fk("created_by", "users"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "(active = true AND disabled_at IS NULL) OR "
            "(active = false AND disabled_at IS NOT NULL)",
            name="ck_risk_controls_active",
        ),
    )
    for name in ("risk_id", "control_id"):
        op.create_index("ix_risk_controls_" + name, "risk_controls", [name])


def downgrade():
    for table in ("risk_controls", "controls", "risks", "vulnerabilities", "threats"):
        op.drop_table(table)
