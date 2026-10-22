"""Zero Trust contracts and append-only decision/version persistence; preserve M0-M4."""

import sqlalchemy as sa
from alembic import op

revision = "0005_zero_trust"
down_revision = "0004_risks_controls"
branch_labels = None
depends_on = None

ACTIONS = ("read", "read_sensitive", "create", "update", "disable", "approve", "export")
TRUST = ("TRUSTED", "LIMITED", "UNTRUSTED")
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
REASONS = (
    "POLICY_ALLOW",
    "EXPLICIT_DENY",
    "MFA_REQUIRED",
    "ROLE_NOT_ALLOWED",
    "DEVICE_UNTRUSTED",
    "RISK_THRESHOLD_EXCEEDED",
    "SESSION_TOO_OLD",
    "DEFAULT_DENY",
)


def choice(name, values):
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True)


def identifier():
    return sa.Column("id", sa.String(36), primary_key=True)


def fk(name, table, *, nullable=False, uuid=False, primary_key=False, ondelete=None):
    return sa.Column(
        name,
        sa.String(36) if uuid else sa.Integer(),
        sa.ForeignKey(table + ".id", ondelete=ondelete),
        nullable=nullable,
        primary_key=primary_key,
    )


def timestamps():
    return (
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def upgrade():
    op.create_table(
        "policies",
        identifier(),
        sa.Column("policy_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("action", choice("policy_action", ACTIONS), nullable=False),
        sa.Column("effect", choice("policy_effect", ("ALLOW", "DENY")), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("require_mfa", sa.Boolean(), nullable=False),
        sa.Column("max_risk_score", sa.Integer(), nullable=True),
        sa.Column(
            "required_device_trust", choice("policy_required_device_trust", TRUST), nullable=True
        ),
        sa.Column("session_max_age_minutes", sa.Integer(), nullable=True),
        *timestamps(),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        fk("created_by", "users"),
        fk("updated_by", "users"),
        sa.CheckConstraint("priority BETWEEN 0 AND 1000", name="ck_policies_priority"),
        sa.CheckConstraint(
            "max_risk_score IS NULL OR max_risk_score BETWEEN 0 AND 25",
            name="ck_policies_risk",
        ),
        sa.CheckConstraint(
            "session_max_age_minutes IS NULL OR session_max_age_minutes BETWEEN 1 AND 10080",
            name="ck_policies_session_age",
        ),
        sa.CheckConstraint(
            "(enabled = true AND disabled_at IS NULL) OR "
            "(enabled = false AND disabled_at IS NOT NULL)",
            name="ck_policies_disabled",
        ),
        sa.CheckConstraint("length(policy_code) BETWEEN 3 AND 40", name="ck_policies_code_length"),
        sa.CheckConstraint(
            "length(resource) BETWEEN 1 AND 64 AND resource NOT LIKE '%*%' "
            "AND resource NOT LIKE '%/%'",
            name="ck_policies_resource",
        ),
    )
    op.create_index("ix_policies_policy_code", "policies", ["policy_code"], unique=True)
    op.create_index("ix_policies_lookup", "policies", ["resource", "action", "enabled", "priority"])
    op.create_table(
        "policy_roles",
        fk("policy_id", "policies", uuid=True, primary_key=True, ondelete="CASCADE"),
        fk("role_id", "roles", primary_key=True),
    )
    op.create_index("ix_policy_roles_role_id", "policy_roles", ["role_id"])
    op.create_table(
        "policy_conditions",
        identifier(),
        fk("policy_id", "policies", uuid=True, ondelete="CASCADE"),
        sa.Column(
            "condition_type",
            choice(
                "condition_type",
                (
                    "ROLE",
                    "MFA",
                    "ASSET_CRITICALITY",
                    "RISK_LEVEL",
                    "RISK_SCORE",
                    "DEVICE_TRUST",
                    "SESSION_AGE",
                    "TIME_WINDOW",
                ),
            ),
            nullable=False,
        ),
        sa.Column(
            "operator",
            choice("condition_operator", ("EQ", "IN", "LTE", "GTE", "BETWEEN")),
            nullable=False,
        ),
        sa.Column("value", sa.JSON(), nullable=False),
    )
    op.create_index("ix_policy_conditions_policy_id", "policy_conditions", ["policy_id"])
    op.create_index(
        "ix_policy_conditions_policy_type",
        "policy_conditions",
        ["policy_id", "condition_type"],
    )
    op.create_table(
        "devices",
        identifier(),
        sa.Column("device_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        fk("assigned_user_id", "users", nullable=True),
        sa.Column("trust_level", choice("device_trust", TRUST), nullable=False),
        sa.Column("status", choice("device_status", ("ACTIVE", "INACTIVE")), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        *timestamps(),
        sa.CheckConstraint("synthetic = true", name="ck_devices_synthetic"),
    )
    op.create_index("ix_devices_device_code", "devices", ["device_code"], unique=True)
    op.create_index("ix_devices_assigned_user_id", "devices", ["assigned_user_id"])
    op.create_table(
        "policy_decisions",
        identifier(),
        fk("user_id", "users"),
        fk("session_id", "sessions", uuid=True, nullable=True),
        fk("policy_id", "policies", uuid=True, nullable=True),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("action", choice("policy_decision_action", ACTIONS), nullable=False),
        fk("asset_id", "assets", nullable=True),
        fk("device_id", "devices", uuid=True, nullable=True),
        sa.Column(
            "decision", choice("policy_decision", ("ALLOW", "DENY", "MFA_REQUIRED")), nullable=False
        ),
        sa.Column("reason_code", choice("policy_reason_code", REASONS), nullable=False),
        sa.Column("risk_score_snapshot", sa.Integer(), nullable=False),
        sa.Column("risk_level_snapshot", choice("policy_risk_level", LEVELS), nullable=False),
        sa.Column("mfa_snapshot", sa.Boolean(), nullable=False),
        sa.Column(
            "device_trust_snapshot", choice("policy_device_trust_snapshot", TRUST), nullable=False
        ),
        sa.Column("simulation", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("risk_score_snapshot BETWEEN 0 AND 25", name="ck_policy_decisions_risk"),
    )
    for column in ("user_id", "session_id", "policy_id", "asset_id", "device_id"):
        op.create_index("ix_policy_decisions_" + column, "policy_decisions", [column])
    for column, label in (("user_id", "user"), ("resource", "resource"), ("decision", "decision")):
        op.create_index(
            "ix_policy_decisions_" + label + "_created",
            "policy_decisions",
            [column, "created_at"],
        )
    op.create_table(
        "policy_versions",
        identifier(),
        fk("policy_id", "policies", uuid=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        fk("created_by", "users"),
        sa.UniqueConstraint("policy_id", "version", name="uq_policy_versions_number"),
        sa.CheckConstraint("version >= 1", name="ck_policy_versions_positive"),
    )
    op.create_index("ix_policy_versions_policy_id", "policy_versions", ["policy_id"])
    with op.batch_alter_table("audit_logs") as batch:
        batch.add_column(sa.Column("policy_decision_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_audit_logs_policy_decision_id",
            "policy_decisions",
            ["policy_decision_id"],
            ["id"],
        )
        batch.create_index("ix_audit_logs_policy_decision_id", ["policy_decision_id"])


def downgrade():
    with op.batch_alter_table("audit_logs") as batch:
        batch.drop_index("ix_audit_logs_policy_decision_id")
        batch.drop_constraint("fk_audit_logs_policy_decision_id", type_="foreignkey")
        batch.drop_column("policy_decision_id")
    for table in (
        "policy_versions",
        "policy_decisions",
        "devices",
        "policy_conditions",
        "policy_roles",
        "policies",
    ):
        op.drop_table(table)
