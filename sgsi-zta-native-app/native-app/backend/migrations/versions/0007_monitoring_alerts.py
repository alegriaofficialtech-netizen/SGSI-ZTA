# ruff: noqa: E501
"""M6 Security Monitoring, Alerts, and Academic FIM tables with DB immutability."""

import sqlalchemy as sa
from alembic import op

revision = "0007_monitoring_alerts"
down_revision = "0006_db_immutability"
branch_labels = None
depends_on = None

SEVERITY = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_STATUS = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
EVENT_TYPES = (
    "AUTH_FAILURE",
    "AUTH_SUCCESS",
    "MFA_FAILURE",
    "POLICY_DENY",
    "POLICY_MFA_REQUIRED",
    "FILE_INTEGRITY_CHANGE",
    "ASSET_CHANGE",
    "RISK_CHANGE",
    "SECURITY_CONFIGURATION_CHANGE",
)
SOURCE_TYPES = ("HOST", "APPLICATION", "DATABASE", "FIM", "NETWORK", "SYNTHETIC_AGENT")


def choice(name, values):
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True)


def identifier():
    return sa.Column("id", sa.String(36), primary_key=True)


def timestamps():
    return (
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def upgrade():
    # 1. monitoring_sources
    op.create_table(
        "monitoring_sources",
        identifier(),
        sa.Column("source_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("source_type", choice("monitoring_source_type", SOURCE_TYPES), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        *timestamps(),
        sa.CheckConstraint("length(source_code) BETWEEN 3 AND 40", name="ck_sources_code_len"),
    )
    op.create_index("ix_monitoring_sources_source_code", "monitoring_sources", ["source_code"], unique=True)
    op.create_index("ix_monitoring_sources_asset_id", "monitoring_sources", ["asset_id"])

    # 2. monitoring_events (APPEND-ONLY)
    op.create_table(
        "monitoring_events",
        identifier(),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("monitoring_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_event_id", sa.String(128), nullable=False),
        sa.Column("event_type", choice("monitoring_event_type", EVENT_TYPES), nullable=False),
        sa.Column("severity", choice("monitoring_severity", SEVERITY), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source_id", "source_event_id", name="uq_monitoring_events_source_event"),
    )
    op.create_index("ix_monitoring_events_source_id", "monitoring_events", ["source_id"])
    op.create_index("ix_monitoring_events_asset_id", "monitoring_events", ["asset_id"])
    op.create_index("ix_monitoring_events_fingerprint", "monitoring_events", ["fingerprint"])
    op.create_index("ix_monitoring_events_occurred_at", "monitoring_events", ["occurred_at"])
    op.create_index("ix_monitoring_events_type_severity", "monitoring_events", ["event_type", "severity"])

    # 3. alert_rules
    op.create_table(
        "alert_rules",
        identifier(),
        sa.Column("rule_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("event_type", choice("alert_rule_event_type", EVENT_TYPES), nullable=False),
        sa.Column("minimum_severity", choice("alert_rule_min_severity", SEVERITY), nullable=False),
        sa.Column("asset_criticality", sa.String(20), nullable=True),
        sa.Column("cooldown_seconds", sa.Integer(), server_default="300", nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        *timestamps(),
        sa.CheckConstraint("cooldown_seconds >= 0", name="ck_alert_rules_cooldown_positive"),
        sa.CheckConstraint("length(rule_code) BETWEEN 3 AND 40", name="ck_alert_rules_code_len"),
    )
    op.create_index("ix_alert_rules_rule_code", "alert_rules", ["rule_code"], unique=True)
    op.create_index("ix_alert_rules_event_type", "alert_rules", ["event_type"])

    # 4. alerts
    op.create_table(
        "alerts",
        identifier(),
        sa.Column("alert_code", sa.String(40), nullable=False),
        sa.Column("event_id", sa.String(36), sa.ForeignKey("monitoring_events.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("rule_id", sa.String(36), sa.ForeignKey("alert_rules.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("severity", choice("alert_severity", SEVERITY), nullable=False),
        sa.Column("status", choice("alert_status", ALERT_STATUS), server_default="OPEN", nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        *timestamps(),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_alerts_occurrence_count_positive"),
    )
    op.create_index("ix_alerts_alert_code", "alerts", ["alert_code"], unique=True)
    op.create_index("ix_alerts_event_id", "alerts", ["event_id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_asset_id", "alerts", ["asset_id"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])

    # 5. alert_history (APPEND-ONLY)
    op.create_table(
        "alert_history",
        identifier(),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("previous_status", choice("alert_hist_prev_status", ALERT_STATUS), nullable=True),
        sa.Column("new_status", choice("alert_hist_new_status", ALERT_STATUS), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_alert_history_alert_id", "alert_history", ["alert_id"])

    # 6. fim_targets
    op.create_table(
        "fim_targets",
        identifier(),
        sa.Column("target_code", sa.String(40), nullable=False),
        sa.Column("relative_path", sa.String(255), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("baseline_sha256", sa.String(64), nullable=False),
        sa.Column("last_sha256", sa.String(64), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        *timestamps(),
        sa.CheckConstraint(
            "relative_path NOT LIKE '/%' AND relative_path NOT LIKE '\\\\%' AND relative_path NOT LIKE '%..%'",
            name="ck_fim_targets_relative_path_safe",
        ),
    )
    op.create_index("ix_fim_targets_target_code", "fim_targets", ["target_code"], unique=True)
    op.create_index("ix_fim_targets_asset_id", "fim_targets", ["asset_id"])

    # 7. PostgreSQL Immutability Triggers (for monitoring_events and alert_history)
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("""
            DO $role$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sgsi_admin') THEN
                    CREATE ROLE sgsi_admin;
                END IF;
            END
            $role$;

            -- MonitoringEvent immutability trigger
            CREATE OR REPLACE FUNCTION protect_monitoring_events_immutability()
            RETURNS TRIGGER AS $$
            DECLARE
                can_bypass boolean := false;
            BEGIN
                IF current_setting('sgsi.bypass_immutability', true) = 'on' THEN
                    IF current_user IN ('sgsi_admin', 'postgres') THEN
                        can_bypass := true;
                    END IF;
                END IF;

                IF can_bypass THEN
                    IF TG_OP = 'DELETE' THEN
                        RETURN OLD;
                    ELSE
                        RETURN NEW;
                    END IF;
                END IF;

                RAISE EXCEPTION 'monitoring_events table is append-only';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS trg_protect_monitoring_events_update ON monitoring_events;
            DROP TRIGGER IF EXISTS trg_protect_monitoring_events_delete ON monitoring_events;

            CREATE TRIGGER trg_protect_monitoring_events_update
            BEFORE UPDATE ON monitoring_events
            FOR EACH ROW EXECUTE FUNCTION protect_monitoring_events_immutability();

            CREATE TRIGGER trg_protect_monitoring_events_delete
            BEFORE DELETE ON monitoring_events
            FOR EACH ROW EXECUTE FUNCTION protect_monitoring_events_immutability();

            -- AlertHistory immutability trigger
            CREATE OR REPLACE FUNCTION protect_alert_history_immutability()
            RETURNS TRIGGER AS $$
            DECLARE
                can_bypass boolean := false;
            BEGIN
                IF current_setting('sgsi.bypass_immutability', true) = 'on' THEN
                    IF current_user IN ('sgsi_admin', 'postgres') THEN
                        can_bypass := true;
                    END IF;
                END IF;

                IF can_bypass THEN
                    IF TG_OP = 'DELETE' THEN
                        RETURN OLD;
                    ELSE
                        RETURN NEW;
                    END IF;
                END IF;

                RAISE EXCEPTION 'alert_history table is append-only';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS trg_protect_alert_history_update ON alert_history;
            DROP TRIGGER IF EXISTS trg_protect_alert_history_delete ON alert_history;

            CREATE TRIGGER trg_protect_alert_history_update
            BEFORE UPDATE ON alert_history
            FOR EACH ROW EXECUTE FUNCTION protect_alert_history_immutability();

            CREATE TRIGGER trg_protect_alert_history_delete
            BEFORE DELETE ON alert_history
            FOR EACH ROW EXECUTE FUNCTION protect_alert_history_immutability();
        """)


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("""
            DROP TRIGGER IF EXISTS trg_protect_monitoring_events_update ON monitoring_events;
            DROP TRIGGER IF EXISTS trg_protect_monitoring_events_delete ON monitoring_events;
            DROP FUNCTION IF EXISTS protect_monitoring_events_immutability();

            DROP TRIGGER IF EXISTS trg_protect_alert_history_update ON alert_history;
            DROP TRIGGER IF EXISTS trg_protect_alert_history_delete ON alert_history;
            DROP FUNCTION IF EXISTS protect_alert_history_immutability();
        """)

    op.drop_table("fim_targets")
    op.drop_table("alert_history")
    op.drop_table("alerts")
    op.drop_table("alert_rules")
    op.drop_table("monitoring_events")
    op.drop_table("monitoring_sources")
