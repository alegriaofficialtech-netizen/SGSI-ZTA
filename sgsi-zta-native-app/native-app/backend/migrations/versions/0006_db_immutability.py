# ruff: noqa: E501
"""Database-level immutability triggers for policy_decisions and policy_versions."""

from alembic import op

revision = "0006_db_immutability"
down_revision = "0005_zero_trust"
branch_labels = None
depends_on = None


def upgrade():
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

            CREATE OR REPLACE FUNCTION protect_policy_decisions_immutability()
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

                RAISE EXCEPTION 'policy_decisions table is append-only';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS trg_protect_policy_decisions_update ON policy_decisions;
            DROP TRIGGER IF EXISTS trg_protect_policy_decisions_delete ON policy_decisions;

            CREATE TRIGGER trg_protect_policy_decisions_update
            BEFORE UPDATE ON policy_decisions
            FOR EACH ROW EXECUTE FUNCTION protect_policy_decisions_immutability();

            CREATE TRIGGER trg_protect_policy_decisions_delete
            BEFORE DELETE ON policy_decisions
            FOR EACH ROW EXECUTE FUNCTION protect_policy_decisions_immutability();

            CREATE OR REPLACE FUNCTION protect_policy_versions_immutability()
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

                RAISE EXCEPTION 'policy_versions table is append-only';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS trg_protect_policy_versions_update ON policy_versions;
            DROP TRIGGER IF EXISTS trg_protect_policy_versions_delete ON policy_versions;

            CREATE TRIGGER trg_protect_policy_versions_update
            BEFORE UPDATE ON policy_versions
            FOR EACH ROW EXECUTE FUNCTION protect_policy_versions_immutability();

            CREATE TRIGGER trg_protect_policy_versions_delete
            BEFORE DELETE ON policy_versions
            FOR EACH ROW EXECUTE FUNCTION protect_policy_versions_immutability();

            DO $owner$
            BEGIN
                BEGIN
                    ALTER TABLE policy_decisions OWNER TO sgsi_admin;
                EXCEPTION WHEN OTHERS THEN
                    NULL;
                END;
                BEGIN
                    ALTER TABLE policy_versions OWNER TO sgsi_admin;
                EXCEPTION WHEN OTHERS THEN
                    NULL;
                END;
                BEGIN
                    ALTER FUNCTION protect_policy_decisions_immutability() OWNER TO sgsi_admin;
                EXCEPTION WHEN OTHERS THEN
                    NULL;
                END;
                BEGIN
                    ALTER FUNCTION protect_policy_versions_immutability() OWNER TO sgsi_admin;
                EXCEPTION WHEN OTHERS THEN
                    NULL;
                END;
            END
            $owner$;

            GRANT SELECT, INSERT ON policy_decisions TO PUBLIC;
            GRANT SELECT, INSERT ON policy_versions TO PUBLIC;
        """)


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("""
            DROP TRIGGER IF EXISTS trg_protect_policy_decisions_update ON policy_decisions;
            DROP TRIGGER IF EXISTS trg_protect_policy_decisions_delete ON policy_decisions;
            DROP FUNCTION IF EXISTS protect_policy_decisions_immutability();

            DROP TRIGGER IF EXISTS trg_protect_policy_versions_update ON policy_versions;
            DROP TRIGGER IF EXISTS trg_protect_policy_versions_delete ON policy_versions;
            DROP FUNCTION IF EXISTS protect_policy_versions_immutability();
        """)
