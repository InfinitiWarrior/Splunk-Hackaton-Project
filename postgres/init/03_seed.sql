-- ============================================================
-- SOC Triage Seed
-- Roles and grants — runs after 01_schema.sql and 02_audit.sql
-- ============================================================

-- ── DB roles ──────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auth_app') THEN
        CREATE ROLE auth_app LOGIN PASSWORD 'PLACEHOLDER_auth_app';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE soc_triage TO auth_app;
GRANT USAGE ON SCHEMA public TO auth_app;
-- Grant on all EXISTING tables (created by 01_schema.sql above)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_app;
-- Grant on future tables too
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO auth_app;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_writer') THEN
        CREATE ROLE audit_writer LOGIN PASSWORD 'PLACEHOLDER_audit_writer';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE soc_triage TO audit_writer;
GRANT USAGE ON SCHEMA audit TO audit_writer;
GRANT INSERT ON audit.log TO audit_writer;
GRANT USAGE, SELECT ON SEQUENCE audit.log_id_seq TO audit_writer;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_reader') THEN
        CREATE ROLE audit_reader LOGIN PASSWORD 'PLACEHOLDER_audit_reader';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE soc_triage TO audit_reader;
GRANT USAGE ON SCHEMA audit TO audit_reader;
GRANT SELECT ON audit.log TO audit_reader;
GRANT SELECT ON audit.log TO audit_writer;
