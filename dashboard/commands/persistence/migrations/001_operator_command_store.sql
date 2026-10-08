-- Phase 11 — Operator command / audit / idempotency store
-- Forward migration (applied by dashboard.commands.persistence.db.ensure_schema)
-- Reversible: DROP TABLE operator_audits; DROP TABLE operator_idempotency;
--             DROP TABLE operator_commands; (schema_migrations row optional)

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_commands (
    command_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    event_id TEXT,
    principal_id TEXT NOT NULL,
    principal_username TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    confirmation_required INTEGER NOT NULL DEFAULT 0,
    confirmation_token TEXT,
    confirmation_expires_at TEXT,
    confirmed_at TEXT,
    confirmed_by TEXT,
    confirmation_used INTEGER NOT NULL DEFAULT 0,
    idempotency_key TEXT,
    authorization_json TEXT NOT NULL DEFAULT '{}',
    validation_json TEXT NOT NULL DEFAULT '{}',
    safety_json TEXT NOT NULL DEFAULT '{}',
    freshness_json TEXT NOT NULL DEFAULT '{}',
    audit_id TEXT,
    failure_reason TEXT,
    execution_enabled INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_operator_commands_created
    ON operator_commands(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_commands_status
    ON operator_commands(status);
CREATE INDEX IF NOT EXISTS idx_operator_commands_principal
    ON operator_commands(principal_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_commands_expires
    ON operator_commands(expires_at);

CREATE TABLE IF NOT EXISTS operator_idempotency (
    principal_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    command_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, action, target_type, target_id, idempotency_key),
    FOREIGN KEY (command_id) REFERENCES operator_commands(command_id)
);

CREATE INDEX IF NOT EXISTS idx_operator_idempotency_command
    ON operator_idempotency(command_id);

CREATE TABLE IF NOT EXISTS operator_audits (
    audit_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT,
    event_id TEXT,
    previous_status TEXT,
    new_status TEXT,
    result TEXT,
    failure_reason TEXT,
    source TEXT,
    parent_audit_id TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operator_audits_created
    ON operator_audits(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_audits_command
    ON operator_audits(command_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_audits_principal
    ON operator_audits(principal_id, created_at DESC);
