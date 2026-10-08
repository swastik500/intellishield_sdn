"""SQLite persistence for operator commands (Phase 11).

No PostgreSQL/SQLAlchemy in this repo — use stdlib sqlite3 with WAL +
BEGIN IMMEDIATE for multi-process durability and concurrency.

Scoped to operator command/safety infrastructure only.
Does not touch detection/mitigation/controller engines.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

SCHEMA_VERSION = 2

_SCHEMA_SQL = """
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
    version INTEGER NOT NULL DEFAULT 1,
    execution_json TEXT NOT NULL DEFAULT '{}',
    execution_id TEXT,
    executed_at TEXT
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

CREATE TABLE IF NOT EXISTS operator_executions (
    execution_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    event_id TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    success INTEGER NOT NULL DEFAULT 0,
    result_summary TEXT,
    failure_code TEXT,
    failure_reason TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (command_id) REFERENCES operator_commands(command_id)
);

CREATE INDEX IF NOT EXISTS idx_operator_executions_command
    ON operator_executions(command_id, created_at DESC);
"""

_V2_ALTERS = (
    "ALTER TABLE operator_commands ADD COLUMN execution_json TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE operator_commands ADD COLUMN execution_id TEXT",
    "ALTER TABLE operator_commands ADD COLUMN executed_at TEXT",
)


class PersistenceUnavailableError(RuntimeError):
    """Raised when the durable command store cannot be used — fail closed."""


def default_db_path() -> Path:
    raw = os.environ.get("INTELLISHIELD_COMMAND_DB_PATH", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    # Repo-root logs/operator (file-based project convention)
    root = Path(__file__).resolve().parents[3]
    return (root / "logs" / "operator" / "command_store.db").resolve()


_local = threading.local()
_init_lock = threading.Lock()
_initialized_paths: set[str] = set()


def get_db_path() -> Path:
    return default_db_path()


def _connect(path: Optional[Path] = None) -> sqlite3.Connection:
    p = path or get_db_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(p),
            timeout=30.0,
            isolation_level=None,  # manage transactions explicitly
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn
    except OSError as exc:
        raise PersistenceUnavailableError(f"Cannot open command DB: {exc}") from exc
    except sqlite3.Error as exc:
        raise PersistenceUnavailableError(f"SQLite error opening DB: {exc}") from exc


def ensure_schema(path: Optional[Path] = None) -> Path:
    """Apply schema migrations (idempotent)."""
    p = path or get_db_path()
    key = str(p)
    with _init_lock:
        if key in _initialized_paths and p.exists():
            return p
        conn = _connect(p)
        try:
            # executescript auto-commits; do not wrap it in BEGIN/COMMIT
            conn.executescript(_SCHEMA_SQL)
            row = conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
            ).fetchone()
            current = int(row["version"]) if row else 0
            if current < 2:
                # Additive alters for DBs created at schema v1
                for stmt in _V2_ALTERS:
                    try:
                        conn.execute(stmt)
                    except sqlite3.OperationalError as exc:
                        if "duplicate column" not in str(exc).lower():
                            raise
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS operator_executions (
                        execution_id TEXT PRIMARY KEY,
                        command_id TEXT NOT NULL,
                        principal_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target_type TEXT,
                        target_id TEXT,
                        event_id TEXT,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        success INTEGER NOT NULL DEFAULT 0,
                        result_summary TEXT,
                        failure_code TEXT,
                        failure_reason TEXT,
                        payload_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (command_id) REFERENCES operator_commands(command_id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_operator_executions_command
                        ON operator_executions(command_id, created_at DESC);
                    """
                )
            if current < SCHEMA_VERSION:
                from dashboard.commands.models import iso_utc

                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, iso_utc()),
                )
                conn.execute("COMMIT")
            _initialized_paths.add(key)
        except Exception as exc:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            conn.close()
            raise PersistenceUnavailableError(f"schema migration failed: {exc}") from exc
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return p


def reset_initialized_cache() -> None:
    """Test helper — clear process init cache."""
    with _init_lock:
        _initialized_paths.clear()


@contextmanager
def transaction(*, immediate: bool = True, path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    """
    Durable transaction. BEGIN IMMEDIATE acquires a reserved lock (writer),
    preventing concurrent writers from confirming the same row.
    """
    ensure_schema(path)
    conn = _connect(path)
    try:
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        yield conn
        conn.execute("COMMIT")
    except PersistenceUnavailableError:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    except sqlite3.Error as exc:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise PersistenceUnavailableError(f"transaction failed: {exc}") from exc
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


@contextmanager
def connection(path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    """Read-oriented connection (still ensures schema)."""
    ensure_schema(path)
    conn = _connect(path)
    try:
        yield conn
    finally:
        conn.close()
