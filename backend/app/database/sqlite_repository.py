"""SQLite persistence for normalized events, alerts, and incident records."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, cast

from backend.app.models.incident import (
    INCIDENT_TRANSITIONS,
    Incident,
    IncidentSeverity,
    IncidentStatus,
)
from ingestion.normalizer import (
    EventNormalizationError,
    NormalizedEvent,
    normalize_event,
)


_EVENT_SEVERITIES = {
    "unknown", "informational", "low", "medium", "high", "critical"
}
_ALERT_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_INCIDENT_STATUSES = {"open", "investigating", "resolved", "closed"}
_TOKEN_HASH = re.compile(r"^[0-9a-f]{64}$")
_USER_ID = re.compile(r"^[0-9a-f]{32}$")
_USERNAME = re.compile(r"^[a-z0-9._-]{3,64}$")
_AUDIT_ACTION = re.compile(r"^[a-z][a-z0-9_.-]{0,99}$")
_RESOURCE_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,49}$")
_USER_ROLES = {"reader", "analyst", "admin"}
_AUDIT_ACTOR_TYPES = {"user", "configured_token", "delegated_token"}


class StorageError(RuntimeError):
    """A database operation could not be completed."""


class StorageValidationError(ValueError):
    """A supplied record is invalid or refers to a missing stored record."""


class StorageConflictError(StorageError):
    """A stable identifier was reused for different record contents."""


def _canonical_json(value: Any, field_name: str) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise StorageValidationError(
            f"Field '{field_name}' must contain JSON-serializable values."
        ) from exc


def _canonical_event(raw_event: Mapping[str, Any]) -> tuple[NormalizedEvent, str]:
    try:
        event = normalize_event(raw_event)
    except EventNormalizationError as exc:
        raise StorageValidationError(str(exc)) from exc
    return event, _canonical_json(event, "event")


def event_reference(raw_event: Mapping[str, Any]) -> str:
    """Return the same stable SHA-256 reference used by the detection engine."""
    _, encoded = _canonical_event(raw_event)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return f"event:{digest}"


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StorageValidationError(
            f"Field '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _validate_pagination(limit: int, offset: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise StorageValidationError("limit must be an integer from 1 through 100.")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise StorageValidationError("offset must be a non-negative integer.")


def _timestamp(value: Any, field_name: str) -> str:
    try:
        return normalize_event(
            {"timestamp": value, "event_type": f"storage_{field_name}"}
        )["timestamp"]
    except EventNormalizationError as exc:
        raise StorageValidationError(f"Invalid {field_name}: {exc}") from exc


def _validate_alert(raw_alert: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    if not isinstance(raw_alert, Mapping):
        raise StorageValidationError("Alert must be an object.")
    if any(not isinstance(key, str) for key in raw_alert):
        raise StorageValidationError("Alert field names must be strings.")

    required = {
        "alert_id",
        "rule_id",
        "rule_name",
        "severity",
        "description",
        "event_timestamp",
        "source_ip",
        "sources",
        "supporting_event_refs",
        "evidence",
    }
    missing = required - set(raw_alert)
    if missing:
        raise StorageValidationError(
            f"Alert is missing required field(s): {', '.join(sorted(missing))}."
        )

    alert = dict(raw_alert)
    for field in ("alert_id", "rule_id", "rule_name", "description"):
        alert[field] = _required_text(alert[field], field)

    source_ip = alert["source_ip"]
    validation_event: dict[str, Any] = {
        "timestamp": alert["event_timestamp"],
        "event_type": "stored_alert",
        "severity": alert["severity"],
    }
    if source_ip is not None:
        validation_event["source_ip"] = source_ip
    try:
        normalized = normalize_event(validation_event)
    except EventNormalizationError as exc:
        raise StorageValidationError(f"Invalid alert: {exc}") from exc
    if normalized["severity"] not in _ALERT_SEVERITIES:
        raise StorageValidationError("Alert severity must be a supported alert level.")
    alert["severity"] = normalized["severity"]
    alert["event_timestamp"] = normalized["timestamp"]
    alert["source_ip"] = normalized["source_ip"]

    sources = alert["sources"]
    if not isinstance(sources, list) or any(
        not isinstance(source, str) or not source.strip() for source in sources
    ):
        raise StorageValidationError("Alert sources must be a list of non-empty strings.")
    alert["sources"] = [source.strip() for source in sources]

    references = alert["supporting_event_refs"]
    if (
        not isinstance(references, list)
        or not references
        or any(not isinstance(ref, str) or not ref.strip() for ref in references)
    ):
        raise StorageValidationError(
            "Alert supporting_event_refs must be a non-empty list of identifiers."
        )
    normalized_references = [_required_text(ref, "supporting_event_refs") for ref in references]
    if len(normalized_references) != len(set(normalized_references)):
        raise StorageValidationError("Alert event references must be unique.")
    alert["supporting_event_refs"] = normalized_references

    if not isinstance(alert["evidence"], dict):
        raise StorageValidationError("Alert evidence must be an object.")
    encoded = _canonical_json(alert, "alert")
    return alert, encoded


def _normalize_incident(incident: Incident) -> Incident:
    if not isinstance(incident, Incident):
        raise StorageValidationError("Incident record has an unsupported type.")
    incident_id = _required_text(incident.incident_id, "incident_id")
    title = _required_text(incident.title, "title")
    if not isinstance(incident.description, str):
        raise StorageValidationError("Field 'description' must be text.")
    if not isinstance(incident.severity, str) or incident.severity not in _ALERT_SEVERITIES:
        raise StorageValidationError("Incident severity must be a supported level.")
    if not isinstance(incident.status, str) or incident.status not in _INCIDENT_STATUSES:
        raise StorageValidationError("Incident status is not supported.")

    if not isinstance(incident.alert_ids, tuple):
        raise StorageValidationError("Incident alert_ids must be identifiers.")
    alert_ids = tuple(_required_text(item, "alert_ids") for item in incident.alert_ids)
    if len(alert_ids) != len(set(alert_ids)):
        raise StorageValidationError("Incident alert_ids must be unique.")
    if not isinstance(incident.supporting_event_refs, tuple):
        raise StorageValidationError(
            "Incident supporting_event_refs must be identifiers."
        )
    event_refs = tuple(
        _required_text(item, "supporting_event_refs")
        for item in incident.supporting_event_refs
    )
    if len(event_refs) != len(set(event_refs)):
        raise StorageValidationError(
            "Incident supporting_event_refs must be unique."
        )

    created_at = _timestamp(incident.created_at, "created_at")
    updated_at = _timestamp(incident.updated_at, "updated_at")
    resolved_at = (
        None
        if incident.resolved_at is None
        else _timestamp(incident.resolved_at, "resolved_at")
    )
    closed_at = (
        None if incident.closed_at is None else _timestamp(incident.closed_at, "closed_at")
    )
    if incident.status == "open" or incident.status == "investigating":
        if resolved_at is not None or closed_at is not None:
            raise StorageValidationError(
                "Unresolved incidents cannot have resolved_at or closed_at timestamps."
            )
    elif incident.status == "resolved" and (resolved_at is None or closed_at is not None):
        raise StorageValidationError(
            "Resolved incidents require resolved_at and cannot have closed_at."
        )
    elif incident.status == "closed" and (resolved_at is None or closed_at is None):
        raise StorageValidationError(
            "Closed incidents require both resolved_at and closed_at."
        )

    return replace(
        incident,
        incident_id=incident_id,
        title=title,
        alert_ids=alert_ids,
        supporting_event_refs=event_refs,
        created_at=created_at,
        updated_at=updated_at,
        resolved_at=resolved_at,
        closed_at=closed_at,
        severity=cast(IncidentSeverity, incident.severity),
        status=cast(IncidentStatus, incident.status),
    )


class SQLiteRepository:
    """Parameterized SQLite storage behind a small replaceable repository API."""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 5.0):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")
        self.database_path = Path(database_path)
        self.timeout_seconds = timeout_seconds

    @contextmanager
    def _session(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise StorageError("Could not open the SQLite database.") from exc

        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise StorageError("SQLite operation failed; the transaction was rolled back.") from exc
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create the local schema and indexes if they do not already exist."""
        statements = (
            """CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT,
                source_ip TEXT,
                severity TEXT NOT NULL CHECK (
                    severity IN ('unknown', 'informational', 'low', 'medium', 'high', 'critical')
                ),
                details_json TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('informational', 'low', 'medium', 'high', 'critical')
                ),
                alert_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS alert_event_refs (
                alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
                event_id TEXT NOT NULL REFERENCES security_events(event_id) ON DELETE RESTRICT,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                PRIMARY KEY (alert_id, event_id),
                UNIQUE (alert_id, ordinal)
            )""",
            """CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL CHECK (length(trim(title)) > 0),
                description TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('informational', 'low', 'medium', 'high', 'critical')
                ),
                status TEXT NOT NULL CHECK (
                    status IN ('open', 'investigating', 'resolved', 'closed')
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                closed_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE RESTRICT,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                PRIMARY KEY (incident_id, alert_id),
                UNIQUE (incident_id, ordinal)
            )""",
            """CREATE TABLE IF NOT EXISTS incident_event_refs (
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                event_id TEXT NOT NULL REFERENCES security_events(event_id) ON DELETE RESTRICT,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                PRIMARY KEY (incident_id, event_id),
                UNIQUE (incident_id, ordinal)
            )""",
            """CREATE TABLE IF NOT EXISTS revoked_api_tokens (
                token_hash TEXT PRIMARY KEY CHECK (
                    length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'
                ),
                revoked_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS api_users (
                user_id TEXT PRIMARY KEY CHECK (
                    length(user_id) = 32 AND user_id NOT GLOB '*[^0-9a-f]*'
                ),
                username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (
                    length(username) BETWEEN 3 AND 64
                ),
                password_hash TEXT NOT NULL CHECK (
                    length(password_hash) BETWEEN 20 AND 1024
                    AND password_hash LIKE '$argon2id$%'
                ),
                role TEXT NOT NULL CHECK (role IN ('reader', 'analyst', 'admin')),
                is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS audit_events (
                audit_event_id TEXT PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (
                    actor_type IN ('user', 'configured_token', 'delegated_token')
                ),
                actor_user_id TEXT REFERENCES api_users(user_id) ON DELETE SET NULL,
                actor_username TEXT CHECK (
                    actor_username IS NULL OR length(actor_username) BETWEEN 3 AND 64
                ),
                actor_role TEXT NOT NULL CHECK (actor_role IN ('reader', 'analyst', 'admin')),
                action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
                resource_type TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 50),
                resource_id TEXT CHECK (resource_id IS NULL OR length(resource_id) <= 200),
                changes_json TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS incident_notes (
                note_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
                created_at TEXT NOT NULL,
                author_type TEXT NOT NULL CHECK (
                    author_type IN ('user', 'configured_token', 'delegated_token')
                ),
                author_user_id TEXT REFERENCES api_users(user_id) ON DELETE SET NULL,
                author_username TEXT CHECK (
                    author_username IS NULL OR length(author_username) BETWEEN 3 AND 64
                ),
                author_role TEXT NOT NULL CHECK (author_role IN ('reader', 'analyst', 'admin')),
                note_text TEXT NOT NULL CHECK (length(trim(note_text)) BETWEEN 1 AND 5000)
            )""",
            """CREATE TABLE IF NOT EXISTS api_tokens (
                token_hash TEXT PRIMARY KEY CHECK (
                    length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'
                ),
                role TEXT NOT NULL CHECK (role IN ('reader', 'analyst', 'admin')),
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                user_id TEXT REFERENCES api_users(user_id),
                issued_by_user_id TEXT REFERENCES api_users(user_id),
                CHECK (expires_at > issued_at)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(event_timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at, audit_event_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(resource_type, resource_id)",
            "CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id, created_at, note_id)",
            """CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS incident_notes_no_update
                BEFORE UPDATE ON incident_notes
                BEGIN SELECT RAISE(ABORT, 'incident notes are append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS incident_notes_no_delete
                BEFORE DELETE ON incident_notes
                BEGIN SELECT RAISE(ABORT, 'incident notes are append-only'); END""",
        )
        with self._session(write=True) as connection:
            for statement in statements:
                connection.execute(statement)
            token_columns = {
                column["name"]
                for column in connection.execute("PRAGMA table_info(api_tokens)").fetchall()
            }
            if "revoked_at" not in token_columns:
                connection.execute("ALTER TABLE api_tokens ADD COLUMN revoked_at TEXT")
            if "user_id" not in token_columns:
                connection.execute(
                    "ALTER TABLE api_tokens ADD COLUMN user_id TEXT REFERENCES api_users(user_id)"
                )
            if "issued_by_user_id" not in token_columns:
                connection.execute(
                    "ALTER TABLE api_tokens ADD COLUMN issued_by_user_id TEXT REFERENCES api_users(user_id)"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_tokens_issuer ON api_tokens(issued_by_user_id)"
            )

    @staticmethod
    def _validate_actor(record: Mapping[str, Any], prefix: str) -> tuple[str, str | None, str | None, str]:
        actor_type = record.get(f"{prefix}_type")
        actor_user_id = record.get(f"{prefix}_user_id")
        actor_username = record.get(f"{prefix}_username")
        actor_role = record.get(f"{prefix}_role")
        if actor_type not in _AUDIT_ACTOR_TYPES:
            raise StorageValidationError("Actor type is not supported.")
        if actor_user_id is not None and (
            not isinstance(actor_user_id, str) or not _USER_ID.fullmatch(actor_user_id)
        ):
            raise StorageValidationError("Actor account identifier is invalid.")
        if actor_username is not None:
            actor_username = _required_text(actor_username, f"{prefix}_username")
            if len(actor_username) > 64:
                raise StorageValidationError("Actor username is too long.")
        if (actor_type == "user") != (actor_user_id is not None):
            raise StorageValidationError("User actors must include an account identifier.")
        if not isinstance(actor_role, str) or actor_role not in _USER_ROLES:
            raise StorageValidationError("Actor role is not supported.")
        return actor_type, actor_user_id, actor_username, actor_role

    @staticmethod
    def _audit_changes(value: Any) -> str:
        if not isinstance(value, Mapping):
            raise StorageValidationError("Audit changes must be an object.")
        encoded = _canonical_json(dict(value), "audit changes")
        if len(encoded.encode("utf-8")) > 4096:
            raise StorageValidationError("Audit changes exceed the size limit.")
        return encoded

    def _prepare_audit_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            raise StorageValidationError("Audit event must be an object.")
        actor_type, actor_id, actor_username, actor_role = self._validate_actor(
            event, "actor"
        )
        action = event.get("action")
        resource_type = event.get("resource_type")
        resource_id = event.get("resource_id")
        if not isinstance(action, str) or not _AUDIT_ACTION.fullmatch(action):
            raise StorageValidationError("Audit action is invalid.")
        if not isinstance(resource_type, str) or not _RESOURCE_TYPE.fullmatch(resource_type):
            raise StorageValidationError("Audit resource type is invalid.")
        if resource_id is not None:
            resource_id = _required_text(resource_id, "resource_id")
            if len(resource_id) > 200:
                raise StorageValidationError("Audit resource identifier is too long.")
        changes_json = self._audit_changes(event.get("changes", {}))
        audit_event_id = event.get("audit_event_id") or uuid.uuid4().hex
        if not isinstance(audit_event_id, str) or not re.fullmatch(r"[0-9a-f]{32}", audit_event_id):
            raise StorageValidationError("Audit event identifier is invalid.")
        occurred_at = _timestamp(
            event.get("occurred_at")
            or datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "occurred_at",
        )
        return {
            "audit_event_id": audit_event_id,
            "occurred_at": occurred_at,
            "actor_type": actor_type,
            "actor_user_id": actor_id,
            "actor_username": actor_username,
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "changes": json.loads(changes_json),
            "changes_json": changes_json,
        }

    @staticmethod
    def _insert_audit_event(
        connection: sqlite3.Connection, event: Mapping[str, Any]
    ) -> None:
        connection.execute(
            """INSERT INTO audit_events (
                audit_event_id, occurred_at, actor_type, actor_user_id,
                actor_username, actor_role, action, resource_type,
                resource_id, changes_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["audit_event_id"],
                event["occurred_at"],
                event["actor_type"],
                event["actor_user_id"],
                event["actor_username"],
                event["actor_role"],
                event["action"],
                event["resource_type"],
                event["resource_id"],
                event["changes_json"],
            ),
        )

    def append_audit_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Append one validated audit record; no update/delete API is exposed."""
        prepared = self._prepare_audit_event(event)
        with self._session(write=True) as connection:
            self._insert_audit_event(connection, prepared)
        return {key: value for key, value in prepared.items() if key != "changes_json"}

    def list_audit_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return a bounded, filtered page of persistent audit records."""
        _validate_pagination(limit, offset)
        if action is not None and (not isinstance(action, str) or not _AUDIT_ACTION.fullmatch(action)):
            raise StorageValidationError("Audit action is invalid.")
        if resource_type is not None and (
            not isinstance(resource_type, str) or not _RESOURCE_TYPE.fullmatch(resource_type)
        ):
            raise StorageValidationError("Audit resource type is invalid.")
        if resource_id is not None:
            resource_id = _required_text(resource_id, "resource_id")
        filters = (action, action, resource_type, resource_type, resource_id, resource_id)
        with self._session() as connection:
            total = connection.execute(
                """SELECT COUNT(*) FROM audit_events WHERE
                (? IS NULL OR action = ?) AND (? IS NULL OR resource_type = ?)
                AND (? IS NULL OR resource_id = ?)""",
                filters,
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT * FROM audit_events WHERE
                (? IS NULL OR action = ?) AND (? IS NULL OR resource_type = ?)
                AND (? IS NULL OR resource_id = ?)
                ORDER BY occurred_at DESC, audit_event_id DESC LIMIT ? OFFSET ?""",
                (*filters, limit, offset),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                changes = json.loads(row["changes_json"])
            except json.JSONDecodeError as exc:
                raise StorageError("Stored audit JSON is invalid.") from exc
            result.append({
                "audit_event_id": row["audit_event_id"],
                "occurred_at": row["occurred_at"],
                "actor_type": row["actor_type"],
                "actor_user_id": row["actor_user_id"],
                "actor_username": row["actor_username"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "changes": changes,
            })
        return result, total

    def create_incident_note(
        self,
        note: Mapping[str, Any],
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an incident note with its author snapshot and timestamp."""
        if not isinstance(note, Mapping):
            raise StorageValidationError("Incident note must be an object.")
        incident_id = _required_text(note.get("incident_id"), "incident_id")
        note_text = note.get("note_text")
        if not isinstance(note_text, str) or not note_text.strip() or len(note_text.strip()) > 5000:
            raise StorageValidationError("Incident note must contain 1 through 5000 characters.")
        note_text = note_text.strip()
        author_type, author_id, author_username, author_role = self._validate_actor(
            note, "author"
        )
        note_id = note.get("note_id") or uuid.uuid4().hex
        if not isinstance(note_id, str) or not re.fullmatch(r"[0-9a-f]{32}", note_id):
            raise StorageValidationError("Incident note identifier is invalid.")
        created_at = _timestamp(
            note.get("created_at")
            or datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "created_at",
        )
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        with self._session(write=True) as connection:
            connection.execute(
                """INSERT INTO incident_notes (
                    note_id, incident_id, created_at, author_type, author_user_id,
                    author_username, author_role, note_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    note_id,
                    incident_id,
                    created_at,
                    author_type,
                    author_id,
                    author_username,
                    author_role,
                    note_text,
                ),
            )
            if prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)
        return {
            "note_id": note_id,
            "incident_id": incident_id,
            "created_at": created_at,
            "author_type": author_type,
            "author_user_id": author_id,
            "author_username": author_username,
            "author_role": author_role,
            "note_text": note_text,
        }

    def list_incident_notes(
        self, incident_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        incident_id = _required_text(incident_id, "incident_id")
        _validate_pagination(limit, offset)
        with self._session() as connection:
            total = connection.execute(
                "SELECT COUNT(*) FROM incident_notes WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT * FROM incident_notes WHERE incident_id = ?
                ORDER BY created_at ASC, note_id ASC LIMIT ? OFFSET ?""",
                (incident_id, limit, offset),
            ).fetchall()
        return [
            {
                "note_id": row["note_id"],
                "incident_id": row["incident_id"],
                "created_at": row["created_at"],
                "author_type": row["author_type"],
                "author_user_id": row["author_user_id"],
                "author_username": row["author_username"],
                "author_role": row["author_role"],
                "note_text": row["note_text"],
            }
            for row in rows
        ], total

    def revoke_api_token(
        self,
        token_hash: str,
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> bool:
        """Persist a token digest revocation; repeated requests are idempotent."""
        if not isinstance(token_hash, str) or not _TOKEN_HASH.fullmatch(token_hash):
            raise StorageValidationError("Token hash must be a lowercase SHA-256 digest.")
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        revoked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self._session(write=True) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO revoked_api_tokens(token_hash, revoked_at) VALUES (?, ?)",
                (token_hash, revoked_at),
            )
            connection.execute(
                "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?",
                (revoked_at, token_hash),
            )
            if prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)
        return cursor.rowcount == 1

    def create_api_token(
        self,
        token_hash: str,
        role: str,
        issued_at: str,
        expires_at: str,
        user_id: str | None = None,
        issued_by_user_id: str | None = None,
        audit_event: Mapping[str, Any] | None = None,
    ) -> None:
        """Persist token metadata only; the bearer secret is never stored."""
        if not isinstance(token_hash, str) or not _TOKEN_HASH.fullmatch(token_hash):
            raise StorageValidationError("Token hash must be a lowercase SHA-256 digest.")
        if not isinstance(role, str) or role not in {"reader", "analyst", "admin"}:
            raise StorageValidationError("Token role is not supported.")
        if user_id is not None and (
            not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id)
        ):
            raise StorageValidationError("User identifier is invalid.")
        if issued_by_user_id is not None and (
            not isinstance(issued_by_user_id, str)
            or not _USER_ID.fullmatch(issued_by_user_id)
        ):
            raise StorageValidationError("Issuer identifier is invalid.")
        issued = self._token_timestamp(issued_at, "issued_at")
        expires = self._token_timestamp(expires_at, "expires_at")
        lifetime = (expires - issued).total_seconds()
        if not 0 < lifetime <= 90 * 24 * 60 * 60:
            raise StorageValidationError("Token expiration must be within 90 days of issue time.")
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        with self._session(write=True) as connection:
            if user_id is not None:
                user = connection.execute(
                    "SELECT role, is_active FROM api_users WHERE user_id = ?",
                    (user_id,),
                ).fetchone()
                if user is None or not user["is_active"]:
                    raise StorageValidationError("User account is unavailable.")
                if user["role"] != role:
                    raise StorageValidationError("Token role must match the account role.")
            if issued_by_user_id is not None:
                issuer = connection.execute(
                    "SELECT role, is_active FROM api_users WHERE user_id = ?",
                    (issued_by_user_id,),
                ).fetchone()
                if issuer is None or not issuer["is_active"] or issuer["role"] != "admin":
                    raise StorageValidationError("Administrator issuer is unavailable.")
            connection.execute(
                """INSERT INTO api_tokens (
                    token_hash, role, issued_at, expires_at, user_id, issued_by_user_id
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    token_hash,
                    role,
                    issued.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    expires.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    user_id,
                    issued_by_user_id,
                ),
            )
            if prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)

    def create_api_user(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        role: str,
        created_at: str,
        audit_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist one account and return its public fields, never its hash."""
        if not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id):
            raise StorageValidationError("User identifier is invalid.")
        if not isinstance(username, str) or not _USERNAME.fullmatch(username):
            raise StorageValidationError("Username is invalid.")
        if (
            not isinstance(password_hash, str)
            or not 20 <= len(password_hash) <= 1024
            or not password_hash.startswith("$argon2id$")
        ):
            raise StorageValidationError("Password hash is invalid.")
        if not isinstance(role, str) or role not in {"reader", "analyst", "admin"}:
            raise StorageValidationError("Account role is not supported.")
        created = self._token_timestamp(created_at, "created_at")
        normalized_username = username.lower()
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        with self._session(write=True) as connection:
            cursor = connection.execute(
                """INSERT INTO api_users (user_id, username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?) ON CONFLICT(username) DO NOTHING""",
                (
                    user_id,
                    normalized_username,
                    password_hash,
                    role,
                    created.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                ),
            )
            if cursor.rowcount == 0:
                raise StorageConflictError("Username is already in use.")
            if prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)
        return {
            "user_id": user_id,
            "username": normalized_username,
            "role": role,
            "is_active": True,
            "created_at": created.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def get_api_user_by_username(self, username: str) -> dict[str, Any] | None:
        if not isinstance(username, str) or not _USERNAME.fullmatch(username.lower()):
            return None
        with self._session() as connection:
            row = connection.execute(
                """SELECT user_id, username, password_hash, role, is_active, created_at
                FROM api_users WHERE username = ? COLLATE NOCASE""",
                (username.lower(),),
            ).fetchone()
        return self._api_user_dict(row, include_password_hash=True)

    def get_api_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        if not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id):
            return None
        with self._session() as connection:
            row = connection.execute(
                """SELECT user_id, username, password_hash, role, is_active, created_at
                FROM api_users WHERE user_id = ?""",
                (user_id,),
            ).fetchone()
        return self._api_user_dict(row, include_password_hash=False)

    @staticmethod
    def _api_user_dict(row: sqlite3.Row | None, *, include_password_hash: bool) -> dict[str, Any] | None:
        if row is None:
            return None
        user = {
            "user_id": row["user_id"],
            "username": row["username"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
        }
        if include_password_hash:
            user["password_hash"] = row["password_hash"]
        return user

    def disable_api_user(
        self,
        user_id: str,
        *,
        account_marker_hash: str,
        revoke_token: Callable[[str], bool],
        audit_event: Mapping[str, Any] | None = None,
    ) -> list[str] | None:
        """Disable a user and revoke its tokens while login writes are serialized.

        The callback writes durable revocations before the account transaction
        commits. SQLite's immediate write lock prevents a concurrent login from
        inserting a token between enumeration and disablement.
        """
        if not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id):
            raise StorageValidationError("User identifier is invalid.")
        if not isinstance(account_marker_hash, str) or not _TOKEN_HASH.fullmatch(account_marker_hash):
            raise StorageValidationError("Account revocation marker is invalid.")
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        with self._session(write=True) as connection:
            user = connection.execute(
                "SELECT role, is_active FROM api_users WHERE user_id = ?", (user_id,)
            ).fetchone()
            if user is None:
                return None
            if not user["is_active"]:
                return []
            if user["role"] == "admin":
                admin_count = connection.execute(
                    "SELECT COUNT(*) FROM api_users WHERE role = 'admin' AND is_active = 1"
                ).fetchone()[0]
                if admin_count <= 1:
                    raise StorageConflictError(
                        "The last active account administrator cannot be disabled."
                    )
            tokens = connection.execute(
                """SELECT token_hash FROM api_tokens
                WHERE user_id = ? OR issued_by_user_id = ? ORDER BY token_hash""",
                (user_id, user_id),
            ).fetchall()
            token_hashes = [row["token_hash"] for row in tokens]
            revoke_token(account_marker_hash)
            for token_hash in token_hashes:
                revoke_token(token_hash)
            disabled_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            connection.execute(
                "UPDATE api_users SET is_active = 0 WHERE user_id = ?", (user_id,)
            )
            for token_hash in token_hashes:
                connection.execute(
                    "INSERT OR IGNORE INTO revoked_api_tokens(token_hash, revoked_at) VALUES (?, ?)",
                    (token_hash, disabled_at),
                )
                connection.execute(
                    "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?",
                    (disabled_at, token_hash),
                )
            if prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)
        return token_hashes

    def list_disabled_api_users(self) -> list[str]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT user_id FROM api_users WHERE is_active = 0 ORDER BY user_id"
            ).fetchall()
        return [row["user_id"] for row in rows]

    def list_api_tokens_for_user(self, user_id: str) -> list[str]:
        if not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id):
            raise StorageValidationError("User identifier is invalid.")
        with self._session() as connection:
            rows = connection.execute(
                """SELECT token_hash FROM api_tokens
                WHERE user_id = ? OR issued_by_user_id = ? ORDER BY token_hash""",
                (user_id, user_id),
            ).fetchall()
        return [row["token_hash"] for row in rows]

    @staticmethod
    def _token_timestamp(value: Any, field_name: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise StorageValidationError(f"{field_name} must be an ISO-8601 timestamp.")
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise StorageValidationError(
                f"{field_name} must be an ISO-8601 timestamp."
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise StorageValidationError(f"{field_name} must include a timezone.")
        parsed = parsed.astimezone(timezone.utc)
        if field_name == "issued_at" and parsed > datetime.now(timezone.utc):
            raise StorageValidationError("issued_at cannot be in the future.")
        return parsed

    def get_api_token(self, token_hash: str) -> dict[str, Any] | None:
        """Look up one issued grant by digest without returning secret material."""
        if not isinstance(token_hash, str) or not _TOKEN_HASH.fullmatch(token_hash):
            raise StorageValidationError("Token hash must be a lowercase SHA-256 digest.")
        with self._session() as connection:
            row = connection.execute(
                """SELECT role, issued_at, expires_at, user_id, issued_by_user_id
                FROM api_tokens WHERE token_hash = ?""",
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        result = {
            "role": row["role"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
        }
        if row["user_id"] is not None:
            result["user_id"] = row["user_id"]
        if row["issued_by_user_id"] is not None:
            result["issued_by_user_id"] = row["issued_by_user_id"]
        return result

    def has_api_tokens(self) -> bool:
        """Return whether database-backed bearer grants have been issued."""
        with self._session() as connection:
            row = connection.execute("SELECT 1 FROM api_tokens LIMIT 1").fetchone()
        return row is not None

    def is_api_token_revoked(self, token_hash: str) -> bool:
        """Check a configured token digest against the persistent revocation list."""
        if not isinstance(token_hash, str) or not _TOKEN_HASH.fullmatch(token_hash):
            raise StorageValidationError("Token hash must be a lowercase SHA-256 digest.")
        with self._session() as connection:
            row = connection.execute(
                "SELECT 1 FROM revoked_api_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        return row is not None

    def list_api_token_revocations(self) -> list[str]:
        """Return all SQLite revocations for migration into trusted state."""
        with self._session() as connection:
            rows = connection.execute(
                "SELECT token_hash FROM revoked_api_tokens ORDER BY token_hash"
            ).fetchall()
        return [row["token_hash"] for row in rows]

    def save_event(self, raw_event: Mapping[str, Any]) -> bool:
        """Insert a normalized event; return False for an exact duplicate."""
        event, event_json = _canonical_event(raw_event)
        event_id = f"event:{hashlib.sha256(event_json.encode('utf-8')).hexdigest()}"
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        details_json = _canonical_json(event["details"], "details")

        with self._session(write=True) as connection:
            row = connection.execute(
                "SELECT event_json FROM security_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if row is not None:
                if row["event_json"] != event_json:
                    raise StorageConflictError(
                        "Stable event identifier already has different contents."
                    )
                return False

            connection.execute(
                """INSERT INTO security_events (
                    event_id, timestamp, event_type, source, source_ip,
                    severity, details_json, event_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id,
                    event["timestamp"],
                    event["event_type"],
                    event["source"],
                    event["source_ip"],
                    event["severity"],
                    details_json,
                    event_json,
                    created_at,
                ),
            )
        return True

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        event_id = _required_text(event_id, "event_id")
        with self._session() as connection:
            row = connection.execute(
                "SELECT event_json FROM security_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            event = json.loads(row["event_json"])
        except json.JSONDecodeError as exc:
            raise StorageError("Stored event JSON is invalid.") from exc
        return {"event_id": event_id, **event}

    def list_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        event_type: str | None = None,
        source_ip: str | None = None,
        severity: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return a filtered event page and total filtered count."""
        _validate_pagination(limit, offset)
        if event_type is not None:
            event_type = _required_text(event_type, "event_type")
        if source_ip is not None:
            try:
                source_ip = str(ipaddress.ip_address(source_ip))
            except (ValueError, TypeError) as exc:
                raise StorageValidationError("source_ip must be a valid IP address.") from exc
        if severity is not None and (
            not isinstance(severity, str) or severity not in _EVENT_SEVERITIES
        ):
            raise StorageValidationError("severity is not supported.")

        filters = (event_type, event_type, source_ip, source_ip, severity, severity)
        with self._session() as connection:
            total = connection.execute(
                """SELECT COUNT(*) FROM security_events WHERE
                (? IS NULL OR event_type = ?)
                AND (? IS NULL OR source_ip = ?)
                AND (? IS NULL OR severity = ?)""",
                filters,
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT event_id, event_json FROM security_events
                WHERE (? IS NULL OR event_type = ?)
                AND (? IS NULL OR source_ip = ?)
                AND (? IS NULL OR severity = ?)
                ORDER BY timestamp DESC, event_id ASC LIMIT ? OFFSET ?""",
                (*filters, limit, offset),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            try:
                event = json.loads(row["event_json"])
            except json.JSONDecodeError as exc:
                raise StorageError("Stored event JSON is invalid.") from exc
            events.append({"event_id": row["event_id"], **event})
        return events, total

    def save_alert(self, raw_alert: Mapping[str, Any]) -> bool:
        """Persist a generated alert and its event links atomically.

        Returns False when an identical alert ID and payload are already stored.
        Every supporting reference must identify a previously stored event.
        """
        alert, alert_json = _validate_alert(raw_alert)
        alert_id = alert["alert_id"]
        references = alert["supporting_event_refs"]
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        with self._session(write=True) as connection:
            existing = connection.execute(
                "SELECT alert_json FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if existing is not None:
                if existing["alert_json"] != alert_json:
                    raise StorageConflictError(
                        "Alert identifier already has different contents."
                    )
                return False

            for event_id in references:
                event_row = connection.execute(
                    "SELECT 1 FROM security_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if event_row is None:
                    raise StorageValidationError(
                        f"Alert references an unknown event: {event_id}."
                    )

            connection.execute(
                """INSERT INTO alerts (
                    alert_id, rule_id, event_timestamp, severity, alert_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    alert_id,
                    alert["rule_id"],
                    alert["event_timestamp"],
                    alert["severity"],
                    alert_json,
                    created_at,
                ),
            )
            for ordinal, event_id in enumerate(references):
                connection.execute(
                    """INSERT INTO alert_event_refs (alert_id, event_id, ordinal)
                    VALUES (?, ?, ?)""",
                    (alert_id, event_id, ordinal),
                )
        return True

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        alert_id = _required_text(alert_id, "alert_id")
        with self._session() as connection:
            row = connection.execute(
                "SELECT alert_json FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                return None
            ref_rows = connection.execute(
                """SELECT event_id FROM alert_event_refs
                WHERE alert_id = ? ORDER BY ordinal""",
                (alert_id,),
            ).fetchall()
        try:
            alert = json.loads(row["alert_json"])
        except json.JSONDecodeError as exc:
            raise StorageError("Stored alert JSON is invalid.") from exc
        alert["supporting_event_refs"] = [ref["event_id"] for ref in ref_rows]
        return alert

    def list_alerts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return a filtered alert page and total filtered count."""
        _validate_pagination(limit, offset)
        if severity is not None and (
            not isinstance(severity, str) or severity not in _ALERT_SEVERITIES
        ):
            raise StorageValidationError("severity is not supported.")
        if rule_id is not None:
            rule_id = _required_text(rule_id, "rule_id")

        filters = (severity, severity, rule_id, rule_id)
        with self._session() as connection:
            total = connection.execute(
                """SELECT COUNT(*) FROM alerts WHERE
                (? IS NULL OR severity = ?) AND (? IS NULL OR rule_id = ?)""",
                filters,
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT alert_id, alert_json FROM alerts
                WHERE (? IS NULL OR severity = ?) AND (? IS NULL OR rule_id = ?)
                ORDER BY event_timestamp DESC, alert_id ASC LIMIT ? OFFSET ?""",
                (*filters, limit, offset),
            ).fetchall()
            alerts: list[dict[str, Any]] = []
            for row in rows:
                try:
                    alert = json.loads(row["alert_json"])
                except json.JSONDecodeError as exc:
                    raise StorageError("Stored alert JSON is invalid.") from exc
                refs = connection.execute(
                    """SELECT event_id FROM alert_event_refs
                    WHERE alert_id = ? ORDER BY ordinal""",
                    (row["alert_id"],),
                ).fetchall()
                alert["supporting_event_refs"] = [ref["event_id"] for ref in refs]
                alerts.append(alert)
        return alerts, total

    def create_incident(
        self,
        incident: Incident,
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> None:
        """Insert an incident and its links as one transaction."""
        incident = _normalize_incident(incident)
        if incident.status != "open":
            raise StorageValidationError("New incidents must start in the open status.")
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )

        with self._session(write=True) as connection:
            connection.execute(
                """INSERT INTO incidents (
                    incident_id, title, description, severity, status,
                    created_at, updated_at, resolved_at, closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident.incident_id,
                    incident.title,
                    incident.description,
                    incident.severity,
                    incident.status,
                    incident.created_at,
                    incident.updated_at,
                    incident.resolved_at,
                    incident.closed_at,
                ),
            )
            for ordinal, alert_id in enumerate(incident.alert_ids):
                if connection.execute(
                    "SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)
                ).fetchone() is None:
                    raise StorageValidationError(
                        f"Incident references an unknown alert: {alert_id}."
                    )
                connection.execute(
                    """INSERT INTO incident_alerts (incident_id, alert_id, ordinal)
                    VALUES (?, ?, ?)""",
                    (incident.incident_id, alert_id, ordinal),
                )
            for ordinal, event_id in enumerate(incident.supporting_event_refs):
                if connection.execute(
                    "SELECT 1 FROM security_events WHERE event_id = ?", (event_id,)
                ).fetchone() is None:
                    raise StorageValidationError(
                        f"Incident references an unknown event: {event_id}."
                    )
                connection.execute(
                    """INSERT INTO incident_event_refs (
                        incident_id, event_id, ordinal
                    ) VALUES (?, ?, ?)""",
                    (incident.incident_id, event_id, ordinal),
                )
            if prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)

    def get_incident(self, incident_id: str) -> Incident | None:
        incident_id = _required_text(incident_id, "incident_id")
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return None
            alert_rows = connection.execute(
                """SELECT alert_id FROM incident_alerts
                WHERE incident_id = ? ORDER BY ordinal""",
                (incident_id,),
            ).fetchall()
            event_rows = connection.execute(
                """SELECT event_id FROM incident_event_refs
                WHERE incident_id = ? ORDER BY ordinal""",
                (incident_id,),
            ).fetchall()
        return Incident(
            incident_id=row["incident_id"],
            title=row["title"],
            description=row["description"],
            severity=cast(IncidentSeverity, row["severity"]),
            status=cast(IncidentStatus, row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            resolved_at=row["resolved_at"],
            closed_at=row["closed_at"],
            alert_ids=tuple(item["alert_id"] for item in alert_rows),
            supporting_event_refs=tuple(item["event_id"] for item in event_rows),
        )

    def list_incidents(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: IncidentStatus | None = None,
        severity: str | None = None,
    ) -> tuple[list[Incident], int]:
        """Return a filtered incident page and total filtered count."""
        _validate_pagination(limit, offset)
        if status is not None and (
            not isinstance(status, str) or status not in _INCIDENT_STATUSES
        ):
            raise StorageValidationError("status is not supported.")
        if severity is not None and (
            not isinstance(severity, str) or severity not in _ALERT_SEVERITIES
        ):
            raise StorageValidationError("severity is not supported.")
        filters = (status, status, severity, severity)
        with self._session() as connection:
            total = connection.execute(
                """SELECT COUNT(*) FROM incidents WHERE
                (? IS NULL OR status = ?) AND (? IS NULL OR severity = ?)""",
                filters,
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT * FROM incidents
                WHERE (? IS NULL OR status = ?) AND (? IS NULL OR severity = ?)
                ORDER BY created_at DESC, incident_id ASC LIMIT ? OFFSET ?""",
                (*filters, limit, offset),
            ).fetchall()
            incidents: list[Incident] = []
            for row in rows:
                alert_rows = connection.execute(
                    """SELECT alert_id FROM incident_alerts
                    WHERE incident_id = ? ORDER BY ordinal""",
                    (row["incident_id"],),
                ).fetchall()
                event_rows = connection.execute(
                    """SELECT event_id FROM incident_event_refs
                    WHERE incident_id = ? ORDER BY ordinal""",
                    (row["incident_id"],),
                ).fetchall()
                incidents.append(
                    Incident(
                        incident_id=row["incident_id"],
                        title=row["title"],
                        description=row["description"],
                        severity=cast(IncidentSeverity, row["severity"]),
                        status=cast(IncidentStatus, row["status"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        resolved_at=row["resolved_at"],
                        closed_at=row["closed_at"],
                        alert_ids=tuple(item["alert_id"] for item in alert_rows),
                        supporting_event_refs=tuple(
                            item["event_id"] for item in event_rows
                        ),
                    )
                )
        return incidents, total

    def update_incident_fields(
        self,
        incident: Incident,
        expected_updated_at: str,
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> bool:
        """Update metadata only, using optimistic concurrency on updated_at."""
        incident = _normalize_incident(incident)
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        with self._session(write=True) as connection:
            cursor = connection.execute(
                """UPDATE incidents SET title = ?, description = ?, severity = ?,
                    updated_at = ?
                WHERE incident_id = ? AND updated_at = ?""",
                (
                    incident.title,
                    incident.description,
                    incident.severity,
                    incident.updated_at,
                    incident.incident_id,
                    expected_updated_at,
                ),
            )
            if cursor.rowcount == 1 and prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)
            return cursor.rowcount == 1

    def transition_incident(
        self,
        incident: Incident,
        expected_status: IncidentStatus,
        expected_updated_at: str,
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> bool:
        """Apply one allowed status transition with a compare-and-set update."""
        incident = _normalize_incident(incident)
        if incident.status not in INCIDENT_TRANSITIONS.get(expected_status, frozenset()):
            raise StorageValidationError(
                f"Invalid incident transition from {expected_status} to {incident.status}."
            )
        prepared_audit = (
            None if audit_event is None else self._prepare_audit_event(audit_event)
        )
        with self._session(write=True) as connection:
            cursor = connection.execute(
                """UPDATE incidents SET status = ?, updated_at = ?,
                    resolved_at = ?, closed_at = ?
                WHERE incident_id = ? AND status = ? AND updated_at = ?""",
                (
                    incident.status,
                    incident.updated_at,
                    incident.resolved_at,
                    incident.closed_at,
                    incident.incident_id,
                    expected_status,
                    expected_updated_at,
                ),
            )
            if cursor.rowcount == 1 and prepared_audit is not None:
                self._insert_audit_event(connection, prepared_audit)
            return cursor.rowcount == 1
