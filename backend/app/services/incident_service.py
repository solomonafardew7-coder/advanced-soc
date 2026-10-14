"""Incident validation and lifecycle rules, independent of SQLite details."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence, cast

from backend.app.database.repository import IncidentRepository
from backend.app.models.incident import (
    INCIDENT_TRANSITIONS,
    Incident,
    IncidentSeverity,
    IncidentStatus,
)


_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_STATUSES = {"open", "investigating", "resolved", "closed"}


class IncidentValidationError(ValueError):
    """An incident request contains invalid values."""


class IncidentNotFoundError(LookupError):
    """The requested incident does not exist."""


class IncidentTransitionError(ValueError):
    """A requested incident status transition is not allowed."""


class IncidentConflictError(RuntimeError):
    """Another update changed the incident while this request was in progress."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _text(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        qualifier = "text" if allow_empty else "non-empty text"
        raise IncidentValidationError(f"{field} must be {qualifier}.")
    return value.strip() if not allow_empty else value


def _identifiers(values: Sequence[str], field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise IncidentValidationError(f"{field} must be a sequence of identifiers.")
    try:
        result = tuple(_text(value, field) for value in values)
    except TypeError as exc:
        raise IncidentValidationError(
            f"{field} must be a sequence of identifiers."
        ) from exc
    if len(result) != len(set(result)):
        raise IncidentValidationError(f"{field} must not contain duplicates.")
    return result


class IncidentService:
    """Create, read, update, and transition incidents using a repository port."""

    def __init__(self, repository: IncidentRepository) -> None:
        self.repository = repository

    def create_incident(
        self,
        *,
        title: str,
        description: str = "",
        severity: str = "medium",
        alert_ids: Sequence[str] = (),
        supporting_event_refs: Sequence[str] = (),
        audit_context: Mapping[str, Any] | None = None,
    ) -> Incident:
        title = _text(title, "title")
        description = _text(description, "description", allow_empty=True)
        severity = _text(severity, "severity").lower()
        if severity not in _SEVERITIES:
            raise IncidentValidationError("severity must be a supported level.")
        alerts = _identifiers(alert_ids, "alert_ids")
        event_refs = _identifiers(supporting_event_refs, "supporting_event_refs")
        timestamp = _now()
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=cast(IncidentSeverity, severity),
            status="open",
            created_at=timestamp,
            updated_at=timestamp,
            resolved_at=None,
            closed_at=None,
            alert_ids=alerts,
            supporting_event_refs=event_refs,
        )
        if audit_context is None:
            self.repository.create_incident(incident)
        else:
            self.repository.create_incident(
                incident,
                audit_event={
                    **audit_context,
                    "action": "incident.create",
                    "resource_type": "incident",
                    "resource_id": incident.incident_id,
                    "changes": {"status": "open", "severity": incident.severity},
                },
            )
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        incident_id = _text(incident_id, "incident_id")
        return self.repository.get_incident(incident_id)

    def update_incident(
        self,
        incident_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        audit_context: Mapping[str, Any] | None = None,
    ) -> Incident:
        """Update editable metadata without allowing a status bypass."""
        if title is None and description is None and severity is None:
            raise IncidentValidationError("At least one incident field must be supplied.")
        current = self.get_incident(incident_id)
        if current is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_id}.")

        updates: dict[str, object] = {"updated_at": _now()}
        if title is not None:
            updates["title"] = _text(title, "title")
        if description is not None:
            updates["description"] = _text(
                description, "description", allow_empty=True
            )
        if severity is not None:
            normalized_severity = _text(severity, "severity").lower()
            if normalized_severity not in _SEVERITIES:
                raise IncidentValidationError("severity must be a supported level.")
            updates["severity"] = cast(IncidentSeverity, normalized_severity)

        updated = replace(current, **updates)
        if audit_context is None:
            updated_ok = self.repository.update_incident_fields(updated, current.updated_at)
        else:
            changes: dict[str, Any] = {
                "changed_fields": sorted(
                    field
                    for field, value in (
                        ("title", title),
                        ("description", description),
                        ("severity", severity),
                    )
                    if value is not None
                )
            }
            if severity is not None:
                changes["severity"] = {"from": current.severity, "to": updated.severity}
            updated_ok = self.repository.update_incident_fields(
                updated,
                current.updated_at,
                audit_event={
                    **audit_context,
                    "action": "incident.update",
                    "resource_type": "incident",
                    "resource_id": incident_id,
                    "changes": changes,
                },
            )
        if not updated_ok:
            raise self._conflict_or_not_found(incident_id)
        stored = self.get_incident(incident_id)
        if stored is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_id}.")
        return stored

    def transition_status(
        self,
        incident_id: str,
        new_status: str,
        *,
        audit_context: Mapping[str, Any] | None = None,
    ) -> Incident:
        """Apply a validated transition and maintain lifecycle timestamps."""
        incident_id = _text(incident_id, "incident_id")
        if not isinstance(new_status, str) or new_status not in _STATUSES:
            raise IncidentTransitionError("Status must be open, investigating, resolved, or closed.")
        current = self.repository.get_incident(incident_id)
        if current is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_id}.")
        target = cast(IncidentStatus, new_status)
        if target not in INCIDENT_TRANSITIONS[current.status]:
            raise IncidentTransitionError(
                f"Cannot transition incident from {current.status} to {target}."
            )

        now = _now()
        if target == "resolved":
            resolved_at, closed_at = now, None
        elif target == "closed":
            resolved_at, closed_at = current.resolved_at, now
        else:
            resolved_at, closed_at = None, None
        updated = replace(
            current,
            status=target,
            updated_at=now,
            resolved_at=resolved_at,
            closed_at=closed_at,
        )
        if audit_context is None:
            transitioned = self.repository.transition_incident(
                updated, current.status, current.updated_at
            )
        else:
            transitioned = self.repository.transition_incident(
                updated,
                current.status,
                current.updated_at,
                audit_event={
                    **audit_context,
                    "action": f"incident.transition.{target}",
                    "resource_type": "incident",
                    "resource_id": incident_id,
                    "changes": {"status": {"from": current.status, "to": target}},
                },
            )
        if not transitioned:
            raise self._conflict_or_not_found(incident_id)
        stored = self.repository.get_incident(incident_id)
        if stored is None:
            raise IncidentNotFoundError(f"Incident not found: {incident_id}.")
        return stored

    def _conflict_or_not_found(self, incident_id: str) -> Exception:
        if self.repository.get_incident(incident_id) is None:
            return IncidentNotFoundError(f"Incident not found: {incident_id}.")
        return IncidentConflictError(
            "Incident changed concurrently; reload it before retrying."
        )
