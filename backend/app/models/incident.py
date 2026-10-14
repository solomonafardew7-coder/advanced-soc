"""Incident domain model and allowed lifecycle transitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


IncidentStatus = Literal["open", "investigating", "resolved", "closed"]
IncidentSeverity = Literal[
    "informational", "low", "medium", "high", "critical"
]

INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    "open": frozenset({"investigating"}),
    "investigating": frozenset({"open", "resolved"}),
    "resolved": frozenset({"investigating", "closed"}),
    "closed": frozenset(),
}


@dataclass(frozen=True)
class Incident:
    """Immutable incident snapshot returned by the storage layer."""

    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: str
    updated_at: str
    resolved_at: str | None
    closed_at: str | None
    alert_ids: tuple[str, ...]
    supporting_event_refs: tuple[str, ...]
