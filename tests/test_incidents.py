"""Temporary-database tests for incident CRUD and status transitions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.app.database.sqlite_repository import (
    SQLiteRepository,
    StorageValidationError,
    event_reference,
)
from backend.app.models.incident import Incident
from backend.app.services.incident_service import (
    IncidentNotFoundError,
    IncidentService,
    IncidentTransitionError,
    IncidentValidationError,
)


@pytest.fixture
def store_and_service(tmp_path: Path) -> tuple[SQLiteRepository, IncidentService]:
    store = SQLiteRepository(tmp_path / "incidents-test.sqlite3")
    store.initialize()
    return store, IncidentService(store)


def _stored_alert(store: SQLiteRepository) -> tuple[str, str]:
    event = {
        "timestamp": "2026-10-14T13:00:00Z",
        "event_type": "authentication_failure",
        "source": "sshd",
        "source_ip": "198.51.100.10",
        "severity": "high",
        "details": {"username": "synthetic-user"},
    }
    event_ref = event_reference(event)
    store.save_event(event)
    alert = {
        "alert_id": "synthetic-alert-incident-test",
        "rule_id": "SYNTHETIC-TEST-001",
        "rule_name": "Synthetic alert",
        "severity": "high",
        "description": "Synthetic alert backing an incident test.",
        "event_timestamp": event["timestamp"],
        "source_ip": event["source_ip"],
        "sources": ["sshd"],
        "supporting_event_refs": [event_ref],
        "evidence": {"synthetic": True},
    }
    store.save_alert(alert)
    return alert["alert_id"], event_ref


def _assert_utc_timestamp(value: str | None) -> None:
    assert value is not None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def test_create_and_read_incident_with_references(
    store_and_service: tuple[SQLiteRepository, IncidentService],
) -> None:
    store, service = store_and_service
    alert_id, event_ref = _stored_alert(store)

    created = service.create_incident(
        title="Repeated synthetic authentication failures",
        description="Analyst review required.",
        severity="high",
        alert_ids=[alert_id],
        supporting_event_refs=[event_ref],
    )
    read_back = service.get_incident(created.incident_id)

    assert read_back == created
    assert read_back.status == "open"
    assert read_back.alert_ids == (alert_id,)
    assert read_back.supporting_event_refs == (event_ref,)
    assert read_back.resolved_at is None
    assert read_back.closed_at is None
    _assert_utc_timestamp(read_back.created_at)
    _assert_utc_timestamp(read_back.updated_at)


def test_update_incident_fields_without_changing_status(
    store_and_service: tuple[SQLiteRepository, IncidentService],
) -> None:
    _, service = store_and_service
    incident = service.create_incident(title="Initial title")

    updated = service.update_incident(
        incident.incident_id,
        title="Revised title with 'quoted' text",
        description="Reviewed locally.",
        severity="critical",
    )

    assert updated.title == "Revised title with 'quoted' text"
    assert updated.description == "Reviewed locally."
    assert updated.severity == "critical"
    assert updated.status == "open"
    assert updated.updated_at != incident.updated_at


def test_incident_lifecycle_updates_resolution_and_closure_timestamps(
    store_and_service: tuple[SQLiteRepository, IncidentService],
) -> None:
    _, service = store_and_service
    incident = service.create_incident(title="Lifecycle test")

    investigating = service.transition_status(incident.incident_id, "investigating")
    assert investigating.status == "investigating"
    assert investigating.resolved_at is None

    resolved = service.transition_status(incident.incident_id, "resolved")
    assert resolved.status == "resolved"
    _assert_utc_timestamp(resolved.resolved_at)
    assert resolved.closed_at is None

    closed = service.transition_status(incident.incident_id, "closed")
    assert closed.status == "closed"
    assert closed.resolved_at == resolved.resolved_at
    _assert_utc_timestamp(closed.closed_at)

    with pytest.raises(IncidentTransitionError, match="Cannot transition"):
        service.transition_status(incident.incident_id, "investigating")


def test_reopening_a_resolved_incident_clears_resolution_timestamp(
    store_and_service: tuple[SQLiteRepository, IncidentService],
) -> None:
    _, service = store_and_service
    incident = service.create_incident(title="Reopen test")
    service.transition_status(incident.incident_id, "investigating")
    resolved = service.transition_status(incident.incident_id, "resolved")
    reopened = service.transition_status(incident.incident_id, "investigating")

    assert resolved.resolved_at is not None
    assert reopened.status == "investigating"
    assert reopened.resolved_at is None
    assert reopened.closed_at is None


@pytest.mark.parametrize("status", ["resolved", "closed", "unknown", ""])
def test_invalid_status_transition_is_rejected(
    store_and_service: tuple[SQLiteRepository, IncidentService], status: str
) -> None:
    _, service = store_and_service
    incident = service.create_incident(title="Transition validation")

    with pytest.raises(IncidentTransitionError):
        service.transition_status(incident.incident_id, status)

    assert service.get_incident(incident.incident_id).status == "open"


@pytest.mark.parametrize(
    ("field", "value"),
    [("title", ""), ("severity", "urgent"), ("description", 10)],
)
def test_incident_values_are_validated_on_create(
    store_and_service: tuple[SQLiteRepository, IncidentService],
    field: str,
    value: object,
) -> None:
    _, service = store_and_service
    fields = {"title": "Valid title"}
    fields[field] = value

    with pytest.raises(IncidentValidationError):
        service.create_incident(**fields)


def test_update_validation_and_missing_incident_errors(
    store_and_service: tuple[SQLiteRepository, IncidentService],
) -> None:
    _, service = store_and_service
    incident = service.create_incident(title="Keep this title")

    with pytest.raises(IncidentValidationError, match="non-empty text"):
        service.update_incident(incident.incident_id, title=" ")
    with pytest.raises(IncidentValidationError, match="supported level"):
        service.update_incident(incident.incident_id, severity="urgent")
    with pytest.raises(IncidentValidationError, match="At least one"):
        service.update_incident(incident.incident_id)
    with pytest.raises(IncidentNotFoundError):
        service.update_incident("absent", title="No such incident")

    assert service.get_incident(incident.incident_id).title == "Keep this title"
    assert service.get_incident("absent") is None


def test_incident_link_failure_rolls_back_incident_row(
    store_and_service: tuple[SQLiteRepository, IncidentService],
) -> None:
    store, _ = store_and_service
    incident = Incident(
        incident_id="incident-rollback-test",
        title="Rollback test",
        description="",
        severity="medium",
        status="open",
        created_at="2026-10-14T13:00:00Z",
        updated_at="2026-10-14T13:00:00Z",
        resolved_at=None,
        closed_at=None,
        alert_ids=("missing-alert",),
        supporting_event_refs=(),
    )

    with pytest.raises(StorageValidationError, match="unknown alert"):
        store.create_incident(incident)

    assert store.get_incident(incident.incident_id) is None
