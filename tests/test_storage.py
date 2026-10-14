"""Temporary-database tests for persistent events and generated alerts."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from backend.app.database.sqlite_repository import (
    SQLiteRepository,
    StorageConflictError,
    StorageError,
    StorageValidationError,
    event_reference,
)
from detection.engine import DetectionEngine


@pytest.fixture
def repository(tmp_path: Path) -> SQLiteRepository:
    store = SQLiteRepository(tmp_path / "soc-test.sqlite3")
    store.initialize()
    return store


def _event(index: int = 0) -> dict:
    return {
        "timestamp": f"2026-10-14T13:00:{index:02d}Z",
        "event_type": "authentication_failure",
        "source": "sshd",
        "source_ip": "198.51.100.10",
        "severity": "high",
        "details": {"username": f"synthetic-user-{index}"},
    }


def _alert(event_ref: str, alert_id: str = "synthetic-alert-1") -> dict:
    return {
        "alert_id": alert_id,
        "rule_id": "SYNTHETIC-TEST-001",
        "rule_name": "Synthetic storage test",
        "severity": "high",
        "description": "Synthetic alert used by persistence tests.",
        "event_timestamp": "2026-10-14T13:00:00Z",
        "source_ip": "198.51.100.10",
        "sources": ["sshd"],
        "supporting_event_refs": [event_ref],
        "evidence": {"test": True},
    }


def test_event_identifier_is_stable_and_duplicate_insert_is_idempotent(
    repository: SQLiteRepository,
) -> None:
    event = _event()
    event_id = event_reference(event)

    assert repository.save_event(event) is True
    assert repository.save_event(event) is False
    assert event_reference(event) == event_id
    assert repository.get_event(event_id) == {
        "event_id": event_id,
        "timestamp": "2026-10-14T13:00:00Z",
        "event_type": "authentication_failure",
        "source": "sshd",
        "source_ip": "198.51.100.10",
        "severity": "high",
        "details": {"username": "synthetic-user-0"},
    }


def test_event_persists_across_repository_instances(
    tmp_path: Path,
) -> None:
    path = tmp_path / "persistent.sqlite3"
    first_store = SQLiteRepository(path)
    first_store.initialize()
    event = _event()
    event_id = event_reference(event)
    first_store.save_event(event)

    second_store = SQLiteRepository(path)
    second_store.initialize()

    assert second_store.get_event(event_id)["event_type"] == "authentication_failure"


def test_parameterized_values_are_stored_as_data(
    repository: SQLiteRepository,
) -> None:
    event = _event()
    event["event_type"] = "login'; DROP TABLE security_events; --"

    assert repository.save_event(event) is True
    assert repository.get_event(event_reference(event))["event_type"] == event["event_type"]


def test_invalid_events_are_rejected_before_storage(
    repository: SQLiteRepository,
) -> None:
    bad_timestamp = _event()
    bad_timestamp["timestamp"] = "not-a-timestamp"
    with pytest.raises(StorageValidationError, match="timestamp"):
        repository.save_event(bad_timestamp)

    unsupported_value = _event()
    unsupported_value["details"] = {"not_json": object()}
    with pytest.raises(StorageValidationError, match="JSON-serializable"):
        repository.save_event(unsupported_value)


def test_generated_detection_alert_and_supporting_events_persist(
    repository: SQLiteRepository,
) -> None:
    events = [_event(index) for index in range(5)]
    engine_result = DetectionEngine.from_directory().evaluate(events)
    assert len(engine_result.alerts) == 1
    alert = engine_result.alerts[0]

    for event in events:
        assert repository.save_event(event) is True
    assert repository.save_alert(alert) is True
    assert repository.save_alert(alert) is False

    stored = repository.get_alert(alert["alert_id"])
    assert stored == dict(alert)
    assert stored["supporting_event_refs"] == [event_reference(event) for event in events]


def test_alert_duplicate_identifier_with_different_payload_is_conflict(
    repository: SQLiteRepository,
) -> None:
    event = _event()
    repository.save_event(event)
    alert = _alert(event_reference(event))
    repository.save_alert(alert)
    conflicting = deepcopy(alert)
    conflicting["description"] = "Different content under the same stable ID."

    with pytest.raises(StorageConflictError, match="different contents"):
        repository.save_alert(conflicting)


def test_alert_reference_validation_rolls_back_alert_insert(
    repository: SQLiteRepository,
) -> None:
    alert = _alert("event:does-not-exist")

    with pytest.raises(StorageValidationError, match="unknown event"):
        repository.save_alert(alert)

    assert repository.get_alert(alert["alert_id"]) is None


@pytest.mark.parametrize(
    "change",
    [
        {"severity": "unknown"},
        {"supporting_event_refs": []},
        {"evidence": []},
    ],
)
def test_alert_data_is_validated(
    repository: SQLiteRepository, change: dict
) -> None:
    alert = _alert("event:unused")
    alert.update(change)

    with pytest.raises(StorageValidationError):
        repository.save_alert(alert)


def test_database_open_and_corruption_errors_are_reported(tmp_path: Path) -> None:
    missing_parent = SQLiteRepository(tmp_path / "missing" / "db.sqlite3")
    with pytest.raises(StorageError, match="open the SQLite database"):
        missing_parent.initialize()

    corrupt_path = tmp_path / "corrupt.sqlite3"
    corrupt_path.write_text("not a SQLite database", encoding="utf-8")
    with pytest.raises(StorageError, match="SQLite operation failed"):
        SQLiteRepository(corrupt_path).initialize()
