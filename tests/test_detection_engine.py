"""Tests for configurable detection rules and structured alerts."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from detection.engine import DetectionEngine, RuleConfigurationError, load_rules, main


ROOT = Path(__file__).parents[1]
RULE_DIRECTORY = ROOT / "detection" / "rules"
BASE_TIME = datetime(2026, 10, 14, 13, 0, tzinfo=timezone.utc)


def _timestamp(seconds: float) -> str:
    return (BASE_TIME + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _auth_failure(
    seconds: float, source_ip: str | None = "198.51.100.10"
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": _timestamp(seconds),
        "event_type": "authentication_failure",
        "source": "sshd",
        "severity": "high",
        "details": {"username": "synthetic-user"},
    }
    if source_ip is not None:
        event["source_ip"] = source_ip
    return event


def _engine() -> DetectionEngine:
    return DetectionEngine.from_directory(RULE_DIRECTORY)


def test_loads_local_configurable_rules() -> None:
    rules = load_rules(RULE_DIRECTORY)

    assert [rule["rule_id"] for rule in rules] == [
        "AUTH-REPEATED-FAILURES-001",
        "SYNTHETIC-PRIVILEGE-PATTERN-001",
    ]
    auth_rule = next(rule for rule in rules if rule["rule_type"] == "threshold")
    assert auth_rule["threshold"] == 5
    assert auth_rule["window_seconds"] == 300


def test_repeated_authentication_failures_create_structured_alert() -> None:
    result = _engine().evaluate([_auth_failure(seconds) for seconds in range(5)])

    assert len(result.alerts) == 1
    assert result.errors == ()
    assert result.events_evaluated == 5
    alert = result.alerts[0]
    uuid.UUID(alert["alert_id"])
    assert alert["rule_id"] == "AUTH-REPEATED-FAILURES-001"
    assert alert["severity"] == "high"
    assert alert["event_timestamp"] == _timestamp(4)
    assert alert["source_ip"] == "198.51.100.10"
    assert alert["sources"] == ["sshd"]
    assert len(alert["supporting_event_refs"]) == 5
    assert alert["evidence"] == {
        "failure_count": 5,
        "threshold": 5,
        "window_seconds": 300,
    }


def test_authentication_failures_below_threshold_do_not_alert() -> None:
    result = _engine().evaluate([_auth_failure(seconds) for seconds in range(4)])

    assert result.alerts == ()


def test_threshold_is_grouped_by_source_ip() -> None:
    events = [
        _auth_failure(0, "198.51.100.10"),
        _auth_failure(1, "198.51.100.10"),
        _auth_failure(2, "198.51.100.10"),
        _auth_failure(3, "203.0.113.8"),
        _auth_failure(4, "203.0.113.8"),
    ]

    assert _engine().evaluate(events).alerts == ()


def test_sliding_window_includes_exact_boundary() -> None:
    events = [_auth_failure(seconds) for seconds in (0, 60, 120, 240, 300)]

    result = _engine().evaluate(events)

    assert len(result.alerts) == 1
    assert result.alerts[0]["evidence"]["failure_count"] == 5


def test_sliding_window_excludes_events_just_outside_boundary() -> None:
    events = [_auth_failure(seconds) for seconds in (0, 60, 120, 240, 300.001)]

    result = _engine().evaluate(events)

    assert result.alerts == ()


def test_window_expiry_rearms_rule_for_a_later_burst() -> None:
    events = [_auth_failure(seconds) for seconds in range(5)]
    events.extend(_auth_failure(1000 + seconds) for seconds in range(5))

    result = _engine().evaluate(events)

    assert len(result.alerts) == 2
    assert all(alert["rule_id"] == "AUTH-REPEATED-FAILURES-001" for alert in result.alerts)


def test_duplicate_events_are_ignored_and_do_not_raise_threshold_count() -> None:
    unique_events = [_auth_failure(seconds) for seconds in range(4)]
    result = _engine().evaluate([*unique_events, unique_events[0]])

    assert result.alerts == ()
    assert result.events_evaluated == 4
    assert result.duplicates_ignored == 1


def test_missing_source_ip_is_safe_and_does_not_match_threshold_rule() -> None:
    result = _engine().evaluate([_auth_failure(seconds, None) for seconds in range(6)])

    assert result.alerts == ()
    assert result.errors == ()
    assert result.events_evaluated == 6


def test_invalid_events_are_reported_without_stopping_evaluation() -> None:
    invalid_events: list[Any] = [
        None,
        {"timestamp": "not-a-timestamp", "event_type": "authentication_failure"},
        {"timestamp": _timestamp(0), "event_type": 17},
    ]
    valid_events = [_auth_failure(seconds) for seconds in range(5)]

    result = _engine().evaluate([*invalid_events, *valid_events])

    assert len(result.errors) == 3
    assert [error.event_index for error in result.errors] == [1, 2, 3]
    assert len(result.alerts) == 1
    assert result.events_evaluated == 5


def test_synthetic_denied_root_pattern_creates_alert() -> None:
    event = {
        "timestamp": _timestamp(10),
        "event_type": "privilege_change",
        "source": "synthetic-audit",
        "source_ip": "198.51.100.20",
        "severity": "medium",
        "details": {"target_user": "root", "outcome": "denied"},
    }

    result = _engine().evaluate([event])

    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert["rule_id"] == "SYNTHETIC-PRIVILEGE-PATTERN-001"
    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "198.51.100.20"
    assert alert["evidence"]["matched_conditions"] == {
        "details.target_user": "root",
        "details.outcome": "denied",
    }
    assert len(alert["supporting_event_refs"]) == 1


@pytest.mark.parametrize(
    "event",
    [
        {
            "timestamp": _timestamp(10),
            "event_type": "privilege_change",
            "details": {"target_user": "root", "outcome": "allowed"},
        },
        {
            "timestamp": _timestamp(10),
            "event_type": "privilege_change",
            "details": {"target_user": "operator", "outcome": "denied"},
        },
        {
            "timestamp": _timestamp(10),
            "event_type": "process_observation",
            "details": {"target_user": "root", "outcome": "denied"},
        },
    ],
)
def test_synthetic_pattern_requires_all_configured_conditions(
    event: dict[str, Any],
) -> None:
    assert _engine().evaluate([event]).alerts == ()


def test_alert_identifiers_are_unique_across_matches() -> None:
    events = [_auth_failure(seconds) for seconds in range(5)]
    events.append(
        {
            "timestamp": _timestamp(10),
            "event_type": "privilege_change",
            "details": {"target_user": "root", "outcome": "denied"},
        }
    )

    result = _engine().evaluate(events)

    identifiers = [alert["alert_id"] for alert in result.alerts]
    assert len(identifiers) == 2
    assert len(set(identifiers)) == 2


def test_rule_configuration_controls_threshold_and_window(tmp_path: Path) -> None:
    rule = {
        "id": "TEST-THRESHOLD",
        "name": "Test configurable threshold",
        "type": "threshold",
        "severity": "medium",
        "description": "Test rule with a local threshold and time window.",
        "event_type": "authentication_failure",
        "threshold": 2,
        "window_seconds": 30,
    }
    (tmp_path / "test-rule.json").write_text(json.dumps(rule), encoding="utf-8")
    engine = DetectionEngine.from_directory(tmp_path)

    assert len(engine.evaluate([_auth_failure(0), _auth_failure(30)]).alerts) == 1
    assert engine.evaluate([_auth_failure(0), _auth_failure(30.001)]).alerts == ()


def test_cli_runs_ingestion_and_reports_malformed_lines(tmp_path: Path, capsys) -> None:
    input_path = tmp_path / "events.jsonl"
    valid_lines = [
        json.dumps(_auth_failure(seconds), separators=(",", ":"))
        for seconds in range(5)
    ]
    input_path.write_text("\n".join([*valid_lines, "{malformed"]), encoding="utf-8")

    exit_code = main([str(input_path), "--rules", str(RULE_DIRECTORY)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert len(captured.out.strip().splitlines()) == 1
    assert "Input line 6:" in captured.err
    assert "1 input error(s)" in captured.err


@pytest.mark.parametrize(
    ("field", "value"),
    [("threshold", 0), ("window_seconds", -1)],
)
def test_invalid_threshold_rule_configuration_is_rejected(
    tmp_path: Path, field: str, value: int
) -> None:
    rule = {
        "id": "BAD-RULE",
        "name": "Invalid threshold",
        "type": "threshold",
        "severity": "high",
        "description": "Invalid test configuration.",
        "event_type": "authentication_failure",
        "threshold": 2,
        "window_seconds": 60,
    }
    rule[field] = value
    (tmp_path / "bad-rule.json").write_text(json.dumps(rule), encoding="utf-8")

    with pytest.raises(RuleConfigurationError):
        load_rules(tmp_path)
