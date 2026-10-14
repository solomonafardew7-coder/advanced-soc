"""Tests for the normalized security-event schema."""

import pytest

from ingestion.normalizer import EventNormalizationError, normalize_event


def test_normalize_event_converts_timestamp_ip_and_severity() -> None:
    normalized = normalize_event(
        {
            "timestamp": "2026-10-14T09:00:00-04:00",
            "event_type": "authentication_failure",
            "source": "sshd",
            "source_ip": "192.0.2.25",
            "severity": "HIGH",
            "username": "synthetic-user",
        }
    )

    assert normalized == {
        "timestamp": "2026-10-14T13:00:00Z",
        "event_type": "authentication_failure",
        "source": "sshd",
        "source_ip": "192.0.2.25",
        "severity": "high",
        "details": {"username": "synthetic-user"},
    }


def test_normalize_event_defaults_missing_optional_fields() -> None:
    normalized = normalize_event(
        {"timestamp": "2026-10-14T13:00:00Z", "event_type": "process_observation"}
    )

    assert normalized["source"] is None
    assert normalized["source_ip"] is None
    assert normalized["severity"] == "unknown"
    assert normalized["details"] == {}


def test_normalize_event_accepts_documented_aliases_and_numeric_severity() -> None:
    normalized = normalize_event(
        {
            "event_timestamp": "2026-10-14T13:00:00+00:00",
            "event_type": "network_connection",
            "src_ip": "2001:db8::1",
            "severity": 2,
        }
    )

    assert normalized["timestamp"] == "2026-10-14T13:00:00Z"
    assert normalized["source_ip"] == "2001:db8::1"
    assert normalized["severity"] == "medium"


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ({"event_type": "login"}, "Missing required field: timestamp"),
        ({"timestamp": "2026-10-14T13:00:00Z"}, "event_type"),
        (
            {"timestamp": "2026-10-14T13:00:00", "event_type": "login"},
            "timezone offset",
        ),
        (
            {
                "timestamp": "2026-10-14T13:00:00Z",
                "event_type": "login",
                "source_ip": "not-an-ip",
            },
            "valid IP address",
        ),
        (
            {
                "timestamp": "2026-10-14T13:00:00Z",
                "event_type": "login",
                "severity": "urgent-ish",
            },
            "supported level",
        ),
        (
            {
                "timestamp": "2026-10-14T13:00:00Z",
                "event_type": "login",
                "details": [],
            },
            "details.*object",
        ),
    ],
)
def test_normalize_event_validates_required_and_present_fields(
    event: dict[str, object], message: str
) -> None:
    with pytest.raises(EventNormalizationError, match=message):
        normalize_event(event)


def test_normalize_event_rejects_conflicting_timestamp_aliases() -> None:
    with pytest.raises(EventNormalizationError, match="Conflicting values for timestamp"):
        normalize_event(
            {
                "timestamp": "2026-10-14T13:00:00Z",
                "event_timestamp": "2026-10-14T14:00:00Z",
                "event_type": "login",
            }
        )
