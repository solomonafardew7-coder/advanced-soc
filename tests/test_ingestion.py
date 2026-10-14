"""Tests for parsing individual security events."""

import pytest

from ingestion.parser import EventParseError, parse_event


def test_parse_event_returns_valid_json_object() -> None:
    raw_json = (
        '{"timestamp":"2026-10-14T12:00:00Z",'
        '"event_type":"authentication_failure",'
        '"source":"sshd","username":"synthetic-user"}'
    )

    assert parse_event(raw_json) == {
        "timestamp": "2026-10-14T12:00:00Z",
        "event_type": "authentication_failure",
        "source": "sshd",
        "username": "synthetic-user",
    }


def test_parse_event_rejects_malformed_json() -> None:
    with pytest.raises(EventParseError, match="invalid JSON"):
        parse_event('{"event_type": "authentication_failure"')


@pytest.mark.parametrize("raw_json", ["", "   ", "\n\t"])
def test_parse_event_rejects_empty_input(raw_json: str) -> None:
    with pytest.raises(EventParseError, match="must not be empty"):
        parse_event(raw_json)


@pytest.mark.parametrize("raw_json", ["[]", '"event"', "42", "true", "null"])
def test_parse_event_rejects_json_that_is_not_an_object(raw_json: str) -> None:
    with pytest.raises(EventParseError, match="must be a JSON object"):
        parse_event(raw_json)


def test_parse_event_rejects_empty_json_object() -> None:
    with pytest.raises(EventParseError, match="object must not be empty"):
        parse_event("{}")


def test_parse_event_rejects_nonstandard_json_constant() -> None:
    with pytest.raises(EventParseError, match="invalid JSON value"):
        parse_event('{"score": NaN}')
