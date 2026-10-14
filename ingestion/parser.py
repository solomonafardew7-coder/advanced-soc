"""Parse individual JSON security events."""

from __future__ import annotations

import json
from typing import Any, NoReturn


class EventParseError(ValueError):
    """Raised when input cannot be parsed as a security-event JSON object."""


def _reject_non_json_constant(value: str) -> NoReturn:
    """Reject Python's non-standard JSON constants such as ``NaN``."""
    raise ValueError(f"{value} is not a valid JSON constant")


def parse_event(raw_json: str) -> dict[str, Any]:
    """Parse one JSON security event and return its object without modification.

    The parser validates the JSON syntax and the top-level event shape. It does
    not normalize source-specific fields; that belongs to the ingestion stage.

    Args:
        raw_json: Text containing one JSON object.

    Raises:
        EventParseError: If the input is not text, is empty, contains invalid
            JSON, or does not contain a non-empty JSON object.
    """
    if not isinstance(raw_json, str):
        raise EventParseError("Security event input must be JSON text.")

    if not raw_json.strip():
        raise EventParseError("Security event input must not be empty.")

    try:
        event = json.loads(raw_json, parse_constant=_reject_non_json_constant)
    except json.JSONDecodeError as exc:
        raise EventParseError(
            f"Security event contains invalid JSON at line {exc.lineno}, "
            f"column {exc.colno}."
        ) from exc
    except ValueError as exc:
        raise EventParseError("Security event contains an invalid JSON value.") from exc

    if not isinstance(event, dict):
        raise EventParseError("Security event must be a JSON object.")

    if not event:
        raise EventParseError("Security event object must not be empty.")

    return event
