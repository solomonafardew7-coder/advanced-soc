"""Validate source records and normalize them to the platform event schema."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict


Severity = Literal[
    "unknown", "informational", "low", "medium", "high", "critical"
]


class NormalizedEvent(TypedDict):
    """Stable, JSON-serializable shape emitted by the ingestion pipeline."""

    timestamp: str
    event_type: str
    source: str | None
    source_ip: str | None
    severity: Severity
    details: dict[str, Any]


class EventNormalizationError(ValueError):
    """Raised when an event field cannot be represented in the common schema."""


_CANONICAL_INPUT_FIELDS = {
    "timestamp",
    "event_timestamp",
    "event_type",
    "source",
    "source_ip",
    "src_ip",
    "severity",
    "details",
}

_SEVERITY_ALIASES: dict[str, Severity] = {
    "unknown": "unknown",
    "info": "informational",
    "informational": "informational",
    "0": "informational",
    "low": "low",
    "1": "low",
    "medium": "medium",
    "moderate": "medium",
    "2": "medium",
    "high": "high",
    "3": "high",
    "critical": "critical",
    "4": "critical",
}


def _aliased_value(
    event: Mapping[str, Any], field_name: str, aliases: tuple[str, ...]
) -> Any:
    """Get one aliased value, rejecting conflicting spellings."""
    present = [(name, event[name]) for name in aliases if name in event]
    if not present:
        raise EventNormalizationError(f"Missing required field: {field_name}.")

    first_value = present[0][1]
    if any(value != first_value for _, value in present[1:]):
        raise EventNormalizationError(f"Conflicting values for {field_name}.")
    return first_value


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EventNormalizationError(f"Field '{field_name}' must be a non-empty string.")
    return value.strip()


def _normalize_timestamp(value: Any) -> str:
    raw_timestamp = _required_text(value, "timestamp")
    iso_timestamp = raw_timestamp
    if iso_timestamp.endswith(("Z", "z")):
        iso_timestamp = f"{iso_timestamp[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(iso_timestamp)
    except ValueError as exc:
        raise EventNormalizationError(
            "Field 'timestamp' must be a valid ISO 8601 date-time."
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventNormalizationError(
            "Field 'timestamp' must include a timezone offset."
        )

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_source_ip(value: Any) -> str:
    raw_ip = _required_text(value, "source_ip")
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError as exc:
        raise EventNormalizationError("Field 'source_ip' must be a valid IP address.") from exc


def _normalize_severity(value: Any) -> Severity:
    if isinstance(value, bool):
        raise EventNormalizationError("Field 'severity' must be a supported level.")

    if isinstance(value, int):
        key = str(value)
    elif isinstance(value, str):
        key = value.strip().lower()
    else:
        raise EventNormalizationError("Field 'severity' must be a supported level.")

    normalized = _SEVERITY_ALIASES.get(key)
    if normalized is None:
        raise EventNormalizationError("Field 'severity' must be a supported level.")
    return normalized


def normalize_event(event: Mapping[str, Any]) -> NormalizedEvent:
    """Normalize one parsed event to the common SOC event schema.

    Required input fields are ``timestamp`` (or ``event_timestamp``) and
    ``event_type``. Timestamps must include a timezone and are converted to UTC.
    Optional ``source``, ``source_ip`` (or ``src_ip``), ``severity``, and
    ``details`` fields are validated when present. Other top-level fields are
    retained inside ``details``.

    Missing optional fields become ``None`` for source/IP, ``"unknown"`` for
    severity, and an empty object for details.

    Raises:
        EventNormalizationError: If a required field is absent, a supplied
            field has the wrong type or format, or aliases conflict.
    """
    if not isinstance(event, Mapping):
        raise EventNormalizationError("Security event must be an object.")
    if any(not isinstance(key, str) for key in event):
        raise EventNormalizationError("Security event field names must be strings.")

    timestamp = _normalize_timestamp(
        _aliased_value(event, "timestamp", ("timestamp", "event_timestamp"))
    )
    event_type = _required_text(event.get("event_type"), "event_type")

    source: str | None = None
    if "source" in event:
        source = _required_text(event["source"], "source")

    source_ip: str | None = None
    if "source_ip" in event or "src_ip" in event:
        source_ip = _normalize_source_ip(
            _aliased_value(event, "source_ip", ("source_ip", "src_ip"))
        )

    severity: Severity = "unknown"
    if "severity" in event:
        severity = _normalize_severity(event["severity"])

    supplied_details = event.get("details", {})
    if not isinstance(supplied_details, dict):
        raise EventNormalizationError("Field 'details' must be an object.")

    details = dict(supplied_details)
    for key, value in event.items():
        if key in _CANONICAL_INPUT_FIELDS:
            continue
        if key in details:
            raise EventNormalizationError(
                f"Field '{key}' appears both at the top level and in details."
            )
        details[key] = value

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "source": source,
        "source_ip": source_ip,
        "severity": severity,
        "details": details,
    }
