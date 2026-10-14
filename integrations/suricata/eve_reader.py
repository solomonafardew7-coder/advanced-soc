"""Read local Suricata EVE JSONL and normalize records for the SOC pipeline."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from ingestion.jsonl import JSONLIngestionResult, JSONLRecordError
from ingestion.normalizer import (
    EventNormalizationError,
    NormalizedEvent,
    normalize_event,
)
from ingestion.parser import EventParseError, parse_event


_EVE_CORE_FIELDS = {"timestamp", "event_type", "src_ip", "source_ip"}
_SURICATA_SEVERITIES = {
    1: "high",
    2: "medium",
    3: "low",
    4: "informational",
}


def _validate_optional_eve_fields(record: dict[str, Any]) -> None:
    """Reject malformed values in optional EVE fields that this adapter uses."""
    for field in ("src_ip", "dest_ip"):
        value = record.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise EventNormalizationError(f"Field '{field}' must be an IP address.")
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise EventNormalizationError(
                f"Field '{field}' must be a valid IP address."
            ) from exc

    for field in ("src_port", "dest_port"):
        value = record.get(field)
        if value is None:
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 65535
        ):
            raise EventNormalizationError(
                f"Field '{field}' must be an integer from 0 through 65535."
            )

    protocol = record.get("proto")
    if protocol is not None and (
        not isinstance(protocol, str) or not protocol.strip()
    ):
        raise EventNormalizationError("Field 'proto' must be a non-empty string.")

    alert = record.get("alert")
    if alert is not None and not isinstance(alert, dict):
        raise EventNormalizationError("Field 'alert' must be an object when supplied.")
    if isinstance(alert, dict):
        for field in ("signature", "category"):
            value = alert.get(field)
            if value is not None and (
                not isinstance(value, str) or not value.strip()
            ):
                raise EventNormalizationError(
                    f"Field 'alert.{field}' must be a non-empty string."
                )
        for field in ("severity", "signature_id"):
            value = alert.get(field)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise EventNormalizationError(
                    f"Field 'alert.{field}' must be an integer."
                )


def _normalize_eve_record(record: dict[str, Any]) -> NormalizedEvent:
    """Map one Suricata EVE object into the shared normalized event schema."""
    _validate_optional_eve_fields(record)

    source_ip = record.get("src_ip", record.get("source_ip"))
    if "src_ip" in record and "source_ip" in record:
        if record["src_ip"] != record["source_ip"]:
            raise EventNormalizationError("Conflicting values for source_ip.")

    details = {
        key: value for key, value in record.items() if key not in _EVE_CORE_FIELDS
    }
    alert = record.get("alert")
    severity: str | None = None
    if isinstance(alert, dict):
        raw_severity = alert.get("severity")
        if raw_severity is not None:
            severity = _SURICATA_SEVERITIES.get(raw_severity, "unknown")
            details["suricata_severity"] = raw_severity
        for source_key, normalized_key in (
            ("signature", "signature"),
            ("category", "category"),
            ("signature_id", "signature_id"),
        ):
            if source_key in alert:
                details[normalized_key] = alert[source_key]

    normalized_input: dict[str, Any] = {
        "timestamp": record.get("timestamp"),
        "event_type": record.get("event_type"),
        "source": "suricata",
        "details": details,
    }
    if source_ip is not None:
        normalized_input["source_ip"] = source_ip
    if severity is not None:
        normalized_input["severity"] = severity

    return normalize_event(normalized_input)


def read_eve_jsonl(path: str | Path) -> JSONLIngestionResult:
    """Read and normalize a local UTF-8 EVE JSONL file.

    Records that fail parsing or validation are reported with their 1-based
    line numbers while later records continue to be processed. File access and
    text-decoding errors propagate to the caller, matching ``ingest_jsonl``.
    """
    accepted: list[NormalizedEvent] = []
    errors: list[JSONLRecordError] = []
    lines_read = 0

    with Path(path).open("r", encoding="utf-8") as eve_file:
        for line_number, raw_line in enumerate(eve_file, start=1):
            lines_read = line_number
            try:
                accepted.append(_normalize_eve_record(parse_event(raw_line)))
            except (EventParseError, EventNormalizationError) as exc:
                errors.append(JSONLRecordError(line_number, str(exc)))

    return JSONLIngestionResult(
        events=tuple(accepted), errors=tuple(errors), lines_read=lines_read
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Normalize EVE JSONL from a local path and print normalized JSONL."""
    argument_parser = argparse.ArgumentParser(
        description="Normalize Suricata EVE JSONL from a local file."
    )
    argument_parser.add_argument("path", type=Path, help="Input EVE JSONL file")
    args = argument_parser.parse_args(argv)

    try:
        result = read_eve_jsonl(args.path)
    except (OSError, UnicodeError) as exc:
        print(f"Could not read EVE file: {exc}", file=sys.stderr)
        return 2

    for event in result.events:
        print(json.dumps(event, sort_keys=True, separators=(",", ":")))
    for error in result.errors:
        print(f"Line {error.line_number}: {error.message}", file=sys.stderr)
    print(
        f"Read {result.lines_read} line(s): {len(result.events)} accepted, "
        f"{len(result.errors)} error(s).",
        file=sys.stderr,
    )
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
