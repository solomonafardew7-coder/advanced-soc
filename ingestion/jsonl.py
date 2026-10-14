"""Read JSON Lines files and normalize each valid security event."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ingestion.normalizer import (
    EventNormalizationError,
    NormalizedEvent,
    normalize_event,
)
from ingestion.parser import EventParseError, parse_event


@dataclass(frozen=True)
class JSONLRecordError:
    """A rejected record, identified by its 1-based line number."""

    line_number: int
    message: str


@dataclass(frozen=True)
class JSONLIngestionResult:
    """Events accepted and record errors found while reading a JSONL file."""

    events: tuple[NormalizedEvent, ...]
    errors: tuple[JSONLRecordError, ...]
    lines_read: int


def ingest_jsonl(path: str | Path) -> JSONLIngestionResult:
    """Parse and normalize each line in a UTF-8 JSONL file.

    A malformed or blank line is recorded as an error and processing continues.
    Error reports contain the line number and validation message, not the raw
    record, so sensitive input is not copied into the report.

    File access and text-decoding errors are allowed to propagate to the caller.
    """
    accepted: list[NormalizedEvent] = []
    errors: list[JSONLRecordError] = []
    lines_read = 0

    with Path(path).open("r", encoding="utf-8") as jsonl_file:
        for line_number, raw_line in enumerate(jsonl_file, start=1):
            lines_read = line_number
            try:
                parsed_event = parse_event(raw_line)
                accepted.append(normalize_event(parsed_event))
            except (EventParseError, EventNormalizationError) as exc:
                errors.append(JSONLRecordError(line_number, str(exc)))

    return JSONLIngestionResult(
        events=tuple(accepted), errors=tuple(errors), lines_read=lines_read
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local JSONL ingestion pipeline as a command-line program."""
    argument_parser = argparse.ArgumentParser(
        description="Normalize security events from a local JSONL file."
    )
    argument_parser.add_argument("path", type=Path, help="Input JSONL file")
    args = argument_parser.parse_args(argv)

    result = ingest_jsonl(args.path)
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
