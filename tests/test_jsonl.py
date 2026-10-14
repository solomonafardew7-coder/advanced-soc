"""Tests for local JSON Lines ingestion."""

from pathlib import Path

from ingestion.jsonl import ingest_jsonl


def test_ingest_jsonl_reads_and_normalizes_synthetic_sample() -> None:
    sample_path = Path(__file__).parents[1] / "data" / "sample_events.jsonl"

    result = ingest_jsonl(sample_path)

    assert result.lines_read == 2
    assert len(result.events) == 2
    assert result.errors == ()
    assert result.events[0]["timestamp"] == "2026-10-14T13:00:00Z"
    assert result.events[0]["details"] == {"username": "synthetic-user"}
    assert result.events[1]["severity"] == "unknown"


def test_ingest_jsonl_reports_bad_line_and_continues(tmp_path: Path) -> None:
    input_path = tmp_path / "events.jsonl"
    input_path.write_text(
        '{"timestamp":"2026-10-14T13:00:00Z","event_type":"login"}\n'
        '{"event_type":"malformed"\n'
        '{"timestamp":"2026-10-14T13:01:00Z","event_type":"logout"}\n',
        encoding="utf-8",
    )

    result = ingest_jsonl(input_path)

    assert result.lines_read == 3
    assert len(result.events) == 2
    assert len(result.errors) == 1
    assert result.errors[0].line_number == 2
    assert "invalid JSON" in result.errors[0].message


def test_ingest_jsonl_reports_blank_line_and_continues(tmp_path: Path) -> None:
    input_path = tmp_path / "events.jsonl"
    input_path.write_text(
        '\n{"timestamp":"2026-10-14T13:00:00Z","event_type":"login"}\n',
        encoding="utf-8",
    )

    result = ingest_jsonl(input_path)

    assert len(result.events) == 1
    assert len(result.errors) == 1
    assert result.errors[0].line_number == 1


def test_ingest_jsonl_handles_empty_file(tmp_path: Path) -> None:
    input_path = tmp_path / "empty.jsonl"
    input_path.touch()

    result = ingest_jsonl(input_path)

    assert result.events == ()
    assert result.errors == ()
    assert result.lines_read == 0
