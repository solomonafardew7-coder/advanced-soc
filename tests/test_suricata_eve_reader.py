"""Tests for local Suricata EVE JSONL ingestion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from integrations.suricata.eve_reader import read_eve_jsonl


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_EVE = PROJECT_ROOT / "data" / "synthetic_suricata_eve.jsonl"


def test_synthetic_alert_maps_into_normalized_event_schema() -> None:
    result = read_eve_jsonl(SYNTHETIC_EVE)

    assert not result.errors
    alert = next(event for event in result.events if event["event_type"] == "alert")
    assert alert["timestamp"] == "2025-03-08T12:01:00Z"
    assert alert["source"] == "suricata"
    assert alert["source_ip"] == "198.51.100.23"
    assert alert["severity"] == "high"
    assert alert["details"]["dest_ip"] == "192.0.2.10"
    assert alert["details"]["src_port"] == 51342
    assert alert["details"]["dest_port"] == 443
    assert alert["details"]["proto"] == "TCP"
    assert (
        alert["details"]["signature"]
        == "Synthetic test signature: unusual TLS server name"
    )
    assert alert["details"]["category"] == "Synthetic policy test"
    assert alert["details"]["signature_id"] == 9000001
    assert alert["details"]["suricata_severity"] == 1
    assert alert["details"]["alert"]["action"] == "allowed"


def test_non_alert_event_is_preserved_without_alert_severity() -> None:
    result = read_eve_jsonl(SYNTHETIC_EVE)

    flow = next(event for event in result.events if event["event_type"] == "flow")
    assert flow["source_ip"] == "192.0.2.10"
    assert flow["severity"] == "unknown"
    assert flow["details"]["dest_ip"] == "198.51.100.23"
    assert flow["details"]["proto"] == "TCP"
    assert flow["details"]["flow"]["state"] == "established"


@pytest.mark.parametrize(
    ("eve_severity", "expected_severity"),
    [(1, "high"), (2, "medium"), (3, "low"), (4, "informational"), (9, "unknown")],
)
def test_suricata_priority_mapping(
    tmp_path: Path, eve_severity: int, expected_severity: str
) -> None:
    path = tmp_path / "priority.jsonl"
    path.write_text(
        json.dumps(
            {
                "timestamp": "2025-03-08T12:00:00Z",
                "event_type": "alert",
                "alert": {"severity": eve_severity},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = read_eve_jsonl(path)

    assert result.errors == ()
    assert result.events[0]["severity"] == expected_severity
    assert result.events[0]["details"]["suricata_severity"] == eve_severity


def test_missing_optional_fields_are_not_invented(tmp_path: Path) -> None:
    path = tmp_path / "minimal.jsonl"
    path.write_text(
        json.dumps({"timestamp": "2025-03-08T12:00:00Z", "event_type": "stats"})
        + "\n",
        encoding="utf-8",
    )

    result = read_eve_jsonl(path)

    assert result.errors == ()
    assert result.events == (
        {
            "timestamp": "2025-03-08T12:00:00Z",
            "event_type": "stats",
            "source": "suricata",
            "source_ip": None,
            "severity": "unknown",
            "details": {},
        },
    )


def test_malformed_lines_are_reported_and_later_records_are_read(tmp_path: Path) -> None:
    path = tmp_path / "mixed.jsonl"
    valid = {"timestamp": "2025-03-08T12:00:00Z", "event_type": "flow"}
    path.write_text(
        json.dumps(valid) + "\n{not json}\n[]\n" + json.dumps(valid) + "\n",
        encoding="utf-8",
    )

    result = read_eve_jsonl(path)

    assert result.lines_read == 4
    assert len(result.events) == 2
    assert [error.line_number for error in result.errors] == [2, 3]


@pytest.mark.parametrize(
    "bad_record",
    [
        {
            "timestamp": "2025-03-08T12:00:00Z",
            "event_type": "flow",
            "dest_ip": "bad",
        },
        {
            "timestamp": "2025-03-08T12:00:00Z",
            "event_type": "flow",
            "src_port": 70000,
        },
        {
            "timestamp": "2025-03-08T12:00:00Z",
            "event_type": "alert",
            "alert": [],
        },
        {
            "timestamp": "2025-03-08T12:00:00Z",
            "event_type": "alert",
            "alert": {"severity": "high"},
        },
    ],
)
def test_invalid_present_eve_fields_are_reported(
    tmp_path: Path, bad_record: dict
) -> None:
    path = tmp_path / "invalid.jsonl"
    path.write_text(json.dumps(bad_record) + "\n", encoding="utf-8")

    result = read_eve_jsonl(path)

    assert result.events == ()
    assert len(result.errors) == 1
    assert result.errors[0].line_number == 1


def test_empty_file_returns_empty_result(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")

    result = read_eve_jsonl(path)

    assert result.events == ()
    assert result.errors == ()
    assert result.lines_read == 0


def test_missing_file_error_is_propagated(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_eve_jsonl(tmp_path / "missing.jsonl")


def test_invalid_utf8_file_error_is_propagated(tmp_path: Path) -> None:
    path = tmp_path / "not_utf8.jsonl"
    path.write_bytes(b"\xff\xfe\n")

    with pytest.raises(UnicodeDecodeError):
        read_eve_jsonl(path)
