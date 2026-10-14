"""Configurable rule evaluation for normalized security events."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, TypedDict

from ingestion.jsonl import ingest_jsonl
from ingestion.normalizer import (
    EventNormalizationError,
    NormalizedEvent,
    normalize_event,
)

RuleType = Literal["threshold", "match"]
AlertSeverity = Literal["informational", "low", "medium", "high", "critical"]
DEFAULT_RULE_DIRECTORY = Path(__file__).resolve().parent / "rules"


class DetectionRule(TypedDict):
    """Validated rule configuration loaded from a JSON rule file."""

    rule_id: str
    name: str
    rule_type: RuleType
    severity: AlertSeverity
    description: str
    event_type: str
    enabled: bool
    threshold: int
    window_seconds: int
    conditions: dict[str, Any]


class Alert(TypedDict):
    """Structured detection result emitted by the engine."""

    alert_id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    description: str
    event_timestamp: str
    source_ip: str | None
    sources: list[str]
    supporting_event_refs: list[str]
    evidence: dict[str, Any]


class RuleConfigurationError(ValueError):
    """Raised when a local rule file is invalid or unsupported."""


@dataclass(frozen=True)
class DetectionInputError:
    """An invalid event, identified by its 1-based position in the input."""

    event_index: int
    message: str


@dataclass(frozen=True)
class DetectionRunResult:
    """Alerts and input-quality information from one engine run."""

    alerts: tuple[Alert, ...]
    errors: tuple[DetectionInputError, ...]
    events_evaluated: int
    duplicates_ignored: int


@dataclass(frozen=True)
class _PreparedEvent:
    event_index: int
    event: NormalizedEvent
    timestamp: datetime
    event_ref: str


_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_BASE_RULE_FIELDS = {
    "id",
    "name",
    "type",
    "severity",
    "description",
    "event_type",
    "enabled",
}


def _required_text(value: Any, field_name: str, path: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleConfigurationError(
            f"{path.name}: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_rule(raw_rule: Any, path: Path) -> DetectionRule:
    if not isinstance(raw_rule, dict):
        raise RuleConfigurationError(f"{path.name}: rule must be a JSON object.")

    rule_type = raw_rule.get("type")
    if rule_type not in ("threshold", "match"):
        raise RuleConfigurationError(
            f"{path.name}: 'type' must be 'threshold' or 'match'."
        )

    allowed_fields = set(_BASE_RULE_FIELDS)
    if rule_type == "threshold":
        allowed_fields.update({"threshold", "window_seconds"})
    else:
        allowed_fields.add("conditions")
    unknown_fields = set(raw_rule) - allowed_fields
    if unknown_fields:
        unexpected = ", ".join(sorted(str(field) for field in unknown_fields))
        raise RuleConfigurationError(f"{path.name}: unsupported field(s): {unexpected}.")

    rule_id = _required_text(raw_rule.get("id"), "id", path)
    name = _required_text(raw_rule.get("name"), "name", path)
    description = _required_text(raw_rule.get("description"), "description", path)
    event_type = _required_text(raw_rule.get("event_type"), "event_type", path)

    severity = raw_rule.get("severity")
    if not isinstance(severity, str) or severity not in _SEVERITIES:
        raise RuleConfigurationError(
            f"{path.name}: 'severity' must be one of {', '.join(sorted(_SEVERITIES))}."
        )

    enabled = raw_rule.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RuleConfigurationError(f"{path.name}: 'enabled' must be a boolean.")

    rule: DetectionRule = {
        "rule_id": rule_id,
        "name": name,
        "rule_type": rule_type,
        "severity": severity,  # type: ignore[typeddict-item]
        "description": description,
        "event_type": event_type,
        "enabled": enabled,
        "threshold": 0,
        "window_seconds": 0,
        "conditions": {},
    }

    if rule_type == "threshold":
        threshold = raw_rule.get("threshold")
        window_seconds = raw_rule.get("window_seconds")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise RuleConfigurationError(
                f"{path.name}: 'threshold' must be a positive integer."
            )
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, int)
            or window_seconds < 1
        ):
            raise RuleConfigurationError(
                f"{path.name}: 'window_seconds' must be a positive integer."
            )
        rule["threshold"] = threshold
        rule["window_seconds"] = window_seconds
    else:
        conditions = raw_rule.get("conditions")
        if not isinstance(conditions, dict) or not conditions:
            raise RuleConfigurationError(
                f"{path.name}: 'conditions' must be a non-empty JSON object."
            )
        for field_path in conditions:
            if (
                not isinstance(field_path, str)
                or not field_path
                or any(not part for part in field_path.split("."))
            ):
                raise RuleConfigurationError(
                    f"{path.name}: condition paths must be non-empty dotted field names."
                )
        rule["conditions"] = conditions

    return rule


def load_rules(directory: str | Path = DEFAULT_RULE_DIRECTORY) -> tuple[DetectionRule, ...]:
    """Load and validate sorted ``*.json`` rule files from a local directory."""
    rule_directory = Path(directory)
    if not rule_directory.is_dir():
        raise RuleConfigurationError(f"Rule directory does not exist: {rule_directory}")

    rule_files = sorted(rule_directory.glob("*.json"))
    if not rule_files:
        raise RuleConfigurationError(f"No JSON rule files found in {rule_directory}.")

    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()
    for path in rule_files:
        try:
            raw_rule = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleConfigurationError(f"Could not read valid JSON from {path.name}.") from exc

        rule = _parse_rule(raw_rule, path)
        if rule["rule_id"] in seen_ids:
            raise RuleConfigurationError(f"Duplicate rule id: {rule['rule_id']}.")
        seen_ids.add(rule["rule_id"])
        rules.append(rule)

    return tuple(rules)


def _prepare_event(raw_event: Any, event_index: int) -> tuple[_PreparedEvent | None, str | None]:
    try:
        event = normalize_event(raw_event)
        encoded = json.dumps(
            event, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except EventNormalizationError as exc:
        return None, str(exc)
    except (TypeError, ValueError, RecursionError):
        return None, "Event contains values that cannot be serialized as JSON."

    timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    timestamp = timestamp.astimezone(timezone.utc)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return (
        _PreparedEvent(
            event_index=event_index,
            event=event,
            timestamp=timestamp,
            event_ref=f"event:{digest}",
        ),
        None,
    )


def _field_value(event: Mapping[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


_MISSING = object()


def _matches_conditions(
    event: Mapping[str, Any], conditions: Mapping[str, Any]
) -> bool:
    return all(
        _field_value(event, field_path) == expected
        for field_path, expected in conditions.items()
    )


def _create_alert(
    rule: DetectionRule,
    supporting_events: Sequence[_PreparedEvent],
    evidence: dict[str, Any],
    source_ip: str | None,
) -> Alert:
    sources = sorted(
        {
            event.event["source"]
            for event in supporting_events
            if event.event["source"] is not None
        }
    )
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_id": rule["rule_id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "description": rule["description"],
        "event_timestamp": supporting_events[-1].event["timestamp"],
        "source_ip": source_ip,
        "sources": sources,
        "supporting_event_refs": [item.event_ref for item in supporting_events],
        "evidence": evidence,
    }


def _evaluate_threshold_rule(
    rule: DetectionRule, events: Sequence[_PreparedEvent]
) -> list[Alert]:
    grouped: dict[str, list[_PreparedEvent]] = defaultdict(list)
    for item in events:
        if (
            item.event["event_type"] == rule["event_type"]
            and item.event["source_ip"] is not None
        ):
            grouped[item.event["source_ip"]].append(item)

    alerts: list[Alert] = []
    window_duration = timedelta(seconds=rule["window_seconds"])
    for source_ip, group in sorted(grouped.items()):
        active: deque[_PreparedEvent] = deque()
        armed = True
        for current in group:
            window_start = current.timestamp - window_duration
            while active and active[0].timestamp < window_start:
                active.popleft()

            if len(active) < rule["threshold"]:
                armed = True
            active.append(current)

            if len(active) >= rule["threshold"] and armed:
                evidence = {
                    "failure_count": len(active),
                    "threshold": rule["threshold"],
                    "window_seconds": rule["window_seconds"],
                }
                alerts.append(
                    _create_alert(rule, tuple(active), evidence, source_ip)
                )
                armed = False

    return alerts


def _evaluate_match_rule(
    rule: DetectionRule, events: Sequence[_PreparedEvent]
) -> list[Alert]:
    alerts: list[Alert] = []
    for item in events:
        if item.event["event_type"] != rule["event_type"]:
            continue
        if not _matches_conditions(item.event, rule["conditions"]):
            continue
        alerts.append(
            _create_alert(
                rule,
                (item,),
                {"matched_conditions": dict(rule["conditions"])},
                item.event["source_ip"],
            )
        )
    return alerts


class DetectionEngine:
    """Evaluate normalized events against a set of validated local rules."""

    def __init__(self, rules: Sequence[DetectionRule]) -> None:
        if not rules:
            raise RuleConfigurationError("At least one detection rule is required.")
        rule_ids = [rule["rule_id"] for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise RuleConfigurationError("Detection rule identifiers must be unique.")
        self.rules = tuple(rules)

    @classmethod
    def from_directory(
        cls, directory: str | Path = DEFAULT_RULE_DIRECTORY
    ) -> DetectionEngine:
        """Create an engine from JSON rules in ``directory``."""
        return cls(load_rules(directory))

    def evaluate(self, events: Iterable[Any]) -> DetectionRunResult:
        """Evaluate events, reporting invalid input and suppressing duplicates.

        An exact duplicate after normalization is evaluated once. Its stable
        SHA-256 event reference is included in any supporting alert evidence.
        Events are sorted by timestamp for time-window rules, so input order
        does not affect correlation.
        """
        prepared: list[_PreparedEvent] = []
        errors: list[DetectionInputError] = []
        seen_fingerprints: set[str] = set()
        duplicates_ignored = 0

        for event_index, raw_event in enumerate(events, start=1):
            item, error = _prepare_event(raw_event, event_index)
            if error is not None:
                errors.append(DetectionInputError(event_index, error))
                continue
            assert item is not None
            fingerprint = item.event_ref
            if fingerprint in seen_fingerprints:
                duplicates_ignored += 1
                continue
            seen_fingerprints.add(fingerprint)
            prepared.append(item)

        prepared.sort(key=lambda item: (item.timestamp, item.event_index))
        alerts: list[Alert] = []
        for rule in self.rules:
            if not rule["enabled"]:
                continue
            if rule["rule_type"] == "threshold":
                alerts.extend(_evaluate_threshold_rule(rule, prepared))
            else:
                alerts.extend(_evaluate_match_rule(rule, prepared))

        alerts.sort(key=lambda alert: (alert["event_timestamp"], alert["rule_id"]))
        return DetectionRunResult(
            alerts=tuple(alerts),
            errors=tuple(errors),
            events_evaluated=len(prepared),
            duplicates_ignored=duplicates_ignored,
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run ingestion followed by local rule evaluation from the command line."""
    parser = argparse.ArgumentParser(
        description="Ingest local JSONL events and evaluate SOC detection rules."
    )
    parser.add_argument("jsonl_path", type=Path, help="Input security-event JSONL file")
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULE_DIRECTORY,
        help="Directory containing JSON detection rules",
    )
    args = parser.parse_args(argv)

    try:
        ingestion_result = ingest_jsonl(args.jsonl_path)
        engine = DetectionEngine.from_directory(args.rules)
    except (OSError, RuleConfigurationError) as exc:
        print(f"Detection run failed: {exc}", file=sys.stderr)
        return 2

    result = engine.evaluate(ingestion_result.events)
    for alert in result.alerts:
        print(json.dumps(alert, sort_keys=True, separators=(",", ":")))

    for error in ingestion_result.errors:
        print(f"Input line {error.line_number}: {error.message}", file=sys.stderr)
    for error in result.errors:
        print(f"Event {error.event_index}: {error.message}", file=sys.stderr)

    total_errors = len(ingestion_result.errors) + len(result.errors)
    print(
        f"Read {ingestion_result.lines_read} line(s), evaluated "
        f"{result.events_evaluated} unique event(s), ignored "
        f"{result.duplicates_ignored} duplicate(s), emitted "
        f"{len(result.alerts)} alert(s), found {total_errors} input error(s).",
        file=sys.stderr,
    )
    return 1 if total_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
