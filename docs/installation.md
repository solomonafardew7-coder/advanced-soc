# Local JSONL event ingestion

The first ingestion pipeline reads one JSON object per line, validates each
record, and emits normalized JSON objects. It uses only Python's standard
library at runtime. Invalid or blank lines are reported with their line number;
valid records in the same file are still emitted. The CLI exits with status 1
if any records were rejected. Error reports omit raw input contents.

## Normalized event schema

Every accepted event contains these fields:

| Field | Type | Input rules and defaults |
| --- | --- | --- |
| `timestamp` | string | Required. ISO 8601 date-time with a timezone. `event_timestamp` is accepted as an alias. Output is UTC and ends in `Z`. |
| `event_type` | string | Required and non-empty. |
| `source` | string or `null` | Optional. Must be a non-empty string when supplied; defaults to `null`. |
| `source_ip` | string or `null` | Optional valid IPv4 or IPv6 address. `src_ip` is accepted as an alias; output uses the canonical IP spelling. Defaults to `null`. |
| `severity` | string | Optional. Accepted levels are `informational`, `low`, `medium`, `high`, and `critical`; `info` and `moderate` are aliases. Integer/string values `0` through `4` map in ascending severity order from informational to critical. Defaults to `unknown`. |
| `details` | object | Optional object. Defaults to `{}`. Other input fields are retained here. |

If both spellings of an aliased field are supplied, their values must agree.
Present optional fields are validated rather than silently discarded. Unknown
fields are preserved in `details`; a duplicate between a top-level field and
`details` is rejected.

## Install and run on Parrot OS

Run these commands from the project root. Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ingestion.jsonl data/sample_events.jsonl
```

To save normalized JSONL output to a local file:

```bash
python -m ingestion.jsonl data/sample_events.jsonl > /tmp/normalized_events.jsonl
```

Accepted events are written to standard output, one JSON object per line.
Line-specific errors and a record summary are written to standard error. The
sample input in `data/sample_events.jsonl` contains synthetic values and uses a
documentation-only IP address.

## Local detection engine

The engine consumes the normalized events from the JSONL ingestion pipeline.
Rules are local JSON files in `detection/rules/`; no network service or
additional runtime dependency is used.

### Included rules

- `AUTH-REPEATED-FAILURES-001` matches `authentication_failure` events sharing
  the same `source_ip`. Its configurable `threshold` is 5 events and its
  `window_seconds` is 300 seconds by default. The window includes events exactly
  on its start boundary. One alert is emitted when a burst first reaches the
  threshold; another alert can be emitted after the rolling count falls below
  the threshold and later reaches it again. Events without a source IP do not
  count.
- `SYNTHETIC-PRIVILEGE-PATTERN-001` matches a `privilege_change` event only when
  both `details.target_user` is exactly `root` and `details.outcome` is exactly
  `denied`. This is a synthetic pattern for exercising nested-field rule
  conditions; it is not an assertion that every denied privilege change is
  malicious.

Each rule sets its identifier, name, severity, description, and event type in
its JSON file. Threshold and time-window values are rule settings, so they can
be adjusted without changing engine code. Match-rule conditions use dotted
field paths and exact value comparisons.

An alert includes a UUID, rule ID and name, severity, description, event
timestamp, source IP, contributing source names, supporting event references,
and evidence for the rule match. Event references are SHA-256 fingerprints of
normalized events. Exact duplicate normalized events are evaluated once and
reported in the run summary. Invalid events are reported by input position and
do not stop the remaining valid events from being evaluated.

### Run ingestion and detection

From the project root, after activating the virtual environment from the
previous section:

```bash
python -m detection.engine data/sample_detection_events.jsonl
```

The command prints one JSON alert per line to standard output. Input errors and
the run summary go to standard error. It exits with status 1 if input records
were rejected, and status 2 if the input file or rule configuration cannot be
loaded. To evaluate another JSONL file, replace the sample path. To use a
different local rule directory, pass `--rules PATH`.

The synthetic sample contains five authentication failures from one
documentation-only IP within four minutes and one denied root privilege-change
event, so it exercises both included rules.

## Suricata EVE JSON integration

The passive EVE reader consumes a local UTF-8 JSONL file; Suricata does not
need to be installed to use it or run its tests. Every line is parsed by the
existing JSON event parser, mapped to the common normalized schema, and
validated by the existing normalizer. A malformed record is reported with its
line number and does not stop later lines. File and UTF-8 errors are reported
to the caller. This reader does not start Suricata or inspect live network
traffic.

`data/synthetic_suricata_eve.jsonl` contains fabricated alert, flow, and DNS
records using documentation-only IP addresses. It is a test fixture, not a
capture or genuine attack observation.

### EVE field mapping

| EVE field | Normalized output |
| --- | --- |
| `timestamp` | Required normalized UTC `timestamp`. |
| `event_type` | Required `event_type`; alert, flow, DNS, and other EVE types are retained. |
| `src_ip` | Canonical `source_ip` when present. |
| `dest_ip`, `src_port`, `dest_port`, `proto`, and other EVE fields | Retained in `details` when present. Present destination IPs and ports are validated. |
| `alert.signature`, `alert.category`, `alert.signature_id` | Flattened to `details.signature`, `details.category`, `details.signature_id`, while the complete original alert object remains under `details.alert`. |
| `alert.severity` | Mapped to the common severity (`1` high, `2` medium, `3` low, `4` informational). The original numeric value is retained as `details.suricata_severity`; unsupported numeric priorities normalize to `unknown`. |
| Missing alert severity | Common severity is `unknown`; no value is inferred. |

Suricata's default classification configuration uses priorities 1 (highest)
through 4 (lowest); the adapter maps those four priorities to the platform's
text levels. Custom
priorities outside 1–4 remain available in the original alert object and are
not assigned a guessed text level. See the [Suricata classification
configuration](https://github.com/OISF/suricata/blob/master/etc/classification.config)
and [EVE JSON format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).

### Run the reader and detection engine

Activate the project virtual environment as described above, then run:

```bash
python -m integrations.suricata.eve_reader data/synthetic_suricata_eve.jsonl
```

Normalized events are written to standard output. Record errors and a summary
are written to standard error; the command exits with status 1 when any lines
are rejected, and status 2 when the input file cannot be read. To pass the
normalized records to the existing detection engine, save the reader output
and then invoke the engine:

```bash
python -m integrations.suricata.eve_reader data/synthetic_suricata_eve.jsonl > /tmp/suricata_normalized.jsonl
python -m detection.engine /tmp/suricata_normalized.jsonl
```

Replace the sample path with the local path to your EVE JSONL file. No package
installation or live-network configuration is required for this integration.

## SQLite persistence and incident management

Storage uses Python's built-in `sqlite3`; no extra package or database server is
needed. The SQLite repository creates its schema when `initialize()` is called.
Choose a local database path such as `data/soc_platform.sqlite3`. Unit tests use
temporary databases and do not create or modify this development database.

The event repository validates records with the existing normalizer and
assigns each normalized event the same stable SHA-256 reference used by the
detection engine. Identical event and alert writes are safe to repeat; reusing
an identifier for different content raises a conflict. Alerts retain their
generated alert IDs and link to stored supporting events. Incidents can link to
stored alerts and events.

Example local usage from the project root after activating `.venv`:

```python
from backend.app.database import SQLiteRepository, event_reference
from backend.app.services import IncidentService
from detection.engine import DetectionEngine
from ingestion.jsonl import ingest_jsonl

store = SQLiteRepository("data/soc_platform.sqlite3")
store.initialize()

events = ingest_jsonl("data/sample_detection_events.jsonl").events
for event in events:
    store.save_event(event)

run = DetectionEngine.from_directory().evaluate(events)
for alert in run.alerts:
    store.save_alert(alert)

if run.alerts:
    alert = run.alerts[0]
    incidents = IncidentService(store)
    incident = incidents.create_incident(
        title=alert["rule_name"],
        description=alert["description"],
        severity=alert["severity"],
        alert_ids=[alert["alert_id"]],
        supporting_event_refs=alert["supporting_event_refs"],
    )
    incident = incidents.transition_status(incident.incident_id, "investigating")
    print(incident.incident_id, incident.status)
```

The supported statuses are `open`, `investigating`, `resolved`, and `closed`.
Incidents start open. Allowed transitions are `open → investigating`,
`investigating → open` or `resolved`, and `resolved → investigating` or
`closed`; closed incidents are terminal. Transition timestamps are stored in
UTC. The `IncidentService` validates requests and enforces the lifecycle;
`SQLiteRepository` contains the parameterized SQL and transaction handling.

Run the full suite with:

```bash
python -m pytest -q
```

## FastAPI local backend

For API installation, local token generation, startup, endpoint access, and
security limitations, see [the API guide](api.md). The API binds to loopback
by default in the documented command and uses the local SQLite database.
