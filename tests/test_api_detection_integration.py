"""End-to-end API checks across detection, SQLite, and incident workflows.

All records, credentials, and databases in this module are disposable synthetic
fixtures stored under pytest's temporary directory.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from asgi_test_client import ASGITestClient as TestClient

from backend.app.api.auth import token_digest
from backend.app.database import SQLiteRepository, event_reference
from backend.app.main import create_app
from backend.app.security import HmacRevocationLedger
from detection.engine import DetectionEngine


def _test_ledger(path):
    ledger = HmacRevocationLedger(path, bytes.fromhex("a1" * 32))
    ledger.initialize()
    return ledger


def _synthetic_failures() -> list[dict[str, object]]:
    start = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)
    return [
        {
            "timestamp": (start + timedelta(seconds=second)).isoformat().replace(
                "+00:00", "Z"
            ),
            "event_type": "authentication_failure",
            "source": "synthetic-sshd",
            "source_ip": "192.0.2.81",
            "severity": "high",
            "details": {"username": f"synthetic-user-{second}"},
        }
        for second in range(5)
    ]


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _grant(role: str) -> dict[str, str]:
    return {
        "role": role,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def test_detection_storage_api_and_incident_lifecycle_are_connected(tmp_path, caplog):
    database_path = tmp_path / "isolated-integration.sqlite3"
    repository = SQLiteRepository(database_path)
    repository.initialize()

    events = _synthetic_failures()
    detection = DetectionEngine.from_directory().evaluate(events)
    assert detection.errors == ()
    assert len(detection.alerts) == 1
    for event in events:
        assert repository.save_event(event)
    alert = detection.alerts[0]
    assert repository.save_alert(alert)

    tokens = {role: secrets.token_urlsafe(32) for role in ("reader", "analyst", "admin")}
    hashes = {token_digest(token): _grant(role) for role, token in tokens.items()}
    app = create_app(
        database_path=database_path,
        token_hashes=hashes,
        cors_origins=["http://127.0.0.1:4173"],
        revocation_ledger=_test_ledger(tmp_path / "integration-revocations.jsonl"),
    )
    caplog.set_level(logging.INFO, logger="soc.api.audit")

    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/api/v1/health").json() == {"status": "ok"}
        assert client.get("/api/v1/alerts").status_code == 401
        assert client.get(
            "/api/v1/alerts", headers=_authorization("invalid-disposable-token")
        ).status_code == 401

        reader = _authorization(tokens["reader"])
        analyst = _authorization(tokens["analyst"])
        admin = _authorization(tokens["admin"])
        alerts = client.get("/api/v1/alerts?limit=1", headers=reader)
        assert alerts.status_code == 200
        assert alerts.json()["total"] == 1
        assert alerts.json()["items"][0]["rule_id"] == alert["rule_id"]
        alert_detail = client.get(
            f"/api/v1/alerts/{alert['alert_id']}", headers=reader
        )
        assert alert_detail.status_code == 200
        assert alert_detail.json()["description"] == alert["description"]
        assert alert_detail.json()["event_timestamp"] == alert["event_timestamp"]
        assert alert_detail.json()["source_ip"] == "192.0.2.81"
        assert alert_detail.json()["supporting_event_refs"] == alert["supporting_event_refs"]
        assert client.post(
            "/api/v1/incidents",
            headers=reader,
            json={"title": "Unauthorized synthetic case"},
        ).status_code == 403
        assert client.get("/api/v1/events", headers=reader).status_code == 403
        assert client.get("/api/v1/incidents", headers=reader).status_code == 403

        event_page = client.get("/api/v1/events?limit=10", headers=analyst)
        assert event_page.status_code == 200
        assert event_page.json()["total"] == 5
        assert event_page.json()["items"][0]["event_id"] == event_reference(events[-1])
        assert client.get("/api/v1/incidents", headers=analyst).json()["total"] == 0

        created = client.post(
            "/api/v1/incidents",
            headers=analyst,
            json={
                "title": "Synthetic repeated authentication failures",
                "description": "Disposable end-to-end integration fixture.",
                "severity": "high",
                "alert_ids": [alert["alert_id"]],
                "supporting_event_refs": alert["supporting_event_refs"],
            },
        )
        assert created.status_code == 201
        incident_id = created.json()["incident_id"]
        assert created.json()["status"] == "open"
        assert f"action=incident.create role=analyst resource_id='{incident_id}'" in caplog.text

        investigating = client.post(
            f"/api/v1/incidents/{incident_id}/transitions",
            headers=analyst,
            json={"status": "investigating"},
        )
        assert investigating.status_code == 200
        assert investigating.json()["status"] == "investigating"
        assert f"action=incident.transition.investigating role=analyst resource_id='{incident_id}'" in caplog.text
        resolved = client.post(
            f"/api/v1/incidents/{incident_id}/transitions",
            headers=analyst,
            json={"status": "resolved"},
        )
        assert resolved.status_code == 200
        assert resolved.json()["resolved_at"] is not None
        assert f"action=incident.transition.resolved role=analyst resource_id='{incident_id}'" in caplog.text
        assert client.post(
            f"/api/v1/incidents/{incident_id}/transitions",
            headers=analyst,
            json={"status": "closed"},
        ).status_code == 403
        closed = client.post(
            f"/api/v1/incidents/{incident_id}/transitions",
            headers=admin,
            json={"status": "closed"},
        )
        assert closed.status_code == 200
        assert closed.json()["closed_at"] is not None
        assert f"action=incident.transition.closed role=admin resource_id='{incident_id}'" in caplog.text
        assert "Disposable end-to-end integration fixture." not in caplog.text

        injection_like_filter = client.get(
            "/api/v1/events?event_type=authentication_failure%27%20OR%201%3D1%20--",
            headers=analyst,
        )
        assert injection_like_filter.status_code == 200
        assert injection_like_filter.json()["total"] == 0

    # A separate repository and app instance prove the API data is durable.
    reopened = SQLiteRepository(database_path)
    persisted_app = create_app(
        repository=reopened,
        token_hashes=hashes,
        cors_origins=["http://127.0.0.1:4173"],
        revocation_ledger=HmacRevocationLedger(
            tmp_path / "integration-revocations.jsonl", bytes.fromhex("a1" * 32)
        ),
    )
    with TestClient(persisted_app, base_url="http://127.0.0.1") as client:
        assert client.get("/api/v1/alerts", headers=reader).json()["total"] == 1
        assert client.get("/api/v1/events", headers=analyst).json()["total"] == 5
        persisted_incident = client.get(
            f"/api/v1/incidents/{incident_id}", headers=analyst
        )
        assert persisted_incident.status_code == 200
        assert persisted_incident.json()["status"] == "closed"
        assert len(persisted_incident.json()["supporting_event_refs"]) == 5


def test_empty_database_returns_empty_pages_for_dashboard_views(tmp_path):
    repository = SQLiteRepository(tmp_path / "empty-dashboard.sqlite3")
    repository.initialize()
    token = secrets.token_urlsafe(32)
    app = create_app(
        repository=repository,
        token_hashes={token_digest(token): _grant("analyst")},
        revocation_ledger=_test_ledger(tmp_path / "empty-dashboard-revocations.jsonl"),
    )

    with TestClient(app, base_url="http://127.0.0.1") as client:
        headers = _authorization(token)
        for path in ("/api/v1/alerts", "/api/v1/events", "/api/v1/incidents"):
            response = client.get(path, headers=headers)
            assert response.status_code == 200
            assert response.json()["items"] == []
            assert response.json()["total"] == 0

