"""Isolated tests for API validation, authorization, and persistence access."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone

import pytest
from asgi_test_client import ASGITestClient as TestClient

from backend.app.api.auth import token_digest
from backend.app.database import SQLiteRepository, event_reference
from backend.app.database.sqlite_repository import StorageError
from backend.app.main import create_app
from backend.app.security import HmacRevocationLedger


def _test_ledger(path):
    ledger = HmacRevocationLedger(path, bytes.fromhex("a1" * 32))
    ledger.initialize()
    return ledger


def _grant(role: str) -> dict[str, str]:
    return {
        "role": role,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


@pytest.fixture
def api(tmp_path):
    tokens = {
        "reader": secrets.token_urlsafe(32),
        "analyst": secrets.token_urlsafe(32),
        "admin": secrets.token_urlsafe(32),
    }
    repository = SQLiteRepository(tmp_path / "api-test.sqlite3")
    repository.initialize()
    event = {
        "timestamp": "2026-10-14T10:00:00Z",
        "event_type": "authentication_failure",
        "source": "synthetic_test",
        "source_ip": "192.0.2.45",
        "severity": "medium",
        "details": {"synthetic": True, "outcome": "failed"},
    }
    repository.save_event(event)
    event_id = event_reference(event)
    alert = {
        "alert_id": "test-alert-001",
        "rule_id": "TEST-RULE-001",
        "rule_name": "Synthetic test alert",
        "severity": "high",
        "description": "Synthetic alert fixture.",
        "event_timestamp": "2026-10-14T10:00:00Z",
        "source_ip": "192.0.2.45",
        "sources": ["synthetic_test"],
        "supporting_event_refs": [event_id],
        "evidence": {"count": 1},
    }
    repository.save_alert(alert)
    app = create_app(
        repository=repository,
        token_hashes={token_digest(token): _grant(role) for role, token in tokens.items()},
        cors_origins=["http://localhost:5173"],
        revocation_ledger=_test_ledger(tmp_path / "api-test-revocations.jsonl"),
    )
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client, repository, tokens, event_id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_is_public_and_reports_service_status(api):
    client, _, _, _ = api
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_reader_can_list_and_read_alerts_with_pagination(api):
    client, _, tokens, _ = api
    response = client.get(
        "/api/v1/alerts?severity=high&limit=1&offset=0",
        headers=_auth(tokens["reader"]),
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["alert_id"] == "test-alert-001"
    detail = client.get(
        "/api/v1/alerts/test-alert-001", headers=_auth(tokens["reader"])
    )
    assert detail.status_code == 200
    assert detail.json()["supporting_event_refs"]


def test_events_are_filtered_and_require_analyst_role(api):
    client, _, tokens, event_id = api
    denied = client.get("/api/v1/events", headers=_auth(tokens["reader"]))
    assert denied.status_code == 403
    response = client.get(
        "/api/v1/events?event_type=authentication_failure&source_ip=192.0.2.45",
        headers=_auth(tokens["analyst"]),
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["event_id"] == event_id
    detail = client.get(f"/api/v1/events/{event_id}", headers=_auth(tokens["admin"]))
    assert detail.status_code == 200
    assert detail.json()["details"]["synthetic"] is True


def test_incident_create_read_update_and_role_restricted_transitions(api):
    client, _, tokens, event_id = api
    created = client.post(
        "/api/v1/incidents",
        headers=_auth(tokens["analyst"]),
        json={
            "title": "Synthetic investigation",
            "description": "Local API fixture.",
            "severity": "high",
            "alert_ids": ["test-alert-001"],
            "supporting_event_refs": [event_id],
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]
    assert created.json()["status"] == "open"

    listed = client.get("/api/v1/incidents?status=open", headers=_auth(tokens["analyst"]))
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    read = client.get(
        f"/api/v1/incidents/{incident_id}", headers=_auth(tokens["analyst"])
    )
    assert read.status_code == 200

    updated = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=_auth(tokens["analyst"]),
        json={"description": "Updated synthetic notes."},
    )
    assert updated.status_code == 200
    assert updated.json()["description"] == "Updated synthetic notes."

    investigating = client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        headers=_auth(tokens["analyst"]),
        json={"status": "investigating"},
    )
    assert investigating.status_code == 200
    resolved = client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        headers=_auth(tokens["analyst"]),
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["resolved_at"] is not None

    analyst_close = client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        headers=_auth(tokens["analyst"]),
        json={"status": "closed"},
    )
    assert analyst_close.status_code == 403
    admin_close = client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        headers=_auth(tokens["admin"]),
        json={"status": "closed"},
    )
    assert admin_close.status_code == 200
    assert admin_close.json()["closed_at"] is not None


def test_request_validation_is_strict_and_does_not_echo_payload(api):
    client, _, tokens, _ = api
    invalid = client.post(
        "/api/v1/incidents",
        headers=_auth(tokens["analyst"]),
        json={"title": 27, "private_note": "never-echo-this-value"},
    )
    assert invalid.status_code == 422
    assert invalid.json() == {"detail": "Request validation failed."}
    assert "never-echo-this-value" not in invalid.text

    query_error = client.get(
        "/api/v1/alerts?limit=101", headers=_auth(tokens["reader"])
    )
    assert query_error.status_code == 422


def test_missing_and_invalid_bearer_tokens_are_rejected(api):
    client, _, _, _ = api
    missing = client.get("/api/v1/alerts")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    invalid = client.get(
        "/api/v1/alerts", headers={"Authorization": "Bearer invalid-test-token"}
    )
    assert invalid.status_code == 401


def test_reader_cannot_create_or_update_incidents(api):
    client, _, tokens, _ = api
    denied_create = client.post(
        "/api/v1/incidents",
        headers=_auth(tokens["reader"]),
        json={"title": "Should be denied"},
    )
    assert denied_create.status_code == 403
    created = client.post(
        "/api/v1/incidents",
        headers=_auth(tokens["analyst"]),
        json={"title": "Analyst-created fixture"},
    )
    assert created.status_code == 201
    denied_update = client.patch(
        f"/api/v1/incidents/{created.json()['incident_id']}",
        headers=_auth(tokens["reader"]),
        json={"title": "Reader must not update this"},
    )
    assert denied_update.status_code == 403


def test_database_errors_return_a_safe_service_unavailable(api, monkeypatch):
    client, repository, tokens, _ = api

    def fail_list(**kwargs):
        raise StorageError("private database path /do/not/expose.sqlite3")

    monkeypatch.setattr(repository, "list_events", fail_list)
    response = client.get("/api/v1/events", headers=_auth(tokens["analyst"]))
    assert response.status_code == 503
    assert response.json() == {"detail": "The local data store is unavailable."}
    assert "/do/not/expose.sqlite3" not in response.text


def test_cors_is_explicit_and_never_uses_credentials(api):
    client, _, _, _ = api
    response = client.options(
        "/api/v1/alerts",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://dashboard.example.test",
        "http://localhost.attacker.test:4173",
        "http://127.0.0.1:8000/path",
        "not-an-origin",
    ],
)
def test_cors_rejects_wildcard_non_loopback_and_malformed_origins(origin):
    with pytest.raises(ValueError, match="CORS origins"):
        create_app(token_hashes={}, cors_origins=[origin])


def test_wildcard_cors_origin_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Wildcard"):
        create_app(database_path=tmp_path / "cors.sqlite3", cors_origins=["*"])


def test_audit_logs_do_not_include_bearer_token_or_incident_body(api, caplog):
    client, _, tokens, _ = api
    caplog.set_level(logging.INFO, logger="soc.api.audit")
    private_description = "sensitive-synthetic-description"
    response = client.post(
        "/api/v1/incidents",
        headers=_auth(tokens["analyst"]),
        json={"title": "Synthetic", "description": private_description},
    )
    assert response.status_code == 201
    assert tokens["analyst"] not in caplog.text
    assert private_description not in caplog.text
    assert "action=incident.create" in caplog.text
