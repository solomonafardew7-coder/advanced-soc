"""Persistent audit history and append-only incident note API checks."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timezone

import pytest
from asgi_test_client import ASGITestClient as TestClient

from backend.app.api.auth import token_digest
from backend.app.database import SQLiteRepository
from backend.app.main import create_app
from backend.app.security import HmacRevocationLedger


def _ledger(path):
    ledger = HmacRevocationLedger(path, bytes.fromhex("c2" * 32))
    if path.exists():
        ledger.verify()
    else:
        ledger.initialize()
    return ledger


def _grant(role: str) -> dict[str, str]:
    return {
        "role": role,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _app(repository, tmp_path, admin_token):
    return create_app(
        repository=repository,
        token_hashes={token_digest(admin_token): _grant("admin")},
        cors_origins=["http://127.0.0.1:4173"],
        revocation_ledger=_ledger(tmp_path / "audit-notes-revocations.jsonl"),
    )


def test_incident_notes_and_audit_are_role_protected_and_append_only(tmp_path):
    database_path = tmp_path / "notes.sqlite3"
    repository = SQLiteRepository(database_path)
    repository.initialize()
    admin_token = secrets.token_urlsafe(32)
    analyst_token = secrets.token_urlsafe(32)
    reader_token = secrets.token_urlsafe(32)
    app = create_app(
        repository=repository,
        token_hashes={
            token_digest(admin_token): _grant("admin"),
            token_digest(analyst_token): _grant("analyst"),
            token_digest(reader_token): _grant("reader"),
        },
        revocation_ledger=_ledger(tmp_path / "role-revocations.jsonl"),
    )

    with TestClient(app, base_url="http://127.0.0.1") as client:
        created = client.post(
            "/api/v1/incidents",
            headers=_auth(analyst_token),
            json={"title": "Synthetic note workflow"},
        )
        assert created.status_code == 201
        incident_id = created.json()["incident_id"]

        assert client.get(f"/api/v1/incidents/{incident_id}/notes").status_code == 401
        assert client.get(
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(reader_token),
        ).status_code == 403
        assert client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(reader_token),
            json={"note_text": "reader must not append"},
        ).status_code == 403

        invalid = client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(analyst_token),
            json={"note_text": "   "},
        )
        assert invalid.status_code == 422
        assert "   " not in invalid.text

        created_note = client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(analyst_token),
            json={"note_text": "Reviewed synthetic authentication events."},
        )
        assert created_note.status_code == 201
        note = created_note.json()
        assert note["incident_id"] == incident_id
        assert note["note_text"] == "Reviewed synthetic authentication events."
        assert note["author_role"] == "analyst"
        assert note["author_type"] == "configured_token"
        assert note["author_user_id"] is None

        listing = client.get(
            f"/api/v1/incidents/{incident_id}/notes?limit=10",
            headers=_auth(analyst_token),
        )
        assert listing.status_code == 200
        assert listing.json()["total"] == 1
        assert listing.json()["items"][0]["note_id"] == note["note_id"]

        transition = client.post(
            f"/api/v1/incidents/{incident_id}/transitions",
            headers=_auth(analyst_token),
            json={"status": "investigating"},
        )
        assert transition.status_code == 200

        # There are deliberately no note edit/delete or audit write routes.
        assert client.patch(
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(analyst_token),
            json={"note_text": "replacement"},
        ).status_code == 405
        audit_reader = client.get(
            "/api/v1/admin/audit-events", headers=_auth(analyst_token)
        )
        assert audit_reader.status_code == 403
        audit_admin = client.get(
            "/api/v1/admin/audit-events?resource_type=incident",
            headers=_auth(admin_token),
        )
        assert audit_admin.status_code == 200
        audit_items = audit_admin.json()["items"]
        create_event = next(item for item in audit_items if item["action"] == "incident.create")
        assert create_event["actor_role"] == "analyst"
        assert create_event["actor_type"] == "configured_token"
        assert create_event["resource_id"] == incident_id
        assert "Synthetic note workflow" not in str(create_event["changes"])
        denied_events = client.get(
            "/api/v1/admin/audit-events?action=authorization.denied",
            headers=_auth(admin_token),
        )
        assert denied_events.status_code == 200
        assert any(item["actor_role"] == "reader" for item in denied_events.json()["items"])
        transition_event = next(
            item
            for item in audit_items
            if item["action"] == "incident.transition.investigating"
        )
        assert transition_event["changes"]["status"] == {
            "from": "open",
            "to": "investigating",
        }

        audit_delete = client.request(
            "DELETE", "/api/v1/admin/audit-events", headers=_auth(admin_token)
        )
        assert audit_delete.status_code == 405
        audit_patch = client.patch(
            "/api/v1/admin/audit-events",
            headers=_auth(admin_token),
            json={"action": "changed"},
        )
        assert audit_patch.status_code == 405
        note_delete = client.request(
            "DELETE",
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(analyst_token),
        )
        assert note_delete.status_code == 405

    # SQLite triggers reject ordinary row mutations too. This is not protection
    # against an operator who can replace the database or remove its triggers.
    connection = sqlite3.connect(database_path)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE audit_events SET action = 'changed'")
    connection.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM audit_events")
    connection.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE incident_notes SET note_text = 'changed'")
    connection.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM incident_notes")
    connection.rollback()
    connection.close()

    reopened = SQLiteRepository(database_path)
    notes, note_count = reopened.list_incident_notes(incident_id)
    audit_events, audit_count = reopened.list_audit_events(resource_type="incident")
    assert note_count == 1
    assert notes[0]["note_text"] == "Reviewed synthetic authentication events."
    assert audit_count == 2
    assert {event["action"] for event in audit_events} == {
        "incident.create",
        "incident.transition.investigating",
    }


def test_account_actor_and_audit_history_persist_across_application_restart(tmp_path):
    database_path = tmp_path / "restart.sqlite3"
    admin_token = secrets.token_urlsafe(32)
    repository = SQLiteRepository(database_path)
    repository.initialize()
    app = _app(repository, tmp_path, admin_token)
    analyst = app.state.account_service.create_user(
        username="investigator.one",
        password="synthetic-test-password-1",
        role="analyst",
    )

    with TestClient(app, base_url="http://127.0.0.1") as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "investigator.one", "password": "synthetic-test-password-1"},
        )
        assert login.status_code == 200
        analyst_token = login.json()["access_token"]
        created = client.post(
            "/api/v1/incidents",
            headers=_auth(analyst_token),
            json={"title": "Persistent synthetic investigation"},
        )
        assert created.status_code == 201
        incident_id = created.json()["incident_id"]
        note = client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            headers=_auth(analyst_token),
            json={"note_text": "Follow-up persisted across restart."},
        )
        assert note.status_code == 201
        assert note.json()["author_user_id"] == analyst["user_id"]

    reopened = SQLiteRepository(database_path)
    restarted_app = _app(reopened, tmp_path, admin_token)
    with TestClient(restarted_app, base_url="http://127.0.0.1") as client:
        notes_response = client.get(
            f"/api/v1/incidents/{incident_id}/notes", headers=_auth(analyst_token)
        )
        assert notes_response.status_code == 200
        assert notes_response.json()["items"][0]["note_text"] == "Follow-up persisted across restart."

        audit_response = client.get(
            "/api/v1/admin/audit-events?limit=100", headers=_auth(admin_token)
        )
        assert audit_response.status_code == 200
        rows = audit_response.json()["items"]
        login_event = next(row for row in rows if row["action"] == "auth.login")
        note_event = next(row for row in rows if row["action"] == "incident.note.append")
        assert login_event["actor_user_id"] == analyst["user_id"]
        assert login_event["actor_username"] == "investigator.one"
        assert note_event["actor_user_id"] == analyst["user_id"]
        assert note_event["actor_username"] == "investigator.one"
        assert note_event["resource_id"] == note.json()["note_id"]
        assert "Follow-up persisted across restart." not in str(note_event["changes"])
        assert "synthetic-test-password-1" not in str(rows)
        assert analyst_token not in str(rows)
