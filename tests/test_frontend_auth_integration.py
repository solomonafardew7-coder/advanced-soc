"""Integration contract between browser sign-in and the real local auth API."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asgi_test_client import ASGITestClient

from backend.app.api.auth import token_digest
from backend.app.database import SQLiteRepository
from backend.app.main import create_app
from backend.app.security import HmacRevocationLedger


def _make_app(tmp_path: Path, *, ttl: int = 3600):
    repository = SQLiteRepository(tmp_path / "frontend-auth.sqlite3")
    bootstrap_token = secrets.token_urlsafe(32)
    issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ledger = HmacRevocationLedger(
        tmp_path / "frontend-auth-revocations.jsonl", bytes.fromhex("c3" * 32)
    )
    ledger.initialize()
    app = create_app(
        repository=repository,
        token_hashes={
            token_digest(bootstrap_token): {
                "role": "admin",
                "issued_at": issued_at,
            }
        },
        token_ttl_seconds=ttl,
        cors_origins=[],
        revocation_ledger=ledger,
    )
    return app, repository, bootstrap_token


def _request(app, method: str, path: str, *, token: str | None = None, body=None):
    options = {}
    if token is not None:
        options["headers"] = {"Authorization": f"Bearer {token}"}
    if body is not None:
        options["json"] = body
    with ASGITestClient(app) as client:
        return client.request(method, path, **options)


def _create_user(app, admin_token: str, username: str, role: str):
    return _request(
        app,
        "POST",
        "/api/v1/admin/users",
        token=admin_token,
        body={"username": username, "password": "synthetic-password-123", "role": role},
    )


def _login(app, username: str, password: str = "synthetic-password-123"):
    return _request(
        app,
        "POST",
        "/api/v1/auth/login",
        body={"username": username, "password": password},
    )


def test_dashboard_login_role_permissions_logout_and_invalid_credentials(tmp_path):
    app, _, bootstrap_admin = _make_app(tmp_path)
    assert _create_user(app, bootstrap_admin, "reader.one", "reader").status_code == 201
    assert _create_user(app, bootstrap_admin, "analyst.one", "analyst").status_code == 201
    assert _create_user(app, bootstrap_admin, "admin.one", "admin").status_code == 201
    assert _request(app, "GET", "/api/v1/alerts").status_code == 401
    assert _request(app, "GET", "/api/v1/events", token=bootstrap_admin).status_code == 200

    bad_login = _login(app, "reader.one", "wrong-synthetic-password")
    assert bad_login.status_code == 401
    assert bad_login.json() == {"detail": "Invalid username or password."}
    assert "wrong-synthetic-password" not in bad_login.text

    reader_login = _login(app, "reader.one")
    assert reader_login.status_code == 200
    assert reader_login.headers["cache-control"] == "no-store"
    reader_token = reader_login.json()["access_token"]
    assert _request(app, "GET", "/api/v1/alerts", token=reader_token).status_code == 200
    assert _request(app, "GET", "/api/v1/events", token=reader_token).status_code == 403

    analyst_login = _login(app, "analyst.one")
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["access_token"]
    assert _request(app, "GET", "/api/v1/events", token=analyst_token).status_code == 200
    forbidden_admin = _request(
        app,
        "POST",
        "/api/v1/admin/users",
        token=analyst_token,
        body={"username": "blocked.admin", "password": "synthetic-password-456", "role": "admin"},
    )
    assert forbidden_admin.status_code == 403

    admin_login = _login(app, "admin.one")
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]
    assert _request(app, "GET", "/api/v1/events", token=admin_token).status_code == 200
    assert _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        token=admin_token,
        body={"role": "reader", "expires_in_seconds": 60},
    ).status_code == 201

    logout = _request(app, "POST", "/api/v1/auth/logout", token=reader_token, body={})
    assert logout.status_code == 200
    assert logout.json() == {"status": "revoked"}
    assert _request(app, "GET", "/api/v1/alerts", token=reader_token).status_code == 401


def test_dashboard_bearer_is_rejected_after_its_expiration(tmp_path):
    app, _, bootstrap_admin = _make_app(tmp_path, ttl=3600)
    assert _create_user(app, bootstrap_admin, "reader.one", "reader").status_code == 201
    login = _login(app, "reader.one")
    assert login.status_code == 200
    token = login.json()["access_token"]

    expired = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    issued = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(app.state.repository.database_path) as connection:
        connection.execute(
            "UPDATE api_tokens SET issued_at = ?, expires_at = ? WHERE token_hash = ?",
            (issued, expired, token_digest(token)),
        )

    rejected = _request(app, "GET", "/api/v1/alerts", token=token)
    assert rejected.status_code == 401


def test_frontend_auth_contract_uses_existing_routes_and_memory_only_credentials():
    root = Path(__file__).resolve().parents[1]
    api = (root / "frontend/js/api.js").read_text(encoding="utf-8")
    app_js = (root / "frontend/js/app.js").read_text(encoding="utf-8")
    all_js = "\n".join(path.read_text(encoding="utf-8") for path in (root / "frontend/js").glob("*.js"))
    routes = create_app().openapi()["paths"]

    assert "/api/v1/auth/login" in routes
    assert "/api/v1/auth/logout" in routes
    assert 'login: "/api/v1/auth/login"' in api
    assert 'logout: "/api/v1/auth/logout"' in api
    assert "credentials: \"omit\"" in api
    assert "cache: \"no-store\"" in api
    assert "localStorage" not in all_js and "sessionStorage" not in all_js
    assert "document.cookie" not in all_js
    assert "await current.logout()" in app_js
    assert "Your session is no longer valid. Sign in again." in api


def test_dashboard_investigation_notes_and_admin_audit_use_real_paginated_api(tmp_path):
    app, _, admin_token = _make_app(tmp_path)
    assert _create_user(app, admin_token, "analyst.notes", "analyst").status_code == 201
    assert _create_user(app, admin_token, "reader.notes", "reader").status_code == 201
    analyst_token = _login(app, "analyst.notes").json()["access_token"]
    reader_token = _login(app, "reader.notes").json()["access_token"]

    incident = _request(
        app,
        "POST",
        "/api/v1/incidents",
        token=analyst_token,
        body={"title": "Synthetic dashboard investigation"},
    )
    assert incident.status_code == 201
    incident_id = incident.json()["incident_id"]
    note_texts = ["First synthetic review", "Second synthetic review"]
    notes = []
    for note_text in note_texts:
        response = _request(
            app,
            "POST",
            f"/api/v1/incidents/{incident_id}/notes",
            token=analyst_token,
            body={"note_text": note_text},
        )
        assert response.status_code == 201
        notes.append(response.json())

    first_page = _request(
        app,
        "GET",
        f"/api/v1/incidents/{incident_id}/notes?limit=1&offset=0",
        token=analyst_token,
    )
    second_page = _request(
        app,
        "GET",
        f"/api/v1/incidents/{incident_id}/notes?limit=1&offset=1",
        token=analyst_token,
    )
    assert first_page.status_code == second_page.status_code == 200
    assert first_page.json()["items"][0]["note_text"] == note_texts[0]
    assert second_page.json()["items"][0]["note_text"] == note_texts[1]
    assert _request(app, "GET", f"/api/v1/incidents/{incident_id}/notes").status_code == 401
    assert _request(
        app,
        "GET",
        f"/api/v1/incidents/{incident_id}/notes",
        token=reader_token,
    ).status_code == 403
    assert _request(
        app,
        "POST",
        f"/api/v1/incidents/{incident_id}/notes",
        token=reader_token,
        body={"note_text": "Reader cannot append"},
    ).status_code == 403

    audit_path = "/api/v1/admin/audit-events?action=incident.note.append&resource_type=incident_note"
    audit_first = _request(app, "GET", f"{audit_path}&limit=1&offset=0", token=admin_token)
    audit_second = _request(app, "GET", f"{audit_path}&limit=1&offset=1", token=admin_token)
    assert audit_first.status_code == audit_second.status_code == 200
    assert audit_first.json()["total"] == 2
    assert audit_first.json()["items"][0]["audit_event_id"] != audit_second.json()["items"][0]["audit_event_id"]
    audit_filter = _request(
        app,
        "GET",
        f"{audit_path}&resource_id={notes[0]['note_id']}",
        token=admin_token,
    )
    assert audit_filter.status_code == 200
    assert audit_filter.json()["total"] == 1
    assert _request(app, "GET", "/api/v1/admin/audit-events").status_code == 401
    assert _request(
        app,
        "GET",
        "/api/v1/admin/audit-events",
        token=analyst_token,
    ).status_code == 403
