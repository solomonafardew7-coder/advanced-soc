"""Password accounts retain the existing bearer-token security model."""

from __future__ import annotations

import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asgi_test_client import ASGITestClient
from pwdlib import PasswordHash

from backend.app.api.auth import disabled_user_marker_hash, token_digest
from backend.app.database import SQLiteRepository
from backend.app.main import create_app
from backend.app.security import HmacRevocationLedger


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _request(app, method: str, path: str, *, token: str | None = None, body=None):
    options = {}
    if token is not None:
        options["headers"] = _headers(token)
    if body is not None:
        options["json"] = body
    with ASGITestClient(app) as client:
        return client.request(method, path, **options)


def _app(tmp_path: Path, *, ttl: int = 3600):
    database = tmp_path / "accounts.sqlite3"
    repository = SQLiteRepository(database)
    admin_token = secrets.token_urlsafe(32)
    issued = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ledger = HmacRevocationLedger(
        tmp_path / "accounts.revocations.jsonl", bytes.fromhex("b2" * 32)
    )
    ledger.initialize()
    app = create_app(
        repository=repository,
        token_hashes={token_digest(admin_token): {"role": "admin", "issued_at": issued}},
        token_ttl_seconds=ttl,
        cors_origins=[],
        revocation_ledger=ledger,
    )
    return app, repository, ledger, admin_token, database


def _create_account(app, admin_token: str, *, username="analyst.one", password="synthetic-password-12", role="analyst"):
    return _request(
        app,
        "POST",
        "/api/v1/admin/users",
        token=admin_token,
        body={"username": username, "password": password, "role": role},
    )


def _login(app, username: str, password: str):
    return _request(
        app,
        "POST",
        "/api/v1/auth/login",
        body={"username": username, "password": password},
    )


def test_account_login_uses_argon2_and_returns_no_password_material(tmp_path, caplog):
    app, repository, _, admin_token, database = _app(tmp_path)
    password = "synthetic-password-12"
    created = _create_account(app, admin_token, password=password)
    assert created.status_code == 201
    assert created.json()["username"] == "analyst.one"
    assert "password" not in created.json()
    assert password not in created.text

    user = repository.get_api_user_by_username("analyst.one")
    assert user is not None
    stored_hash = user["password_hash"]
    assert stored_hash.startswith("$argon2id$")
    password_hash = PasswordHash.recommended()
    assert password_hash.verify(password, stored_hash)
    assert not password_hash.verify("wrong-password", stored_hash)
    assert password.encode() not in database.read_bytes()

    caplog.set_level(logging.INFO, logger="soc.api.audit")
    logged_in = _login(app, "ANALYST.ONE", password)
    assert logged_in.status_code == 200
    assert logged_in.headers["cache-control"] == "no-store"
    assert logged_in.headers["pragma"] == "no-cache"
    payload = logged_in.json()
    assert payload["role"] == "analyst"
    assert payload["token_hash"] == token_digest(payload["access_token"])
    assert password not in logged_in.text
    assert password not in caplog.text
    assert payload["access_token"] not in caplog.text
    assert payload["token_hash"] not in caplog.text

    access = _request(app, "GET", "/api/v1/events", token=payload["access_token"])
    assert access.status_code == 200


def test_login_failures_are_generic_and_do_not_echo_credentials(tmp_path, caplog):
    app, _, _, admin_token, _ = _app(tmp_path)
    password = "synthetic-password-12"
    assert _create_account(app, admin_token, password=password).status_code == 201

    wrong_password = _login(app, "analyst.one", "private-wrong-password")
    missing_username = _login(app, "not-a-user", "private-wrong-password")
    assert wrong_password.status_code == missing_username.status_code == 401
    assert wrong_password.json() == missing_username.json() == {
        "detail": "Invalid username or password."
    }
    assert "private-wrong-password" not in wrong_password.text
    assert "private-wrong-password" not in missing_username.text
    assert "private-wrong-password" not in caplog.text


def test_analyst_cannot_create_accounts_or_issue_privileged_credentials(tmp_path):
    app, _, _, admin_token, _ = _app(tmp_path)
    assert _create_account(app, admin_token).status_code == 201
    analyst_token = _login(app, "analyst.one", "synthetic-password-12").json()["access_token"]

    create_admin = _request(
        app,
        "POST",
        "/api/v1/admin/users",
        token=analyst_token,
        body={"username": "attempted.admin", "password": "another-synthetic-pass", "role": "admin"},
    )
    issue_admin = _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        token=analyst_token,
        body={"role": "admin"},
    )
    assert create_admin.status_code == issue_admin.status_code == 403
    assert create_admin.json() == issue_admin.json() == {"detail": "Insufficient permissions."}


def test_admin_can_create_another_admin_and_duplicate_username_is_rejected(tmp_path):
    app, repository, _, admin_token, _ = _app(tmp_path)
    created = _create_account(
        app,
        admin_token,
        username="second.admin",
        password="another-synthetic-pass",
        role="admin",
    )
    assert created.status_code == 201
    account_admin_token = _login(
        app, "second.admin", "another-synthetic-pass"
    ).json()["access_token"]
    assert _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        token=account_admin_token,
        body={"role": "reader", "expires_in_seconds": 60},
    ).status_code == 201

    duplicate = _create_account(
        app,
        admin_token,
        username="SECOND.ADMIN",
        password="different-synthetic-pass",
        role="reader",
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Record conflict."}
    assert repository.get_api_user_by_username("second.admin")["role"] == "admin"


def test_admin_cannot_disable_self_or_last_account_administrator(tmp_path):
    app, repository, _, bootstrap_admin, _ = _app(tmp_path)
    assert _create_account(
        app,
        bootstrap_admin,
        username="only.admin",
        password="only-admin-password-123",
        role="admin",
    ).status_code == 201
    account = repository.get_api_user_by_username("only.admin")
    account_token = _login(
        app, "only.admin", "only-admin-password-123"
    ).json()["access_token"]

    self_disable = _request(
        app,
        "POST",
        f"/api/v1/admin/users/{account['user_id']}/disable",
        token=account_token,
        body={},
    )
    last_admin_disable = _request(
        app,
        "POST",
        f"/api/v1/admin/users/{account['user_id']}/disable",
        token=bootstrap_admin,
        body={},
    )
    assert self_disable.status_code == last_admin_disable.status_code == 409
    assert repository.get_api_user_by_id(account["user_id"])["is_active"] is True


def test_disabling_account_revokes_existing_tokens_and_blocks_future_login(tmp_path):
    app, repository, ledger, admin_token, _ = _app(tmp_path)
    assert _create_account(app, admin_token).status_code == 201
    account = repository.get_api_user_by_username("analyst.one")
    user_id = account["user_id"]
    bearer = _login(app, "analyst.one", "synthetic-password-12").json()["access_token"]
    digest = token_digest(bearer)

    disabled = _request(
        app,
        "POST",
        f"/api/v1/admin/users/{user_id}/disable",
        token=admin_token,
        body={},
    )
    assert disabled.status_code == 200
    assert disabled.json() == {"status": "disabled"}
    assert repository.get_api_user_by_id(user_id)["is_active"] is False
    assert repository.is_api_token_revoked(digest)
    assert ledger.is_revoked(digest)
    assert ledger.is_revoked(disabled_user_marker_hash(user_id))

    rejected_session = _request(app, "GET", "/api/v1/events", token=bearer)
    rejected_login = _login(app, "analyst.one", "synthetic-password-12")
    assert rejected_session.status_code == rejected_login.status_code == 401
    assert rejected_login.json() == {"detail": "Invalid username or password."}


def test_disabling_admin_revokes_tokens_the_account_issued(tmp_path):
    app, repository, ledger, bootstrap_admin, _ = _app(tmp_path)
    assert _create_account(
        app,
        bootstrap_admin,
        username="operator.one",
        password="operator-password-123",
        role="admin",
    ).status_code == 201
    assert _create_account(
        app,
        bootstrap_admin,
        username="operator.two",
        password="second-operator-password",
        role="admin",
    ).status_code == 201
    issuer_token = _login(
        app, "operator.one", "operator-password-123"
    ).json()["access_token"]
    other_admin = _login(
        app, "operator.two", "second-operator-password"
    ).json()["access_token"]
    issued = _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        token=issuer_token,
        body={"role": "admin", "expires_in_seconds": 3600},
    )
    assert issued.status_code == 201
    delegated_admin = issued.json()["access_token"]
    delegated_admin_hash = issued.json()["token_hash"]
    issuer_id = repository.get_api_user_by_username("operator.one")["user_id"]
    with sqlite3.connect(repository.database_path) as connection:
        issuer_row = connection.execute(
            "SELECT issued_by_user_id FROM api_tokens WHERE token_hash = ?",
            (delegated_admin_hash,),
        ).fetchone()
    assert issuer_row[0] == issuer_id
    second_generation = _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        token=delegated_admin,
        body={"role": "reader", "expires_in_seconds": 3600},
    )
    assert second_generation.status_code == 201
    delegated_reader = second_generation.json()["access_token"]
    delegated_reader_hash = second_generation.json()["token_hash"]
    assert _request(app, "GET", "/api/v1/alerts", token=delegated_reader).status_code == 200

    disabled = _request(
        app,
        "POST",
        f"/api/v1/admin/users/{issuer_id}/disable",
        token=other_admin,
        body={},
    )
    assert disabled.status_code == 200
    for digest in (delegated_admin_hash, delegated_reader_hash):
        assert ledger.is_revoked(digest)
        assert repository.is_api_token_revoked(digest)
    assert _request(app, "GET", "/api/v1/alerts", token=delegated_admin).status_code == 401
    assert _request(app, "GET", "/api/v1/alerts", token=delegated_reader).status_code == 401


def test_revocation_journal_failure_rolls_back_account_disablement(tmp_path, monkeypatch):
    from backend.app.security import RevocationStateError

    app, repository, ledger, admin_token, _ = _app(tmp_path)
    assert _create_account(app, admin_token).status_code == 201
    target = repository.get_api_user_by_username("analyst.one")

    def fail_revoke(_digest):
        raise RevocationStateError("journal unavailable")

    monkeypatch.setattr(ledger, "revoke", fail_revoke)
    response = _request(
        app,
        "POST",
        f"/api/v1/admin/users/{target['user_id']}/disable",
        token=admin_token,
        body={},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "Trusted token revocation state is unavailable."}
    assert repository.get_api_user_by_id(target["user_id"])["is_active"] is True


def test_logout_revokes_account_token_using_existing_journal(tmp_path):
    app, repository, ledger, admin_token, _ = _app(tmp_path)
    assert _create_account(app, admin_token).status_code == 201
    bearer = _login(app, "analyst.one", "synthetic-password-12").json()["access_token"]
    digest = token_digest(bearer)

    logout = _request(app, "POST", "/api/v1/auth/logout", token=bearer)
    assert logout.status_code == 200
    assert logout.json() == {"status": "revoked"}
    assert ledger.is_revoked(digest)
    assert repository.is_api_token_revoked(digest)
    assert _request(app, "GET", "/api/v1/events", token=bearer).status_code == 401


def test_login_token_expiry_is_checked_on_every_request(tmp_path):
    app, repository, _, admin_token, database = _app(tmp_path, ttl=1)
    assert _create_account(app, admin_token).status_code == 201
    login = _login(app, "analyst.one", "synthetic-password-12")
    bearer = login.json()["access_token"]
    issued = datetime.fromisoformat(login.json()["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(login.json()["expires_at"].replace("Z", "+00:00"))
    assert (expires - issued).total_seconds() == 1

    # Force the stored expiry into the past so the test is deterministic and
    # does not depend on scheduler timing around a one-second sleep.
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE api_tokens SET issued_at = ?, expires_at = ? WHERE token_hash = ?",
            (
                (datetime.now(timezone.utc) - timedelta(seconds=10))
                .isoformat()
                .replace("+00:00", "Z"),
                (datetime.now(timezone.utc) - timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
                token_digest(bearer),
            ),
        )
    assert repository.get_api_token(token_digest(bearer)) is not None
    assert _request(app, "GET", "/api/v1/events", token=bearer).status_code == 401


def test_existing_database_token_survives_additive_account_schema_migration(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    legacy_bearer = secrets.token_urlsafe(32)
    digest = token_digest(legacy_bearer)
    now = datetime.now(timezone.utc)
    issued = now.isoformat().replace("+00:00", "Z")
    expires = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(database) as connection:
        connection.execute(
            """CREATE TABLE api_tokens (
                token_hash TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO api_tokens(token_hash, role, issued_at, expires_at) VALUES (?, ?, ?, ?)",
            (digest, "analyst", issued, expires),
        )

    repository = SQLiteRepository(database)
    repository.initialize()
    grant = repository.get_api_token(digest)
    assert grant == {"role": "analyst", "issued_at": issued, "expires_at": expires}
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(api_tokens)")}
    assert {"revoked_at", "user_id", "issued_by_user_id"} <= columns

    ledger_path = tmp_path / "legacy.revocations.jsonl"
    ledger = HmacRevocationLedger(ledger_path, bytes.fromhex("c3" * 32))
    ledger.initialize()
    app = create_app(
        repository=repository,
        token_hashes={},
        cors_origins=[],
        revocation_ledger=ledger,
    )
    response = _request(app, "GET", "/api/v1/events", token=legacy_bearer)
    assert response.status_code == 200


def test_legacy_static_token_grants_remain_compatible(tmp_path):
    app, _, _, admin_token, _ = _app(tmp_path)
    assert _request(app, "GET", "/api/v1/alerts", token=admin_token).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"username": "x", "password": "short", "role": "admin"},
        {"username": "bad user", "password": "synthetic-password-12", "role": "analyst"},
        {"username": "valid.user", "password": "synthetic-password-12", "role": "root"},
    ],
)
def test_account_creation_validates_fields_without_echoing_input(tmp_path, body):
    app, _, _, admin_token, _ = _app(tmp_path)
    response = _request(app, "POST", "/api/v1/admin/users", token=admin_token, body=body)
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed."}
    assert "synthetic-password-12" not in response.text


def test_account_token_malformed_user_link_fails_closed(tmp_path):
    database = tmp_path / "malformed-link.sqlite3"
    repository = SQLiteRepository(database)
    with sqlite3.connect(database) as connection:
        # Simulate a pre-account token table; migration adds a nullable link.
        connection.execute(
            """CREATE TABLE api_tokens (
                token_hash TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            )"""
        )
    repository.initialize()
    bearer = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO api_tokens(token_hash, role, issued_at, expires_at, user_id) VALUES (?, ?, ?, ?, ?)",
            (
                token_digest(bearer),
                "analyst",
                now.isoformat().replace("+00:00", "Z"),
                (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "not-a-user-id",
            ),
        )
    ledger = HmacRevocationLedger(
        tmp_path / "malformed-link.revocations.jsonl", bytes.fromhex("d4" * 32)
    )
    ledger.initialize()
    app = create_app(
        repository=repository,
        token_hashes={},
        cors_origins=[],
        revocation_ledger=ledger,
    )
    response = _request(app, "GET", "/api/v1/events", token=bearer)
    assert response.status_code == 503
    assert response.json() == {"detail": "Token revocation storage is unavailable."}
