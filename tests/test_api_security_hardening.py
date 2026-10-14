"""Expiration, revocation, and local-bind checks use disposable credentials."""

from __future__ import annotations

import logging
import json
import secrets
import sqlite3
import socket
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asgi_test_client import ASGITestClient

from backend.app.api.auth import (
    DEFAULT_TOKEN_TTL_SECONDS,
    MAX_TOKEN_TTL_SECONDS,
    parse_token_ttl_seconds,
    token_digest,
)
from backend.app.database import SQLiteRepository, event_reference
from backend.app.database.sqlite_repository import StorageError
from backend.app.main import create_app, is_loopback_bind_host
from backend.app.security import HmacRevocationLedger, RevocationStateError
from scripts.run_api import configured_port, main as run_api_main, validate_bind_host


def _grant(role: str, *, issued_at: datetime | None = None) -> dict[str, str]:
    issued_at = issued_at or datetime.now(timezone.utc)
    return {
        "role": role,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _request(
    app,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, str] | None = None,
    base_url: str = "http://127.0.0.1",
):
    """Call the ASGI app directly with its lifespan, without opening a socket."""
    options = {}
    if headers is not None:
        options["headers"] = headers
    if body is not None:
        options["json"] = body
    with ASGITestClient(app, base_url=base_url) as client:
        return client.request(method, path, **options)


def _build_app(path, tokens, grants=None, *, ttl=DEFAULT_TOKEN_TTL_SECONDS):
    repository = SQLiteRepository(path)
    ledger_path = Path(path).with_suffix(".revocations.jsonl")
    ledger = HmacRevocationLedger(ledger_path, bytes.fromhex("a1" * 32))
    if not ledger_path.exists():
        ledger.initialize()
    return create_app(
        repository=repository,
        token_hashes=grants
        or {token_digest(token): _grant(role) for role, token in tokens.items()},
        token_ttl_seconds=ttl,
        cors_origins=[],
        revocation_ledger=ledger,
    ), repository


def test_expired_token_is_rejected_and_not_logged(tmp_path, caplog):
    token = secrets.token_urlsafe(32)
    issued_at = datetime.now(timezone.utc) - timedelta(seconds=3)
    grants = {token_digest(token): _grant("analyst", issued_at=issued_at)}
    app, _ = _build_app(
        tmp_path / "expired.sqlite3", {"analyst": token}, grants, ttl=2
    )

    caplog.set_level(logging.INFO, logger="soc.api.audit")
    response = _request(app, "GET", "/api/v1/events", headers=_headers(token))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert token not in caplog.text
    assert "outcome=expired" in caplog.text


def test_token_ttl_environment_setting_controls_expiration(tmp_path, monkeypatch):
    token = secrets.token_urlsafe(32)
    issued_at = datetime.now(timezone.utc) - timedelta(seconds=2)
    monkeypatch.setenv("SOC_API_TOKEN_TTL_SECONDS", "1")
    grants = {token_digest(token): _grant("analyst", issued_at=issued_at)}
    monkeypatch.setenv("SOC_API_TOKEN_HASHES", json.dumps(grants))
    ledger = HmacRevocationLedger(
        tmp_path / "env-expired.revocations.jsonl", bytes.fromhex("a1" * 32)
    )
    ledger.initialize()
    app = create_app(
        database_path=tmp_path / "env-expired.sqlite3",
        cors_origins=[],
        revocation_ledger=ledger,
    )
    response = _request(app, "GET", "/api/v1/events", headers=_headers(token))
    assert response.status_code == 401


@pytest.mark.parametrize(
    "value", ["0", "-1", "7776001", "1.5", "", "abc", " 60", 1.5, True]
)
def test_token_ttl_rejects_invalid_or_out_of_range_values(value):
    with pytest.raises(ValueError):
        parse_token_ttl_seconds(value)


def test_token_ttl_default_and_bounds_are_explicit():
    assert parse_token_ttl_seconds() == 12 * 60 * 60
    assert parse_token_ttl_seconds("1") == 1
    assert parse_token_ttl_seconds(str(MAX_TOKEN_TTL_SECONDS)) == MAX_TOKEN_TTL_SECONDS


@pytest.mark.parametrize(
    "grant",
    [
        "analyst",
        {"role": "analyst"},
        {"role": [], "issued_at": "2026-01-01T00:00:00Z"},
        {"role": "analyst", "issued_at": "2026-01-01T00:00:00"},
        {"role": "unknown", "issued_at": "2026-01-01T00:00:00Z"},
        {
            "role": "admin",
            "issued_at": (datetime.now(timezone.utc) + timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z"),
        },
    ],
)
def test_token_grants_require_valid_explicit_issue_metadata(grant):
    digest = "a" * 64
    with pytest.raises(ValueError):
        create_app(token_hashes={digest: grant}, cors_origins=[])


def test_token_grants_accept_bounded_token_specific_expiration():
    token = secrets.token_urlsafe(32)
    issued_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    expiration = issued_at + timedelta(minutes=1)
    grant = _grant("analyst", issued_at=issued_at)
    grant["expires_at"] = expiration.isoformat().replace("+00:00", "Z")
    parsed = create_app(
        token_hashes={token_digest(token): grant},
        token_ttl_seconds=DEFAULT_TOKEN_TTL_SECONDS,
        cors_origins=[],
    ).state.token_hashes[token_digest(token)]
    assert parsed.expires_at == expiration


@pytest.mark.parametrize(
    "expiration",
    [
        "2026-01-01T00:00:00",
        "not-a-timestamp",
        (datetime.now(timezone.utc) + timedelta(days=91))
        .isoformat()
        .replace("+00:00", "Z"),
    ],
)
def test_token_grant_rejects_malformed_or_overlong_specific_expiration(expiration):
    token = secrets.token_urlsafe(32)
    grant = _grant("analyst", issued_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    grant["expires_at"] = expiration
    with pytest.raises(ValueError):
        create_app(token_hashes={token_digest(token): grant}, cors_origins=[])


def test_database_token_expiration_is_checked_on_each_protected_request(tmp_path):
    admin = secrets.token_urlsafe(32)
    database_path = tmp_path / "expired-issued.sqlite3"
    app, repository = _build_app(database_path, {"admin": admin})
    repository.initialize()
    expired = secrets.token_urlsafe(32)
    issued_at = datetime.now(timezone.utc) - timedelta(seconds=3)
    expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    repository.create_api_token(
        token_digest(expired),
        "analyst",
        issued_at.isoformat().replace("+00:00", "Z"),
        expires_at.isoformat().replace("+00:00", "Z"),
    )

    response = _request(app, "GET", "/api/v1/events", headers=_headers(expired))
    assert response.status_code == 401


def test_token_issuance_requires_admin_and_returns_secret_once(tmp_path, caplog):
    tokens = {"admin": secrets.token_urlsafe(32), "reader": secrets.token_urlsafe(32)}
    database_path = tmp_path / "issued.sqlite3"
    app, repository = _build_app(database_path, tokens)
    path = "/api/v1/admin/tokens"
    payload = {"role": "analyst", "expires_in_seconds": 3600}

    missing = _request(app, "POST", path, body=payload)
    assert missing.status_code == 401
    forbidden = _request(
        app, "POST", path, headers=_headers(tokens["reader"]), body=payload
    )
    assert forbidden.status_code == 403

    caplog.set_level(logging.INFO, logger="soc.api.audit")
    issued = _request(
        app, "POST", path, headers=_headers(tokens["admin"]), body=payload
    )
    assert issued.status_code == 201
    assert issued.headers["cache-control"] == "no-store"
    assert issued.headers["pragma"] == "no-cache"
    result = issued.json()
    assert result["token_type"] == "bearer"
    assert result["role"] == "analyst"
    assert result["token_hash"] == token_digest(result["access_token"])
    issued_at = datetime.fromisoformat(result["issued_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
    assert (expires_at - issued_at).total_seconds() == 3600
    assert result["access_token"] not in caplog.text
    assert result["token_hash"] not in caplog.text
    assert repository.get_api_token(result["token_hash"])["role"] == "analyst"
    assert result["access_token"].encode() not in database_path.read_bytes()

    accepted = _request(
        app,
        "GET",
        "/api/v1/events",
        headers=_headers(result["access_token"]),
    )
    assert accepted.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"role": "admin", "expires_in_seconds": 0},
        {"role": "admin", "expires_in_seconds": 7_776_001},
        {"role": "root"},
        {"role": "admin", "extra": "rejected"},
    ],
)
def test_token_issue_request_rejects_invalid_values_safely(tmp_path, payload):
    admin = secrets.token_urlsafe(32)
    app, _ = _build_app(tmp_path / "invalid-issue.sqlite3", {"admin": admin})
    response = _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        headers=_headers(admin),
        body=payload,
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed."}
    assert "rejected" not in response.text


def test_token_issuance_database_failure_does_not_leak_secret_or_error(
    tmp_path, monkeypatch, caplog
):
    admin = secrets.token_urlsafe(32)
    app, repository = _build_app(tmp_path / "issue-failure.sqlite3", {"admin": admin})
    generated = "test-only-generated-token-secret"
    monkeypatch.setattr(
        "backend.app.services.token_service.secrets.token_urlsafe",
        lambda _: generated,
    )

    def fail_to_store(*args, **kwargs):
        raise StorageError(f"failed to persist private token {generated}")

    monkeypatch.setattr(repository, "create_api_token", fail_to_store)
    caplog.set_level(logging.INFO)
    response = _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        headers=_headers(admin),
        body={"role": "reader"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "The local data store is unavailable."}
    assert generated not in response.text
    assert generated not in caplog.text


def test_issued_token_revocation_survives_restart_and_rotation(tmp_path):
    admin = secrets.token_urlsafe(32)
    database_path = tmp_path / "rotation.sqlite3"
    app, repository = _build_app(database_path, {"admin": admin})
    issue_path = "/api/v1/admin/tokens"

    first = _request(
        app,
        "POST",
        issue_path,
        headers=_headers(admin),
        body={"role": "analyst"},
    ).json()
    second = _request(
        app,
        "POST",
        issue_path,
        headers=_headers(admin),
        body={"role": "analyst", "expires_in_seconds": 7200},
    ).json()
    assert first["access_token"] != second["access_token"]
    assert _request(
        app, "GET", "/api/v1/events", headers=_headers(first["access_token"])
    ).status_code == 200

    revoked = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(admin),
        body={"token_hash": first["token_hash"]},
    )
    assert revoked.status_code == 200
    reopened_app, reopened_repository = _build_app(database_path, {"admin": admin})
    assert reopened_repository.has_api_tokens()
    assert _request(
        reopened_app,
        "GET",
        "/api/v1/events",
        headers=_headers(first["access_token"]),
    ).status_code == 401
    assert _request(
        reopened_app,
        "GET",
        "/api/v1/events",
        headers=_headers(second["access_token"]),
    ).status_code == 200
    assert token_digest(first["access_token"]) in reopened_app.state.revocation_ledger.verify()


def test_token_schema_initialization_preserves_existing_data_and_revocations(tmp_path):
    database_path = tmp_path / "schema-migration.sqlite3"
    repository = SQLiteRepository(database_path)
    repository.initialize()
    event = {
        "timestamp": "2026-10-14T10:00:00Z",
        "event_type": "synthetic_migration_test",
        "source": "local_test",
        "severity": "low",
        "details": {"synthetic": True},
    }
    repository.save_event(event)
    revoked_hash = "b" * 64
    repository.revoke_api_token(revoked_hash)
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TABLE api_tokens")

    repository.initialize()

    assert repository.get_event(event_reference(event)) is not None
    assert repository.is_api_token_revoked(revoked_hash)
    assert not repository.has_api_tokens()


@pytest.mark.parametrize("malformed", ["", "not-a-token", "Bearer extra value"])
def test_malformed_bearer_credentials_are_rejected(tmp_path, malformed):
    admin = secrets.token_urlsafe(32)
    app, _ = _build_app(tmp_path / "malformed.sqlite3", {"admin": admin})
    response = _request(
        app,
        "GET",
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {malformed}"},
    )
    assert response.status_code == 401


def test_admin_can_revoke_other_token_and_revocation_survives_restart(tmp_path):
    tokens = {role: secrets.token_urlsafe(32) for role in ("reader", "analyst", "admin")}
    database_path = tmp_path / "revocation.sqlite3"
    app, repository = _build_app(database_path, tokens)
    target_digest = token_digest(tokens["analyst"])

    denied = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(tokens["reader"]),
        body={"token_hash": target_digest},
    )
    assert denied.status_code == 403

    revoked = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(tokens["admin"]),
        body={"token_hash": target_digest},
    )
    assert revoked.status_code == 200
    assert revoked.json() == {"status": "revoked"}
    assert _request(
        app, "GET", "/api/v1/alerts", headers=_headers(tokens["analyst"])
    ).status_code == 401
    # Repeated revocation requests are safe and have the same response.
    repeated = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(tokens["admin"]),
        body={"token_hash": target_digest},
    )
    assert repeated.status_code == 200

    assert repository.is_api_token_revoked(target_digest)
    reopened_app, _ = _build_app(database_path, tokens)
    assert _request(
        reopened_app, "GET", "/api/v1/alerts", headers=_headers(tokens["analyst"])
    ).status_code == 401
    assert _request(
        reopened_app, "GET", "/api/v1/alerts", headers=_headers(tokens["admin"])
    ).status_code == 200


def test_administrator_cannot_revoke_the_credential_used_for_request(tmp_path):
    admin_token = secrets.token_urlsafe(32)
    app, repository = _build_app(
        tmp_path / "self-revocation.sqlite3", {"admin": admin_token}
    )
    admin_digest = token_digest(admin_token)

    response = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(admin_token),
        body={"token_hash": admin_digest},
    )
    assert response.status_code == 409
    assert _request(app, "GET", "/api/v1/alerts", headers=_headers(admin_token)).status_code == 200

    assert not repository.is_api_token_revoked(admin_digest)


def test_invalid_revocation_payload_and_database_error_are_safe(tmp_path, monkeypatch):
    admin_token = secrets.token_urlsafe(32)
    app, repository = _build_app(tmp_path / "revoke-errors.sqlite3", {"admin": admin_token})
    invalid = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(admin_token),
        body={"token_hash": "not-a-digest"},
    )
    assert invalid.status_code == 422
    assert invalid.json() == {"detail": "Request validation failed."}

    def fail_revoke(_: str, **_kwargs) -> bool:
        raise StorageError("private database path must not leak")

    monkeypatch.setattr(repository, "revoke_api_token", fail_revoke)
    response = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(admin_token),
        body={"token_hash": "f" * 64},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "The local data store is unavailable."}
    assert "private database" not in response.text
    assert "f" * 64 in app.state.revocation_ledger.verify()


def test_restoring_pre_revocation_sqlite_backup_does_not_reactivate_token(tmp_path):
    admin = secrets.token_urlsafe(32)
    database_path = tmp_path / "rollback.sqlite3"
    app, repository = _build_app(database_path, {"admin": admin})
    issued = _request(
        app,
        "POST",
        "/api/v1/admin/tokens",
        headers=_headers(admin),
        body={"role": "analyst"},
    ).json()

    backup_path = tmp_path / "pre-revocation.sqlite3"
    with sqlite3.connect(database_path) as current:
        with sqlite3.connect(backup_path) as backup:
            current.backup(backup)

    revoked = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(admin),
        body={"token_hash": issued["token_hash"]},
    )
    assert revoked.status_code == 200
    assert repository.is_api_token_revoked(issued["token_hash"])

    # Restore only SQLite. The independent journal and its key remain current.
    with sqlite3.connect(backup_path) as backup:
        with sqlite3.connect(database_path) as restored:
            backup.backup(restored)

    reopened_app, restored_repository = _build_app(database_path, {"admin": admin})
    assert not restored_repository.is_api_token_revoked(issued["token_hash"])
    assert issued["token_hash"] in reopened_app.state.revocation_ledger.verify()
    rejected = _request(
        reopened_app,
        "GET",
        "/api/v1/events",
        headers=_headers(issued["access_token"]),
    )
    assert rejected.status_code == 401


def test_api_fails_closed_when_trusted_revocation_state_cannot_be_verified(tmp_path):
    admin = secrets.token_urlsafe(32)
    database_path = tmp_path / "untrusted.sqlite3"
    ledger_path = tmp_path / "untrusted.revocations.jsonl"
    ledger = HmacRevocationLedger(ledger_path, bytes.fromhex("a1" * 32))
    ledger.initialize()
    with ledger_path.open("ab") as journal:
        journal.write(b'{"forged":true}\n')
    app = create_app(
        database_path=database_path,
        token_hashes={token_digest(admin): _grant("admin")},
        cors_origins=[],
        revocation_ledger=ledger,
    )

    with pytest.raises(RevocationStateError):
        _request(app, "GET", "/api/v1/alerts", headers=_headers(admin))


def test_api_fails_closed_when_trusted_revocation_journal_is_missing(tmp_path):
    admin = secrets.token_urlsafe(32)
    ledger = HmacRevocationLedger(
        tmp_path / "missing.revocations.jsonl", bytes.fromhex("a1" * 32)
    )
    app = create_app(
        database_path=tmp_path / "missing.sqlite3",
        token_hashes={token_digest(admin): _grant("admin")},
        cors_origins=[],
        revocation_ledger=ledger,
    )

    with pytest.raises(RevocationStateError):
        _request(app, "GET", "/api/v1/alerts", headers=_headers(admin))


def test_revocation_audit_does_not_log_token_or_digest(tmp_path, caplog):
    admin_token = secrets.token_urlsafe(32)
    victim_token = secrets.token_urlsafe(32)
    app, _ = _build_app(
        tmp_path / "audit-revocation.sqlite3",
        {"admin": admin_token, "analyst": victim_token},
    )
    digest = token_digest(victim_token)
    caplog.set_level(logging.INFO, logger="soc.api.audit")
    response = _request(
        app,
        "POST",
        "/api/v1/admin/tokens/revoke",
        headers=_headers(admin_token),
        body={"token_hash": digest},
    )
    assert response.status_code == 200
    assert admin_token not in caplog.text
    assert victim_token not in caplog.text
    assert digest not in caplog.text
    assert "action=token.revoke" in caplog.text


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("localhost", "127.0.0.1"),
        ("127.0.0.1", "127.0.0.1"),
        ("127.12.34.56", "127.12.34.56"),
    ],
)
def test_bind_validation_accepts_ipv4_loopback_only(host, expected):
    assert validate_bind_host(host) == expected
    assert is_loopback_bind_host(expected)


@pytest.mark.skipif(not socket.has_ipv6, reason="Python was built without IPv6 support")
def test_bind_validation_accepts_ipv6_loopback():
    assert validate_bind_host("::1") == "::1"
    assert is_loopback_bind_host("::1")


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",
        "::",
        "192.0.2.10",
        "2001:db8::1",
        "soc.example.test",
        " 127.0.0.1",
    ],
)
def test_bind_validation_rejects_non_loopback_or_malformed_hosts(host):
    with pytest.raises(ValueError):
        validate_bind_host(host)
    assert not is_loopback_bind_host(host)


def test_launcher_rejects_wildcard_before_calling_uvicorn(monkeypatch):
    run_calls = []
    fake_uvicorn = types.SimpleNamespace(
        run=lambda *args, **kwargs: run_calls.append((args, kwargs))
    )
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setenv("SOC_API_BIND_HOST", "0.0.0.0")

    with pytest.raises(ValueError, match="loopback"):
        run_api_main()

    assert run_calls == []


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_launcher_passes_literal_ipv4_loopback_to_uvicorn(monkeypatch, host):
    run_calls = []
    fake_uvicorn = types.SimpleNamespace(
        run=lambda *args, **kwargs: run_calls.append((args, kwargs))
    )
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setenv("SOC_API_BIND_HOST", host)
    monkeypatch.delenv("SOC_API_PORT", raising=False)

    run_api_main()

    assert run_calls == [
        (("backend.app.main:app",), {"host": "127.0.0.1", "port": 8000})
    ]


@pytest.mark.skipif(not socket.has_ipv6, reason="Python was built without IPv6 support")
def test_launcher_passes_ipv6_loopback_to_uvicorn(monkeypatch):
    run_calls = []
    fake_uvicorn = types.SimpleNamespace(
        run=lambda *args, **kwargs: run_calls.append((args, kwargs))
    )
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setenv("SOC_API_BIND_HOST", "::1")
    monkeypatch.setenv("SOC_API_PORT", "8443")

    run_api_main()

    assert run_calls == [
        (("backend.app.main:app",), {"host": "::1", "port": 8443})
    ]


def test_api_fails_closed_when_asgi_server_is_bound_to_non_loopback(tmp_path):
    token = secrets.token_urlsafe(32)
    app, _ = _build_app(tmp_path / "bind-guard.sqlite3", {"analyst": token})
    assert _request(app, "GET", "/api/v1/health").status_code == 200
    response = _request(
        app, "GET", "/api/v1/health", base_url="http://0.0.0.0"
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "The API is restricted to loopback serving."}


@pytest.mark.parametrize("value", ["0", "65536", "1.5", "abc", " 80"])
def test_safe_launcher_rejects_invalid_ports(value):
    with pytest.raises(ValueError):
        configured_port(value)


def test_safe_launcher_defaults_port_and_accepts_valid_port():
    assert configured_port(None) == 8000
    assert configured_port("8443") == 8443
