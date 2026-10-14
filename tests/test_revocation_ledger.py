"""Trusted token revocation state tests using temporary files only."""

from __future__ import annotations

import pytest

from backend.app.database import SQLiteRepository
from backend.app.security import HmacRevocationLedger, RevocationStateError
from scripts.init_revocation_ledger import main as initialize_ledger_main


TEST_KEY = bytes.fromhex("a1" * 32)


def test_hmac_journal_is_idempotent_and_detects_wrong_key(tmp_path):
    path = tmp_path / "revocations.jsonl"
    ledger = HmacRevocationLedger(path, TEST_KEY)
    ledger.initialize()
    token_hash = "c" * 64

    assert ledger.revoke(token_hash)
    assert not ledger.revoke(token_hash)
    assert ledger.verify() == {token_hash}

    wrong_key = HmacRevocationLedger(path, bytes.fromhex("b2" * 32))
    with pytest.raises(RevocationStateError):
        wrong_key.verify()


def test_journal_refuses_a_shared_parent_directory(tmp_path):
    directory = tmp_path / "shared-state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)
    ledger = HmacRevocationLedger(directory / "revocations.jsonl", TEST_KEY)

    with pytest.raises(RevocationStateError):
        ledger.initialize()


def test_initializer_imports_existing_database_revocations(tmp_path, monkeypatch, capsys):
    database_path = tmp_path / "state.sqlite3"
    repository = SQLiteRepository(database_path)
    repository.initialize()
    token_hash = "d" * 64
    repository.revoke_api_token(token_hash)
    ledger_path = tmp_path / "state-revocations.jsonl"

    monkeypatch.setenv("SOC_DATABASE_PATH", str(database_path))
    monkeypatch.setenv("SOC_API_REVOCATION_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("SOC_API_REVOCATION_LEDGER_KEY", TEST_KEY.hex())

    assert initialize_ledger_main() == 0
    assert HmacRevocationLedger(ledger_path, TEST_KEY).verify() == {token_hash}
    assert token_hash not in capsys.readouterr().out


def test_initializer_refuses_to_replace_an_existing_journal(tmp_path, monkeypatch, capsys):
    database_path = tmp_path / "state.sqlite3"
    ledger_path = tmp_path / "state-revocations.jsonl"
    repository = SQLiteRepository(database_path)
    repository.initialize()
    ledger = HmacRevocationLedger(ledger_path, TEST_KEY)
    ledger.initialize()
    ledger.revoke("e" * 64)

    monkeypatch.setenv("SOC_DATABASE_PATH", str(database_path))
    monkeypatch.setenv("SOC_API_REVOCATION_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("SOC_API_REVOCATION_LEDGER_KEY", TEST_KEY.hex())

    assert initialize_ledger_main() == 1
    assert HmacRevocationLedger(ledger_path, TEST_KEY).verify() == {"e" * 64}
    assert "already exists" in capsys.readouterr().err
