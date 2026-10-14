"""HMAC-chained revocation state kept outside the SQLite database backups.

This journal protects against restoring only the application SQLite database.
It is not a hardware or remote monotonic checkpoint: restoring the journal and
its separately managed key to an older matching pair is outside its guarantee.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


_TOKEN_HASH = re.compile(r"^[0-9a-f]{64}$")
_KEY_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_ZERO_HASH = "0" * 64
_DEFAULT_LEDGER = Path.home() / ".local" / "state" / "advanced-soc" / "token-revocations.jsonl"


class RevocationStateError(RuntimeError):
    """Trusted revocation state is missing, damaged, or cannot be updated."""


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


class HmacRevocationLedger:
    """Append-oriented authenticated revocation journal independent of SQLite."""

    def __init__(self, path: str | Path, key: bytes):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Revocation journal key must contain 32 bytes.")
        self.path = Path(path).expanduser()
        self.key = key

    @classmethod
    def from_environment(cls) -> "HmacRevocationLedger":
        key_text = os.getenv("SOC_API_REVOCATION_LEDGER_KEY", "")
        if not _KEY_HEX.fullmatch(key_text):
            raise RevocationStateError(
                "SOC_API_REVOCATION_LEDGER_KEY must be a 64-character hexadecimal key."
            )
        path = os.getenv("SOC_API_REVOCATION_LEDGER_PATH", str(_DEFAULT_LEDGER))
        if not path.strip():
            raise RevocationStateError("SOC_API_REVOCATION_LEDGER_PATH cannot be empty.")
        return cls(Path(path), bytes.fromhex(key_text))

    def initialize(self, revoked_hashes: Iterable[str] = ()) -> None:
        """Create a new journal once, seeding it with known SQLite revocations."""
        digests: set[str] = set()
        for digest in revoked_hashes:
            if not isinstance(digest, str) or not _TOKEN_HASH.fullmatch(digest):
                raise RevocationStateError(
                    "Initial revocation state contains an invalid token hash."
                )
            digests.add(digest)

        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._check_parent(self.path.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise RevocationStateError("Revocation journal already exists; refusing to replace it.") from exc
        except OSError as exc:
            raise RevocationStateError("Could not create the trusted revocation journal.") from exc

        try:
            records = [self._make_record(0, "genesis", _ZERO_HASH)]
            previous = records[-1]["mac"]
            for sequence, token_hash in enumerate(digests, start=1):
                record = self._make_record(
                    sequence,
                    "revoke",
                    previous,
                    token_hash=token_hash,
                    revoked_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                )
                records.append(record)
                previous = record["mac"]
            payload = b"".join(_canonical_json(record) + b"\n" for record in records)
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
            self._fsync_directory(self.path.parent)
        except BaseException:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)

    def verify(self) -> set[str]:
        """Read and authenticate the complete journal; never initialize it."""
        descriptor = self._open_read()
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH)
                payload = self._read_all(descriptor)
                return self._decode(payload)[0]
            except OSError as exc:
                raise RevocationStateError(
                    "Could not verify trusted revocation journal."
                ) from exc
        finally:
            os.close(descriptor)

    def is_revoked(self, token_hash: str) -> bool:
        self._validate_hash(token_hash)
        revoked = self.verify()
        return token_hash in revoked

    def revoke(self, token_hash: str) -> bool:
        """Append and fsync a revocation before the caller updates SQLite."""
        self._validate_hash(token_hash)
        descriptor = self._open_write()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            payload = self._read_all(descriptor)
            revoked, records = self._decode(payload)
            if token_hash in revoked:
                return False
            previous = records[-1]["mac"]
            record = self._make_record(
                len(records),
                "revoke",
                previous,
                token_hash=token_hash,
                revoked_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )
            os.lseek(descriptor, 0, os.SEEK_END)
            self._write_all(descriptor, _canonical_json(record) + b"\n")
            os.fsync(descriptor)
            return True
        except OSError as exc:
            raise RevocationStateError("Could not append trusted revocation state.") from exc
        finally:
            os.close(descriptor)

    def _open_read(self) -> int:
        self._check_parent(self.path.parent)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise RevocationStateError("Trusted revocation journal is unavailable.") from exc
        try:
            self._check_file(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _open_write(self) -> int:
        self._check_parent(self.path.parent)
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise RevocationStateError("Trusted revocation journal is unavailable.") from exc
        try:
            self._check_file(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _check_file(descriptor: int) -> None:
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_uid != os.getuid()
            ):
                raise RevocationStateError(
                    "Trusted revocation journal must be a private file owned by this user."
                )
        except OSError as exc:
            raise RevocationStateError("Could not verify trusted revocation journal metadata.") from exc

    @staticmethod
    def _check_parent(path: Path) -> None:
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise RevocationStateError(
                    "Trusted revocation journal directory must be private and owned by this user."
                )
        except OSError as exc:
            raise RevocationStateError(
                "Could not verify trusted revocation journal directory."
            ) from exc

    @staticmethod
    def _read_all(descriptor: int) -> bytes:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks = []
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise RevocationStateError("Could not read trusted revocation journal.") from exc

    def _decode(self, payload: bytes) -> tuple[set[str], list[dict[str, Any]]]:
        if not payload or not payload.endswith(b"\n"):
            raise RevocationStateError("Trusted revocation journal is empty or incomplete.")
        revoked: set[str] = set()
        records: list[dict[str, Any]] = []
        previous = _ZERO_HASH
        lines = payload.splitlines()
        for sequence, line in enumerate(lines):
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RevocationStateError("Trusted revocation journal is malformed.") from exc
            if not isinstance(record, dict):
                raise RevocationStateError("Trusted revocation journal is malformed.")
            kind = record.get("kind")
            expected_keys = (
                {"seq", "kind", "previous", "mac"}
                if sequence == 0
                else {"seq", "kind", "previous", "token_hash", "revoked_at", "mac"}
            )
            record_sequence = record.get("seq")
            if (
                set(record) != expected_keys
                or isinstance(record_sequence, bool)
                or not isinstance(record_sequence, int)
                or record_sequence != sequence
            ):
                raise RevocationStateError("Trusted revocation journal sequence is invalid.")
            if sequence == 0 and kind != "genesis":
                raise RevocationStateError("Trusted revocation journal genesis is missing.")
            if sequence > 0 and kind != "revoke":
                raise RevocationStateError("Trusted revocation journal record type is invalid.")
            if record.get("previous") != previous:
                raise RevocationStateError("Trusted revocation journal chain is broken.")
            unsigned = {key: value for key, value in record.items() if key != "mac"}
            supplied_mac = record.get("mac")
            try:
                expected_mac = hmac.new(
                    self.key, _canonical_json(unsigned), hashlib.sha256
                ).hexdigest()
            except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
                raise RevocationStateError(
                    "Trusted revocation journal is malformed."
                ) from exc
            if (
                not isinstance(supplied_mac, str)
                or not re.fullmatch(r"[0-9a-f]{64}", supplied_mac)
                or not hmac.compare_digest(expected_mac, supplied_mac)
            ):
                raise RevocationStateError("Trusted revocation journal authentication failed.")
            if sequence > 0:
                token_hash = record.get("token_hash")
                revoked_at = record.get("revoked_at")
                if not isinstance(token_hash, str) or not _TOKEN_HASH.fullmatch(token_hash):
                    raise RevocationStateError("Trusted revocation journal token reference is invalid.")
                if not isinstance(revoked_at, str) or not revoked_at.strip():
                    raise RevocationStateError("Trusted revocation journal timestamp is invalid.")
                try:
                    parsed_timestamp = datetime.fromisoformat(
                        revoked_at.replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise RevocationStateError(
                        "Trusted revocation journal timestamp is invalid."
                    ) from exc
                if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
                    raise RevocationStateError(
                        "Trusted revocation journal timestamp is invalid."
                    )
                revoked.add(token_hash)
            records.append(record)
            previous = supplied_mac
        return revoked, records

    def _make_record(
        self,
        sequence: int,
        kind: str,
        previous: str,
        *,
        token_hash: str | None = None,
        revoked_at: str | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {"seq": sequence, "kind": kind, "previous": previous}
        if token_hash is not None:
            record["token_hash"] = token_hash
            record["revoked_at"] = revoked_at
        record["mac"] = hmac.new(self.key, _canonical_json(record), hashlib.sha256).hexdigest()
        return record

    @staticmethod
    def _validate_hash(token_hash: str) -> None:
        if not isinstance(token_hash, str) or not _TOKEN_HASH.fullmatch(token_hash):
            raise RevocationStateError("Token hash must be a lowercase SHA-256 digest.")

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("Short write while updating revocation journal.")
            view = view[count:]

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class UnavailableRevocationLedger:
    """Fail-closed stand-in used when trusted-state configuration is absent."""

    def verify(self) -> set[str]:
        raise RevocationStateError("Trusted revocation state is not configured.")

    def is_revoked(self, token_hash: str) -> bool:
        raise RevocationStateError("Trusted revocation state is not configured.")

    def revoke(self, token_hash: str) -> bool:
        raise RevocationStateError("Trusted revocation state is not configured.")


def revocation_ledger_from_environment() -> HmacRevocationLedger | UnavailableRevocationLedger:
    try:
        return HmacRevocationLedger.from_environment()
    except RevocationStateError:
        return UnavailableRevocationLedger()
