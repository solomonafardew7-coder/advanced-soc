"""Password hashing and account authentication helpers."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Literal, Mapping

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

_PASSWORDS = PasswordHash.recommended()
_USERNAME = re.compile(r"^[a-z0-9._-]{3,64}$")
AccountRole = Literal["reader", "analyst", "admin"]


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    """Use a real Argon2 hash for unknown usernames to reduce timing leaks."""
    return _PASSWORDS.hash(secrets.token_urlsafe(32))


def normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValueError("Username is invalid.")
    normalized = username.strip().lower()
    if not _USERNAME.fullmatch(normalized):
        raise ValueError("Username is invalid.")
    return normalized


class AccountService:
    """Create accounts and verify password credentials without exposing hashes."""

    def __init__(self, repository: Any):
        self.repository = repository

    def create_user(
        self,
        *,
        username: str,
        password: str,
        role: AccountRole,
        audit_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_username(username)
        if not isinstance(password, str) or not 12 <= len(password) <= 256:
            raise ValueError("Password must contain between 12 and 256 characters.")
        if not isinstance(role, str) or role not in {"reader", "analyst", "admin"}:
            raise ValueError("Account role is not supported.")
        password_hash = _PASSWORDS.hash(password)
        user_id = secrets.token_hex(16)
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if audit_context is None:
            return self.repository.create_api_user(
                user_id, normalized, password_hash, role, created_at
            )
        return self.repository.create_api_user(
            user_id,
            normalized,
            password_hash,
            role,
            created_at,
            audit_event={
                **audit_context,
                "action": "user.create",
                "resource_type": "api_user",
                "resource_id": user_id,
                "changes": {"role": role},
            },
        )

    def authenticate(self, *, username: str, password: str) -> dict[str, Any] | None:
        normalized = normalize_username(username)
        user = self.repository.get_api_user_by_username(normalized)
        password_hash = user["password_hash"] if user is not None else _dummy_password_hash()
        try:
            verified = _PASSWORDS.verify(password, password_hash)
        except UnknownHashError:
            # A malformed or unsupported stored hash must not authenticate.
            verified = False
        if (
            user is None
            or not verified
            or not user["is_active"]
            or not isinstance(user["role"], str)
            or user["role"] not in {"reader", "analyst", "admin"}
        ):
            return None
        return {
            key: user[key]
            for key in ("user_id", "username", "role", "is_active", "created_at")
        }
