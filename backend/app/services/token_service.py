"""One-time issuance of database-backed local API bearer tokens."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Mapping

from backend.app.api.auth import MAX_TOKEN_TTL_SECONDS, token_digest


TokenRole = Literal["reader", "analyst", "admin"]


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    token_hash: str
    role: TokenRole
    issued_at: str
    expires_at: str


def issue_api_token(
    repository,
    *,
    role: TokenRole,
    expires_in_seconds: int | None,
    default_ttl_seconds: int,
    user_id: str | None = None,
    issued_by_user_id: str | None = None,
    audit_context: Mapping[str, Any] | None = None,
    audit_action: str | None = None,
) -> IssuedToken:
    """Create a random token and persist only its digest and grant metadata."""
    if role not in {"reader", "analyst", "admin"}:
        raise ValueError("Token role is not supported.")
    if expires_in_seconds is None:
        ttl_seconds = default_ttl_seconds
    else:
        if (
            isinstance(expires_in_seconds, bool)
            or not isinstance(expires_in_seconds, int)
            or not 1 <= expires_in_seconds <= MAX_TOKEN_TTL_SECONDS
        ):
            raise ValueError("Token lifetime must be from 1 second through 90 days.")
        ttl_seconds = expires_in_seconds

    access_token = secrets.token_urlsafe(32)
    token_hash = token_digest(access_token)
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl_seconds)
    issued_at = issued.isoformat().replace("+00:00", "Z")
    expires_at = expires.isoformat().replace("+00:00", "Z")
    audit_event = None
    if audit_context is not None:
        if audit_action not in {"auth.login", "token.issue"}:
            raise ValueError("Audit action is not supported for token issuance.")
        audit_event = {
            **audit_context,
            "action": audit_action,
            "resource_type": "api_token",
            "resource_id": None,
            "changes": {"issued_role": role, "expires_at": expires_at},
        }
    repository.create_api_token(
        token_hash,
        role,
        issued_at,
        expires_at,
        user_id=user_id,
        issued_by_user_id=issued_by_user_id,
        audit_event=audit_event,
    )
    return IssuedToken(
        access_token=access_token,
        token_hash=token_hash,
        role=role,
        issued_at=issued_at,
        expires_at=expires_at,
    )
