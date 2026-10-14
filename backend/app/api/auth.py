"""Bearer-token authentication for local API clients.

Static configured grants accept only hashes and explicit UTC issue times, with
an optional per-grant expiration. API-issued grants keep their role and exact
expiration in SQLite. Both forms check the persistent revocation ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Mapping

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


Role = Literal["reader", "analyst", "admin"]
DEFAULT_TOKEN_TTL_SECONDS = 12 * 60 * 60
MAX_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60
_TOKEN_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_USER_ID = re.compile(r"^[0-9a-f]{32}$")
_bearer = HTTPBearer(auto_error=False)
_AUTH_AUDIT = logging.getLogger("soc.api.audit")


@dataclass(frozen=True)
class TokenGrant:
    role: Role
    issued_at: datetime
    expires_at: datetime


def token_digest(token: str) -> str:
    """Return the lowercase SHA-256 digest used in the server allowlist."""
    if not isinstance(token, str):
        raise TypeError("Bearer token must be text.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def disabled_user_marker_hash(user_id: str) -> str:
    """Derive a journal digest that permanently disables account-linked tokens."""
    if not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id):
        raise ValueError("User identifier is invalid.")
    return hashlib.sha256(b"advanced-soc-disabled-user\x00" + user_id.encode("ascii")).hexdigest()


def parse_token_ttl_seconds(value: str | int | None = None) -> int:
    """Validate the configured grant lifetime, defaulting to twelve hours."""
    if value is None:
        return DEFAULT_TOKEN_TTL_SECONDS
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("SOC_API_TOKEN_TTL_SECONDS must be an integer.")
    if isinstance(value, str) and (not value.isascii() or not value.isdigit()):
        raise ValueError("SOC_API_TOKEN_TTL_SECONDS must be an integer.")
    try:
        ttl = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("SOC_API_TOKEN_TTL_SECONDS must be an integer.") from exc
    if isinstance(value, str) and str(ttl) != value:
        raise ValueError("SOC_API_TOKEN_TTL_SECONDS must be an integer.")
    if not 1 <= ttl <= MAX_TOKEN_TTL_SECONDS:
        raise ValueError(
            f"SOC_API_TOKEN_TTL_SECONDS must be between 1 and {MAX_TOKEN_TTL_SECONDS}."
        )
    return ttl


def _parse_issued_at(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Token grant issued_at must be an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Token grant issued_at must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Token grant issued_at must include a timezone.")
    parsed = parsed.astimezone(timezone.utc)
    if parsed > datetime.now(timezone.utc):
        raise ValueError("Token grant issued_at cannot be in the future.")
    return parsed


def _parse_expires_at(value: Any, issued_at: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Token grant expires_at must be an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Token grant expires_at must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Token grant expires_at must include a timezone.")
    parsed = parsed.astimezone(timezone.utc)
    lifetime = (parsed - issued_at).total_seconds()
    if not 0 < lifetime <= MAX_TOKEN_TTL_SECONDS:
        raise ValueError("Token grant expiration must be after issue time and within 90 days.")
    return parsed


def validate_token_hashes(
    values: Mapping[str, Any],
    *,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
) -> dict[str, TokenGrant]:
    """Validate digest-to-grant configuration without accepting raw tokens.

    Each value must contain ``role`` and timezone-aware ``issued_at``. An
    optional timezone-aware ``expires_at`` overrides the configured lifetime
    for that grant. Old permanent role-only grants remain rejected.
    """
    ttl = parse_token_ttl_seconds(ttl_seconds)
    if not isinstance(values, Mapping):
        raise ValueError("SOC_API_TOKEN_HASHES must be a JSON object.")
    grants: dict[str, TokenGrant] = {}
    for digest, raw_grant in values.items():
        if not isinstance(digest, str) or not _TOKEN_DIGEST.fullmatch(digest):
            raise ValueError("Token allowlist keys must be lowercase SHA-256 digests.")
        if not isinstance(raw_grant, Mapping) or set(raw_grant) not in (
            {"role", "issued_at"},
            {"role", "issued_at", "expires_at"},
        ):
            raise ValueError(
                "Each token grant must contain role and issued_at, with optional expires_at."
            )
        role = raw_grant.get("role")
        if not isinstance(role, str) or role not in {"reader", "analyst", "admin"}:
            raise ValueError("Token grant role is not supported.")
        issued_at = _parse_issued_at(raw_grant.get("issued_at"))
        expires_at = (
            _parse_expires_at(raw_grant["expires_at"], issued_at)
            if "expires_at" in raw_grant
            else issued_at + timedelta(seconds=ttl)
        )
        grants[digest] = TokenGrant(
            role=role,  # type: ignore[arg-type]
            issued_at=issued_at,
            expires_at=expires_at,
        )
    return grants


def parse_token_hashes(
    value: str | None,
    *,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
) -> dict[str, TokenGrant]:
    """Read and validate the JSON token-hash allowlist from configuration."""
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("SOC_API_TOKEN_HASHES must contain valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise ValueError("SOC_API_TOKEN_HASHES must be a JSON object.")
    return validate_token_hashes(parsed, ttl_seconds=ttl_seconds)


def require_roles(*allowed: Role):
    async def dependency(
        request: Request,
        role: Role = Depends(current_principal),
    ) -> Role:
        if role not in allowed:
            actor_user_id = getattr(request.state, "auth_actor_user_id", None)
            actor_username = None
            if actor_user_id is not None:
                account = request.app.state.repository.get_api_user_by_id(actor_user_id)
                actor_username = account["username"] if account is not None else None
            route = request.scope.get("route")
            route_template = getattr(route, "path", "") or "unknown"
            request.app.state.repository.append_audit_event(
                {
                    "actor_type": getattr(
                        request.state, "auth_actor_type", "configured_token"
                    ),
                    "actor_user_id": actor_user_id,
                    "actor_username": actor_username,
                    "actor_role": role,
                    "action": "authorization.denied",
                    "resource_type": "api_route",
                    "resource_id": route_template,
                    "changes": {
                        "method": request.method,
                        "required_roles": sorted(allowed),
                    },
                }
            )
            _AUTH_AUDIT.warning(
                "action=authorization.denied role=%s method=%s",
                role,
                request.method,
            )
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
        return role

    return dependency


async def current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Role:
    grants: Mapping[str, TokenGrant] = request.app.state.token_hashes
    if credentials is None or credentials.scheme.lower() != "bearer":
        if not grants and not request.app.state.repository.has_api_tokens():
            raise HTTPException(
                status_code=503,
                detail="API authentication is not configured.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        _AUTH_AUDIT.warning("action=auth outcome=missing")
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    supplied = credentials.credentials
    candidate = token_digest(supplied)
    matched_digest: str | None = None
    matched_grant: TokenGrant | None = None
    matched_user_id: str | None = None
    matched_issuer_user_id: str | None = None
    for digest, grant in grants.items():
        if hmac.compare_digest(candidate, digest):
            matched_digest, matched_grant = digest, grant
    if matched_digest is None:
        issued_grant = request.app.state.repository.get_api_token(candidate)
        if issued_grant is not None:
            matched_digest = candidate
            matched_user_id = issued_grant.get("user_id")
            matched_issuer_user_id = issued_grant.get("issued_by_user_id")
            try:
                issued_at = _parse_issued_at(issued_grant["issued_at"])
                expires_at = _parse_expires_at(issued_grant["expires_at"], issued_at)
                role = issued_grant["role"]
                if role not in {"reader", "analyst", "admin"}:
                    raise ValueError("Unsupported stored token role.")
                matched_grant = TokenGrant(
                    role=role,  # type: ignore[arg-type]
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Token storage is unavailable.",
                ) from exc
    if matched_digest is None or matched_grant is None:
        if not grants and not request.app.state.repository.has_api_tokens():
            raise HTTPException(
                status_code=503,
                detail="API authentication is not configured.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        _AUTH_AUDIT.warning("action=auth outcome=invalid")
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        trusted_revoked = request.app.state.revocation_ledger.is_revoked(matched_digest)
        database_revoked = request.app.state.repository.is_api_token_revoked(matched_digest)
        user_disabled = False
        if matched_user_id is not None:
            user_disabled = request.app.state.revocation_ledger.is_revoked(
                disabled_user_marker_hash(matched_user_id)
            )
            account = request.app.state.repository.get_api_user_by_id(matched_user_id)
            if account is None or not account["is_active"]:
                user_disabled = True
            elif account["role"] not in {"reader", "analyst", "admin"}:
                raise ValueError("Stored account role is invalid.")
            else:
                matched_grant = TokenGrant(
                    role=account["role"],  # type: ignore[arg-type]
                    issued_at=matched_grant.issued_at,
                    expires_at=matched_grant.expires_at,
                )
        if matched_issuer_user_id is not None:
            issuer_disabled = request.app.state.revocation_ledger.is_revoked(
                disabled_user_marker_hash(matched_issuer_user_id)
            )
            issuer = request.app.state.repository.get_api_user_by_id(
                matched_issuer_user_id
            )
            if (
                issuer is None
                or not issuer["is_active"]
                or issuer["role"] != "admin"
            ):
                issuer_disabled = True
            user_disabled = user_disabled or issuer_disabled
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Token revocation storage is unavailable.",
        ) from exc
    if trusted_revoked or database_revoked or user_disabled:
        _AUTH_AUDIT.warning("action=auth outcome=revoked")
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if datetime.now(timezone.utc) >= matched_grant.expires_at:
        _AUTH_AUDIT.warning("action=auth outcome=expired")
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.auth_token_hash = matched_digest
    # Carry the original account administrator through delegated credentials
    # so disabling that account also revokes grants issued downstream.
    request.state.auth_user_id = matched_user_id or matched_issuer_user_id
    # Audit attribution is separate: an unbound delegated token's issuer is not
    # necessarily the person currently using it.
    request.state.auth_actor_user_id = matched_user_id
    request.state.auth_actor_type = (
        "user"
        if matched_user_id is not None
        else "delegated_token"
        if matched_issuer_user_id is not None
        else "configured_token"
    )
    _AUTH_AUDIT.info("action=auth outcome=accepted role=%s", matched_grant.role)
    return matched_grant.role
