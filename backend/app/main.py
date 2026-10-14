"""FastAPI application for the local Advanced SOC platform."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path as PathParam, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from backend.app.api.auth import (
    Role,
    TokenGrant,
    disabled_user_marker_hash,
    parse_token_hashes,
    parse_token_ttl_seconds,
    require_roles,
    validate_token_hashes,
)
from backend.app.api.schemas import (
    AccountCreateRequest,
    AccountDisableResponse,
    AccountLoginRequest,
    AccountResponse,
    AuditEventPage,
    AuditEventResponse,
    AlertPage,
    AlertResponse,
    EventPage,
    EventResponse,
    HealthResponse,
    IncidentCreateRequest,
    IncidentPage,
    IncidentNoteCreateRequest,
    IncidentNotePage,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentTransitionRequest,
    IncidentUpdateRequest,
    TokenRevocationRequest,
    TokenRevocationResponse,
    TokenIssueRequest,
    TokenIssueResponse,
)
from backend.app.database import (
    SQLiteRepository,
    StorageConflictError,
    StorageError,
    StorageValidationError,
)
from backend.app.models.incident import Incident
from backend.app.security import (
    RevocationStateError,
    UnavailableRevocationLedger,
    revocation_ledger_from_environment,
)
from backend.app.services import (
    AccountService,
    IncidentConflictError,
    IncidentNotFoundError,
    IncidentService,
    IncidentTransitionError,
    IncidentValidationError,
    issue_api_token,
)


_AUDIT = logging.getLogger("soc.api.audit")
_ERROR = logging.getLogger("soc.api")


def _origins_from_environment() -> list[str]:
    configured = os.getenv("SOC_CORS_ORIGINS", "")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def _validated_origins(origins: list[str] | None) -> list[str]:
    normalized = _origins_from_environment() if origins is None else origins
    if any(not isinstance(origin, str) or not origin.strip() for origin in normalized):
        raise ValueError("CORS origins must be non-empty origin strings.")
    normalized = [origin.strip() for origin in normalized]
    if "*" in normalized:
        raise ValueError("Wildcard CORS origins are not supported.")
    for origin in normalized:
        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("CORS origins must be valid loopback HTTP(S) origins.") from exc
        hostname = (parsed.hostname or "").lower()
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or port == 0
        ):
            raise ValueError("CORS origins must be valid loopback HTTP(S) origins.")
    return list(dict.fromkeys(normalized))


def _incident_response(incident: Incident) -> IncidentResponse:
    return IncidentResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        closed_at=incident.closed_at,
        alert_ids=list(incident.alert_ids),
        supporting_event_refs=list(incident.supporting_event_refs),
    )


def _audit(action: str, role: Role, resource_id: str | None = None) -> None:
    if resource_id is None:
        _AUDIT.info("action=%s role=%s", action, role)
    else:
        # repr escapes control characters so IDs cannot inject fake log lines.
        _AUDIT.info("action=%s role=%s resource_id=%r", action, role, resource_id)


def _actor_snapshot(
    repository: Any,
    role: Role,
    *,
    request: Request | None = None,
    user: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if user is not None:
        actor_type = "user"
        actor_user_id = user.get("user_id")
        actor_username = user.get("username")
    else:
        actor_type = getattr(request.state, "auth_actor_type", "configured_token") if request else "configured_token"
        actor_user_id = getattr(request.state, "auth_actor_user_id", None) if request else None
        actor_username = None
    if actor_user_id is not None and actor_username is None:
        account = repository.get_api_user_by_id(actor_user_id)
        if account is None:
            raise StorageValidationError("Audit actor account is unavailable.")
        actor_username = account["username"]
    return {
        "actor_type": actor_type,
        "actor_user_id": actor_user_id,
        "actor_username": actor_username,
        "actor_role": role,
    }


def _persist_audit(
    repository: Any,
    action: str,
    role: Role,
    resource_type: str,
    resource_id: str | None = None,
    *,
    request: Request | None = None,
    user: Mapping[str, Any] | None = None,
    changes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist a sanitized action without credentials or request contents."""
    return repository.append_audit_event(
        {
            **_actor_snapshot(repository, role, request=request, user=user),
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "changes": dict(changes or {}),
        }
    )


def is_loopback_bind_host(host: object) -> bool:
    """Return whether a server bind address names only the local machine."""
    if not isinstance(host, str) or not host or host != host.strip():
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_app(
    *,
    repository: Any | None = None,
    database_path: str | Path | None = None,
    token_hashes: Mapping[str, Any] | None = None,
    token_ttl_seconds: int | str | None = None,
    cors_origins: list[str] | None = None,
    revocation_ledger: Any | None = None,
) -> FastAPI:
    """Build an application with injectable local storage and auth configuration.

    ``token_hashes`` maps SHA-256 digests to grants containing a role and an
    explicit ISO-8601 ``issued_at`` value, with optional per-grant
    ``expires_at``. Raw bearer tokens are never accepted as application
    configuration. ``token_ttl_seconds`` defaults to twelve hours and is
    bounded to ninety days.
    """
    if repository is not None and database_path is not None:
        raise ValueError("Pass either repository or database_path, not both.")
    if repository is None:
        resolved_path = database_path or os.getenv(
            "SOC_DATABASE_PATH", "data/soc_platform.sqlite3"
        )
        repository = SQLiteRepository(resolved_path)
    if revocation_ledger is None:
        revocation_ledger = revocation_ledger_from_environment()
    repository_path = getattr(repository, "database_path", database_path)
    ledger_path = getattr(revocation_ledger, "path", None)
    if repository_path is not None and ledger_path is not None:
        if Path(repository_path).expanduser().resolve() == Path(ledger_path).expanduser().resolve():
            revocation_ledger = UnavailableRevocationLedger()
    configured_ttl = parse_token_ttl_seconds(
        os.getenv("SOC_API_TOKEN_TTL_SECONDS")
        if token_ttl_seconds is None
        else token_ttl_seconds
    )
    configured_hashes: dict[str, TokenGrant] = (
        parse_token_hashes(os.getenv("SOC_API_TOKEN_HASHES"), ttl_seconds=configured_ttl)
        if token_hashes is None
        else validate_token_hashes(token_hashes, ttl_seconds=configured_ttl)
    )
    allowed_origins = _validated_origins(cors_origins)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        revocation_ledger.verify()
        repository.initialize()
        for token_hash in repository.list_api_token_revocations():
            revocation_ledger.revoke(token_hash)
        for user_id in repository.list_disabled_api_users():
            revocation_ledger.revoke(disabled_user_marker_hash(user_id))
            for token_hash in repository.list_api_tokens_for_user(user_id):
                revocation_ledger.revoke(token_hash)
        yield

    application = FastAPI(
        title="Advanced SOC API",
        version="1.0.0",
        description="Local API for stored security events, alerts, and incidents.",
        lifespan=lifespan,
        debug=False,
    )
    application.state.repository = repository
    application.state.incident_service = IncidentService(repository)
    application.state.account_service = AccountService(repository)
    application.state.token_hashes = configured_hashes
    application.state.token_ttl_seconds = configured_ttl
    application.state.revocation_ledger = revocation_ledger
    application.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @application.middleware("http")
    async def require_loopback_server(request: Request, call_next):
        # The ASGI server address comes from its bound socket, unlike the
        # caller-controlled Host header. Fail closed if the server omits it.
        server = request.scope.get("server")
        bind_host = server[0] if isinstance(server, (tuple, list)) and server else None
        if not is_loopback_bind_host(bind_host):
            return JSONResponse(
                status_code=503,
                content={"detail": "The API is restricted to loopback serving."},
            )
        return await call_next(request)

    @application.exception_handler(StorageConflictError)
    async def storage_conflict_handler(_: Request, __: StorageConflictError):
        return JSONResponse(status_code=409, content={"detail": "Record conflict."})

    @application.exception_handler(StorageValidationError)
    async def storage_validation_handler(_: Request, __: StorageValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid record."})

    @application.exception_handler(StorageError)
    async def storage_error_handler(_: Request, __: StorageError):
        _ERROR.error("action=database outcome=unavailable")
        return JSONResponse(
            status_code=503,
            content={"detail": "The local data store is unavailable."},
        )

    @application.exception_handler(RevocationStateError)
    async def trusted_revocation_error_handler(_: Request, __: RevocationStateError):
        _ERROR.error("action=trusted_revocation_state outcome=unavailable")
        return JSONResponse(
            status_code=503,
            content={"detail": "Trusted token revocation state is unavailable."},
        )

    @application.exception_handler(IncidentNotFoundError)
    async def incident_not_found_handler(_: Request, __: IncidentNotFoundError):
        return JSONResponse(status_code=404, content={"detail": "Incident not found."})

    @application.exception_handler(IncidentConflictError)
    async def incident_conflict_handler(_: Request, __: IncidentConflictError):
        return JSONResponse(
            status_code=409,
            content={"detail": "Incident changed; reload it and retry."},
        )

    @application.exception_handler(IncidentTransitionError)
    async def incident_transition_handler(_: Request, __: IncidentTransitionError):
        return JSONResponse(
            status_code=422,
            content={"detail": "Incident status transition is invalid."},
        )

    @application.exception_handler(IncidentValidationError)
    async def incident_validation_handler(_: Request, __: IncidentValidationError):
        return JSONResponse(
            status_code=422, content={"detail": "Incident request is invalid."}
        )

    @application.exception_handler(ValidationError)
    async def response_validation_handler(_: Request, __: ValidationError):
        _ERROR.error("action=response_validation outcome=failed")
        return JSONResponse(
            status_code=500, content={"detail": "The server could not format a response."}
        )

    @application.exception_handler(RequestValidationError)
    async def request_validation_handler(_: Request, __: RequestValidationError):
        # FastAPI's default includes rejected input values; keep request data out
        # of API error responses because event and incident payloads are sensitive.
        return JSONResponse(
            status_code=422, content={"detail": "Request validation failed."}
        )

    @application.exception_handler(Exception)
    async def unexpected_error_handler(_: Request, exc: Exception):
        _ERROR.error("action=request outcome=failed error_type=%s", type(exc).__name__)
        return JSONResponse(
            status_code=500, content={"detail": "An internal server error occurred."}
        )

    v1 = APIRouter(prefix="/api/v1")

    @v1.get("/health", response_model=HealthResponse, tags=["health"])
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @v1.post(
        "/auth/login",
        response_model=TokenIssueResponse,
        tags=["authentication"],
    )
    async def login(
        body: AccountLoginRequest,
        response: Response,
    ) -> TokenIssueResponse:
        try:
            user = application.state.account_service.authenticate(
                username=body.username, password=body.password
            )
        except ValueError:
            user = None
        if user is None or revocation_ledger.is_revoked(
            disabled_user_marker_hash(user["user_id"])
        ):
            _AUDIT.warning("action=auth.login outcome=failed")
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            issued = issue_api_token(
                repository,
                role=user["role"],
                expires_in_seconds=None,
                default_ttl_seconds=application.state.token_ttl_seconds,
                user_id=user["user_id"],
                audit_context=_actor_snapshot(repository, user["role"], user=user),
                audit_action="auth.login",
            )
        except StorageValidationError as exc:
            # A concurrent account disable can invalidate the login between
            # password verification and token persistence.
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        _AUDIT.info("action=auth.login outcome=accepted role=%s", user["role"])
        return TokenIssueResponse(**issued.__dict__)

    @v1.post(
        "/auth/logout",
        response_model=TokenRevocationResponse,
        tags=["authentication"],
    )
    async def logout(
        request: Request,
        role: Role = Depends(require_roles("reader", "analyst", "admin")),
    ) -> TokenRevocationResponse:
        token_hash = getattr(request.state, "auth_token_hash", None)
        if token_hash is None:
            raise HTTPException(status_code=401, detail="A valid bearer token is required.")
        revocation_ledger.revoke(token_hash)
        repository.revoke_api_token(
            token_hash,
            audit_event={
                **_actor_snapshot(repository, role, request=request),
                "action": "auth.logout",
                "resource_type": "api_token",
                "resource_id": None,
                "changes": {"revoked": True},
            },
        )
        _audit("auth.logout", role)
        return TokenRevocationResponse(status="revoked")

    @v1.post(
        "/admin/users",
        response_model=AccountResponse,
        status_code=201,
        tags=["administration"],
    )
    async def create_user(
        body: AccountCreateRequest,
        request: Request,
        role: Role = Depends(require_roles("admin")),
    ) -> AccountResponse:
        try:
            user = application.state.account_service.create_user(
                username=body.username,
                password=body.password,
                role=body.role,
                audit_context=_actor_snapshot(repository, role, request=request),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Account request is invalid.") from exc
        _audit("user.create", role)
        return AccountResponse(**user)

    @v1.post(
        "/admin/users/{user_id}/disable",
        response_model=AccountDisableResponse,
        tags=["administration"],
    )
    async def disable_user(
        user_id: Annotated[str, PathParam(pattern=r"^[0-9a-f]{32}$")],
        request: Request,
        role: Role = Depends(require_roles("admin")),
    ) -> AccountDisableResponse:
        if getattr(request.state, "auth_user_id", None) == user_id:
            raise HTTPException(status_code=409, detail="An administrator cannot disable their own account.")
        user = repository.get_api_user_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="Account not found.")
        disabled = repository.disable_api_user(
            user_id,
            account_marker_hash=disabled_user_marker_hash(user_id),
            revoke_token=revocation_ledger.revoke,
            audit_event={
                **_actor_snapshot(repository, role, request=request),
                "action": "user.disable",
                "resource_type": "api_user",
                "resource_id": user_id,
                "changes": {"is_active": False},
            },
        )
        if disabled is None:
            raise HTTPException(status_code=404, detail="Account not found.")
        _audit("user.disable", role)
        return AccountDisableResponse(status="disabled")

    @v1.post(
        "/admin/tokens",
        response_model=TokenIssueResponse,
        status_code=201,
        tags=["administration"],
    )
    async def issue_token(
        body: TokenIssueRequest,
        response: Response,
        request: Request,
        role: Role = Depends(require_roles("admin")),
    ) -> TokenIssueResponse:
        issued = issue_api_token(
            repository,
            role=body.role,
            expires_in_seconds=body.expires_in_seconds,
            default_ttl_seconds=application.state.token_ttl_seconds,
            issued_by_user_id=getattr(request.state, "auth_user_id", None),
            audit_context=_actor_snapshot(repository, role, request=request),
            audit_action="token.issue",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        _AUDIT.info("action=token.issue role=%s issued_role=%s", role, body.role)
        return TokenIssueResponse(**issued.__dict__)

    @v1.post(
        "/admin/tokens/revoke",
        response_model=TokenRevocationResponse,
        tags=["administration"],
    )
    async def revoke_token(
        body: TokenRevocationRequest,
        request: Request,
        role: Role = Depends(require_roles("admin")),
    ) -> TokenRevocationResponse:
        active_token_hash = getattr(request.state, "auth_token_hash", None)
        if active_token_hash is not None and hmac.compare_digest(
            active_token_hash, body.token_hash
        ):
            raise HTTPException(
                status_code=409,
                detail="An administrator cannot revoke the credential used by this request.",
            )
        revocation_ledger.revoke(body.token_hash)
        repository.revoke_api_token(
            body.token_hash,
            audit_event={
                **_actor_snapshot(repository, role, request=request),
                "action": "token.revoke",
                "resource_type": "api_token",
                "resource_id": None,
                "changes": {"revoked": True},
            },
        )
        _audit("token.revoke", role)
        return TokenRevocationResponse(status="revoked")

    @v1.get("/alerts", response_model=AlertPage, tags=["alerts"])
    async def list_alerts(
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        severity: Literal["informational", "low", "medium", "high", "critical"] | None = None,
        rule_id: str | None = Query(default=None, min_length=1, max_length=200),
        role: Role = Depends(require_roles("reader", "analyst", "admin")),
    ) -> AlertPage:
        items, total = repository.list_alerts(
            limit=limit, offset=offset, severity=severity, rule_id=rule_id
        )
        _audit("alert.list", role)
        return AlertPage(items=items, total=total, limit=limit, offset=offset)

    @v1.get("/alerts/{alert_id}", response_model=AlertResponse, tags=["alerts"])
    async def get_alert(
        alert_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        role: Role = Depends(require_roles("reader", "analyst", "admin")),
    ) -> AlertResponse:
        alert = repository.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        _audit("alert.read", role, alert_id)
        return AlertResponse.model_validate(alert)

    @v1.get("/events", response_model=EventPage, tags=["events"])
    async def list_events(
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        event_type: str | None = Query(default=None, min_length=1, max_length=200),
        source_ip: str | None = Query(default=None, min_length=1, max_length=45),
        severity: Literal[
            "unknown", "informational", "low", "medium", "high", "critical"
        ] | None = None,
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> EventPage:
        items, total = repository.list_events(
            limit=limit,
            offset=offset,
            event_type=event_type,
            source_ip=source_ip,
            severity=severity,
        )
        _audit("event.list", role)
        return EventPage(items=items, total=total, limit=limit, offset=offset)

    @v1.get("/events/{event_id}", response_model=EventResponse, tags=["events"])
    async def get_event(
        event_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> EventResponse:
        event = repository.get_event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found.")
        _audit("event.read", role, event_id)
        return EventResponse.model_validate(event)

    @v1.get("/incidents", response_model=IncidentPage, tags=["incidents"])
    async def list_incidents(
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        status: Literal["open", "investigating", "resolved", "closed"] | None = None,
        severity: Literal[
            "informational", "low", "medium", "high", "critical"
        ] | None = None,
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentPage:
        items, total = repository.list_incidents(
            limit=limit, offset=offset, status=status, severity=severity
        )
        _audit("incident.list", role)
        return IncidentPage(
            items=[_incident_response(incident) for incident in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    @v1.get("/incidents/{incident_id}", response_model=IncidentResponse, tags=["incidents"])
    async def get_incident(
        incident_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentResponse:
        incident = application.state.incident_service.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        _audit("incident.read", role, incident_id)
        return _incident_response(incident)

    @v1.post("/incidents", response_model=IncidentResponse, status_code=201, tags=["incidents"])
    async def create_incident(
        body: IncidentCreateRequest,
        request: Request,
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentResponse:
        incident = application.state.incident_service.create_incident(
            title=body.title,
            description=body.description,
            severity=body.severity,
            alert_ids=body.alert_ids,
            supporting_event_refs=body.supporting_event_refs,
            audit_context=_actor_snapshot(repository, role, request=request),
        )
        _audit("incident.create", role, incident.incident_id)
        return _incident_response(incident)

    @v1.patch("/incidents/{incident_id}", response_model=IncidentResponse, tags=["incidents"])
    async def update_incident(
        body: IncidentUpdateRequest,
        incident_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        request: Request,
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentResponse:
        fields = body.model_dump(exclude_unset=True, exclude_none=True)
        incident = application.state.incident_service.update_incident(
            incident_id,
            **fields,
            audit_context=_actor_snapshot(repository, role, request=request),
        )
        _audit("incident.update", role, incident_id)
        return _incident_response(incident)

    @v1.post(
        "/incidents/{incident_id}/transitions",
        response_model=IncidentResponse,
        tags=["incidents"],
    )
    async def transition_incident(
        body: IncidentTransitionRequest,
        incident_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        request: Request,
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentResponse:
        if role == "analyst" and body.status not in {"investigating", "resolved"}:
            _AUDIT.warning(
                "action=incident.transition outcome=forbidden role=%s resource_id=%r",
                role,
                incident_id,
            )
            _persist_audit(
                repository,
                "incident.transition.denied",
                role,
                "incident",
                incident_id,
                request=request,
                changes={"requested_status": body.status},
            )
            raise HTTPException(
                status_code=403,
                detail="Only administrators may reopen or close incidents.",
            )
        incident = application.state.incident_service.transition_status(
            incident_id,
            body.status,
            audit_context=_actor_snapshot(repository, role, request=request),
        )
        _audit(f"incident.transition.{body.status}", role, incident_id)
        return _incident_response(incident)

    @v1.get(
        "/incidents/{incident_id}/notes",
        response_model=IncidentNotePage,
        tags=["incidents"],
    )
    async def list_incident_notes(
        incident_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentNotePage:
        incident = application.state.incident_service.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        items, total = repository.list_incident_notes(
            incident_id, limit=limit, offset=offset
        )
        return IncidentNotePage(
            items=[IncidentNoteResponse.model_validate(item) for item in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    @v1.post(
        "/incidents/{incident_id}/notes",
        response_model=IncidentNoteResponse,
        status_code=201,
        tags=["incidents"],
    )
    async def create_incident_note(
        body: IncidentNoteCreateRequest,
        incident_id: Annotated[str, PathParam(min_length=1, max_length=200)],
        request: Request,
        role: Role = Depends(require_roles("analyst", "admin")),
    ) -> IncidentNoteResponse:
        incident = application.state.incident_service.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        actor = _actor_snapshot(repository, role, request=request)
        note_id = uuid.uuid4().hex
        note = repository.create_incident_note(
            {
                "note_id": note_id,
                "incident_id": incident_id,
                "author_type": actor["actor_type"],
                "author_user_id": actor["actor_user_id"],
                "author_username": actor["actor_username"],
                "author_role": actor["actor_role"],
                "note_text": body.note_text,
            },
            audit_event={
                **actor,
                "action": "incident.note.append",
                "resource_type": "incident_note",
                "resource_id": note_id,
                "changes": {"incident_id": incident_id, "author_role": role},
            },
        )
        return IncidentNoteResponse.model_validate(note)

    @v1.get(
        "/admin/audit-events",
        response_model=AuditEventPage,
        tags=["administration"],
    )
    async def list_audit_events(
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        action: str | None = Query(default=None, min_length=1, max_length=100),
        resource_type: str | None = Query(default=None, min_length=1, max_length=50),
        resource_id: str | None = Query(default=None, min_length=1, max_length=200),
        role: Role = Depends(require_roles("admin")),
    ) -> AuditEventPage:
        del role
        items, total = repository.list_audit_events(
            limit=limit,
            offset=offset,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        return AuditEventPage(
            items=[AuditEventResponse.model_validate(item) for item in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    application.include_router(v1)
    return application


app = create_app()
