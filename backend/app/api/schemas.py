"""Strict request and response contracts for the versioned HTTP API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["informational", "low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "resolved", "closed"]
ActorType = Literal["user", "configured_token", "delegated_token"]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class HealthResponse(StrictModel):
    status: Literal["ok"]


class EventResponse(StrictModel):
    event_id: str
    timestamp: str
    event_type: str
    source: str | None
    source_ip: str | None
    severity: str
    details: dict[str, Any]


class AlertResponse(StrictModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    event_timestamp: str
    source_ip: str | None
    sources: list[str]
    supporting_event_refs: list[str]
    evidence: dict[str, Any]


class IncidentResponse(StrictModel):
    incident_id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    created_at: str
    updated_at: str
    resolved_at: str | None
    closed_at: str | None
    alert_ids: list[str]
    supporting_event_refs: list[str]


class EventPage(StrictModel):
    items: list[EventResponse]
    total: int
    limit: int
    offset: int


class AlertPage(StrictModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int


class IncidentPage(StrictModel):
    items: list[IncidentResponse]
    total: int
    limit: int
    offset: int


class IncidentNoteCreateRequest(StrictModel):
    note_text: str = Field(min_length=1, max_length=5000)


class IncidentNoteResponse(StrictModel):
    note_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    incident_id: str
    created_at: str
    author_type: ActorType
    author_user_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    author_username: str | None
    author_role: Literal["reader", "analyst", "admin"]
    note_text: str


class IncidentNotePage(StrictModel):
    items: list[IncidentNoteResponse]
    total: int
    limit: int
    offset: int


class AuditEventResponse(StrictModel):
    audit_event_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    occurred_at: str
    actor_type: ActorType
    actor_user_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    actor_username: str | None
    actor_role: Literal["reader", "analyst", "admin"]
    action: str
    resource_type: str
    resource_id: str | None
    changes: dict[str, Any]


class AuditEventPage(StrictModel):
    items: list[AuditEventResponse]
    total: int
    limit: int
    offset: int


class IncidentCreateRequest(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10_000)
    severity: Severity = "medium"
    alert_ids: list[str] = Field(default_factory=list, max_length=500)
    supporting_event_refs: list[str] = Field(default_factory=list, max_length=1000)


class IncidentUpdateRequest(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    severity: Severity | None = None


class IncidentTransitionRequest(StrictModel):
    status: IncidentStatus


class TokenRevocationRequest(StrictModel):
    token_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class TokenRevocationResponse(StrictModel):
    status: Literal["revoked"]


class TokenIssueRequest(StrictModel):
    role: Literal["reader", "analyst", "admin"]
    expires_in_seconds: int | None = Field(default=None, ge=1, le=7_776_000)


class TokenIssueResponse(StrictModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    role: Literal["reader", "analyst", "admin"]
    issued_at: str
    expires_at: str


class AccountLoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AccountCreateRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["reader", "analyst", "admin"]


class AccountResponse(StrictModel):
    user_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    username: str
    role: Literal["reader", "analyst", "admin"]
    is_active: bool
    created_at: str


class AccountDisableResponse(StrictModel):
    status: Literal["disabled"]
