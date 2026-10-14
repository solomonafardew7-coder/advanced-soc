"""Storage port used by incident business logic."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Protocol

from backend.app.models.incident import Incident, IncidentStatus


class EventAlertRepository(Protocol):
    """Operations required to persist normalized events and generated alerts."""

    def save_event(self, raw_event: Mapping[str, Any]) -> bool: ...

    def get_event(self, event_id: str) -> dict[str, Any] | None: ...

    def list_events(
        self,
        *,
        limit: int,
        offset: int,
        event_type: str | None = None,
        source_ip: str | None = None,
        severity: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]: ...

    def save_alert(self, raw_alert: Mapping[str, Any]) -> bool: ...

    def get_alert(self, alert_id: str) -> dict[str, Any] | None: ...

    def list_alerts(
        self,
        *,
        limit: int,
        offset: int,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]: ...


class IncidentRepository(Protocol):
    """Operations required by the incident service.

    A future PostgreSQL adapter can implement this protocol without changing
    incident validation or lifecycle rules.
    """

    def create_incident(
        self, incident: Incident, *, audit_event: Mapping[str, Any] | None = None
    ) -> None: ...

    def get_incident(self, incident_id: str) -> Incident | None: ...

    def list_incidents(
        self,
        *,
        limit: int,
        offset: int,
        status: IncidentStatus | None = None,
        severity: str | None = None,
    ) -> tuple[list[Incident], int]: ...

    def update_incident_fields(
        self,
        incident: Incident,
        expected_updated_at: str,
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> bool: ...

    def transition_incident(
        self,
        incident: Incident,
        expected_status: IncidentStatus,
        expected_updated_at: str,
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> bool: ...

    def create_incident_note(
        self,
        note: Mapping[str, Any],
        *,
        audit_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def list_incident_notes(
        self, incident_id: str, *, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]: ...


class StorageRepository(EventAlertRepository, IncidentRepository, Protocol):
    """Complete persistence boundary implemented by a storage adapter."""

    def revoke_api_token(
        self, token_hash: str, *, audit_event: Mapping[str, Any] | None = None
    ) -> bool: ...

    def is_api_token_revoked(self, token_hash: str) -> bool: ...

    def list_api_token_revocations(self) -> list[str]: ...

    def create_api_token(
        self,
        token_hash: str,
        role: str,
        issued_at: str,
        expires_at: str,
        user_id: str | None = None,
        issued_by_user_id: str | None = None,
        audit_event: Mapping[str, Any] | None = None,
    ) -> None: ...

    def get_api_token(self, token_hash: str) -> dict[str, Any] | None: ...

    def has_api_tokens(self) -> bool: ...

    def create_api_user(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        role: str,
        created_at: str,
        audit_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def get_api_user_by_username(self, username: str) -> dict[str, Any] | None: ...

    def get_api_user_by_id(self, user_id: str) -> dict[str, Any] | None: ...

    def disable_api_user(
        self,
        user_id: str,
        *,
        account_marker_hash: str,
        revoke_token: Callable[[str], bool],
        audit_event: Mapping[str, Any] | None = None,
    ) -> list[str] | None: ...

    def list_disabled_api_users(self) -> list[str]: ...

    def list_api_tokens_for_user(self, user_id: str) -> list[str]: ...

    def append_audit_event(self, event: Mapping[str, Any]) -> dict[str, Any]: ...

    def list_audit_events(
        self,
        *,
        limit: int,
        offset: int,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]: ...
