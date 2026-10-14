"""Structural checks for the dependency-free browser dashboard."""

from pathlib import Path

from backend.app.main import app


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def _javascript_sources() -> list[str]:
    return [path.read_text(encoding="utf-8") for path in (FRONTEND / "js").glob("*.js")]


def test_dashboard_calls_only_existing_read_auth_and_investigation_endpoints():
    route_pairs = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method != "parameters"
    }
    expected = {
        ("GET", "/api/v1/health"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", "/api/v1/alerts"),
        ("GET", "/api/v1/alerts/{alert_id}"),
        ("GET", "/api/v1/events"),
        ("GET", "/api/v1/events/{event_id}"),
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/incidents/{incident_id}"),
        ("POST", "/api/v1/incidents"),
        ("POST", "/api/v1/incidents/{incident_id}/transitions"),
        ("GET", "/api/v1/incidents/{incident_id}/notes"),
        ("POST", "/api/v1/incidents/{incident_id}/notes"),
        ("GET", "/api/v1/admin/audit-events"),
    }
    assert expected <= route_pairs
    client = (FRONTEND / "js" / "api.js").read_text(encoding="utf-8")
    for path in ("/api/v1/health", "/api/v1/alerts", "/api/v1/events", "/api/v1/incidents"):
        assert path in client
    assert "getAlert(alertId)" in client
    assert "getEvent(eventId)" in client
    assert "getIncident(incidentId)" in client
    assert "createIncident(values)" in client
    assert "transitionIncident(incidentId, status)" in client
    assert 'login: "/api/v1/auth/login"' in client
    assert 'logout: "/api/v1/auth/logout"' in client
    assert "async logout()" in client
    assert "PATCH" not in client


def test_investigation_actions_use_existing_incident_routes_and_alert_fields():
    client = (FRONTEND / "js" / "api.js").read_text(encoding="utf-8")
    app_source = (FRONTEND / "js" / "app.js").read_text(encoding="utf-8")
    assert 'method: "POST", body: values' in client
    assert "}/transitions" in client
    assert 'title: String(detail.rule_name || "Alert investigation")' in app_source
    assert "alert_ids: [detail.alert_id]" in app_source
    assert "supporting_event_refs: detail.supporting_event_refs || []" in app_source
    assert 'item.description, "truncate"' in app_source
    assert 'detail.source_ip || "—"' in app_source
    assert 'badge("Not tracked", "unavailable")' in app_source
    assert "Create linked incident" in app_source
    assert 'TRANSITION_LABELS = {' in app_source
    assert "Start investigation" in app_source
    assert "Resolve incident" in app_source
    assert 'state.role === "analyst"' in app_source
    assert "assignment" not in app_source.lower()
    assert "append-only" in app_source.lower()


def test_dashboard_uses_existing_note_and_audit_routes_with_role_boundaries():
    client = (FRONTEND / "js" / "api.js").read_text(encoding="utf-8")
    app_source = (FRONTEND / "js" / "app.js").read_text(encoding="utf-8")
    routes = app.openapi()["paths"]
    assert "/api/v1/incidents/{incident_id}/notes" in routes
    assert "/api/v1/admin/audit-events" in routes
    assert "listIncidentNotes(incidentId" in client
    assert "appendIncidentNote(incidentId, noteText)" in client
    assert 'body: { note_text: noteText }' in client
    assert "listAuditEvents({ limit = 25, offset = 0, action, resource_type, resource_id } = {})" in client
    assert 'data-view="audit"' in (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert 'state.role !== "admin"' in app_source
    assert 'state.role !== "analyst" && state.role !== "admin"' in app_source
    assert "oldest first" in app_source
    assert "item.changes" not in app_source
    assert 'item.resource_type === "api_token"' in app_source
    assert "note.note_text" in app_source
    assert "loadIncidentNotes" in app_source
    assert "Loading investigation notes" in app_source
    assert "No investigation notes" in app_source
    assert "The note could not be confirmed" in app_source
    assert "Could not load data" in app_source
    assert 'if (error instanceof ApiError && error.status === 401)' in app_source
    assert "error.status === 403" in app_source


def test_untrusted_api_values_are_inserted_as_text_not_html():
    sources = _javascript_sources()
    joined = "\n".join(sources)
    assert "textContent" in joined
    for unsafe_api in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert unsafe_api not in joined


def test_frontend_does_not_persist_tokens_or_load_sample_records():
    joined = "\n".join(_javascript_sources())
    assert "localStorage" not in joined
    assert "sessionStorage" not in joined
    assert "document.cookie" not in joined
    assert 'headers.Authorization = `Bearer ${this.token}`' in joined
    assert "sample_events.jsonl" not in joined
    assert "sample_detection_events.jsonl" not in joined


def test_login_form_uses_generic_auth_errors_and_clears_expired_sessions():
    sources = _javascript_sources()
    joined = "\n".join(sources)
    app_source = (FRONTEND / "js" / "app.js").read_text(encoding="utf-8")
    assert 'inputControl("login-username"' in app_source
    assert 'inputControl("login-password"' in app_source
    assert 'credentialInput.autocomplete = mode === "account" ? "current-password" : "off"' in app_source
    assert '"Invalid username or password."' in joined
    assert 'if (error instanceof ApiError && error.status === 401)' in app_source
    assert "showConnectError(error.message)" in app_source
    assert "await current.logout()" in app_source
    assert "credentialInput.value = \"\"" in app_source
    assert "console." not in joined


def test_dashboard_has_accessible_views_and_responsive_theme():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    css = (FRONTEND / "styles.css").read_text(encoding="utf-8")
    app_source = "\n".join(_javascript_sources())
    for view in ("overview", "alerts", "incidents", "events", "health"):
        assert f'data-view="{view}"' in html
    assert 'aria-label="Primary navigation"' in html
    assert 'aria-live="polite"' in html
    assert "@media (max-width: 620px)" in css
    assert "prefers-reduced-motion" in css
    assert "Access restricted" in app_source
    assert "No events yet" in app_source
    assert "Loading live data" in app_source


def test_dashboard_only_accepts_loopback_api_urls():
    client = (FRONTEND / "js" / "api.js").read_text(encoding="utf-8")
    assert 'hostname === "localhost"' in client
    assert 'hostname === "127.0.0.1"' in client
    assert 'hostname === "::1"' in client
    assert 'credentials: "omit"' in client


def test_api_client_preserves_the_browser_fetch_receiver():
    client = (FRONTEND / "js" / "api.js").read_text(encoding="utf-8")
    assert "this.fetchImplementation.call(globalThis," in client
