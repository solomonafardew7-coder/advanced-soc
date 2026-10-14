/** Small authenticated client for the existing local FastAPI routes. */

export const API_PATHS = Object.freeze({
  health: "/api/v1/health",
  login: "/api/v1/auth/login",
  logout: "/api/v1/auth/logout",
  alerts: "/api/v1/alerts",
  events: "/api/v1/events",
  incidents: "/api/v1/incidents",
  auditEvents: "/api/v1/admin/audit-events",
});

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function validateApiBase(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Enter a valid local API address.");
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const loopback = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  if (!loopback || !["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("For safety, connect only to an API on this computer (localhost or 127.0.0.1).");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !["", "/"].includes(parsed.pathname)) {
    throw new Error("Use the local API origin only, without credentials, a path, or query string.");
  }
  return parsed.origin;
}

function queryString(values) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

export class ApiClient {
  constructor(baseUrl, token, fetchImplementation = globalThis.fetch) {
    this.baseUrl = validateApiBase(baseUrl);
    if (typeof token !== "string" || token.trim().length < 16) {
      throw new Error("Enter the bearer token generated for this local API.");
    }
    if (typeof fetchImplementation !== "function") {
      throw new Error("This browser does not provide the fetch API.");
    }
    this.token = token.trim();
    this.fetchImplementation = fetchImplementation;
  }

  static async login(baseUrl, { username, password }, fetchImplementation = globalThis.fetch) {
    const base = validateApiBase(baseUrl);
    if (typeof fetchImplementation !== "function") {
      throw new Error("This browser does not provide the fetch API.");
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12_000);
    let response;
    try {
      response = await fetchImplementation.call(globalThis, `${base}${API_PATHS.login}`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
      });
    } catch (error) {
      const message = error?.name === "AbortError"
        ? "The local API did not respond within 12 seconds."
        : "Could not reach the local API. Check that the backend is running.";
      throw new ApiError(0, message);
    } finally {
      clearTimeout(timeout);
    }

    if (response.status === 401) throw new ApiError(401, "Invalid username or password.");
    if (response.status === 422) throw new ApiError(422, "Sign-in request was rejected. Check the submitted fields.");
    if (response.status === 503) throw new ApiError(503, "The API or local data store is unavailable.");
    if (!response.ok) throw new ApiError(response.status, `Sign-in failed (HTTP ${response.status}).`);

    let result;
    try {
      result = await response.json();
    } catch {
      throw new ApiError(502, "The API returned a response that was not valid JSON.");
    }
    if (
      !result || typeof result.access_token !== "string" || result.access_token.length < 16 ||
      result.token_type !== "bearer" || !["reader", "analyst", "admin"].includes(result.role)
    ) {
      throw new ApiError(502, "The API returned an invalid sign-in response.");
    }
    return {
      client: new ApiClient(base, result.access_token, fetchImplementation),
      role: result.role,
      expiresAt: result.expires_at,
    };
  }

  async request(path, { query = {}, authenticated = true, method = "GET", body } = {}) {
    const url = new URL(`${this.baseUrl}${path}`);
    url.search = queryString(query);
    const headers = { Accept: "application/json" };
    if (authenticated) headers.Authorization = `Bearer ${this.token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12_000);
    let response;
    try {
      // Browser fetch requires the Window/global receiver; calling the stored
      // function as an instance method would bind `this` to ApiClient.
      response = await this.fetchImplementation.call(globalThis, url.toString(), {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
      });
    } catch (error) {
      const message = error?.name === "AbortError"
        ? "The local API did not respond within 12 seconds."
        : "Could not reach the local API. Check that the backend is running.";
      throw new ApiError(0, message);
    } finally {
      clearTimeout(timeout);
    }

    if (response.status === 401) {
      throw new ApiError(401, "Your session is no longer valid. Sign in again.");
    }
    if (response.status === 403) {
      throw new ApiError(403, "Your API role does not have access to this information.");
    }
    if (response.status === 503) {
      throw new ApiError(503, "The API or local data store is unavailable.");
    }
    if (!response.ok) {
      throw new ApiError(response.status, `The API returned HTTP ${response.status}.`);
    }
    try {
      return await response.json();
    } catch {
      throw new ApiError(502, "The API returned a response that was not valid JSON.");
    }
  }

  health() {
    return this.request(API_PATHS.health, { authenticated: false });
  }

  async logout() {
    const result = await this.request(API_PATHS.logout, { method: "POST" });
    if (result?.status !== "revoked") {
      throw new ApiError(502, "The API did not confirm token revocation.");
    }
    return result;
  }

  listAlerts({ limit = 25, offset = 0, severity, rule_id } = {}) {
    return this.request(API_PATHS.alerts, {
      query: { limit, offset, severity, rule_id },
    });
  }

  getAlert(alertId) {
    return this.request(`${API_PATHS.alerts}/${encodeURIComponent(alertId)}`);
  }

  listEvents({ limit = 25, offset = 0, event_type, source_ip, severity } = {}) {
    return this.request(API_PATHS.events, {
      query: { limit, offset, event_type, source_ip, severity },
    });
  }

  getEvent(eventId) {
    return this.request(`${API_PATHS.events}/${encodeURIComponent(eventId)}`);
  }

  listIncidents({ limit = 25, offset = 0, status, severity } = {}) {
    return this.request(API_PATHS.incidents, {
      query: { limit, offset, status, severity },
    });
  }

  createIncident(values) {
    return this.request(API_PATHS.incidents, { method: "POST", body: values });
  }

  transitionIncident(incidentId, status) {
    return this.request(
      `${API_PATHS.incidents}/${encodeURIComponent(incidentId)}/transitions`,
      { method: "POST", body: { status } },
    );
  }

  getIncident(incidentId) {
    return this.request(`${API_PATHS.incidents}/${encodeURIComponent(incidentId)}`);
  }

  listIncidentNotes(incidentId, { limit = 25, offset = 0 } = {}) {
    return this.request(`${API_PATHS.incidents}/${encodeURIComponent(incidentId)}/notes`, {
      query: { limit, offset },
    });
  }

  appendIncidentNote(incidentId, noteText) {
    return this.request(`${API_PATHS.incidents}/${encodeURIComponent(incidentId)}/notes`, {
      method: "POST",
      body: { note_text: noteText },
    });
  }

  listAuditEvents({ limit = 25, offset = 0, action, resource_type, resource_id } = {}) {
    return this.request(API_PATHS.auditEvents, {
      query: { limit, offset, action, resource_type, resource_id },
    });
  }
}
